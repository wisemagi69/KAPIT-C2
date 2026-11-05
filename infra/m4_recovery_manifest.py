"""Bounded synthetic whole-application recovery metadata preparation.

No file access, restore, key material, decryption, database query or authority
adoption. External model metadata/key availability are assumptions. Hash equality
does not prove semantic consistency or actual restore success. Production closed.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re

COMPONENTS = ("database", "private_evidence", "photos", "coordinates", "application",
              "sources", "policy", "revocations", "key_index")
PATHS = {name: "components/" + name + ".bin" for name in COMPONENTS}
ENCRYPTED = frozenset(("database", "private_evidence", "photos", "coordinates"))
MAX_METADATA = 65536
MAX_COMPONENT = 1048576
MAX_OPERATIONS = 128


class RecoveryRefused(ValueError):
    def __init__(self):
        super().__init__("SYNTHETIC_RECOVERY_PREPARATION_REFUSED")


def _need(value):
    if value is not True:
        raise RecoveryRefused()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _parse(raw):
    _need(type(raw) is bytes and 1 <= len(raw) <= MAX_METADATA and raw.isascii())
    value = json.loads(raw.decode("ascii"))
    _need(type(value) is dict and canonical(value) == raw)
    return value


def _fields(value, names):
    _need(type(value) is dict and set(value) == set(names.split()))


def _hex(value, width=64):
    _need(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % width, value) is not None
          and value != "0" * width)


def _integer(value, low, high):
    _need(type(value) is int and low <= value <= high)


def _clock(value):
    _need(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value,
                                            flags=re.ASCII) is not None)
    result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    _need(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value)
    return result


def _key_ids(value, *, tuple_required=False):
    _need(type(value) is (tuple if tuple_required else list) and len(value) <= 32)
    _need(all(type(item) is str and re.fullmatch(r"key-[a-z0-9]{1,24}", item) is not None
              for item in value))
    _need(len(set(value)) == len(value))
    return frozenset(value)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class Preparation:
    """Model integrity result only. No IDs, filenames or key material exposed.

    pending_operations_retained counts preserved metadata rows only; no durable
    queue, operation payload restoration or delivery/commit is established.
    """
    status: str
    manifest_sha256: str
    authoritative_model_sha256: str
    component_count: int
    committed_operations: int
    pending_operations_retained: int
    recovery_authority: bool = False
    decryption_verified: bool = False
    semantic_coherence_verified: bool = False


def production_restore(*args, **kwargs):
    raise RecoveryRefused()


def validate_synthetic_manifest(raw, authoritative_raw, *, components,
                                available_key_ids, now_utc):
    """Prepare fixed synthetic buffers against explicitly supplied model facts.

    The authoritative model is NOT authenticated/adopted by this API. Its key
    availability claims never establish key custody, correctness or decryption.
    Stale revocations refuse; C12 still needs an admitted latest-revocation overlay
    to recover older backups safely. Protocol time bounds are not agreed RPO/RTO.
    No caller callbacks or file/database operations are performed.
    """
    try:
        manifest, authority = _parse(raw), _parse(authoritative_raw)
        _fields(manifest, "scope version snapshot_id commit_id generation schema captured_utc components operations")
        _fields(authority, "scope version snapshot_id commit_id generation schema issued_utc expires_utc component_sha256 operation_sha256 active_key_ids revoked_key_ids")
        _need(manifest["scope"] == "SYNTHETIC_RECOVERY_MANIFEST_V1")
        _need(authority["scope"] == "SYNTHETIC_CURRENT_RECOVERY_MODEL_V1")
        for document in (manifest, authority):
            _integer(document["version"], 1, 1)
            _hex(document["snapshot_id"], 32)
            _hex(document["commit_id"], 32)
            _integer(document["generation"], 1, 2**63 - 1)
            _integer(document["schema"], 1, 65535)
        for field in ("snapshot_id", "commit_id", "generation", "schema"):
            _need(manifest[field] == authority[field])
        now, captured = _clock(now_utc), _clock(manifest["captured_utc"])
        issued, expires = _clock(authority["issued_utc"]), _clock(authority["expires_utc"])
        _need(issued <= captured <= now < expires and 0 < (expires - issued).total_seconds() <= 3600)
        active = _key_ids(authority["active_key_ids"])
        revoked = _key_ids(authority["revoked_key_ids"])
        available = _key_ids(available_key_ids, tuple_required=True)
        _need(not active & revoked and available <= active and not available & revoked)
        expected = authority["component_sha256"]
        _need(type(expected) is dict and set(expected) == set(COMPONENTS))
        for digest in expected.values():
            _hex(digest)
        _need(type(components) is dict and set(components) == set(COMPONENTS))
        # Freeze the map before validation; values are immutable bounded bytes.
        buffers = dict(components)
        _need(all(type(payload) is bytes and 1 <= len(payload) <= MAX_COMPONENT
                  for payload in buffers.values()))
        records = manifest["components"]
        _need(type(records) is list and len(records) == len(COMPONENTS))
        for name, row in zip(COMPONENTS, records):
            _fields(row, "id path snapshot_id commit_id generation schema size sha256 required_key_ids")
            _need(row["id"] == name and row["path"] == PATHS[name])
            for field in ("snapshot_id", "commit_id", "generation", "schema"):
                _need(type(row[field]) is type(manifest[field]) and row[field] == manifest[field])
            _integer(row["size"], 1, MAX_COMPONENT)
            _hex(row["sha256"])
            _need(row["size"] == len(buffers[name]))
            _need(_digest(buffers[name]) == row["sha256"] == expected[name])
            required = _key_ids(row["required_key_ids"])
            _need(required <= available and not required & revoked)
            _need(1 <= len(required) <= 4 if name in ENCRYPTED else len(required) == 0)
        operations = manifest["operations"]
        _need(type(operations) is list and len(operations) <= MAX_OPERATIONS)
        operation_bindings = authority["operation_sha256"]
        _need(type(operation_bindings) is dict and len(operation_bindings) <= MAX_OPERATIONS)
        for operation_id, digest in operation_bindings.items():
            _hex(operation_id, 32)
            _hex(digest)
        seen, committed, pending = set(), 0, 0
        for operation in operations:
            _fields(operation, "operation_id payload_sha256 state database_commit_sha256")
            _hex(operation["operation_id"], 32)
            _hex(operation["payload_sha256"])
            _need(operation["operation_id"] not in seen)
            seen.add(operation["operation_id"])
            _need(_digest(canonical(operation)) == operation_bindings.get(operation["operation_id"]))
            state = operation["state"]
            _need(type(state) is str and state in ("COMMITTED", "PENDING"))
            if state == "COMMITTED":
                _need(operation["database_commit_sha256"] == expected["database"])
                committed += 1
            else:
                _need(operation["database_commit_sha256"] == "")
                pending += 1
        _need(seen == set(operation_bindings))
        return Preparation("SYNTHETIC_PREPARATION_ONLY", _digest(raw), _digest(authoritative_raw),
                           len(COMPONENTS), committed, pending)
    except BaseException:
        pass
    # Raise outside the handler so decoder exceptions cannot retain raw input
    # through __context__ even when callers inspect exception objects directly.
    raise RecoveryRefused()
