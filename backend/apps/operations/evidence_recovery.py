"""Offline encrypted-evidence integrity only; no ORM, delivery or native readiness.

The trusted root adapter owns connections, cryptographic capability and lifecycle.
All database access here is read-only, in a repeatable-read transaction. Historical
manifest parsing uses recorded completion time, never grants current eligibility.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
import hashlib
import json
import re
import uuid

from .evidence_capture import PURPOSE, validate_capture
from .evidence_policy import MAX_BYTES, REJECT_CODES, CODES, inspect_container, parse_manifest

MAX_ROWS = 100
MAX_TOTAL = 64 * 1024 * 1024
MAX_CIPHER = 12_000_000
HEX = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
STEPS = ("ORIGINAL_SCAN_CLEAN", "DECODE_COMPLETE", "DERIVATIVE_SCAN_CLEAN")
QUARANTINE = CODES - REJECT_CODES - {"DECODE_COMPLETE"}


class RecoveryError(ValueError):
    def __init__(self):
        super().__init__("RESTORED_EVIDENCE_INTEGRITY")


def require(value):
    if not value:
        raise RecoveryError()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def identifier(value):
    require(type(value) is str and str(uuid.UUID(value)) == value)
    return value


def stamp(value):
    require(type(value) is datetime and value.tzinfo is not None and value.utcoffset() == timedelta(0))
    return value


def strict_json(raw, limit):
    require(type(raw) is bytes and 0 < len(raw) <= limit)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise RecoveryError()
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid,
                       parse_float=invalid)
    stack, remaining = [(value, 0)], 2048
    while stack:
        item, depth = stack.pop()
        remaining -= 1
        require(remaining >= 0 and depth <= 8)
        if type(item) is dict:
            require(all(type(k) is str for k in item))
            stack.extend((v, depth + 1) for v in item.values())
        elif type(item) is list:
            stack.extend((v, depth + 1) for v in item)
        else:
            require(type(item) in (str, int, bool, type(None)))
    return value


def plaintext(ciphertext, decrypt_bytes, limit):
    require(type(ciphertext) is bytes and 0 < len(ciphertext) <= MAX_CIPHER)
    raw = decrypt_bytes(ciphertext)
    return strict_json(raw, limit), len(raw)


def decode_bytes(encoded, size):
    require(type(size) is int and 0 < size <= MAX_BYTES)
    require(type(encoded) is str and 0 < len(encoded) <= 6_990_508)
    raw = base64.b64decode(encoded, validate=True)
    require(len(raw) == size and base64.b64encode(raw).decode("ascii") == encoded)
    return raw


@dataclass(frozen=True, repr=False)
class OriginalRecord:
    id: str
    organization_id: str
    revision_id: str
    uploaded_by_id: str
    operation_id: str
    request_hash: str
    payload_ciphertext: bytes
    key_id: str
    media_type: str
    byte_size: int
    slot: int
    state: str
    validation_code: str
    created_at: datetime
    revision_organization_id: str
    report_organization_id: str
    uploader_organization_id: str
    revision_submitted_by_id: str
    report_author_id: str

    def __repr__(self):
        return "OriginalRecord(<private>)"


@dataclass(frozen=True, repr=False)
class ValidationRecord:
    id: str
    organization_id: str
    evidence_id: str
    validated_by_id: str
    operation_id: str
    request_hash: str
    manifest_hash: str
    signature_generation: str
    input_sha256: str
    state: str
    code: str
    created_at: datetime
    validated_at: datetime | None
    expires_at: datetime | None
    provenance_ciphertext: bytes
    derivative_ciphertext: bytes | None
    derivative_sha256: str | None
    derivative_size: int | None
    width: int | None
    height: int | None
    key_id: str
    validator_organization_id: str

    def __repr__(self):
        return "ValidationRecord(<private>)"


@dataclass(frozen=True, repr=False)
class RecoveryBinding:
    original: OriginalRecord
    data: bytes
    capture_json: bytes | None
    input_sha256: str
    plaintext_bytes: int
    validation_id: str | None = None
    derivative: bytes | None = None

    def __repr__(self):
        return "RecoveryBinding(<private; not delivery authority>)"


@dataclass(frozen=True, repr=False)
class ExpectedEvidence:
    data: bytes
    capture_json: bytes | None
    derivatives: tuple[tuple[str, bytes], ...] = ()

    def __repr__(self):
        return "ExpectedEvidence(<private fixture>)"


@dataclass(frozen=True)
class RecoverySummary:
    originals_verified: int = 0
    legacy_verified: int = 0
    capture_verified: int = 0
    located_verified: int = 0
    derivatives_verified: int = 0
    provenance_verified: int = 0

    def as_dict(self):
        return {**self.__dict__, "integrity": "VERIFIED", "current_delivery": "NOT_EVALUATED",
                "native_validation": "NOT_PROVEN_BY_THIS_TEST"}


def verify_original(record, *, decrypt_bytes):
    try:
        require(type(record) is OriginalRecord)
        for key in ("id", "organization_id", "revision_id", "uploaded_by_id", "operation_id"):
            identifier(getattr(record, key))
        require(record.organization_id == record.revision_organization_id == record.report_organization_id
                == record.uploader_organization_id)
        require(record.uploaded_by_id == record.revision_submitted_by_id == record.report_author_id)
        require(record.key_id == "local-fernet-v1" and record.state == "QUARANTINED"
                and record.validation_code == "DECODER_REQUIRED"
                and type(record.slot) is int and record.slot in (1, 2)
                and record.media_type in ("image/jpeg", "image/png")
                and type(record.request_hash) is str and HEX.fullmatch(record.request_hash))
        stamp(record.created_at)
        value, length = plaintext(record.payload_ciphertext, decrypt_bytes, 7_100_000)
        fields = {"purpose", "id", "actor_id", "revision_id", "operation_id", "media_type", "filename", "bytes_base64"}
        require(type(value) is dict)
        captured = value.get("purpose") == PURPOSE
        require(set(value) == fields | ({"capture"} if captured else set()))
        require(value["purpose"] in ("private-evidence-v1", PURPOSE))
        for name, expected in (("id", record.id), ("actor_id", record.uploaded_by_id),
                               ("revision_id", record.revision_id), ("operation_id", record.operation_id),
                               ("media_type", record.media_type)):
            require(type(value[name]) is str and value[name] == expected)
        require(type(value["filename"]) is str and 1 <= len(value["filename"]) <= 100)
        data = decode_bytes(value["bytes_base64"], record.byte_size)
        checksum = hashlib.sha256(data).hexdigest()
        capture = validate_capture(value["capture"], now=record.created_at) if captured else None
        binding = {"purpose": value["purpose"], "actor_id": record.uploaded_by_id,
                   "revision_id": record.revision_id, "media_type": record.media_type,
                   "filename": value["filename"], "bytes_sha256": checksum}
        if captured:
            binding["capture"] = capture
        require(digest(binding) == record.request_hash)
        return RecoveryBinding(record, data, canonical(capture) if captured else None, checksum, length)
    except Exception:
        raise RecoveryError() from None


def verify_validation(record, original_binding, *, decrypt_bytes):
    try:
        require(type(record) is ValidationRecord and type(original_binding) is RecoveryBinding
                and original_binding.validation_id is None)
        original = original_binding.original
        for key in ("id", "organization_id", "evidence_id", "validated_by_id", "operation_id"):
            identifier(getattr(record, key))
        require(record.organization_id == original.organization_id == record.validator_organization_id
                and record.evidence_id == original.id and record.key_id == "local-fernet-v1"
                and record.input_sha256 == original_binding.input_sha256)
        for key in ("manifest_hash", "signature_generation", "request_hash", "input_sha256"):
            require(type(getattr(record, key)) is str and HEX.fullmatch(getattr(record, key)))
        stamp(record.created_at)
        require(type(record.provenance_ciphertext) is bytes and len(record.provenance_ciphertext) <= 100000)
        value, length = plaintext(record.provenance_ciphertext, decrypt_bytes, 65536)
        require(type(value) is dict and type(value.get("completed_at")) is str)
        completed = stamp(datetime.fromisoformat(value["completed_at"]))
        require(value["completed_at"] == completed.isoformat())
        require(original.created_at <= completed <= record.created_at)
        manifest = parse_manifest(canonical(value.get("manifest")), now=completed)
        require(manifest.manifest_hash == record.manifest_hash and manifest.signature_generation == record.signature_generation)
        request = {"purpose": "private-evidence-validation-v1", "actor_id": record.validated_by_id,
                   "evidence_id": original.id, "original_request_hash": original.request_hash,
                   "input_sha256": record.input_sha256, "manifest_hash": record.manifest_hash}
        require(record.request_hash == digest(request))
        steps = value.get("steps")
        require(type(steps) is list and steps == list(STEPS[:len(steps)]) and len(steps) <= 3)
        expected = {"purpose": "private-evidence-validation-provenance-v1", "validation_id": record.id,
                    "evidence_id": original.id, "organization_id": original.organization_id,
                    "revision_id": original.revision_id, "actor_id": record.validated_by_id,
                    "operation_id": record.operation_id, "request_hash": record.request_hash,
                    "input_sha256": record.input_sha256, "manifest_hash": record.manifest_hash,
                    "signature_generation": record.signature_generation, "manifest": value["manifest"],
                    "code": record.code, "steps": steps, "completed_at": value["completed_at"]}
        require(canonical(value) == canonical(expected))
        success = record.state == "VALIDATED_PRIVATE" and record.code == "VALIDATION_COMPLETE"
        fields = (record.validated_at, record.expires_at, record.derivative_ciphertext, record.derivative_sha256,
                  record.derivative_size, record.width, record.height)
        if not success:
            require((record.state == "REJECTED_PRIVATE" and record.code in REJECT_CODES
                     or record.state == "QUARANTINED" and record.code in QUARANTINE)
                    and all(v is None for v in fields) and len(steps) < 3)
            return RecoveryBinding(original, b"", original_binding.capture_json, original_binding.input_sha256,
                                   length, record.id)
        require(all(v is not None for v in fields) and steps == list(STEPS))
        require(stamp(record.validated_at) == completed and stamp(record.expires_at)
                and completed <= record.created_at < record.expires_at
                <= min(manifest.expires_at, completed + timedelta(days=1)))
        require(type(record.width) is int and type(record.height) is int
                and 1 <= record.width <= 6000 and 1 <= record.height <= 6000
                and record.width * record.height <= 24_000_000
                and type(record.derivative_sha256) is str and HEX.fullmatch(record.derivative_sha256))
        derivative, size = plaintext(record.derivative_ciphertext, decrypt_bytes, 7_100_000)
        require(type(derivative) is dict)
        expected = {"purpose": "private-evidence-derivative-v1", "validation_id": record.id,
                    "evidence_id": original.id, "organization_id": original.organization_id,
                    "revision_id": original.revision_id, "manifest_hash": record.manifest_hash,
                    "signature_generation": record.signature_generation, "input_sha256": record.input_sha256,
                    "media_type": "image/png", "width": record.width, "height": record.height,
                    "frames": 1, "bytes_sha256": record.derivative_sha256}
        require(set(derivative) == set(expected) | {"bytes_base64"})
        require(all(type(derivative[k]) is type(v) and derivative[k] == v for k, v in expected.items()))
        data = decode_bytes(derivative["bytes_base64"], record.derivative_size)
        require(hashlib.sha256(data).hexdigest() == record.derivative_sha256)
        info = inspect_container(data, "image/png", normalized=True)
        require((info.width, info.height) == (record.width, record.height))
        return RecoveryBinding(original, b"", original_binding.capture_json, original_binding.input_sha256,
                               length + size, record.id, data)
    except Exception:
        raise RecoveryError() from None


ORIGINAL_COLUMNS = tuple(OriginalRecord.__dataclass_fields__)
VALIDATION_COLUMNS = tuple(ValidationRecord.__dataclass_fields__)


def _record(cursor, kind, values):
    require(values is not None)
    names = ORIGINAL_COLUMNS if kind is OriginalRecord else VALIDATION_COLUMNS
    require(len(values) == len(names))
    # PostgreSQL UUID/bytea adapters return UUID and possibly memoryview.
    result = dict(zip(names, values))
    for name in names:
        if name == "id" or name.endswith("_id") and name != "key_id":
            result[name] = str(result[name]) if type(result[name]) is uuid.UUID else result[name]
        if name.endswith("ciphertext") and type(result[name]) is memoryview:
            result[name] = bytes(result[name])
    return kind(**result)


def _snapshot(connection):
    with connection.cursor() as cursor:
        cursor.execute("SHOW transaction_read_only")
        require(cursor.fetchone() == ("on",))
        cursor.execute("SHOW transaction_isolation")
        require(cursor.fetchone() == ("repeatable read",))


def _closed(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except Exception:
            raise RecoveryError() from None
    return wrapped


@_closed
def read_original(connection, evidence_id):
    """One bounded ciphertext at a time, after a length-only check in the same RR snapshot."""
    identifier(evidence_id)
    _snapshot(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT octet_length(payload_ciphertext) FROM operations_privateevidence WHERE id=%s", (evidence_id,))
        value = cursor.fetchone()
        require(value is not None and type(value[0]) is int and 0 < value[0] <= MAX_CIPHER)
        columns = ",".join("e." + key for key in ORIGINAL_COLUMNS[:-5])
        cursor.execute("SELECT " + columns + ",r.organization_id,p.organization_id,u.organization_id,r.submitted_by_id,p.author_id "
                       "FROM operations_privateevidence e LEFT JOIN reports_reportrevision r ON r.id=e.revision_id "
                       "LEFT JOIN reports_report p ON p.id=r.report_id LEFT JOIN accounts_user u ON u.id=e.uploaded_by_id "
                       "WHERE e.id=%s", (evidence_id,))
        return _record(cursor, OriginalRecord, cursor.fetchone())


@_closed
def read_validation(connection, validation_id):
    identifier(validation_id)
    _snapshot(connection)
    with connection.cursor() as cursor:
        cursor.execute("SELECT octet_length(provenance_ciphertext),octet_length(derivative_ciphertext) "
                       "FROM operations_privateevidencevalidation WHERE id=%s", (validation_id,))
        value = cursor.fetchone()
        require(value is not None and type(value[0]) is int and 0 < value[0] <= 100000
                and (value[1] is None or type(value[1]) is int and 0 < value[1] <= MAX_CIPHER))
        columns = ",".join("v." + key for key in VALIDATION_COLUMNS[:-1])
        cursor.execute("SELECT " + columns + ",u.organization_id FROM operations_privateevidencevalidation v "
                       "LEFT JOIN accounts_user u ON u.id=v.validated_by_id WHERE v.id=%s", (validation_id,))
        return _record(cursor, ValidationRecord, cursor.fetchone())


def verify_restored_evidence(connection, *, decrypt_bytes, expected_cohort=None):
    """Only fixed aggregate counts leave this API; all categories mandatory for fixtures."""
    try:
        _snapshot(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM operations_privateevidence ORDER BY id LIMIT 101")
            evidence_ids = [str(row[0]) for row in cursor.fetchall()]
            cursor.execute("SELECT id,evidence_id FROM operations_privateevidencevalidation ORDER BY id LIMIT 101")
            validations = [(str(row[0]), str(row[1])) for row in cursor.fetchall()]
        require(0 < len(evidence_ids) <= MAX_ROWS and len(validations) <= MAX_ROWS)
        if expected_cohort is not None:
            require(type(expected_cohort) is dict and set(expected_cohort) == set(evidence_ids)
                    and all(type(v) is ExpectedEvidence for v in expected_cohort.values()))
            for value in expected_cohort.values():
                require(type(value.data) is bytes and 0 < len(value.data) <= MAX_BYTES
                        and (value.capture_json is None or type(value.capture_json) is bytes and len(value.capture_json) <= 1024)
                        and type(value.derivatives) is tuple and len(value.derivatives) <= MAX_ROWS)
                for pair in value.derivatives:
                    require(type(pair) is tuple and len(pair) == 2)
                    identifier(pair[0])
                    require(type(pair[1]) is bytes and 0 < len(pair[1]) <= MAX_BYTES)
        counts = dict(RecoverySummary().__dict__)
        total, seen_validations = 0, set()
        for evidence_id in evidence_ids:
            original = verify_original(read_original(connection, evidence_id), decrypt_bytes=decrypt_bytes)
            total += original.plaintext_bytes
            counts["originals_verified"] += 1
            counts["legacy_verified" if original.capture_json is None else "capture_verified"] += 1
            if original.capture_json is not None and strict_json(original.capture_json, 1024)["location"] is not None:
                counts["located_verified"] += 1
            wanted = expected_cohort[evidence_id] if expected_cohort is not None else None
            if wanted:
                require(type(wanted.data) is bytes and wanted.data == original.data and wanted.capture_json == original.capture_json
                        and type(wanted.derivatives) is tuple)
            derivative_ids = set()
            for validation_id, owner in validations:
                if owner != evidence_id:
                    continue
                result = verify_validation(read_validation(connection, validation_id), original, decrypt_bytes=decrypt_bytes)
                seen_validations.add(validation_id)
                total += result.plaintext_bytes
                counts["provenance_verified"] += 1
                if result.derivative is not None:
                    counts["derivatives_verified"] += 1
                    derivative_ids.add(validation_id)
                    if wanted:
                        expectations = dict(wanted.derivatives)
                        require(len(expectations) == len(wanted.derivatives) and validation_id in expectations
                                and type(expectations[validation_id]) is bytes and expectations[validation_id] == result.derivative)
                require(total <= MAX_TOTAL)
            if wanted:
                require(derivative_ids == {pair[0] for pair in wanted.derivatives})
            require(total <= MAX_TOTAL)
        require(seen_validations == {row[0] for row in validations})
        if expected_cohort is not None:
            require(all(counts[k] > 0 for k in counts))
        return RecoverySummary(**counts)
    except Exception:
        raise RecoveryError() from None
