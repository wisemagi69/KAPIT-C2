"""Read-only restore preparation guards; never runs or certifies a restore.

This module does not create a cluster, reserve a target, run subprocesses,
read key material, remove files, or reopen an application. A future executor
must atomically reserve ownership and recheck all guards immediately before use.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import socket

ROOT = Path(__file__).resolve().parents[1]
OWNER = "KAPIT-C2 isolated recovery v1"
HEX = re.compile(r"[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
KEY_ID = re.compile(r"[a-zA-Z0-9_.-]{1,80}\Z")


class RecoveryGuard(ValueError):
    """Fixed code only; no source paths, keys or exception text."""


@dataclass(frozen=True)
class ExpectedBackup:
    """Trusted inventory values, supplied independently of the backup manifest.

    These values establish integrity/compatibility, not current authorization.
    No key bytes belong in this structure.
    """
    archive_sha256: str
    storage_sha256: str
    postgres_major: int
    code_sha256: str
    migrations_sha256: str
    key_ids: frozenset[str]


def _deny(code):
    raise RecoveryGuard(code)


def _digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def _private_file(value):
    path = Path(value)
    cache = (ROOT / ".cache").resolve()
    # Reject path traversal and symlink redirects, including parent redirects.
    if ".." in path.parts or not path.is_absolute():
        _deny("INPUT_PATH_INVALID")
    resolved = path.resolve()
    if not resolved.is_relative_to(cache) or not cache.is_relative_to(ROOT.resolve()) or path != resolved or not path.is_file():
        _deny("INPUT_PATH_INVALID")
    return resolved


def _port_free(port):
    # Binding checks listener conflicts without connecting to any service.
    # Closing this socket does NOT reserve the port for a future executor.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(("127.0.0.1", port))


def prepare(manifest, *, archive, storage_snapshot, key_inventory, target_id, port, expected):
    """Verify bytes/metadata and return a closed, unreserved dry-run plan.

    ``key_inventory`` maps opaque key IDs to existing private files; only file
    availability is checked. Key correctness/decryption requires a real isolated
    rehearsal. ``storage_snapshot`` is an opaque snapshot file, never unpacked.
    The caller must obtain ExpectedBackup from a trusted independent inventory.
    """
    try:
        return _prepare(manifest, archive, storage_snapshot, key_inventory, target_id, port, expected)
    except RecoveryGuard:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        raise RecoveryGuard("PREPARATION_UNAVAILABLE") from None


def _prepare(manifest, archive, storage_snapshot, key_inventory, target_id, port, expected):
    if not isinstance(expected, ExpectedBackup):
        _deny("EXPECTED_INVENTORY_REQUIRED")
    hashes = (expected.archive_sha256, expected.storage_sha256, expected.code_sha256, expected.migrations_sha256)
    if any(not isinstance(value, str) or not HEX.fullmatch(value) for value in hashes):
        _deny("EXPECTED_INVENTORY_INVALID")
    if type(expected.postgres_major) is not int or expected.postgres_major < 16:
        _deny("EXPECTED_INVENTORY_INVALID")
    if not isinstance(expected.key_ids, frozenset) or not expected.key_ids or any(not isinstance(key, str) or not KEY_ID.fullmatch(key) for key in expected.key_ids):
        _deny("EXPECTED_INVENTORY_INVALID")
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "archive_sha256", "storage_sha256", "postgres_major", "code_sha256", "migrations_sha256", "key_ids"}:
        _deny("MANIFEST_INVALID")
    if type(manifest["schema"]) is not int or manifest["schema"] != 1:
        _deny("MANIFEST_INVALID")
    for field in ("archive_sha256", "storage_sha256", "postgres_major", "code_sha256", "migrations_sha256"):
        if type(manifest[field]) is not type(getattr(expected, field)) or manifest[field] != getattr(expected, field):
            _deny("BACKUP_INCOMPATIBLE")
    if not isinstance(manifest["key_ids"], list) or any(not isinstance(key, str) for key in manifest["key_ids"]) or len(set(manifest["key_ids"])) != len(manifest["key_ids"]) or set(manifest["key_ids"]) != expected.key_ids:
        _deny("KEY_INVENTORY_MISMATCH")
    if not isinstance(key_inventory, dict) or not expected.key_ids.issubset(key_inventory):
        _deny("KEY_INVENTORY_MISSING")
    for key in expected.key_ids:
        _private_file(key_inventory[key])  # Deliberately no open/read of key files.
    archive_path = _private_file(archive)
    storage_path = _private_file(storage_snapshot)
    if archive_path.samefile(storage_path) or any(archive_path.samefile(key_inventory[key]) or storage_path.samefile(key_inventory[key]) for key in expected.key_ids):
        _deny("INPUT_IDENTITY_CONFLICT")
    if _digest(archive_path) != expected.archive_sha256 or _digest(storage_path) != expected.storage_sha256:
        _deny("BACKUP_DIGEST_MISMATCH")
    if not isinstance(target_id, str) or not TOKEN.fullmatch(target_id):
        _deny("TARGET_INVALID")
    # No configurable DB name/root/port can target the retained kapit_m1 cluster.
    if type(port) is not int or not 56000 <= port <= 56999:
        _deny("TARGET_PORT_INVALID")
    owned_root = ROOT / ".cache" / "m4-recovery"
    if not owned_root.resolve().is_relative_to(ROOT.resolve() / ".cache") or owned_root != owned_root.resolve():
        _deny("TARGET_OWNERSHIP_INVALID")
    if owned_root.exists():
        marker = owned_root / "owner.json"
        if marker.is_symlink() or not marker.is_file():
            _deny("TARGET_OWNERSHIP_INVALID")
        if marker.stat().st_size > 4096:
            _deny("TARGET_OWNERSHIP_INVALID")
        try:
            owner = json.loads(marker.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            _deny("TARGET_OWNERSHIP_INVALID")
        if (not isinstance(owner, dict) or type(owner.get("schema")) is not int
                or owner != {"schema": 1, "owner": OWNER, "workspace": str(ROOT.resolve())}):
            _deny("TARGET_OWNERSHIP_INVALID")
    target = owned_root / target_id
    if target.exists() or target.is_symlink():
        _deny("TARGET_PREEXISTS")
    try:
        _port_free(port)
    except OSError:
        _deny("TARGET_PORT_UNAVAILABLE")
    return {
        "schema": 1, "status": "PREPARED_NOT_RESTORED", "application": "CLOSED",
        "target_id": target_id, "database": "kapit_recovery_" + target_id,
        "port": port, "target_reserved": False, "key_material_verified": False,
        "required_before_restore": ["ATOMIC_OWNERSHIP_RESERVATION", "RECHECK_INPUTS_AND_LISTENER", "ISOLATED_RUNTIME_CONTEXT"],
        "required_before_open": ["ACTUAL_RESTORE", "DECRYPTION_AND_RELATIONAL_GUARDS", "LEASE_RECEIPT_DEDUP_RECOVERY", "AUTHORITATIVE_CURRENT_REVOCATION_POLICY_WITHDRAWAL_RECONCILIATION", "CURRENT_ACCESS_DENIAL_TESTS", "ELAPSED_TIME_AND_DATA_LOSS_MEASUREMENT"],
    }
