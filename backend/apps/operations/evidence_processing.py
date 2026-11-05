"""Private evidence validation orchestration; no recipient or HTTP entrypoint.

Trusted current-tools fence precedes every business transaction and remains held
through COMMIT. Native scan/decode runs between transactions, without that fence.
Current native adapters deliberately refuse until independent OS/tool proof exists.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
import json
from pathlib import Path
import secrets
import sys
import uuid

from django.db import connection, transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.reports.canonical import canonical, digest
from apps.reports.crypto import encrypt, source_payload
from apps.scopes.access import live_memberships, source_allowed
from apps.scopes.models import Unit

_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from infra import evidence_tools as tools

from .errors import ApiError, missing
from .evidence import _lock_revision
from .evidence_capture import PURPOSE as CAPTURE_PURPOSE, decrypt_original as decrypt, validate_capture
from .evidence_decoder import DecodedEvidence
from .evidence_policy import CODES, DEFAULT_POLICY, EvidenceError, REJECT_CODES, inspect_container
from .models import PrivateEvidence, PrivateEvidenceValidation

_KEY = secrets.token_bytes(32)
_QUARANTINE = CODES - REJECT_CODES - {"DECODE_COMPLETE"}
_PROVENANCE_LIMIT = 65536


def _unavailable():
    return ApiError("EVIDENCE_UNAVAILABLE", "Evidence remains private. Retry the same operation later.", 503)


def _conflict():
    return ApiError("IDEMPOTENCY_CONFLICT", "This evidence operation was accepted with a different request.", 409)


def _stale():
    return ApiError("VALIDATION_STALE", "Evidence remains private. Start a new validation operation.", 409)


def _uuid(value):
    if type(value) is not uuid.UUID:
        raise ApiError("INVALID_EVIDENCE_OPERATION", "Use a valid evidence operation identifier.")
    return value


def _date(value):
    return type(value) is datetime and value.tzinfo is not None and value.utcoffset() == timedelta(0)


def _boundary():
    # A caller's outer transaction could outlive current_tools and release the
    # fence before its COMMIT. No ATOMIC_REQUESTS/outer-atomic use is supported.
    if connection.in_atomic_block:
        raise _unavailable()


def _tool_error(error):
    code = error.code
    if code == "FENCE_UNAVAILABLE":
        return "PROVENANCE_UNAVAILABLE"
    return code if type(code) is str and code in _QUARANTINE else "PROVENANCE_UNAVAILABLE"


def _manifest_identity(manifest):
    if type(manifest) is not tools.ToolManifest or not _date(manifest.expires_at):
        raise _unavailable()
    return (manifest.manifest_hash, manifest.signature_generation, manifest.policy_generation,
            manifest.contract_sha256, manifest.expires_at.isoformat())


def _auth(actor, org, report, revision):
    unit = Unit.objects.get(pk=report.unit_id, organization=org)
    members = list(live_memberships(actor, actor.role).filter(unit_id=unit.id).order_by("id")
                   .values_list("id", "organization_id", "user_id", "unit_id", "role", "active", "valid_until"))
    return digest({
        "organization": [str(org.id), org.active],
        "actor": [str(actor.id), str(actor.organization_id), actor.role, actor.is_active, actor.permission_version],
        "report": [str(report.id), str(report.organization_id), str(report.unit_id), str(report.author_id)],
        "revision": [str(revision.id), str(revision.organization_id), str(revision.report_id),
                     str(revision.submitted_by_id), revision.revision_no, revision.content_digest, revision.key_id],
        "unit": [str(unit.id), str(unit.organization_id), unit.active, unit.scope_epoch],
        "members": [[str(v) if type(v) is uuid.UUID else v.isoformat() if type(v) is datetime else v for v in row]
                    for row in members],
    })


def _lock_evidence(user, evidence_id):
    # Never look up another organization's evidence identity before identity lock.
    from apps.scopes.access import lock_identity
    try:
        actor, org = lock_identity(user)
    except ApiError:
        raise missing() from None
    link = PrivateEvidence.objects.filter(pk=evidence_id, organization=org).values("revision_id").first()
    if link is None:
        raise missing()
    actor, org, report, revision = _lock_revision(actor, link["revision_id"])
    item = PrivateEvidence.objects.select_for_update().filter(pk=evidence_id, organization=org, revision=revision).first()
    if item is None:
        raise missing()
    return actor, org, report, revision, item


def strict_original(item):
    if item.key_id != "local-fernet-v1" or not 1 <= item.byte_size <= DEFAULT_POLICY.max_bytes or len(item.payload_ciphertext) > 12000000:
        raise _unavailable()
    try:
        value = decrypt(item.payload_ciphertext)
        fields = {"purpose", "id", "actor_id", "revision_id", "operation_id", "media_type", "filename", "bytes_base64"}
        if type(value) is not dict:
            raise ValueError
        captured = value.get("purpose") == CAPTURE_PURPOSE
        if (set(value) != fields | ({"capture"} if captured else set())
                or value["purpose"] not in {"private-evidence-v1", CAPTURE_PURPOSE} or value["id"] != str(item.id)
                or value["actor_id"] != str(item.uploaded_by_id) or value["revision_id"] != str(item.revision_id)
                or value["operation_id"] != str(item.operation_id) or value["media_type"] != item.media_type
                or type(value["filename"]) is not str or not 1 <= len(value["filename"]) <= 100
                or type(value["bytes_base64"]) is not str or len(value["bytes_base64"]) > 6990510):
            raise ValueError
        data = base64.b64decode(value["bytes_base64"], validate=True)
        if len(data) != item.byte_size or base64.b64encode(data).decode("ascii") != value["bytes_base64"]:
            raise ValueError
        checksum = hashlib.sha256(data).hexdigest()
        capture = validate_capture(value["capture"], now=item.created_at) if captured else None
        binding = {"purpose": value["purpose"], "actor_id": str(item.uploaded_by_id),
                           "revision_id": str(item.revision_id), "media_type": item.media_type,
                           "filename": value["filename"], "bytes_sha256": checksum}
        if captured:
            binding["capture"] = capture
        expected = digest(binding)
        if expected != item.request_hash:
            raise ValueError
        return data, checksum, capture
    except Exception:
        raise _unavailable() from None


def _original(item):
    data, checksum, _ = strict_original(item)
    return data, checksum


def _evidence_identity(item):
    return digest({"id": str(item.id), "organization": str(item.organization_id), "revision": str(item.revision_id),
                   "uploader": str(item.uploaded_by_id), "operation": str(item.operation_id),
                   "request_hash": item.request_hash, "ciphertext_hash": hashlib.sha256(bytes(item.payload_ciphertext)).hexdigest(),
                   "media_type": item.media_type, "size": item.byte_size, "slot": item.slot, "key_id": item.key_id,
                   "state": item.state, "code": item.validation_code})


@dataclass(frozen=True)
class ValidationSnapshot:
    actor_id: uuid.UUID
    organization_id: uuid.UUID
    revision_id: uuid.UUID
    evidence_id: uuid.UUID
    operation_id: uuid.UUID
    request_hash: str
    authority_hash: str
    evidence_hash: str
    input_sha256: str
    media_type: str
    data: bytes
    manifest: tools.ToolManifest
    prepared_at: datetime
    seal: str


@dataclass(frozen=True)
class ValidationReplay:
    status: dict


@dataclass(frozen=True)
class ValidationResult:
    code: str
    completed_at: datetime
    data: bytes = b""
    width: int | None = None
    height: int | None = None
    steps: tuple = ()
    seal: str = ""


def _snapshot_seal(snapshot):
    return hmac.new(_KEY, canonical({
        "purpose": "prepared-evidence-validation-v1", "actor": str(snapshot.actor_id),
        "org": str(snapshot.organization_id), "revision": str(snapshot.revision_id),
        "evidence": str(snapshot.evidence_id), "operation": str(snapshot.operation_id),
        "request_hash": snapshot.request_hash, "authority_hash": snapshot.authority_hash,
        "evidence_hash": snapshot.evidence_hash, "input": hashlib.sha256(snapshot.data).hexdigest(),
        "input_sha256": snapshot.input_sha256, "media_type": snapshot.media_type,
        "manifest": _manifest_identity(snapshot.manifest), "prepared_at": snapshot.prepared_at.isoformat(),
    }), hashlib.sha256).hexdigest()


def _check_snapshot(snapshot):
    try:
        if (type(snapshot) is not ValidationSnapshot or type(snapshot.data) is not bytes
                or not 1 <= len(snapshot.data) <= DEFAULT_POLICY.max_bytes or not _date(snapshot.prepared_at)
                or type(snapshot.seal) is not str or not hmac.compare_digest(snapshot.seal, _snapshot_seal(snapshot))):
            raise ValueError
        now = timezone.now()
        if not snapshot.prepared_at <= now < snapshot.manifest.expires_at:
            raise _stale()
    except ApiError:
        raise
    except Exception:
        raise _unavailable() from None


def _result_seal(snapshot, result):
    return hmac.new(_KEY, canonical({
        "purpose": "evidence-result-v1", "snapshot": snapshot.seal, "code": result.code,
        "completed_at": result.completed_at.isoformat(), "data_sha256": hashlib.sha256(result.data).hexdigest(),
        "size": len(result.data), "width": result.width, "height": result.height, "steps": result.steps,
    }), hashlib.sha256).hexdigest()


def _status(row, *, replay=False):
    return {"evidence_id": str(row.evidence_id), "state": row.state, "validation_code": row.code,
            # A replay's old success is not a new current latest-attempt check.
            "can_download": False if replay else row.state == "VALIDATED_PRIVATE"}


def prepare_validation(user, evidence_id, operation_id):
    _uuid(evidence_id)
    _uuid(operation_id)
    _boundary()
    try:
        with tools.current_tools() as manifest:
            _manifest_identity(manifest)
            with transaction.atomic(durable=True):
                actor, org, report, revision, item = _lock_evidence(user, evidence_id)
                if revision.key_id != "local-fernet-v1" or len(revision.payload_ciphertext) > 100000:
                    raise _unavailable()
                try:
                    source_payload(revision)  # verifies actual source digest without retaining plaintext
                except Exception:
                    raise _unavailable() from None
                data, checksum = _original(item)
                request_hash = digest({"purpose": "private-evidence-validation-v1", "actor_id": str(actor.id),
                                       "evidence_id": str(item.id), "original_request_hash": item.request_hash,
                                       "input_sha256": checksum, "manifest_hash": manifest.manifest_hash})
                previous = PrivateEvidenceValidation.objects.filter(validated_by=actor, operation_id=operation_id).first()
                if previous is not None:
                    if previous.organization_id != org.id or previous.evidence_id != item.id or previous.request_hash != request_hash:
                        raise _conflict()
                    tools.assert_current(manifest)
                    if not source_allowed(actor, report):
                        raise missing()
                    audit.record(org.id, actor, "EVIDENCE_VALIDATION_REPLAY", item.id, operation_id=str(operation_id))
                    result = ValidationReplay(_status(previous, replay=True))
                else:
                    now = timezone.now()
                    if now >= manifest.expires_at:
                        raise _stale()
                    snapshot = ValidationSnapshot(actor.id, org.id, revision.id, item.id, operation_id, request_hash,
                                                  _auth(actor, org, report, revision), _evidence_identity(item),
                                                  checksum, item.media_type, data, manifest, now, "")
                    result = replace(snapshot, seal=_snapshot_seal(snapshot))
                    tools.assert_current(manifest)
            return result
    except tools.ToolUnavailable:
        raise _unavailable() from None


def run_validation(snapshot):
    _boundary()
    _check_snapshot(snapshot)
    steps, output, width, height = [], b"", None, None
    try:
        inspect_container(snapshot.data, snapshot.media_type)
        verdict = tools.run_scan(snapshot.data, manifest=snapshot.manifest, media_type=snapshot.media_type)
        if type(verdict) is not str or verdict != "SCAN_CLEAN":
            raise EvidenceError("SCAN_NOT_CLEAN")
        steps.append("ORIGINAL_SCAN_CLEAN")
        decoded = tools.decode(snapshot.data, manifest=snapshot.manifest, media_type=snapshot.media_type)
        if (type(decoded) is not DecodedEvidence or decoded.media_type != "image/png"
                or type(decoded.frames) is not int or decoded.frames != 1):
            raise EvidenceError("DECODE_UNAVAILABLE")
        info = inspect_container(decoded.data, "image/png", normalized=True)
        if (type(decoded.width) is not int or type(decoded.height) is not int
                or (decoded.width, decoded.height) != (info.width, info.height)):
            raise EvidenceError("DECODE_UNAVAILABLE")
        steps.append("DECODE_COMPLETE")
        verdict = tools.run_scan(decoded.data, manifest=snapshot.manifest, media_type="image/png")
        if type(verdict) is not str or verdict != "SCAN_CLEAN":
            raise EvidenceError("SCAN_NOT_CLEAN")
        steps.append("DERIVATIVE_SCAN_CLEAN")
        output, width, height = decoded.data, decoded.width, decoded.height
        code = "VALIDATION_COMPLETE"
    except tools.ToolUnavailable as error:
        code = _tool_error(error)
    except EvidenceError as error:
        code = error.code if error.code in REJECT_CODES | _QUARANTINE else "DECODE_UNAVAILABLE"
    except MemoryError:
        code = "RESOURCE_LIMIT"
    except Exception:
        code = "DECODE_UNAVAILABLE"
    if code != "VALIDATION_COMPLETE":
        output, width, height = b"", None, None
    result = ValidationResult(code, timezone.now(), output, width, height, tuple(steps))
    return replace(result, seal=_result_seal(snapshot, result))


def _check_result(snapshot, result):
    try:
        if (type(result) is not ValidationResult or type(result.data) is not bytes or not _date(result.completed_at)
                or not snapshot.prepared_at <= result.completed_at <= timezone.now()
                or type(result.seal) is not str or not hmac.compare_digest(result.seal, _result_seal(snapshot, result))):
            raise ValueError
        if result.code == "VALIDATION_COMPLETE":
            if result.steps != ("ORIGINAL_SCAN_CLEAN", "DECODE_COMPLETE", "DERIVATIVE_SCAN_CLEAN"):
                raise ValueError
            info = inspect_container(result.data, "image/png", normalized=True)
            if type(result.width) is not int or type(result.height) is not int or (result.width, result.height) != (info.width, info.height):
                raise ValueError
        elif result.code not in REJECT_CODES | _QUARANTINE or result.data or result.width is not None or result.height is not None:
            raise ValueError
    except Exception:
        raise _unavailable() from None


def derivative_envelope(validation_id, snapshot, result):
    """Internal identity recipe shared with separately reviewed private retrieval."""
    return {"purpose": "private-evidence-derivative-v1", "validation_id": str(validation_id),
            "evidence_id": str(snapshot.evidence_id), "organization_id": str(snapshot.organization_id),
            "revision_id": str(snapshot.revision_id), "manifest_hash": snapshot.manifest.manifest_hash,
            "signature_generation": snapshot.manifest.signature_generation, "input_sha256": snapshot.input_sha256,
            "media_type": "image/png", "width": result.width, "height": result.height, "frames": 1,
            "bytes_sha256": hashlib.sha256(result.data).hexdigest(), "bytes_base64": base64.b64encode(result.data).decode("ascii")}


def commit_validation(user, snapshot, result):
    _check_snapshot(snapshot)
    _check_result(snapshot, result)
    _boundary()
    try:
        with tools.current_tools() as manifest:
            if _manifest_identity(manifest) != _manifest_identity(snapshot.manifest):
                raise _stale()
            with transaction.atomic(durable=True):
                actor, org, report, revision, item = _lock_evidence(user, snapshot.evidence_id)
                if (actor.id != snapshot.actor_id or org.id != snapshot.organization_id or revision.id != snapshot.revision_id
                        or _auth(actor, org, report, revision) != snapshot.authority_hash
                        or _evidence_identity(item) != snapshot.evidence_hash):
                    raise _stale()
                data, checksum = _original(item)
                if checksum != snapshot.input_sha256 or data != snapshot.data:
                    raise _stale()
                previous = PrivateEvidenceValidation.objects.filter(validated_by=actor, operation_id=snapshot.operation_id).first()
                if previous is not None:
                    if previous.evidence_id != item.id or previous.request_hash != snapshot.request_hash:
                        raise _conflict()
                    tools.assert_current(manifest)
                    if not source_allowed(actor, report) or _auth(actor, org, report, revision) != snapshot.authority_hash:
                        raise _stale()
                    audit.record(org.id, actor, "EVIDENCE_VALIDATION_REPLAY", item.id, operation_id=str(snapshot.operation_id))
                    status = _status(previous, replay=True)
                else:
                    now = timezone.now()
                    expiry = min(manifest.expires_at, result.completed_at + timedelta(days=1))
                    if not result.completed_at <= now < expiry:
                        raise _stale()
                    validation_id = uuid.uuid4()
                    success = result.code == "VALIDATION_COMPLETE"
                    state = "VALIDATED_PRIVATE" if success else "REJECTED_PRIVATE" if result.code in REJECT_CODES else "QUARANTINED"
                    provenance = {
                        "purpose": "private-evidence-validation-provenance-v1", "validation_id": str(validation_id),
                        "evidence_id": str(item.id), "organization_id": str(org.id), "revision_id": str(revision.id),
                        "actor_id": str(actor.id), "operation_id": str(snapshot.operation_id), "request_hash": snapshot.request_hash,
                        "input_sha256": checksum, "manifest_hash": manifest.manifest_hash,
                        "signature_generation": manifest.signature_generation, "manifest": manifest.as_provenance(),
                        "code": result.code, "steps": list(result.steps), "completed_at": result.completed_at.isoformat(),
                    }
                    if len(canonical(provenance)) > _PROVENANCE_LIMIT:
                        raise _unavailable()
                    try:
                        provenance_ciphertext = encrypt(provenance)
                        derivative = encrypt(derivative_envelope(validation_id, snapshot, result)) if success else None
                        if not 1 <= len(provenance_ciphertext) <= 100000 or derivative is not None and not 1 <= len(derivative) <= 12000000:
                            raise ValueError
                    except Exception:
                        raise _unavailable() from None
                    row = PrivateEvidenceValidation.objects.create(
                        id=validation_id, organization=org, evidence=item, validated_by=actor,
                        operation_id=snapshot.operation_id, request_hash=snapshot.request_hash,
                        manifest_hash=manifest.manifest_hash, signature_generation=manifest.signature_generation,
                        input_sha256=checksum, state=state, code=result.code, provenance_ciphertext=provenance_ciphertext,
                        derivative_ciphertext=derivative, derivative_sha256=hashlib.sha256(result.data).hexdigest() if success else None,
                        derivative_size=len(result.data) if success else None, width=result.width, height=result.height,
                        validated_at=result.completed_at if success else None, expires_at=expiry if success else None)
                    tools.assert_current(manifest)  # must occur INSIDE transaction before audit+COMMIT
                    # Artifact re-verification/encryption may take time; do not
                    # let a membership/validation clock expire during that work.
                    if (not source_allowed(actor, report) or _auth(actor, org, report, revision) != snapshot.authority_hash
                            or timezone.now() >= expiry):
                        raise _stale()
                    audit.record(org.id, actor, "EVIDENCE_VALIDATED" if success else "EVIDENCE_VALIDATION_PRIVATE",
                                 item.id, operation_id=str(snapshot.operation_id), error_code=None if success else result.code)
                    status = _status(row)
            return status
    except tools.ToolUnavailable:
        raise _unavailable() from None


def validate_evidence(user, evidence_id, operation_id):
    prepared = prepare_validation(user, evidence_id, operation_id)
    if type(prepared) is ValidationReplay:
        return prepared.status
    return commit_validation(user, prepared, run_validation(prepared))
