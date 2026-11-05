"""Current original-access checks and bounded prepared private PNG delivery."""
import base64
from datetime import timedelta
import hashlib
from pathlib import Path
import sys

from django.db import connection, transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.reports.crypto import decrypt
from apps.reports.canonical import canonical, digest
from apps.scopes.access import lock_identity
from .errors import ApiError, missing
from .evidence import _lock_revision
from .evidence_policy import CODES, EvidenceError, inspect_container
from .models import PrivateEvidence, PrivateEvidenceValidation

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import evidence_tools as tools


def _locked(user, evidence_id):
    # _lock_revision takes organization/identity locks before report/revision.
    try:
        user, _ = lock_identity(user)
    except ApiError:
        raise missing() from None
    link = PrivateEvidence.objects.filter(pk=evidence_id,
        organization_id=user.organization_id).values("revision_id").first()
    if link is None:
        raise missing()
    actor, org, _, revision = _lock_revision(user, link["revision_id"])
    item = PrivateEvidence.objects.filter(pk=evidence_id, organization=org, revision=revision).first()
    if item is None:
        raise missing()
    return actor, org, item


def _preauthorize(user, evidence_id):
    # Release this short early check before taking the tool fence. Repeat the
    # complete authorization under fence+transaction before any disclosure.
    with transaction.atomic():
        _locked(user, evidence_id)


def _latest(item, manifest):
    return PrivateEvidenceValidation.objects.filter(evidence=item, organization_id=item.organization_id,
        manifest_hash=manifest.manifest_hash, signature_generation=manifest.signature_generation
        ).order_by("-created_at", "-id").first()


def _provenance(row, item, manifest):
    if not 0 < len(row.provenance_ciphertext) <= 100000:
        raise ValueError("invalid private envelope")
    value = decrypt(row.provenance_ciphertext)
    request_hash = digest({"purpose": "private-evidence-validation-v1", "actor_id": str(row.validated_by_id),
        "evidence_id": str(item.id), "original_request_hash": item.request_hash,
        "input_sha256": row.input_sha256, "manifest_hash": manifest.manifest_hash})
    if row.request_hash != request_hash or len(canonical(value)) > 65536:
        raise ValueError("invalid private binding")
    expected = {
        "purpose": "private-evidence-validation-provenance-v1", "validation_id": str(row.id),
        "evidence_id": str(item.id), "organization_id": str(item.organization_id),
        "revision_id": str(item.revision_id), "actor_id": str(row.validated_by_id),
        "operation_id": str(row.operation_id), "request_hash": row.request_hash,
        "input_sha256": row.input_sha256, "manifest_hash": row.manifest_hash,
        "signature_generation": row.signature_generation, "manifest": manifest.as_provenance(),
        "code": "VALIDATION_COMPLETE", "steps": ["ORIGINAL_SCAN_CLEAN", "DECODE_COMPLETE", "DERIVATIVE_SCAN_CLEAN"],
        "completed_at": row.validated_at.isoformat(),
    }
    if type(value) is not dict or canonical(value) != canonical(expected):
        raise ValueError("invalid private envelope")


def _derivative(row, item, manifest):
    """No native parsing. Reject any swapped, stale or malformed encrypted copy."""
    try:
        now = timezone.now()
        if (row.state != "VALIDATED_PRIVATE" or row.code != "VALIDATION_COMPLETE"
                or row.validated_at is None or row.expires_at is None
                or not row.validated_at <= row.created_at <= now < row.expires_at
                or row.expires_at > min(manifest.expires_at, row.validated_at + timedelta(days=1))
                or row.derivative_ciphertext is None or not 0 < len(row.derivative_ciphertext) <= 12000000):
            raise ValueError("unavailable private copy")
        _provenance(row, item, manifest)
        value = decrypt(row.derivative_ciphertext)
        keys = {"purpose", "validation_id", "evidence_id", "organization_id", "revision_id", "manifest_hash",
                "signature_generation", "input_sha256", "media_type", "width", "height", "frames",
                "bytes_sha256", "bytes_base64"}
        if type(value) is not dict or set(value) != keys:
            raise ValueError("invalid private envelope")
        expected = {"purpose": "private-evidence-derivative-v1", "validation_id": str(row.id),
            "evidence_id": str(item.id), "organization_id": str(item.organization_id),
            "revision_id": str(item.revision_id), "manifest_hash": manifest.manifest_hash,
            "signature_generation": manifest.signature_generation, "input_sha256": row.input_sha256,
            "media_type": "image/png", "width": row.width, "height": row.height, "frames": 1,
            "bytes_sha256": row.derivative_sha256}
        if any(type(value[k]) is not type(v) or value[k] != v for k, v in expected.items()):
            raise ValueError("invalid private envelope")
        encoded = value["bytes_base64"]
        if type(encoded) is not str or not 0 < len(encoded) <= 6990508:
            raise ValueError("invalid private bytes")
        data = base64.b64decode(encoded, validate=True)
        if (not 0 < len(data) <= 5242880 or len(data) != row.derivative_size
                or base64.b64encode(data).decode("ascii") != encoded
                or hashlib.sha256(data).hexdigest() != row.derivative_sha256):
            raise ValueError("invalid private bytes")
        info = inspect_container(data, "image/png", normalized=True)
        if (info.width, info.height) != (row.width, row.height):
            raise ValueError("invalid private dimensions")
        return data
    except Exception:
        # No tool/schema/decrypt reason is reflected to an object requester.
        raise missing() from None


def _dto(item, state, code, available=False):
    return {"evidence_id": str(item.id), "state": state, "validation_code": code, "can_download": available}


def _unavailable():
    return ApiError("EVIDENCE_UNAVAILABLE", "Private evidence is unavailable. Retry later.", 503)


def _final_authorization(user, item, manifest, row=None):
    # Parsing and artifact verification can consume a permission/validation
    # window even while row locks prevent a concurrent grant mutation.
    actor, org, current = _locked(user, item.id)
    now = timezone.now()
    ready = now < manifest.expires_at
    if row is not None and row.state == "VALIDATED_PRIVATE":
        ready = ready and row.validated_at <= now < row.expires_at
    return actor, org, ready


def validation_status(user, evidence_id):
    if connection.in_atomic_block:
        raise _unavailable()
    try:
        _preauthorize(user, evidence_id)
        try:
            with tools.current_tools() as manifest:
                with transaction.atomic(durable=True):
                    actor, org, item = _locked(user, evidence_id)
                    row = _latest(item, manifest)
                    if row is None:
                        prior = PrivateEvidenceValidation.objects.filter(evidence=item, organization=org).exists()
                        result = _dto(item, "QUARANTINED", "VALIDATION_STALE" if prior else "DECODER_REQUIRED")
                    elif row.state == "VALIDATED_PRIVATE":
                        try:
                            _derivative(row, item, manifest)
                            result = _dto(item, row.state, row.code, True)
                        except ApiError:
                            result = _dto(item, "QUARANTINED", "VALIDATION_STALE")
                    elif row.state in {"QUARANTINED", "REJECTED_PRIVATE"} and row.code in CODES:
                        result = _dto(item, row.state, row.code)
                    else:
                        result = _dto(item, "QUARANTINED", "VALIDATION_STALE")
                    tools.assert_current(manifest)
                    actor, org, current = _final_authorization(user, item, manifest, row)
                    if result["can_download"] and not current:
                        result = _dto(item, "QUARANTINED", "VALIDATION_STALE")
                    audit.record(org.id, actor, "EVIDENCE_VALIDATION_READ", item.id)
                    _, _, current = _final_authorization(user, item, manifest, row)
                    if result["can_download"] and not current:
                        result = _dto(item, "QUARANTINED", "VALIDATION_STALE")
                return result
        except tools.ToolUnavailable:
            # A readiness problem cannot bypass current original authorization.
            with transaction.atomic(durable=True):
                actor, org, item = _locked(user, evidence_id)
                prior = PrivateEvidenceValidation.objects.filter(evidence=item, organization=org).exists()
                result = _dto(item, "QUARANTINED", "VALIDATION_STALE" if prior else "DECODER_REQUIRED")
                audit.record(org.id, actor, "EVIDENCE_VALIDATION_READ", item.id)
                _locked(user, item.id)
                return result
    except ApiError:
        raise
    except Exception:
        raise _unavailable() from None


def private_evidence_download(user, evidence_id):
    # Refuse before taking any org lock or tool fence. A surrounding transaction
    # could otherwise outlive the fence and roll back the required audit.
    if connection.in_atomic_block:
        raise missing()
    try:
        _preauthorize(user, evidence_id)
        with tools.current_tools() as manifest:
            with transaction.atomic(durable=True):
                actor, org, item = _locked(user, evidence_id)
                row = _latest(item, manifest)
                if row is None:
                    raise missing()
                data = _derivative(row, item, manifest)
                tools.assert_current(manifest)
                actor, org, current = _final_authorization(user, item, manifest, row)
                if not current:
                    raise missing()
                audit.record(org.id, actor, "EVIDENCE_PRIVATE_DOWNLOAD", item.id)
                _, _, current = _final_authorization(user, item, manifest, row)
                if not current:
                    raise missing()
            # Already bounded/prepared bytes; no lazy stream outlives the fence.
            return data
    except tools.ToolUnavailable:
        raise missing() from None
    except ApiError:
        raise
    except Exception:
        raise _unavailable() from None
