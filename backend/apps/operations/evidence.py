"""Encrypted private quarantine. No decoder/scanner or download capability.

Reuses the established source Fernet primitive and key custody. Encrypted typed
envelopes bind object/actor/revision/operation identity, media, filename and bytes.
This is not independent evidence-key management or a new crypto certification.
"""
import base64
import hashlib
import uuid

from django.db import transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.reports.crypto import digest, encrypt
from apps.reports.models import Report, ReportRevision
from apps.scopes.access import lock_identity, source_allowed

from .errors import ApiError, missing
from .evidence_validation import EvidenceLimits, preflight
from .evidence_capture import CaptureError, PURPOSE as CAPTURE_PURPOSE, validate_capture
from .models import PrivateEvidence


LIMITS = EvidenceLimits(max_bytes=5242880, max_width=6000, max_height=6000, max_pixels=24000000)


def _lock_revision(user, revision_id, *, upload=False):
    try:
        actor, org = lock_identity(user)
    except ApiError:
        raise missing() from None
    link = ReportRevision.objects.filter(pk=revision_id, organization=org).values("report_id").first()
    if link is None:
        raise missing()
    report = Report.objects.select_for_update().filter(pk=link["report_id"], organization=org).first()
    if report is None or not source_allowed(actor, report):
        raise missing()
    revision = ReportRevision.objects.select_for_update().filter(pk=revision_id, report=report, organization=org).first()
    if revision is None or (upload and (actor.role != "submitter" or report.author_id != actor.id or revision.submitted_by_id != actor.id)):
        raise missing()
    return actor, org, report, revision


@transaction.atomic
def authorize_upload(user, revision_id):
    """Early authorization only; release locks before reading a network body.

    The write service repeats authorization under its own commit locks. Replay of
    an accepted historical revision remains possible with current original access;
    a fresh operation can only attach to the current revision.
    """
    _lock_revision(user, revision_id, upload=True)


def metadata(item):
    return {"id": str(item.id), "operation_id": str(item.operation_id), "state": item.state,
            "validation_code": item.validation_code, "created_at": item.created_at.isoformat()}


@transaction.atomic
def accept_evidence(user, revision_id, operation_id, data, media_type, filename, *, capture=None):
    actor, org, report, revision = _lock_revision(user, revision_id, upload=True)
    if type(operation_id) is not uuid.UUID:
        raise ApiError("INVALID_EVIDENCE_OPERATION", "Send a valid evidence operation identifier.")
    # Validate bounded types before hashing. No decoder/scanner is invoked here.
    if type(data) is not bytes or not data:
        raise ApiError("INVALID_EVIDENCE", "This evidence could not be accepted.")
    if len(data) > LIMITS.max_bytes:
        raise ApiError("REQUEST_TOO_LARGE", "Evidence must be at most 5 MiB.", 413)
    if not isinstance(filename, str) or not isinstance(media_type, str) or len(filename) > 100 or len(media_type) > 100:
        raise ApiError("INVALID_EVIDENCE", "This evidence could not be accepted.")
    if capture is not None:
        try:
            capture = validate_capture(capture, now=timezone.now())
        except CaptureError:
            raise ApiError("INVALID_EVIDENCE_CAPTURE", "This capture metadata could not be accepted.") from None
    binding = {"purpose": "private-evidence-v1" if capture is None else CAPTURE_PURPOSE, "actor_id": str(actor.id),
        "revision_id": str(revision.id), "media_type": media_type, "filename": filename,
        "bytes_sha256": hashlib.sha256(data).hexdigest()}
    if capture is not None:
        binding["capture"] = capture
    request_hash = digest(binding)
    previous = PrivateEvidence.objects.filter(uploaded_by=actor, operation_id=operation_id, organization=org).first()
    if previous is not None:
        if previous.revision_id != revision.id or previous.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This evidence operation was accepted with a different request.", 409)
        audit.record(org.id, actor, "EVIDENCE_REPLAY", previous.id, operation_id=str(operation_id))
        return metadata(previous), False
    if revision.revision_no != report.current_revision_no:
        raise ApiError("REVISION_CONFLICT", "Only the current source revision can accept new evidence.", 409)
    checked = preflight(data, media_type, filename, LIMITS)
    if checked.state != "QUARANTINED" or checked.code != "DECODER_REQUIRED":
        raise ApiError("INVALID_EVIDENCE", "This evidence could not be accepted.")
    used_slots = set(PrivateEvidence.objects.filter(revision=revision).values_list("slot", flat=True))
    available = [slot for slot in (1, 2) if slot not in used_slots]
    if not available:
        raise ApiError("EVIDENCE_LIMIT", "This source revision already has its permitted evidence objects.", 409)
    evidence_id = uuid.uuid4()
    try:
        envelope = {"purpose": binding["purpose"], "id": str(evidence_id),
            "actor_id": str(actor.id), "revision_id": str(revision.id), "operation_id": str(operation_id),
            "media_type": media_type, "filename": filename, "bytes_base64": base64.b64encode(data).decode("ascii")}
        if capture is not None:
            envelope["capture"] = capture
        ciphertext = encrypt(envelope)
    except Exception:
        raise ApiError("EVIDENCE_UNAVAILABLE", "Evidence remains private. Retry the same operation later.", 503) from None
    item = PrivateEvidence.objects.create(id=evidence_id, organization=org, revision=revision,
        uploaded_by=actor, operation_id=operation_id, request_hash=request_hash,
        payload_ciphertext=ciphertext, media_type=media_type, byte_size=len(data), slot=available[0])
    audit.record(org.id, actor, "EVIDENCE_QUARANTINED", item.id, operation_id=str(operation_id), revision_no=revision.revision_no)
    return metadata(item), True


@transaction.atomic
def evidence_metadata(user, evidence_id):
    # Lock identity before the lookup; never expose guessed object identity.
    try:
        actor, org = lock_identity(user)
    except ApiError:
        raise missing() from None
    link = PrivateEvidence.objects.filter(pk=evidence_id, organization=org).values("revision_id").first()
    if link is None:
        raise missing()
    actor, org, _, _ = _lock_revision(actor, link["revision_id"])
    item = PrivateEvidence.objects.filter(pk=evidence_id, revision_id=link["revision_id"], organization=org).first()
    if item is None:
        raise missing()
    result = metadata(item)
    audit.record(org.id, actor, "EVIDENCE_METADATA_READ", item.id)
    return result
