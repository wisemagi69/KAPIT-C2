"""Private mobile image seam; retain original device claims through each commit."""
import uuid

from django.db import transaction
from django.utils import timezone
from rest_framework.response import Response

from apps.accounts.mobile_services import lock_mobile_identity
from apps.accounts.mobile_views import MobileView
from apps.audit import service as audit
from .errors import ApiError
from .evidence import accept_evidence, authorize_upload
from .evidence_capture import CaptureError, parse_capture_header
from .evidence_policy import CODES
from .evidence_processing import strict_original
from .evidence_retrieval import _locked, validation_status
from .evidence_views import BoundedEvidenceParser


def _locked_mobile(claims, evidence_id):
    actor, _, _, _ = lock_mobile_identity(claims)
    return _locked(actor, evidence_id)


@transaction.atomic
def authorize_mobile_upload(claims, revision_id):
    actor, _, _, _ = lock_mobile_identity(claims)
    authorize_upload(actor, revision_id)


@transaction.atomic
def accept_mobile_evidence(claims, revision_id, operation_id, data, media_type, filename, capture):
    actor, _, _, _ = lock_mobile_identity(claims)
    if media_type != "image/jpeg" or filename != "capture.jpg":
        raise ApiError("INVALID_EVIDENCE", "This evidence could not be accepted.")
    result = accept_evidence(actor, revision_id, operation_id, data, media_type, filename, capture=capture)
    # Access tokens/leases may expire during body/envelope work. Recheck the
    # original claims rather than silently replacing them with current identity.
    actor, _, _, _ = lock_mobile_identity(claims)
    authorize_upload(actor, revision_id)
    return result


@transaction.atomic
def mobile_capture(claims, evidence_id):
    actor, org, item = _locked_mobile(claims, evidence_id)
    _, _, capture = strict_original(item)
    audit.record(org.id, actor, "EVIDENCE_CAPTURE_READ", item.id)
    _locked_mobile(claims, evidence_id)
    return {"capture": capture}


def mobile_validation_status(claims, evidence_id):
    # validation_status owns the current-tools fence before its own durable DB
    # transaction. Never wrap it in our identity transaction.
    with transaction.atomic():
        actor, _, _ = _locked_mobile(claims, evidence_id)
    result, failure = None, None
    try:
        result = validation_status(actor, evidence_id)
    except Exception as error:
        failure = error
    with transaction.atomic():
        actor, org, item = _locked_mobile(claims, evidence_id)
        # A device/scope denial after the service wins even over service failure.
        if failure is not None:
            raise failure
        if (type(result) is not dict or set(result) != {"evidence_id", "state", "validation_code", "can_download"}
                or result["evidence_id"] != str(item.id) or type(result["evidence_id"]) is not str
                or type(result["state"]) is not str or result["state"] not in {"QUARANTINED", "REJECTED_PRIVATE", "VALIDATED_PRIVATE"}
                or type(result["validation_code"]) is not str or result["validation_code"] not in CODES | {"DECODER_REQUIRED", "VALIDATION_COMPLETE"}
                or type(result["can_download"]) is not bool
                or (result["can_download"] and (result["state"] != "VALIDATED_PRIVATE" or result["validation_code"] != "VALIDATION_COMPLETE"))):
            raise ApiError("EVIDENCE_UNAVAILABLE", "Private evidence is unavailable. Retry later.", 503)
        response = {key: result[key] for key in ("evidence_id", "state", "validation_code", "can_download")}
        audit.record(org.id, actor, "MOBILE_EVIDENCE_VALIDATION_READ", item.id)
        _locked_mobile(claims, evidence_id)
        return response


class MobileEvidenceUploadView(MobileView):
    parser_classes = [BoundedEvidenceParser]
    http_method_names = ["post"]

    def post(self, request, revision_id):
        authorize_mobile_upload(request.auth, revision_id)
        raw_operation = request.headers.get("Idempotency-Key", "")
        try:
            operation_id = uuid.UUID(raw_operation)
        except (ValueError, TypeError, AttributeError):
            raise ApiError("INVALID_EVIDENCE_OPERATION", "Send a canonical UUID Idempotency-Key.") from None
        if str(operation_id) != raw_operation:
            raise ApiError("INVALID_EVIDENCE_OPERATION", "Send a canonical UUID Idempotency-Key.")
        try:
            capture = parse_capture_header(request.headers.get("X-Evidence-Capture"), now=timezone.now())
        except CaptureError:
            raise ApiError("INVALID_EVIDENCE_CAPTURE", "This capture metadata could not be accepted.") from None
        result, created = accept_mobile_evidence(request.auth, revision_id, operation_id, request.data,
            request.content_type, request.headers.get("X-Evidence-Filename", ""), capture)
        return Response(result, status=201 if created else 200)


class MobileEvidenceCaptureView(MobileView):
    http_method_names = ["get"]

    def get(self, request, evidence_id):
        return Response(mobile_capture(request.auth, evidence_id))


class MobileEvidenceValidationView(MobileView):
    http_method_names = ["get"]

    def get(self, request, evidence_id):
        return Response(mobile_validation_status(request.auth, evidence_id))
