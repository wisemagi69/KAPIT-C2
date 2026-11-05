"""Dedicated bounded raw-image parser; existing 20-KiB JSON parser is unchanged."""
import uuid

from django.http import HttpResponse
from django.db import transaction
from django.utils import timezone

from rest_framework.parsers import BaseParser
from rest_framework.response import Response

from .errors import ApiError, missing
from .evidence import LIMITS, accept_evidence, authorize_upload, evidence_metadata
from .evidence_retrieval import private_evidence_download, validation_status
from .evidence_capture import CaptureError, parse_capture_header
from .views import BusinessView


class BoundedEvidenceParser(BaseParser):
    media_type = "*/*"

    def parse(self, stream, media_type=None, parser_context=None):
        data = stream.read(LIMITS.max_bytes + 1)
        if len(data) > LIMITS.max_bytes:
            raise ApiError("REQUEST_TOO_LARGE", "Evidence must be at most 5 MiB.", 413)
        return data


class EvidenceUploadView(BusinessView):
    parser_classes = [BoundedEvidenceParser]

    def post(self, request, revision_id):
        self.forbid_filters(request)
        authorize_upload(request.user, revision_id)
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
        result, created = accept_evidence(request.user, revision_id, operation_id, request.data,
            request.content_type, request.headers.get("X-Evidence-Filename", ""), capture=capture)
        return Response(result, status=201 if created else 200)


class EvidenceCaptureView(BusinessView):
    http_method_names = ["get"]

    def get(self, request, evidence_id):
        from .evidence_retrieval import _locked
        from .evidence_processing import strict_original
        from apps.audit import service as audit
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org, item = _locked(request.user, evidence_id)
            _, _, capture = strict_original(item)
            audit.record(org.id, actor, "EVIDENCE_CAPTURE_READ", item.id)
            _locked(actor, evidence_id)
            response = Response({"capture": capture})
        response["Cache-Control"] = "private, no-store"
        return response


class EvidenceMetadataView(BusinessView):
    def get(self, request, evidence_id):
        self.forbid_filters(request)
        return Response(evidence_metadata(request.user, evidence_id))


class EvidenceDownloadView(BusinessView):
    http_method_names = ["get"]

    def get(self, request, evidence_id):
        if request.query_params or any(name in request.headers for name in
                ("Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since")):
            raise missing()
        data = private_evidence_download(request.user, evidence_id)
        response = HttpResponse(data, content_type="image/png")
        response["Content-Disposition"] = 'attachment; filename="evidence.png"'
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response


class EvidenceValidationStatusView(BusinessView):
    http_method_names = ["get"]

    def get(self, request, evidence_id):
        self.forbid_filters(request)
        response = Response(validation_status(request.user, evidence_id))
        response["Cache-Control"] = "no-store"
        return response
