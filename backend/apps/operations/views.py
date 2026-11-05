from django.db import transaction
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit import service as audit
from apps.publications import selectors as publications
from apps.reports.activity import report_activity_page
from apps.reports.crypto import decrypt, source_payload
from apps.reports.selectors import authorized_receipt, can_correct, own_reports, review_reports, revision_history, source_report, summary
from apps.reports.services import accept_operation, receipt_body, web_can_correct
from apps.reports.workflow import revision_workflow
from apps.review.services import decide, review_variant, verified_candidate
from apps.scopes.access import lock_identity, require_role

from .errors import ApiError, missing
from .parsers import BoundedJSONParser
from .pagination import report_filters
from .serializers import DecisionSerializer, OperationSerializer, WebOperationSerializer
from .worker import binding_for


class BusinessView(APIView):
    parser_classes = [BoundedJSONParser]

    def handle_exception(self, exc):
        # Denial metadata is recorded after the failed service transaction rolls
        # back. Guessed object IDs and submitted data are deliberately excluded.
        if getattr(self.request.user, "is_authenticated", False) and getattr(exc, "status_code", 500) in {403, 404, 409}:
            audit.record(self.request.user.organization_id, self.request.user, "ACCESS_DENIED", outcome="DENIED", error_code=getattr(exc, "safe_body", {}).get("code", "ACCESS_DENIED"))
        return super().handle_exception(exc)

    def forbid_filters(self, request):
        if request.query_params:
            raise ApiError("UNSUPPORTED_FILTER", "Filters are not supported by this endpoint.")

    def check_key(self, request, operation_id):
        if request.headers.get("Idempotency-Key") != str(operation_id):
            raise ApiError("INVALID_IDEMPOTENCY_KEY", "The request key must match its operation identifier.")


class OperationsView(BusinessView):
    def post(self, request):
        serializer = WebOperationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_key(request, serializer.validated_data["operation_id"])
        result, created = accept_operation(request.user, serializer.validated_data, request.data)
        return Response(result, status=201 if created else 200)


class ReceiptView(BusinessView):
    def get(self, request, operation_id):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, _ = lock_identity(request.user)
            require_role(actor, "submitter")
            return Response(authorized_receipt(actor, operation_id))


class ReportsView(BusinessView):
    def get(self, request):
        options = report_filters(request.query_params, "ALL")
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            require_role(actor, "submitter")
            result = report_activity_page(own_reports(actor), options, summary)
            audit.record(org.id, actor, "SOURCE_LIST_READ")
            return Response(result)


class RevisionView(BusinessView):
    def get(self, request, report_id, revision_no):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            report = source_report(actor, report_id)
            revision = report.revisions.filter(revision_no=revision_no).first()
            if revision is None:
                raise missing()
            result = {"report": summary(report, revision), "payload": source_payload(revision), "receipt": receipt_body(revision),
                      "can_correct": web_can_correct(actor, report, revision), "history": revision_history(report),
                      "workflow": revision_workflow(report, revision, org)}
            if revision.correction_reason_ciphertext is not None:
                result["correction_reason"] = decrypt(revision.correction_reason_ciphertext)
            audit.record(org.id, actor, "ORIGINAL_READ", revision.id)
            return Response(result)


class QueueView(BusinessView):
    def get(self, request):
        options = report_filters(request.query_params, "AWAITING_REVIEW")
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            require_role(actor, "reviewer")
            result = report_activity_page(review_reports(actor), options, summary)
            audit.record(org.id, actor, "REVIEW_QUEUE_READ")
            return Response(result)


class ReviewView(BusinessView):
    def get(self, request, variant_id):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            require_role(actor, "reviewer")
            variant = review_variant(actor, variant_id)
            if variant.revision.report.author_id == actor.id or variant.revision.submitted_by_id == actor.id:
                raise ApiError("SELF_APPROVAL_DENIED", "The submitting author cannot review this source.", 403)
            source = verified_candidate(variant, org)
            result = {"report": summary(variant.revision.report, variant.revision), "source": source,
                      "candidate": variant.projection, "warnings": variant.warnings, "binding": binding_for(variant)}
            audit.record(org.id, actor, "REVIEW_READ", variant.id)
            return Response(result)


class DecisionView(BusinessView):
    def post(self, request, variant_id):
        serializer = DecisionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_key(request, serializer.validated_data["operation_id"])
        return Response(decide(request.user, variant_id, serializer.validated_data, request.data))


class FeedView(BusinessView):
    def get(self, request, channel_id):
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            result = publications.feed(actor, org, channel_id, request.query_params)
            audit.record(org.id, actor, "RECIPIENT_FEED_READ")
            return Response({**result, "refreshed_at": timezone.now().isoformat()})


class PublicationView(BusinessView):
    def get(self, request, publication_id):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = lock_identity(request.user)
            result = publications.detail(actor, org, publication_id)
            audit.record(org.id, actor, "PUBLICATION_READ", publication_id)
            return Response(result)
