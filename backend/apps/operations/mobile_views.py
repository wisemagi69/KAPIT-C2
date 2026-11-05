from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.mobile_protocol import config, scalar_text
from apps.accounts.mobile_views import MobileView
from apps.reports.mobile_services import accept_mobile_operation, mobile_receipt, mobile_reports, mobile_revision

from .errors import ApiError, missing
from .mobile_serializers import MobileOperationSerializer
from .parsers import BoundedJSONParser


class MobileOperationParser(BoundedJSONParser):
    def parse(self, *args, **kwargs):
        result = super().parse(*args, **kwargs)
        try:
            scalar_text(result)
        except UnicodeError:
            # Frozen source fixtures treat valid JSON with an escaped lone
            # surrogate as a schema error; malformed UTF-8/JSON stays 400.
            raise ApiError("VALIDATION_ERROR", "Check the highlighted fields.", 422,
                errors={"non_field_errors": ["Use valid Unicode text."]}) from None
        except RecursionError:
            raise ApiError("INVALID_JSON", "Send one valid JSON object.") from None
        return result


class MobileOperationsView(MobileView):
    parser_classes = [MobileOperationParser]

    def post(self, request):
        serializer = MobileOperationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if request.headers.get("Idempotency-Key") != str(serializer.validated_data["operation_id"]):
            raise ApiError("INVALID_IDEMPOTENCY_KEY", "The request key must match its operation identifier.")
        result, created = accept_mobile_operation(request.auth, serializer.validated_data, request.data)
        return Response(result, status=201 if created else 200)


class MobileReceiptView(MobileView):
    def get(self, request, operation_id):
        return Response(mobile_receipt(request.auth, operation_id))


class MobileReportsView(MobileView):
    def initial(self, request, *args, **kwargs):
        # This is the only mobile route accepting the frozen query filters.
        # Keep the same config/auth/permission checks without forbid_queries.
        config()
        APIView.initial(self, request, *args, **kwargs)

    def get(self, request):
        return Response(mobile_reports(request.auth, request.query_params))


class MobileRevisionView(MobileView):
    def get(self, request, report_id, revision_no):
        if not 1 <= revision_no <= 2147483647:
            raise missing()
        return Response(mobile_revision(request.auth, report_id, revision_no))
