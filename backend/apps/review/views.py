from rest_framework.response import Response

from apps.operations.serializers import BatchDecisionSerializer, WithdrawalSerializer
from apps.operations.views import BusinessView
from apps.publications.services import withdraw_report

from .services import candidate_set, decide_batch


class CandidateSetView(BusinessView):
    def get(self, request, revision_id):
        self.forbid_filters(request)
        return Response(candidate_set(request.user, revision_id))


class BatchDecisionView(BusinessView):
    def post(self, request, revision_id):
        self.forbid_filters(request)
        serializer = BatchDecisionSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_key(request, serializer.validated_data["operation_id"])
        return Response(decide_batch(request.user, revision_id, serializer.validated_data, request.data))


class WithdrawalView(BusinessView):
    def post(self, request, report_id):
        self.forbid_filters(request)
        serializer = WithdrawalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_key(request, serializer.validated_data["operation_id"])
        return Response(withdraw_report(request.user, report_id, serializer.validated_data, request.data))
