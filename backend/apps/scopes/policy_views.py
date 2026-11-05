"""Private POLICY-holder endpoints; mounted only in the serialized URL task."""
from rest_framework import serializers
from rest_framework.response import Response

from apps.audit import service as audit
from apps.operations.serializers import StrictSerializer
from apps.operations.views import BusinessView
from . import policy


class ProposalSerializer(StrictSerializer):
    operation_id = serializers.UUIDField()
    kind = serializers.ChoiceField(choices=["ACTIVATE", "DEACTIVATE"], error_messages={"invalid_choice": "Choose one of the listed values."})
    target_policy_id = serializers.UUIDField()
    target_rules_hash = serializers.RegexField(r"^[a-f0-9]{64}$")
    expected_active_policy_id = serializers.UUIDField(allow_null=True)


class EmptySerializer(StrictSerializer):
    pass


class PolicyView(BusinessView):
    def handle_exception(self, exc):
        if (getattr(self.request.user, "is_authenticated", False)
                and getattr(exc, "status_code", 500) in {403, 404, 409}):
            audit.record(self.request.user.organization_id, self.request.user, "POLICY_DENIED",
                         outcome="DENIED", error_code=getattr(exc, "safe_body", {}).get("code", "ACCESS_DENIED"))
        return super().handle_exception(exc)


class PolicyStateView(PolicyView):
    def get(self, request):
        self.forbid_filters(request)
        return Response(policy.state(request.user))


class PolicyProposalView(PolicyView):
    def post(self, request):
        self.forbid_filters(request)
        serializer = ProposalSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_key(request, serializer.validated_data["operation_id"])
        result, created = policy.propose(request.user, serializer.validated_data, request.data)
        return Response(result, status=201 if created else 200)


class PolicyApplyView(PolicyView):
    def post(self, request, proposal_id):
        self.forbid_filters(request)
        serializer = EmptySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result, created = policy.apply(request.user, proposal_id)
        return Response(result, status=201 if created else 200)
