from io import BytesIO

from django.db import transaction
from django.utils import timezone
from rest_framework.response import Response
from rest_framework import serializers

from apps.audit import service as audit
from apps.operations import health
from apps.operations.views import BusinessView

from . import services
from .serializers import CreateUserSerializer, PasswordSerializer, UpdateUserSerializer
from apps.operations.serializers import StrictSerializer
from apps.operations.parsers import BoundedJSONParser
from apps.scopes.models import AdminAuthority
from . import integration_services


class IntegrationRequestSerializer(StrictSerializer):
    operation_id = serializers.UUIDField()
    channel_id = serializers.UUIDField()
    profile_ceiling = serializers.ChoiceField(choices=["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"], error_messages={"invalid_choice": "Choose a supported profile."})
    label = serializers.CharField(max_length=80, trim_whitespace=False)
    expires_at = serializers.DateTimeField()

    def validate_expires_at(self, value):
        from django.utils.dateparse import parse_datetime
        from django.utils import timezone
        raw = self.raw_input.get("expires_at")
        try:
            stamp = parse_datetime(raw) if isinstance(raw, str) else None
        except ValueError:
            stamp = None
        if stamp is None or timezone.is_naive(stamp):
            raise serializers.ValidationError("Use a timezone-aware expiry.")
        return value


class EmptyIntegrationSerializer(StrictSerializer):
    pass


class IntegrationRequestParser(BoundedJSONParser):
    def parse(self, stream, media_type=None, parser_context=None):
        raw = stream.read(20 * 1024 + 1)
        value = super().parse(BytesIO(raw), media_type, parser_context)
        parser_context["request"].integration_raw_body = raw.decode("utf-8")
        return value


class IntegrationClientsView(BusinessView):
    parser_classes = [IntegrationRequestParser]

    def get(self, request):
        return Response(integration_services.administration_state(request.user, request.query_params))

    def post(self, request):
        self.forbid_filters(request)
        serializer = IntegrationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.check_key(request, serializer.validated_data["operation_id"])
        result, created = integration_services.request_client(request.user, serializer.validated_data, request.integration_raw_body)
        return Response(result, status=201 if created else 200)


class IntegrationMutationView(BusinessView):
    operation = None

    def post(self, request, object_id):
        self.forbid_filters(request)
        serializer = EmptyIntegrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = self.operation(request.user, object_id)
        if isinstance(result, tuple):
            result, _ = result
        return Response(result)


class IntegrationApproveView(IntegrationMutationView):
    operation = staticmethod(integration_services.approve_client)


class IntegrationCollectView(IntegrationMutationView):
    operation = staticmethod(integration_services.collect_client)


class IntegrationRevokeView(IntegrationMutationView):
    operation = staticmethod(integration_services.revoke_client)


class ContextView(BusinessView):
    def get(self, request):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = services.administrator(request.user)
            result = services.context(org)
            authorities = list(AdminAuthority.objects.filter(
                organization=org, user=actor, active=True,
                kind__in=["POLICY", "INTEGRATION"],
            ).order_by("kind").values_list("kind", flat=True))
            if authorities:
                result["authorities"] = authorities
            return Response(result)


class HealthView(BusinessView):
    """Read-only operator health for the administrator's organization: counts and ages only."""
    def get(self, request):
        self.forbid_filters(request)
        with transaction.atomic():
            actor, org = services.administrator(request.user)
            result = health.organization_health(org.id, timezone.now())
            audit.record(org.id, actor, "OPERATIONS_HEALTH_READ")
            return Response(result)


class UsersView(BusinessView):
    def get(self, request):
        with transaction.atomic():
            _, org = services.administrator(request.user)
            return Response(services.list_users(org, request.query_params))

    def post(self, request):
        self.forbid_filters(request)
        serializer = CreateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(services.create_user(request.user, serializer.validated_data), status=201)


class UserView(BusinessView):
    def patch(self, request, user_id):
        self.forbid_filters(request)
        serializer = UpdateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(services.update_user(request.user, user_id, serializer.validated_data))


class PasswordView(BusinessView):
    def post(self, request, user_id):
        self.forbid_filters(request)
        serializer = PasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(services.reset_password(request.user, user_id, serializer.validated_data))
