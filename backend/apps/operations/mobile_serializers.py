"""Narrower mobile wire validation; historical browser input stays unchanged."""
from rest_framework import serializers

from apps.accounts.mobile_protocol import CanonicalUUIDField
from .errors import ApiError
from .serializers import OperationSerializer


class MobileOperationSerializer(OperationSerializer):
    operation_id = CanonicalUUIDField()
    report_id = CanonicalUUIDField()
    expected_revision = serializers.IntegerField(min_value=0, max_value=2147483646)
    template_version = serializers.CharField(allow_blank=True, trim_whitespace=False)

    def validate_template_version(self, value):
        if value != "demo-maintenance-v1":
            raise ApiError("TEMPLATE_UNSUPPORTED", "This report template is unavailable. Update the app before submitting.", 422)
        return value
