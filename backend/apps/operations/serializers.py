from datetime import timedelta

from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework import serializers


class StrictSerializer(serializers.Serializer):
    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError({"non_field_errors": ["Expected an object."]})
        unknown = set(data) - set(self.fields)
        if unknown:
            # Unknown field names are untrusted and are never reflected.
            raise serializers.ValidationError({"non_field_errors": ["Unknown fields are not accepted."]})
        for name, field in self.fields.items():
            if name in data and isinstance(field, (serializers.CharField, serializers.ChoiceField, serializers.UUIDField)) and not isinstance(data[name], str) and not (data[name] is None and field.allow_null):
                raise serializers.ValidationError({name: ["Use a text value."]})
        # Nested serializers have no initial_data; keep the raw object for type checks.
        self.raw_input = data
        return super().to_internal_value(data)


class LoginSerializer(StrictSerializer):
    username = serializers.CharField(max_length=150, trim_whitespace=False)
    password = serializers.CharField(max_length=128, trim_whitespace=False, write_only=True)


class PayloadSerializer(StrictSerializer):
    observed_at = serializers.CharField(max_length=50, trim_whitespace=False)
    category = serializers.ChoiceField(choices=["INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"], error_messages={"invalid_choice": "Choose one of the listed values."})
    urgency = serializers.ChoiceField(choices=["ROUTINE", "PRIORITY"], error_messages={"invalid_choice": "Choose one of the listed values."})
    area_label = serializers.ChoiceField(choices=["Area A", "Area B", "Area C"], error_messages={"invalid_choice": "Choose one of the listed values."})
    site_label = serializers.CharField(max_length=100, trim_whitespace=False)
    reporter_label = serializers.CharField(max_length=100, trim_whitespace=False)
    narrative = serializers.CharField(max_length=2000, trim_whitespace=False)
    assistance_requested = serializers.ChoiceField(choices=["Repair assistance", "Inspection", "Replacement parts"], error_messages={"invalid_choice": "Choose one of the listed values."})

    def validate_observed_at(self, value):
        try:
            stamp = parse_datetime(value)
        except ValueError:
            stamp = None
        if stamp is None or timezone.is_naive(stamp):
            raise serializers.ValidationError("Use a timezone-aware date and time.")
        if stamp > timezone.now() + timedelta(minutes=5):
            raise serializers.ValidationError("Observation time cannot be more than five minutes ahead.")
        return value


class OperationSerializer(StrictSerializer):
    operation_id = serializers.UUIDField()
    report_id = serializers.UUIDField()
    expected_revision = serializers.IntegerField(min_value=0)
    template_version = serializers.ChoiceField(choices=["demo-maintenance-v1"], error_messages={"invalid_choice": "Choose one of the listed values."})
    payload = PayloadSerializer()

    def validate_expected_revision(self, value):
        raw = self.raw_input.get("expected_revision")
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise serializers.ValidationError("Use an integer revision number.")
        return value


class BindingSerializer(StrictSerializer):
    revision_id = serializers.UUIDField()
    revision_no = serializers.IntegerField(min_value=1)
    candidate_hash = serializers.RegexField(r"^[a-f0-9]{64}$")
    policy_version = serializers.CharField(max_length=40, trim_whitespace=False)
    policy_hash = serializers.RegexField(r"^[a-f0-9]{64}$")
    profile = serializers.ChoiceField(choices=["DEMO-REDUCED"], error_messages={"invalid_choice": "Choose one of the listed values."})
    channel_ids = serializers.ListField(child=serializers.UUIDField(), min_length=1, max_length=1)

    def validate_revision_no(self, value):
        raw = self.raw_input.get("revision_no")
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise serializers.ValidationError("Use an integer revision number.")
        return value


class DecisionSerializer(StrictSerializer):
    operation_id = serializers.UUIDField()
    action = serializers.ChoiceField(choices=["APPROVE", "RETURN", "REJECT"], error_messages={"invalid_choice": "Choose one of the listed values."})
    expected = BindingSerializer()
    reason = serializers.CharField(max_length=500, allow_blank=True, trim_whitespace=False)

    def validate(self, attrs):
        if attrs["action"] in {"RETURN", "REJECT"} and not attrs["reason"].strip():
            raise serializers.ValidationError({"reason": ["A private reason is required."]})
        return attrs


class WebOperationSerializer(OperationSerializer):
    correction_reason = serializers.CharField(max_length=500, required=False, allow_null=True, allow_blank=True, trim_whitespace=False)

    def validate(self, attrs):
        if attrs["expected_revision"] > 0 and not (attrs.get("correction_reason") or "").strip():
            raise serializers.ValidationError({"correction_reason": ["A private correction reason is required."]})
        if attrs["expected_revision"] == 0 and attrs.get("correction_reason") is not None:
            raise serializers.ValidationError({"correction_reason": ["Use a correction reason only for a new source revision."]})
        return attrs


class SetCandidateBindingSerializer(StrictSerializer):
    variant_id = serializers.UUIDField()
    profile = serializers.ChoiceField(choices=["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"], error_messages={"invalid_choice": "Choose a listed profile."})
    candidate_hash = serializers.RegexField(r"^[a-f0-9]{64}$")
    channel_ids = serializers.ListField(child=serializers.UUIDField(), min_length=1, max_length=100)

    def validate_channel_ids(self, value):
        if len(set(value)) != len(value):
            raise serializers.ValidationError("Duplicate channels are not accepted.")
        return value


class CandidateSetBindingSerializer(StrictSerializer):
    revision_id = serializers.UUIDField()
    revision_no = serializers.IntegerField(min_value=1)
    policy_version = serializers.CharField(max_length=40, trim_whitespace=False)
    policy_hash = serializers.RegexField(r"^[a-f0-9]{64}$")
    scope_context_hash = serializers.RegexField(r"^[a-f0-9]{64}$", allow_null=True)
    candidates = SetCandidateBindingSerializer(many=True, min_length=1, max_length=3)

    def validate_revision_no(self, value):
        if type(self.raw_input.get("revision_no")) is not int:
            raise serializers.ValidationError("Use an integer revision number.")
        return value

    def validate_candidates(self, value):
        if len({row["variant_id"] for row in value}) != len(value) or len({row["profile"] for row in value}) != len(value):
            raise serializers.ValidationError("Duplicate candidates are not accepted.")
        return value


class BatchDecisionSerializer(StrictSerializer):
    operation_id = serializers.UUIDField()
    action = serializers.ChoiceField(choices=["APPROVE", "RETURN", "REJECT"], error_messages={"invalid_choice": "Choose a listed action."})
    approve_profiles = serializers.ListField(child=serializers.ChoiceField(choices=["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"], error_messages={"invalid_choice": "Choose a listed profile."}), max_length=3)
    expected = CandidateSetBindingSerializer()
    reason = serializers.CharField(max_length=500, allow_null=True, allow_blank=True, trim_whitespace=False)

    def validate(self, attrs):
        profiles = attrs["approve_profiles"]
        if len(set(profiles)) != len(profiles) or (attrs["action"] == "APPROVE" and not profiles) or (attrs["action"] != "APPROVE" and profiles):
            raise serializers.ValidationError({"approve_profiles": ["Choose a unique nonempty subset only for approval."]})
        if attrs["action"] != "APPROVE" and not (attrs["reason"] or "").strip():
            raise serializers.ValidationError({"reason": ["A private reason is required."]})
        return attrs


class WithdrawalSerializer(StrictSerializer):
    operation_id = serializers.UUIDField()
    expected_revision_no = serializers.IntegerField(min_value=1)
    reason = serializers.CharField(max_length=500, trim_whitespace=False)

    def validate_expected_revision_no(self, value):
        if type(self.raw_input.get("expected_revision_no")) is not int:
            raise serializers.ValidationError("Use an integer revision number.")
        return value

    def validate_reason(self, value):
        if not value.strip():
            raise serializers.ValidationError("A private reason is required.")
        return value
