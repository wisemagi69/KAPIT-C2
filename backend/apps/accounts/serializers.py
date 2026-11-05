from django.contrib.auth.validators import UnicodeUsernameValidator
from rest_framework import serializers

from apps.operations.serializers import StrictSerializer

from .models import User


class AssignmentSerializer(StrictSerializer):
    display_name = serializers.CharField(max_length=120)
    role = serializers.ChoiceField(choices=User.Role.values, error_messages={"invalid_choice": "Choose a supported role."})
    is_active = serializers.BooleanField()
    unit_id = serializers.UUIDField(allow_null=True)
    channel_id = serializers.UUIDField(allow_null=True)
    profile_ceiling = serializers.ChoiceField(choices=["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"], required=False)

    def to_internal_value(self, data):
        if isinstance(data, dict):
            if "is_active" in data and not isinstance(data["is_active"], bool):
                raise serializers.ValidationError({"is_active": ["Use true or false."]})
            if "expected_permission_version" in data and (isinstance(data["expected_permission_version"], bool) or not isinstance(data["expected_permission_version"], int)):
                raise serializers.ValidationError({"expected_permission_version": ["Use an integer version."]})
            # StrictSerializer's string requirement deliberately excludes valid
            # explicit nulls in assignment UUID fields.
            for name in ("unit_id", "channel_id"):
                if name in data and data[name] is not None and not isinstance(data[name], str):
                    raise serializers.ValidationError({name: ["Use an identifier or null."]})
        return super().to_internal_value(data)


class CreateUserSerializer(AssignmentSerializer):
    username = serializers.CharField(max_length=150, trim_whitespace=False, validators=[UnicodeUsernameValidator()])
    password = serializers.CharField(min_length=12, max_length=128, trim_whitespace=False, write_only=True)

    def validate_username(self, value):
        normalized = User.normalize_username(value)
        UnicodeUsernameValidator()(normalized)
        if len(normalized) > 150:
            raise serializers.ValidationError("Use at most 150 characters.")
        return normalized


class UpdateUserSerializer(AssignmentSerializer):
    expected_permission_version = serializers.IntegerField(min_value=0, max_value=2147483647)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            field.required = name == "expected_permission_version"

    def validate(self, attrs):
        if len(attrs) < 2:
            raise serializers.ValidationError({"non_field_errors": ["Choose at least one account field to update."]})
        return attrs


class PasswordSerializer(StrictSerializer):
    password = serializers.CharField(min_length=12, max_length=128, trim_whitespace=False, write_only=True)
    expected_permission_version = serializers.IntegerField(min_value=0, max_value=2147483647)

    def validate_expected_permission_version(self, value):
        raw = self.initial_data.get("expected_permission_version")
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise serializers.ValidationError("Use an integer version.")
        return value


class ChangePasswordSerializer(StrictSerializer):
    current_password = serializers.CharField(min_length=1, max_length=128, trim_whitespace=False, write_only=True)
    new_password = serializers.CharField(min_length=12, max_length=128, trim_whitespace=False, write_only=True)
