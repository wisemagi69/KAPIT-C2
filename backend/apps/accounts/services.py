"""Organization-scoped business administration; infrastructure flags grant nothing."""
import re

from django.contrib.auth.password_validation import MinimumLengthValidator, validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from rest_framework import serializers

from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.operations.pagination import page_result, pagination_values, query_values
from apps.scopes.access import PROFILE, eligible_channels, live_memberships, lock_identity, require_role, user_object
from apps.scopes.models import ChannelMember, ChannelSource, SharingChannel, Unit, UnitMembership

from .models import User


def administrator(user):
    actor, org = lock_identity(user)
    require_role(actor, User.Role.ADMINISTRATOR)
    return actor, org


def assignment_ids(user):
    # No source content is traversed, including for disabled accounts. Grants
    # retained from an earlier assignment are intentionally excluded.
    unit_id = channel_id = None
    if user.role in {User.Role.SUBMITTER, User.Role.REVIEWER}:
        units = list(live_memberships(user, user.role).values_list("unit_id", flat=True)[:2])
        if len(units) == 1:
            unit_id = units[0]
            channels = eligible_channels(user.organization_id, unit_id)
            channel_id = channels[0] if len(channels) == 1 else None
    elif user.role == User.Role.RECIPIENT:
        channels = list(ChannelMember.objects.filter(user=user, organization_id=user.organization_id,
                        channel__organization_id=user.organization_id, channel__active=True, active=True, revoked_at__isnull=True,
                        profile_ceiling=PROFILE).filter(Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now())).values_list("channel_id", flat=True)[:2])
        channel_id = channels[0] if len(channels) == 1 else None
    return unit_id, channel_id


def admin_user(user):
    unit_id, channel_id = assignment_ids(user)
    return {"id": str(user.id), "username": user.username, "display_name": user.display_name,
            "role": user.role, "is_active": user.is_active, "permission_version": user.permission_version,
            "unit_id": str(unit_id) if unit_id else None, "channel_id": str(channel_id) if channel_id else None}


def admin_user_m3(user):
    result = admin_user(user)
    if user.role == User.Role.RECIPIENT:
        grants = list(ChannelMember.objects.filter(user=user, organization_id=user.organization_id,
            channel__organization_id=user.organization_id, active=True, revoked_at__isnull=True, channel__active=True)
            .filter(Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now())).select_related("channel"))
        if grants and (len(grants) != 1 or grants[0].profile_ceiling != PROFILE or grants[0].channel.max_profile is not None):
            result["profile_ceiling"] = grants[0].profile_ceiling if len(grants) == 1 else None
            result["channel_id"] = str(grants[0].channel_id) if len(grants) == 1 else None
    return result


def context(org):
    def scope(value):
        return {"id": str(value.id), "code": value.code, "name": value.name, "active": value.active}
    sources = ChannelSource.objects.filter(organization=org, unit__organization=org, channel__organization=org).order_by("unit_id", "channel_id")
    return {"units": [scope(value) for value in Unit.objects.filter(organization=org).order_by("code", "id")],
            "channels": [scope(value) for value in SharingChannel.objects.filter(organization=org).order_by("code", "id")],
            "channel_sources": [{"unit_id": str(value.unit_id), "channel_id": str(value.channel_id), "active": value.active} for value in sources]}


def list_users(org, params):
    values = query_values(params, {"q", "role", "active", "page", "page_size"})
    options = pagination_values(values)
    queryset = User.objects.filter(organization=org).order_by("username", "id")
    role = values.get("role", "ALL")
    active = values.get("active", "ALL")
    if role not in {"ALL", *User.Role.values} or active not in {"true", "false", "ALL"}:
        raise ApiError("INVALID_FILTER", "Choose supported role and account status filters.")
    query = values.get("q", "").strip()
    if len(query) > 150:
        raise ApiError("INVALID_FILTER", "Account search must be at most 150 characters.")
    if query:
        queryset = queryset.filter(Q(username__icontains=query) | Q(display_name__icontains=query))
    if role != "ALL":
        queryset = queryset.filter(role=role)
    if active != "ALL":
        queryset = queryset.filter(is_active=active == "true")
    return page_result(queryset, options, admin_user_m3)


def validate_assignment(org, role, unit_id, channel_id):
    if role == User.Role.ADMINISTRATOR:
        valid = unit_id is None and channel_id is None
    elif role == User.Role.RECIPIENT:
        valid = unit_id is None and channel_id is not None and SharingChannel.objects.filter(pk=channel_id, organization=org, active=True).exists()
    else:
        channels = eligible_channels(org.id, unit_id) if unit_id is not None else []
        valid = (role in {User.Role.SUBMITTER, User.Role.REVIEWER}
                 and Unit.objects.filter(pk=unit_id, organization=org, active=True).exists()
                 and len(channels) >= 1
                 and (channel_id is None or SharingChannel.objects.filter(pk=channel_id, organization=org, active=True).exists()))
    if not valid:
        raise ApiError("INVALID_ASSIGNMENT", "Choose an eligible unit and channel for this role.", 422)


def assign_scope(user, unit_id, channel_id, profile_ceiling=PROFILE):
    # Keep every retired row; later reassignments create new grants. Permission
    # version and scope changes commit together with the audit record.
    now = timezone.now()
    UnitMembership.objects.filter(user=user, organization_id=user.organization_id, active=True).update(active=False, valid_until=now)
    ChannelMember.objects.filter(user=user, organization_id=user.organization_id, active=True).update(active=False, revoked_at=now)
    if user.role in {User.Role.SUBMITTER, User.Role.REVIEWER}:
        UnitMembership.objects.create(organization_id=user.organization_id, user=user, role=user.role, unit_id=unit_id)
    elif user.role == User.Role.RECIPIENT:
        ChannelMember.objects.create(organization_id=user.organization_id, user=user, channel_id=channel_id, profile_ceiling=profile_ceiling)


def assignment_profile(org, role, channel_id, data, default=PROFILE):
    from apps.reports.projection import PROFILE_RANK
    value = data.get("profile_ceiling", default)
    if role != User.Role.RECIPIENT:
        if "profile_ceiling" in data:
            raise ApiError("INVALID_ASSIGNMENT", "Profile ceilings apply to recipients only.", 422)
        return PROFILE
    channel = SharingChannel.objects.filter(organization=org, pk=channel_id, active=True).first()
    if channel is None or value not in PROFILE_RANK or PROFILE_RANK[value] > PROFILE_RANK[channel.max_profile or PROFILE]:
        raise ApiError("INVALID_ASSIGNMENT", "Choose an eligible recipient profile.", 422)
    return value


def validate_new_password(password, user, field="password"):
    try:
        MinimumLengthValidator(12).validate(password, user)
        # Repeated units such as "passwordpassword" evade the common-password list.
        if re.fullmatch(r"(.+?)\1+", password, flags=re.DOTALL):
            raise ValidationError("repeated")
        validate_password(password, user)
    except ValidationError:
        # Never reflect a password, username similarity value or validator detail.
        raise serializers.ValidationError({field: ["Use at least 12 characters and avoid common, numeric, or account-related passwords."]}) from None


def target_user(actor, org, user_id, expected_version):
    target = User.objects.select_for_update().filter(pk=user_id, organization=org).first()
    if target is None:
        raise missing()
    if target.id == actor.id:
        raise ApiError("SELF_ADMINISTRATION_DENIED", "Another administrator must change your account.", 403)
    if target.permission_version != expected_version:
        raise ApiError("STALE_PERMISSIONS", "This account changed. Reload it before saving.", 409)
    return target


@transaction.atomic
def create_user(user, data):
    actor, org = administrator(user)
    validate_assignment(org, data["role"], data["unit_id"], data["channel_id"])
    profile = assignment_profile(org, data["role"], data["channel_id"], data)
    target = User(organization=org, username=data["username"], display_name=data["display_name"], role=data["role"], is_active=data["is_active"])
    validate_new_password(data["password"], target)
    target.set_password(data["password"])
    try:
        with transaction.atomic():
            target.save(force_insert=True)
    except IntegrityError:
        raise ApiError("ACCOUNT_UNAVAILABLE", "An account could not be created with this username.", 409) from None
    assign_scope(target, data["unit_id"], data["channel_id"], profile)
    audit.record(org.id, actor, "ACCOUNT_CREATED", target.id)
    return admin_user_m3(target)


@transaction.atomic
def update_user(user, user_id, data):
    actor, org = administrator(user)
    target = target_user(actor, org, user_id, data["expected_permission_version"])
    from apps.scopes.authority import protect_authority
    if "role" in data or data.get("is_active") is False:
        protect_authority(target)
    current_unit, current_channel = assignment_ids(target)
    current_profile = PROFILE
    if target.role == User.Role.RECIPIENT:
        grants = list(ChannelMember.objects.filter(user=target, organization=org, active=True,
            revoked_at__isnull=True, channel__active=True).filter(Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now()))[:2])
        if len(grants) == 1:
            current_channel, current_profile = grants[0].channel_id, grants[0].profile_ceiling
    unit_id, channel_id = data.get("unit_id", current_unit), data.get("channel_id", current_channel)
    role, active = data.get("role", target.role), data.get("is_active", target.is_active)
    validate_assignment(org, role, unit_id, channel_id)
    profile = assignment_profile(org, role, channel_id, data, current_profile)
    if target.role == User.Role.ADMINISTRATOR and target.is_active and (role != target.role or not active):
        if not User.objects.filter(organization=org, role=User.Role.ADMINISTRATOR, is_active=True).exclude(pk=target.pk).exists():
            raise ApiError("LAST_ADMINISTRATOR", "Keep at least one active administrator.", 409)
    scope_changed = (role, active, unit_id, channel_id, profile) != (target.role, target.is_active, current_unit, current_channel, current_profile)
    target.display_name = data.get("display_name", target.display_name)
    target.role, target.is_active = role, active
    target.permission_version += 1
    target.save(update_fields=["display_name", "role", "is_active", "permission_version"])
    if scope_changed:
        assign_scope(target, unit_id, channel_id, profile)
    audit.record(org.id, actor, "ACCOUNT_ACCESS_CHANGED", target.id)
    return admin_user_m3(target)


@transaction.atomic
def reset_password(user, user_id, data):
    actor, org = administrator(user)
    target = target_user(actor, org, user_id, data["expected_permission_version"])
    from apps.scopes.authority import protect_authority
    protect_authority(target)
    validate_new_password(data["password"], target)
    target.set_password(data["password"])
    target.permission_version += 1
    target.save(update_fields=["password", "permission_version"])
    audit.record(org.id, actor, "ACCOUNT_PASSWORD_RESET", target.id)
    return admin_user_m3(target)


@transaction.atomic
def change_password(user, data):
    """Reauthenticate only the current actor; never accept another target."""
    actor, org = lock_identity(user)
    user_object(actor)  # Require a current website role and live assignment.
    if not actor.check_password(data["current_password"]):
        raise ApiError("PASSWORD_NOT_ACCEPTED", "The current password was not accepted.", 400,
                       {"current_password": ["The current password was not accepted."]})
    if actor.check_password(data["new_password"]):
        raise serializers.ValidationError({"new_password": ["Choose a different suitable password."]})
    validate_new_password(data["new_password"], actor, "new_password")
    actor.set_password(data["new_password"])
    actor.permission_version += 1
    actor.save(update_fields=["password", "permission_version"])
    audit.record(org.id, actor, "ACCOUNT_PASSWORD_CHANGED", actor.id)
    return {"changed": True, "reauthenticate": True}
