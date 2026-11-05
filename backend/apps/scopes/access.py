from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import User
from apps.operations.errors import forbidden, missing

from .models import ChannelMember, ChannelSource, Organization, UnitMembership, PROFILES


PROFILE = "DEMO-REDUCED"


def lock_identity(user):
    """Every business read/write is serialized with policy/grant changes per org.

    Administrative changes take this same organization lock explicitly BEFORE
    updating related rows. A row
    trigger runs after PostgreSQL takes that row's update lock and cannot impose
    the required order on an arbitrary administrative update.
    """
    org = Organization.objects.select_for_update().filter(pk=user.organization_id, active=True).first()
    actor = User.objects.select_for_update().filter(pk=user.pk, is_active=True, organization_id=user.organization_id).first()
    if org is None or actor is None or actor.role != user.role or actor.permission_version != user.permission_version:
        raise forbidden()
    return actor, org


def live_memberships(actor, role):
    return UnitMembership.objects.filter(
        user_id=actor.pk, organization_id=actor.organization_id, role=role,
        active=True, unit__active=True, unit__organization_id=actor.organization_id,
    ).filter(Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now()))


def require_role(actor, role):
    if actor.role != role:
        raise forbidden()


def submitter_unit(actor):
    require_role(actor, "submitter")
    memberships = list(live_memberships(actor, "submitter").select_related("unit")[:2])
    if len(memberships) != 1:
        raise forbidden()
    return memberships[0].unit


def source_allowed(actor, report, reviewer_only=False):
    if report.organization_id != actor.organization_id:
        return False
    if actor.role == "reviewer":
        return live_memberships(actor, "reviewer").filter(unit_id=report.unit_id).exists()
    return not reviewer_only and actor.role == "submitter" and report.author_id == actor.id and live_memberships(actor, "submitter").filter(unit_id=report.unit_id).exists()


def eligible_channels(org_id, unit_id):
    return list(ChannelSource.objects.filter(
        organization_id=org_id, unit_id=unit_id, unit__active=True, channel__organization_id=org_id,
        active=True, channel__active=True,
    ).order_by("channel_id").values_list("channel_id", flat=True))


def recipient_grant(actor, channel_id):
    require_role(actor, "recipient")
    grant = ChannelMember.objects.filter(
        user_id=actor.pk, organization_id=actor.organization_id, channel_id=channel_id,
        channel__organization_id=actor.organization_id, channel__active=True,
        profile_ceiling__in=PROFILES, active=True, revoked_at__isnull=True,
    ).filter(Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now())).select_related("channel").first()
    if grant is None:
        raise missing()
    # Preserve the M1 legacy-only channel denial until explicit M3 source
    # eligibility exists. A new profile never widens a legacy grant implicitly.
    if (grant.channel.max_profile is None and grant.profile_ceiling != PROFILE
            and not ChannelSource.objects.filter(organization_id=actor.organization_id,
                channel_id=channel_id, active=True, unit__active=True, max_profile__isnull=False).exists()):
        raise missing()
    return grant


def user_object(actor):
    from apps.reports.scope_context import is_legacy
    from apps.reports.projection import PROFILE_RANK
    unit = None
    channel = None
    grants = []
    channels = []
    profile = PROFILE
    expanded = False
    if actor.role in {"submitter", "reviewer"}:
        entries = list(live_memberships(actor, actor.role).select_related("unit")[:2])
        if len(entries) != 1:
            raise forbidden()
        unit = entries[0].unit
        sources = list(ChannelSource.objects.filter(organization_id=actor.organization_id, unit=unit,
            unit__active=True, channel__organization_id=actor.organization_id, active=True,
            channel__active=True).select_related("channel").order_by("channel_id"))
        if not sources:
            raise forbidden()
        channels = [value.channel for value in sources]
        expanded = not is_legacy([{"source_max": value.max_profile, "channel_max": value.channel.max_profile} for value in sources])
        channel = channels[0] if len(channels) == 1 else None
        profile = min((sources[0].max_profile or PROFILE, channel.max_profile or PROFILE), key=PROFILE_RANK.get) if channel else None
    elif actor.role == "recipient":
        grants = list(ChannelMember.objects.filter(
            user=actor, organization_id=actor.organization_id, channel__active=True,
            channel__organization_id=actor.organization_id,
            active=True, profile_ceiling__in=PROFILES, revoked_at__isnull=True,
        ).filter(Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now())).select_related("channel").order_by("channel_id"))
        if not grants:
            raise forbidden()
        channels = [value.channel for value in grants]
        channel = channels[0] if len(channels) == 1 else None
        profile = grants[0].profile_ceiling if channel else None
        expanded = len(grants) != 1 or profile != PROFILE or channel.max_profile is not None
    elif actor.role != "administrator":
        raise forbidden()
    def scope_object(value):
        return {"id": str(value.id), "code": value.code, "name": value.name} if value else None
    result = {"id": str(actor.id), "username": actor.username, "display_name": actor.display_name,
            "role": actor.role, "unit": scope_object(unit), "channel": scope_object(channel), "profile": profile}
    if expanded:
        result.update(channels=[scope_object(value) for value in channels],
            grants=[{"channel": scope_object(value.channel), "profile_ceiling": value.profile_ceiling} for value in grants])
    return result
