"""Supported topology mutations: exact affected-unit epochs, removal and regeneration."""
from django.db import transaction

from apps.operations.errors import ApiError, missing
from apps.reports.regeneration import invalidate_scope
from .access import lock_identity
from .authority import require_authority
from .models import ChannelSource, SharingChannel, Unit, PROFILES

UNSET = object()


def _actor(user):
    actor, org = lock_identity(user)
    require_authority(actor, "POLICY")
    return actor, org


def _changes(active, max_profile):
    changes = {}
    if active is not UNSET:
        if type(active) is not bool:
            raise ApiError("INVALID_REQUEST", "Use supported topology values.")
        changes["active"] = active
    if max_profile is not UNSET:
        if max_profile is not None and (not isinstance(max_profile, str) or max_profile not in PROFILES):
            raise ApiError("INVALID_REQUEST", "Use supported topology values.")
        changes["max_profile"] = max_profile
    return changes


def _protect_mobile(org, ids):
    # Explicit current M2 boundary: unit 01 topology is frozen while phone acceptance is open.
    if Unit.objects.filter(organization=org, pk__in=ids, code="SIM-UNIT-01").exists():
        raise ApiError("SCOPE_UNAVAILABLE", "This context is preserved for mobile acceptance.", 409)


@transaction.atomic
def update_channel(user, channel_id, *, active=UNSET, max_profile=UNSET):
    actor, org = _actor(user)
    changes = _changes(active, max_profile)
    channel = SharingChannel.objects.select_for_update().filter(pk=channel_id, organization=org).first()
    if channel is None:
        raise missing()
    changes = {key: value for key, value in changes.items() if getattr(channel, key) != value}
    if not changes:
        return channel
    ids = list(ChannelSource.objects.filter(organization=org, channel=channel).order_by("unit_id").values_list("unit_id", flat=True))
    _protect_mobile(org, ids)
    for key, value in changes.items():
        setattr(channel, key, value)
    channel.save(update_fields=list(changes))
    invalidate_scope(org, ids, actor=actor)
    return channel


@transaction.atomic
def update_source(user, unit_id, channel_id, *, active=UNSET, max_profile=UNSET):
    actor, org = _actor(user)
    changes = _changes(active, max_profile)
    unit = Unit.objects.filter(pk=unit_id, organization=org).first()
    channel = SharingChannel.objects.filter(pk=channel_id, organization=org).first()
    if unit is None or channel is None:
        raise missing()
    source = ChannelSource.objects.select_for_update().filter(organization=org, unit=unit, channel=channel).first()
    if source is not None:
        changes = {key: value for key, value in changes.items() if getattr(source, key) != value}
        if not changes:
            return source
    _protect_mobile(org, [unit.id])
    if source is None:
        source = ChannelSource.objects.create(organization=org, unit=unit, channel=channel, **changes)
    else:
        for key, value in changes.items():
            setattr(source, key, value)
        source.save(update_fields=list(changes))
    invalidate_scope(org, [unit.id], actor=actor)
    return source


@transaction.atomic
def update_unit(user, unit_id, *, active):
    actor, org = _actor(user)
    changes = _changes(active, UNSET)
    unit = Unit.objects.select_for_update().filter(pk=unit_id, organization=org).first()
    if unit is None:
        raise missing()
    if unit.active == active:
        return unit
    _protect_mobile(org, [unit.id])
    unit.active = changes["active"]
    unit.save(update_fields=["active"])
    invalidate_scope(org, [unit.id], actor=actor)
    return unit
