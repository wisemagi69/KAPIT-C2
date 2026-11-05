"""Explicit business authority; infrastructure/staff flags grant nothing."""
from apps.operations.errors import ApiError, forbidden
from .models import AdminAuthority


def has_authority(actor, kind):
    return (actor.is_active and actor.role == "administrator" and
        AdminAuthority.objects.filter(organization_id=actor.organization_id, user=actor, kind=kind, active=True).exists())


def require_authority(actor, kind):
    if kind not in {"POLICY", "INTEGRATION"} or not has_authority(actor, kind):
        raise forbidden()


def protect_authority(target):
    if AdminAuthority.objects.filter(organization_id=target.organization_id, user=target, active=True).exists():
        raise ApiError("AUTHORITY_PROTECTED", "This authority holder requires local operator recovery.", 403)
