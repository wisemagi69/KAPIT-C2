import re

from django.db import transaction

from apps.operations.errors import ApiError
from .models import AnonymousIntegrationFailure, AuditEvent


# Positional-only so a review decision's "action" metadata cannot collide with the event action.
def record(organization_id, actor, action, target_id=None, /, outcome="ALLOWED", **metadata):
    allowed = {"operation_id", "revision_no", "action", "error_code", "lease_generation"}
    if "prefix" in metadata:
        if action != "INTEGRATION_AUTH_FAILED" or not isinstance(metadata["prefix"], str) or re.fullmatch(r"[a-z0-9]{8}", metadata["prefix"], re.ASCII) is None:
            raise ValueError("unsupported audit metadata")
        allowed.add("prefix")
    if set(metadata) - allowed:
        raise ValueError("unsupported audit metadata")
    return AuditEvent.objects.create(
        organization_id=organization_id,
        actor=actor,
        action=action,
        target_id=target_id,
        outcome=outcome,
        safe_metadata=metadata,
    )


def anonymous_integration_failure(prefix=None):
    # Invalid/unavailable prefix is omitted; no arbitrary request value is stored.
    if not isinstance(prefix, str) or re.fullmatch(r"[a-z0-9]{8}", prefix, re.ASCII) is None:
        prefix = None
    try:
        with transaction.atomic():
            return AnonymousIntegrationFailure.objects.create(prefix=prefix)
    except Exception:
        raise ApiError("SERVER_ERROR", "The service is unavailable. Retry later.", 503) from None
