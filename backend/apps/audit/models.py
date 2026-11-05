import uuid

from django.conf import settings
from django.db import models


class AuditEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    action = models.CharField(max_length=40)
    target_id = models.UUIDField(null=True)
    outcome = models.CharField(max_length=8)
    safe_metadata = models.JSONField(default=dict)
    recorded_at = models.DateTimeField(auto_now_add=True)


class AnonymousIntegrationFailure(models.Model):
    """Identity-free denial evidence; never attribute unknown credentials to an org."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    event = models.CharField(max_length=40, default="INTEGRATION_AUTH_FAILED")
    outcome = models.CharField(max_length=8, default="DENIED")
    code = models.CharField(max_length=40, default="AUTHENTICATION_REQUIRED")
    prefix = models.CharField(max_length=8, null=True, db_collation="C")
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(event="INTEGRATION_AUTH_FAILED", outcome="DENIED",
                code="AUTHENTICATION_REQUIRED"), name="anonymous_integration_fixed_event"),
            models.CheckConstraint(condition=models.Q(prefix__isnull=True) | models.Q(prefix__regex=r"^[a-z0-9]{8}$"),
                name="anonymous_integration_prefix_ascii"),
        ]
