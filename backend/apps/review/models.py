import uuid

from django.conf import settings
from django.db import models


class DecisionBatch(models.Model):
    """M3: one atomic decision covering a job's complete candidate set; frozen."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    revision = models.ForeignKey("reports.ReportRevision", on_delete=models.PROTECT, related_name="decision_batches")
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    action = models.CharField(max_length=8, choices=[(x, x) for x in ["APPROVE", "RETURN", "REJECT"]])
    binding = models.JSONField()
    reason_ciphertext = models.BinaryField(null=True)
    response_body = models.JSONField()
    recorded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["reviewer", "operation_id"], name="batch_reviewer_operation"),
            models.CheckConstraint(condition=models.Q(action__in=["APPROVE", "RETURN", "REJECT"]), name="batch_action_valid"),
        ]


class ReviewDecision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    variant = models.OneToOneField("reports.ReportVariant", on_delete=models.PROTECT, related_name="decision")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    action = models.CharField(max_length=8, choices=[(x, x) for x in ["APPROVE", "RETURN", "REJECT"]])
    binding = models.JSONField()
    reason_ciphertext = models.BinaryField(null=True)
    response_body = models.JSONField()
    recorded_at = models.DateTimeField(auto_now_add=True)
    # M3: NULL for legacy single-variant decisions; required for non-NULL-context variants (trigger).
    batch = models.ForeignKey(DecisionBatch, on_delete=models.PROTECT, null=True, related_name="decisions")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["reviewer", "operation_id"], name="decision_reviewer_operation"),
            models.CheckConstraint(condition=models.Q(action__in=["APPROVE", "RETURN", "REJECT"]), name="decision_action_valid"),
        ]
