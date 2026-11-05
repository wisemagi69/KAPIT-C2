import uuid

from django.conf import settings
from django.db import models


class Report(models.Model):
    id = models.UUIDField(primary_key=True, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    unit = models.ForeignKey("scopes.Unit", on_delete=models.PROTECT)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    current_revision_no = models.PositiveIntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.CheckConstraint(condition=models.Q(current_revision_no__gte=1), name="report_revision_positive")]


class ReportRevision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    report = models.ForeignKey(Report, on_delete=models.PROTECT, related_name="revisions")
    revision_no = models.PositiveIntegerField(default=1)
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    accepted_device = models.ForeignKey("accounts.DeviceEnrollment", on_delete=models.PROTECT, null=True)
    template_version = models.CharField(max_length=40)
    observed_at = models.DateTimeField()
    received_at = models.DateTimeField(auto_now_add=True)
    payload_ciphertext = models.BinaryField()
    key_id = models.CharField(max_length=40, default="local-fernet-v1")
    content_digest = models.CharField(max_length=64)
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    processing_state = models.CharField(max_length=24, default="PENDING", choices=[(x, x) for x in ["PENDING", "PROCESSING", "AWAITING_REVIEW", "FAILED"]])
    # M3 (D4): website correction reason, encrypted; insert-only (the revision is frozen).
    correction_reason_ciphertext = models.BinaryField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["report", "revision_no"], name="revision_report_number"),
            models.UniqueConstraint(fields=["submitted_by", "operation_id"], condition=models.Q(accepted_device__isnull=True), name="revision_web_operation"),
            models.UniqueConstraint(fields=["accepted_device", "operation_id"], condition=models.Q(accepted_device__isnull=False), name="revision_device_operation"),
            models.CheckConstraint(condition=models.Q(revision_no__gte=1), name="revision_positive"),
        ]


class ReportVariant(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    revision = models.ForeignKey(ReportRevision, on_delete=models.PROTECT, related_name="variants")
    policy = models.ForeignKey("scopes.PolicyVersion", on_delete=models.PROTECT)
    job = models.ForeignKey("operations.ProcessingJob", on_delete=models.PROTECT, related_name="variants")
    profile = models.CharField(max_length=16, default="DEMO-REDUCED")
    projection = models.JSONField()
    candidate_hash = models.CharField(max_length=64)
    channel_ids = models.JSONField()
    warnings = models.JSONField(default=list)
    state = models.CharField(max_length=16, default="CANDIDATE", choices=[(x, x) for x in ["CANDIDATE", "APPROVED", "RETURNED", "REJECTED"]])
    created_at = models.DateTimeField(auto_now_add=True)
    # M3: equals the job's hash (NULL for the legacy context).
    scope_context_hash = models.CharField(max_length=64, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["job", "profile"], name="worker_job_profile_candidate"),
            models.CheckConstraint(condition=models.Q(profile__in=["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"]), name="variant_profile_valid"),
        ]
