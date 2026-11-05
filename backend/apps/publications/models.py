import uuid

from django.conf import settings
from django.db import models

PROFILES = ["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"]  # TASK-120 contract vocabulary


class Publication(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    variant = models.ForeignKey("reports.ReportVariant", on_delete=models.PROTECT)
    decision = models.ForeignKey("review.ReviewDecision", on_delete=models.PROTECT)
    channel = models.ForeignKey("scopes.SharingChannel", on_delete=models.PROTECT)
    report = models.ForeignKey("reports.Report", on_delete=models.PROTECT)
    profile = models.CharField(max_length=16, default="DEMO-REDUCED")
    projection = models.JSONField()
    published_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["variant", "channel"], name="publication_variant_channel"),
            models.UniqueConstraint(fields=["report", "channel", "profile"], condition=models.Q(revoked_at__isnull=True), name="publication_active_report_channel"),
            models.CheckConstraint(condition=models.Q(profile__in=PROFILES), name="publication_profile_valid"),
        ]
        indexes = [models.Index(fields=["channel", "profile", "-published_at", "-id"], condition=models.Q(revoked_at__isnull=True),
                                name="publication_live_channel_index")]


class RevisionWithdrawal(models.Model):
    """M3 (S1): durable withdrawal marker; once present, no approval, publication or regeneration for the revision."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    revision = models.OneToOneField("reports.ReportRevision", on_delete=models.PROTECT, related_name="withdrawal")
    report = models.ForeignKey("reports.Report", on_delete=models.PROTECT)
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    expected_revision_no = models.PositiveIntegerField()
    reason_ciphertext = models.BinaryField()
    publication_ids = models.JSONField()
    response_body = models.JSONField()
    withdrawn_at = models.DateTimeField()

    class Meta:
        constraints = [models.UniqueConstraint(fields=["reviewer", "operation_id"], name="withdrawal_reviewer_operation")]


class PublicationRemoval(models.Model):
    """M3 (D6): permanent removal record; removed publications never return."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    publication = models.OneToOneField(Publication, on_delete=models.PROTECT, related_name="removal")
    kind = models.CharField(max_length=16)
    cause = models.CharField(max_length=16)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    removed_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(kind__in=["WITHDRAWN", "SUPERSEDED"]), name="removal_kind_valid"),
            models.CheckConstraint(condition=models.Q(cause__in=["WITHDRAWAL", "CORRECTION", "POLICY", "SCOPE", "REAPPROVAL"]), name="removal_cause_valid"),
        ]


class PublicationDelivery(models.Model):
    """M3 (S13, F16): private delivery ledger, one row per (principal, publication); frozen."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    publication = models.ForeignKey(Publication, on_delete=models.PROTECT, related_name="deliveries")
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True)
    client = models.ForeignKey("accounts.IntegrationClient", on_delete=models.PROTECT, null=True)
    channel = models.ForeignKey("scopes.SharingChannel", on_delete=models.PROTECT)
    profile = models.CharField(max_length=16)
    first_delivered_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.CheckConstraint(condition=(models.Q(user__isnull=False) & models.Q(client__isnull=True)) | (models.Q(user__isnull=True) & models.Q(client__isnull=False)),
                                   name="delivery_one_principal"),
            models.CheckConstraint(condition=models.Q(profile__in=PROFILES), name="delivery_profile_valid"),
            models.UniqueConstraint(fields=["user", "publication"], condition=models.Q(user__isnull=False), name="delivery_user_publication"),
            models.UniqueConstraint(fields=["client", "publication"], condition=models.Q(client__isnull=False), name="delivery_client_publication"),
        ]
