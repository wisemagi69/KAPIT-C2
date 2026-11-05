import uuid

from django.contrib.auth.models import AbstractUser
from datetime import timedelta

from django.db import models
from django.utils.crypto import salted_hmac


class User(AbstractUser):
    class Role(models.TextChoices):
        SUBMITTER = "submitter", "Submitter"
        REVIEWER = "reviewer", "Originating reviewer"
        RECIPIENT = "recipient", "Recipient"
        ADMINISTRATOR = "administrator", "Administrator"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    display_name = models.CharField(max_length=120)
    role = models.CharField(max_length=16, choices=Role.choices)
    permission_version = models.PositiveIntegerField(default=0)

    def _get_session_auth_hash(self, secret=None):
        # Django uses this for both the current and fallback signing secrets.
        # Every access change revokes existing sessions, even with the same password.
        return salted_hmac(
            "kapit.accounts.User.session_auth", f"{self.password}:{self.permission_version}",
            secret=secret, algorithm="sha256",
        ).hexdigest()

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(role__in=["submitter", "reviewer", "recipient", "administrator"]), name="user_business_role"),
        ]


class DeviceEnrollment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    installation_id = models.UUIDField()
    public_key_spki = models.BinaryField()
    key_fingerprint = models.CharField(max_length=64, unique=True)
    label = models.CharField(max_length=80)
    created_at = models.DateTimeField()
    last_authenticated_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["owner", "installation_id"], name="device_owner_installation")]


class DeviceFamily(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    enrollment = models.ForeignKey(DeviceEnrollment, on_delete=models.PROTECT)
    permission_version = models.PositiveIntegerField()
    auth_stamp = models.CharField(max_length=64)
    issued_at = models.DateTimeField()
    absolute_expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["enrollment"], condition=models.Q(revoked_at__isnull=True), name="device_one_live_family")]


class MobileChallenge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    owner = models.ForeignKey(User, on_delete=models.PROTECT)
    enrollment = models.ForeignKey(DeviceEnrollment, on_delete=models.PROTECT, null=True)
    action = models.CharField(max_length=20, choices=[("NEW_ENROLLMENT", "NEW_ENROLLMENT"), ("REAUTHENTICATE", "REAUTHENTICATE")])
    installation_id = models.UUIDField()
    public_key_spki = models.BinaryField()
    key_fingerprint = models.CharField(max_length=64)
    label = models.CharField(max_length=80)
    permission_version = models.PositiveIntegerField()
    auth_stamp = models.CharField(max_length=64)
    nonce_digest = models.CharField(max_length=64)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)

    class Meta:
        indexes = [models.Index(fields=["owner", "consumed_at", "created_at"], name="mobile_challenge_owner")]


class RefreshCredential(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    family = models.ForeignKey(DeviceFamily, on_delete=models.PROTECT)
    digest = models.CharField(max_length=64, unique=True)
    generation = models.PositiveIntegerField()
    issued_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True)
    revoked_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["family", "generation"], name="refresh_family_generation"),
            models.UniqueConstraint(fields=["family"], condition=models.Q(consumed_at__isnull=True, revoked_at__isnull=True), name="refresh_one_current"),
        ]


class MobileThrottle(models.Model):
    key = models.CharField(max_length=64, primary_key=True)
    window_start = models.PositiveBigIntegerField()
    attempts = models.PositiveIntegerField()
    updated_at = models.DateTimeField()


PROFILES = ["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"]  # TASK-120 contract vocabulary


class IntegrationClientRequest(models.Model):
    """M3 (D5, SN4): read-only integration key request; frozen; collect deadline within 24 hours."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    requester = models.ForeignKey(User, on_delete=models.PROTECT)
    channel = models.ForeignKey("scopes.SharingChannel", on_delete=models.PROTECT)
    profile_ceiling = models.CharField(max_length=16)
    label = models.CharField(max_length=80)
    expires_at = models.DateTimeField()
    collect_deadline = models.DateTimeField()
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["requester", "operation_id"], name="client_request_operation"),
            models.CheckConstraint(condition=models.Q(profile_ceiling__in=PROFILES), name="client_request_profile_valid"),
            models.CheckConstraint(condition=models.Q(collect_deadline__gt=models.F("created_at")) & models.Q(collect_deadline__lte=models.F("created_at") + timedelta(hours=24)),
                                   name="client_request_collect_24h"),
            models.CheckConstraint(condition=models.Q(expires_at__gt=models.F("created_at")) & models.Q(expires_at__lte=models.F("created_at") + timedelta(days=90)),
                                   name="client_request_expiry_90d"),
        ]


class IntegrationClientApproval(models.Model):
    """M3 (D5): a different INTEGRATION holder approves a FULL request; frozen."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    request = models.OneToOneField(IntegrationClientRequest, on_delete=models.PROTECT)
    approver = models.ForeignKey(User, on_delete=models.PROTECT)
    approved_at = models.DateTimeField()


class IntegrationClient(models.Model):
    """M3 (S5, SN4): created only at collect; only the HMAC digest is stored; only revocation fields are mutable."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    request = models.OneToOneField(IntegrationClientRequest, on_delete=models.PROTECT)
    channel = models.ForeignKey("scopes.SharingChannel", on_delete=models.PROTECT)
    profile_ceiling = models.CharField(max_length=16)
    label = models.CharField(max_length=80)
    key_prefix = models.CharField(max_length=8)
    key_digest = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True)
    revoked_by = models.ForeignKey(User, on_delete=models.PROTECT, null=True, related_name="revoked_integration_clients")

    class Meta:
        constraints = [
            models.CheckConstraint(condition=models.Q(profile_ceiling__in=PROFILES), name="client_profile_valid"),
            models.CheckConstraint(condition=models.Q(key_prefix__regex=r"^[a-z0-9]{8}$"), name="client_prefix_format"),
            models.CheckConstraint(condition=models.Q(expires_at__gt=models.F("created_at")) & models.Q(expires_at__lte=models.F("created_at") + timedelta(days=90)),
                                   name="client_expiry_90d"),
            models.CheckConstraint(condition=(models.Q(revoked_at__isnull=True) & models.Q(revoked_by__isnull=True)) | models.Q(revoked_at__isnull=False),
                                   name="client_revoked_by_needs_revoked_at"),
        ]
