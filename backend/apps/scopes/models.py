import uuid

from django.conf import settings
from datetime import timedelta

from django.db import models

PROFILES = ["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"]  # TASK-120 contract vocabulary


class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=40, unique=True)
    name = models.CharField(max_length=160)
    active = models.BooleanField(default=True)
    active_policy = models.ForeignKey("PolicyVersion", on_delete=models.PROTECT, null=True, related_name="active_for")
    created_at = models.DateTimeField(auto_now_add=True)
    # M3 (SN1): +1 per policy activate/deactivate, by the policy service only; a trigger refuses decrease or skip.
    policy_epoch = models.PositiveBigIntegerField(default=0)


class Unit(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    code = models.CharField(max_length=40)
    name = models.CharField(max_length=160)
    active = models.BooleanField(default=True)
    # M3 (SN1): +1 per scope change affecting this unit, by the topology service only.
    scope_epoch = models.PositiveBigIntegerField(default=0)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "code"], name="unit_org_code")]


class SharingChannel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    code = models.CharField(max_length=40)
    name = models.CharField(max_length=160)
    active = models.BooleanField(default=True)
    max_profile = models.CharField(max_length=16, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "code"], name="channel_org_code"),
            models.CheckConstraint(condition=models.Q(max_profile__isnull=True) | models.Q(max_profile__in=PROFILES), name="channel_max_profile_valid"),
        ]


class UnitMembership(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    unit = models.ForeignKey(Unit, on_delete=models.PROTECT)
    role = models.CharField(max_length=16, choices=[("submitter", "Submitter"), ("reviewer", "Reviewer")])
    active = models.BooleanField(default=True)
    valid_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "unit", "role"], condition=models.Q(active=True), name="active_membership_user_unit_role"),
            models.CheckConstraint(condition=models.Q(role__in=["submitter", "reviewer"]), name="membership_role_valid"),
        ]


class ChannelSource(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    channel = models.ForeignKey(SharingChannel, on_delete=models.PROTECT)
    unit = models.ForeignKey(Unit, on_delete=models.PROTECT)
    active = models.BooleanField(default=True)
    max_profile = models.CharField(max_length=16, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["channel", "unit"], name="source_channel_unit"),
            models.CheckConstraint(condition=models.Q(max_profile__isnull=True) | models.Q(max_profile__in=PROFILES), name="source_max_profile_valid"),
        ]


class ChannelMember(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    channel = models.ForeignKey(SharingChannel, on_delete=models.PROTECT)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    profile_ceiling = models.CharField(max_length=16, default="DEMO-REDUCED")
    active = models.BooleanField(default=True)
    valid_until = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["channel", "user"], condition=models.Q(active=True), name="active_member_channel_user"),
            models.CheckConstraint(condition=models.Q(profile_ceiling__in=PROFILES), name="member_profile_ceiling_valid"),
        ]


class PolicyVersion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    version = models.CharField(max_length=40)
    active = models.BooleanField(default=False)
    rules = models.JSONField()
    rules_hash = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["organization", "version"], name="policy_org_version"),
            models.UniqueConstraint(fields=["organization"], condition=models.Q(active=True), name="one_active_policy_org"),
        ]


class AdminAuthority(models.Model):
    """M3 (D2/D5): explicit POLICY or INTEGRATION authority; only `active` is mutable."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    kind = models.CharField(max_length=16, choices=[("POLICY", "POLICY"), ("INTEGRATION", "INTEGRATION")])
    active = models.BooleanField(default=True)
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "kind"], condition=models.Q(active=True), name="authority_active_user_kind"),
            models.CheckConstraint(condition=models.Q(kind__in=["POLICY", "INTEGRATION"]), name="authority_kind_valid"),
        ]


class PolicyProposal(models.Model):
    """M3 (D2): first person of a two-person policy change; fully frozen; expires within 24 hours."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    kind = models.CharField(max_length=16, choices=[("ACTIVATE", "ACTIVATE"), ("DEACTIVATE", "DEACTIVATE")])
    target_policy = models.ForeignKey(PolicyVersion, on_delete=models.PROTECT, related_name="proposals")
    target_rules_hash = models.CharField(max_length=64)
    expected_active_policy = models.ForeignKey(PolicyVersion, on_delete=models.PROTECT, null=True, related_name="expected_by_proposals")
    proposer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    proposer_permission_version = models.PositiveIntegerField()
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    proposed_at = models.DateTimeField()
    expires_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["proposer", "operation_id"], name="proposal_proposer_operation"),
            models.CheckConstraint(condition=models.Q(kind__in=["ACTIVATE", "DEACTIVATE"]), name="proposal_kind_valid"),
            models.CheckConstraint(condition=models.Q(expires_at__gt=models.F("proposed_at")) & models.Q(expires_at__lte=models.F("proposed_at") + timedelta(hours=24)),
                                   name="proposal_expiry_24h"),
        ]


class PolicyActivation(models.Model):
    """M3 (D2): second person applies a proposal; fully frozen; a trigger enforces the two-person rule."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.PROTECT)
    proposal = models.OneToOneField(PolicyProposal, on_delete=models.PROTECT)
    activator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    activated_at = models.DateTimeField()
