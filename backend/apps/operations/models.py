import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.db.models.lookups import GreaterThan, LessThanOrEqual


class SyncReceipt(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    accepted_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    accepted_device = models.ForeignKey("accounts.DeviceEnrollment", on_delete=models.PROTECT, null=True)
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    revision = models.OneToOneField("reports.ReportRevision", on_delete=models.PROTECT)
    response_body = models.JSONField()
    received_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["accepted_user", "operation_id"], condition=models.Q(accepted_device__isnull=True), name="receipt_web_operation"),
            models.UniqueConstraint(fields=["accepted_device", "operation_id"], condition=models.Q(accepted_device__isnull=False), name="receipt_device_operation"),
        ]


class ProcessingJob(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    revision = models.ForeignKey("reports.ReportRevision", on_delete=models.PROTECT, related_name="jobs")
    policy = models.ForeignKey("scopes.PolicyVersion", on_delete=models.PROTECT)
    engine_manifest = models.CharField(max_length=40, default="demo-rules-v1")
    channel_ids = models.JSONField()
    status = models.CharField(max_length=16, default="PENDING", choices=[(x, x) for x in ["PENDING", "PROCESSING", "DONE", "FAILED"]])
    attempts = models.PositiveIntegerField(default=0)
    lease_generation = models.PositiveBigIntegerField(default=0)
    lease_token = models.UUIDField(null=True)
    lease_until = models.DateTimeField(null=True)
    available_at = models.DateTimeField()
    error_code = models.CharField(max_length=40, null=True)
    # M3: NULL context = legacy M1/M2 context; both epochs are frozen at job creation.
    scope_context = models.JSONField(null=True)
    scope_context_hash = models.CharField(max_length=64, null=True)
    policy_epoch = models.PositiveBigIntegerField(default=0)
    scope_epoch = models.PositiveBigIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["revision", "policy", "engine_manifest", "policy_epoch", "scope_epoch"],
                                    condition=models.Q(scope_context_hash__isnull=True), name="job_legacy_context_epoch"),
            models.UniqueConstraint(fields=["revision", "policy", "engine_manifest", "scope_context_hash", "policy_epoch", "scope_epoch"],
                                    condition=models.Q(scope_context_hash__isnull=False), name="job_scope_context_epoch"),
            models.CheckConstraint(condition=(models.Q(scope_context__isnull=True) & models.Q(scope_context_hash__isnull=True))
                                   | (models.Q(scope_context__isnull=False) & models.Q(scope_context_hash__isnull=False) & models.Q(scope_context_hash__regex=r"^[a-f0-9]{64}$")),
                                   name="job_context_hash_pair"),
        ]
        indexes = [models.Index(fields=["status", "available_at"], name="job_ready_index"),
                   models.Index(fields=["revision", "status"], name="job_revision_status_index")]


class PrivateEvidence(models.Model):
    """Immutable encrypted quarantine; no validated/downloadable state in this slice."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    revision = models.ForeignKey("reports.ReportRevision", on_delete=models.PROTECT, related_name="private_evidence")
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    payload_ciphertext = models.BinaryField()
    key_id = models.CharField(max_length=40, default="local-fernet-v1")
    media_type = models.CharField(max_length=16)
    byte_size = models.PositiveIntegerField()
    slot = models.PositiveSmallIntegerField()
    state = models.CharField(max_length=24, default="QUARANTINED", choices=[("QUARANTINED", "QUARANTINED")])
    validation_code = models.CharField(max_length=40, default="DECODER_REQUIRED")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["uploaded_by", "operation_id"], name="evidence_actor_operation"),
            models.UniqueConstraint(fields=["revision", "slot"], name="evidence_revision_slot"),
            models.CheckConstraint(condition=models.Q(slot__in=[1, 2]), name="evidence_slot_valid"),
            models.CheckConstraint(condition=models.Q(byte_size__gte=1, byte_size__lte=5242880), name="evidence_size_valid"),
            models.CheckConstraint(condition=models.Q(media_type__in=["image/jpeg", "image/png"]), name="evidence_media_valid"),
            models.CheckConstraint(condition=models.Q(state="QUARANTINED", validation_code="DECODER_REQUIRED"), name="evidence_quarantine_only"),
            models.CheckConstraint(condition=models.Q(request_hash__regex=r"^[a-f0-9]{64}$"), name="evidence_hash_valid"),
            models.CheckConstraint(condition=models.Q(key_id="local-fernet-v1"), name="evidence_key_valid"),
            models.CheckConstraint(condition=~models.Q(payload_ciphertext=b""), name="evidence_ciphertext_nonempty"),
        ]


class PrivateEvidenceValidation(models.Model):
    """Append-only private attempts; an original quarantine row is never promoted."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey("scopes.Organization", on_delete=models.PROTECT)
    evidence = models.ForeignKey(PrivateEvidence, on_delete=models.PROTECT, related_name="validations")
    validated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    operation_id = models.UUIDField()
    request_hash = models.CharField(max_length=64)
    manifest_hash = models.CharField(max_length=64)
    signature_generation = models.CharField(max_length=64)
    input_sha256 = models.CharField(max_length=64)
    state = models.CharField(max_length=24)
    code = models.CharField(max_length=40)
    created_at = models.DateTimeField(auto_now_add=True)
    validated_at = models.DateTimeField(null=True)
    expires_at = models.DateTimeField(null=True)
    provenance_ciphertext = models.BinaryField()
    derivative_ciphertext = models.BinaryField(null=True)
    derivative_sha256 = models.CharField(max_length=64, null=True)
    derivative_size = models.PositiveIntegerField(null=True)
    width = models.PositiveIntegerField(null=True)
    height = models.PositiveIntegerField(null=True)
    key_id = models.CharField(max_length=40, default="local-fernet-v1")

    class Meta:
        # Explicit scalar branches avoid SQL NULL/UNKNOWN accepting success with
        # absent fields, and preserve the exact closed state/code vocabulary.
        _present = models.Q(validated_at__isnull=False, expires_at__isnull=False,
            derivative_ciphertext__isnull=False, derivative_sha256__isnull=False,
            derivative_size__isnull=False, width__isnull=False, height__isnull=False)
        _absent = models.Q(validated_at__isnull=True, expires_at__isnull=True,
            derivative_ciphertext__isnull=True, derivative_sha256__isnull=True,
            derivative_size__isnull=True, width__isnull=True, height__isnull=True)
        _rejected = (models.Q(code="INVALID_IMAGE") | models.Q(code="TYPE_MISMATCH")
            | models.Q(code="PIXEL_LIMIT") | models.Q(code="MULTIFRAME_UNSUPPORTED")
            | models.Q(code="METADATA_INVALID"))
        _quarantined = (models.Q(code="DEPENDENCY_UNAVAILABLE") | models.Q(code="PROVENANCE_UNAVAILABLE")
            | models.Q(code="ISOLATION_UNAVAILABLE") | models.Q(code="SCANNER_UNAVAILABLE")
            | models.Q(code="SIGNATURES_STALE") | models.Q(code="SCAN_NOT_CLEAN")
            | models.Q(code="RESOURCE_LIMIT") | models.Q(code="DECODE_UNAVAILABLE")
            | models.Q(code="DERIVATIVE_LIMIT") | models.Q(code="VALIDATION_STALE")
            | models.Q(code="SCRATCH_CLEANUP_REQUIRED"))
        _success = (models.Q(state="VALIDATED_PRIVATE", code="VALIDATION_COMPLETE") & _present
            & models.Q(derivative_size__gte=1, derivative_size__lte=5242880,
                width__gte=1, width__lte=6000, height__gte=1, height__lte=6000,
                derivative_sha256__regex=r"^[a-f0-9]{64}$",
                validated_at__lte=models.F("created_at"), created_at__lt=models.F("expires_at"),
                expires_at__lte=models.F("validated_at") + timedelta(days=1))
            & models.Q(LessThanOrEqual(models.F("width") * models.F("height"), models.Value(24000000)))
            & ~models.Q(derivative_ciphertext=b""))
        constraints = [
            models.UniqueConstraint(fields=["validated_by", "operation_id"], name="evidence_validation_actor_op"),
            models.CheckConstraint(condition=(_success
                | (models.Q(state="REJECTED_PRIVATE") & _rejected & _absent)
                | (models.Q(state="QUARANTINED") & _quarantined & _absent)), name="evidence_validation_shape"),
            models.CheckConstraint(condition=models.Q(request_hash__regex=r"^[a-f0-9]{64}$",
                manifest_hash__regex=r"^[a-f0-9]{64}$", signature_generation__regex=r"^[a-f0-9]{64}$",
                input_sha256__regex=r"^[a-f0-9]{64}$"), name="evidence_validation_hashes"),
            models.CheckConstraint(condition=models.Q(key_id="local-fernet-v1"), name="evidence_validation_key"),
            models.CheckConstraint(condition=(
                models.Q(GreaterThan(models.Func(models.F("provenance_ciphertext"), function="octet_length",
                    output_field=models.IntegerField()), models.Value(0)))
                & models.Q(LessThanOrEqual(models.Func(models.F("provenance_ciphertext"), function="octet_length",
                    output_field=models.IntegerField()), models.Value(100000)))
                & (models.Q(derivative_ciphertext__isnull=True)
                    | models.Q(LessThanOrEqual(models.Func(models.F("derivative_ciphertext"), function="octet_length",
                        output_field=models.IntegerField()), models.Value(12000000))))), name="evidence_validation_bytes"),
        ]
        indexes = [models.Index(fields=["evidence", "created_at", "id"], name="evidence_validation_latest"),
                   models.Index(fields=["organization", "evidence"], name="evidence_validation_org")]
