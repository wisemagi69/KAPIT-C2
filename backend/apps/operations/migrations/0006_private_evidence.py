"""Additive encrypted quarantine only; not approved for retained application.

No existing records/functions are rewritten. Rollback of populated evidence is
not authorized; the reverse exists solely for empty disposable schema checks.
"""
import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


SQL = r"""
CREATE FUNCTION kapit_evidence_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE revision reports_reportrevision%ROWTYPE; source reports_report%ROWTYPE;
BEGIN
  SELECT * INTO revision FROM reports_reportrevision WHERE id = NEW.revision_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'private evidence revision is inconsistent' USING ERRCODE = '23514';
  END IF;
  SELECT * INTO source FROM reports_report WHERE id = revision.report_id;
  IF NOT FOUND OR NEW.organization_id IS DISTINCT FROM revision.organization_id
     OR NEW.organization_id IS DISTINCT FROM source.organization_id
     OR NEW.uploaded_by_id IS DISTINCT FROM source.author_id
     OR NEW.uploaded_by_id IS DISTINCT FROM revision.submitted_by_id
     OR revision.revision_no IS DISTINCT FROM source.current_revision_no THEN
    RAISE EXCEPTION 'private evidence owner or source is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER a_evidence_org BEFORE INSERT OR UPDATE ON operations_privateevidence
  FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('revision_id', 'reports_reportrevision', 'uploaded_by_id', 'accounts_user');
CREATE TRIGGER b_evidence_frozen BEFORE UPDATE OR DELETE ON operations_privateevidence
  FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER c_evidence_source BEFORE INSERT ON operations_privateevidence
  FOR EACH ROW EXECUTE FUNCTION kapit_evidence_source_guard();
"""

REVERSE = r"""
DROP TRIGGER c_evidence_source ON operations_privateevidence;
DROP TRIGGER b_evidence_frozen ON operations_privateevidence;
DROP TRIGGER a_evidence_org ON operations_privateevidence;
DROP FUNCTION kapit_evidence_source_guard();
"""


def refuse_populated_reverse(apps, schema_editor):
    if apps.get_model("operations", "PrivateEvidence").objects.exists():
        raise RuntimeError("Private evidence history exists; destructive reversal is refused.")


class Migration(migrations.Migration):
    dependencies = [
        ("operations", "0005_m3_guards"),
        ("reports", "0004_m3_variants_corrections"),
        ("scopes", "0004_m3_scope_profiles"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="PrivateEvidence",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("operation_id", models.UUIDField()),
                ("request_hash", models.CharField(max_length=64)),
                ("payload_ciphertext", models.BinaryField()),
                ("key_id", models.CharField(default="local-fernet-v1", max_length=40)),
                ("media_type", models.CharField(max_length=16)),
                ("byte_size", models.PositiveIntegerField()),
                ("slot", models.PositiveSmallIntegerField()),
                ("state", models.CharField(choices=[("QUARANTINED", "QUARANTINED")], default="QUARANTINED", max_length=24)),
                ("validation_code", models.CharField(default="DECODER_REQUIRED", max_length=40)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
                ("revision", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="private_evidence", to="reports.reportrevision")),
                ("uploaded_by", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
            ],
            options={"constraints": [
                models.UniqueConstraint(fields=("uploaded_by", "operation_id"), name="evidence_actor_operation"),
                models.UniqueConstraint(fields=("revision", "slot"), name="evidence_revision_slot"),
                models.CheckConstraint(condition=models.Q(slot__in=[1, 2]), name="evidence_slot_valid"),
                models.CheckConstraint(condition=models.Q(byte_size__gte=1, byte_size__lte=5242880), name="evidence_size_valid"),
                models.CheckConstraint(condition=models.Q(media_type__in=["image/jpeg", "image/png"]), name="evidence_media_valid"),
                models.CheckConstraint(condition=models.Q(state="QUARANTINED", validation_code="DECODER_REQUIRED"), name="evidence_quarantine_only"),
                models.CheckConstraint(condition=models.Q(request_hash__regex=r"^[a-f0-9]{64}$"), name="evidence_hash_valid"),
                models.CheckConstraint(condition=models.Q(key_id="local-fernet-v1"), name="evidence_key_valid"),
                models.CheckConstraint(condition=~models.Q(payload_ciphertext=b""), name="evidence_ciphertext_nonempty"),
            ]},
        ),
        migrations.RunSQL(SQL, REVERSE),
        migrations.RunPython(migrations.RunPython.noop, refuse_populated_reverse),
    ]
