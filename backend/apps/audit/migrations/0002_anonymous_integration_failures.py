"""Add identity-free immutable integration denial evidence; never alter old audit rows."""
import uuid

from django.db import migrations, models


def refuse_populated_reverse(apps, schema_editor):
    model = apps.get_model("audit", "AnonymousIntegrationFailure")
    if model.objects.using(schema_editor.connection.alias).exists():
        raise RuntimeError("Anonymous integration denial history must be retained; reversal refused.")


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial"), ("operations", "0006_private_evidence")]
    operations = [
        migrations.CreateModel(
            name="AnonymousIntegrationFailure",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("event", models.CharField(default="INTEGRATION_AUTH_FAILED", max_length=40)),
                ("outcome", models.CharField(default="DENIED", max_length=8)),
                ("code", models.CharField(default="AUTHENTICATION_REQUIRED", max_length=40)),
                ("prefix", models.CharField(db_collation="C", max_length=8, null=True)),
                ("recorded_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"constraints": [
                models.CheckConstraint(condition=models.Q(event="INTEGRATION_AUTH_FAILED", outcome="DENIED",
                    code="AUTHENTICATION_REQUIRED"), name="anonymous_integration_fixed_event"),
                models.CheckConstraint(condition=models.Q(prefix__isnull=True) | models.Q(prefix__regex=r"^[a-z0-9]{8}$"),
                    name="anonymous_integration_prefix_ascii"),
            ]},
        ),
        migrations.RunSQL(
            "CREATE TRIGGER a_anonymous_integration_frozen BEFORE UPDATE OR DELETE ON audit_anonymousintegrationfailure "
            "FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();",
            "DROP TRIGGER a_anonymous_integration_frozen ON audit_anonymousintegrationfailure;",
        ),
        # First reverse operation: refuse before dropping any immutable guard or table.
        migrations.RunPython(migrations.RunPython.noop, refuse_populated_reverse),
    ]
