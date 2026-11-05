import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("scopes", "0002_memberships"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(name="Report", fields=[
            ("id", models.UUIDField(editable=False, primary_key=True, serialize=False)),
            ("current_revision_no", models.PositiveIntegerField(default=1)), ("created_at", models.DateTimeField(auto_now_add=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("unit", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.unit")),
            ("author", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
        ], options={"constraints": [models.CheckConstraint(condition=models.Q(current_revision_no__gte=1), name="report_revision_positive")]}),
        migrations.CreateModel(name="ReportRevision", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("revision_no", models.PositiveIntegerField(default=1)), ("template_version", models.CharField(max_length=40)),
            ("observed_at", models.DateTimeField()), ("received_at", models.DateTimeField(auto_now_add=True)),
            ("payload_ciphertext", models.BinaryField()), ("key_id", models.CharField(default="local-fernet-v1", max_length=40)),
            ("content_digest", models.CharField(max_length=64)), ("operation_id", models.UUIDField()), ("request_hash", models.CharField(max_length=64)),
            ("processing_state", models.CharField(choices=[("PENDING", "PENDING"), ("PROCESSING", "PROCESSING"), ("AWAITING_REVIEW", "AWAITING_REVIEW"), ("FAILED", "FAILED")], default="PENDING", max_length=24)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("report", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="revisions", to="reports.report")),
            ("submitted_by", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
        ], options={"constraints": [models.UniqueConstraint(fields=("report", "revision_no"), name="revision_report_number"), models.UniqueConstraint(fields=("submitted_by", "operation_id"), name="revision_accepting_operation"), models.CheckConstraint(condition=models.Q(revision_no__gte=1), name="revision_positive")]}),
    ]
