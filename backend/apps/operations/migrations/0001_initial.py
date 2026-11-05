import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("reports", "0001_sources"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(name="ProcessingJob", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("engine_manifest", models.CharField(default="demo-rules-v1", max_length=40)), ("channel_ids", models.JSONField()),
            ("status", models.CharField(choices=[("PENDING", "PENDING"), ("PROCESSING", "PROCESSING"), ("DONE", "DONE"), ("FAILED", "FAILED")], default="PENDING", max_length=16)),
            ("attempts", models.PositiveIntegerField(default=0)), ("lease_generation", models.PositiveBigIntegerField(default=0)),
            ("lease_token", models.UUIDField(null=True)), ("lease_until", models.DateTimeField(null=True)),
            ("available_at", models.DateTimeField()), ("error_code", models.CharField(max_length=40, null=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("revision", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="jobs", to="reports.reportrevision")),
            ("policy", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.policyversion")),
        ], options={"constraints": [models.UniqueConstraint(fields=("revision", "policy", "engine_manifest"), name="job_revision_policy_engine")], "indexes": [models.Index(fields=["status", "available_at"], name="job_ready_index")]}),
        migrations.CreateModel(name="SyncReceipt", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("operation_id", models.UUIDField()), ("request_hash", models.CharField(max_length=64)), ("response_body", models.JSONField()),
            ("received_at", models.DateTimeField(auto_now_add=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("accepted_user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
            ("revision", models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, to="reports.reportrevision")),
        ], options={"constraints": [models.UniqueConstraint(fields=("accepted_user", "operation_id"), name="receipt_user_operation")]}),
    ]
