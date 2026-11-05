import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("reports", "0001_sources"), ("operations", "0001_initial")]
    operations = [migrations.CreateModel(name="ReportVariant", fields=[
        ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
        ("profile", models.CharField(default="DEMO-REDUCED", max_length=16)),
        ("projection", models.JSONField()), ("candidate_hash", models.CharField(max_length=64)), ("channel_ids", models.JSONField()),
        ("warnings", models.JSONField(default=list)),
        ("state", models.CharField(choices=[("CANDIDATE", "CANDIDATE"), ("APPROVED", "APPROVED"), ("RETURNED", "RETURNED"), ("REJECTED", "REJECTED")], default="CANDIDATE", max_length=16)),
        ("created_at", models.DateTimeField(auto_now_add=True)),
        ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ("revision", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="variants", to="reports.reportrevision")),
        ("policy", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.policyversion")),
        ("job", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="variants", to="operations.processingjob")),
    ], options={"constraints": [models.UniqueConstraint(fields=("job", "profile"), name="worker_job_profile_candidate")]})]
