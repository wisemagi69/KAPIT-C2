import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("review", "0001_initial")]
    operations = [migrations.CreateModel(name="Publication", fields=[
        ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
        ("profile", models.CharField(default="DEMO-REDUCED", max_length=16)), ("projection", models.JSONField()),
        ("published_at", models.DateTimeField(auto_now_add=True)), ("revoked_at", models.DateTimeField(null=True)),
        ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ("variant", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="reports.reportvariant")),
        ("decision", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="review.reviewdecision")),
        ("channel", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.sharingchannel")),
        ("report", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="reports.report")),
    ], options={"constraints": [models.UniqueConstraint(fields=("variant", "channel"), name="publication_variant_channel"), models.UniqueConstraint(condition=models.Q(revoked_at__isnull=True), fields=("report", "channel", "profile"), name="publication_active_report_channel")]})]
