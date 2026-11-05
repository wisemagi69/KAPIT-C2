import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("reports", "0002_variants"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [migrations.CreateModel(name="ReviewDecision", fields=[
        ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
        ("operation_id", models.UUIDField()), ("request_hash", models.CharField(max_length=64)),
        ("action", models.CharField(choices=[("APPROVE", "APPROVE"), ("RETURN", "RETURN"), ("REJECT", "REJECT")], max_length=8)),
        ("binding", models.JSONField()), ("reason_ciphertext", models.BinaryField(null=True)), ("response_body", models.JSONField()),
        ("recorded_at", models.DateTimeField(auto_now_add=True)),
        ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ("variant", models.OneToOneField(on_delete=django.db.models.deletion.PROTECT, related_name="decision", to="reports.reportvariant")),
        ("reviewer", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
    ], options={"constraints": [models.UniqueConstraint(fields=("reviewer", "operation_id"), name="decision_reviewer_operation"), models.CheckConstraint(condition=models.Q(action__in=["APPROVE", "RETURN", "REJECT"]), name="decision_action_valid")]})]
