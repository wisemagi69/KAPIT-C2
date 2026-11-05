import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [("scopes", "0001_initial"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [migrations.CreateModel(name="AuditEvent", fields=[
        ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
        ("action", models.CharField(max_length=40)), ("target_id", models.UUIDField(null=True)),
        ("outcome", models.CharField(max_length=8)), ("safe_metadata", models.JSONField(default=dict)), ("recorded_at", models.DateTimeField(auto_now_add=True)),
        ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ("actor", models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
    ])]
