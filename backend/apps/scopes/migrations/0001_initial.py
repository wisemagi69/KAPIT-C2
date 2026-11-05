import uuid

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = []
    operations = [
        migrations.CreateModel(name="Organization", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("code", models.CharField(max_length=40, unique=True)), ("name", models.CharField(max_length=160)),
            ("active", models.BooleanField(default=True)), ("created_at", models.DateTimeField(auto_now_add=True)),
        ]),
        migrations.CreateModel(name="Unit", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("code", models.CharField(max_length=40)), ("name", models.CharField(max_length=160)), ("active", models.BooleanField(default=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ], options={"constraints": [models.UniqueConstraint(fields=("organization", "code"), name="unit_org_code")]}),
        migrations.CreateModel(name="SharingChannel", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("code", models.CharField(max_length=40)), ("name", models.CharField(max_length=160)), ("active", models.BooleanField(default=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ], options={"constraints": [models.UniqueConstraint(fields=("organization", "code"), name="channel_org_code")]}),
        migrations.CreateModel(name="PolicyVersion", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("version", models.CharField(max_length=40)), ("active", models.BooleanField(default=False)),
            ("rules", models.JSONField()), ("rules_hash", models.CharField(max_length=64)), ("created_at", models.DateTimeField(auto_now_add=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
        ], options={"constraints": [models.UniqueConstraint(fields=("organization", "version"), name="policy_org_version"), models.UniqueConstraint(condition=models.Q(active=True), fields=("organization",), name="one_active_policy_org")]}),
        migrations.AddField(model_name="organization", name="active_policy", field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.PROTECT, related_name="active_for", to="scopes.policyversion")),
    ]
