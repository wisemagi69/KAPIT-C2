import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("scopes", "0001_initial"), migrations.swappable_dependency(settings.AUTH_USER_MODEL)]
    operations = [
        migrations.CreateModel(name="UnitMembership", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("role", models.CharField(choices=[("submitter", "Submitter"), ("reviewer", "Reviewer")], max_length=16)),
            ("active", models.BooleanField(default=True)), ("valid_until", models.DateTimeField(blank=True, null=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("unit", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.unit")),
            ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
        ], options={"constraints": [models.UniqueConstraint(fields=("user", "unit", "role"), name="membership_user_unit_role"), models.CheckConstraint(condition=models.Q(role__in=["submitter", "reviewer"]), name="membership_role_valid")]}),
        migrations.CreateModel(name="ChannelSource", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("active", models.BooleanField(default=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("unit", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.unit")),
            ("channel", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.sharingchannel")),
        ], options={"constraints": [models.UniqueConstraint(fields=("channel", "unit"), name="source_channel_unit")]}),
        migrations.CreateModel(name="ChannelMember", fields=[
            ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
            ("profile_ceiling", models.CharField(default="DEMO-REDUCED", max_length=16)),
            ("active", models.BooleanField(default=True)), ("valid_until", models.DateTimeField(blank=True, null=True)), ("revoked_at", models.DateTimeField(blank=True, null=True)),
            ("organization", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.organization")),
            ("channel", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to="scopes.sharingchannel")),
            ("user", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, to=settings.AUTH_USER_MODEL)),
        ], options={"constraints": [models.UniqueConstraint(fields=("channel", "user"), name="member_channel_user")]}),
    ]
