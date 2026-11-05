"""Keep retired grants when accounts are assigned back to an earlier scope."""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("scopes", "0002_memberships"), ("accounts", "0002_administrator_role")]
    operations = [
        migrations.RemoveConstraint(model_name="unitmembership", name="membership_user_unit_role"),
        migrations.AddConstraint(
            model_name="unitmembership",
            constraint=models.UniqueConstraint(fields=["user", "unit", "role"], condition=models.Q(active=True), name="active_membership_user_unit_role"),
        ),
        migrations.RemoveConstraint(model_name="channelmember", name="member_channel_user"),
        migrations.AddConstraint(
            model_name="channelmember",
            constraint=models.UniqueConstraint(fields=["channel", "user"], condition=models.Q(active=True), name="active_member_channel_user"),
        ),
    ]
