from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("accounts", "0001_initial")]
    operations = [
        migrations.RemoveConstraint(model_name="user", name="user_business_role"),
        migrations.AlterField(
            model_name="user", name="role",
            field=models.CharField(max_length=16, choices=[
                ("submitter", "Submitter"), ("reviewer", "Originating reviewer"),
                ("recipient", "Recipient"), ("administrator", "Administrator"),
            ]),
        ),
        migrations.AddConstraint(
            model_name="user",
            constraint=models.CheckConstraint(
                condition=models.Q(role__in=["submitter", "reviewer", "recipient", "administrator"]),
                name="user_business_role",
            ),
        ),
    ]
