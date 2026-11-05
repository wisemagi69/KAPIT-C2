import io
import json
import uuid
from unittest.mock import patch

from django.contrib.auth import authenticate, get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.operations.serializers import BatchDecisionSerializer
from apps.operations.worker import process_one
from apps.publications.models import Publication
from apps.reports.models import Report, ReportRevision
from apps.reports.services import accept_operation
from apps.review.services import candidate_set, decide_batch
from apps.scopes.models import ChannelMember, ChannelSource, Organization, SharingChannel, Unit, UnitMembership
from tests.m3.test_m3_review import SETTINGS
from tests.test_workflow import operation

ADMIN, OPERATOR = "Xq7-synthetic-admin-pass-001", "Xq7-synthetic-operator-pass-002"
ENVIRONMENT = {"KAPIT_EVENT_ADMIN_PASSWORD": ADMIN, "KAPIT_OPERATOR_PASSWORD": OPERATOR}


@override_settings(**SETTINGS)
class SeedEventTests(TestCase):
    def seed(self, environment=ENVIRONMENT):
        output = io.StringIO()
        with patch.dict("os.environ", environment, clear=False):
            call_command("seed_event", stdout=output, verbosity=0)
        return output.getvalue()

    def snapshot(self):
        return {model.__name__: list(model.objects.order_by("pk").values()) for model in
                (get_user_model(), Organization, Unit, SharingChannel, ChannelSource, UnitMembership, ChannelMember)}

    def test_creates_only_scope_and_operator_accounts_with_private_passwords(self):
        output = self.seed()
        self.assertNotIn(ADMIN, output)
        self.assertNotIn(OPERATOR, output)
        org = Organization.objects.get(code="KAPIT-TRN-01")
        self.assertEqual(org.active_policy.version, "demo-policy-v1")
        self.assertEqual(Report.objects.count(), 0)
        users = {user.username: user for user in get_user_model().objects.all()}
        self.assertEqual(set(users), {"admin", "ops-submitter", "ops-recipient"})
        self.assertEqual({user.role for user in users.values()}, {"administrator", "submitter", "recipient"})
        self.assertTrue(all(user.organization_id == org.id for user in users.values()))
        self.assertIsNotNone(authenticate(username="admin", password=ADMIN))
        self.assertIsNotNone(authenticate(username="ops-submitter", password=OPERATOR))
        self.assertIsNone(authenticate(username="admin", password="DemoMaintenance!2026"))
        self.assertEqual(UnitMembership.objects.get(user=users["ops-submitter"]).unit.code, "LB-MAINT-01")
        self.assertEqual(ChannelMember.objects.get(user=users["ops-recipient"]).profile_ceiling, "DEMO-REDUCED")

    def test_rerun_is_idempotent_and_never_resets_passwords(self):
        self.seed()
        user = get_user_model().objects.get(username="admin")
        user.set_password("Changed-by-the-administrator-9")
        user.save()
        before = self.snapshot()
        output = self.seed({"KAPIT_EVENT_ADMIN_PASSWORD": "Other-admin-pass-xyz-123", "KAPIT_OPERATOR_PASSWORD": "Other-operator-pass-xyz-456"})
        self.assertEqual(self.snapshot(), before)
        self.assertIn("admin: existing account retained; the private file's password was not applied.", output)
        self.assertNotIn("Other-admin-pass", output)

    def test_rerun_reports_inactive_or_unscoped_operator_accounts_and_refuses_a_changed_role(self):
        self.seed()
        users = get_user_model().objects
        users.filter(username="ops-recipient").update(is_active=False)
        ChannelMember.objects.filter(user__username="ops-recipient").update(active=False)
        output = self.seed()
        self.assertIn("ops-recipient: account is inactive.", output)
        self.assertIn("ops-recipient: no active grant on the exercise channel.", output)
        users.filter(username="ops-submitter").update(role="reviewer")
        with self.assertRaisesRegex(CommandError, "another scope or role"):
            self.seed()

    def test_refuses_an_inactive_or_changed_exercise_scope(self):
        self.seed()
        channel = SharingChannel.objects.get(code="CH-LB-01")
        for change, message in ((dict(active=False), "inactive"), (dict(max_profile="DEMO-REDUCED"), "differs")):
            with self.subTest(change=sorted(change)):
                try:
                    SharingChannel.objects.filter(pk=channel.pk).update(**change)
                    before = self.snapshot()
                    with self.assertRaisesRegex(CommandError, message):
                        self.seed()
                    self.assertEqual(self.snapshot(), before)
                finally:
                    # Restore even when an assertion fails, so one failing case cannot cascade.
                    SharingChannel.objects.filter(pk=channel.pk).update(active=True, max_profile="DEMO-FULL")

    def test_refusal_after_a_write_rolls_back_the_whole_command(self):
        """The cases above refuse before writing anything. Here the command first recreates the missing
        channel source (get_or_create) and only then refuses as inactive, so an unchanged snapshot,
        which includes ChannelSource, proves the atomic rollback rather than merely no change."""
        self.seed()
        channel = SharingChannel.objects.get(code="CH-LB-01")
        # Nothing references ChannelSource (no FK to it, no delete trigger) and a fresh scope holds no reports.
        ChannelSource.objects.filter(channel=channel).delete()
        self.addCleanup(SharingChannel.objects.filter(pk=channel.pk).update, active=True)
        SharingChannel.objects.filter(pk=channel.pk).update(active=False)
        before = self.snapshot()
        self.assertFalse(ChannelSource.objects.filter(channel=channel).exists())
        with self.assertRaisesRegex(CommandError, "inactive"):
            self.seed()
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(ChannelSource.objects.filter(channel=channel).exists())

    def test_missing_or_weak_passwords_change_nothing(self):
        for environment in ({"KAPIT_EVENT_ADMIN_PASSWORD": "", "KAPIT_OPERATOR_PASSWORD": OPERATOR},
                            {"KAPIT_EVENT_ADMIN_PASSWORD": ADMIN, "KAPIT_OPERATOR_PASSWORD": "password"}):
            with self.subTest(environment=sorted(environment)), self.assertRaisesRegex(CommandError, "nothing was changed"):
                self.seed(environment)
        self.assertFalse(Organization.objects.exists())
        self.assertFalse(get_user_model().objects.exists())

    def test_refuses_a_database_holding_the_earlier_example_data(self):
        call_command("seed_demo", verbosity=0)
        before = self.snapshot()
        with self.assertRaisesRegex(CommandError, "earlier example data"):
            self.seed()
        self.assertEqual(self.snapshot(), before)

    def test_event_rehearsal_uses_multi_view_review_and_recipient_map(self):
        """A5 rehearsal on the isolated test database: the live event database stays empty."""
        self.seed()
        org, unit = Organization.objects.get(code="KAPIT-TRN-01"), Unit.objects.get(code="LB-MAINT-01")
        reviewer = get_user_model().objects.create_user(username="rehearsal-reviewer", password=OPERATOR, organization=org,
                                                        display_name="Rehearsal reviewer", role="reviewer")
        UnitMembership.objects.create(organization=org, user=reviewer, unit=unit, role="reviewer")
        author = get_user_model().objects.get(username="ops-submitter")
        raw = operation()
        receipt, _ = accept_operation(author, raw, raw)
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.assertTrue(process_one())
        binding = candidate_set(reviewer, revision.id)["binding"]
        self.assertEqual(sorted(row["profile"] for row in binding["candidates"]), ["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"])
        body = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding,
                "approve_profiles": ["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"], "reason": None}
        serializer = BatchDecisionSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        decide_batch(reviewer, revision.id, serializer.validated_data, body)
        self.assertTrue(Publication.objects.filter(report_id=revision.report_id, revoked_at__isnull=True).exists())
        client = APIClient()
        client.force_authenticate(user=get_user_model().objects.get(username="ops-recipient"))
        channel = SharingChannel.objects.get(code="CH-LB-01")
        feed = client.get(f"/api/v1/channels/{channel.id}/feed/").json()
        self.assertEqual(feed["count"], 1)
        self.assertEqual(feed["results"][0]["projection"]["profile"], "DEMO-REDUCED")
        area = client.get(f"/api/v1/channels/{channel.id}/map/").json()
        self.assertEqual(sum(row["count"] for row in area["areas"]) + area["unmapped"], 1)
        for private in ("PRIVATE_SITE_CANARY", "PRIVATE_REPORTER_CANARY", "PRIVATE_NARRATIVE_CANARY"):
            self.assertNotIn(private, json.dumps([feed, area]))
