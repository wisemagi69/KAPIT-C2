from datetime import timedelta
import uuid

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.reports.models import Report
from apps.scopes.models import (AdminAuthority, ChannelMember, ChannelSource, Organization,
    PolicyActivation, PolicyProposal, PolicyVersion, SharingChannel, Unit, UnitMembership)


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3SeedTests(TestCase):
    def setUp(self):
        call_command("seed_demo", verbosity=0)
        self.org = Organization.objects.get(code="SIM-ORG-01")
        self.legacy = list(Unit.objects.filter(code="SIM-UNIT-01").values())
        call_command("seed_m3_demo", verbosity=0)

    def snapshot(self):
        return {model.__name__: list(model.objects.order_by("pk").values()) for model in
            (get_user_model(), Organization, Unit, SharingChannel, ChannelSource, UnitMembership,
             ChannelMember, AdminAuthority, PolicyVersion)}

    def test_seed_is_idempotent_and_leaves_m1_unchanged(self):
        before = self.snapshot()
        call_command("seed_m3_demo", verbosity=0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(Unit.objects.filter(code="SIM-UNIT-01").values()), self.legacy)
        self.assertFalse(Report.objects.exists())

    def test_any_existing_difference_refuses_without_revival_or_partial_changes(self):
        users = get_user_model()
        changes = [
            lambda: AdminAuthority.objects.filter(user__username="administrator2").update(active=False),
            lambda: ChannelSource.objects.filter(unit__code="SIM-UNIT-02").update(active=False),
            lambda: SharingChannel.objects.filter(code="CH-DEMO-02").update(active=False),
            lambda: Unit.objects.filter(code="SIM-UNIT-02").update(active=False),
            lambda: users.objects.filter(username="submitter2").update(is_active=False),
            lambda: users.objects.filter(username="submitter2").update(password="unusable-synthetic"),
            lambda: ChannelMember.objects.filter(user__username="recipient-full").update(profile_ceiling="DEMO-SUMMARY"),
            lambda: UnitMembership.objects.filter(user__username="submitter2").update(active=False),
            lambda: ChannelSource.objects.create(organization=self.org, unit=Unit.objects.get(code="SIM-UNIT-01"),
                channel=SharingChannel.objects.get(code="CH-DEMO-02")),
            lambda: ChannelSource.objects.create(organization=self.org, unit=Unit.objects.get(code="SIM-UNIT-02"),
                channel=SharingChannel.objects.get(code="CH-DEMO-01")),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)), transaction.atomic():
                change()
                before = self.snapshot()
                with self.assertRaises(CommandError):
                    call_command("seed_m3_demo", verbosity=0)
                self.assertEqual(self.snapshot(), before)
                transaction.set_rollback(True)

    def test_seed_refuses_after_new_unit_reporting_starts(self):
        Report.objects.create(id=uuid.uuid4(), organization=self.org,
            unit=Unit.objects.get(code="SIM-UNIT-02"), author=get_user_model().objects.get(username="submitter2"))
        with self.assertRaises(CommandError):
            call_command("seed_m3_demo", verbosity=0)

    def test_legacy_seed_never_repoints_policy_after_any_activation(self):
        users = get_user_model()
        proposer, actor = users.objects.get(username="administrator"), users.objects.get(username="administrator2")
        v1 = PolicyVersion.objects.get(version="demo-policy-v1")
        v2 = PolicyVersion.objects.get(version="demo-policy-v2")
        for target in (v2, None, v1):
            self.org.refresh_from_db()
            proposed = PolicyProposal.objects.create(organization=self.org, kind="ACTIVATE" if target else "DEACTIVATE",
                target_policy=target or v2, target_rules_hash=(target or v2).rules_hash,
                expected_active_policy_id=self.org.active_policy_id, proposer=proposer,
                proposer_permission_version=proposer.permission_version, operation_id=uuid.uuid4(),
                request_hash="a" * 64, proposed_at=timezone.now(), expires_at=timezone.now() + timedelta(hours=1))
            PolicyActivation.objects.create(organization=self.org, proposal=proposed, activator=actor, activated_at=timezone.now())
            PolicyVersion.objects.filter(organization=self.org, active=True).update(active=False)
            if target:
                PolicyVersion.objects.filter(pk=target.id).update(active=True)
            self.org.active_policy = target
            self.org.save(update_fields=["active_policy"])
            before = list(PolicyVersion.objects.order_by("pk").values())
            call_command("seed_demo", verbosity=0)
            self.org.refresh_from_db()
            self.assertEqual(self.org.active_policy_id, target.id if target else None)
            self.assertEqual(before, list(PolicyVersion.objects.order_by("pk").values()))
