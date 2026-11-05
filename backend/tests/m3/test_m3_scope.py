"""Real PostgreSQL M3 account context and separate authority boundaries."""
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import transaction
from django.test import TestCase, override_settings

from apps.accounts.services import admin_user_m3, reset_password, update_user
from apps.operations.errors import ApiError
from apps.scopes.access import recipient_grant, user_object
from apps.scopes.models import ChannelMember, SharingChannel, UnitMembership


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3ScopeTests(TestCase):
    def setUp(self):
        call_command("seed_demo", verbosity=0)
        self.users = get_user_model()
        self.legacy = user_object(self.users.objects.get(username="submitter"))
        call_command("seed_m3_demo", verbosity=0)

    def test_legacy_unchanged_and_multi_contexts_expose_only_assignments(self):
        self.assertEqual(user_object(self.users.objects.get(username="submitter")), self.legacy)
        submitter = user_object(self.users.objects.get(username="submitter2"))
        self.assertIsNone(submitter["channel"])
        self.assertIsNone(submitter["profile"])
        self.assertEqual({row["code"] for row in submitter["channels"]}, {"CH-DEMO-02", "CH-DEMO-03"})
        multi = user_object(self.users.objects.get(username="recipient-multi"))
        self.assertEqual(len(multi["grants"]), 2)
        self.assertEqual(len(multi["channels"]), 2)
        self.assertIsNone(multi["channel"])
        full = self.users.objects.get(username="recipient-full")
        channel = SharingChannel.objects.get(code="CH-DEMO-02")
        self.assertEqual(recipient_grant(full, channel.id).profile_ceiling, "DEMO-FULL")
        ChannelMember.objects.filter(user=full).update(active=False)
        with self.assertRaises(ApiError):
            recipient_grant(full, channel.id)

    def test_authority_holders_cannot_be_reset_demoted_or_disabled_by_another_admin(self):
        actor = self.users.objects.get(username="administrator")
        target = self.users.objects.get(username="administrator2")
        for changes in ({"role": "submitter"}, {"is_active": False}):
            with self.subTest(changes=changes), self.assertRaises(ApiError) as caught, transaction.atomic():
                update_user(actor, target.id, {"expected_permission_version": 0, **changes})
            self.assertEqual(caught.exception.safe_body["code"], "AUTHORITY_PROTECTED")
        with self.assertRaises(ApiError) as caught, transaction.atomic():
            reset_password(actor, target.id, {"expected_permission_version": 0, "password": "FictionalReplacement!2026"})
        self.assertEqual(caught.exception.safe_body["code"], "AUTHORITY_PROTECTED")
        target.refresh_from_db()
        self.assertEqual(target.permission_version, 0)
        self.assertTrue(target.check_password("DemoMaintenance!2026"))

    def test_administrator_can_assign_multi_channel_unit_without_review_authority(self):
        actor = self.users.objects.get(username="administrator")
        target = self.users.objects.get(username="submitter2")
        result = update_user(actor, target.id, {"expected_permission_version": 0, "display_name": "Changed synthetic label"})
        self.assertEqual(result["role"], "submitter")
        self.assertFalse(UnitMembership.objects.filter(user=actor, active=True).exists())

    def test_admin_projection_keeps_legacy_shape_and_exposes_expanded_ceiling(self):
        legacy = admin_user_m3(self.users.objects.get(username="recipient"))
        self.assertEqual(set(legacy), {"id", "username", "display_name", "role", "is_active",
            "permission_version", "unit_id", "channel_id"})
        for name, ceiling in (("recipient-full", "DEMO-FULL"), ("recipient-summary", "DEMO-SUMMARY")):
            with self.subTest(name=name):
                result = admin_user_m3(self.users.objects.get(username=name))
                self.assertEqual(result["profile_ceiling"], ceiling)
                self.assertIsNotNone(result["channel_id"])
        result = admin_user_m3(self.users.objects.get(username="recipient-multi"))
        self.assertIsNone(result["profile_ceiling"])
        self.assertIsNone(result["channel_id"])
        # CH01 gains explicit M3 eligibility without changing its legacy maximum.
        recipient = self.users.objects.get(username="recipient-multi")
        channel = SharingChannel.objects.get(code="CH-DEMO-01")
        ChannelMember.objects.filter(user=recipient, channel=channel).update(profile_ceiling="DEMO-SUMMARY")
        self.assertEqual(recipient_grant(recipient, channel.id).profile_ceiling, "DEMO-SUMMARY")
