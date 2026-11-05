from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.accounts.mobile_protocol import MobileError
from apps.accounts.mobile_services import _submitter_context


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3MobileContextTests(TestCase):
    def test_new_contexts_cannot_enroll_and_m2_user_shape_is_frozen(self):
        call_command("seed_demo", verbosity=0)
        users = get_user_model()
        before = _submitter_context(users.objects.get(username="submitter"))
        call_command("seed_m3_demo", verbosity=0)
        self.assertEqual(_submitter_context(users.objects.get(username="submitter")), before)
        self.assertEqual(set(before), {"id", "username", "display_name", "role", "unit", "channel", "profile"})
        self.assertEqual(before["profile"], "DEMO-REDUCED")
        with self.assertRaises(MobileError):
            _submitter_context(users.objects.get(username="submitter2"))
