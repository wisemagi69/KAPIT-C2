"""Self capability hints never confer policy or integration authority."""
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.scopes.models import AdminAuthority
from tests import test_workflow as workflow


@override_settings(ROOT_URLCONF="config.urls",
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3AdminCapabilityTests(TestCase):
    sign_in = workflow.WorkflowTests.sign_in

    def setUp(self):
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        self.client = APIClient(enforce_csrf_checks=True)
        self.admin = get_user_model().objects.get(username="administrator")

    def context(self):
        response = self.client.get("/api/v1/administration/context/")
        self.assertEqual(response.status_code, 200, response.content)
        return response.json()

    def test_live_self_authorities_and_revocation_leave_account_administration_available(self):
        self.sign_in("administrator")
        self.assertEqual(self.context()["authorities"], ["INTEGRATION", "POLICY"])
        grant = AdminAuthority.objects.get(user=self.admin, kind="POLICY", active=True)
        grant.active = False
        grant.save(update_fields=["active"])
        self.assertEqual(self.context()["authorities"], ["INTEGRATION"])
        grant = AdminAuthority.objects.get(user=self.admin, kind="INTEGRATION", active=True)
        grant.active = False
        grant.save(update_fields=["active"])
        self.assertEqual(set(self.context()), {"units", "channels", "channel_sources"})
        response = self.client.get("/api/v1/administration/users/")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 200)

    def test_no_other_users_authorities_and_nonadministrator_context_denied(self):
        self.sign_in("administrator")
        for grant in AdminAuthority.objects.filter(user=self.admin, active=True):
            grant.active = False
            grant.save(update_fields=["active"])
        self.assertTrue(AdminAuthority.objects.filter(active=True).exists())
        self.assertNotIn("authorities", self.context())
        self.sign_in("reviewer")
        self.assertEqual(self.client.get("/api/v1/administration/context/").status_code, 403)
