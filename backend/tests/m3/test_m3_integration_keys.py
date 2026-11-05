"""Real PostgreSQL one-time secret lifecycle; never print generated keys."""
import json
import re
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.accounts.integration_services import (administration_state, approve_client, collect_client,
                                              key_digest, request_client, revoke_client)
from apps.accounts.models import IntegrationClient, IntegrationClientApproval, IntegrationClientRequest
from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.scopes.models import AdminAuthority, SharingChannel


@override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3IntegrationKeyTests(TestCase):
    def setUp(self):
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        self.first = get_user_model().objects.get(username="administrator")
        self.second = get_user_model().objects.get(username="administrator2")
        self.recipient = get_user_model().objects.get(username="recipient-full")
        self.channel = SharingChannel.objects.get(code="CH-DEMO-02")

    def request(self, profile="DEMO-REDUCED", **overrides):
        data = {"operation_id": uuid.uuid4(), "channel_id": self.channel.id,
                "profile_ceiling": profile, "label": "Fictional local reader",
                "expires_at": timezone.now() + timedelta(days=7), **overrides}
        raw = {key: value.isoformat() if hasattr(value, "isoformat") else str(value) for key, value in data.items()}
        return data, raw

    def full(self):
        data, raw = self.request("DEMO-FULL")
        result, created = request_client(self.first, data, raw)
        self.assertTrue(created)
        self.assertIsNone(result["client"])
        self.assertNotIn("key", result)
        return result["request"]["id"]

    def test_reduced_and_summary_collect_atomically_secret_is_never_replayed_or_stored(self):
        for profile in ("DEMO-REDUCED", "DEMO-SUMMARY"):
            with self.subTest(profile=profile):
                data, raw = self.request(profile)
                result, created = request_client(self.first, data, raw)
                self.assertTrue(created)
                key = result.pop("key")
                self.assertTrue(bool(re.fullmatch(r"kapit_ic_[a-z0-9]{8}_[A-Za-z0-9_-]{43}", key)))
                client = IntegrationClient.objects.get(pk=result["client"]["id"])
                self.assertTrue(client.key_digest == key_digest(key))
                replay, created = request_client(self.first, data, raw)
                self.assertEqual(replay, result)
                self.assertFalse(created)
                collected, created = collect_client(self.first, result["request"]["id"])
                self.assertEqual(collected, result)
                self.assertFalse(created)
                serialized = json.dumps({"state": administration_state(self.second),
                    "audit": list(AuditEvent.objects.values("action", "safe_metadata")),
                    "requests": list(IntegrationClientRequest.objects.values("request_hash"))})
                self.assertTrue(key not in serialized, "Plaintext key escaped its first collect response")

    def test_full_requires_different_approver_and_requester_collects_once(self):
        request_id = self.full()
        with self.assertRaises(ApiError):
            collect_client(self.first, request_id)
        with self.assertRaises(ApiError) as caught:
            approve_client(self.first, request_id)
        self.assertEqual(caught.exception.safe_body["code"], "SELF_APPROVAL_DENIED")
        approval, created = approve_client(self.second, request_id)
        self.assertTrue(created)
        self.assertEqual(approve_client(self.second, request_id), (approval, False))
        with self.assertRaises(ApiError):
            collect_client(self.second, request_id)
        result, created = collect_client(self.first, request_id)
        self.assertTrue(created)
        self.assertTrue("key" in result)
        replay, created = collect_client(self.first, request_id)
        self.assertFalse(created)
        self.assertNotIn("key", replay)
        self.assertEqual(IntegrationClient.objects.count(), 1)

    def test_current_authorities_checked_at_collect_but_issued_client_is_not_revoked_with_issuer(self):
        request_id = self.full()
        approve_client(self.second, request_id)
        grant = AdminAuthority.objects.get(user=self.second, kind="INTEGRATION", active=True)
        grant.active = False
        grant.save(update_fields=["active"])
        with self.assertRaises(ApiError):
            collect_client(self.first, request_id)
        self.assertFalse(IntegrationClient.objects.exists())
        grant.active = True
        grant.save(update_fields=["active"])
        result, _ = collect_client(self.first, request_id)
        AdminAuthority.objects.filter(user=self.first, kind="INTEGRATION").update(active=False)
        client = IntegrationClient.objects.get(pk=result["client"]["id"])
        self.assertIsNone(client.revoked_at)
        # Authentication's separate T21 tests must establish that this stored key still reads.
        with self.assertRaises(ApiError):
            collect_client(self.first, request_id)

    def test_expiry_channel_ceiling_deadline_roles_and_conflicting_operation(self):
        for overrides in ({"expires_at": timezone.now() - timedelta(seconds=1)},
                          {"expires_at": timezone.now() + timedelta(days=91)}, {"label": " "}):
            data, raw = self.request(**overrides)
            with self.assertRaises(ApiError):
                request_client(self.first, data, raw)
        data, raw = self.request()
        with self.assertRaises(ApiError):
            request_client(self.recipient, data, raw)
        result, _ = request_client(self.first, data, raw)
        with self.assertRaises(ApiError) as caught:
            request_client(self.first, data, {**raw, "label": "Changed fictional reader"})
        self.assertEqual(caught.exception.safe_body["code"], "IDEMPOTENCY_CONFLICT")
        request_id = self.full()
        deadline = IntegrationClientRequest.objects.get(pk=request_id).collect_deadline
        with patch("apps.accounts.integration_services.timezone.now", return_value=deadline + timedelta(seconds=1)), self.assertRaises(ApiError):
            approve_client(self.second, request_id)
        approve_client(self.second, request_id)
        SharingChannel.objects.filter(pk=self.channel.id).update(max_profile="DEMO-REDUCED")
        with self.assertRaises(ApiError):
            collect_client(self.first, request_id)
        self.assertEqual(IntegrationClient.objects.count(), 1)

    def test_request_approve_collect_and_revoke_audit_faults_roll_back(self):
        data, raw = self.request()
        with patch("apps.accounts.integration_services.audit.record", side_effect=RuntimeError("synthetic fault")), self.assertRaises(RuntimeError):
            request_client(self.first, data, raw)
        self.assertFalse(IntegrationClientRequest.objects.exists())
        request_id = self.full()
        with patch("apps.accounts.integration_services.audit.record", side_effect=RuntimeError("synthetic fault")), self.assertRaises(RuntimeError):
            approve_client(self.second, request_id)
        self.assertFalse(IntegrationClientApproval.objects.exists())
        approve_client(self.second, request_id)
        with patch("apps.accounts.integration_services.audit.record", side_effect=RuntimeError("synthetic fault")), self.assertRaises(RuntimeError):
            collect_client(self.first, request_id)
        self.assertFalse(IntegrationClient.objects.exists())
        result, _ = collect_client(self.first, request_id)
        client_id = result["client"]["id"]
        with patch("apps.accounts.integration_services.audit.record", side_effect=RuntimeError("synthetic fault")), self.assertRaises(RuntimeError):
            revoke_client(self.second, client_id)
        self.assertIsNone(IntegrationClient.objects.get(pk=client_id).revoked_at)
        first = revoke_client(self.second, client_id)
        self.assertEqual(revoke_client(self.second, client_id), first)
        self.assertEqual(AuditEvent.objects.filter(action="INTEGRATION_REVOKED").count(), 1)

    def test_digest_domain_separation_and_global_key_rotation(self):
        with override_settings(SECRET_KEY="synthetic signing key A"):
            first = key_digest("kapit_ic_aaaaaaaa_synthetic-test-key")
        with override_settings(SECRET_KEY="synthetic signing key B"):
            second = key_digest("kapit_ic_aaaaaaaa_synthetic-test-key")
        self.assertNotEqual(first, second)
