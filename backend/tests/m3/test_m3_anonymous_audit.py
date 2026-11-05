"""Actual org-free denial evidence; no fabricated identity or secret fields."""
import json
import uuid
from unittest.mock import patch

from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.accounts.integration_services import revoke_client
from apps.accounts.models import MobileThrottle
from apps.audit import service as audit
from apps.audit.models import AnonymousIntegrationFailure, AuditEvent
from apps.publications.models import PublicationDelivery
from .test_m3_integration import IntegrationFixture, SETTINGS


@override_settings(**SETTINGS, ROOT_URLCONF="config.urls")
class AnonymousIntegrationAuditTests(IntegrationFixture, TestCase):
    route = "/api/integration/v1/publications/"

    def test_unknown_missing_and_malformed_keys_commit_one_fixed_identity_free_event(self):
        cases = [(None, None), ("Basic invalid", None), ("Bearer invalid", None),
                 ("Bearer kapit_ic_abcd1234_" + "A" * 43, "abcd1234"),
                 ("Bearer kapit_ic_abcd12é3_" + "A" * 43, None)]
        expected = {"code": "AUTHENTICATION_REQUIRED", "message": "Use a valid integration key."}
        for header, prefix in cases:
            before = AnonymousIntegrationFailure.objects.count()
            self.reader.credentials(**({"HTTP_AUTHORIZATION": header} if header else {}))
            response = self.reader.get(self.route)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json(), expected)
            self.assertEqual(AnonymousIntegrationFailure.objects.count(), before + 1)
            row = AnonymousIntegrationFailure.objects.latest("recorded_at")
            self.assertEqual((row.event, row.outcome, row.code, row.prefix),
                ("INTEGRATION_AUTH_FAILED", "DENIED", "AUTHENTICATION_REQUIRED", prefix))
            self.assertTrue(timezone.is_aware(row.recorded_at))
            if header:
                encoded = json.dumps(list(AnonymousIntegrationFailure.objects.values()), default=str)
                self.assertTrue(header not in encoded, "Raw header escaped into anonymous evidence")
        self.assertEqual(AuditEvent.objects.filter(action="INTEGRATION_AUTH_FAILED").count(), 0)
        self.assertEqual({field.name for field in AnonymousIntegrationFailure._meta.fields},
                         {"id", "event", "outcome", "code", "prefix", "recorded_at"})

    def test_known_revoked_key_uses_only_organization_event_and_never_stores_key(self):
        client, key = self.issue()
        revoke_client(self.admin, client.id)
        response = self.reader.get(self.route)
        self.assertEqual(response.status_code, 401)
        self.assertFalse(AnonymousIntegrationFailure.objects.exists())
        event = AuditEvent.objects.get(action="INTEGRATION_AUTH_FAILED")
        self.assertEqual(event.organization_id, client.organization_id)
        self.assertEqual(event.safe_metadata, {"prefix": client.key_prefix})
        self.assertTrue(key not in json.dumps(event.safe_metadata))

    def test_anonymous_and_known_audit_failures_are_fixed_503_without_partial_read(self):
        with patch("apps.audit.service.AnonymousIntegrationFailure.objects.create",
                   side_effect=RuntimeError("RAW_FAILURE_CANARY")):
            response = self.reader.get(self.route)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"code": "SERVER_ERROR", "message": "The service is unavailable. Retry later."})
        self.assertNotIn("RAW_FAILURE_CANARY", response.content.decode())
        self.assertFalse(AnonymousIntegrationFailure.objects.exists())
        client, _ = self.issue()
        revoke_client(self.admin, client.id)
        with patch("apps.accounts.integration_auth.audit.record", side_effect=DatabaseError("RAW_FAILURE_CANARY")):
            response = self.reader.get(self.route)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("RAW_FAILURE_CANARY", response.content.decode())
        self.assertFalse(AuditEvent.objects.filter(action="INTEGRATION_AUTH_FAILED").exists())
        self.assertFalse(PublicationDelivery.objects.exists())

    def test_disallowed_methods_have_no_anonymous_or_counter_side_effect(self):
        for method in ("post", "put", "patch", "delete", "head", "options"):
            response = getattr(self.reader, method)(self.route)
            self.assertEqual(response.status_code, 405)
        self.assertFalse(AnonymousIntegrationFailure.objects.exists())
        self.assertFalse(MobileThrottle.objects.exists())
        self.assertFalse(PublicationDelivery.objects.exists())

    def test_service_omits_invalid_prefix_and_sql_enforces_ascii_fixed_fields_and_immutability(self):
        for prefix in ("TOOLONGPREFIX", "UPPER123", "abc1234\n", "abcd12é3", 123, ""):
            row = audit.anonymous_integration_failure(prefix)
            self.assertIsNone(row.prefix)
        initial = AnonymousIntegrationFailure.objects.count()
        for field, value in (("prefix", "UPPER123"), ("prefix", "abc1234\n"), ("prefix", "abcd12é3"),
                             ("prefix", "abcd1234\n"), ("event", "ARBITRARY"), ("outcome", "ALLOWED"), ("code", "ARBITRARY")):
            values = {"event": "INTEGRATION_AUTH_FAILED", "outcome": "DENIED", "code": "AUTHENTICATION_REQUIRED", "prefix": None, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(DatabaseError), transaction.atomic():
                with connection.cursor() as cursor:
                    cursor.execute("INSERT INTO audit_anonymousintegrationfailure (id,event,outcome,code,prefix,recorded_at) VALUES (%s,%s,%s,%s,%s,%s)",
                        [uuid.uuid4(), values["event"], values["outcome"], values["code"], values["prefix"], timezone.now()])
        self.assertEqual(AnonymousIntegrationFailure.objects.count(), initial)
        row = AnonymousIntegrationFailure.objects.first()
        with self.assertRaises(DatabaseError), transaction.atomic():
            AnonymousIntegrationFailure.objects.filter(pk=row.pk).update(prefix="abcd1234")
        with self.assertRaises(DatabaseError), transaction.atomic():
            AnonymousIntegrationFailure.objects.filter(pk=row.pk).delete()
        with connection.cursor() as cursor:
            cursor.execute("SELECT collation_name FROM information_schema.columns WHERE table_schema='public' AND table_name='audit_anonymousintegrationfailure' AND column_name='prefix'")
            self.assertEqual(cursor.fetchone()[0], "C")
