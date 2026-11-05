"""Integration API tests; PostgreSQL/LiveServer execution belongs to parent."""
import json
import os
import subprocess
import sys
import threading
import uuid
from io import BytesIO
from contextlib import redirect_stderr, redirect_stdout
from http.client import BadStatusLine, IncompleteRead
from io import StringIO
from types import SimpleNamespace
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core import signing
from django.db import close_old_connections
from django.http import QueryDict
from django.test import LiveServerTestCase, SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import include, path
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.integration_services import administration_state, approve_client, collect_client, request_client, revoke_client
from apps.accounts.administration import IntegrationRequestParser
from apps.accounts.models import IntegrationClient, MobileThrottle
from apps.audit import service as audit
from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.publications import selectors
from apps.publications.models import PublicationDelivery
from apps.scopes.models import AdminAuthority, SharingChannel
from .clients.kapit_feed import local_base
from .clients import kapit_feed
from .test_m3_review import ReviewFixture, SETTINGS


urlpatterns = [path("api/v1/", include("apps.operations.urls")),
               path("api/integration/v1/", include("apps.publications.integration_urls"))]
API = "/api/integration/v1/"
ADMIN = "/api/v1/administration/integration-clients/"


class ReferenceBoundaryTests(SimpleTestCase):
    def test_malformed_reference_response_prints_only_fixed_failure(self):
        secret = "SYNTHETIC_KEY_ECHO_CANARY"
        for error in (BadStatusLine("RAW_SERVER_CANARY " + secret), IncompleteRead(b"RAW_SERVER_CANARY " + secret.encode(), 100)):
            stdout, stderr = StringIO(), StringIO()
            with patch.object(sys, "argv", ["kapit_feed.py", "http://127.0.0.1:8000/api/integration/v1/"]), patch.dict(os.environ, {"KAPIT_INTEGRATION_KEY": secret}), patch.object(kapit_feed, "build_opener") as opener, redirect_stdout(stdout), redirect_stderr(stderr):
                opener.return_value.open.side_effect = error
                self.assertEqual(kapit_feed.main(), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "Integration read failed.\n")
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
            self.assertNotIn("RAW_SERVER_CANARY", stdout.getvalue() + stderr.getvalue())

    def test_admin_parser_preserves_exact_bounded_wire_payload(self):
        request = SimpleNamespace()
        parser = IntegrationRequestParser()
        wire = b'{ "label" : "Fictional" }'
        self.assertEqual(parser.parse(BytesIO(wire), parser_context={"request": request}), {"label": "Fictional"})
        self.assertEqual(request.integration_raw_body, wire.decode())
        with self.assertRaises(ApiError) as caught:
            parser.parse(BytesIO(b" " * (20 * 1024 + 1)), parser_context={"request": request})
        self.assertEqual(caught.exception.status_code, 413)

    def test_reader_accepts_only_literal_loopback_http_and_exact_path(self):
        self.assertEqual(local_base("http://localhost:9876/api/integration/v1/"), "http://127.0.0.1:9876/api/integration/v1/")
        for value in ("https://example.com/api/integration/v1/", "http://127.0.0.1.evil/api/integration/v1/", "http://user@127.0.0.1/api/integration/v1/", "http://127.0.0.1/api/integration/v1/?key=canary", "http://127.0.0.1/wrong/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                local_base(value)

    def test_audit_prefix_only_fixed_grammar_for_auth_failure(self):
        for action, metadata in (("INTEGRATION_READ", {"prefix": "abcd1234"}), ("INTEGRATION_AUTH_FAILED", {"prefix": "PRIVATE_CANARY"}), ("INTEGRATION_AUTH_FAILED", {"key": "PRIVATE_CANARY"})):
            with patch("apps.audit.service.AuditEvent.objects.create") as create:
                with self.assertRaises(ValueError):
                    audit.record(uuid.uuid4(), None, action, **metadata)
                create.assert_not_called()
        with patch("apps.audit.service.AuditEvent.objects.create") as create:
            audit.record(uuid.uuid4(), None, "INTEGRATION_AUTH_FAILED", prefix="abcd1234")
            self.assertEqual(create.call_args.kwargs["safe_metadata"], {"prefix": "abcd1234"})


class IntegrationFixture(ReviewFixture):
    def setUp(self):
        super().setUp()
        self.admin = get_user_model().objects.get(username="administrator")
        self.second = get_user_model().objects.get(username="administrator2")
        self.channel = SharingChannel.objects.get(code="CH-DEMO-02")
        self.reader = APIClient()

    def issue(self, profile="DEMO-REDUCED"):
        data = {"operation_id": uuid.uuid4(), "channel_id": self.channel.id, "profile_ceiling": profile,
                "label": "Fictional local reader", "expires_at": timezone.now() + timedelta(days=7)}
        result, _ = request_client(self.admin, data, {key: str(value) for key, value in data.items()})
        if profile == "DEMO-FULL":
            approve_client(self.second, result["request"]["id"])
            result, _ = collect_client(self.admin, result["request"]["id"])
        client = IntegrationClient.objects.get(pk=result["client"]["id"])
        self.reader.credentials(HTTP_AUTHORIZATION="Bearer " + result["key"])
        return client, result["key"]


@override_settings(**SETTINGS, ROOT_URLCONF=__name__)
class IntegrationAPITests(IntegrationFixture, TestCase):
    def test_uniform_401_session_ignored_no_secret_audit_and_known_revocation(self):
        client, key = self.issue()
        bad_headers = [None, "Basic invalid", "Bearer invalid", "Bearer kapit_ic_abcd1234_" + "x" * 43]
        expected = {"code": "AUTHENTICATION_REQUIRED", "message": "Use a valid integration key."}
        for header in bad_headers:
            self.reader.credentials(**({"HTTP_AUTHORIZATION": header} if header else {}))
            self.reader.force_authenticate(user=self.admin)
            response = self.reader.get(API + "publications/")
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json(), expected)
            self.assertIn("no-store", response["Cache-Control"])
        self.reader.force_authenticate(user=None)
        self.reader.credentials(HTTP_AUTHORIZATION="Bearer " + key)
        self.assertEqual(self.reader.get(API + "publications/", {"api_key": key}).status_code, 401)
        revoke_client(self.admin, client.id)
        response = self.reader.get(API + "publications/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), expected)
        events = AuditEvent.objects.filter(action="INTEGRATION_AUTH_FAILED")
        self.assertEqual(events.count(), 1)
        self.assertEqual(events.get().safe_metadata, {"prefix": client.key_prefix})
        self.assertNotIn(key, json.dumps(list(AuditEvent.objects.values("safe_metadata"))))

    def test_write_head_options_have_no_counter_audit_or_delivery_side_effects(self):
        self.issue()
        before = (MobileThrottle.objects.count(), AuditEvent.objects.count(), PublicationDelivery.objects.count())
        for method in ("post", "put", "patch", "delete", "head", "options"):
            response = getattr(self.reader, method)(API + "publications/")
            self.assertEqual(response.status_code, 405)
            self.assertEqual(response["Allow"], "GET")
        self.assertEqual((MobileThrottle.objects.count(), AuditEvent.objects.count(), PublicationDelivery.objects.count()), before)

    def test_exact_recipient_projection_and_client_delivery_detail(self):
        revision, _ = self.submit_source()
        self.batch(revision)
        client, _ = self.issue()
        response = self.reader.get(API + "publications/")
        self.assertEqual(response.status_code, 200)
        _, chosen = selectors.selected_publications(None, self.org, client.channel_id, client=client)
        self.assertEqual(response.json()["results"], [selectors.serialize_publication(row) for row in chosen])
        self.assertTrue(chosen)
        recipient = get_user_model().objects.get(username="recipient-limited")
        actor_scope, recipient_rows = selectors.selected_publications(recipient, self.org, self.channel.id)
        self.assertEqual(response.json()["results"], [selectors.serialize_publication(row) for row in recipient_rows])
        row = chosen[0]
        self.assertEqual(self.reader.get(API + f"publications/{row.id}/").json(), selectors.serialize_publication(row))
        self.assertEqual(PublicationDelivery.objects.filter(client=client, user__isnull=True).count(), len(chosen))
        self.assertEqual(self.reader.get(API + f"publications/{uuid.uuid4()}/").status_code, 404)

    def test_cursor_binds_client_filters_surface_scope_policy_and_signature(self):
        for _ in range(3):
            revision, _ = self.submit_source()
            self.batch(revision)
        client, first_key = self.issue()
        first = self.reader.get(API + "publications/", {"limit": 1}).json()
        cursor = first["next_cursor"]
        self.assertIsInstance(cursor, str)
        decoded = signing.loads(cursor, salt="kapit.integration.cursor")
        self.assertNotIn("published_at", decoded)
        self.assertEqual(len(self.reader.get(API + "publications/", {"limit": 1, "cursor": cursor}).json()["results"]), 1)
        for params in ({"limit": 2, "cursor": cursor}, {"limit": 1, "cursor": cursor + "x"}, {"limit": 1, "cursor": cursor, "category": "WATER_SUPPLY"}):
            response = self.reader.get(API + "publications/", params)
            self.assertEqual(response.json()["code"], "INVALID_CURSOR")
        self.assertEqual(self.reader.get(API + "removed/", {"cursor": cursor}).json()["code"], "INVALID_CURSOR")
        self.issue()
        self.assertEqual(self.reader.get(API + "publications/", {"limit": 1, "cursor": cursor}).json()["code"], "INVALID_CURSOR")
        self.reader.credentials(HTTP_AUTHORIZATION="Bearer " + first_key)
        for field in ("scope_epochs_digest", "policy_epoch"):
            changed = dict(decoded)
            changed[field] = "wrong" if field.endswith("digest") else decoded[field] + 1
            forged = signing.dumps(changed, salt="kapit.integration.cursor")
            self.assertEqual(self.reader.get(API + "publications/", {"limit": 1, "cursor": forged}).json()["code"], "INVALID_CURSOR")
        with patch("django.core.signing.time.time", return_value=timezone.now().timestamp() + 901):
            self.assertEqual(self.reader.get(API + "publications/", {"limit": 1, "cursor": cursor}).json()["code"], "INVALID_CURSOR")

    def test_different_channel_publication_is_absent_from_feed_detail_and_removals(self):
        revision, _ = self.submit_source()
        self.batch(revision)
        other, _ = self.submit_source(author=get_user_model().objects.get(username="submitter"))
        previous = self.reviewer
        self.reviewer = get_user_model().objects.get(username="reviewer")
        self.batch(other)
        self.reviewer = previous
        client, _ = self.issue()
        from apps.publications.models import Publication
        hidden = Publication.objects.filter(report=other.report).first()
        self.assertIsNotNone(hidden)
        response = self.reader.get(API + "publications/")
        self.assertEqual(len(response.json()["results"]), 1)
        self.assertNotIn(str(hidden.id), json.dumps(response.json()))
        self.assertEqual(self.reader.get(API + f"publications/{hidden.id}/").status_code, 404)
        self.assertEqual(self.reader.get(API + "removed/").json()["results"], [])

    def test_removed_only_delivered_to_this_client_and_no_republication_on_retry(self):
        from apps.publications.services import withdraw_report
        revision, _ = self.submit_source()
        self.batch(revision)
        client, first_key = self.issue()
        items = self.reader.get(API + "publications/").json()["results"]
        second, second_key = self.issue()
        withdrawal = self.withdrawal_body(revision)
        withdraw_report(self.reviewer, revision.report_id, withdrawal, withdrawal)
        self.assertEqual(self.reader.get(API + "removed/").json()["results"], [])
        self.reader.credentials(HTTP_AUTHORIZATION="Bearer " + first_key)
        self.assertEqual(self.reader.get(API + "publications/").json()["results"], [])
        self.assertEqual(self.reader.get(API + "removed/").json()["results"], [{"publication_id": row["id"], "state": "WITHDRAWN"} for row in items])

    def test_issuer_revocation_does_not_revoke_client_channel_and_expiry_do(self):
        client, _ = self.issue()
        AdminAuthority.objects.filter(user=self.admin, kind="INTEGRATION").update(active=False)
        self.assertEqual(self.reader.get(API + "publications/").status_code, 200)
        # Time advancement exercises the immutable expiry without forbidden row edits.
        with patch("apps.accounts.integration_auth.timezone.now", return_value=client.expires_at + timedelta(seconds=1)):
            self.assertEqual(self.reader.get(API + "publications/").status_code, 401)
        SharingChannel.objects.filter(pk=self.channel.id).update(active=False)
        self.assertEqual(self.reader.get(API + "publications/").status_code, 401)

    def test_nullable_active_policy_and_inactive_policy_return_uniform_401(self):
        from django.db import transaction
        from apps.scopes.models import Organization, PolicyVersion
        self.issue()
        expected = {"code": "AUTHENTICATION_REQUIRED", "message": "Use a valid integration key."}
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.pk)
            org.active_policy = None
            org.save(update_fields=["active_policy"])
        response = self.reader.get(API + "publications/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), expected)
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.pk)
            org.active_policy_id = self.org.active_policy_id
            org.save(update_fields=["active_policy"])
            PolicyVersion.objects.filter(pk=org.active_policy_id).update(active=False)
        response = self.reader.get(API + "publications/")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json(), expected)

    def test_throttle_is_bounded_private_and_independent_of_mobile_config(self):
        from apps.accounts.integration_auth import consume
        with override_settings(KAPIT_MOBILE_AUTH=None):
            consume("address", "PRIVATE_ADDRESS_CANARY", 1)
            with self.assertRaises(ApiError) as caught:
                consume("address", "PRIVATE_ADDRESS_CANARY", 1)
        self.assertEqual(caught.exception.status_code, 429)
        counter = MobileThrottle.objects.get()
        self.assertEqual(len(counter.key), 64)
        self.assertTrue(counter.key.startswith("integration:"))
        self.assertNotIn("PRIVATE_ADDRESS_CANARY", counter.key)
        self.assertEqual(counter.attempts, 2)

    def test_delivery_and_read_audit_failure_return_no_body_and_roll_back_delivery(self):
        revision, _ = self.submit_source()
        self.batch(revision)
        client, _ = self.issue()
        for target in ("apps.publications.delivery.PublicationDelivery.objects.get_or_create", "apps.publications.integration_views.audit.record"):
            with patch(target, side_effect=RuntimeError("PRIVATE_FAILURE_CANARY")):
                response = self.reader.get(API + "publications/")
            self.assertEqual(response.status_code, 500)
            self.assertNotIn("PRIVATE_FAILURE_CANARY", response.content.decode())
            self.assertFalse(PublicationDelivery.objects.filter(client=client).exists())

    def test_admin_strict_request_full_two_person_collect_once_and_bounded_state(self):
        admin = APIClient()
        admin.force_authenticate(user=self.admin)
        body = {"operation_id": str(uuid.uuid4()), "channel_id": str(self.channel.id), "profile_ceiling": "DEMO-FULL",
                "label": "Fictional reader", "expires_at": (timezone.now() + timedelta(days=2)).isoformat()}
        response = admin.post(ADMIN, body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(response.status_code, 201)
        request_id = response.json()["request"]["id"]
        replay = admin.post(ADMIN, body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(replay.status_code, 200)
        conflict = admin.post(ADMIN, json.dumps(body, indent=2), content_type="application/json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["code"], "IDEMPOTENCY_CONFLICT")
        approve = ADMIN + f"requests/{request_id}/approve/"
        collect = ADMIN + f"requests/{request_id}/collect/"
        self.assertEqual(admin.post(approve, {}, format="json").status_code, 403)
        admin.force_authenticate(user=self.second)
        self.assertEqual(admin.post(approve, {}, format="json").status_code, 200)
        self.assertEqual(admin.post(collect, {}, format="json").status_code, 404)
        admin.force_authenticate(user=self.admin)
        first = admin.post(collect, {}, format="json")
        self.assertIn("key", first.json())
        self.assertNotIn("key", admin.post(collect, {}, format="json").json())
        self.issue()
        state = admin.get(ADMIN, {"page_size": 1}).json()
        self.assertEqual(len(state["clients"]), 1)
        self.assertTrue(state["clients_more"])
        self.assertNotIn(first.json()["key"], json.dumps(state))
        self.assertEqual(admin.get(ADMIN + "?page=1&page=2").json()["code"], "INVALID_FILTER")
        body.update(operation_id=str(uuid.uuid4()), unexpected="PRIVATE_INPUT_CANARY")
        rejected = admin.post(ADMIN, body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(rejected.status_code, 422)
        self.assertNotIn("PRIVATE_INPUT_CANARY", rejected.content.decode())

    def test_web_admin_retains_real_csrf_gate(self):
        client = APIClient(enforce_csrf_checks=True)
        client.force_login(self.admin)
        response = client.post(ADMIN, {}, format="json")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "CSRF_FAILED")


@override_settings(**SETTINGS, ROOT_URLCONF=__name__)
class IntegrationCollectionRaceTests(IntegrationFixture, TransactionTestCase):
    def test_withdrawal_waits_for_atomic_page_then_next_page_is_removed(self):
        from apps.publications.services import withdraw_report
        revision, _ = self.submit_source()
        self.batch(revision)
        client, key = self.issue()
        entered, release, withdrawing = threading.Event(), threading.Event(), threading.Event()
        original = selectors.selected_publications
        results, errors = [], []
        def paused_selector(*args, **kwargs):
            entered.set()
            if not release.wait(timeout=10):
                raise RuntimeError("Local race synchronization timed out")
            return original(*args, **kwargs)
        def read():
            close_old_connections()
            try:
                reader = APIClient()
                reader.credentials(HTTP_AUTHORIZATION="Bearer " + key)
                response = reader.get(API + "publications/")
                results.append((response.status_code, len(response.json().get("results", []))))
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                close_old_connections()
        def withdraw():
            close_old_connections()
            try:
                withdrawing.set()
                body = self.withdrawal_body(revision)
                withdraw_report(self.reviewer, revision.report_id, body, body)
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                close_old_connections()
        with patch("apps.publications.integration_views.selectors.selected_publications", side_effect=paused_selector):
            reader = threading.Thread(target=read)
            reader.start()
            self.assertTrue(entered.wait(timeout=10))
            writer = threading.Thread(target=withdraw)
            writer.start()
            self.assertTrue(withdrawing.wait(timeout=10))
            release.set()
            for worker in (reader, writer):
                worker.join(timeout=20)
                self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [(200, 1)])
        self.assertEqual(self.reader.get(API + "publications/").json()["results"], [])
        self.assertEqual(len(self.reader.get(API + "removed/").json()["results"]), 1)

    def test_simultaneous_full_collections_commit_one_secret_and_one_client(self):
        data = {"operation_id": uuid.uuid4(), "channel_id": self.channel.id, "profile_ceiling": "DEMO-FULL", "label": "Fictional race", "expires_at": timezone.now() + timedelta(days=1)}
        result, _ = request_client(self.admin, data, {key: str(value) for key, value in data.items()})
        request_id = result["request"]["id"]
        approve_client(self.second, request_id)
        barrier, results, errors = threading.Barrier(2), [], []
        def collect():
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                value, created = collect_client(self.admin, request_id)
                results.append(("key" in value, created))
            except Exception as error:
                errors.append(type(error).__name__)
            finally:
                close_old_connections()
        workers = [threading.Thread(target=collect) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=20)
            self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(sorted(results), [(False, False), (True, True)])
        self.assertEqual(IntegrationClient.objects.filter(request_id=request_id).count(), 1)


@override_settings(**SETTINGS, ROOT_URLCONF=__name__)
class IntegrationReferenceClientTests(IntegrationFixture, LiveServerTestCase):
    def test_standard_library_reference_client_reads_live_loopback_without_secret_output(self):
        revision, _ = self.submit_source()
        self.batch(revision)
        _, key = self.issue()
        script = Path(__file__).parent / "clients" / "kapit_feed.py"
        result = subprocess.run([sys.executable, str(script), self.live_server_url + API], env={**os.environ, "KAPIT_INTEGRATION_KEY": key}, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, "Reference client failed; output intentionally withheld")
        self.assertGreater(json.loads(result.stdout)["received"], 0)
        self.assertNotIn(key, result.stdout + result.stderr)
