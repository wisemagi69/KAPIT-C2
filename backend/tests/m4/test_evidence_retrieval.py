"""Real disposable DB/session checks with explicit synthetic tool fixtures.

Patched trusted tools establish service/API behavior only, never native readiness.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from threading import Event
from unittest.mock import patch
import uuid

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.services import update_user
from apps.audit.models import AuditEvent
from apps.operations import evidence_processing as processing, evidence_retrieval as retrieval
from apps.operations.evidence import accept_evidence
from apps.operations.evidence_decoder import DecodedEvidence
from apps.operations.evidence_policy import EvidenceError
from apps.operations.errors import ApiError
from apps.operations.models import PrivateEvidence, PrivateEvidenceValidation
from apps.reports.crypto import decrypt, encrypt
from apps.reports.services import accept_operation
from apps.scopes.models import Organization, UnitMembership
from tests.test_workflow import operation
from tests.m4.test_evidence_decoder import png


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(),
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class PrivateEvidenceRetrievalTests(TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        users = get_user_model().objects
        self.actor = users.get(username="submitter")
        self.reviewer = users.get(username="reviewer")
        self.admin = users.get(username="administrator")
        self.recipient = users.get(username="recipient")
        body = operation()
        receipt, _ = accept_operation(self.actor, body, body)
        self.revision_id = uuid.UUID(receipt["revision_id"])
        result, _ = accept_evidence(self.actor, self.revision_id, uuid.uuid4(), png(), "image/png", "synthetic.png")
        self.item = PrivateEvidence.objects.get(pk=result["id"])
        self.manifest = retrieval.tools.ToolManifest("a" * 64, "b" * 64,
            timezone.now() + timedelta(hours=1), 1, "c" * 64, b'{"synthetic_tool_declaration":1}')
        @contextmanager
        def current():
            self.assertFalse(connection.in_atomic_block)
            yield self.manifest
            self.assertFalse(connection.in_atomic_block)
        self.current = patch.object(retrieval.tools, "current_tools", side_effect=current)
        self.current.start()
        self.addCleanup(self.current.stop)
        self.assertion = patch.object(retrieval.tools, "assert_current", side_effect=self.assert_current)
        self.assertion.start()
        self.addCleanup(self.assertion.stop)

    def assert_current(self, manifest):
        self.assertIs(manifest, self.manifest)
        self.assertTrue(connection.in_atomic_block)

    def validate(self, failure=None):
        snapshot = processing.prepare_validation(self.actor, self.item.id, uuid.uuid4())
        scan = (dict(side_effect=EvidenceError(failure)) if failure
                else dict(return_value="SCAN_CLEAN"))
        with patch.object(retrieval.tools, "run_scan", **scan), patch.object(retrieval.tools, "decode",
                return_value=DecodedEvidence("image/png", 1, 1, 1, png())):
            result = processing.run_validation(snapshot)
        processing.commit_validation(self.actor, snapshot, result)
        return PrivateEvidenceValidation.objects.order_by("-created_at", "-id").first()

    def session_client(self, username="submitter"):
        # Real session/CSRF authentication on the disposable database.
        client = APIClient(enforce_csrf_checks=True)
        token = client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        response = client.post("/api/v1/auth/login/", {"username": username,
            "password": "DemoMaintenance!2026"}, format="json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)
        return client

    def test_status_is_exact_and_unvalidated_download_is_uniform_missing(self):
        client = self.session_client()
        result = client.get(f"/api/v1/evidence/{self.item.id}/validation/")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {"evidence_id": str(self.item.id), "state": "QUARANTINED",
            "validation_code": "DECODER_REQUIRED", "can_download": False})
        known = client.get(f"/api/v1/evidence/{self.item.id}/download/")
        unknown = client.get(f"/api/v1/evidence/{uuid.uuid4()}/download/")
        self.assertEqual((known.status_code, known.json()), (unknown.status_code, unknown.json()))

    def test_success_is_audited_prepared_attachment_and_never_invokes_native_on_get(self):
        self.validate()
        client = self.session_client()
        with patch.object(retrieval.tools, "run_scan", side_effect=AssertionError("scan on GET")), \
                patch.object(retrieval.tools, "decode", side_effect=AssertionError("decode on GET")):
            status = client.get(f"/api/v1/evidence/{self.item.id}/validation/")
            response = client.get(f"/api/v1/evidence/{self.item.id}/download/")
        self.assertTrue(status.json()["can_download"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, png())
        self.assertEqual(response["Content-Type"], "image/png")
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="evidence.png"')
        self.assertIn("no-store", {part.strip() for part in response["Cache-Control"].split(",")})
        self.assertNotIn("public", response["Cache-Control"])
        self.assertEqual(response["X-Content-Type-Options"], "nosniff")
        for header in ("ETag", "Last-Modified", "Content-Range"):
            self.assertNotIn(header, response)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_PRIVATE_DOWNLOAD").count(), 1)

    def test_current_origin_reviewer_may_read_but_admin_recipient_and_other_org_may_not(self):
        self.validate()
        self.assertEqual(retrieval.private_evidence_download(self.reviewer, self.item.id), png())
        other = Organization.objects.create(code="RETRIEVAL-OTHER", name="Synthetic other organization")
        outsider = get_user_model().objects.create(username="retrieval-outsider", organization=other, role="submitter")
        for user in (self.admin, self.recipient, outsider):
            for function in (retrieval.validation_status, retrieval.private_evidence_download):
                with self.subTest(user=user.role, function=function.__name__), self.assertRaises(ApiError) as error:
                    function(user, self.item.id)
                self.assertEqual(error.exception.status_code, 404)

    def test_later_failure_prevents_older_success_fallback(self):
        self.validate()
        self.validate("SCAN_NOT_CLEAN")
        status = retrieval.validation_status(self.actor, self.item.id)
        self.assertEqual((status["state"], status["validation_code"], status["can_download"]),
                         ("QUARANTINED", "SCAN_NOT_CLEAN", False))
        with self.assertRaises(ApiError) as error:
            retrieval.private_evidence_download(self.actor, self.item.id)
        self.assertEqual(error.exception.status_code, 404)

    def test_new_manifest_or_expiry_closes_historical_success(self):
        self.validate()
        original = self.manifest
        self.manifest = replace(original, manifest_hash="f" * 64, policy_generation=2)
        self.assertFalse(retrieval.validation_status(self.actor, self.item.id)["can_download"])
        with self.assertRaises(ApiError):
            retrieval.private_evidence_download(self.actor, self.item.id)
        self.manifest = original
        with patch.object(retrieval.timezone, "now", return_value=timezone.now() + timedelta(hours=2)):
            self.assertFalse(retrieval.validation_status(self.actor, self.item.id)["can_download"])

    def test_envelope_swap_identity_bool_digest_metadata_and_provenance_tamper_deny(self):
        row = self.validate()
        envelope = decrypt(row.derivative_ciphertext)
        provenance = decrypt(row.provenance_ciphertext)
        for changes in ({"validation_id": str(uuid.uuid4())}, {"evidence_id": str(uuid.uuid4())},
                        {"organization_id": str(uuid.uuid4())}, {"revision_id": str(uuid.uuid4())},
                        {"input_sha256": "f" * 64}, {"manifest_hash": "f" * 64}, {"frames": True},
                        {"width": True}, {"bytes_sha256": "f" * 64}, {"bytes_base64": "!"},
                        {"unknown": "not accepted"}):
            row.derivative_ciphertext = encrypt(envelope | changes)
            with self.subTest(changes=list(changes)), patch.object(retrieval, "_latest", return_value=row):
                with self.assertRaises(ApiError) as error:
                    retrieval.private_evidence_download(self.actor, self.item.id)
                self.assertEqual(error.exception.status_code, 404)
        row.derivative_ciphertext = encrypt(envelope)
        for changes in ({"actor_id": str(uuid.uuid4())}, {"steps": []},
                        {"manifest": {"synthetic_tool_declaration": True}}, {"code": "UNKNOWN"}):
            row.provenance_ciphertext = encrypt(provenance | changes)
            with self.subTest(changes=list(changes)), patch.object(retrieval, "_latest", return_value=row):
                self.assertFalse(retrieval.validation_status(self.actor, self.item.id)["can_download"])
                with self.assertRaises(ApiError):
                    retrieval.private_evidence_download(self.actor, self.item.id)

    def test_audit_or_currentness_failure_returns_no_bytes(self):
        self.validate()
        before = AuditEvent.objects.count()
        with patch.object(retrieval.audit, "record", side_effect=RuntimeError("PRIVATE_AUDIT_CANARY")):
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
        self.assertEqual(error.exception.status_code, 503)
        self.assertNotIn("PRIVATE", str(error.exception))
        self.assertEqual(AuditEvent.objects.count(), before)
        with patch.object(retrieval.tools, "assert_current", side_effect=retrieval.tools.ToolUnavailable()):
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
        self.assertEqual(error.exception.status_code, 404)

    def test_missing_runtime_does_not_bypass_scope_or_fabricate_ready_status(self):
        self.validate()
        with patch.object(retrieval.tools, "current_tools", side_effect=retrieval.tools.ToolUnavailable()):
            self.assertFalse(retrieval.validation_status(self.actor, self.item.id)["can_download"])
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
            self.assertEqual(error.exception.status_code, 404)
            with self.assertRaises(ApiError) as error:
                retrieval.validation_status(self.recipient, self.item.id)
            self.assertEqual(error.exception.status_code, 404)

    def test_head_options_conditional_range_and_filters_cannot_return_image(self):
        self.validate()
        client = self.session_client()
        url = f"/api/v1/evidence/{self.item.id}/download/"
        for response in (client.head(url), client.options(url), client.get(url, HTTP_RANGE="bytes=0-1"),
                         client.get(url, HTTP_IF_NONE_MATCH='"synthetic"'), client.get(url + "?preview=1")):
            self.assertIn(response.status_code, (404, 405))
            self.assertNotIn(png(), response.content)

    def test_revocation_between_early_check_and_final_fenced_authorization_denies(self):
        self.validate()
        entered, proceed = Event(), Event()
        @contextmanager
        def paused():
            entered.set()
            if not proceed.wait(10):
                raise AssertionError("revocation interleave timed out")
            yield self.manifest
        def download():
            close_old_connections()
            try:
                try:
                    retrieval.private_evidence_download(self.actor, self.item.id)
                    return 200
                except ApiError as error:
                    return error.status_code
            finally:
                close_old_connections()
        with patch.object(retrieval.tools, "current_tools", side_effect=paused):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(download)
                self.assertTrue(entered.wait(10))
                try:
                    update_user(self.admin, self.actor.id, {"is_active": False,
                        "expected_permission_version": self.actor.permission_version})
                finally:
                    proceed.set()
                self.assertEqual(future.result(15), 404)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_PRIVATE_DOWNLOAD").count(), 0)

    def test_outer_transaction_cannot_outlive_fence_or_roll_back_a_delivered_audit(self):
        self.validate()
        before = AuditEvent.objects.count()
        with transaction.atomic(), patch.object(retrieval.tools, "current_tools") as current:
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
            self.assertEqual(error.exception.status_code, 404)
            with self.assertRaises(ApiError) as error:
                retrieval.validation_status(self.actor, self.item.id)
            self.assertEqual(error.exception.status_code, 503)
            current.assert_not_called()
        self.assertEqual(AuditEvent.objects.count(), before)

    def test_validation_expiry_during_artifact_check_cannot_deliver_or_report_ready(self):
        row = self.validate()
        clock = [timezone.now()]
        def slow_check(manifest):
            clock[0] = row.expires_at + timedelta(microseconds=1)
        before = AuditEvent.objects.filter(action="EVIDENCE_PRIVATE_DOWNLOAD").count()
        with patch.object(retrieval.timezone, "now", side_effect=lambda: clock[0]), \
                patch.object(retrieval.tools, "assert_current", side_effect=slow_check):
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
            self.assertEqual(error.exception.status_code, 404)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_PRIVATE_DOWNLOAD").count(), before)
        clock[0] = row.validated_at + timedelta(seconds=1)
        with patch.object(retrieval.timezone, "now", side_effect=lambda: clock[0]), \
                patch.object(retrieval.tools, "assert_current", side_effect=slow_check):
            self.assertFalse(retrieval.validation_status(self.actor, self.item.id)["can_download"])

    def test_membership_expiry_during_artifact_check_is_rechecked_before_audit(self):
        expiry = timezone.now() + timedelta(minutes=1)
        UnitMembership.objects.filter(user=self.actor, active=True).update(valid_until=expiry)
        self.validate()
        clock = [timezone.now()]
        def slow_check(manifest):
            clock[0] = expiry + timedelta(seconds=1)
        with patch.object(retrieval.timezone, "now", side_effect=lambda: clock[0]), \
                patch.object(retrieval.tools, "assert_current", side_effect=slow_check):
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
            self.assertEqual(error.exception.status_code, 404)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_PRIVATE_DOWNLOAD").count(), 0)


    def test_expiry_while_required_audit_is_written_rolls_back_without_delivery(self):
        row = self.validate()
        clock = [timezone.now()]
        original = retrieval.audit.record
        def slow_audit(*args, **kwargs):
            result = original(*args, **kwargs)
            clock[0] = row.expires_at + timedelta(microseconds=1)
            return result
        before = AuditEvent.objects.count()
        with patch.object(retrieval.timezone, "now", side_effect=lambda: clock[0]), \
                patch.object(retrieval.audit, "record", side_effect=slow_audit):
            with self.assertRaises(ApiError) as error:
                retrieval.private_evidence_download(self.actor, self.item.id)
            self.assertEqual(error.exception.status_code, 404)
        self.assertEqual(AuditEvent.objects.count(), before)
