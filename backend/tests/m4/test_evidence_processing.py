"""TASK-227: planned PostgreSQL processing cases; no retained DB/native scanner."""
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from io import StringIO
import json
from types import SimpleNamespace
from threading import Barrier
import unittest
from unittest.mock import Mock, patch
import uuid

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.accounts.services import update_user
from apps.audit.models import AuditEvent
from apps.operations import evidence_processing as service
from apps.operations.evidence import accept_evidence
from apps.operations.evidence_decoder import DecodedEvidence
from apps.operations.evidence_policy import EvidenceError
from apps.operations.errors import ApiError
from apps.operations.models import PrivateEvidence, PrivateEvidenceValidation
from apps.reports.crypto import decrypt
from apps.reports.models import ReportRevision
from apps.reports.services import accept_operation
from apps.scopes.models import Unit
from tests.test_workflow import operation
from tests.m4.test_evidence_decoder import png


class ValidationStageTests(unittest.TestCase):
    """No DB path: patch only trusted capabilities, never a production enable flag."""
    def setUp(self):
        self.snapshot = SimpleNamespace(data=png(), media_type="image/png", manifest=object())
        self.verify = patch.object(service, "_check_snapshot")
        self.verify.start()
        self.addCleanup(self.verify.stop)
        self.seal = patch.object(service, "_result_seal", return_value="sealed")
        self.seal.start()
        self.addCleanup(self.seal.stop)

    def test_scan_decode_scan_order_and_no_active_database_transaction(self):
        events = []
        def scan(data, **kwargs):
            events.append("scan")
            self.assertFalse(connection.in_atomic_block)
            return "SCAN_CLEAN"
        def decode(data, **kwargs):
            events.append("decode")
            self.assertFalse(connection.in_atomic_block)
            return DecodedEvidence("image/png", 1, 1, 1, png())
        with patch.object(service.tools, "run_scan", side_effect=scan), patch.object(service.tools, "decode", side_effect=decode):
            result = service.run_validation(self.snapshot)
        self.assertEqual(events, ["scan", "decode", "scan"])
        self.assertEqual(result.code, "VALIDATION_COMPLETE")
        self.assertEqual(result.steps, ("ORIGINAL_SCAN_CLEAN", "DECODE_COMPLETE", "DERIVATIVE_SCAN_CLEAN"))

    def test_unknown_original_scan_verdict_prevents_decoder(self):
        for verdict in (True, None, "CLEAN", {}, ["SCAN_CLEAN"]):
            with patch.object(service.tools, "run_scan", return_value=verdict), patch.object(service.tools, "decode") as decode:
                result = service.run_validation(self.snapshot)
            self.assertEqual(result.code, "SCAN_NOT_CLEAN")
            self.assertEqual(result.data, b"")
            decode.assert_not_called()

    def test_missing_native_or_cleanup_failure_cannot_promote(self):
        for code in ("ISOLATION_UNAVAILABLE", "SCRATCH_CLEANUP_REQUIRED", "RESOURCE_LIMIT"):
            with patch.object(service.tools, "run_scan", side_effect=service.tools.ToolUnavailable(code)), patch.object(service.tools, "decode") as decode:
                result = service.run_validation(self.snapshot)
            self.assertEqual(result.code, code)
            self.assertEqual(result.data, b"")
            decode.assert_not_called()

    def test_malformed_decoder_shape_metadata_and_second_scan_error_fail_closed(self):
        for decoded in (True, {}, DecodedEvidence("image/png", True, 1, 1, png()),
                        DecodedEvidence("image/png", 1, 1, True, png()),
                        DecodedEvidence("image/jpeg", 1, 1, 1, png()),
                        DecodedEvidence("image/png", 2, 1, 1, png())):
            with patch.object(service.tools, "run_scan", return_value="SCAN_CLEAN"), patch.object(service.tools, "decode", return_value=decoded):
                result = service.run_validation(self.snapshot)
            self.assertNotEqual(result.code, "VALIDATION_COMPLETE")
            self.assertEqual(result.data, b"")
        with patch.object(service.tools, "run_scan", side_effect=["SCAN_CLEAN", service.tools.ToolUnavailable("SCANNER_UNAVAILABLE")]), patch.object(service.tools, "decode", return_value=DecodedEvidence("image/png", 1, 1, 1, png())):
            result = service.run_validation(self.snapshot)
        self.assertEqual(result.code, "SCANNER_UNAVAILABLE")
        self.assertEqual(result.steps, ("ORIGINAL_SCAN_CLEAN", "DECODE_COMPLETE"))

    def test_unexpected_exception_text_is_discarded(self):
        with patch.object(service.tools, "run_scan", side_effect=RuntimeError("PRIVATE_SCANNER_CANARY")):
            result = service.run_validation(self.snapshot)
        self.assertEqual(result.code, "DECODE_UNAVAILABLE")
        self.assertNotIn("PRIVATE", result.code)
        self.assertEqual(result.data, b"")


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(),
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ValidationProcessingTests(TransactionTestCase):
    """Parent executes on its guarded disposable PostgreSQL after source freeze."""
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        self.actor = get_user_model().objects.get(username="submitter")
        self.reviewer = get_user_model().objects.get(username="reviewer")
        self.admin = get_user_model().objects.get(username="administrator")
        self.recipient = get_user_model().objects.get(username="recipient")
        body = operation()
        receipt, _ = accept_operation(self.actor, body, body)
        self.revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        metadata, _ = accept_evidence(self.actor, self.revision.id, uuid.uuid4(), png(), "image/png", "synthetic.png")
        self.evidence = PrivateEvidence.objects.get(pk=metadata["id"])
        self.manifest = service.tools.ToolManifest("a" * 64, "b" * 64, timezone.now() + timedelta(hours=1),
                                                   1, "c" * 64, b'{"synthetic_tool_declaration":1}')
        self.events = []
        @contextmanager
        def current():
            self.assertFalse(connection.in_atomic_block)
            self.events.append("fence_enter")
            yield self.manifest
            self.assertFalse(connection.in_atomic_block)
            self.events.append("fence_exit")
        self.current = patch.object(service.tools, "current_tools", side_effect=current)
        self.current.start()
        self.addCleanup(self.current.stop)
        def asserted(manifest):
            self.assertIs(manifest, self.manifest)
            self.assertTrue(connection.in_atomic_block)
            self.events.append("assert_current")
        self.assertion = patch.object(service.tools, "assert_current", side_effect=asserted)
        self.assertion.start()
        self.addCleanup(self.assertion.stop)

    def prepared(self, operation_id=None, actor=None, evidence=None):
        return service.prepare_validation(actor or self.actor, (evidence or self.evidence).id, operation_id or uuid.uuid4())

    def test_outer_transaction_refuses_native_processing_before_any_tool_call(self):
        snapshot = self.prepared()
        with transaction.atomic(), patch.object(service.tools, "run_scan") as scan, \
                patch.object(service.tools, "decode") as decode:
            with self.assertRaises(ApiError) as error:
                service.run_validation(snapshot)
            self.assertEqual(error.exception.status_code, 503)
            scan.assert_not_called()
            decode.assert_not_called()

    def success(self, snapshot):
        def scan(*args, **kwargs):
            self.assertFalse(connection.in_atomic_block)
            return "SCAN_CLEAN"
        with patch.object(service.tools, "run_scan", side_effect=scan), patch.object(service.tools, "decode", return_value=DecodedEvidence("image/png", 1, 1, 1, png())):
            return service.run_validation(snapshot)

    def test_success_encrypts_identity_bound_derivative_provenance_and_required_audit(self):
        snapshot = self.prepared()
        status = service.commit_validation(self.actor, snapshot, self.success(snapshot))
        row = PrivateEvidenceValidation.objects.get()
        self.assertEqual((status["state"], status["validation_code"]), ("VALIDATED_PRIVATE", "VALIDATION_COMPLETE"))
        self.assertTrue(status["can_download"])
        envelope = decrypt(row.derivative_ciphertext)
        self.assertEqual(envelope["validation_id"], str(row.id))
        self.assertEqual(envelope["evidence_id"], str(self.evidence.id))
        self.assertEqual(envelope["revision_id"], str(self.revision.id))
        self.assertEqual(envelope["input_sha256"], snapshot.input_sha256)
        self.assertEqual(envelope["bytes_sha256"], row.derivative_sha256)
        self.assertEqual(decrypt(row.provenance_ciphertext)["steps"], ["ORIGINAL_SCAN_CLEAN", "DECODE_COMPLETE", "DERIVATIVE_SCAN_CLEAN"])
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_VALIDATED").count(), 1)
        self.evidence.refresh_from_db()
        self.assertEqual((self.evidence.state, self.evidence.validation_code), ("QUARANTINED", "DECODER_REQUIRED"))
        self.assertEqual(self.events, ["fence_enter", "assert_current", "fence_exit",
                                       "fence_enter", "assert_current", "fence_exit"])

    def test_exact_replay_avoids_native_scan_and_changed_manifest_conflicts(self):
        operation_id = uuid.uuid4()
        snapshot = self.prepared(operation_id)
        first = service.commit_validation(self.actor, snapshot, self.success(snapshot))
        with patch.object(service.tools, "run_scan") as scan:
            again = service.validate_evidence(self.actor, self.evidence.id, operation_id)
        scan.assert_not_called()
        self.assertEqual(again["validation_code"], first["validation_code"])
        self.assertFalse(again["can_download"])
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 1)
        self.manifest = replace(self.manifest, manifest_hash="d" * 64)
        with self.assertRaises(ApiError) as caught:
            self.prepared(operation_id)
        self.assertEqual(caught.exception.status_code, 409)

    def test_operation_rebind_to_another_evidence_conflicts(self):
        operation_id = uuid.uuid4()
        snapshot = self.prepared(operation_id)
        service.commit_validation(self.actor, snapshot, self.success(snapshot))
        metadata, _ = accept_evidence(self.actor, self.revision.id, uuid.uuid4(), png(), "image/png", "other.png")
        other = PrivateEvidence.objects.get(pk=metadata["id"])
        with self.assertRaises(ApiError) as caught:
            self.prepared(operation_id, evidence=other)
        self.assertEqual(caught.exception.safe_body["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 1)

    def test_supported_revoke_regrant_invalidates_snapshot_even_with_renewed_access(self):
        snapshot = self.prepared()
        result = self.success(snapshot)
        version = self.actor.permission_version
        update_user(self.admin, self.actor.id, {"expected_permission_version": version, "is_active": False})
        self.actor.refresh_from_db()
        update_user(self.admin, self.actor.id, {"expected_permission_version": self.actor.permission_version, "is_active": True})
        self.actor.refresh_from_db()
        with self.assertRaises(ApiError) as caught:
            service.commit_validation(self.actor, snapshot, result)
        self.assertEqual(caught.exception.safe_body["code"], "VALIDATION_STALE")
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)

    def test_scope_epoch_or_manifest_change_blocks_commit(self):
        snapshot = self.prepared()
        result = self.success(snapshot)
        unit = Unit.objects.get(pk=self.revision.report.unit_id)
        unit.scope_epoch += 1
        unit.save(update_fields=["scope_epoch"])
        with self.assertRaises(ApiError):
            service.commit_validation(self.actor, snapshot, result)
        snapshot = self.prepared()
        result = self.success(snapshot)
        self.manifest = replace(self.manifest, signature_generation="d" * 64)
        with self.assertRaises(ApiError):
            service.commit_validation(self.actor, snapshot, result)
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)

    def test_currentness_assertion_or_audit_failure_rolls_back_insert(self):
        snapshot = self.prepared()
        result = self.success(snapshot)
        with patch.object(service.tools, "assert_current", side_effect=service.tools.ToolUnavailable()):
            with self.assertRaises(ApiError): service.commit_validation(self.actor, snapshot, result)
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)
        with patch.object(service.audit, "record", side_effect=RuntimeError("PRIVATE_AUDIT_CANARY")):
            with self.assertRaises(RuntimeError): service.commit_validation(self.actor, snapshot, result)
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_VALIDATED").count(), 0)

    def test_membership_expiring_during_provenance_check_rolls_back(self):
        snapshot = self.prepared()
        result = self.success(snapshot)
        with patch.object(service, "source_allowed", return_value=False):
            with self.assertRaises(ApiError):
                service.commit_validation(self.actor, snapshot, result)
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)

    def test_unavailable_scanner_records_only_private_quarantine_no_derivative(self):
        snapshot = self.prepared()
        with patch.object(service.tools, "run_scan", side_effect=service.tools.ToolUnavailable("ISOLATION_UNAVAILABLE")):
            result = service.run_validation(snapshot)
        status = service.commit_validation(self.actor, snapshot, result)
        row = PrivateEvidenceValidation.objects.get()
        self.assertEqual(status["state"], "QUARANTINED")
        self.assertIsNone(row.derivative_ciphertext)
        self.assertIsNone(row.validated_at)
        self.assertIsNone(row.expires_at)
        self.assertEqual(row.code, "ISOLATION_UNAVAILABLE")

    def test_forged_results_and_snapshot_or_envelope_identity_tamper_reject(self):
        snapshot = self.prepared()
        result = self.success(snapshot)
        for changed in (replace(result, width=True), replace(result, data=png() + b"PRIVATE_CANARY"),
                        replace(result, seal=""), replace(result, code="VALIDATED_PRIVATE")):
            with self.assertRaises(ApiError): service.commit_validation(self.actor, snapshot, changed)
        with self.assertRaises(ApiError):
            service.run_validation(replace(snapshot, operation_id=uuid.uuid4()))
        with patch.object(service, "decrypt", return_value={"purpose": "PRIVATE_WRONG_ENVELOPE"}):
            with self.assertRaises(ApiError): self.prepared()
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)

    def test_recipient_admin_unknown_and_revoked_source_are_uniform_missing(self):
        bodies = []
        for actor, evidence in ((self.recipient, self.evidence.id), (self.admin, self.evidence.id),
                                (self.actor, uuid.uuid4())):
            with self.assertRaises(ApiError) as caught:
                service.prepare_validation(actor, evidence, uuid.uuid4())
            bodies.append(caught.exception.safe_body)
        self.assertEqual(bodies[0], bodies[1])
        self.assertEqual(bodies[1], bodies[2])
        self.actor.is_active = False
        self.actor.permission_version += 1
        self.actor.save(update_fields=["is_active", "permission_version"])
        with self.assertRaises(ApiError) as caught: self.prepared()
        self.assertEqual(caught.exception.safe_body, bodies[0])

    def test_current_origin_reviewer_may_prepare_and_outer_atomic_is_refused(self):
        self.assertIsInstance(self.prepared(actor=self.reviewer), service.ValidationSnapshot)
        with transaction.atomic():
            with self.assertRaises(ApiError): self.prepared()

    def test_tool_unavailable_before_decrypt_or_database_transaction(self):
        with patch.object(service.tools, "current_tools", side_effect=service.tools.ToolUnavailable()), patch.object(service, "_lock_evidence") as locked, patch.object(service, "decrypt") as decryptor:
            with self.assertRaises(ApiError): self.prepared()
        locked.assert_not_called()
        decryptor.assert_not_called()

    def test_two_connection_same_operation_commits_once_then_replays(self):
        operation_id = uuid.uuid4()
        first, second = self.prepared(operation_id), self.prepared(operation_id)
        first_result, second_result = self.success(first), self.success(second)
        barrier = Barrier(2)
        def commit(pair):
            close_old_connections()
            try:
                actor = get_user_model().objects.get(pk=self.actor.id)
                barrier.wait(timeout=10)
                return service.commit_validation(actor, *pair)
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(commit, pair) for pair in ((first, first_result), (second, second_result))]
            results = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(result["can_download"] for result in results), [False, True])
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_VALIDATED").count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_VALIDATION_REPLAY").count(), 1)


class ValidationCommandTests(unittest.TestCase):
    def options(self):
        return ["--actor", str(uuid.uuid4()), "--evidence", str(uuid.uuid4()), "--operation", str(uuid.uuid4())]

    def test_prepare_default_never_queries_actor_or_decrypts(self):
        from apps.operations.management.commands import validate_private_evidence as command
        @contextmanager
        def current(): yield object()
        output = StringIO()
        with patch.object(command, "require_native"), patch.object(command.tools, "current_tools", side_effect=current), patch.object(command.tools, "assert_current"), patch.object(command, "get_user_model") as user_model, patch.object(command, "validate_evidence") as validate:
            call_command("validate_private_evidence", *self.options(), stdout=output)
        user_model.assert_not_called()
        validate.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())["validation"], "NOT_RUN")

    def test_missing_native_guard_precedes_tools_and_actor_query(self):
        from apps.operations.management.commands import validate_private_evidence as command
        with patch.object(command, "require_native", side_effect=CommandError("NATIVE_ONLY")), patch.object(command.tools, "current_tools") as tools, patch.object(command, "get_user_model") as user_model:
            with self.assertRaises(CommandError): call_command("validate_private_evidence", *self.options())
        tools.assert_not_called()
        user_model.assert_not_called()

    def test_unavailable_tool_output_fixed_and_no_exception_text(self):
        from apps.operations.management.commands import validate_private_evidence as command
        output = StringIO()
        with patch.object(command, "require_native"), patch.object(command.tools, "current_tools", side_effect=command.tools.ToolUnavailable("ISOLATION_UNAVAILABLE")):
            with self.assertRaises(CommandError) as caught:
                call_command("validate_private_evidence", *self.options(), stdout=output)
        self.assertEqual(caught.exception.returncode, 2)
        self.assertEqual(json.loads(output.getvalue()), {"status": "UNAVAILABLE", "validation_code": "ISOLATION_UNAVAILABLE", "attempts": 0})
