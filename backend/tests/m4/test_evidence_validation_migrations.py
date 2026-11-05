"""Disposable PostgreSQL invariants; opaque bytes here are not validation proof."""
from datetime import timedelta
import uuid

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection, DatabaseError, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.operations.evidence import accept_evidence
from apps.operations.models import PrivateEvidence, PrivateEvidenceValidation
from apps.reports.services import accept_operation
from apps.scopes.models import Organization
from tests.test_workflow import operation
from tests.m4.test_evidence_runtime import TEST_SETTINGS, IMAGE, FILENAME
from tests.mobile import test_upgrade as upgrade
from tests.m3 import test_m3_migrations as m3_upgrade


def attempt_fields(actor, evidence, **changes):
    fields = dict(organization_id=actor.organization_id, evidence_id=evidence.id,
        validated_by_id=actor.id, operation_id=uuid.uuid4(), request_hash="a" * 64,
        manifest_hash="b" * 64, signature_generation="c" * 64, input_sha256="d" * 64,
        state="QUARANTINED", code="ISOLATION_UNAVAILABLE", provenance_ciphertext=b"opaque test fixture")
    return fields | changes


@override_settings(**TEST_SETTINGS)
class EvidenceValidationConstraintsTests(TestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        self.actor = get_user_model().objects.get(username="submitter")
        body = operation()
        receipt, _ = accept_operation(self.actor, body, body)
        meta, _ = accept_evidence(self.actor, uuid.UUID(receipt["revision_id"]), uuid.uuid4(), IMAGE, "image/jpeg", FILENAME)
        self.evidence = PrivateEvidence.objects.get(pk=meta["id"])

    def success(self):
        return attempt_fields(self.actor, self.evidence, state="VALIDATED_PRIVATE", code="VALIDATION_COMPLETE",
            validated_at=timezone.now() - timedelta(seconds=1), expires_at=timezone.now() + timedelta(hours=1),
            derivative_ciphertext=b"opaque derivative fixture", derivative_sha256="e" * 64,
            derivative_size=20, width=2, height=2)

    def refused(self, fields):
        with self.assertRaises(DatabaseError), transaction.atomic():
            PrivateEvidenceValidation.objects.create(**fields)

    def test_valid_attempts_append_without_promoting_original(self):
        failed = PrivateEvidenceValidation.objects.create(**attempt_fields(self.actor, self.evidence))
        complete = PrivateEvidenceValidation.objects.create(**self.success())
        self.evidence.refresh_from_db()
        self.assertEqual((self.evidence.state, self.evidence.validation_code), ("QUARANTINED", "DECODER_REQUIRED"))
        self.assertNotEqual(failed.id, complete.id)
        for fields in ({"code": "VALIDATION_COMPLETE"}, {"organization_id": self.actor.organization_id},
                       {"provenance_ciphertext": b"changed"}):
            with self.subTest(fields=fields), self.assertRaises(DatabaseError), transaction.atomic():
                PrivateEvidenceValidation.objects.filter(pk=failed.pk).update(**fields)
        with self.assertRaises(DatabaseError), transaction.atomic():
            PrivateEvidenceValidation.objects.filter(pk=complete.pk).delete()
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 2)

    def test_every_success_field_is_explicitly_nonnull(self):
        success = self.success()
        for field in ("validated_at", "expires_at", "derivative_ciphertext", "derivative_sha256",
                      "derivative_size", "width", "height"):
            with self.subTest(field=field):
                self.refused(success | {field: None})

    def test_success_bounds_hashes_and_times_are_enforced(self):
        success = self.success()
        attacks = [{"width": 6001}, {"height": 6001}, {"width": 6000, "height": 6000},
            {"derivative_size": 0}, {"derivative_size": 5242881}, {"derivative_ciphertext": b""},
            {"derivative_sha256": "E" * 64}, {"validated_at": timezone.now() + timedelta(days=2)},
            {"expires_at": timezone.now() - timedelta(days=1)},
            {"expires_at": timezone.now() + timedelta(days=2)}]
        for changes in attacks:
            with self.subTest(changes=changes):
                self.refused(success | changes)

    def test_closed_state_code_pairs_and_absence_on_failure(self):
        base = attempt_fields(self.actor, self.evidence)
        for changes in ({"state": "VALIDATED_PRIVATE"}, {"code": "VALIDATION_COMPLETE"},
                        {"state": "UNKNOWN"}, {"code": "UNKNOWN"}, {"code": "INVALID_IMAGE"},
                        {"state": "REJECTED_PRIVATE"}, {"width": 1}, {"derivative_ciphertext": b"x"},
                        {"validated_at": timezone.now()}, {"derivative_sha256": "a" * 64}):
            with self.subTest(changes=changes):
                self.refused(base | changes)
        for state, code in [("QUARANTINED", "SCRATCH_CLEANUP_REQUIRED"), ("QUARANTINED", "SCAN_NOT_CLEAN"),
                            ("REJECTED_PRIVATE", "INVALID_IMAGE"), ("REJECTED_PRIVATE", "PIXEL_LIMIT")]:
            PrivateEvidenceValidation.objects.create(**attempt_fields(self.actor, self.evidence, state=state, code=code))

    def test_hash_key_provenance_and_organization_guards(self):
        base = attempt_fields(self.actor, self.evidence)
        for field in ("request_hash", "manifest_hash", "signature_generation", "input_sha256"):
            for bad in ("a" * 63, "A" * 64, "a" * 64 + "\n", "ａ" * 64):
                with self.subTest(field=field, bad=bad):
                    self.refused(base | {field: bad})
        other = Organization.objects.create(code="VALIDATION-OTHER", name="Synthetic other organization")
        outsider = get_user_model().objects.create(username="validation-outsider", organization=other, role="submitter")
        for changes in ({"key_id": "other"}, {"provenance_ciphertext": b""},
                        {"provenance_ciphertext": b"x" * 100001}, {"organization_id": other.id},
                        {"validated_by_id": outsider.id}):
            with self.subTest(changes=list(changes)):
                self.refused(base | changes)

    def test_actor_operation_is_unique_without_global_digest_deduplication(self):
        fields = attempt_fields(self.actor, self.evidence)
        PrivateEvidenceValidation.objects.create(**fields)
        self.refused(fields)
        PrivateEvidenceValidation.objects.create(**(fields | {"operation_id": uuid.uuid4()}))
        reviewer = get_user_model().objects.get(username="reviewer")
        PrivateEvidenceValidation.objects.create(**(fields | {"validated_by_id": reviewer.id}))
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 3)

    def test_retention_inventory_counts_attempts_without_reading_encrypted_bodies(self):
        from apps.operations.management.commands.retention_inventory import collect_inventory
        before = collect_inventory()
        PrivateEvidenceValidation.objects.create(**attempt_fields(self.actor, self.evidence))
        with CaptureQueriesContext(connection) as captured:
            after = collect_inventory()
        def total(value, category):
            return sum(row["count"] for row in value["counts"] if row["category"] == category)
        for category in ("EVIDENCE", "OPERATION_IDENTITY"):
            self.assertEqual(total(after, category), total(before, category) + 1)
        self.assertEqual(after["disposition"], "RETAIN_ALL")
        self.assertEqual(after["policy_status"], "NO_ACTIVE_WINDOWS")
        sql = " ".join(row["sql"] for row in captured.captured_queries)
        for private_column in ("payload_ciphertext", "derivative_ciphertext", "provenance_ciphertext", "request_hash"):
            self.assertNotIn(private_column, sql)


@override_settings(**TEST_SETTINGS)
class EvidenceValidationMigrationTests(TransactionTestCase):
    def test_empty_reverse_reapply_preserves_every_previous_guard_and_fixture(self):
        self.assertEqual(connection.vendor, "postgresql")
        with upgrade.owned_upgrade_schema() as (_, oid):
            executor = MigrationExecutor(connection)
            latest = executor.loader.graph.leaf_nodes()
            previous = [(app, "0006_private_evidence" if app == "operations" else name) for app, name in latest]
            executor.migrate(previous)
            apps = executor.loader.project_state(previous).apps
            actor_id, _, receipt = upgrade.MobileAcceptedM1UpgradeTests.seed_historical_acceptance(apps)
            before = upgrade.MobileAcceptedM1UpgradeTests.snapshot(apps)
            functions = m3_upgrade.functions(oid)
            triggers = m3_upgrade.triggers(oid)
            executor = MigrationExecutor(connection)
            self.assertEqual({(m.app_label, m.name, backwards) for m, backwards in executor.migration_plan(latest)},
                             {("operations", "0007_private_evidence_validation", False)})
            executor.migrate(latest)
            after = executor.loader.project_state(latest).apps
            self.assertEqual(upgrade.MobileAcceptedM1UpgradeTests.snapshot(after), before)
            after_functions = m3_upgrade.functions(oid)
            self.assertEqual({key: after_functions[key] for key in functions}, functions)
            self.assertEqual(set(after_functions) - set(functions), {"kapit_evidence_validation_frozen"})
            expected = {("operations_privateevidencevalidation", name) for name in
                        ("a_evidence_validation_org", "b_evidence_validation_frozen")}
            self.assertEqual(m3_upgrade.triggers(oid) - triggers, expected)
            MigrationExecutor(connection).migrate(previous)
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(m3_upgrade.triggers(oid) - triggers, expected)
            actor = after.get_model("accounts", "User").objects.get(pk=actor_id)
            evidence = after.get_model("operations", "PrivateEvidence").objects.create(
                organization_id=actor.organization_id, revision_id=receipt["revision_id"], uploaded_by_id=actor_id,
                operation_id=uuid.uuid4(), request_hash="a" * 64, payload_ciphertext=b"opaque test fixture",
                media_type="image/jpeg", byte_size=10, slot=1)
            model = after.get_model("operations", "PrivateEvidenceValidation")
            model.objects.create(**attempt_fields(actor, evidence))
            with self.assertRaisesRegex(RuntimeError, "destructive reversal is refused"):
                MigrationExecutor(connection).migrate(previous)
            self.assertEqual(model.objects.count(), 1)
            self.assertEqual(m3_upgrade.triggers(oid) - triggers, expected)
            self.assertEqual(upgrade.MobileAcceptedM1UpgradeTests.snapshot(after), before)
