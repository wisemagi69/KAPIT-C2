"""Authored native-only metadata collector checks; real DB execution is parent-owned."""
from contextlib import ExitStack, redirect_stdout
from datetime import timedelta
from io import StringIO
import json
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from apps.operations.management.commands.retention_inventory import collect_inventory
from apps.operations.management.commands.workflow_health import collect_health
from apps.operations.models import ProcessingJob
from apps.reports.models import ReportRevision
from apps.reports.services import accept_operation
from tests.test_workflow import operation


class NativeCollectorGuardTests(SimpleTestCase):
    def database(self, **changes):
        from django.conf import settings
        return dict(settings.DATABASES["default"], ENGINE="django.db.backends.postgresql",
                    HOST="127.0.0.1", PORT="55436", NAME="kapit_m1", USER="kapit_m1",
                    OPTIONS={"connect_timeout": 5}) | changes

    def test_remote_context_refuses_before_any_database_or_orm_access(self):
        for collector in (collect_inventory, collect_health):
            for context in ("supabase-m1", "compose-m1", "unknown"):
                with self.subTest(collector=collector.__name__, context=context):
                    with patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": context}):
                        with patch("apps.operations.management.commands.retention_inventory.connection.introspection.table_names",
                                   side_effect=AssertionError("must not inspect schema")):
                            with self.assertRaisesRegex(CommandError, "NATIVE_ONLY"):
                                collector()

    def test_loopback_environment_does_not_override_remote_configured_database(self):
        database = self.database(HOST="hosted.invalid")
        with patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native", "KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55436"}):
            with override_settings(DATABASES={"default": database}):
                for collector in (collect_inventory, collect_health):
                    with self.assertRaisesRegex(CommandError, "NATIVE_ONLY"):
                        collector()

    def test_wrong_user_alternate_host_or_libpq_overrides_refuse_before_proof_and_orm(self):
        changes = ({"USER": "another_user"}, {"HOST": "localhost"}, {"HOST": "::1"},
                   {"NAME": "unrelated"}, {"PORT": "5432"},
                   {"OPTIONS": {"connect_timeout": 5, "service": "unrelated"}},
                   {"OPTIONS": {"connect_timeout": 5, "options": "-c search_path=other"}})
        for change in changes:
            with self.subTest(change=change), patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native", "KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55436"}):
                with override_settings(DATABASES={"default": self.database(**change)}):
                    with patch("apps.operations.management.commands.retention_inventory.verify_owned_runtime", side_effect=AssertionError("proof must not run")):
                        for collector in (collect_inventory, collect_health):
                            with self.assertRaisesRegex(CommandError, "NATIVE_ONLY"):
                                collector()

    def test_failed_or_malformed_ownership_proof_refuses_before_orm(self):
        proofs = [RuntimeError("PRIVATE_OWNERSHIP_CANARY"), {}, {"state": "running", "owned": False, "port": 55436},
                  {"state": "stopped", "owned": True, "port": 55436}, {"state": "running", "owned": True, "port": 5432}]
        with override_settings(DATABASES={"default": self.database()}), patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native", "KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55436"}):
            for proof in proofs:
                with self.subTest(proof=type(proof).__name__):
                    with patch("apps.operations.management.commands.retention_inventory.verify_owned_runtime",
                               **({"side_effect": proof} if isinstance(proof, Exception) else {"return_value": proof})):
                        with patch("apps.operations.management.commands.retention_inventory.connection.introspection.table_names", side_effect=AssertionError("ORM must not run")):
                            for collector in (collect_inventory, collect_health):
                                with self.assertRaisesRegex(CommandError, "^NATIVE_ONLY$"):
                                    collector()

    def test_libpq_environment_cannot_redirect_the_django_connection(self):
        for variable in ("PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS"):
            with self.subTest(variable=variable), patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native", variable: "private-untrusted"}):
                with patch("apps.operations.management.commands.retention_inventory.verify_owned_runtime", side_effect=AssertionError("proof must not run")):
                    for collector in (collect_inventory, collect_health):
                        with self.assertRaisesRegex(CommandError, "^NATIVE_ONLY$"):
                            collector()

    def test_valid_owned_proof_is_required_before_introspection(self):
        with override_settings(DATABASES={"default": self.database()}), patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native", "KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55436"}):
            with patch("apps.operations.management.commands.retention_inventory.verify_owned_runtime", return_value={"state": "running", "owned": True, "port": 55436}) as proof:
                from apps.operations.management.commands.retention_inventory import require_native
                require_native()
                proof.assert_called_once_with()

    def test_no_apply_delete_or_policy_window_command_flags_exist(self):
        from apps.operations.management.commands.retention_inventory import Command
        parser = Command().create_parser("manage.py", "retention_inventory")
        for flag in ("--apply", "--delete", "--purge", "--days", "--cleanup"):
            with self.subTest(flag=flag), redirect_stdout(StringIO()):
                with self.assertRaises(CommandError):
                    parser.parse_args([flag])


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class OperationsInventoryTests(TestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        actor = get_user_model().objects.get(username="submitter")
        body = operation()
        body["payload"]["narrative"] = "PRIVATE_INVENTORY_CANARY"
        receipt, _ = accept_operation(actor, body, body)
        self.revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.now = timezone.now()

    def native(self):
        stack = ExitStack()
        stack.enter_context(patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native", "KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55436"}))
        stack.enter_context(patch("apps.operations.management.commands.retention_inventory.verify_owned_runtime", return_value={"state": "running", "owned": True, "port": 55436}))
        return stack

    def test_inventory_counts_metadata_and_all_unknown_hold_records_remain_retained(self):
        with self.native():
            result = collect_inventory()
        self.assertEqual(result["mode"], "DRY_RUN")
        self.assertEqual(result["completeness"], "PARTIAL")
        self.assertEqual(result["policy_status"], "NO_ACTIVE_WINDOWS")
        self.assertEqual(result["disposition"], "RETAIN_ALL")
        self.assertTrue(result["counts"])
        self.assertTrue(all(row["disposition"] == "RETAIN" for row in result["counts"]))
        self.assertTrue(any(row["category"] == "OPERATION_IDENTITY" and row["count"] >= 2 for row in result["counts"]))
        unavailable = {row["category"] for row in result["unavailable"]}
        self.assertTrue({"MOBILE_OUTBOX", "FINDING", "BACKUP", "ENCRYPTION_KEY", "SESSION", "ALL"} <= unavailable)
        self.assertNotIn("PRIVATE_INVENTORY_CANARY", json.dumps(result))
        self.assertNotIn(str(self.revision.id), json.dumps(result))

    def test_queries_do_not_select_source_ciphertext_content_digests_or_response_bodies(self):
        with self.native(), CaptureQueriesContext(connection) as queries:
            collect_inventory()
            collect_health()
        sql = " ".join(query["sql"].lower() for query in queries)
        for forbidden in ("payload_ciphertext", "reason_ciphertext", "correction_reason_ciphertext", "content_digest", "request_hash", "response_body", "session_data", "public_key_spki"):
            self.assertNotIn(forbidden, sql)

    def test_absent_private_evidence_table_reports_unavailable_not_a_zero_inventory(self):
        real = connection.introspection.table_names
        for missing in ("operations_privateevidence", "operations_privateevidencevalidation"):
            with self.subTest(missing=missing), self.native(), patch.object(
                    connection.introspection, "table_names",
                    side_effect=lambda: [name for name in real() if name != missing]):
                result = collect_inventory()
            for category in ("EVIDENCE", "OPERATION_IDENTITY"):
                self.assertIn({"category": category, "code": "SCHEMA_UNAVAILABLE"}, result["unavailable"])
                self.assertFalse(any(row["category"] == category for row in result["sources"]))
                self.assertFalse(any(row["category"] == category for row in result["counts"]))

    def test_worker_health_fixed_poison_codes_ages_and_no_private_labels(self):
        job = ProcessingJob.objects.get(revision=self.revision)
        ProcessingJob.objects.filter(pk=job.pk).update(available_at=self.now - timedelta(seconds=120))
        with self.native(), patch("apps.operations.management.commands.workflow_health.timezone.now", return_value=self.now):
            pending = collect_health()
        self.assertEqual(pending["job_status_counts"]["PENDING"], 1)
        self.assertEqual(pending["oldest_pending_available_age_seconds"], 120)
        self.assertIsNone(pending["oldest_pending_age_seconds"])
        self.assertEqual(pending["pending_creation_age_status"], "CREATION_TIME_UNAVAILABLE")
        ProcessingJob.objects.filter(pk=job.pk).update(status="FAILED", error_code="PRIVATE_CODE_CANARY")
        with self.native():
            failed = collect_health()
        self.assertEqual(failed["unclassified_failure_count"], 1)
        self.assertNotIn("PRIVATE_CODE_CANARY", json.dumps(failed))
        self.assertNotIn(str(job.id), json.dumps(failed))
        self.assertEqual(set(failed["poison_code_counts"]), {"RULE_PROCESSING_FAILED", "ATTEMPTS_EXHAUSTED", "STALE_CONTEXT"})
        ProcessingJob.objects.filter(pk=job.pk).update(status="PROCESSING", lease_until=self.now - timedelta(seconds=1))
        with self.native(), patch("apps.operations.management.commands.workflow_health.timezone.now", return_value=self.now):
            self.assertEqual(collect_health()["expired_lease_count"], 1)

    def test_commands_emit_only_json_and_leave_source_and_jobs_unchanged(self):
        before = (ReportRevision.objects.count(), ProcessingJob.objects.count(), bytes(self.revision.payload_ciphertext))
        for command in ("retention_inventory", "workflow_health"):
            output = StringIO()
            with self.native():
                call_command(command, stdout=output)
            result = json.loads(output.getvalue())
            self.assertEqual(result["schema_version"], 1)
            self.assertNotIn("PRIVATE_INVENTORY_CANARY", output.getvalue())
        self.revision.refresh_from_db()
        self.assertEqual((ReportRevision.objects.count(), ProcessingJob.objects.count(), bytes(self.revision.payload_ciphertext)), before)
