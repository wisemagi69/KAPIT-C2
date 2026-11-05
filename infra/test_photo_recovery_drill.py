"""Pure orchestration/guard tests; no actual PG, real keys or native processes."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from infra import photo_recovery_drill as drill

NEGATIVES = ["OWNED_RECOVERY_KEY_FILE_MISSING", "WRONG_KEY_RESTORED_EVIDENCE_DENIED",
             "REENCRYPTED_CAPTURE_BINDING_DENIED", "REVISION_BINDING_DENIED", "PROVENANCE_BINDING_DENIED",
             "SWAPPED_VALIDATION_SOURCE_DENIED", "TAMPERED_DERIVATIVE_DENIED"]


def summary():
    return {**{name: 1 for name in drill.COUNTS}, "integrity": "VERIFIED", "current_delivery": "NOT_EVALUATED",
            "native_validation": "NOT_PROVEN_BY_THIS_TEST"}


class Client:
    def __init__(self, *, code=0, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = code, io.BytesIO(stdout), io.BytesIO(stderr)
        self.terminated, self.killed, self.waited = False, False, False
    def poll(self): return self.returncode
    def terminate(self): self.terminated = True; self.returncode = 1
    def kill(self): self.killed = True; self.returncode = 1
    def wait(self, timeout): self.waited = True; return self.returncode


class FakeRuntime:
    """In-memory coordinator capability only; never a real archive receipt."""
    def __init__(self, target, fault=None):
        self.target, self.fault, self.events = target, fault, []
        self.archive = self.archive_hash = None
        def write(path, text):
            with path.open("x", encoding="ascii") as stream: stream.write(text)
        self.local = SimpleNamespace(write_private=write)
    def checked(self, path): return Path(path)
    def preflight(self): self.events.append("preflight")
    def source_snapshot(self, *, retained=False):
        key = "retained" if retained else "source"
        return {key: 2 if "restore" in self.events and self.fault == key else 1}
    def private_baseline(self): return {"fixed": 2 if "restore" in self.events and self.fault == "private" else 1}
    def old_archives(self): return {"archive": 2 if "restore" in self.events and self.fault == "old_archive" else 1}
    def reserve(self): self.events.append("reserve")
    def recovery_key(self, name): return (self.target / name).read_bytes()
    def dump(self):
        self.events.append("dump")
        self.archive = self.target / "photo-cohort.dump"
        self.archive.write_bytes(b"PGDMP-pure-test-double")
        self.archive_hash = hashlib.sha256(self.archive.read_bytes()).hexdigest()
    def initialize(self): self.events.append("initialize")
    def start(self): self.events.append("start")
    def restore(self):
        self.events.append("restore")
        if self.fault == "interrupt": raise KeyboardInterrupt()
    def restored_snapshot(self): return {"source": 1}
    def verify(self, **kwargs):
        self.events.append("verify")
        result = summary()
        if self.fault == "empty": result["located_verified"] = 0
        return result
    def negative_integrity(self, **kwargs):
        if self.fault == "copied_archive": self.archive.write_bytes(b"changed")
        if self.fault == "fixture_key": (self.target / "recovery.key").write_bytes(Fernet.generate_key())
        if self.fault == "exception": raise RuntimeError("private raw exception canary")
        return NEGATIVES[:-1] if self.fault == "negative" else list(NEGATIVES)
    def stop_owned(self):
        self.events.append("stop")
        if self.fault == "stop_error": raise RuntimeError("private stop canary")
        return "NOT_STARTED" if self.fault == "stop" else "STOPPED_VERIFIED"


class PhotoDrillTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No real native process")))
        self.stack.enter_context(patch("subprocess.run", side_effect=AssertionError("No real native process")))
        self.stack.enter_context(patch("socket.socket", side_effect=AssertionError("No real socket")))
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()

    def test_default_cli_and_unrequested_calls_do_not_construct_runtime_or_read_keys(self):
        with patch.object(drill, "PhotoRuntime", side_effect=AssertionError("No runtime")), \
             patch.object(drill, "unchanged_runners", side_effect=AssertionError("No file hashes")):
            self.assertEqual(drill.archive_restore()["status"], "PREPARED_NOT_EXECUTED")
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(drill.main([]), 0)
            self.assertEqual(json.loads(output.getvalue()), drill.preparation())

    def test_execute_needs_optin_valid_reservation_and_private_cohort_before_runtime(self):
        with patch.object(drill, "PhotoRuntime", side_effect=AssertionError("No runtime")):
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(drill.archive_restore(execute=True)["code"], "PHOTO_EXPLICIT_OPT_IN_REQUIRED")
            with patch.dict(os.environ, {drill.OPT_IN: "1"}, clear=True):
                self.assertEqual(drill.archive_restore(execute=True, reservation="bad")["code"], "RESERVATION_REQUIRED")
                self.assertEqual(drill.archive_restore(execute=True, reservation="a" * 32)["code"], "GUARDED_TEST_COHORT_REQUIRED")

    def coordinate(self, fault=None):
        runtime = FakeRuntime(self.root, fault)
        with patch.dict(os.environ, {drill.OPT_IN: "1"}), patch.object(drill, "PhotoRuntime", return_value=runtime), \
             patch.object(drill, "unchanged_runners"):
            result = drill.archive_restore(execute=True, reservation="a" * 32, expected_cohort={"fixture": object()}, recovery_key=Fernet.generate_key())
        return result, runtime

    def test_positive_coordinator_requires_all_categories_actual_sequence_and_cleanup(self):
        result, runtime = self.coordinate()
        self.assertEqual(result["status"], "ENCRYPTED_EVIDENCE_ARCHIVE_RECOVERY_VERIFIED")
        self.assertEqual(runtime.events, ["preflight", "reserve", "dump", "initialize", "start", "restore", "verify", "stop"])
        self.assertEqual(result["negative_cases"], NEGATIVES)
        self.assertTrue(all(result[k] for k in ("source_preserved", "retained_preserved", "private_files_preserved", "archives_preserved", "fixture_key_preserved")))
        self.assertNotIn("fixture-owned-private-value", json.dumps(result))
        self.assertEqual(result["native_validation"], "NOT_PROVEN_BY_THIS_TEST")

    def test_cleanup_uncertainty_dominates_otherwise_successful_recovery(self):
        for fault in ("stop", "stop_error"):
            with self.subTest(fault=fault):
                target = self.root / fault; target.mkdir()
                original = self.root; self.root = target
                try: result, runtime = self.coordinate(fault)
                finally: self.root = original
                self.assertEqual(result["status"], "UNAVAILABLE")
                self.assertEqual(result["code"], "CHILD_STOP_UNCONFIRMED")
                self.assertIn("stop", runtime.events)

    def test_all_final_drift_surfaces_prevent_false_success(self):
        for fault in ("source", "retained", "private", "old_archive", "copied_archive", "fixture_key"):
            with self.subTest(fault=fault):
                target = self.root / fault; target.mkdir()
                original = self.root; self.root = target
                try: result, runtime = self.coordinate(fault)
                finally: self.root = original
                self.assertEqual(result["status"], "UNAVAILABLE")
                self.assertEqual(result["code"], "FINAL_PRESERVATION_UNAVAILABLE")
                self.assertFalse(any(result[k] for k in ("source_preserved", "retained_preserved", "private_files_preserved", "archives_preserved", "fixture_key_preserved")))

    def test_empty_category_or_missing_negative_is_not_recovery(self):
        for fault in ("empty", "negative", "exception"):
            with self.subTest(fault=fault):
                target = self.root / fault; target.mkdir()
                original = self.root; self.root = target
                try: result, runtime = self.coordinate(fault)
                finally: self.root = original
                self.assertEqual(result["status"], "UNAVAILABLE")
                self.assertNotIn("private raw", json.dumps(result))
                self.assertIn("stop", runtime.events)

    def test_baseexception_propagates_after_owned_stop_and_final_preservation(self):
        runtime = FakeRuntime(self.root, "interrupt")
        with patch.dict(os.environ, {drill.OPT_IN: "1"}), patch.object(drill, "PhotoRuntime", return_value=runtime), \
             patch.object(drill, "unchanged_runners"):
            with self.assertRaises(KeyboardInterrupt):
                drill.archive_restore(execute=True, reservation="a" * 32, expected_cohort={"fixture": object()}, recovery_key=Fernet.generate_key())
        self.assertEqual(runtime.events[-1], "stop")

    def test_summary_closed_schema_nonvacuity_and_no_boolean_counts(self):
        self.assertEqual(drill.summary_closed(summary()), summary())
        for changed in (summary() | {"located_verified": 0}, summary() | {"located_verified": True},
                        summary() | {"raw": "private"}, summary() | {"current_delivery": "ALLOWED"}):
            with self.assertRaises(drill.PhotoRecoveryError): drill.summary_closed(changed)

    def test_real_private_missing_key_read_has_no_fallback_and_key_length_is_bounded(self):
        runtime = object.__new__(drill.PhotoRuntime)
        runtime.target, runtime.checked, runtime.check_owner = self.root, Path, Mock()
        with self.assertRaises(FileNotFoundError): runtime.recovery_key("missing-recovery.key")
        (self.root / "recovery.key").write_bytes(Fernet.generate_key() + b"extra")
        with self.assertRaises(drill.PhotoRecoveryError): runtime.recovery_key("recovery.key")
        with self.assertRaises(drill.PhotoRecoveryError): runtime.recovery_key("../secret")

    def test_pipe_archive_limit_never_writes_beyond_cap_or_retains_raw_stderr(self):
        destination = io.BytesIO()
        reader = drill._PipeReader(io.BytesIO(b"x" * 65537), destination=destination, limit=65536)
        reader.read()
        self.assertTrue(reader.overflow)
        self.assertEqual(len(destination.getvalue()), 65536)
        error = drill._PipeReader(io.BytesIO(b"private raw canary"), limit=4)
        error.read()
        self.assertTrue(error.overflow)
        self.assertFalse(hasattr(error, "data"))

    def command(self, client, **kwargs):
        runtime = SimpleNamespace(tools={"pg_dump": (str(self.root / "fixed.exe"), "pinned")}, native=SimpleNamespace(digest=lambda _: "pinned"))
        with patch.object(drill.subprocess, "Popen", return_value=client) as popen:
            drill.bounded_command(runtime, "pg_dump", ["--format=custom"], env={"SAFE": "fixed"}, timeout=5, **kwargs)
        return popen

    def test_native_command_uses_pinned_binary_bounded_file_and_fixed_environment(self):
        client = Client(stdout=b"PGDMP-synthetic-output")
        destination = io.BytesIO()
        popen = self.command(client, destination=destination, output_limit=100)
        self.assertEqual(destination.getvalue(), b"PGDMP-synthetic-output")
        self.assertTrue(client.waited)
        self.assertEqual(popen.call_args.kwargs["env"], {"SAFE": "fixed"})
        self.assertEqual(popen.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_native_error_oversize_or_changed_binary_cannot_pass(self):
        for client in (Client(code=1, stderr=b"private error"), Client(stdout=b"x" * 101)):
            with self.assertRaises(drill.PhotoRecoveryError): self.command(client, destination=io.BytesIO(), output_limit=100)
            self.assertTrue(client.waited)
        runtime = SimpleNamespace(tools={"pg_dump": ("fixed.exe", "pinned")}, native=SimpleNamespace(digest=lambda _: "changed"))
        with self.assertRaisesRegex(drill.PhotoRecoveryError, "RESTORE_BINARY_CHANGED"):
            drill.bounded_command(runtime, "pg_dump", [], env={}, timeout=5)

    def test_interrupt_during_client_wait_stops_direct_handle_and_propagates(self):
        client = Client(code=None)
        with patch.object(drill.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.command(client)
        self.assertTrue(client.terminated)
        self.assertTrue(client.waited)

    def test_failed_direct_client_termination_never_reports_completed(self):
        client = Client(code=None)
        client.terminate = Mock(side_effect=RuntimeError("private failure"))
        with self.assertRaises(RuntimeError): drill.stop_client(client)
        self.assertFalse(client.killed)  # No arbitrary alternate PID path.

    def test_pgpass_escapes_delimiters_and_refuses_injection(self):
        self.assertEqual(drill.pgpass_value("a:b\\c"), "a\\:b\\\\c")
        for value in ("password\nother", "password\r", "a\x00b", "", None, "x" * 4097):
            with self.assertRaises(drill.PhotoRecoveryError): drill.pgpass_value(value)

    def source_guard(self, *, advisory=(1,), source_oid=40, actual_oid=40, atomic=False, owner="kapit_m1", held=True):
        class Lease:
            def assert_owned(self):
                if self.owned_oid != source_oid: raise RuntimeError("fixed ownership refusal")
        def cursor(value):
            item = Mock()
            item.__enter__ = Mock(return_value=item)
            item.__exit__ = Mock(return_value=False)
            item.fetchone.return_value = value
            return item
        lease = Lease()
        lease.locked, lease.owned_oid = held, source_oid
        lock_cursor = cursor(advisory)
        lease.connection = SimpleNamespace(cursor=lambda: lock_cursor)
        db_cursor = cursor(("test_kapit_m1", actual_oid, owner, "kapit_m1"))
        connection = SimpleNamespace(settings_dict={}, in_atomic_block=atomic, get_autocommit=lambda: True,
                                     cursor=lambda: db_cursor)
        guard = SimpleNamespace(DatabaseLease=Lease, ACTIVE_DATABASE_LEASE=lease, ADVISORY_LOCK=746397301,
                                TEST_DATABASE="test_kapit_m1", require_target=Mock())
        runtime = object.__new__(drill.PhotoRuntime)
        runtime.lease, runtime.source_oid, runtime.info = lease, source_oid, {"fixed": "owned"}
        runtime.native = SimpleNamespace(ownership=lambda: runtime.info, status=Mock())
        modules = {"django": SimpleNamespace(), "django.db": SimpleNamespace(connection=connection),
                   "tests": SimpleNamespace(browser_runner=guard)}
        with patch.dict(sys.modules, modules):
            runtime.guard_source()
        return runtime, lock_cursor, db_cursor

    def test_source_guard_checks_real_lease_identity_advisory_and_current_owner(self):
        runtime, lock_cursor, db_cursor = self.source_guard()
        self.assertIn("pg_locks", lock_cursor.execute.call_args.args[0])
        self.assertIn("pg_backend_pid()", lock_cursor.execute.call_args.args[0])
        self.assertEqual(lock_cursor.execute.call_args.args[1], [746397301])
        self.assertIn("current_database()", db_cursor.execute.call_args.args[0])
        runtime.native.status.assert_called_once_with(require_running=True)

    def test_unheld_advisory_wrong_oid_owner_or_uncommitted_source_refuse(self):
        for kwargs in ({"advisory": (0,)}, {"actual_oid": 41}, {"owner": "another"},
                       {"held": False}, {"atomic": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(drill.PhotoRecoveryError):
                self.source_guard(**kwargs)

    def test_source_dump_never_uses_retained_database_or_unbounded_dump_file(self):
        runtime = object.__new__(drill.PhotoRuntime)
        runtime.target, runtime.archive, runtime.archive_hash = self.root, None, None
        runtime.checked, runtime.guard_source, runtime.check_owner = Path, Mock(), Mock()
        runtime.source_password = "synthetic:password"
        def write(path, value):
            with path.open("x", encoding="ascii") as stream: stream.write(value)
        runtime.local = SimpleNamespace(write_private=write)
        runtime.environment = Mock(return_value={"PGPASSFILE": "private fixed owned passfile"})
        calls = []
        def command(_runtime, name, args, **kwargs):
            calls.append((name, args, kwargs))
            if name == "pg_dump": kwargs["destination"].write(b"PGDMP-guard-fixture")
        with patch.object(drill, "bounded_command", side_effect=command): runtime.dump()
        self.assertEqual(calls[0][0], "pg_dump")
        self.assertIn("--dbname=test_kapit_m1", calls[0][1])
        self.assertNotIn("--dbname=kapit_m1", calls[0][1])
        self.assertIn("--no-blobs", calls[0][1])
        self.assertEqual(calls[0][2]["output_limit"], drill.MAX_ARCHIVE)
        self.assertEqual(calls[1][0], "pg_restore")
        self.assertEqual(calls[1][1], ["--list", str(runtime.archive)])
        self.assertEqual(runtime.guard_source.call_count, 2)
        self.assertEqual((self.root / "source.pgpass").read_text(),
                         "127.0.0.1:55436:test_kapit_m1:kapit_m1:synthetic\\:password\n")

    def test_each_actual_source_connection_checks_its_own_oid_and_retained_oid(self):
        for retained in (False, True):
            for changed in (False, True):
                with self.subTest(retained=retained, changed=changed):
                    runtime = object.__new__(drill.PhotoRuntime)
                    runtime.guard_source = Mock()
                    runtime.native = SimpleNamespace(PORT=55436, DATA=self.root)
                    runtime.info, runtime.source_password = {"process": {"started": 100}}, "synthetic"
                    runtime.source_oid, runtime.retained_oid = 40, 50
                    cursor = Mock()
                    cursor.__enter__ = Mock(return_value=cursor)
                    cursor.__exit__ = Mock(return_value=False)
                    expected_oid = 50 if retained else 40
                    cursor.fetchone.return_value = ("kapit_m1" if retained else "test_kapit_m1", str(self.root), "55436",
                        "127.0.0.1", "kapit_m1", 100, expected_oid + int(changed), "kapit_m1")
                    connection = Mock()
                    connection.__enter__ = Mock(return_value=connection)
                    connection.__exit__ = Mock(return_value=False)
                    connection.cursor.return_value = cursor
                    runtime.psycopg = SimpleNamespace(connect=Mock(return_value=connection))
                    if changed:
                        with self.assertRaisesRegex(drill.PhotoRecoveryError, "PHOTO_SOURCE_IDENTITY_CHANGED"):
                            with runtime.source_connection(retained=retained): self.fail("Wrong actual connection must not reach verifier")
                    else:
                        with runtime.source_connection(retained=retained) as actual: self.assertIs(actual, connection)
                    self.assertIn("d.oid", cursor.execute.call_args.args[0])
                    self.assertIn("default_transaction_read_only=on", runtime.psycopg.connect.call_args.kwargs["options"])


if __name__ == "__main__":
    unittest.main()
