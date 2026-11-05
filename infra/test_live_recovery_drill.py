"""Pure guards: real synthetic Fernet/files, fake SQL/process; never live proof."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from infra import live_recovery_drill as drill


class Client:
    def __init__(self, code=None):
        self.code, self.terminations, self.waits = code, 0, 0
    def poll(self): return self.code
    def terminate(self):
        self.terminations += 1
        self.code = 1
    def wait(self, timeout):
        assert timeout == 10
        self.waits += 1
        return self.code


class SQL:
    def __init__(self, events, *, wait=True):
        self.events, self.wait, self.value = events, wait, 0
    def __enter__(self): return self
    def __exit__(self, *_): return False
    def execute(self, sql, parameters=None):
        self.events.append((sql, parameters))
        self.value = int(self.wait) if "AND query LIKE" in sql else 0
    def fetchone(self): return (self.value,)


class Connection:
    def __init__(self, events, *, wait=True):
        self.events, self.wait = events, wait
        self.autocommit = False
    def cursor(self): return SQL(self.events, wait=self.wait)
    def rollback(self): self.events.append(("ROLLBACK", None))
    def close(self): self.events.append(("CLOSE", None))


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("subprocess.run", side_effect=AssertionError("No real subprocess")))
        self.stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No real subprocess")))
        self.stack.enter_context(patch("socket.socket", side_effect=AssertionError("No socket")))
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()

    def test_default_and_invalid_optin_do_not_construct_runtime_or_hash_files(self):
        with patch.object(drill.restore, "LocalRuntime", side_effect=AssertionError("No runtime")), \
                patch.object(drill, "runner_unchanged", side_effect=AssertionError("No file read")):
            self.assertEqual(drill.run()["status"], "PREPARED_NOT_EXECUTED")
            for value in (None, "", "A" * 32, True, "../archive"):
                self.assertEqual(drill.run(execute=True, reservation=value)["code"], "RESERVATION_REQUIRED")

    def test_cli_has_no_path_key_pid_or_scenario_options_and_default_exit_two(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(drill.main([]), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "PREPARED_NOT_EXECUTED")
        with contextlib.redirect_stderr(io.StringIO()):
            for name in ("--key", "--pid", "--archive", "--scenario", "--target", "--force"):
                with self.assertRaises(SystemExit) as error:
                    drill.main([name, "synthetic"])
                self.assertEqual(error.exception.code, 2)

    def test_reviewed_runner_hash_and_required_quality_wiring(self):
        drill.runner_unchanged()
        with patch.object(drill, "RUNNER_SHA256", "0" * 64), self.assertRaises(drill.DrillError):
            drill.runner_unchanged()
        from infra import quality
        check = next(item for item in quality.CHECKS if item.name == "live-recovery-guards")
        self.assertIn("infra.test_live_recovery_drill", check.command)
        self.assertNotIn("--execute", check.command)
        self.assertIn("infra/test_live_recovery_drill.py", check.files)

    def driver(self, scenario):
        actual = object.__new__(drill.FaultRuntime)
        actual.scenario, actual.proof = scenario, None
        actual.client, actual.client_reaped = None, False
        actual.target = self.root
        actual.checked = lambda p: Path(p)
        actual.check_owner, actual.verify_child = Mock(), Mock()
        actual.token = "b" * 32
        actual.port, actual.user, actual.database = 56555, "synthetic_child", "synthetic_child"
        actual.archive = self.root / "original.dump"
        actual.archive.write_bytes(b"PGDMP" + b"synthetic opaque archive" * 20)
        actual.native = SimpleNamespace(digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(),
            clean_environment=lambda: {"PATH": "trusted", "KAPIT_SOURCE_KEY": "PRIVATE_CANARY"})
        actual.archive_hash = actual.native.digest(actual.archive)
        binary = self.root / "pg_restore.exe"
        binary.write_bytes(b"synthetic pinned executable, never executed")
        actual.tools = {"pg_restore": (str(binary), actual.native.digest(binary))}
        (self.root / "pgpass").write_bytes(b"synthetic passfile")
        actual.command = Mock()
        return actual

    def test_binary_changed_refuses_before_spawn_and_passfile_secret_not_in_environment(self):
        actual = self.driver("CORRUPT_COPY_PARSER")
        _, env = actual.command_environment()
        self.assertNotIn("KAPIT_SOURCE_KEY", env)
        self.assertNotIn("PRIVATE_CANARY", json.dumps(env))
        self.assertEqual(env["PGAPPNAME"], "kapit-drill-" + "b" * 32)
        Path(actual.tools["pg_restore"][0]).write_bytes(b"changed")
        with self.assertRaises(drill.DrillError): actual.command_environment()

    def test_real_missing_recovery_file_check_does_not_fallback_or_touch_original(self):
        actual = self.driver("MISSING_RECOVERY_KEY")
        original = self.root / "original-key.fixture"
        original.write_bytes(b"never altered fixture")
        actual.source_key = Mock(side_effect=AssertionError("No fallback"))
        with self.assertRaisesRegex(drill.restore.RehearsalError, "RESTORE_KEYS_UNAVAILABLE"):
            actual.verify_decryption()
        self.assertEqual(actual.proof, drill.EXPECTED[actual.scenario][1])
        actual.source_key.assert_not_called()
        self.assertFalse((self.root / "recovery.key").exists())
        self.assertEqual(original.read_bytes(), b"never altered fixture")

    def test_wrong_key_uses_real_fernet_and_restores_only_inmemory_source_key(self):
        actual = self.driver("WRONG_RECOVERY_KEY")
        from infra import local
        from infra.test_restore_failures import Connection as Rows
        key = Fernet.generate_key()
        actual.Fernet, actual.values = Fernet, {"KAPIT_SOURCE_KEY": key.decode()}
        actual.local = SimpleNamespace(write_private=local.write_private)
        original = actual.source_key = Fernet(key)
        token = original.encrypt(b'{"synthetic":true}')
        actual.connection = lambda: Rows([[(token, drill.restore._hash({"synthetic": True}), None)]])
        with self.assertRaisesRegex(drill.restore.RehearsalError, "RESTORED_SOURCE_INTEGRITY"):
            actual.verify_decryption()
        self.assertIs(actual.source_key, original)
        self.assertNotEqual((self.root / "recovery.key").read_bytes(), key)
        self.assertEqual(actual.proof, drill.EXPECTED[actual.scenario][1])

    def test_existing_recovery_key_never_adopted_or_overwritten(self):
        actual = self.driver("MISSING_RECOVERY_KEY")
        path = self.root / "recovery.key"
        path.write_bytes(b"preserve")
        with self.assertRaises(drill.DrillError): actual.verify_decryption()
        self.assertEqual(path.read_bytes(), b"preserve")
        self.assertIsNone(actual.proof)

    def parser(self, message, returncode):
        actual = self.driver("CORRUPT_COPY_PARSER")
        original = actual.archive.read_bytes()
        def command(args, **kwargs):
            kwargs["stderr"].write(message)
            self.assertEqual(kwargs["timeout"], 30)
            self.assertNotEqual(Path(args[-1]), actual.archive)
            self.assertNotIn("PRIVATE_CANARY", json.dumps(kwargs["env"]))
            return SimpleNamespace(returncode=returncode)
        with patch.object(drill.subprocess, "run", side_effect=command):
            try:
                actual.parser_failure()
            finally:
                self.assertEqual(actual.archive.read_bytes(), original)
        return actual

    def test_parser_receipt_requires_exact_native_header_rejection_and_nonzero(self):
        with self.assertRaisesRegex(drill.restore.RehearsalError, "REHEARSAL_UNAVAILABLE"):
            self.parser(next(iter(drill.PARSER_REJECTIONS)) + b"\n", 1)

    def test_arbitrary_native_error_or_exit_is_not_corrupt_archive_proof(self):
        for message, status in ((b"PRIVATE_CANARY connection refused", 1), (b"", 0), (b"x" * 65537, 1)):
            with self.subTest(status=status, size=len(message)):
                with self.assertRaises(drill.DrillError): self.parser(message, status)
                # Each parser output is exclusive; release only test-owned files.
                (self.root / "corrupt-copy.dump").unlink()
                (self.root / "parser.stderr").unlink()

    def interrupt(self, *, wait=True, code=None):
        actual = self.driver("INTERRUPTED_COPY")
        events = []
        lock, observer = Connection(events), Connection(events, wait=wait)
        actual.connection = Mock(side_effect=[lock, observer])
        client = Client(code)
        return actual, events, client

    def test_interruption_needs_observed_copy_lock_then_direct_reap_and_backend_absence(self):
        actual, events, client = self.interrupt()
        with patch.object(drill.subprocess, "Popen", return_value=client) as spawn, \
                self.assertRaisesRegex(drill.restore.RehearsalError, "REHEARSAL_UNAVAILABLE"):
            actual.interrupted_copy()
        self.assertEqual(actual.proof, drill.EXPECTED[actual.scenario][1])
        self.assertEqual((client.terminations, client.waits), (1, 1))
        self.assertTrue(actual.client_reaped)
        sql = [text for text, _ in events]
        self.assertLess(sql.index("ROLLBACK"), next(i for i, text in enumerate(sql) if "pg_stat_activity" in text and "AND query LIKE" not in text))
        self.assertEqual(sql[-2:], ["CLOSE", "CLOSE"])
        args = spawn.call_args.args[0]
        self.assertIn("--data-only", args)
        self.assertIn("--table=reports_reportrevision", args)

    def test_no_observation_or_early_client_exit_cannot_claim_interruption(self):
        for wait, code in ((False, None), (True, 0)):
            with self.subTest(wait=wait, early_exit=code):
                actual, events, client = self.interrupt(wait=wait, code=code)
                with patch.object(drill.subprocess, "Popen", return_value=client), \
                        patch.object(drill.time, "sleep"), \
                        patch.object(drill.time, "monotonic", side_effect=iter(range(100))), \
                        self.assertRaises(drill.DrillError):
                    actual.interrupted_copy()
                self.assertIsNone(actual.proof)
                self.assertTrue(actual.client_reaped)
                self.assertIn(("ROLLBACK", None), events)

    def test_client_wait_timeout_does_not_claim_reaped_or_proven(self):
        actual, _, client = self.interrupt()
        client.wait = Mock(side_effect=subprocess.TimeoutExpired("synthetic", 10))
        with patch.object(drill.subprocess, "Popen", return_value=client), self.assertRaises(subprocess.TimeoutExpired):
            actual.interrupted_copy()
        self.assertFalse(actual.client_reaped)
        self.assertIsNone(actual.proof)

    def test_interrupt_during_client_cleanup_still_attempts_guarded_cluster_stop(self):
        actual = self.driver("INTERRUPTED_COPY")
        actual.client = Client()
        actual.stop_client = Mock(side_effect=KeyboardInterrupt())
        with patch.object(drill.PrivateRuntime, "stop_owned", return_value="STOPPED_VERIFIED") as stop:
            with self.assertRaises(KeyboardInterrupt): actual.stop_owned()
            stop.assert_called_once()

    def test_private_pin_released_even_when_guarded_cluster_stop_refuses(self):
        actual = object.__new__(drill.PrivateRuntime)
        pin = actual.private_pin = SimpleNamespace(__exit__=Mock())
        with patch.object(drill.restore.LocalRuntime, "stop_owned", side_effect=drill.restore.RehearsalError("CHILD_STOP_UNCONFIRMED")):
            with self.assertRaises(drill.restore.RehearsalError): actual.stop_owned()
        pin.__exit__.assert_called_once_with(None, None, None)
        self.assertIsNone(actual.private_pin)

    def test_partial_observer_connection_failure_still_releases_held_connection(self):
        actual = self.driver("INTERRUPTED_COPY")
        events = []
        actual.connection = Mock(side_effect=[Connection(events), RuntimeError("PRIVATE_CANARY")])
        with self.assertRaises(RuntimeError): actual.interrupted_copy()
        self.assertEqual(events, [("ROLLBACK", None), ("CLOSE", None)])

    def test_guarded_fingerprint_refuses_hardlinks_and_oversized_artifacts(self):
        actual = self.driver("CORRUPT_COPY_PARSER")
        with self.assertRaises(drill.DrillError): drill.fingerprint(actual, actual.archive, 1)
        import os
        os.link(actual.archive, self.root / "alias")
        with self.assertRaises(drill.DrillError): drill.fingerprint(actual, actual.archive, drill.MAX_ARCHIVE)

    def coordinator(self, *, missing_proof=False, bad_cleanup=False, mutate=False):
        from infra import start_local
        cache, data = self.root / "cache", self.root / "data"
        cache.mkdir(); data.mkdir()
        paths = [cache / name for name in ("secrets.json", "backend.env", "db.env", "owner.json")]
        paths += [data / name for name in ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")]
        for path in paths: path.write_bytes(b"synthetic protected fixture")
        guard = SimpleNamespace(checked=lambda p: Path(p), preflight=Mock(), source_snapshot=Mock(return_value={"current": 1}),
            local=SimpleNamespace(SECRET_FILE=paths[0], CACHE=cache), native=SimpleNamespace(MARKER=paths[3], DATA=data))
        made, executions = [], []
        def make(scenario):
            archive = self.root / (scenario + ".dump")
            archive.write_bytes(b"synthetic owned original archive")
            runtime = SimpleNamespace(archive=archive, archive_hash=hashlib.sha256(archive.read_bytes()).hexdigest(),
                                      scenario=scenario, proof=None if scenario == "POSITIVE" else drill.EXPECTED[scenario][1])
            made.append(runtime)
            return runtime
        positive = make("POSITIVE")
        def execute(**options):
            runtime = options["driver"]
            executions.append(runtime.scenario)
            if runtime.scenario == "POSITIVE":
                return {"status": "DATABASE_REHEARSAL_PASSED_CLOSED", "cleanup": "NOT_STARTED" if bad_cleanup else "STOPPED_VERIFIED"}
            if missing_proof:
                runtime.proof = None
            if mutate == "private":
                paths[0].write_bytes(b"changed protected fixture")
            elif mutate == "archive":
                runtime.archive.write_bytes(b"changed owned original archive")
            elif mutate == "source":
                guard.source_snapshot.return_value = {"current": 2}
            return {"status": "UNAVAILABLE", "code": drill.EXPECTED[runtime.scenario][0], "cleanup": "STOPPED_VERIFIED"}
        with patch.object(drill, "runner_unchanged"), patch.object(start_local, "listener_owners", return_value=[]), \
                patch.object(drill.restore, "LocalRuntime", return_value=guard), \
                patch.object(drill, "PrivateRuntime", return_value=positive), \
                patch.object(drill, "FaultRuntime", side_effect=lambda token, scenario: make(scenario)), \
                patch.object(drill.restore, "rehearse", side_effect=execute), \
                patch.dict(drill.os.environ, {"KAPIT_RESTORE_RESERVATION": "a" * 32}), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            status = drill.main(["--execute"])
        result = json.loads(output.getvalue().splitlines()[-1])
        self.assertEqual(status, 0 if result["status"] == "DRILL_PASSED_CLOSED" else 2)
        self.assertNotIn("synthetic protected fixture", output.getvalue() + json.dumps(result))
        self.assertNotIn("sha256", json.dumps(result))
        return result, made, executions

    def test_fixed_case_coordinator_needs_five_distinct_runtime_receipts(self):
        result, made, executions = self.coordinator()
        self.assertEqual(result["status"], "DRILL_PASSED_CLOSED")
        self.assertEqual(executions, ["POSITIVE", *drill.SCENARIOS])
        self.assertEqual(len({id(item) for item in made}), 5)
        self.assertTrue(result["original_private_files_preserved"])
        self.assertTrue(result["original_archives_preserved"])
        self.assertTrue(result["current_source_equal"])

    def test_expected_unavailable_without_primitive_proof_cannot_qualify(self):
        result, _, executions = self.coordinator(missing_proof=True)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(executions, ["POSITIVE", "MISSING_RECOVERY_KEY"])
        self.assertFalse(result["cases"][-1]["expected_behavior_observed"])

    def test_positive_with_unproved_cleanup_stops_all_later_cases(self):
        result, _, executions = self.coordinator(bad_cleanup=True)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(executions, ["POSITIVE"])

    def test_failure_finally_rechecks_original_private_archive_and_source(self):
        for surface in ("private", "archive", "source"):
            with self.subTest(surface=surface):
                folder = self.root / surface
                folder.mkdir()
                original_root, self.root = self.root, folder
                try:
                    result, _, _ = self.coordinator(mutate=surface)
                finally:
                    self.root = original_root
                self.assertEqual(result["status"], "UNAVAILABLE")
                self.assertEqual(result["code"], "FINAL_PRESERVATION_UNAVAILABLE")
                self.assertFalse(result["original_private_files_preserved"])
                self.assertFalse(result["original_archives_preserved"])
                self.assertFalse(result["current_source_equal"])

    def private_reservation(self, *, proof=True):
        root = self.root / ".cache/m4-recovery"
        root.mkdir(parents=True)
        (root / "owner.json").write_text(json.dumps({"schema": 1, "owner": drill.restore.OWNER, "workspace": str(self.root)}))
        events = []
        actual = drill.PrivateRuntime("a" * 32)
        actual.checked = lambda p: Path(p)
        actual.local = SimpleNamespace(write_private=lambda p, value: events.append(("write", p.name)))
        def create(path):
            events.append(("create", path.name))
            path.mkdir()  # Fake OS primitive: never a native ACL claim.
        @contextlib.contextmanager
        def pin(*args, **kwargs):
            events.append(("proof", None))
            if not proof:
                raise drill.DrillError("PRIVATE_DIRECTORY_UNAVAILABLE")
            try:
                yield
            finally:
                events.append(("unpin", None))
        api = SimpleNamespace(create=create, pin=pin)
        sock = SimpleNamespace(setsockopt=lambda *a: None, bind=lambda *a: None, getsockname=lambda: ("127.0.0.1", 56555))
        with patch.object(drill, "ROOT", self.root), patch.object(drill, "PrivateDirectory", return_value=api), \
                patch.object(drill.restore.socket, "socket", return_value=sock), \
                patch.object(drill.restore.secrets, "token_hex", return_value="b" * 32):
            if proof:
                actual.reserve()
                actual.private_pin.__exit__(None, None, None)
                actual.private_pin = None
            else:
                with self.assertRaises(drill.DrillError): actual.reserve()
        return events

    def test_private_directory_proof_precedes_every_child_content_write(self):
        events = self.private_reservation()
        self.assertEqual([kind for kind, _ in events], ["create", "proof", "write", "write", "write", "unpin"])
        self.assertEqual([name for kind, name in events if kind == "write"], ["owner.json", "bootstrap.pass", "pgpass"])

    def test_failed_private_directory_proof_writes_no_child_content(self):
        self.assertEqual([kind for kind, _ in self.private_reservation(proof=False)], ["create", "proof"])

    def test_atomic_creation_security_attributes_are_protected_noninheritable(self):
        import ctypes as c
        api = object.__new__(drill.PrivateDirectory)
        api.user = "S-1-5-21-111-222-333-1001"
        seen = []
        def convert(text, revision, output, size):
            seen.append(text)
            c.cast(output, c.POINTER(c.c_void_p))[0] = 123
            return True
        def create(path, attributes):
            class Attributes(c.Structure):
                _fields_ = [("length", drill.w.DWORD), ("descriptor", c.c_void_p), ("inherit", drill.w.BOOL)]
            observed = c.cast(attributes, c.POINTER(Attributes)).contents
            self.assertEqual(observed.descriptor, 123)
            self.assertFalse(observed.inherit)
            self.assertEqual(observed.length, c.sizeof(Attributes))
            return True
        api.a = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=convert)
        api.k = SimpleNamespace(CreateDirectoryW=Mock(side_effect=create), LocalFree=Mock())
        api.create(self.root / "not-created-by-fake-api")
        self.assertEqual(seen, ["O:" + api.user + "D:P" + "".join("(A;OICI;FA;;;" + sid + ")"
            for sid in (api.user, "S-1-5-18", "S-1-5-32-544"))])
        api.k.LocalFree.assert_called_once()
        self.assertFalse((self.root / "not-created-by-fake-api").exists())

    def test_atomic_creation_refusal_never_repairs_or_adopts_existing_path(self):
        import ctypes as c
        api = object.__new__(drill.PrivateDirectory)
        api.user = "S-1-5-21-111-222-333-1001"
        def convert(text, revision, output, size):
            c.cast(output, c.POINTER(c.c_void_p))[0] = 123
            return True
        api.a = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=convert)
        api.k = SimpleNamespace(CreateDirectoryW=Mock(return_value=False), LocalFree=Mock())
        with self.assertRaises(drill.DrillError): api.create(self.root)
        api.k.LocalFree.assert_called_once()

    def test_acl_inspector_requires_exact_owner_protection_and_inheritable_entries(self):
        import ctypes as c
        for fault in (None, "owner", "unprotected", "extra", "mask", "flags"):
            with self.subTest(fault=fault):
                api = object.__new__(drill.PrivateDirectory)
                api.user = "S-1-5-21-111-222-333-1001"
                acl = c.create_string_buffer(8)
                c.c_ushort.from_buffer(acl, 4).value = 4 if fault == "extra" else 3
                aces = [c.create_string_buffer(24) for _ in range(3)]
                identities = {1: "other" if fault == "owner" else api.user}
                for index, ace in enumerate(aces):
                    c.c_ubyte.from_buffer(ace, 1).value = 16 if fault == "flags" else 3
                    drill.w.DWORD.from_buffer(ace, 4).value = 1 if fault == "mask" else 0x1f01ff
                    identities[c.addressof(ace) + 8] = (api.user, "S-1-5-18", "S-1-5-32-544")[index]
                def security(handle, kind, fields, owner, group, dacl, sacl, descriptor):
                    c.cast(owner, c.POINTER(c.c_void_p))[0] = 1
                    c.cast(dacl, c.POINTER(c.c_void_p))[0] = c.addressof(acl)
                    c.cast(descriptor, c.POINTER(c.c_void_p))[0] = 2
                    return 0
                def control(descriptor, output, revision):
                    c.cast(output, c.POINTER(drill.w.WORD))[0] = 0 if fault == "unprotected" else 0x1000
                    return True
                def getace(dacl, index, output):
                    c.cast(output, c.POINTER(c.c_void_p))[0] = c.addressof(aces[index])
                    return True
                api.a = SimpleNamespace(GetSecurityInfo=security, GetSecurityDescriptorControl=control, GetAce=getace)
                api.k = SimpleNamespace(LocalFree=Mock())
                api.sid = lambda address: identities[address.value if isinstance(address, c.c_void_p) else address]
                if fault:
                    with self.assertRaises(drill.DrillError): api.verify_acl(99, directory=True)
                else:
                    api.verify_acl(99, directory=True)
                api.k.LocalFree.assert_called_once()


if __name__ == "__main__":
    unittest.main()
