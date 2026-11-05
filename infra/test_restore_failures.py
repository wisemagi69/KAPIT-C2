"""Synthetic failure exercises: real Fernet/files; no PostgreSQL, keys or children.

cryptography is required, never skipped: missing dependency cannot report coverage.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet

from infra import restore_rehearsal as restore
from infra.test_restore_rehearsal import StubCursor, StubRuntime


CANARY = "SYNTHETIC_PRIVATE_FAILURE_CANARY"


class Connection:
    def __init__(self, batches):
        self.reader = StubCursor(batches)

    def __enter__(self): return self
    def __exit__(self, *_): return False
    def cursor(self): return self.reader


class IsolatedTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for target in ("subprocess.run", "subprocess.Popen", "socket.socket"):
            self.stack.enter_context(patch(target, side_effect=AssertionError("External action forbidden")))

    def execute(self, driver):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = restore.rehearse(execute=True, reservation="a" * 32, driver=driver)
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(CANARY, json.dumps(result))
        self.assertEqual(result["application"], "CLOSED")
        return result

    def unavailable(self, driver, code=None):
        result = self.execute(driver)
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["restore"], "INCOMPLETE")
        if code:
            self.assertEqual(result["code"], code)
        return result


class FernetFailureTests(IsolatedTests):
    def setUp(self):
        super().setUp()
        self.key = Fernet(Fernet.generate_key())
        self.payload = {"synthetic": CANARY}
        self.raw = json.dumps(self.payload).encode()

    def driver(self, raw=None, reason=None, key=None, expected=None, token=None):
        token = self.key.encrypt(self.raw if raw is None else raw) if token is None else token
        actual = object.__new__(restore.LocalRuntime)
        actual.source_key = self.key if key is None else key
        actual.verify_child = Mock()
        actual.connection = lambda: Connection([[(token, expected or restore._hash(self.payload), reason)]])
        driver = StubRuntime()
        driver.verify_decryption = actual.verify_decryption
        return driver

    def test_real_payload_and_optional_correction_decrypt_success(self):
        for reason in (None, self.key.encrypt(json.dumps("synthetic correction").encode()),
                       self.key.encrypt(json.dumps("\u6c34" * 500, ensure_ascii=False).encode())):
            with self.subTest(has_reason=reason is not None):
                driver = self.driver(reason=reason)
                result = self.execute(driver)
                self.assertEqual(result["status"], "DATABASE_REHEARSAL_PASSED_CLOSED")
                self.assertEqual(result["cleanup"], "STOPPED_VERIFIED")

    def test_unrelated_real_key_cannot_restore_payload(self):
        result = self.unavailable(self.driver(key=Fernet(Fernet.generate_key())), "REHEARSAL_UNAVAILABLE")
        self.assertNotIn("SOURCE_DECRYPTION_AND_SCHEMA_VERIFIED", result["phases"])
        self.assertEqual(result["cleanup"], "STOPPED_VERIFIED")

    def test_truncated_and_bit_changed_payload_and_reason_tokens(self):
        token = self.key.encrypt(self.raw)
        damaged = token[:-5] + bytes([token[-5] ^ 1]) + token[-4:]
        for bad in (token[:-12], damaged, b"not-fernet-" + CANARY.encode()):
            for surface in ("payload", "reason"):
                with self.subTest(surface=surface, variant=len(bad)):
                    driver = self.driver(token=bad) if surface == "payload" else self.driver(reason=bad)
                    self.unavailable(driver, "REHEARSAL_UNAVAILABLE")
                    self.assertEqual(driver.events[-1], "stop_owned")

    def test_correctly_encrypted_but_wrong_content_digest_refuses(self):
        self.unavailable(self.driver(expected="0" * 64), "RESTORED_SOURCE_INTEGRITY")

    def test_invalid_duplicate_and_nonfinite_source_json(self):
        cases = [b"{" + CANARY.encode(), b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}']
        for raw in cases:
            with self.subTest(variant=raw[:1]):
                expected = restore._hash(json.loads(raw)) if raw == b'{"a":1,"a":2}' else "0" * 64
                self.unavailable(self.driver(raw=raw, expected=expected))

    def test_payload_ciphertext_and_plaintext_bounds_before_success(self):
        for driver, code in ((self.driver(token=b"x" * 100001), "SOURCE_CIPHERTEXT_LIMIT"),
                             (self.driver(raw=json.dumps({"s": "x" * (20 * 1024)}).encode()), "RESTORED_SOURCE_INTEGRITY")):
            self.unavailable(driver, code)

    def test_correction_reason_requires_bounded_authenticated_json_string(self):
        for raw in (CANARY.encode(), b'null', b'{}', b'[]', json.dumps("x" * 501).encode(),
                    json.dumps("x" * (20 * 1024)).encode()):
            with self.subTest(variant=raw[:1], size=len(raw)):
                self.unavailable(self.driver(reason=self.key.encrypt(raw)))
        self.unavailable(self.driver(reason=b"x" * 100001), "SOURCE_CIPHERTEXT_LIMIT")


class PreflightAndArchiveTests(IsolatedTests):
    def setUp(self):
        super().setUp()
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.temp).resolve()

    def test_missing_key_file_refuses_before_any_source_connection(self):
        from infra import local, native_postgres
        tools = self.root / "bin"
        tools.mkdir()
        for name in ("postgres", "initdb", "pg_ctl", "createdb", "pg_dump", "pg_restore"):
            (tools / name).write_bytes(b"synthetic binary identity, never executed")
        driver = restore.LocalRuntime("a" * 32)
        driver.checked = lambda path: Path(path)
        driver.source_snapshot = Mock(side_effect=AssertionError("No database allowed"))
        missing_field = self.root / "synthetic-missing-key.json"
        missing_field.write_text(json.dumps({"KAPIT_SECRET_KEY": "s" * 64, "KAPIT_DB_PASSWORD": "p" * 40}))
        for key_path, code in ((self.root / "missing.json", "RESTORE_KEYS_UNAVAILABLE"),
                               (missing_field, "REHEARSAL_UNAVAILABLE")):
            with self.subTest(file_present=key_path.exists()), patch.dict(restore.os.environ, {}, clear=True), \
                patch.object(local, "SECRET_FILE", key_path), \
                patch.object(native_postgres, "ownership", return_value={"binaries": {"directory": str(tools), "hashes": {}}}), \
                patch.object(native_postgres, "status"), \
                patch.object(native_postgres, "binary", side_effect=lambda info, name: str(tools / name)), \
                patch.object(native_postgres, "execute", return_value=SimpleNamespace(stdout="tool (PostgreSQL) 18.0")):
                self.unavailable(driver, code)
        driver.source_snapshot.assert_not_called()

    def archive_driver(self):
        driver = object.__new__(restore.LocalRuntime)
        driver.checked = lambda path: Path(path)
        driver.native = SimpleNamespace(digest=lambda path: hashlib.sha256(path.read_bytes()).hexdigest())
        driver.archive = self.root / "disposable.dump"
        driver.archive.write_bytes(b"PGDMP\x01" + b"synthetic opaque archive fixture" * 8)
        driver.archive_hash = driver.native.digest(driver.archive)
        driver.verify_child = Mock()
        driver.command = Mock()
        driver.port, driver.user, driver.database = 56555, "synthetic_child", "synthetic_restore"
        return driver

    def test_actual_file_truncation_and_same_size_tampering_refuse_before_command(self):
        for mode in ("truncate", "tamper"):
            with self.subTest(mode=mode):
                driver = self.archive_driver()
                original = driver.archive.read_bytes()
                modified = original[:-7] if mode == "truncate" else original[:-1] + bytes([original[-1] ^ 1])
                driver.archive.write_bytes(modified)
                with self.assertRaisesRegex(restore.RehearsalError, "BACKUP_CHANGED"):
                    driver.restore()
                driver.command.assert_not_called()
                self.assertEqual(driver.archive.read_bytes(), modified)

    def test_deleted_archive_refuses_without_restore_command(self):
        driver = self.archive_driver()
        driver.archive.unlink()
        coordinated = StubRuntime()
        coordinated.restore = driver.restore
        self.unavailable(coordinated, "REHEARSAL_UNAVAILABLE")
        driver.command.assert_not_called()
        self.assertEqual(coordinated.events[-1], "stop_owned")

    def test_interrupted_partial_backup_propagates_without_child_or_cleanup_adoption(self):
        backup_dir = self.root / ".cache/m1-runtime/backups"
        backup_dir.mkdir(parents=True)
        partial = backup_dir / "synthetic.partial"
        def interrupted():
            partial.write_bytes(b"interrupted synthetic archive")
            raise KeyboardInterrupt()
        actual = object.__new__(restore.LocalRuntime)
        actual.checked = lambda path: Path(path)
        actual.local = SimpleNamespace(BACKUP_DIR=backup_dir, native_backup=interrupted)
        driver = StubRuntime()
        driver.fresh_backup = actual.fresh_backup
        with patch.object(restore, "ROOT", self.root), self.assertRaises(KeyboardInterrupt):
            self.execute(driver)
        self.assertTrue(partial.is_file())
        self.assertFalse(hasattr(actual, "archive"))
        self.assertNotIn("reserve", driver.events)
        self.assertNotIn("stop_owned", driver.events)

    def test_interrupted_mock_command_from_real_restore_method_stops_reserved_child(self):
        actual = self.archive_driver()
        actual.command.side_effect = KeyboardInterrupt()
        driver = StubRuntime()
        driver.restore = actual.restore
        with self.assertRaises(KeyboardInterrupt):
            self.execute(driver)
        actual.command.assert_called_once()
        self.assertEqual(actual.command.call_args.args[0], "pg_restore")
        self.assertEqual(driver.events[-1], "stop_owned")
        self.assertEqual(driver.events.count("stop_owned"), 1)
        self.assertTrue(actual.archive.exists())

    def test_recorded_child_missing_pidfile_never_claims_not_started_or_signals(self):
        actual = object.__new__(restore.LocalRuntime)
        actual.port_socket = None
        actual.target = self.root
        actual.data = self.root / "data"
        actual.data.mkdir()
        actual.process = {"pid": 999999, "started": 12345}
        actual.check_owner = Mock()
        actual.checked = lambda path: Path(path)
        actual.verify_child, actual.command = Mock(), Mock()
        driver = StubRuntime()
        driver.failure = "restore"
        driver.stop_owned = actual.stop_owned
        result = self.unavailable(driver)
        self.assertEqual(result["cleanup"], "STOP_UNCONFIRMED")
        actual.verify_child.assert_not_called()
        actual.command.assert_not_called()
        self.assertEqual(actual.process["pid"], 999999)

    def test_launch_attempt_without_recorded_identity_stays_uncertain_if_pid_missing(self):
        for failure in (KeyboardInterrupt(), RuntimeError(CANARY)):
            with self.subTest(exception=type(failure).__name__):
                actual = object.__new__(restore.LocalRuntime)
                actual.target, actual.data = self.root, self.root / "unverified-child"
                actual.data.mkdir(exist_ok=True)
                actual.checked = lambda path: Path(path)
                actual.process, actual.launch_attempted = None, False
                socket = Mock()
                actual.port_socket = socket
                actual.check_configuration = Mock()
                actual.check_owner = Mock()
                actual.command = Mock(side_effect=failure)
                actual.verify_child = Mock()
                driver = StubRuntime()
                driver.start, driver.stop_owned = actual.start, actual.stop_owned
                if isinstance(failure, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        self.execute(driver)
                else:
                    self.assertEqual(self.unavailable(driver)["cleanup"], "STOP_UNCONFIRMED")
                self.assertTrue(actual.launch_attempted)
                socket.close.assert_called_once()
                self.assertEqual(actual.command.call_count, 1)
                actual.verify_child.assert_not_called()
                with self.assertRaisesRegex(restore.RehearsalError, "CHILD_STOP_UNCONFIRMED"):
                    actual.stop_owned()


class AuthorizationAndInterruptTests(IsolatedTests):
    # Real model-derived names/field labels, but intentionally synthetic row
    # values and cursor responses: hashing/coordination, not SQL/schema/API proof.
    SURFACES = {
        "scopes_organization": {"policy_epoch": 1, "active_policy_id": "synthetic policy"},
        "scopes_unit": {"scope_epoch": 1},
        "scopes_unitmembership": {"active": True},
        "scopes_channelmember": {"active": True},
        "scopes_channelsource": {"active": True},
        "scopes_policyversion": {"active": True},
        "accounts_user": {"permission_version": 1},
        "django_session": {"session_data": "synthetic before"},
        "accounts_deviceenrollment": {"revoked_at": None},
        "accounts_devicefamily": {"revoked_at": None},
        "accounts_integrationclient": {"revoked_at": None},
        "publications_publicationremoval": {"removed_at": "synthetic before"},
        "publications_revisionwithdrawal": {"withdrawn_at": "synthetic before"},
    }

    def snapshot(self, rows):
        names = sorted(rows)
        batches = [[(name,) for name in names]]
        batches += [[(json.dumps(rows[name], sort_keys=True),)] for name in names]
        batches += [[("operations", "0007_private_evidence_validation")],
                    [("synthetic", "guard", "c", True, "CHECK (epoch >= 0)")],
                    [(name, "synthetic function") for name in sorted(restore.REQUIRED_FUNCTIONS)],
                    [("synthetic", "guard_" + str(i), "O", "synthetic trigger") for i in range(20)],
                    [], []]
        return restore.database_snapshot(Connection(batches))

    def test_each_authority_surface_drift_blocks_current_and_restored_equality(self):
        baseline = self.snapshot(self.SURFACES)
        for name, row in self.SURFACES.items():
            for field in row:
                changed = copy.deepcopy(self.SURFACES)
                changed[name][field] = CANARY
                snapshot = self.snapshot(changed)
                self.assertNotEqual(snapshot["tables"][name], baseline["tables"][name])
                self.assertNotIn(CANARY, json.dumps(snapshot))
                for when, code in (("restored", "RESTORED_SNAPSHOT_MISMATCH"), ("current", "CURRENT_AUTHORIZATION_CHANGED")):
                    with self.subTest(table=name, field=field, when=when):
                        driver = StubRuntime()
                        driver.snapshots = [baseline, baseline, snapshot if when == "current" else baseline]
                        driver.restored = snapshot if when == "restored" else baseline
                        result = self.unavailable(driver, code)
                        self.assertEqual(result["cleanup"], "STOPPED_VERIFIED")
                        self.assertEqual(driver.events[-1], "stop_owned")

    def test_interrupts_and_system_exit_after_reservation_propagate_after_cleanup(self):
        for phase in ("reserve", "initialize", "start", "restored_snapshot", "verify_decryption"):
            for error in (KeyboardInterrupt(), SystemExit(130)):
                with self.subTest(phase=phase, exception=type(error).__name__):
                    driver = StubRuntime()
                    setattr(driver, phase, Mock(side_effect=error))
                    with self.assertRaises(type(error)) as caught:
                        self.execute(driver)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(driver.events[-1], "stop_owned")
                    self.assertEqual(driver.events.count("stop_owned"), 1)

    def test_cleanup_ordinary_failure_cannot_swallow_restore_interrupt(self):
        driver = StubRuntime()
        interrupt = KeyboardInterrupt()
        driver.restore = Mock(side_effect=interrupt)
        driver.stop_owned = Mock(side_effect=RuntimeError(CANARY))
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.execute(driver)
        self.assertIs(caught.exception, interrupt)
        driver.stop_owned.assert_called_once()

    def test_cleanup_failure_keeps_stale_authority_failure_incomplete_and_redacted(self):
        driver = StubRuntime()
        driver.snapshots[-1] = {"current": CANARY}
        driver.stop_owned = Mock(side_effect=RuntimeError(CANARY))
        result = self.unavailable(driver, "CURRENT_AUTHORIZATION_CHANGED")
        self.assertEqual(result["cleanup"], "STOP_UNCONFIRMED")
        driver.stop_owned.assert_called_once()

    def test_interrupt_during_cleanup_is_not_converted_to_a_success_result(self):
        driver = StubRuntime()
        interrupt = KeyboardInterrupt()
        driver.stop_owned = Mock(side_effect=interrupt)
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.execute(driver)
        self.assertIs(caught.exception, interrupt)
        driver.stop_owned.assert_called_once()


if __name__ == "__main__":
    unittest.main()
