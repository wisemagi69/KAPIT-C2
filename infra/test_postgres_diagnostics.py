"""Synthetic, mocked-runtime diagnostics/privacy tests; never starts a service."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infra import local, postgres_diagnostics as diag, start_local

CANARY = "PRIVATE_CANARY_password_report_coordinates_C:/private/user"


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.temp).resolve()
        self.cluster = self.root / "cluster"
        self.data = self.cluster / "data"
        self.data.mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.marker = self.cluster / "owner.json"
        for name, value in (("ROOT", self.root), ("CLUSTER_ROOT", self.cluster), ("DATA", self.data), ("MARKER", self.marker)):
            self.stack.enter_context(patch.object(diag.native, name, value))
        self.execute = self.stack.enter_context(patch.object(diag.native, "execute", return_value=SimpleNamespace(stdout="postgres (PostgreSQL) 18.3\n")))
        self.token = self.stack.enter_context(patch.object(diag, "token_restriction", return_value="NOT_RESTRICTED"))
        for name in ("status", "sql", "password_file", "init", "start", "stop", "save_marker", "verify_connection", "pid_record", "process_identity"):
            self.stack.enter_context(patch.object(diag.native, name, side_effect=AssertionError("MUTATION_OR_DB_FORBIDDEN")))
        self.stack.enter_context(patch.object(local, "managed_environment", side_effect=AssertionError("ENV_FORBIDDEN")))
        self.stack.enter_context(patch.object(local, "checked_cache", side_effect=AssertionError("CACHE_FORBIDDEN")))
        hashes = {}
        for name in diag.native.TOOLS:
            path = self.bin / (name + (".exe" if os.name == "nt" else ""))
            path.write_bytes(b"synthetic public binary")
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        configs = {}
        for name in diag.CONFIG_NAMES:
            (self.data / name).write_bytes(b"synthetic config")
            configs[name] = hashlib.sha256(b"synthetic config").hexdigest()
        self.info = {"schema": 1, "workspace": str(self.root), "data": str(self.data), "port": diag.native.PORT,
                     "phase": "ready", "process": None, "config_hashes": configs,
                     "binaries": {"directory": str(self.bin), "version": "postgres (PostgreSQL) 18.3", "hashes": hashes}}
        self.write_marker()

    def write_marker(self):
        self.marker.write_text(json.dumps(self.info), encoding="utf-8")

    def test_owned_absent_pid_log_readiness_stays_unverified(self):
        report = diag.diagnose()
        self.assertEqual(report["ownership"], "VERIFIED")
        self.assertEqual(report["pid_file"], "ABSENT")
        self.assertEqual(report["log"], "ABSENT")
        self.assertEqual(report["cause"], "UNCONFIRMED")
        self.assertEqual(report["readiness"], "UNVERIFIED")
        self.assertEqual(diag.exit_code(report), 0)
        self.execute.assert_called_once_with([diag.native.binary(self.info, "postgres"), "--version"], timeout=5)

    def test_marker_absent_prevents_binary_and_log_reads(self):
        self.marker.unlink()
        (self.cluster / "server.log").write_text(CANARY)
        report = diag.diagnose()
        self.assertEqual(report["ownership"], "ABSENT")
        self.assertEqual(report["log"], "NOT_INSPECTED")
        self.execute.assert_not_called()

    def test_malformed_and_unknown_ownership_fail_closed(self):
        for value in ("{", "[]", json.dumps({**self.info, "workspace": CANARY}), json.dumps({**self.info, "phase": "unknown"})):
            with self.subTest(value=value):
                self.marker.write_text(value)
                report = diag.diagnose()
                self.assertEqual(report["ownership"], "INVALID")
                self.assertEqual(report["log"], "NOT_INSPECTED")
                self.assertNotIn(CANARY, json.dumps(report))
        self.execute.assert_not_called()

    def test_configuration_or_binary_tamper_blocks_observation(self):
        for path in (self.data / "pg_hba.conf", self.bin / ("postgres.exe" if os.name == "nt" else "postgres")):
            original = path.read_bytes()
            path.write_bytes(CANARY.encode())
            report = diag.diagnose()
            self.assertEqual(report["ownership"], "INVALID")
            self.assertEqual(report["pid_file"], "NOT_INSPECTED")
            path.write_bytes(original)
        self.execute.assert_not_called()

    def test_incomplete_initialization_never_reads_log_or_pid(self):
        self.info["phase"] = "initializing"
        self.write_marker()
        report = diag.diagnose()
        self.assertEqual(report["initialization"], "INCOMPLETE")
        self.assertEqual(report["log"], "NOT_INSPECTED")
        self.assertEqual(diag.exit_code(report), 2)

    def test_native_version_error_never_discloses_exception(self):
        self.execute.side_effect = RuntimeError(CANARY)
        report = diag.diagnose()
        self.assertEqual(report["log"], "NOT_INSPECTED")
        self.assertNotIn(CANARY, json.dumps(report))

    def test_wrong_version_never_reads_log(self):
        self.execute.return_value.stdout = CANARY
        self.assertEqual(diag.diagnose()["ownership"], "INVALID")

    def test_deeply_nested_marker_is_finite_invalid(self):
        self.marker.write_text("[" * 2000 + "0" + "]" * 2000)
        report = diag.diagnose()
        self.assertEqual(report["ownership"], "INVALID")
        self.assertEqual(report["log"], "NOT_INSPECTED")
        self.execute.assert_not_called()

    def test_changed_binary_between_hash_and_execution_prevents_command(self):
        actual = diag._read_bound
        target = Path(diag.native.binary(self.info, "postgres"))
        def read(path, limit):
            content, stamp = actual(path, limit)
            if Path(path) == target:
                target.write_bytes(b"changed after authenticated read")
            return content, stamp
        with patch.object(diag, "_read_bound", side_effect=read):
            report = diag.diagnose()
        self.assertEqual(report["ownership"], "UNAVAILABLE")
        self.execute.assert_not_called()

    def test_changed_configuration_during_version_prevents_log_observation(self):
        def version(*args, **kwargs):
            (self.data / "pg_hba.conf").write_bytes(b"changed during version")
            return SimpleNamespace(stdout=self.info["binaries"]["version"])
        self.execute.side_effect = version
        report = diag.diagnose()
        self.assertEqual(report["ownership"], "UNAVAILABLE")
        self.assertEqual(report["log"], "NOT_INSPECTED")

    def test_existing_log_categories_are_unattributed_and_private(self):
        text = CANARY + " restricted token; permission denied; address already in use; database system is ready to accept connections"
        (self.cluster / "server.log").write_text(text)
        report = diag.diagnose()
        self.assertEqual(report["log_conditions"], ["TOKEN_RESTRICTION", "PERMISSION_DENIED", "PORT_UNAVAILABLE", "READY_RECORDED"])
        self.assertEqual(report["log_attribution"], "EXISTING_LOG_NOT_BOUND_TO_FAILED_ATTEMPT")
        self.assertEqual(report["cause"], "UNCONFIRMED")
        self.assertNotIn(CANARY, json.dumps(report))

    def test_unknown_log_does_not_echo_or_invent_category(self):
        (self.cluster / "server.log").write_text(CANARY)
        self.assertEqual(diag.diagnose()["log_conditions"], [])

    def test_oversized_log_never_classifies_prefix(self):
        (self.cluster / "server.log").write_bytes(b"permission denied" + b"x" * diag.LOG_LIMIT)
        report = diag.diagnose()
        self.assertEqual(report["log"], "OVERSIZED")
        self.assertEqual(report["log_conditions"], [])
        self.assertEqual(diag.exit_code(report), 2)

    def test_valid_pid_reports_no_identifier_or_running_claim(self):
        (self.data / "postmaster.pid").write_text(f"12345\n{self.data}\n100\n{diag.native.PORT}\n\n127.0.0.1\n")
        report = diag.diagnose()
        self.assertEqual(report["pid_file"], "PRESENT_VALIDATED_PROCESS_UNVERIFIED")
        self.assertNotIn("12345", json.dumps(report))
        self.assertNotIn(str(self.data), json.dumps(report))

    def test_invalid_pid_is_not_absent(self):
        for text in (CANARY, f"0\n{self.data}\n100\n55436\n\n127.0.0.1", f"12\n{self.root}\n100\n55436\n\n127.0.0.1"):
            (self.data / "postmaster.pid").write_text(text)
            report = diag.diagnose()
            self.assertEqual(report["pid_file"], "INVALID")
            self.assertEqual(diag.exit_code(report), 2)

    def test_token_restriction_does_not_establish_cause(self):
        self.token.return_value = "RESTRICTED"
        report = diag.diagnose()
        self.assertEqual(report["current_token"], "RESTRICTED")
        self.assertEqual(report["cause"], "UNCONFIRMED")

    def test_token_api_unavailable_is_finite_nonzero(self):
        self.token.side_effect = OSError(CANARY)
        report = diag.diagnose()
        self.assertEqual(report["current_token"], "UNAVAILABLE")
        self.assertEqual(diag.exit_code(report), 2)
        self.assertNotIn(CANARY, json.dumps(report))

    def test_denied_log_metadata_is_finite(self):
        actual = diag.read_bounded
        def read(path, limit):
            if Path(path).name == "server.log":
                raise PermissionError(CANARY)
            return actual(path, limit)
        with patch.object(diag, "read_bounded", side_effect=read):
            report = diag.diagnose()
        self.assertEqual(report["log"], "UNAVAILABLE")
        self.assertNotIn(CANARY, json.dumps(report))

    def test_cli_dispatch_precedes_cache_environment_and_docker(self):
        with patch("sys.argv", ["local.py", "native-diagnose", "--docker-host", "invalid"]), patch.object(local, "local_docker_endpoint", side_effect=AssertionError("DOCKER_FORBIDDEN")), redirect_stdout(io.StringIO()) as stream:
            with self.assertRaises(SystemExit) as result:
                local.main()
        self.assertEqual(result.exception.code, 0)
        self.assertEqual(json.loads(stream.getvalue())["readiness"], "UNVERIFIED")

    def test_script_entry_adds_project_root_before_diagnostic_import(self):
        # Reproduce direct script sys.path with no project-root search entry.
        search = [str(Path(local.__file__).parent)] + [p for p in sys.path if p and Path(p).resolve() != local.ROOT.resolve()]
        def entry():
            self.assertEqual(sys.path[0], str(local.ROOT))
            raise SystemExit(2)
        with patch.object(sys, "path", search), patch.object(sys, "argv", ["infra/local.py", "native-diagnose"]), patch.object(diag, "main", side_effect=entry):
            with self.assertRaises(SystemExit) as result:
                local.main()
        self.assertEqual(result.exception.code, 2)

    def test_failure_hint_retains_code_and_never_runs_diagnose(self):
        with patch.object(local, "native_module") as module, patch.object(diag, "diagnose", side_effect=AssertionError("AUTORUN_FORBIDDEN")), redirect_stdout(io.StringIO()):
            module.return_value.start.side_effect = RuntimeError("NATIVE_COMMAND: " + CANARY)
            with self.assertRaises(start_local.StartupError) as raised:
                start_local.native_phase("start")
        self.assertIn("NATIVE_COMMAND", str(raised.exception))
        self.assertIn("native-diagnose", str(raised.exception))
        self.assertNotIn("native-start", str(raised.exception))
        self.assertNotIn(CANARY, str(raised.exception))


class BoundedReadTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory())).resolve()
        self.path = self.directory / "sample"
        self.path.write_bytes(b"sample")

    def test_regular_read_and_size_bound(self):
        self.assertEqual(diag.read_bounded(self.path, 6), b"sample")
        with self.assertRaises(diag.Unavailable):
            diag.read_bounded(self.path, 5)

    def test_nonregular_file_is_rejected(self):
        with self.assertRaises(diag.Unavailable):
            diag.read_bounded(self.directory, 4096)

    def test_reparse_attribute_is_rejected(self):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400, st_nlink=1)):
            with self.assertRaises(diag.Unavailable):
                diag._plain(self.path)

    def test_hardlink_is_rejected(self):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0, st_nlink=2)):
            with self.assertRaises(diag.Unavailable):
                diag._plain(self.path)

    def test_symlink_mode_is_rejected(self):
        with patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0, st_nlink=1)):
            with self.assertRaises(diag.Unavailable):
                diag._plain(self.path)

    def test_changed_open_identity_is_rejected(self):
        actual = os.fstat(self.stack.enter_context(open(self.path, "rb")).fileno())
        changed = SimpleNamespace(**{name: getattr(actual, name) for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_nlink")})
        changed.st_ino += 1
        with patch.object(diag.os, "fstat", return_value=changed):
            with self.assertRaises(diag.Unavailable):
                diag.read_bounded(self.path, 4096)


if __name__ == "__main__":
    unittest.main()
