"""Boundary and failure tests; mocked lifecycle cases are not live PostgreSQL evidence."""
from contextlib import ExitStack, contextmanager, redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from infra import local
from infra import native_postgres as pg


class NativeClusterTests(unittest.TestCase):
    def setUp(self):
        base = pg.ROOT / ".cache/m1-runtime/native-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        self.root = Path(self.temporary.name) / "postgres"
        self.patches = [patch.object(pg, "CLUSTER_ROOT", self.root), patch.object(pg, "DATA", self.root / "data"), patch.object(pg, "MARKER", self.root / "owner.json")]
        for item in self.patches:
            item.start()
        self.binaries = {"directory": str(Path(self.temporary.name) / "bin"), "version": "postgres (PostgreSQL) 18.3", "hashes": {}}

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def marker(self, phase="initializing"):
        self.root.mkdir(exist_ok=True)
        info = {"schema": 1, "workspace": str(pg.ROOT.resolve()), "data": str(pg.DATA.resolve()), "port": 55436,
                "binaries": self.binaries, "phase": phase, "process": None}
        pg.save_marker(info, first=not pg.MARKER.exists())
        return info

    def complete_files(self):
        pg.DATA.mkdir(exist_ok=True)
        for name in ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"):
            (pg.DATA / name).write_text("synthetic config\n")

    def ready(self):
        info = self.marker("ready")
        self.complete_files()
        info["config_hashes"] = {name: pg.digest(pg.DATA / name) for name in
                               ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")}
        pg.save_marker(info)
        return info

    def test_unknown_directory_is_never_adopted_or_replaced(self):
        self.root.mkdir()
        sentinel = self.root / "existing.data"
        sentinel.write_text("existing data")
        with self.assertRaisesRegex(RuntimeError, "NATIVE_OWNER"), patch.object(pg, "execute") as run:
            pg.init()
        run.assert_not_called()
        self.assertEqual(sentinel.read_text(), "existing data")

    def test_mismatched_workspace_and_port_fail_before_launch(self):
        self.marker()
        for name, value in (("workspace", str(pg.ROOT.parent)), ("port", 5432)):
            info = json.loads(pg.MARKER.read_text())
            original = info[name]
            info[name] = value
            pg.MARKER.write_text(json.dumps(info))
            with self.assertRaisesRegex(RuntimeError, "NATIVE_OWNER"), patch.object(pg, "execute") as run:
                pg.start()
            run.assert_not_called()
            info[name] = original
            pg.MARKER.write_text(json.dumps(info))

    def test_changed_configuration_is_rejected_before_process_action(self):
        self.ready()
        (pg.DATA / "postgresql.conf").write_text("listen_addresses='*'\n")
        with patch.object(pg, "discover", return_value=self.binaries), patch.object(pg, "execute") as run:
            with self.assertRaisesRegex(RuntimeError, "NATIVE_CONFIG"):
                pg.stop()
        run.assert_not_called()

    def test_partial_data_is_retained_and_not_reinitialized(self):
        self.marker()
        pg.DATA.mkdir()
        sentinel = pg.DATA / "PG_VERSION"
        sentinel.write_text("18")
        with patch.object(pg, "discover", return_value=self.binaries), patch.object(pg, "execute") as run:
            with self.assertRaisesRegex(RuntimeError, "NATIVE_INIT_PARTIAL"):
                pg.init()
        run.assert_not_called()
        self.assertEqual(sentinel.read_text(), "18")

    def test_owned_empty_initialization_can_resume_without_changing_marker_identity(self):
        original = self.marker()

        @contextmanager
        def password():
            yield self.root / "temporary.pass"

        def initialize_files(command, **kwargs):
            self.assertIn("--no-clean", command)
            self.assertIn("--auth=scram-sha-256", command)
            pg.DATA.mkdir()
            (pg.DATA / "PG_VERSION").write_text("18\n")
            (pg.DATA / "postgresql.auto.conf").write_text("# owned\n")
            return SimpleNamespace(returncode=0)

        with patch.object(pg, "discover", return_value=self.binaries), patch.object(pg.runtime, "initialize"), patch.object(pg, "password_file", password), patch.object(pg, "execute", side_effect=initialize_files):
            result = pg.init()
        info = json.loads(pg.MARKER.read_text())
        for name in ("workspace", "data", "port", "binaries"):
            self.assertEqual(info[name], original[name])
        self.assertEqual(info["phase"], "ready")
        self.assertFalse(result["retained"])
        self.assertEqual((pg.DATA / "pg_hba.conf").read_text(), pg.HBA)

    def test_occupied_port_does_not_start_or_stop_any_process(self):
        info = self.ready()
        with patch.object(pg, "ownership", return_value=info), patch.object(pg, "pid_record", return_value=None), patch.object(pg.socket, "socket") as sock, patch.object(pg, "execute") as run:
            sock.return_value.__enter__.return_value.bind.side_effect = OSError("occupied")
            with self.assertRaisesRegex(RuntimeError, "NATIVE_PORT"):
                pg.start()
        run.assert_not_called()

    def test_pid_reuse_or_wrong_executable_prevents_stop(self):
        info = self.ready()
        record = {"pid": 123, "started": 500}
        expected = pg.binary(info, "postgres")
        for identity in ({"path": expected, "started": 100}, {"path": "C:/unrelated/server.exe", "started": 500}):
            with patch.object(pg, "ownership", return_value=info), patch.object(pg, "pid_record", return_value=record), patch.object(pg, "process_identity", return_value=identity), patch.object(pg, "execute") as run:
                with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                    pg.stop()
            run.assert_not_called()

    def test_connection_identity_rejects_another_data_directory(self):
        info = self.ready()
        info["process"] = {"started": 500}
        remote = {"data": str(pg.ROOT / "unrelated"), "port": "55436", "listen": "127.0.0.1", "user": "kapit_m1", "started": 500, "version": "18.3"}
        with patch.object(pg, "sql", return_value=json.dumps(remote)):
            with self.assertRaisesRegex(RuntimeError, "NATIVE_DATABASE"):
                pg.verify_connection(info)

    def test_child_environment_cannot_inherit_postgres_redirects(self):
        with patch.dict(pg.os.environ, {"PGSERVICE": "other", "PGPASSWORD": "private-canary", "PGOPTIONS": "redirect", "PGDATA": "other"}):
            env = pg.clean_environment()
            self.assertNotIn("PGPASSWORD", env)
            self.assertNotIn("PGSERVICE", env)
            self.assertNotIn("PGDATA", env)
            self.assertNotIn("PGOPTIONS", env)
            self.assertEqual(pg.os.environ["PGPASSWORD"], "private-canary")

    def test_command_failure_redacts_output_and_classifies_token_denial(self):
        result = SimpleNamespace(returncode=1, stdout="private-canary", stderr="CreateRestrictedToken failed")
        with patch.object(pg.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "NATIVE_TOKEN_RESTRICTED") as error:
                pg.execute(["initdb"])
        self.assertNotIn("private-canary", str(error.exception))

    def stale_ready(self):
        info = self.ready()
        info["process"] = {"pid": 12345, "started": 500,
                           "executable": pg.binary(info, "postgres"), "process_started": 501}
        pg.save_marker(info)
        (pg.DATA / "postmaster.pid").write_text(
            f"12345\n{pg.DATA.resolve()}\n500\n55436\n\n127.0.0.1\n0\nready\n")
        return info

    @contextmanager
    def recovery_guards(self):
        with ExitStack() as stack:
            mocks = {}
            stack.enter_context(patch.object(pg, "discover", return_value=self.binaries))
            mocks["absence"] = stack.enter_context(patch.object(pg, "process_absent", return_value=True))
            mocks["socket"] = stack.enter_context(patch.object(pg.socket, "socket"))
            mocks["launch"] = stack.enter_context(patch.object(pg, "execute"))
            mocks["process"] = stack.enter_context(patch.object(pg, "verify_process", return_value={
                "pid": 54321, "started": 900, "executable": str(Path(self.binaries["directory"]) / "postgres.exe"),
                "process_started": 900}))
            mocks["connection"] = stack.enter_context(patch.object(pg, "verify_connection", return_value="18.3"))
            mocks["database"] = stack.enter_context(patch.object(pg, "sql", return_value="1"))
            mocks["status"] = stack.enter_context(patch.object(pg, "status", return_value={"state": "running", "owned": True}))
            yield mocks

    def test_windows_absence_requires_exact_positive_result_not_probe_failure(self):
        for raw, expected in (("absent\r\n", True), ("present\r\n", False)):
            with patch.object(pg.os, "name", "nt"), patch.object(pg, "execute", return_value=SimpleNamespace(stdout=raw)) as run:
                self.assertIs(pg.process_absent(12345), expected)
                command = run.call_args.args[0][-1]
                self.assertIn("[System.Diagnostics.Process]::GetProcessById(12345)", command)
                self.assertIn("catch [System.ArgumentException]", command)
                self.assertIn("catch { 'unknown' }", command)
        for raw in ("unknown", "", "absent\npresent", "access denied private-canary"):
            with self.subTest(raw=raw), patch.object(pg.os, "name", "nt"), patch.object(pg, "execute", return_value=SimpleNamespace(stdout=raw)):
                with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS") as failure:
                    pg.process_absent(12345)
                self.assertNotIn("private-canary", str(failure.exception))
        with patch.object(pg.os, "name", "nt"), patch.object(pg, "execute", side_effect=RuntimeError("NATIVE_COMMAND: unavailable")):
            with self.assertRaisesRegex(RuntimeError, "absence is unverified"):
                pg.process_absent(12345)

    def test_invalid_pid_never_reaches_absence_probe(self):
        for pid in (0, -1, True, "123", 2147483648):
            with self.subTest(pid=pid), patch.object(pg.os, "name", "nt"), patch.object(pg, "execute") as run:
                with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                    pg.process_absent(pid)
                run.assert_not_called()

    def test_live_owned_pid_only_uses_existing_status_path(self):
        self.stale_ready()
        with self.recovery_guards() as guard:
            guard["absence"].return_value = False
            self.assertEqual(pg.start(), {"state": "running", "owned": True})
            guard["status"].assert_called_once_with(require_running=True)
            guard["launch"].assert_not_called()
            guard["socket"].assert_not_called()

    def test_reused_pid_start_refuses_via_original_identity_check(self):
        info = self.stale_ready()
        for identity in ({"path": pg.binary(info, "postgres"), "started": 800},
                         {"path": str(pg.ROOT / "unrelated.exe"), "started": 500}):
            with self.subTest(identity=identity), patch.object(pg, "discover", return_value=self.binaries), patch.object(pg, "process_absent", return_value=False), patch.object(pg, "process_identity", return_value=identity), patch.object(pg, "execute") as run:
                with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                    pg.start()
                run.assert_not_called()

    def test_unknown_process_state_never_launches_or_changes_owner(self):
        self.stale_ready()
        before = pg.MARKER.read_bytes()
        with self.recovery_guards() as guard:
            guard["absence"].side_effect = RuntimeError("NATIVE_PROCESS: absence unverified")
            with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                pg.start()
            guard["launch"].assert_not_called()
        self.assertEqual(pg.MARKER.read_bytes(), before)

    def test_absent_pid_must_match_complete_retained_owner(self):
        for field, value in (("pid", 34567), ("started", 600), ("process_started", 900),
                             ("executable", str(pg.ROOT / "other.exe")), ("pid", True)):
            with self.subTest(field=field, value=value):
                info = self.stale_ready()
                info["process"][field] = value
                pg.save_marker(info)
                before = pg.MARKER.read_bytes()
                with self.recovery_guards() as guard:
                    with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                        pg.start()
                    guard["launch"].assert_not_called()
                self.assertEqual(pg.MARKER.read_bytes(), before)

    def test_stale_pid_data_port_and_listen_mismatch_refuses_launch(self):
        for index, value in ((1, str(pg.ROOT / "other")), (3, "5432"), (5, "0.0.0.0")):
            with self.subTest(index=index):
                self.stale_ready()
                target = pg.DATA / "postmaster.pid"
                lines = target.read_text().splitlines()
                lines[index] = value
                target.write_text("\n".join(lines) + "\n")
                with self.recovery_guards() as guard:
                    with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                        pg.start()
                    guard["launch"].assert_not_called()

    def test_recovery_rechecks_changed_marker_pid_config_and_binary(self):
        for change in ("marker", "pid", "config", "binary"):
            with self.subTest(change=change):
                self.stale_ready()
                with self.recovery_guards() as guard:
                    def mutate(_address):
                        if change == "marker":
                            pg.MARKER.write_text(pg.MARKER.read_text() + "\n")
                        elif change == "pid":
                            target = pg.DATA / "postmaster.pid"
                            target.write_text(target.read_text() + "\n")
                        elif change == "config":
                            (pg.DATA / "postgresql.conf").write_text("changed")
                        else:
                            self.binaries = {**self.binaries, "version": "changed"}
                            pg.discover.return_value = self.binaries
                    guard["socket"].return_value.__enter__.return_value.bind.side_effect = mutate
                    with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS|NATIVE_CONFIG"):
                        pg.start()
                    guard["launch"].assert_not_called()

    def test_recovery_rechecks_absence_and_final_snapshot(self):
        for mutation in ("reappeared", "pid_after_probe", "config_after_probe"):
            with self.subTest(mutation=mutation):
                self.stale_ready()
                with self.recovery_guards() as guard:
                    calls = 0
                    def absence(_pid):
                        nonlocal calls
                        calls += 1
                        if calls == 2:
                            if mutation == "reappeared":
                                return False
                            target = pg.DATA / ("postgresql.conf" if mutation == "config_after_probe" else "postmaster.pid")
                            target.write_text(target.read_text() + "changed\n")
                        return True
                    guard["absence"].side_effect = absence
                    with self.assertRaisesRegex(RuntimeError, "NATIVE_PROCESS"):
                        pg.start()
                    guard["launch"].assert_not_called()

    def test_stale_recovery_occupied_port_preserves_pid_and_owner(self):
        self.stale_ready()
        before = pg.startup_snapshot()
        with self.recovery_guards() as guard:
            guard["socket"].return_value.__enter__.return_value.bind.side_effect = OSError("occupied")
            with self.assertRaisesRegex(RuntimeError, "NATIVE_PORT"):
                pg.start()
            guard["launch"].assert_not_called()
        self.assertEqual(pg.startup_snapshot(), before)

    def test_failed_launch_or_new_identity_never_rewrites_owner_or_pid(self):
        for stage in ("launch", "process", "connection", "database", "no_process"):
            with self.subTest(stage=stage):
                self.stale_ready()
                before = pg.startup_snapshot()
                with self.recovery_guards() as guard:
                    if stage == "database":
                        guard[stage].return_value = "0"
                    elif stage == "no_process":
                        guard["process"].return_value = None
                    else:
                        guard[stage].side_effect = RuntimeError("NATIVE_COMMAND: test failure")
                    with self.assertRaises(RuntimeError):
                        pg.start()
                    # The only possible lifecycle command is guarded pg_ctl start.
                    for call in guard["launch"].call_args_list:
                        self.assertEqual(Path(call.args[0][0]).stem, "pg_ctl")
                        self.assertEqual(call.args[0][-1], "start")
                self.assertEqual(pg.startup_snapshot(), before)

    def test_stale_recovery_validates_server_before_accepting_new_owner(self):
        original = self.stale_ready()
        pid_before = (pg.DATA / "postmaster.pid").read_bytes()
        with self.recovery_guards() as guard:
            def verify_before_save(_info):
                self.assertEqual(json.loads(pg.MARKER.read_text()), original)
                self.assertEqual((pg.DATA / "postmaster.pid").read_bytes(), pid_before)
                return "18.3"
            guard["connection"].side_effect = verify_before_save
            self.assertTrue(pg.start()["owned"])
            guard["launch"].assert_called_once()
            self.assertEqual(guard["launch"].call_args.args[0][-1], "start")
            self.assertFalse(guard["launch"].call_args.kwargs["capture"])
            self.assertEqual(guard["absence"].call_count, 2)
            self.assertEqual(json.loads(pg.MARKER.read_text())["process"], guard["process"].return_value)
        # Only PostgreSQL may arbitrate the old lock. This mocked launch leaves it.
        self.assertEqual((pg.DATA / "postmaster.pid").read_bytes(), pid_before)

    def test_initial_start_can_create_its_workspace_database(self):
        self.ready()
        with self.recovery_guards() as guard:
            guard["database"].return_value = "0"
            @contextmanager
            def password(**kwargs):
                yield self.root / "synthetic.pass"
            with patch.object(pg, "password_file", password):
                self.assertTrue(pg.start()["owned"])
            guard["absence"].assert_not_called()
            self.assertEqual([Path(call.args[0][0]).stem for call in guard["launch"].call_args_list], ["pg_ctl", "createdb"])


class ManagedLaunchTests(unittest.TestCase):
    def test_alternate_loopback_addresses_cannot_redirect_owned_database_commands(self):
        for host in ("127.0.0.2", "::1", "::ffff:127.0.0.1"):
            with self.subTest(host=host), patch.dict(local.os.environ, {"KAPIT_DB_HOST": host, "KAPIT_RUNTIME_CONTEXT": "native"}, clear=True), patch.object(local, "native_module") as module, patch.object(local, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "NATIVE_HOST|Remote database access"):
                    local.native_test()
                module.assert_not_called()
                run.assert_not_called()
        with patch.dict(local.os.environ, {"KAPIT_DB_HOST": "localhost"}, clear=True):
            self.assertEqual(local.managed_environment()["KAPIT_DB_HOST"], "127.0.0.1")

    def test_hosted_context_cannot_enter_native_test_runner(self):
        with patch.dict(local.os.environ, {"KAPIT_RUNTIME_CONTEXT": "supabase-m1"}), patch.object(local, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "NATIVE_CONTEXT"):
                local.native_test()
        run.assert_not_called()

    def test_unowned_database_prevents_django_test_command(self):
        with patch.dict(local.os.environ, {}, clear=True), patch.object(local, "native_module") as module, patch.object(local, "run") as run:
            module.return_value.status.side_effect = RuntimeError("NATIVE_OWNER: unknown")
            with self.assertRaisesRegex(RuntimeError, "NATIVE_OWNER"):
                local.native_test()
        run.assert_not_called()

    def test_native_test_only_uses_explicit_local_test_settings(self):
        with patch.dict(local.os.environ, {}, clear=True), patch.object(local, "native_module"), patch.object(local, "dependency_status", return_value={"modules": {"django": True}}), patch.object(local, "run") as run:
            local.native_test()
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertTrue(all("--settings=config.test_settings" in command for command in commands))
        self.assertIn("--testrunner=tests.browser_runner.BrowserAcceptanceRunner", commands[-1])
        self.assertNotIn("--noinput", commands[-1])
        self.assertNotIn("--keepdb", commands[-1])
        self.assertFalse(any("flush" in command or "seed_demo" in command for command in commands))

    def test_doctor_uses_blocked_exit_and_never_initializes(self):
        report = {"ready": False, "checks": [{"code": "PYTHON_PACKAGES_MISSING"}]}
        with patch.object(local.sys, "argv", ["local.py", "doctor"]), patch.object(local, "doctor", return_value=report), patch.object(local, "initialize") as initialize, redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                local.main()
        self.assertEqual(error.exception.code, 2)
        initialize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
