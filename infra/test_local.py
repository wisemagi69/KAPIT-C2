"""Executed native-runtime safety tests; these do not verify Django or PostgreSQL."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import infra.local as runtime
import infra.container_entrypoint as container
from config.runtime_boundary import boundary


class KeyInitializationTests(unittest.TestCase):
    def setUp(self):
        base = runtime.ROOT / ".cache/m1-runtime/runtime-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.folder = tempfile.TemporaryDirectory(dir=base)
        self.cache = Path(self.folder.name)
        self.patch_cache = patch.object(runtime, "CACHE", self.cache)
        self.patch_file = patch.object(runtime, "SECRET_FILE", self.cache / "secrets.json")
        self.patch_cache.start()
        self.patch_file.start()

    def tearDown(self):
        self.patch_file.stop()
        self.patch_cache.stop()
        self.folder.cleanup()

    def initialize_quietly(self):
        output = io.StringIO()
        with redirect_stdout(output):
            runtime.initialize()
        return output.getvalue()

    def test_restart_retains_all_keys_and_never_prints_them(self):
        first_output = self.initialize_quietly()
        before = {path.name: path.read_bytes() for path in self.cache.iterdir()}
        second_output = self.initialize_quietly()
        after = {path.name: path.read_bytes() for path in self.cache.iterdir()}
        self.assertEqual(before, after)
        for value in json.loads(before["secrets.json"]).values():
            self.assertNotIn(value, first_output + second_output)

    def test_conflicting_environment_file_fails_without_replacing_keys(self):
        self.initialize_quietly()
        original = (self.cache / "secrets.json").read_bytes()
        (self.cache / "db.env").write_text("POSTGRES_PASSWORD=conflicting-private-value\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "files differ"):
            self.initialize_quietly()
        self.assertEqual(original, (self.cache / "secrets.json").read_bytes())
        self.assertIn("conflicting-private-value", (self.cache / "db.env").read_text())

    def test_environment_injection_in_existing_secret_is_rejected(self):
        self.initialize_quietly()
        values = json.loads((self.cache / "secrets.json").read_text())
        values["KAPIT_DB_PASSWORD"] += "\nUNEXPECTED_SETTING=canary"
        original = json.dumps(values)
        (self.cache / "secrets.json").write_text(original, encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "invalid format"):
            self.initialize_quietly()
        self.assertEqual(original, (self.cache / "secrets.json").read_text())

    def test_cache_target_outside_workspace_is_denied_before_creation(self):
        # Path validation only; no outside path is read or written.
        with patch.object(runtime, "CACHE", runtime.ROOT.parent / "kapit-denied-fixture"):
            with self.assertRaisesRegex(RuntimeError, "outside this workspace"):
                runtime.checked_cache()


class LocalDockerBoundaryTests(unittest.TestCase):
    def test_remote_endpoints_are_rejected_before_runtime_mutation(self):
        for endpoint in ["tcp://remote.example:2375", "tcp://192.0.2.10:2375", "npipe:////remote/pipe/docker_engine", "ssh://remote.example", "unix://remote.example/run/docker.sock"]:
            with self.subTest(endpoint=endpoint):
                with patch.object(runtime.sys, "argv", ["local.py", "up", "--docker-host", endpoint]), patch.object(runtime, "initialize") as init, patch.object(runtime, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "Remote daemon access"):
                        runtime.main()
                    init.assert_not_called()
                    run.assert_not_called()

    def test_explicit_local_endpoints_are_allowed_without_connecting(self):
        for endpoint in ["npipe:////./pipe/dockerDesktopLinuxEngine", "unix:///var/run/docker.sock", "tcp://127.0.0.1:2375", "tcp://[::1]:2375"]:
            self.assertEqual(runtime.local_docker_endpoint(endpoint), endpoint)

    def test_inherited_daemon_redirect_is_removed_from_invocation_only(self):
        with patch.dict(runtime.os.environ, {"DOCKER_HOST": "tcp://remote.example:2375", "DOCKER_CONTEXT": "remote-demo", "DOCKER_TLS_VERIFY": "1", "DOCKER_CERT_PATH": "private-canary-path", "BUILDKIT_HOST": "tcp://remote-builder.example:1234", "BUILDX_BUILDER": "remote-builder"}):
            env = runtime.docker_environment()
            for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
                self.assertNotIn(key, env)
            self.assertEqual(runtime.os.environ["DOCKER_CONTEXT"], "remote-demo")
            self.assertNotIn("BUILDKIT_HOST", env)
            self.assertEqual(env["BUILDX_BUILDER"], "default")
            self.assertEqual(runtime.os.environ["BUILDX_BUILDER"], "remote-builder")


class NativeRuntimeBoundaryTests(unittest.TestCase):
    def test_backend_start_preserves_administered_accounts_and_seed_is_explicit(self):
        with patch.dict(runtime.os.environ, {}, clear=True), patch.object(runtime.sys, "argv", ["local.py", "backend"]), patch.object(runtime, "initialize"), patch.object(runtime, "run") as run, patch.object(runtime, "require_migration_approval") as guard:
            runtime.main()
            self.assertEqual(len(run.call_args_list), 2)
            self.assertEqual(run.call_args_list[0].args[0][-2:], ["migrate", "--noinput"])
            self.assertTrue(run.call_args_list[1].args[0][-1].endswith("server.py"))
            self.assertFalse(any("seed_demo" in call.args[0] for call in run.call_args_list))
            guard.assert_called_once()
        with patch.dict(runtime.os.environ, {}, clear=True), patch.object(runtime.sys, "argv", ["local.py", "seed-demo"]), patch.object(runtime, "initialize"), patch.object(runtime, "run") as run, patch.object(runtime, "require_migration_approval"):
            runtime.main()
            self.assertEqual(run.call_args_list[-1].args[0][-1], "seed_demo")

    def test_compose_backend_start_never_recreates_demo_grants(self):
        with patch.object(container.sys, "argv", ["container_entrypoint.py", "backend"]), patch.object(container, "boundary", return_value=SimpleNamespace(context="compose-m1")), patch.object(container.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run, patch.object(container.os, "execve") as launch:
            container.main()
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][-2:], ["migrate", "--noinput"])
            self.assertTrue(launch.call_args.args[1][-1].endswith("server.py"))

    def test_native_inherited_settings_are_replaced_without_parent_mutation(self):
        for module in ["unrelated.production_settings", "config.test_settings"]:
            with self.subTest(module=module), patch.dict(runtime.os.environ, {"KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55436", "DJANGO_SETTINGS_MODULE": module}):
                env = runtime.environment()
                self.assertEqual(env["DJANGO_SETTINGS_MODULE"], "config.settings")
                self.assertEqual(runtime.os.environ["DJANGO_SETTINGS_MODULE"], module)

    def test_remote_database_is_rejected_before_native_mutation(self):
        for command in ["backend", "worker"]:
            for host in ["remote.example", "192.0.2.10", "0.0.0.0", "db"]:
                with self.subTest(command=command, host=host), patch.dict(runtime.os.environ, {"KAPIT_DB_HOST": host}), patch.object(runtime.sys, "argv", ["local.py", command]), patch.object(runtime, "initialize") as init, patch.object(runtime, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "Remote database access"):
                        runtime.main()
                    init.assert_not_called()
                    run.assert_not_called()

    def test_external_project_port_is_rejected_before_native_mutation(self):
        with patch.dict(runtime.os.environ, {"KAPIT_DB_HOST": "127.0.0.1", "KAPIT_DB_PORT": "55434"}), patch.object(runtime.sys, "argv", ["local.py", "backend"]), patch.object(runtime, "initialize") as init, patch.object(runtime, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "isolated port"):
                runtime.main()
            init.assert_not_called()
            run.assert_not_called()

    def test_native_child_cannot_inherit_container_bind_or_external_keys(self):
        variables = {"KAPIT_DB_HOST": "localhost", "KAPIT_DB_PORT": "55436", "KAPIT_LOCAL_CONTAINER": "1", "KAPIT_RUNTIME_CONTEXT": "compose-m1", "KAPIT_DB_PASSWORD": "unrelated-private-canary"}
        with patch.dict(runtime.os.environ, variables):
            env = runtime.environment()
            self.assertEqual(env["KAPIT_DB_HOST"], "127.0.0.1")
            self.assertEqual(env["KAPIT_LOCAL_CONTAINER"], "0")
            self.assertEqual(env["KAPIT_RUNTIME_CONTEXT"], "native")
            self.assertNotIn("KAPIT_DB_PASSWORD", env)
            self.assertEqual(boundary(env).bind_host, "127.0.0.1")
            self.assertEqual(runtime.os.environ["KAPIT_LOCAL_CONTAINER"], "1")

    def test_direct_context_flag_without_image_markers_is_denied(self):
        with patch("config.runtime_boundary.verified_container_image", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "reviewed local Docker image"):
                boundary({"KAPIT_RUNTIME_CONTEXT": "compose-m1", "KAPIT_DB_HOST": "db", "KAPIT_DB_PORT": "5432"})

    def test_verified_compose_context_only_accepts_private_db_service(self):
        with patch("config.runtime_boundary.verified_container_image", return_value=True):
            selected = boundary({"KAPIT_RUNTIME_CONTEXT": "compose-m1", "KAPIT_DB_HOST": "db", "KAPIT_DB_PORT": "5432"})
            self.assertEqual(selected.bind_host, "0.0.0.0")
            self.assertEqual(selected.db_host, "db")
            with self.assertRaisesRegex(RuntimeError, "private compose service"):
                boundary({"KAPIT_RUNTIME_CONTEXT": "compose-m1", "KAPIT_DB_HOST": "remote.example", "KAPIT_DB_PORT": "5432"})



class MigrationGuardTests(unittest.TestCase):
    """TASK-121: the retained database is never migrated past its heads without a fresh verified backup and human approval."""
    PLAN = "Planned operations:\nscopes.0004_m3_topology\n    Add field scope_epoch to unit\nreports.0009_m3_context\n    Raw SQL operation\n"

    def setUp(self):
        base = runtime.ROOT / ".cache/m1-runtime/runtime-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.folder = tempfile.TemporaryDirectory(dir=base)
        root = Path(self.folder.name)
        self.backups, self.approval = root / "backups", root / "approval.md"
        self.patches = [patch.object(runtime, "BACKUP_DIR", self.backups), patch.object(runtime, "MIGRATION_APPROVAL", self.approval),
                        patch.object(runtime, "OPERATOR_FILE", root / "operator-accounts.json"),
                        patch.object(runtime, "migration_tree_time", return_value=1000.0)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.folder.cleanup()

    RETAINED = "[X]  contenttypes.0001_initial\n[X]  scopes.0003_previous\n[ ]  scopes.0004_m3_topology\n"
    FRESH = "[ ]  scopes.0004_m3_topology\n[ ]  reports.0009_m3_context\n"

    def plan(self, text, applied=RETAINED):
        return lambda command, environment: applied if "showmigrations" in command else text

    def backup(self, created_epoch=2000.0, verified=True, tamper=False):
        self.backups.mkdir(parents=True, exist_ok=True)
        dump = self.backups / "kapit_m1-x.dump"
        dump.write_bytes(b"synthetic dump bytes")
        digest = runtime.hashlib.sha256(b"synthetic dump bytes").hexdigest()
        if tamper:
            dump.write_bytes(b"changed")
        (self.backups / "kapit_m1-x.json").write_text(json.dumps({"file": dump.name, "sha256": digest, "created_epoch": created_epoch,
                                                                  "verified": verified}), encoding="utf-8")

    def approve(self, *names):
        self.approval.write_text("# Approval\n\n" + "".join(f"- `{name}`\n" for name in names), encoding="utf-8")

    def test_no_pending_migrations_needs_nothing(self):
        self.assertEqual(runtime.require_migration_approval({}, self.plan("Planned operations:\n  No planned migration operations.\n")), [])

    def test_pending_without_backup_or_with_stale_or_tampered_backup_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD_BACKUP"):
            runtime.require_migration_approval({}, self.plan(self.PLAN))
        for kwargs in ({"created_epoch": 999.0}, {"verified": False}, {"tamper": True}):
            self.backup(**kwargs)
            self.approve("scopes.0004_m3_topology", "reports.0009_m3_context")
            with self.subTest(**kwargs), self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD_BACKUP"):
                runtime.require_migration_approval({}, self.plan(self.PLAN))

    def test_approval_must_list_exactly_the_pending_migrations(self):
        self.backup()
        with self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD_APPROVAL"):
            runtime.require_migration_approval({}, self.plan(self.PLAN))
        for names in (("scopes.0004_m3_topology",), ("scopes.0004_m3_topology", "reports.0009_m3_context", "review.0007_extra")):
            self.approve(*names)
            with self.subTest(names=names), self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD_APPROVAL"):
                runtime.require_migration_approval({}, self.plan(self.PLAN))
        self.approve("reports.0009_m3_context", "scopes.0004_m3_topology")
        self.assertEqual(runtime.require_migration_approval({}, self.plan(self.PLAN)), ["scopes.0004_m3_topology", "reports.0009_m3_context"])

    def test_fresh_database_with_nothing_applied_migrates_without_backup_or_approval(self):
        self.assertEqual(runtime.require_migration_approval({}, self.plan(self.PLAN, applied=self.FRESH)),
                         ["scopes.0004_m3_topology", "reports.0009_m3_context"])

    def test_any_applied_migration_keeps_the_retained_database_guard(self):
        for applied in (self.RETAINED, "[X]  contenttypes.0001_initial\n", " [ ]  a.0001_x\n [X]  b.0002_y\n"):
            with self.subTest(applied=applied), self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD_BACKUP"):
                runtime.require_migration_approval({}, self.plan(self.PLAN, applied=applied))

    def test_unreadable_applied_list_fails_closed(self):
        for applied in ("", "contenttypes\n (no migrations)\n", "[?]  a.0001_x\n", "[ ] a.b\n",
                        # An applied entry that does not parse must not let a retained database pass as fresh.
                        "[X]  thirdparty.custom_name\n" + self.FRESH):
            with self.subTest(applied=applied), self.assertRaisesRegex(RuntimeError, "applied-migration list could not be read"):
                runtime.require_migration_approval({}, self.plan(self.PLAN, applied=applied))

    def test_unapplied_list_must_equal_the_pending_plan(self):
        for applied in ("[ ]  scopes.0004_m3_topology\n", self.FRESH + "[ ]  review.0007_extra\n"):
            with self.subTest(applied=applied), self.assertRaisesRegex(RuntimeError, "differs from the pending plan"):
                runtime.require_migration_approval({}, self.plan(self.PLAN, applied=applied))

    def test_operator_accounts_are_generated_privately_once_and_validated(self):
        target = Path(self.folder.name) / "operator-accounts.json"
        with patch.object(runtime, "OPERATOR_FILE", target), patch.object(runtime, "checked_cache"):
            first = runtime.operator_accounts()
            self.assertEqual(runtime.operator_accounts(), first)
            self.assertNotEqual(first["admin"]["password"], first["operator"]["password"])
            for broken in ({"schema": 2}, {**first, "admin": {"username": "root", "password": first["admin"]["password"]}},
                           {**first, "operator": {"usernames": ["ops-submitter", "ops-recipient"], "password": "short"}}, []):
                target.write_text(json.dumps(broken), encoding="utf-8")
                with self.subTest(broken=str(broken)[:20]), self.assertRaisesRegex(RuntimeError, "OPERATOR_ACCOUNTS"):
                    runtime.operator_accounts()

    def test_unreadable_plan_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD"):
            runtime.require_migration_approval({}, self.plan("Planned operations:\nsomething unexpected\n"))

    def test_seed_paths_check_the_guard_before_migrating(self):
        for function, last in ((runtime.seed_native, "seed_event"), (runtime.seed_m3_native, "seed_m3_demo")):
            calls = []
            with patch.object(runtime, "managed_environment", return_value={}), patch.object(runtime, "native_module") as module, \
                    patch.object(runtime, "dependency_status", return_value={"modules": {"django": True}}):
                module.return_value.status.return_value = {}
                with self.subTest(function=function.__name__), self.assertRaisesRegex(RuntimeError, "MIGRATION_GUARD_BACKUP"):
                    function(command_runner=lambda command, environment: calls.append(command), capture_runner=self.plan(self.PLAN))
                self.assertEqual(calls, [], "nothing may run before the guard passes")
            self.backup()
            self.approve("scopes.0004_m3_topology", "reports.0009_m3_context")
            with patch.object(runtime, "managed_environment", return_value={}), patch.object(runtime, "native_module") as module, \
                    patch.object(runtime, "dependency_status", return_value={"modules": {"django": True}}):
                module.return_value.status.return_value = {}
                function(command_runner=lambda command, environment: calls.append(command), capture_runner=self.plan(self.PLAN))
            self.assertEqual([call[-2:] for call in calls][0], ["migrate", "--noinput"])
            self.assertEqual(calls[-1][-1], last)
            for path in self.backups.glob("*"):
                path.unlink()
            self.approval.unlink()

    def test_starter_never_runs_the_m3_seed(self):
        starter = (runtime.ROOT / "infra/start_local.py").read_text(encoding="utf-8")
        self.assertNotIn("seed_m3", starter)
        self.assertNotIn("seed-m3", starter)

    def test_redirected_backup_path_refuses_before_any_write_or_database_command(self):
        with patch.object(runtime, "native_module") as factory:
            module = factory.return_value
            module.checked_path.side_effect = RuntimeError("NATIVE_PATH")
            with self.assertRaisesRegex(RuntimeError, "NATIVE_PATH"):
                runtime.native_backup()
            self.assertFalse(self.backups.exists())
            module.execute.assert_not_called()
            module.ownership.assert_not_called()

    def test_redirected_backup_record_or_dump_is_not_trusted(self):
        self.backup()
        for rejected in (self.backups, self.backups / "kapit_m1-x.json", self.backups / "kapit_m1-x.dump"):
            with self.subTest(path=rejected), patch.object(runtime, "native_module") as factory:
                def check(path):
                    if path == rejected:
                        raise RuntimeError("NATIVE_PATH")
                    return path
                factory.return_value.checked_path.side_effect = check
                self.assertIsNone(runtime.latest_verified_backup())


if __name__ == "__main__":
    unittest.main()
