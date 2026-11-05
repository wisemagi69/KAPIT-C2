"""Dispatch/denial evidence only; these tests do not execute Django or a browser."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from infra import local


class BrowserNativeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "web/dist").mkdir(parents=True)
        (self.root / "web/dist/index.html").write_text("compiled synthetic fixture")
        self.native = Mock()
        self.dependencies = {"modules": dict.fromkeys(("django", "rest_framework", "psycopg", "cryptography"), True)}
        self.patches = [
            patch.object(local, "ROOT", self.root),
            patch.object(local, "native_module", return_value=self.native),
            patch.object(local, "dependency_status", return_value=self.dependencies),
            patch.object(local, "initialize"),
            patch.object(local, "run"),
            patch.dict(local.os.environ, {}, clear=True),
        ]
        self.started = [item.start() for item in self.patches]
        self.initialize = self.started[3]
        self.run = self.started[4]

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def test_explicit_command_uses_guarded_runner_without_database_adoption_options(self):
        with patch.object(local, "checked_cache"), patch.object(local.sys, "argv", ["infra/local.py", "browser-native"]):
            local.main()
        self.native.status.assert_called_once_with(require_running=True)
        self.initialize.assert_not_called()
        self.native.init.assert_not_called()
        self.run.assert_called_once()
        command = self.run.call_args.args[0]
        self.assertEqual(command[1:], [str(self.root / "backend/manage.py"), "test", "tests.browser_acceptance",
                                      "--settings=config.test_settings", "--testrunner=tests.browser_runner.BrowserAcceptanceRunner"])
        self.assertNotIn("--noinput", command)
        self.assertNotIn("--keepdb", command)

    def test_hosted_context_and_database_redirection_fail_before_cluster_or_dispatch(self):
        cases = [
            {"KAPIT_RUNTIME_CONTEXT": "supabase"},
            {"KAPIT_RUNTIME_CONTEXT": "container"},
            {"KAPIT_DB_HOST": "remote.example"},
            {"KAPIT_DB_HOST": "127.0.0.2"},
            {"KAPIT_DB_PORT": "5432"},
        ]
        for inherited in cases:
            with self.subTest(inherited=inherited), patch.dict(local.os.environ, inherited, clear=True):
                with self.assertRaises(RuntimeError):
                    local.native_browser()
        self.native.status.assert_not_called()
        self.run.assert_not_called()
        self.initialize.assert_not_called()

    def test_ordinary_native_suite_uses_same_collision_guard_after_read_only_checks(self):
        with patch.object(local, "checked_cache"), patch.object(local.sys, "argv", ["infra/local.py", "test-native"]):
            local.main()
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertEqual(commands[0][2:], ["check", "--settings=config.test_settings"])
        self.assertEqual(commands[1][2:], ["makemigrations", "--check", "--dry-run", "--settings=config.test_settings"])
        self.assertEqual(commands[2][2:], ["test", "tests", "--settings=config.test_settings",
                                          "--testrunner=tests.browser_runner.BrowserAcceptanceRunner"])
        self.assertNotIn("--noinput", commands[2])
        self.assertNotIn("--keepdb", commands[2])
        self.native.status.assert_called_once_with(require_running=True)
        self.initialize.assert_not_called()

    def test_child_context_strips_libpq_redirects_and_pins_native_host(self):
        inherited = {"PGHOST": "other", "PGSERVICE": "other", "PGDATABASE": "other", "PGOPTIONS": "other",
                     "DATABASE_URL": "postgresql://other.invalid/other", "DB_URL": "other", "DJANGO_SETTINGS_MODULE": "other.settings"}
        with patch.dict(local.os.environ, inherited):
            local.native_browser()
            environment = self.run.call_args.kwargs["environment"]
            self.assertEqual(environment["KAPIT_DB_HOST"], "127.0.0.1")
            self.assertEqual(environment["KAPIT_DB_PORT"], "55436")
            self.assertEqual(environment["KAPIT_RUNTIME_CONTEXT"], "native")
            self.assertEqual(environment["DJANGO_SETTINGS_MODULE"], "config.settings")
            for name in inherited:
                if name != "DJANGO_SETTINGS_MODULE":
                    self.assertNotIn(name, environment)
                self.assertEqual(local.os.environ[name], inherited[name])

    def test_unverified_cluster_aborts_before_dependency_check_or_database_creation(self):
        self.native.status.side_effect = RuntimeError("NATIVE_DATABASE: identity unavailable")
        with self.assertRaisesRegex(RuntimeError, "NATIVE_DATABASE"):
            local.native_browser()
        self.started[2].assert_not_called()
        self.run.assert_not_called()
        self.initialize.assert_not_called()

    def test_each_missing_python_dependency_aborts_without_installing(self):
        for name in self.dependencies["modules"]:
            self.dependencies["modules"][name] = False
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "PYTHON_PACKAGES_MISSING"):
                local.native_browser()
            self.dependencies["modules"][name] = True
        self.run.assert_not_called()
        self.initialize.assert_not_called()

    def test_missing_compiled_website_aborts_without_building_or_seeding(self):
        (self.root / "web/dist/index.html").unlink()
        with self.assertRaisesRegex(RuntimeError, "WEBSITE_BUILD_MISSING"):
            local.native_browser()
        self.run.assert_not_called()
        self.initialize.assert_not_called()

    def test_runner_failure_is_propagated_without_retry_or_fallback(self):
        self.run.side_effect = RuntimeError("Runtime command failed (exit 1).")
        with self.assertRaisesRegex(RuntimeError, "exit 1"):
            local.native_browser()
        self.run.assert_called_once()
        self.initialize.assert_not_called()

    def test_quiet_callbacks_receive_only_guarded_direct_management_commands(self):
        callback = Mock()
        local.native_test(command_runner=callback)
        local.native_browser(command_runner=callback)
        plans = []
        accounts = {"admin": {"password": "a" * 24}, "operator": {"password": "o" * 24}}
        with patch.object(local, "operator_accounts", return_value=accounts):
            local.seed_native(command_runner=callback, capture_runner=lambda command, environment: plans.append(command[2:]) or "No planned migration operations.")
        self.assertEqual(plans, [["migrate", "--plan"]])  # TASK-121 read-only guard plan, separate from executed commands
        commands = [call.args[0] for call in callback.call_args_list]
        self.assertEqual(len(commands), 6)
        self.assertTrue(all(command[:2] == [local.python_path(), str(self.root / "backend/manage.py")] for command in commands))
        self.assertEqual(commands[-2][2:], ["migrate", "--noinput"])
        self.assertEqual(commands[-1][2:], ["seed_event"])
        seed_environment = callback.call_args_list[-1].kwargs["environment"]
        self.assertEqual((seed_environment["KAPIT_EVENT_ADMIN_PASSWORD"], seed_environment["KAPIT_OPERATOR_PASSWORD"]), ("a" * 24, "o" * 24))
        self.assertNotIn("KAPIT_EVENT_ADMIN_PASSWORD", callback.call_args_list[-2].kwargs["environment"])
        self.assertTrue(all("a" * 24 not in part and "o" * 24 not in part for command in commands for part in command))
        self.assertTrue(all("flush" not in command for command in commands))
        self.run.assert_not_called()

    def test_callback_cannot_bypass_native_scope_validation(self):
        callback = Mock()
        with patch.dict(local.os.environ, {"KAPIT_RUNTIME_CONTEXT": "supabase-m1"}):
            for entry in (local.native_test, local.native_browser, local.seed_native):
                with self.subTest(entry=entry.__name__), self.assertRaises(RuntimeError):
                    entry(command_runner=callback)
        callback.assert_not_called()
        self.native.status.assert_not_called()


if __name__ == "__main__":
    unittest.main()
