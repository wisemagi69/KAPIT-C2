"""Dependency-free counterfactuals, not evidence of a live Django journey."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent
CONFIG = {"ENGINE": "django.db.backends.postgresql", "NAME": "kapit_m1", "USER": "kapit_m1", "HOST": "127.0.0.1", "PORT": "55436", "TEST": {"NAME": "test_kapit_m1"}, "OPTIONS": {"connect_timeout": 5}}
ENV = {"DJANGO_SETTINGS_MODULE": "config.test_settings", "KAPIT_RUNTIME_CONTEXT": "native"}


def module(name, **values):
    result = types.ModuleType(name)
    result.__dict__.update(values)
    return result


def load(path, name, modules):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    result = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(result)
    return result


class Cursor:
    def __init__(self, state): self.state, self.row = state, None
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def execute(self, sql, params=None):
        self.state["sql"].append(sql)
        if "pg_try_advisory_lock" in sql: self.row = [self.state["lock"]]
        elif "SELECT oid" in sql: self.row = [self.state["oid"]] if self.state["oid"] is not None else None
        elif sql.startswith("CREATE DATABASE"):
            if self.state["oid"] is not None: raise RuntimeError("duplicate")
            self.state["oid"] = 42
        else: raise AssertionError("Unexpected SQL in stand-in")
    def fetchone(self): return self.row


class Connection:
    def __init__(self, state=None):
        self.state = state if state is not None else {"sql": [], "oid": None, "lock": True, "closed": 0, "drops": []}
        self.settings_dict = copy.deepcopy(CONFIG)
        self.creation = Creation(self)
    def ensure_connection(self): pass
    def set_autocommit(self, value): assert value is True
    def cursor(self): return Cursor(self.state)
    def close(self): self.state["closed"] += 1
    def copy(self, alias): return Connection(self.state)


class Creation:
    def __init__(self, connection): self.connection = connection
    def _get_test_db_name(self): return "test_kapit_m1"
    def _create_test_db(self, verbosity, autoclobber, keepdb=False): raise AssertionError("Unsafe default create path called")
    def _destroy_test_db(self, name, verbosity):
        self.connection.state["drops"].append(name)
        self.connection.state["oid"] = None
    def destroy_test_db(self, old_name, verbosity, keepdb):
        self._destroy_test_db(self.connection.settings_dict["NAME"], verbosity)
        self.connection.settings_dict["NAME"] = old_name


class FakeDiscoverRunner:
    connection = None
    fail_before_switch = False
    fail_after_switch = False
    def __init__(self, *args, **kwargs): pass
    def run_tests(self, labels, **kwargs): return list(labels)
    def setup_databases(self, **kwargs):
        self.connection.creation._create_test_db(0, False, False)
        if self.fail_before_switch: raise RuntimeError("failure before NAME update")
        self.connection.settings_dict["NAME"] = "test_kapit_m1"
        if self.fail_after_switch: raise RuntimeError("failure after NAME update")
        return [(self.connection, "kapit_m1", True)]
    def teardown_databases(self, old_config, **kwargs):
        self.connection.creation.destroy_test_db("kapit_m1", verbosity=0, keepdb=False)


def runner_module():
    return load("browser_runner.py", "isolated_browser_runner", {"django.test.runner": module("django.test.runner", DiscoverRunner=FakeDiscoverRunner)})


class BrowserGuardTests(unittest.TestCase):
    def setUp(self): self.target = runner_module()

    def test_exact_native_base_and_actual_test_target(self):
        self.target.require_target(CONFIG, ENV)
        actual = copy.deepcopy(CONFIG); actual["NAME"] = "test_kapit_m1"
        self.target.require_target(actual, ENV, running_test=True)
        with self.assertRaises(self.target.BrowserGuardError): self.target.require_target(CONFIG, ENV, running_test=True)

    def test_hosted_and_database_redirects_rejected(self):
        for key, value in [("ENGINE", "config.supabase_backend"), ("NAME", "postgres"), ("HOST", "localhost"), ("PORT", "5432"), ("USER", "postgres"), ("OPTIONS", {"options": "-c search_path=public"}), ("TEST", {"NAME": "test_other"})]:
            with self.subTest(key=key), self.assertRaises(self.target.BrowserGuardError): self.target.require_target({**CONFIG, key: value}, ENV)
        for key, value in [("KAPIT_RUNTIME_CONTEXT", "supabase-m1"), ("DJANGO_SETTINGS_MODULE", "config.settings"), ("PGHOST", "remote"), ("DATABASE_URL", "remote")]:
            with self.subTest(key=key), self.assertRaises(self.target.BrowserGuardError): self.target.require_target(CONFIG, {**ENV, key: value})

    def test_preexisting_database_rejected_without_creation_or_deletion(self):
        connection = Connection(); connection.state["oid"] = 91
        with self.assertRaisesRegex(self.target.BrowserGuardError, "EXISTS"): self.target.DatabaseLease(connection).acquire()
        self.assertFalse(any(sql.startswith("CREATE") for sql in connection.state["sql"]))
        self.assertEqual(connection.state["oid"], 91); self.assertEqual(connection.state["drops"], [])

    def test_lock_contention_fails_before_database_check(self):
        connection = Connection(); connection.state["lock"] = False
        with self.assertRaisesRegex(self.target.BrowserGuardError, "BUSY"): self.target.DatabaseLease(connection).acquire()
        self.assertEqual(len(connection.state["sql"]), 1); self.assertEqual(connection.state["closed"], 1)

    def test_creation_race_cannot_adopt_or_drop_winners_database(self):
        connection = Connection(); lease = self.target.DatabaseLease(connection); lease.acquire()
        connection.state["oid"] = 91
        with self.assertRaisesRegex(self.target.BrowserGuardError, "CREATE_FAILED"): lease.create()
        self.assertIsNone(lease.owned_oid); self.assertEqual(connection.state["oid"], 91)
        self.assertEqual(connection.state["drops"], [])

    def test_replaced_database_invalidates_teardown_ownership(self):
        connection = Connection(); lease = self.target.DatabaseLease(connection); lease.acquire(); lease.create()
        lease.assert_owned(); connection.state["oid"] = 91
        with self.assertRaisesRegex(self.target.BrowserGuardError, "OWNERSHIP"): lease.assert_owned()

    def test_unsafe_runner_options_and_arbitrary_labels_rejected(self):
        for options in [{"keepdb": True}, {"parallel": 2}, {"interactive": False}]:
            with self.assertRaises(self.target.BrowserGuardError): self.target.BrowserAcceptanceRunner(**options)
        runner = self.target.BrowserAcceptanceRunner()
        self.assertEqual(runner.run_tests(["tests"]), ["tests"])
        self.assertEqual(runner.run_tests(["tests.browser_acceptance"]), ["tests.browser_acceptance"])
        with self.assertRaises(self.target.BrowserGuardError): runner.run_tests(["other.tests"])

    def exercise_setup(self, before=False, after=False):
        connection = Connection(); runner = self.target.BrowserAcceptanceRunner()
        runner.connection, runner.fail_before_switch, runner.fail_after_switch = connection, before, after
        modules = {"django.db": module("django.db", connections={"default": connection}), "infra.native_postgres": module("infra.native_postgres", status=lambda **kwargs: None)}
        return connection, runner, patch.dict(sys.modules, modules)

    def test_success_uses_django_lifecycle_and_only_drops_owned_test_database(self):
        connection, runner, imports = self.exercise_setup()
        with imports, patch.dict(os_environ(), ENV, clear=True):
            configuration = runner.setup_databases(); runner.teardown_databases(configuration)
        self.assertEqual(connection.state["drops"], ["test_kapit_m1"])
        self.assertIsNone(self.target.ACTIVE_DATABASE_LEASE)

    def test_failure_before_name_switch_never_drops_base_database(self):
        connection, runner, imports = self.exercise_setup(before=True)
        with imports, patch.dict(os_environ(), ENV, clear=True), self.assertRaises(self.target.BrowserGuardError): runner.setup_databases()
        self.assertEqual(connection.settings_dict["NAME"], "kapit_m1")
        self.assertEqual(connection.state["drops"], [])
        self.assertEqual(connection.state["oid"], 42)  # retained for explicit review

    def test_migration_failure_cleans_only_successfully_created_database(self):
        connection, runner, imports = self.exercise_setup(after=True)
        with imports, patch.dict(os_environ(), ENV, clear=True), self.assertRaises(self.target.BrowserGuardError): runner.setup_databases()
        self.assertEqual(connection.state["drops"], ["test_kapit_m1"])

    def test_worker_still_alive_prevents_database_drop(self):
        connection, runner, imports = self.exercise_setup()
        with imports, patch.dict(os_environ(), ENV, clear=True):
            configuration = runner.setup_databases(); self.target.preserve_database()
            with self.assertRaisesRegex(self.target.BrowserGuardError, "RETAINED"): runner.teardown_databases(configuration)
        self.assertEqual(connection.state["drops"], []); self.assertEqual(connection.state["oid"], 42)

    def test_unknown_teardown_failure_is_sanitized(self):
        connection, runner, imports = self.exercise_setup()
        with imports, patch.dict(os_environ(), ENV, clear=True):
            configuration = runner.setup_databases()
            with patch.object(runner._browser_lease.connection, "cursor", side_effect=RuntimeError("PRIVATE_DATABASE_ERROR")):
                with self.assertRaises(self.target.BrowserGuardError) as failure: runner.teardown_databases(configuration)
        self.assertNotIn("PRIVATE", str(failure.exception)); self.assertEqual(connection.state["drops"], [])


def os_environ():
    import os
    return os.environ


class BrowserOutputTests(unittest.TestCase):
    def setUp(self):
        runner = runner_module()
        self.target = load("browser_acceptance.py", "isolated_browser_acceptance", {
            "django.core.management": module("django.core.management", call_command=lambda *args, **kwargs: None),
            "django.db": module("django.db", connection=None, connections=None),
            "django.test": module("django.test", LiveServerTestCase=object),
            "tests.browser_runner": runner,
        })

    def test_output_capture_is_bounded_and_stderr_is_not_retained(self):
        output = self.target.BoundedReader(io.BytesIO(b"sensitive" * 2000), limit=16); output.read()
        self.assertTrue(output.overflow); self.assertEqual(len(output.data), 16)
        errors = self.target.BoundedReader(io.BytesIO(b"sensitive"), retain=False); errors.read()
        self.assertEqual(errors.data, b"")

    def test_validated_result_requires_every_real_gate_and_counts(self):
        result = {"ok": True, "stage": "COMPLETE", "gates": self.target.GATES, "scanned_responses": 8}
        self.assertEqual(self.target.browser_result(json.dumps(result), 0), result)
        legacy_gates = ["real_login", "private_submission", "real_worker", "exact_review", "approved_projection", "private_denial", "client_reconnect", "password_sessions", "recipient_revocation"]
        for changed in [
            {**result, "gates": []},
            {**result, "gates": legacy_gates},
            {**result, "gates": [gate for gate in self.target.GATES if gate != "return_correction"]},
            {**result, "gates": self.target.GATES + [self.target.GATES[0]]},
            {**result, "gates": list(reversed(self.target.GATES))},
            {**result, "password": "must not echo"},
            {**result, "scanned_responses": True},
        ]:
            with self.assertRaisesRegex(RuntimeError, "OUTPUT_INVALID"): self.target.browser_result(json.dumps(changed), 0)

    def test_error_payload_cannot_be_reflected_into_failure(self):
        for payload in [b"private narrative", b'{"ok":false,"stage":"private secret"}', b'{"ok":false,"stage":"PASSWORD","private":"secret"}']:
            with self.assertRaises(RuntimeError) as raised: self.target.browser_result(payload, 1)
            self.assertNotIn("private", str(raised.exception)); self.assertNotIn("secret", str(raised.exception))

    def test_broken_output_stream_never_raises_a_reader_thread_exception(self):
        stream = types.SimpleNamespace(read=lambda size: (_ for _ in ()).throw(RuntimeError("private")), close=lambda: None)
        reader = self.target.BoundedReader(stream); reader.read()
        self.assertTrue(reader.failed); self.assertEqual(reader.data, b"")

    def test_actual_database_guard_checks_live_database_name_and_oid(self):
        runner = runner_module(); runner.ACTIVE_DATABASE_LEASE = types.SimpleNamespace(locked=True, owned_oid=42)
        fake_connection = types.SimpleNamespace(cursor=lambda: None)
        for row, denied in [(('test_kapit_m1', 42), False), (('kapit_m1', 42), True), (('test_kapit_m1', 99), True)]:
            class IdentityCursor:
                def __enter__(self): return self
                def __exit__(self, *args): return False
                def execute(self, sql): self.sql = sql
                def fetchone(self): return row
            fake_connection.cursor = IdentityCursor
            with patch.object(self.target, "connection", fake_connection), patch.dict(sys.modules, {"tests": module("tests", browser_runner=runner), "tests.browser_runner": runner}):
                if denied:
                    with self.assertRaises(RuntimeError): self.target.require_actual_database()
                else:
                    self.target.require_actual_database()

    def test_windows_job_close_failure_retains_handle_and_blocks_database_cleanup(self):
        ownership = self.target.ChildOwnership.__new__(self.target.ChildOwnership)
        ownership.job = 7
        ownership.api = types.SimpleNamespace(CloseHandle=lambda handle: False)
        with patch.object(self.target, "preserve_database") as preserve:
            with self.assertRaisesRegex(RuntimeError, "OWNERSHIP_CLEANUP_FAILED"): ownership.close(None)
        preserve.assert_called_once(); self.assertEqual(ownership.job, 7)

    def test_unexpected_process_ownership_setup_error_is_sanitized(self):
        with patch.object(self.target.shutil, "which", return_value="node"), patch.object(self.target.Path, "is_file", return_value=True), patch.object(self.target, "ChildOwnership", side_effect=RuntimeError("private failure")):
            with self.assertRaisesRegex(RuntimeError, "OWNERSHIP_UNAVAILABLE") as failure: self.target.run_browser("http://127.0.0.1:43210", "synthetic")
        self.assertNotIn("private", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
