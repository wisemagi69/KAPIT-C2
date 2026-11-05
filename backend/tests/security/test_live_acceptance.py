"""Independent lifecycle fault checks, using explicit Django/SQL test doubles.

These exercise reviewed runner code, never a real database or browser. The
DiscoverRunner/creation doubles model only the documented setup/teardown calls;
they do not establish framework, SQL, locking, or live acceptance behavior.
"""
import ast
import copy
import io
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import native_postgres

TARGET = {"ENGINE": "django.db.backends.postgresql", "NAME": "kapit_m1", "USER": "kapit_m1",
          "HOST": "127.0.0.1", "PORT": "55436", "TEST": {"NAME": "test_kapit_m1"},
          "OPTIONS": {"connect_timeout": 5}}
ENVIRONMENT = {"DJANGO_SETTINGS_MODULE": "config.test_settings", "KAPIT_RUNTIME_CONTEXT": "native"}


class Cursor:
    def __init__(self, database):
        self.database = database
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, query, params=()):
        self.database.queries.append((query, params))
        if getattr(self.database, "query_failure", False):
            raise RuntimeError("PRIVATE_DATABASE_EXCEPTION_CANARY")
        if "pg_try_advisory_lock" in query:
            self.row = (self.database.lock_available,)
        elif "pg_database" in query:
            self.row = (self.database.oid,) if self.database.oid is not None else None
        elif query.startswith("CREATE DATABASE"):
            if self.database.create_race:
                self.database.oid = 999
                raise RuntimeError("PRIVATE_SQL_CANARY")
            self.database.oid = 101
        else:
            raise AssertionError("Unexpected SQL in lifecycle double")

    def fetchone(self):
        return self.row


class Creation:
    def __init__(self, connection):
        self.connection = connection

    def _get_test_db_name(self):
        return self.connection.settings_dict["TEST"]["NAME"]

    def _create_test_db(self, *args, **kwargs):
        raise AssertionError("Default destructive retry path must never be called")

    def destroy_test_db(self, old_database_name=None, verbosity=0, keepdb=False, suffix=None):
        # Django 5.2 selects the destruction target from the CURRENT NAME.
        current = self.connection.settings_dict["NAME"]
        self.connection.close()
        if not keepdb:
            self._destroy_test_db(current, verbosity)
        if old_database_name is not None:
            self.connection.settings_dict["NAME"] = old_database_name

    def _destroy_test_db(self, name, verbosity):
        self.connection.database.drops.append(name)
        self.connection.database.oid = None


class Connection:
    def __init__(self, database, config=None):
        self.database = database
        self.settings_dict = copy.deepcopy(config or TARGET)
        self.creation = Creation(self)
        self.closed = False

    def copy(self, alias):
        result = Connection(self.database, self.settings_dict)
        self.database.maintenance = result
        return result

    def ensure_connection(self):
        pass

    def set_autocommit(self, value):
        pass

    def cursor(self):
        return Cursor(self.database)

    def close(self):
        self.closed = True


class DiscoverRunnerDouble:
    def __init__(self, *args, **kwargs):
        pass

    def setup_databases(self, **kwargs):
        connection = self.review_connection
        name = connection.creation._create_test_db(verbosity=0, autoclobber=False, keepdb=False)
        if self.failure == "before_name_switch":
            raise RuntimeError("PRIVATE_SETUP_CANARY")
        connection.settings_dict["NAME"] = name
        if self.failure == "migration":
            raise RuntimeError("PRIVATE_MIGRATION_CANARY")
        return [(connection, "kapit_m1", True)]

    def teardown_databases(self, old_config, **kwargs):
        for connection, old_name, destroy in old_config:
            if destroy:
                connection.creation.destroy_test_db(old_name, verbosity=0, keepdb=False)


def runner_namespace():
    path = ROOT / "backend/tests/browser_runner.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    tree.body = [node for node in tree.body
                 if not isinstance(node, ast.ImportFrom) or node.module != "django.test.runner"]
    scope = {"__file__": str(path), "DiscoverRunner": DiscoverRunnerDouble}
    exec(compile(tree, str(path), "exec"), scope)
    return scope


class IndependentLiveAcceptanceChecks(unittest.TestCase):
    def setUp(self):
        self.scope = runner_namespace()
        self.database = SimpleNamespace(oid=None, lock_available=True, create_race=False,
                                        drops=[], queries=[], maintenance=None)
        self.connection = Connection(self.database)
        database_module = ModuleType("django.db")
        database_module.connections = {"default": self.connection}
        self.patches = [patch.dict(sys.modules, {"django.db": database_module}),
                        patch.dict(os.environ, ENVIRONMENT, clear=True),
                        patch.object(native_postgres, "status", return_value={"state": "running"})]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.runner = self.scope["BrowserAcceptanceRunner"]()
        self.runner.review_connection = self.connection
        self.runner.failure = None
        self.error = self.scope["BrowserGuardError"]

    def test_hosted_context_and_each_database_dimension_are_denied_without_sql(self):
        for key, value in (("ENGINE", "config.supabase_backend"), ("NAME", "postgres"),
                           ("HOST", "127.0.0.2"), ("PORT", "5432"), ("USER", "postgres"),
                           ("TEST", {"NAME": "unrelated"}), ("OPTIONS", {"options": "-c search_path=other"})):
            with self.subTest(key=key), self.assertRaises(self.error):
                self.scope["require_target"]({**TARGET, key: value}, ENVIRONMENT)
        for environment in ({**ENVIRONMENT, "KAPIT_RUNTIME_CONTEXT": "supabase-m1"},
                            {**ENVIRONMENT, "PGSERVICE": "external"},
                            {**ENVIRONMENT, "DJANGO_SETTINGS_MODULE": "config.settings"}):
            with self.assertRaises(self.error):
                self.scope["require_target"](TARGET, environment)
        self.assertEqual(self.database.queries, [])

    def test_busy_or_preexisting_database_never_calls_create_or_destroy(self):
        for locked, oid, code in ((False, None, "BUSY"), (True, 90, "EXISTS")):
            self.database.lock_available, self.database.oid = locked, oid
            with self.subTest(code=code), self.assertRaisesRegex(self.error, code):
                self.runner.setup_databases()
            self.assertTrue(self.database.maintenance.closed)
            self.assertFalse(any(query.startswith("CREATE") for query, _ in self.database.queries))
            self.assertEqual(self.database.drops, [])

    def test_creation_race_never_adopts_or_drops_winning_database(self):
        self.database.create_race = True
        with self.assertRaises(self.error) as result:
            self.runner.setup_databases()
        self.assertEqual(self.database.oid, 999)
        self.assertEqual(self.database.drops, [])
        self.assertTrue(self.database.maintenance.closed)
        self.assertNotIn("CANARY", str(result.exception))

    def test_setup_failure_before_name_switch_cannot_destroy_base_database(self):
        self.runner.failure = "before_name_switch"
        with self.assertRaises(self.error):
            self.runner.setup_databases()
        self.assertNotIn("kapit_m1", self.database.drops)
        self.assertTrue(all(name == "test_kapit_m1" for name in self.database.drops))
        self.assertTrue(self.database.maintenance.closed)

    def test_migration_failure_only_destroys_owned_test_database_and_releases_lock(self):
        self.runner.failure = "migration"
        with self.assertRaises(self.error) as result:
            self.runner.setup_databases()
        self.assertEqual(self.database.drops, ["test_kapit_m1"])
        self.assertTrue(self.database.maintenance.closed)
        self.assertNotIn("CANARY", str(result.exception))

    def test_replaced_database_is_preserved_at_teardown(self):
        old_config = self.runner.setup_databases()
        self.database.oid = 707
        with self.assertRaises(self.error):
            self.runner.teardown_databases(old_config)
        self.assertEqual(self.database.drops, [])
        self.assertEqual(self.database.oid, 707)
        self.assertTrue(self.database.maintenance.closed)

    def test_changed_current_name_cannot_redirect_teardown_drop(self):
        old_config = self.runner.setup_databases()
        self.connection.settings_dict["NAME"] = "unrelated_database"
        with self.assertRaises(self.error):
            self.runner.teardown_databases(old_config)
        self.assertEqual(self.database.drops, [])
        self.assertTrue(self.database.maintenance.closed)

    def test_normal_cleanup_drops_only_created_database_and_keeps_base(self):
        old_config = self.runner.setup_databases()
        self.assertEqual(self.database.maintenance.settings_dict["NAME"], "postgres")
        self.runner.teardown_databases(old_config)
        self.assertEqual(self.database.drops, ["test_kapit_m1"])
        self.assertEqual(self.connection.settings_dict["NAME"], "kapit_m1")
        self.assertTrue(self.database.maintenance.closed)

    def test_living_worker_preservation_flag_prevents_any_database_destruction(self):
        old_config = self.runner.setup_databases()
        self.scope["preserve_database"]()
        with self.assertRaises(self.error):
            self.runner.teardown_databases(old_config)
        self.assertEqual(self.database.drops, [])
        self.assertEqual(self.database.oid, 101)
        self.assertTrue(self.database.maintenance.closed)

    def test_unknown_database_failure_is_sanitized_and_does_not_drop(self):
        old_config = self.runner.setup_databases()
        self.database.query_failure = True
        with self.assertRaises(self.error) as result:
            self.runner.teardown_databases(old_config)
        self.assertNotIn("CANARY", str(result.exception))
        self.assertEqual(self.database.drops, [])
        self.assertTrue(self.database.maintenance.closed)


class IndependentBrowserOutputChecks(unittest.TestCase):
    def setUp(self):
        path = ROOT / "backend/tests/browser_acceptance.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {"GATES", "STAGES", "BoundedReader", "browser_result", "require_actual_database"}
        tree.body = [node for node in tree.body if
                     isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names or
                     isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id in names for target in node.targets)]
        self.error = runner_namespace()["BrowserGuardError"]
        self.scope = {"json": json, "BrowserGuardError": self.error}
        exec(compile(tree, str(path), "exec"), self.scope)

    def test_connected_database_name_and_oid_must_match_before_test_writes(self):
        package = ModuleType("tests")
        package.browser_runner = SimpleNamespace(ACTIVE_DATABASE_LEASE=SimpleNamespace(locked=True, owned_oid=101))
        self.scope["connection"] = MagicMock()
        cursor = self.scope["connection"].cursor.return_value.__enter__.return_value
        with patch.dict(sys.modules, {"tests": package}):
            for identity in (("kapit_m1", 101), ("test_kapit_m1", 202), None):
                cursor.fetchone.return_value = identity
                with self.subTest(identity=identity), self.assertRaisesRegex(self.error, "ACTUAL_DATABASE_DENIED"):
                    self.scope["require_actual_database"]()
            cursor.fetchone.return_value = ("test_kapit_m1", 101)
            self.scope["require_actual_database"]()

    def test_oversized_output_is_bounded_and_stderr_is_never_retained(self):
        reader = self.scope["BoundedReader"](io.BytesIO(b"X" * 8000), limit=32)
        reader.read()
        self.assertTrue(reader.overflow)
        self.assertEqual(len(reader.data), 32)
        discarded = self.scope["BoundedReader"](io.BytesIO(b"PRIVATE_STDERR_CANARY"), retain=False)
        discarded.read()
        self.assertEqual(discarded.data, bytearray())

    def test_malformed_or_private_failure_output_never_becomes_error_text(self):
        for payload in (b"PRIVATE_RESPONSE_CANARY", b'{"ok":false,"stage":"PRIVATE_STAGE_CANARY"}',
                        b'{"ok":true,"stage":"COMPLETE","detail":"PRIVATE_DETAIL_CANARY"}'):
            with self.subTest(payload_kind=payload[:1]), self.assertRaises(self.error) as result:
                self.scope["browser_result"](payload, 0)
            self.assertNotIn("CANARY", str(result.exception))
        with self.assertRaisesRegex(self.error, "OUTPUT_INVALID"):
            self.scope["browser_result"](b'{"ok":false,"stage":"PASSWORD","detail":"PRIVATE_CANARY"}', 1)
        with self.assertRaisesRegex(self.error, "FAILED_PASSWORD"):
            self.scope["browser_result"](b'{"ok":false,"stage":"PASSWORD"}', 1)


if __name__ == "__main__":
    unittest.main()
