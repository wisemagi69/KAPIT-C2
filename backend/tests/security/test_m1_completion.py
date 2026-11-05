"""Independent restart-boundary faults, using explicit lifecycle doubles.

These tests never connect to PostgreSQL, launch applications or approve reports.
They exercise the real restart/lease/teardown functions against changed identity,
lost serialization and confidential exceptions; live persistence is separate.
"""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.tests.security.test_live_acceptance import (
    Connection, ENVIRONMENT, runner_namespace,
)
from infra import native_postgres, restart_acceptance


class IndependentRestartBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.scope = runner_namespace()
        self.database = SimpleNamespace(oid=None, lock_available=True, create_race=False,
                                        drops=[], queries=[], maintenance=None)
        self.connection = Connection(self.database)
        database_module = ModuleType("django.db")
        database_module.connections = {"default": self.connection}
        runner_module = ModuleType("tests.browser_runner")
        runner_module.ADVISORY_LOCK = self.scope["ADVISORY_LOCK"]
        self.patches = [patch.dict(sys.modules, {"django.db": database_module,
                                                "tests.browser_runner": runner_module}),
                        patch.dict(os.environ, ENVIRONMENT, clear=True),
                        patch.object(native_postgres, "status", return_value={"state": "running"})]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.runner = self.scope["BrowserAcceptanceRunner"]()
        self.runner.review_connection = self.connection
        self.runner.failure = None
        self.error = self.scope["BrowserGuardError"]

    def restart_boundary(self):
        config = self.runner.setup_databases()
        lease = self.runner._browser_lease
        lease.close()
        return config, lease

    def test_replaced_database_after_restart_cannot_be_destroyed_or_adopted(self):
        config, lease = self.restart_boundary()
        original_oid = lease.owned_oid
        self.database.oid += 1
        with self.assertRaisesRegex(self.error, "BROWSER_DATABASE_OWNERSHIP"):
            restart_acceptance.reconnect_lease(lease, self.scope["ADVISORY_LOCK"])
        with self.assertRaisesRegex(self.error, "BROWSER_DATABASE_OWNERSHIP"):
            self.runner.teardown_databases(config)
        self.assertEqual(lease.owned_oid, original_oid)
        self.assertEqual(self.database.drops, [])

    def test_lost_restart_lock_cannot_drop_even_the_original_database(self):
        config, lease = self.restart_boundary()
        self.database.lock_available = False
        with self.assertRaises(restart_acceptance.AcceptanceError):
            restart_acceptance.reconnect_lease(lease, self.scope["ADVISORY_LOCK"])
        with self.assertRaisesRegex(self.error, "BROWSER_DATABASE_OWNERSHIP"):
            self.runner.teardown_databases(config)
        self.assertFalse(lease.locked)
        self.assertEqual(self.database.drops, [])

    def test_reconnected_identical_owned_database_uses_guarded_teardown_once(self):
        config, lease = self.restart_boundary()
        restart_acceptance.reconnect_lease(lease, self.scope["ADVISORY_LOCK"])
        self.runner.teardown_databases(config)
        self.assertEqual(self.database.drops, ["test_kapit_m1"])
        self.assertIsNone(self.database.oid)
        self.assertFalse(lease.locked)

    def test_unconfirmed_child_cleanup_preservation_blocks_owned_teardown(self):
        config, lease = self.restart_boundary()
        restart_acceptance.reconnect_lease(lease, self.scope["ADVISORY_LOCK"])
        self.scope["preserve_database"]()
        with self.assertRaisesRegex(self.error, "BROWSER_CLEANUP_UNSAFE_DATABASE_RETAINED"):
            self.runner.teardown_databases(config)
        self.assertEqual(self.database.drops, [])
        self.assertFalse(lease.locked)


class IndependentRestartInputAndOutputTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows suspended-process boundary")
    def test_child_job_attachment_failure_cannot_resume_or_receive_fixture_input(self):
        owner, process = Mock(), Mock()
        owner.attach.side_effect = RuntimeError("PRIVATE_ATTACH_FAILURE")
        module = ModuleType("tests.browser_acceptance")
        module.ChildOwnership = Mock(return_value=owner)
        with patch.dict(sys.modules, {"tests.browser_acceptance": module}), \
                patch.object(restart_acceptance.subprocess, "Popen", return_value=process) as spawn, \
                patch.object(restart_acceptance, "resume_owned_process") as resume:
            with self.assertRaises(RuntimeError):
                restart_acceptance.ApplicationChild("server", 123)
        self.assertTrue(spawn.call_args.kwargs["creationflags"] & 0x4)
        resume.assert_not_called()
        process.stdin.write.assert_not_called()
        owner.close.assert_called_once_with(process)
        process.wait.assert_called_once_with(timeout=5)

    def test_listener_ownership_loss_after_http_prevents_accepting_the_response(self):
        client = restart_acceptance.Client()
        response = MagicMock(status=200)
        response.__enter__.return_value = response
        response.read.return_value = b'{"source":"PRIVATE_RESPONSE_CANARY"}'
        client.opener = Mock()
        client.opener.open.return_value = response
        with patch.object(restart_acceptance, "URL", "http://127.0.0.1:18080"), \
                patch.object(restart_acceptance, "server_owned", side_effect=[True, False]):
            with self.assertRaises(restart_acceptance.AcceptanceError):
                client.request("/api/v1/auth/csrf/")
        client.opener.open.assert_called_once()

    def test_invalid_child_identity_stops_before_settings_or_database_loading(self):
        cases = [{"oid": True, "port": 18080}, {"oid": 0, "port": 18080},
                 {"oid": 123, "port": 80}, {"oid": 123, "port": True},
                 {"oid": 123, "port": 18080, "database": "kapit_m1"}]
        for value in cases:
            with self.subTest(case=value), patch.object(restart_acceptance.sys, "stdin",
                    SimpleNamespace(buffer=io.BytesIO(json.dumps(value).encode("ascii")))), \
                    patch.object(restart_acceptance, "setup") as setup:
                with self.assertRaises(restart_acceptance.AcceptanceError):
                    restart_acceptance.child("server")
                setup.assert_not_called()

    def test_failed_restart_reports_only_fixed_metadata_without_exception_text(self):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["restart_acceptance.py"]), \
                patch.object(restart_acceptance, "run", side_effect=RuntimeError("PRIVATE_EXCEPTION_CANARY")), \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(restart_acceptance.main(), 1)
        value = json.loads(out.getvalue())
        self.assertEqual(set(value), {"ok", "code", "harness_line"})
        self.assertFalse(value["ok"])
        self.assertEqual(value["code"], "RESTART_ACCEPTANCE_FAILED")
        self.assertNotIn("CANARY", out.getvalue())
        self.assertEqual(err.getvalue(), "")

    def test_cross_origin_and_non_api_requests_are_rejected_before_network(self):
        client = restart_acceptance.Client()
        client.opener = Mock()
        for path in ("https://example.invalid/api/v1/", "//example.invalid/api/v1/",
                     "/workspace", "/api/v1/auth/csrf/?redirect=foreign"):
            with self.subTest(path=path), self.assertRaises(restart_acceptance.AcceptanceError):
                client.request(path)
        client.opener.open.assert_not_called()


if __name__ == "__main__":
    unittest.main()
