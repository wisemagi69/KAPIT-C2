"""Fast fault/ownership guards; no Django setup, database, phone or child launch."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from infra import mobile_integration as mobile


class FaultTests(unittest.TestCase):
    def invoke(self, mode, *, path=mobile.SOURCE_PATH, method="POST", status="201 Created"):
        state = mobile.FaultState()
        state.set(mode)
        events, headers = [], []
        def app(environ, start):
            events.append("commit")
            start(status, [("Content-Type", "application/json")])
            return [b'{"shared":false}']
        def start(code, values, exc_info=None):
            headers.append((code, dict(values)))
        environ = {"PATH_INFO": path, "REQUEST_METHOD": method,
                   "kapit.owned_disconnect": lambda: events.append("disconnect")}
        result = b"".join(mobile.FaultApplication(app, state)(environ, start))
        return events, headers, result, state

    def test_throttle_is_before_transaction_and_has_retry_after(self):
        events, headers, body, _ = self.invoke("throttle")
        self.assertEqual(events, [])
        self.assertEqual(headers[0][0], "429 Too Many Requests")
        self.assertEqual(headers[0][1]["Retry-After"], "2")
        self.assertEqual(json.loads(body)["code"], "THROTTLED")

    def test_unavailable_is_before_transaction(self):
        events, headers, _, _ = self.invoke("unavailable")
        self.assertEqual(events, [])
        self.assertEqual(headers[0][0], "503 Service Unavailable")

    def test_offline_disconnects_without_dispatch(self):
        events, _, _, _ = self.invoke("offline")
        self.assertEqual(events, ["disconnect"])

    def test_ack_loss_is_after_real_application_return_and_one_shot(self):
        events, _, _, state = self.invoke("drop_after_commit")
        self.assertEqual(events, ["commit", "disconnect"])
        self.assertEqual(state.get(), {"mode": "normal", "generation": 2})

    def test_ack_loss_refuses_to_call_denial_committed(self):
        with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_FAULT_NOT_COMMITTED"):
            self.invoke("drop_after_commit", status="401 Unauthorized")

    def test_fault_never_intercepts_auth_or_web_or_receipt(self):
        for path, method in [("/api/v1/mobile/auth/refresh/", "POST"),
                ("/api/v1/sync/operations/", "POST"), (mobile.SOURCE_PATH, "GET")]:
            with self.subTest(path=path, method=method):
                events, _, _, state = self.invoke("drop_after_commit", path=path, method=method)
                self.assertEqual(events, ["commit"])
                self.assertEqual(state.get()["mode"], "drop_after_commit")

    def test_http_state_is_read_only_and_contains_only_metadata(self):
        events, _, body, state = self.invoke("normal", path=mobile.STATE_PATH, method="GET")
        self.assertEqual(events, [])
        self.assertEqual(json.loads(body), {"mode": "normal", "generation": 1})
        with self.assertRaises(mobile.IntegrationError):
            state.set("publish")

    def test_fault_response_size_is_bounded_and_iterator_closed(self):
        state = mobile.FaultState()
        state.set("drop_after_commit")
        response = Mock()
        response.__iter__ = Mock(return_value=iter([b"x" * 20481]))
        def app(environ, start):
            start("201 Created", [])
            return response
        with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_FAULT_RESPONSE"):
            mobile.FaultApplication(app, state)({"PATH_INFO": mobile.SOURCE_PATH,
                "REQUEST_METHOD": "POST"}, Mock())
        response.close.assert_called_once()


class OwnershipTests(unittest.TestCase):
    def test_fresh_keys_are_distinct_and_strictly_encoded(self):
        first, second = mobile.fresh_secrets(), mobile.fresh_secrets()
        self.assertEqual(mobile.validate_secrets(first), first)
        self.assertNotEqual(first, second)
        for mutation in [{**first, "mobile": first["source"]}, {**first, "django": "x" * 40},
                         {**first, "source": "bad" * 15}, {**first, "extra": "bad"}]:
            with self.assertRaises(mobile.IntegrationError):
                mobile.validate_secrets(mutation)

    def test_busy_port_refuses_without_server_or_database_setup(self):
        probe = Mock()
        probe.bind.side_effect = OSError()
        context = Mock(__enter__=Mock(return_value=probe), __exit__=Mock(return_value=False))
        with patch.object(mobile.socket, "socket", return_value=context), patch.object(mobile, "setup") as setup:
            with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_PORT_BUSY"):
                mobile.MobileHarness().__enter__()
        setup.assert_not_called()

    def test_request_requires_current_process_database_and_listener_ownership(self):
        harness = mobile.MobileHarness()
        harness.server = Mock()
        harness.server.process.poll.return_value = None
        harness.runner = Mock()
        harness.runner._browser_lease.assert_owned = Mock()
        with patch.object(mobile.start_local, "listener_owners", return_value={1}), \
                patch.object(mobile.start_local, "owned_listener", return_value=False):
            with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_LISTENER_OWNERSHIP"):
                harness.assert_owned()
        harness.runner._browser_lease.assert_owned.assert_called_once()

    def test_stopped_server_denies_without_listener_check(self):
        harness = mobile.MobileHarness()
        harness.server = Mock()
        harness.server.process.poll.return_value = 1
        with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_SERVER_STOPPED"):
            harness.assert_owned()

    def test_client_refuses_external_query_and_fragment_paths(self):
        client = mobile.Client(Mock())
        for path in ["https://example.test/", "//example.test/", "/api/v1/mobile/me/?token=x",
                     "/api/v1/mobile/me/#x"]:
            with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_CLIENT_PATH"):
                client.request(path)

    def test_client_denies_redirects(self):
        self.assertIsNone(mobile.NoRedirect().redirect_request(None, None, 307, "", {}, "https://example.test/"))

    def test_console_faults_use_parent_pipe_and_eof_exits(self):
        harness = Mock()
        harness.assert_owned = Mock()
        harness.children = []
        with patch.object(mobile.sys, "stdin", io.StringIO("throttle\nnormal\nquit\n")), \
                patch.object(mobile.sys, "stdout", io.StringIO()):
            mobile.serve(harness)
        self.assertEqual([call.args[0] for call in harness.fault.call_args_list], ["throttle", "normal"])

    def test_child_cleanup_uncertainty_marks_database_preserved_before_teardown(self):
        harness = mobile.MobileHarness()
        harness.runner = Mock()
        harness.config = object()
        child = Mock()
        child.close.side_effect = RuntimeError("private child detail")
        harness.children = [child]
        database, guards = Mock(), Mock()
        order = []
        guards.preserve_database.side_effect = lambda: order.append("preserve")
        harness.runner.teardown_databases.side_effect = lambda _: order.append("teardown")
        with patch.dict(mobile.sys.modules, {"django.db": SimpleNamespace(connections=database),
                                            "tests": SimpleNamespace(browser_runner=guards)}):
            with self.assertRaisesRegex(mobile.IntegrationError, "MOBILE_CLEANUP_UNCERTAIN"):
                harness.__exit__(None, None, None)
        self.assertEqual(order, ["preserve", "teardown"])
        self.assertEqual(harness.keys, {})

    def test_clean_exit_stops_children_before_guarded_database_teardown(self):
        harness = mobile.MobileHarness()
        harness.runner = Mock()
        harness.config = object()
        harness.children = [Mock(), Mock()]
        database, guards, order = Mock(), Mock(), []
        harness.children[0].close.side_effect = lambda: order.append("server")
        harness.children[1].close.side_effect = lambda: order.append("worker")
        database.close_all.side_effect = lambda: order.append("connections")
        harness.runner.teardown_databases.side_effect = lambda _: order.append("teardown")
        with patch.dict(mobile.sys.modules, {"django.db": SimpleNamespace(connections=database),
                                            "tests": SimpleNamespace(browser_runner=guards)}):
            harness.__exit__(None, None, None)
        self.assertEqual(order, ["worker", "server", "connections", "teardown"])
        guards.preserve_database.assert_not_called()


if __name__ == "__main__":
    unittest.main()
