"""Independent local launcher fault checks; no installation, DB or app launch."""
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import start_local as startup


class IndependentLocalStartChecks(unittest.TestCase):
    def test_wrong_target_cannot_reach_any_preparation_or_local_listener_probe(self):
        cases = [{"KAPIT_RUNTIME_CONTEXT": "supabase-m1"}, {"KAPIT_RUNTIME_CONTEXT": "compose-m1"},
                 {"KAPIT_DB_HOST": "::1"}, {"KAPIT_DB_HOST": "127.9.8.7"}, {"KAPIT_DB_PORT": "5432"}]
        with patch.object(startup, "require_free_port") as port, patch.object(startup.local, "run") as run, \
                patch.object(startup.local, "native_module") as native, \
                patch.object(startup.local, "dependency_status") as dependencies:
            for environment in cases:
                with self.subTest(environment=environment), patch.dict(startup.os.environ, environment, clear=True):
                    with self.assertRaises(RuntimeError):
                        startup.prepare()
            port.assert_not_called()
            run.assert_not_called()
            native.assert_not_called()
            dependencies.assert_not_called()

    def test_preexisting_listener_is_not_readiness_even_if_generic_api_probe_succeeds(self):
        report = {"launch_ready": True, "ready": True, "checks": [{"component": "api", "ready": True}]}
        output = io.StringIO()
        with patch.object(startup.local, "managed_environment"), patch.object(startup.local, "checked_cache"), \
                patch.object(startup, "require_free_port", side_effect=startup.StartupError("PORT_8000_IN_USE")), \
                patch.object(startup.local, "doctor", return_value=report), \
                patch.object(startup, "listener_owners", return_value={777}), \
                patch.object(startup, "web_dependencies_ready", return_value=True), \
                patch.object(startup, "prepare") as prepare, patch.object(startup, "supervise") as supervise, \
                redirect_stdout(output):
            self.assertEqual(startup.check(), 2)
        value = json.loads(output.getvalue())
        self.assertFalse(value["ready"])
        prepare.assert_not_called()
        supervise.assert_not_called()

    def test_scope_correct_foreign_or_competing_listener_never_receives_api_probe(self):
        server, worker = Mock(pid=501), Mock(pid=502)
        server.poll.return_value = worker.poll.return_value = None
        for owners in ({777}, {501, 777}, {0, 501}):
            with self.subTest(owners=owners), patch.object(startup, "listener_owners", return_value=owners), \
                    patch.object(startup.local, "api_available") as api:
                with self.assertRaisesRegex(startup.StartupError, "LISTENER_CHANGED"):
                    startup.wait_ready([server, worker], server)
                api.assert_not_called()

    def test_ip_helper_parser_keeps_wildcard_competitor_and_ignores_other_interfaces(self):
        address = lambda value: int.from_bytes(socket.inet_aton(value), "little")
        rows = [(2, address("127.0.0.1"), socket.htons(8000), 0, 0, 501),
                (2, 0, socket.htons(8000), 0, 0, 777),
                (2, address("127.0.0.2"), socket.htons(8000), 0, 0, 888),
                (5, address("127.0.0.1"), socket.htons(8000), 0, 0, 999)]
        encoded = struct.pack("<I", len(rows)) + b"".join(struct.pack("<6I", *row) for row in rows)
        self.assertEqual(startup.parse_listener_owners(encoded), {501, 777})
        for malformed in (b"", struct.pack("<I", 1000), encoded[:-1]):
            with self.assertRaises(startup.StartupError):
                startup.parse_listener_owners(malformed)

    def test_partial_spawn_failure_cleans_created_handle_without_pid_lookup_or_browser(self):
        server = Mock(pid=501)
        server.poll.return_value = None
        with patch.object(startup, "require_free_port"), \
                patch.object(startup.subprocess, "Popen", side_effect=[server, OSError("spawn unavailable")]), \
                patch.object(startup, "listener_owners") as listeners, \
                patch.object(startup.webbrowser, "open") as browser, \
                patch.object(startup.local, "native_module") as native, redirect_stdout(io.StringIO()):
            with self.assertRaises(OSError):
                startup.supervise({}, open_browser=True)
        server.terminate.assert_called_once()
        server.wait.assert_called_once_with(timeout=5)
        listeners.assert_not_called()
        browser.assert_not_called()
        native.assert_not_called()

    def test_cleanup_failure_still_attempts_remaining_owned_child_and_retains_database(self):
        first, second = Mock(pid=501), Mock(pid=502)
        first.poll.return_value = second.poll.return_value = None
        second.wait.side_effect = subprocess.TimeoutExpired("owned", 5)
        with patch.object(startup.local, "native_module") as native:
            with self.assertRaisesRegex(startup.StartupError, "CHILD_STOP_FAILED"):
                startup.stop_children([first, second])
        second.kill.assert_called_once()
        first.terminate.assert_called_once()
        native.assert_not_called()

    def test_browser_gate_failure_never_seeds_or_starts_server(self):
        with ExitStack() as stack:
            stack.enter_context(patch.dict(startup.os.environ, {}, clear=True))
            stack.enter_context(patch.object(startup.local, "checked_cache"))
            stack.enter_context(patch.object(startup, "require_free_port"))
            stack.enter_context(patch.object(startup, "listener_owners", return_value=set()))
            stack.enter_context(patch.object(startup.local, "dependency_status", return_value={"modules": {"django": True}}))
            stack.enter_context(patch.object(startup, "web_dependencies_ready", return_value=True))
            stack.enter_context(patch.object(startup.local, "npm_command", return_value=["node", "npm-cli.js"]))
            run = stack.enter_context(patch.object(startup.local, "run"))
            native = stack.enter_context(patch.object(startup.local, "native_module"))
            seed = stack.enter_context(patch.object(startup.local, "seed_native"))
            stack.enter_context(patch.object(startup.local, "native_test"))
            stack.enter_context(patch.object(startup.local, "native_browser", side_effect=RuntimeError("BROWSER_GATE_FAILED")))
            stack.enter_context(redirect_stdout(io.StringIO()))
            with self.assertRaisesRegex(RuntimeError, "BROWSER_GATE_FAILED"):
                startup.prepare()
        self.assertFalse(any("seed-native" in call.args[0] for call in run.call_args_list))
        native.return_value.stop.assert_not_called()
        seed.assert_not_called()

    def test_private_phase_failure_discards_output_and_runs_direct_management_child(self):
        child = Mock(pid=501)
        child.wait.return_value = child.poll.return_value = 1
        command = [startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "test", "tests.browser_acceptance"]
        def guarded_browser(command_runner=None):
            command_runner(command, environment={"KAPIT_RUNTIME_CONTEXT": "native"})
        output = io.StringIO()
        with patch.object(startup.local, "native_browser", side_effect=guarded_browser), \
                patch.object(startup.subprocess, "Popen", return_value=child) as spawn, redirect_stdout(output):
            with self.assertRaisesRegex(startup.StartupError, "BROWSER_GATE_FAILED"):
                startup.private_phase("browser-native", {})
        self.assertEqual(spawn.call_args.args[0], command)
        self.assertEqual(spawn.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(spawn.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(output.getvalue(), "")
        child.terminate.assert_not_called()

    def test_private_phase_timeout_stops_owned_direct_child_without_exposing_exception(self):
        child = Mock(pid=501)
        child.wait.side_effect = [subprocess.TimeoutExpired("PRIVATE_COMMAND_CANARY", 240), None]
        child.poll.return_value = None
        def guarded_browser(command_runner=None):
            command_runner([startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "test"], environment={})
        with patch.object(startup.local, "native_browser", side_effect=guarded_browser), \
                patch.object(startup.subprocess, "Popen", return_value=child):
            with self.assertRaisesRegex(startup.StartupError, "BROWSER_GATE_FAILED") as result:
                startup.private_phase("browser-native", {})
        self.assertNotIn("CANARY", str(result.exception))
        child.terminate.assert_called_once()

    def test_custom_command_runner_cannot_bypass_existing_native_target_guards(self):
        execute = Mock()
        with patch.dict(startup.os.environ, {"KAPIT_RUNTIME_CONTEXT": "supabase-m1"}, clear=True), \
                patch.object(startup.local, "native_module") as native:
            for helper in (startup.local.native_test, startup.local.native_browser, startup.local.seed_native):
                with self.subTest(helper=helper.__name__), self.assertRaises(RuntimeError):
                    helper(command_runner=execute)
        execute.assert_not_called()
        native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
