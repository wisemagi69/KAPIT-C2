"""Controlled startup boundary/lifecycle checks; no actual install or database."""
from contextlib import ExitStack, redirect_stdout
import io
import socket
import struct
import subprocess
import unittest
from unittest.mock import Mock, patch

from infra import start_local as startup
from infra import startup_failure_diagnostics


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(redirect_stdout(io.StringIO()))
        self.diagnose = self.stack.enter_context(patch.object(startup_failure_diagnostics, "collect", return_value={}))
        self.stack.enter_context(patch.dict(startup.local.os.environ, {}, clear=True))
        self.stack.enter_context(patch.object(startup.local, "checked_cache"))
        self.port = self.stack.enter_context(patch.object(startup, "require_free_port"))
        self.owners = self.stack.enter_context(patch.object(startup, "listener_owners", return_value=set()))
        self.dependencies = self.stack.enter_context(patch.object(startup.local, "dependency_status", return_value={"modules": {"django": True}}))
        self.web = self.stack.enter_context(patch.object(startup, "web_dependencies_ready", return_value=True))
        self.stack.enter_context(patch.object(startup.local, "npm_command", return_value=["node", "npm-cli.js"]))
        self.run = self.stack.enter_context(patch.object(startup.local, "run"))
        self.native = self.stack.enter_context(patch.object(startup.local, "native_module")).return_value
        self.private = self.stack.enter_context(patch.object(startup, "private_phase"))

    def test_wrong_context_or_host_rejected_before_installs_and_database(self):
        for setting in ({"KAPIT_RUNTIME_CONTEXT": "supabase-m1"}, {"KAPIT_DB_HOST": "127.0.0.2"}, {"KAPIT_DB_HOST": "remote.example"}):
            with self.subTest(setting=setting), patch.dict(startup.local.os.environ, setting):
                with self.assertRaises(RuntimeError):
                    startup.prepare()
        self.port.assert_not_called()
        self.run.assert_not_called()
        self.native.init.assert_not_called()

    def test_initial_listener_blocks_before_package_probe_or_mutation(self):
        self.port.side_effect = startup.StartupError("PORT_8000_IN_USE")
        with self.assertRaisesRegex(startup.StartupError, "PORT_8000_IN_USE"):
            startup.prepare()
        self.dependencies.assert_not_called()
        self.run.assert_not_called()
        self.native.init.assert_not_called()

    def test_ready_dependencies_skip_installs_and_gates_precede_seed(self):
        events = []
        self.run.side_effect = lambda command, **kwargs: events.append("build")
        self.private.side_effect = lambda command, environment: events.append(command)
        environment = startup.prepare()
        self.assertEqual(events, ["build", "test-native", "browser-native", "seed-native"])
        self.assertEqual(environment["KAPIT_DB_HOST"], "127.0.0.1")
        self.assertEqual(self.port.call_count, 2)
        self.native.init.assert_called_once()
        self.native.start.assert_called_once()
        self.native.stop.assert_not_called()
        self.diagnose.assert_not_called()

    def test_only_missing_dependencies_trigger_existing_pinned_installers(self):
        self.dependencies.side_effect = [{"modules": {"django": False}}, {"modules": {"django": True}}]
        self.web.side_effect = [False, True]
        startup.prepare()
        commands = [call.args[0] for call in self.run.call_args_list]
        self.assertEqual(commands[0][-1], "prepare-python")
        self.assertIn("ci", commands[1])
        self.assertIn("--ignore-scripts", commands[1])
        self.assertIn("--no-audit", commands[1])
        self.assertEqual(commands[2][-2:], ["run", "build"])
        self.assertEqual(self.private.call_args_list[-1].args[0], "seed-native")

    def test_failed_package_install_stops_before_cluster_and_tests(self):
        self.dependencies.return_value = {"modules": {"django": False}}
        self.run.side_effect = RuntimeError("safe package failure")
        with self.assertRaises(RuntimeError):
            startup.prepare()
        self.run.assert_called_once()
        self.native.init.assert_not_called()
        self.private.assert_not_called()
        self.diagnose.assert_not_called()

    def test_native_failure_stops_later_actions_and_preserves_only_public_diagnostics(self):
        for action, code in (("init", "NATIVE_TOKEN_RESTRICTED"), ("start", "NATIVE_PORT"), ("status", "NATIVE_DATABASE")):
            with self.subTest(action=action):
                self.native.reset_mock(side_effect=True)
                self.private.reset_mock()
                getattr(self.native, action).side_effect = RuntimeError(code + ": SYNTHETIC_PRIVATE_EXCEPTION_SUFFIX")
                with self.assertRaises(startup.StartupError) as failure:
                    startup.prepare()
                self.assertTrue(str(failure.exception).startswith(code + ":"))
                self.assertIn("python -B infra/local.py native-diagnose", str(failure.exception))
                self.assertNotIn("SYNTHETIC_PRIVATE_EXCEPTION_SUFFIX", str(failure.exception))
                self.assertTrue(failure.exception.__suppress_context__)
                self.private.assert_not_called()
                self.native.stop.assert_not_called()
                if action == "init":
                    self.native.start.assert_not_called()
                    self.native.status.assert_not_called()
                elif action == "start":
                    self.native.status.assert_not_called()

    def test_both_gates_abort_before_seed_without_stopping_database(self):
        for gate in ("test-native", "browser-native"):
            self.run.reset_mock()

            def run_phase(command, environment):
                if command == gate:
                    raise RuntimeError("gate failed")

            self.private.reset_mock()
            self.private.side_effect = run_phase
            with self.assertRaisesRegex(RuntimeError, "gate failed"):
                startup.prepare()
            self.assertFalse(any(call.args[0] == "seed-native" for call in self.private.call_args_list))
            self.native.stop.assert_not_called()
            self.private.side_effect = None
        self.diagnose.assert_not_called()

    def test_late_listener_prevents_seed_and_leaves_cluster_running(self):
        self.port.side_effect = [None, startup.StartupError("PORT_8000_IN_USE")]
        with self.assertRaisesRegex(startup.StartupError, "PORT_8000_IN_USE"):
            startup.prepare()
        self.assertFalse(any(call.args[0] == "seed-native" for call in self.private.call_args_list))
        self.native.stop.assert_not_called()

    def test_check_reports_blocked_without_preparation_or_mutation(self):
        with patch.object(startup.local, "doctor", return_value={"launch_ready": False}), patch.object(startup, "prepare") as prepare, patch.object(startup, "supervise") as supervise, patch.object(startup.sys, "argv", ["start_local.py", "--check"]):
            self.assertEqual(startup.main(), 2)
        prepare.assert_not_called()
        supervise.assert_not_called()
        self.run.assert_not_called()
        self.native.init.assert_not_called()

    def test_check_cannot_claim_ready_from_unrelated_api_response(self):
        self.port.side_effect = startup.StartupError("PORT_8000_IN_USE")
        with patch.object(startup.local, "doctor", return_value={"launch_ready": True, "ready": True, "checks": [{"component": "api", "ready": True}]}), patch.object(startup.json, "dumps", wraps=startup.json.dumps) as dump:
            self.assertEqual(startup.check(), 2)
        report = dump.call_args.args[0]
        self.assertFalse(report["ready"])
        self.assertFalse(report["launch_ready"])
        self.assertFalse(report["website_running_verified"])
        self.assertEqual(report["checks"][0]["code"], "API_RESPONSE_OBSERVED_UNVERIFIED")
        self.assertFalse(report["checks"][0]["ready"])

    def test_unknown_listener_ownership_prevents_any_setup_mutation(self):
        self.owners.side_effect = startup.StartupError("LISTENER_OWNER_UNAVAILABLE")
        with self.assertRaisesRegex(startup.StartupError, "LISTENER_OWNER_UNAVAILABLE"):
            startup.prepare()
        self.dependencies.assert_not_called()
        self.run.assert_not_called()
        self.native.init.assert_not_called()


class NativeDiagnosticTests(unittest.TestCase):
    def setUp(self):
        # Inherited failure tests must never perform actual native readbacks.
        collector = patch.object(startup_failure_diagnostics, "collect", return_value={})
        self.diagnose = collector.start()
        self.addCleanup(collector.stop)

    def test_unknown_or_file_errors_do_not_expose_values_or_traceback_suffixes(self):
        errors = [RuntimeError("SYNTHETIC_PRIVATE_EXCEPTION"), RuntimeError("NATIVE_PORT\nSYNTHETIC_PRIVATE_EXCEPTION: denied"),
                  PermissionError("SYNTHETIC_PRIVATE_PATH"), ValueError("SYNTHETIC_PRIVATE_VALUE"),
                  KeyError("SYNTHETIC_PRIVATE_KEY"), TypeError("SYNTHETIC_PRIVATE_TYPE")]
        for error in errors:
            with self.subTest(error_type=type(error).__name__), patch.object(startup.local, "native_module") as native, redirect_stdout(io.StringIO()) as output:
                native.return_value.init.side_effect = error
                with self.assertRaisesRegex(startup.StartupError, "^POSTGRES_SETUP_FAILED:") as failure:
                    startup.native_phase("init")
                self.assertNotIn("SYNTHETIC_PRIVATE", str(failure.exception) + output.getvalue())
                self.assertIsNone(failure.exception.__cause__)
                self.assertTrue(failure.exception.__suppress_context__)
                self.assertIn("python -B infra/local.py native-diagnose", str(failure.exception))

    def test_invalid_action_never_loads_native_manager(self):
        with patch.object(startup.local, "native_module") as native:
            with self.assertRaisesRegex(startup.StartupError, "INVALID_NATIVE_PHASE"):
                startup.native_phase("stop")
        native.assert_not_called()

    def test_status_preserves_running_requirement_and_result(self):
        with patch.object(startup.local, "native_module") as native, redirect_stdout(io.StringIO()):
            native.return_value.status.return_value = {"state": "running"}
            self.assertEqual(startup.native_phase("status"), {"state": "running"})
            native.return_value.status.assert_called_once_with(require_running=True)
            native.return_value.init.assert_not_called()
            native.return_value.start.assert_not_called()


class ScheduledBackupTests(unittest.TestCase):
    def test_recent_verified_backup_is_kept_without_new_dump(self):
        with patch.object(startup.local, "latest_verified_backup", return_value={"created_epoch": 1000.0}), patch.object(startup.local, "native_backup") as backup:
            self.assertEqual(("CURRENT", 1000.0), startup.backup_if_due(now=1000.0 + startup.BACKUP_INTERVAL_SECONDS - 1))
        backup.assert_not_called()

    def test_missing_or_stale_backup_creates_one_inside_rpo(self):
        self.assertLess(startup.BACKUP_INTERVAL_SECONDS + startup.BACKUP_CHECK_SECONDS, 24 * 3600)
        for latest in (None, {"created_epoch": 0.0}):
            with self.subTest(latest=latest), patch.object(startup.local, "latest_verified_backup", return_value=latest), patch.object(startup.local, "native_backup") as backup, redirect_stdout(io.StringIO()):
                self.assertEqual("CREATED", startup.backup_if_due(now=startup.BACKUP_INTERVAL_SECONDS + 1.0)[0])
            backup.assert_called_once()

    def test_backup_failure_is_reported_but_never_stops_the_website(self):
        output = io.StringIO()
        with patch.object(startup.local, "latest_verified_backup", return_value=None), patch.object(startup.local, "native_backup", side_effect=RuntimeError("BACKUP_UNVERIFIED: secret detail")), redirect_stdout(output):
            self.assertEqual(("FAILED", None), startup.backup_if_due())
        self.assertIn("backup failed", output.getvalue()); self.assertNotIn("secret detail", output.getvalue())

    def test_supervisor_checks_backup_after_its_first_healthy_cycle(self):
        server, worker = Mock(pid=100, poll=Mock(return_value=None)), Mock(pid=101, poll=Mock(return_value=None))
        with patch.object(startup, "require_free_port"), patch.object(startup.subprocess, "Popen", side_effect=[server, worker]), patch.object(startup, "wait_ready"), patch.object(startup, "listener_owners", return_value={100}), patch.object(startup.time, "sleep"), patch.object(startup.BackupScheduler, "tick", side_effect=KeyboardInterrupt) as due, redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                startup.supervise({}, open_browser=False)
        due.assert_called_once(); server.terminate.assert_called_once(); worker.terminate.assert_called_once()

    def test_scheduler_runs_off_loop_and_skips_rehash_while_current(self):
        release = __import__("threading").Event()
        def slow_backup():
            release.wait(5)
            return "CREATED", 5000.0
        scheduler = startup.BackupScheduler()
        with patch.object(startup, "backup_if_due", side_effect=slow_backup) as due:
            self.assertEqual("STARTED", scheduler.tick(now=0.0))
            self.assertEqual("RUNNING", scheduler.tick(now=1.0))  # the loop is never blocked by a dump
            release.set(); scheduler.thread.join(5)
            self.assertEqual("CURRENT", scheduler.tick(now=5000.0 + startup.BACKUP_INTERVAL_SECONDS - 1))
            self.assertEqual("STARTED", scheduler.tick(now=5000.0 + startup.BACKUP_INTERVAL_SECONDS + 1)); scheduler.thread.join(5)
        self.assertEqual(2, due.call_count)

    def test_supervisor_exit_waits_for_a_running_backup(self):
        release = __import__("threading").Event()
        scheduler = startup.BackupScheduler()
        with patch.object(startup, "backup_if_due", side_effect=lambda: (release.wait(5), ("CREATED", 1.0))[1]), redirect_stdout(io.StringIO()):
            scheduler.tick(now=0.0)
            self.assertEqual("STILL_RUNNING", scheduler.finish(timeout=0.05))
            release.set()
            self.assertEqual("IDLE", scheduler.finish(timeout=5))
        self.assertFalse(scheduler.thread.daemon)

    def test_failed_backup_is_retried_on_next_check(self):
        scheduler = startup.BackupScheduler()
        with patch.object(startup, "backup_if_due", return_value=("FAILED", None)) as due:
            scheduler.tick(now=0.0); scheduler.thread.join(5)
            self.assertEqual("STARTED", scheduler.tick(now=1.0)); scheduler.thread.join(5)
        self.assertEqual(2, due.call_count)


class SupervisorTests(unittest.TestCase):
    def child(self, pid):
        return Mock(pid=pid, poll=Mock(return_value=None))

    def test_partial_launch_failure_stops_only_created_server(self):
        server = self.child(100)
        with patch.object(startup, "require_free_port"), patch.object(startup.subprocess, "Popen", side_effect=[server, OSError("spawn failed")]), redirect_stdout(io.StringIO()):
            with self.assertRaises(OSError):
                startup.supervise({}, open_browser=False)
        server.terminate.assert_called_once()
        server.wait.assert_called_once_with(timeout=5)

    def test_child_is_registered_before_restoring_interrupt_handler(self):
        import signal
        child = self.child(10)
        registered = []
        original = signal.getsignal(signal.SIGINT)

        def spawn(command, **options):
            self.assertEqual(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
            self.assertEqual(registered, [])
            return child

        with patch.object(startup.subprocess, "Popen", side_effect=spawn):
            self.assertIs(startup.spawn_registered(["owned"], registered, {}), child)
        self.assertEqual(registered, [child])
        self.assertEqual(signal.getsignal(signal.SIGINT), original)

    def test_ctrl_c_stops_direct_children_without_opening_browser_when_disabled(self):
        server, worker = self.child(100), self.child(101)
        with patch.object(startup, "require_free_port"), patch.object(startup.subprocess, "Popen", side_effect=[server, worker]) as popen, patch.object(startup, "wait_ready"), patch.object(startup, "listener_owners", return_value={100}), patch.object(startup.time, "sleep", side_effect=KeyboardInterrupt), patch.object(startup.webbrowser, "open") as browser, redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                startup.supervise({"KAPIT_RUNTIME_CONTEXT": "native"}, open_browser=False)
        server.terminate.assert_called_once()
        worker.terminate.assert_called_once()
        commands = [call.args[0] for call in popen.call_args_list]
        self.assertTrue(commands[0][-1].endswith("infra/server.py") or commands[0][-1].endswith("infra\\server.py"))
        self.assertEqual(commands[1][-1], "process_jobs")
        self.assertFalse(any("local.py" in part for command in commands for part in command))
        self.assertTrue(all(call.kwargs["stdout"] == subprocess.DEVNULL and call.kwargs["stderr"] == subprocess.DEVNULL for call in popen.call_args_list))
        if startup.os.name == "nt":
            self.assertTrue(all(call.kwargs["creationflags"] == subprocess.CREATE_NO_WINDOW for call in popen.call_args_list))
        browser.assert_not_called()

    def test_failed_readiness_closes_both_children_before_any_browser(self):
        server, worker = self.child(100), self.child(101)
        with patch.object(startup, "require_free_port"), patch.object(startup.subprocess, "Popen", side_effect=[server, worker]), patch.object(startup, "wait_ready", side_effect=startup.StartupError("API_TIMEOUT")), patch.object(startup.webbrowser, "open") as browser, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(startup.StartupError, "API_TIMEOUT"):
                startup.supervise({})
        browser.assert_not_called()
        server.terminate.assert_called_once()
        worker.terminate.assert_called_once()

    def test_shutdown_escalates_only_owned_live_child_and_continues_cleanup(self):
        stopped, stubborn, other = self.child(10), self.child(11), self.child(12)
        stopped.poll.return_value = 0
        stubborn.wait.side_effect = [subprocess.TimeoutExpired("owned", 5), None]
        startup.stop_children([other, stubborn, stopped])
        stopped.terminate.assert_not_called()
        stubborn.terminate.assert_called_once()
        stubborn.kill.assert_called_once()
        other.terminate.assert_called_once()

    def test_competing_listener_never_counts_as_api_readiness(self):
        server, worker = self.child(100), self.child(101)
        with patch.object(startup, "listener_owners", return_value={100, 999}), patch.object(startup.local, "api_available") as api:
            with self.assertRaisesRegex(startup.StartupError, "LISTENER_CHANGED"):
                startup.wait_ready([server, worker], server)
        api.assert_not_called()

    def test_child_exit_during_api_probe_rejects_ready(self):
        server, worker = self.child(100), self.child(101)
        server.poll.side_effect = [None, 1]
        with patch.object(startup, "listener_owners", return_value={100}), patch.object(startup.local, "api_available", return_value=True):
            with self.assertRaisesRegex(startup.StartupError, "CHILD_EXITED"):
                startup.wait_ready([server, worker], server)

    def test_owner_change_during_api_probe_rejects_ready(self):
        server, worker = self.child(100), self.child(101)
        with patch.object(startup, "listener_owners", side_effect=[{100}, {999}]), patch.object(startup.local, "api_available", return_value=True):
            with self.assertRaisesRegex(startup.StartupError, "LISTENER_CHANGED"):
                startup.wait_ready([server, worker], server)

    def test_wait_has_bounded_startup_timeout(self):
        server, worker = self.child(100), self.child(101)
        with patch.object(startup.time, "monotonic", side_effect=[0, 41]):
            with self.assertRaisesRegex(startup.StartupError, "API_TIMEOUT"):
                startup.wait_ready([server, worker], server)

    def test_listener_parser_includes_all_relevant_owners_and_rejects_short_tables(self):
        loopback = int.from_bytes(socket.inet_aton("127.0.0.1"), "little")
        rows = [(2, loopback, socket.htons(8000), 0, 0, 10), (2, 0, socket.htons(8000), 0, 0, 20),
                (2, loopback, socket.htons(18081), 0, 0, 30), (5, loopback, socket.htons(8000), 0, 0, 40)]
        raw = struct.pack("<I", len(rows)) + b"".join(struct.pack("<6I", *row) for row in rows)
        self.assertEqual(startup.parse_listener_owners(raw), {10, 20})
        with self.assertRaisesRegex(startup.StartupError, "LISTENER_OWNER_UNAVAILABLE"):
            startup.parse_listener_owners(raw[:-1])


class PrivatePhaseTests(unittest.TestCase):
    def run_browser(self, *, command_runner):
        command_runner([startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "test", "tests.browser_acceptance"],
                       environment={"KAPIT_RUNTIME_CONTEXT": "native"})

    def test_sensitive_command_output_is_discarded_and_failure_is_fixed(self):
        child = Mock(pid=50, poll=Mock(return_value=1), wait=Mock(return_value=1))
        with patch.object(startup.local, "native_browser", side_effect=self.run_browser), patch.object(startup.subprocess, "Popen", return_value=child) as popen, redirect_stdout(io.StringIO()) as output:
            with self.assertRaisesRegex(startup.StartupError, "BROWSER_GATE_FAILED") as error:
                startup.private_phase("browser-native", {})
        self.assertNotIn("Traceback", str(error.exception))
        self.assertEqual(output.getvalue(), "")
        options = popen.call_args.kwargs
        self.assertEqual(options["stdout"], subprocess.DEVNULL)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertTrue(popen.call_args.args[0][1].endswith("manage.py"))
        child.wait.assert_called_once_with(timeout=720)

    def test_private_command_timeout_closes_owned_direct_child(self):
        child = Mock(pid=50, poll=Mock(return_value=None), wait=Mock(side_effect=[subprocess.TimeoutExpired("owned", 720), 0]))
        with patch.object(startup.local, "native_browser", side_effect=self.run_browser), patch.object(startup.subprocess, "Popen", return_value=child):
            with self.assertRaisesRegex(startup.StartupError, "BROWSER_GATE_FAILED"):
                startup.private_phase("browser-native", {})
        child.terminate.assert_called_once()
        self.assertEqual(child.wait.call_args_list[-1].kwargs, {"timeout": 5})

    def test_private_command_interrupt_closes_owned_direct_child(self):
        child = Mock(pid=50, poll=Mock(return_value=None), wait=Mock(side_effect=[KeyboardInterrupt, 0]))
        with patch.object(startup.local, "native_browser", side_effect=self.run_browser), patch.object(startup.subprocess, "Popen", return_value=child):
            with self.assertRaises(KeyboardInterrupt):
                startup.private_phase("browser-native", {})
        child.terminate.assert_called_once()

    def test_unknown_sensitive_phase_cannot_spawn(self):
        with patch.object(startup.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(startup.StartupError, "INVALID_PRIVATE_PHASE"):
                startup.private_phase("other", {})
        popen.assert_not_called()


class FrameworkDeadlineTests(unittest.TestCase):
    """Drive the actual private-phase loop with a deterministic clock/owned child."""
    class Clock:
        def __init__(self): self.now = 0.0
        def __call__(self): return self.now

    class Child:
        def __init__(self, clock, duration, *, status=0, interrupt=False, late=False):
            self.clock, self.finish = clock, clock.now + duration
            self.status, self.interrupt, self.late = status, interrupt, late
            self.code, self.waits, self.terminations = None, [], 0
        def poll(self): return self.code
        def terminate(self):
            self.terminations += 1
            self.code = -15
        def kill(self): raise AssertionError("Unexpected escalation in fixture")
        def wait(self, timeout):
            self.waits.append(timeout)
            if self.code is not None:
                return self.code
            if self.interrupt:
                self.interrupt = False
                raise KeyboardInterrupt()
            if self.late:
                self.clock.now += timeout + 601
                self.code = self.status
                return self.code
            if self.finish <= self.clock.now + timeout:
                self.clock.now = self.finish
                self.code = self.status
                return self.code
            self.clock.now += timeout
            raise subprocess.TimeoutExpired("PRIVATE_ARGV_CANARY", timeout,
                output="PRIVATE_STDOUT_CANARY", stderr="PRIVATE_STDERR_CANARY")

    def invoke(self, duration, *, status=0, interrupt=False, late=False, cleanup_failure=False):
        clock = self.Clock()
        child = self.Child(clock, duration, status=status, interrupt=interrupt, late=late)
        if cleanup_failure:
            child.terminate = Mock(side_effect=OSError("PRIVATE_CLEANUP_CANARY"))
        args = [startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "test", "tests",
                "--settings=config.test_settings", "--testrunner=tests.browser_runner.BrowserAcceptanceRunner"]
        def test(*, command_runner):
            command_runner(args, environment={"KAPIT_SOURCE_KEY": "PRIVATE_ENV_CANARY"})
        output = io.StringIO()
        failure = None
        with patch.object(startup.local, "native_test", side_effect=test), \
                patch.object(startup.time, "monotonic", side_effect=clock), \
                patch.object(startup.subprocess, "Popen", return_value=child) as popen, redirect_stdout(output):
            try:
                startup.private_phase("test-native", {})
            except (startup.StartupError, KeyboardInterrupt) as error:
                failure = error
        self.assertNotIn("PRIVATE_", output.getvalue() + (str(failure) if failure else ""))
        options = popen.call_args.kwargs
        self.assertEqual((options["stdin"], options["stdout"], options["stderr"]), (subprocess.DEVNULL,) * 3)
        self.assertEqual(popen.call_count, 1)
        return clock, child, output.getvalue().splitlines(), failure

    def test_long_migration_and_suite_budget_allows_completion_beyond_old_deadline(self):
        clock, child, messages, failure = self.invoke(420)
        self.assertIsNone(failure)
        self.assertEqual(clock.now, 420)
        self.assertEqual(child.terminations, 0)
        self.assertTrue(all(0 < wait <= 30 for wait in child.waits))
        self.assertEqual(messages[0], "LOCAL_START: framework full-suite started")
        self.assertEqual(messages[-1], "LOCAL_START: framework full-suite passed (elapsed 420s)")
        self.assertEqual(len([line for line in messages if " running " in line]), 13)

    def test_hung_gate_never_resets_deadline_and_terminates_only_owned_child(self):
        clock, child, messages, failure = self.invoke(1200)
        self.assertIsInstance(failure, startup.StartupError)
        self.assertIn("FRAMEWORK_GATE_FAILED: the step timed out", str(failure))
        self.assertEqual(clock.now, 600)
        self.assertEqual(child.terminations, 1)
        self.assertEqual(child.waits[-1], 5)  # Existing owned cleanup bound.
        self.assertEqual(sum(child.waits[:-1]), 600)
        self.assertFalse(any(" passed " in line for line in messages))
        self.assertEqual(messages[-1], "LOCAL_START: framework full-suite running (elapsed 570s)")

    def test_final_slice_is_shortened_to_remaining_budget(self):
        # OS scheduling can consume extra time between waits. The final call
        # still uses the remaining monotonic budget, not another full slice.
        clock = self.Clock()
        waits = []
        def wait(*, timeout):
            waits.append(timeout)
            clock.now += 37 if len(waits) < 17 else timeout
            raise subprocess.TimeoutExpired("PRIVATE_ARGV_CANARY", timeout)
        child = Mock(poll=Mock(return_value=0), wait=Mock(side_effect=wait))
        def test(*, command_runner):
            command_runner([startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "check",
                            "--settings=config.test_settings"], environment={})
        with patch.object(startup.local, "native_test", side_effect=test), patch.object(startup.time, "monotonic", side_effect=clock), \
                patch.object(startup.subprocess, "Popen", return_value=child), redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(startup.StartupError, "FRAMEWORK_GATE_FAILED"):
                startup.private_phase("test-native", {})
        self.assertEqual(waits[-1], 8)
        self.assertEqual(clock.now, 600)

    def test_late_zero_exit_cannot_report_a_pass_after_deadline(self):
        _, child, messages, failure = self.invoke(10, late=True)
        self.assertIn("timed out", str(failure))
        self.assertEqual(child.terminations, 0)  # Already exited; no signal.
        self.assertFalse(any(" passed " in line for line in messages))

    def test_nonzero_and_interrupt_keep_failure_and_owned_cleanup_boundaries(self):
        for options in ({"status": 1}, {"interrupt": True}):
            with self.subTest(options=options):
                _, child, messages, failure = self.invoke(35, **options)
                self.assertIsNotNone(failure)
                self.assertFalse(any(" passed " in line for line in messages))
                if options.get("interrupt"):
                    self.assertIsInstance(failure, KeyboardInterrupt)
                    self.assertEqual(child.terminations, 1)
                else:
                    self.assertIsInstance(failure, startup.StartupError)
                    self.assertIn("FRAMEWORK_GATE_FAILED", str(failure))
                    self.assertEqual(child.terminations, 0)

    def test_uncertain_owned_cleanup_overrides_timeout_without_exception_body(self):
        _, _, _, failure = self.invoke(1200, cleanup_failure=True)
        self.assertIsInstance(failure, startup.StartupError)
        self.assertIn("CHILD_STOP_FAILED", str(failure))

    def test_actual_native_test_still_invokes_all_three_exact_commands_in_order(self):
        children = [Mock(poll=Mock(return_value=0), wait=Mock(return_value=0)) for _ in range(3)]
        with patch.object(startup.local, "managed_environment", return_value={}), \
                patch.object(startup.local, "native_module"), \
                patch.object(startup.local, "dependency_status", return_value={"modules": {"django": True}}), \
                patch.object(startup.subprocess, "Popen", side_effect=children) as popen, redirect_stdout(io.StringIO()) as output:
            startup.private_phase("test-native", {})
        commands = [call.args[0][2:] for call in popen.call_args_list]
        self.assertEqual(commands, [["check", "--settings=config.test_settings"],
            ["makemigrations", "--check", "--dry-run", "--settings=config.test_settings"],
            ["test", "tests", "--settings=config.test_settings", "--testrunner=tests.browser_runner.BrowserAcceptanceRunner"]])
        self.assertEqual([line for line in output.getvalue().splitlines() if line.endswith(" started")],
            ["LOCAL_START: framework check started", "LOCAL_START: framework migration-consistency started", "LOCAL_START: framework full-suite started"])

    def test_unknown_framework_arguments_refused_without_echo_or_spawn(self):
        def test(*, command_runner):
            command_runner([startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "PRIVATE_ARGV_CANARY"], environment={})
        with patch.object(startup.local, "native_test", side_effect=test), patch.object(startup.subprocess, "Popen") as popen, redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(startup.StartupError) as failure:
                startup.private_phase("test-native", {})
        self.assertNotIn("PRIVATE_ARGV_CANARY", str(failure.exception) + output.getvalue())
        popen.assert_not_called()

    def test_browser_and_seed_caps_and_quiet_output_remain_unchanged(self):
        for command, function, cap in (("browser-native", "native_browser", 720), ("seed-native", "seed_native", 60)):
            with self.subTest(command=command):
                child = Mock(poll=Mock(return_value=0), wait=Mock(return_value=0))
                def run(*, command_runner):
                    command_runner([startup.local.python_path(), str(startup.local.ROOT / "backend/manage.py"), "fixed-stage"], environment={})
                with patch.object(startup.local, function, side_effect=run), patch.object(startup.subprocess, "Popen", return_value=child), redirect_stdout(io.StringIO()) as output:
                    startup.private_phase(command, {})
                child.wait.assert_called_once_with(timeout=cap)
                self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
