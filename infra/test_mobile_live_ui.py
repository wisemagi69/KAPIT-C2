"""Pure TASK098 guards. No emulator, ADB, service or database is launched."""
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import Mock, MagicMock, patch

from infra import mobile_live_ui as ui

RUN = "a" * 32


def phase(number, **change):
    value = {"schema": 1, "run": RUN, "seq": number, "phase": ui.STEPS[number - 1][0]}
    value.update(change)
    return json.dumps(value, separators=(",", ":"))


def status(code, *, name=ui.TEST_CLASS, method=ui.METHOD):
    return (f"INSTRUMENTATION_STATUS: class={name}\nINSTRUMENTATION_STATUS: test={method}\n"
            f"INSTRUMENTATION_STATUS: current=1\nINSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS_CODE: {code}\n")


SUCCESS = status(1) + status(0) + "\nTime: 1\n\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n"


class MarkerTests(unittest.TestCase):
    def test_exact_thirteen_phases_and_ack_ownership(self):
        self.assertEqual(len(ui.STEPS), 13)
        for number in range(1, 14):
            self.assertEqual(ui.marker(phase(number), RUN), number)
            self.assertEqual(ui.marker(ui.ack_bytes(RUN, number).decode(), RUN, ack=True), number)

    def test_wrong_run_types_schema_sequence_unknown_fields_and_phase_fail(self):
        bad = [phase(1, run="b" * 32), phase(1, schema=True), phase(1, schema=2), phase(1, seq=True),
               phase(1, seq=0), phase(1, seq=14), phase(1, phase="completed"), phase(1, extra="PRIVATE_CANARY"),
               "[]", "null", "{" , "x" * 257, phase(1).replace("starting", "stärt"),
               phase(1)[:-1] + ',"seq":1}']
        for raw in bad:
            with self.subTest(length=len(raw)), self.assertRaises(ui.Error):
                ui.marker(raw, RUN)

    def test_native_phase_cannot_be_used_as_host_ack(self):
        with self.assertRaises(ui.Error):
            ui.marker(phase(1), RUN, ack=True)

    def test_ack_cannot_embed_shell_code_or_unsupported_sequence(self):
        for run, number in (("'$(echo PRIVATE)'", 1), (RUN, 0), (RUN, True), (RUN, 14)):
            with self.subTest(number=number), self.assertRaises(ui.Error):
                ui.ack_bytes(run, number)


class NativeParserTests(unittest.TestCase):
    def test_complete_exact_one_method_is_required(self):
        self.assertEqual(ui.native_result(SUCCESS, 0)["method_completed_count"], 1)
        bad = [SUCCESS.replace(ui.TEST_CLASS, "foreign.Class"), SUCCESS.replace(ui.METHOD, "other"),
               SUCCESS.replace("numtests=1", "numtests=2"), SUCCESS + status(0), SUCCESS + "INSTRUMENTATION_CODE: -1\n",
               SUCCESS.replace("STATUS_CODE: 0", "STATUS_CODE: -2"), SUCCESS.replace("OK (1 test)", "OK (2 tests)"),
               SUCCESS + "INSTRUMENTATION_RESULT: shortMsg=PRIVATE_CANARY\n", SUCCESS + "java.lang.IllegalStateException: PRIVATE_CANARY\n",
               SUCCESS + "INSTRUMENTATION_STATUS: test=orphan\n", SUCCESS[:-1], SUCCESS + "INSTRUMENTATION_CODE: invalid\n"]
        for raw in bad:
            with self.subTest(length=len(raw)), self.assertRaises(ui.Error):
                ui.native_result(raw, 0)
        with self.assertRaises(ui.Error):
            ui.native_result(SUCCESS, 1)

    def test_stream_start_requires_every_final_line_byte(self):
        raw = status(1)
        for split in range(len(raw)):
            self.assertFalse(ui.native_started(raw[:split]))
        self.assertTrue(ui.native_started(raw))

    def test_every_partial_terminal_or_failure_tail_revokes_prior_ready_start(self):
        for tail in ("INSTRUMENTATION_CODE: -1\n", "INSTRUMENTATION_RESULT: shortMsg=PRIVATE\n",
                     "INSTRUMENTATION_STATUS: stack=PRIVATE\n", "java.lang.AssertionError: PRIVATE\n"):
            for split in range(1, len(tail)):
                with self.subTest(tail=tail.split(":")[0], split=split):
                    self.assertFalse(ui.native_started(status(1) + tail[:split]))
            with self.assertRaises(ui.Error):
                ui.native_started(status(1) + tail)

    def test_live_failure_or_early_terminal_cannot_be_acknowledged(self):
        for raw in (SUCCESS, status(1) + "INSTRUMENTATION_RESULT: stream=\n",
                    status(1) + "java.lang.AssertionError: PRIVATE_CANARY\n",
                    status(1) + "INSTRUMENTATION_STATUS: stack=PRIVATE_CANARY\n", status(1) + status(1)):
            with self.subTest(length=len(raw)), self.assertRaises(ui.Error):
                ui.native_started(raw)

    def test_duplicate_identity_or_malformed_status_code_denied(self):
        for raw in (status(1).replace("INSTRUMENTATION_STATUS: current=1\n", "INSTRUMENTATION_STATUS: current=1\n" * 2),
                    status(1).replace("STATUS_CODE: 1", "STATUS_CODE: invalid"), status(1, name="other.Class")):
            with self.assertRaises(ui.Error):
                ui.native_started(raw)

    def test_failure_metadata_never_exports_message_or_arbitrary_class_name(self):
        class PRIVATE_CANARY(Exception):
            pass
        value = ui.fail_metadata(PRIVATE_CANARY("private values"), "starting")
        self.assertEqual(value["exception_class"], "Other")
        self.assertNotIn("CANARY", json.dumps(value))
        self.assertNotIn("private values", json.dumps(value))


class EmulatorCommandTests(unittest.TestCase):
    def emulator(self):
        emulator = object.__new__(ui.UiEmulator)
        emulator.command = Mock(return_value="acknowledged")
        return emulator

    def test_ack_only_fixed_atomic_path_and_prior_ack_check(self):
        emulator = self.emulator()
        emulator.acknowledge(RUN, 2)
        args, kwargs = emulator.command.call_args
        self.assertEqual(args, ("shell", "run-as", ui.base.PACKAGE, "--user", "0", "sh"))
        script = kwargs["stdin"]
        self.assertIn(ui.ack_bytes(RUN, 1), script)
        self.assertIn(ui.ack_bytes(RUN, 2), script)
        self.assertIn(b"test ! -L no_backup/m2-ui-host-ack", script)
        self.assertIn(b"mv no_backup/m2-ui-host-ack.host-tmp no_backup/m2-ui-host-ack", script)
        self.assertNotIn(RUN, str(args))
        self.assertLessEqual(len(script), 4096)
        self.assertEqual(kwargs["maximum"], 64)

    def test_phase_reader_catches_oversize_and_symlink_before_parse(self):
        emulator = self.emulator()
        emulator.command.return_value = "absent"
        self.assertEqual(emulator.read_phase(), "absent")
        args, kwargs = emulator.command.call_args
        self.assertEqual(kwargs["maximum"], 257)
        self.assertIn(b"head -c 257", kwargs["stdin"])
        self.assertIn(b"test ! -L", kwargs["stdin"])

    def test_exact_mapping_removed_and_other_mapping_preserved(self):
        emulator = self.emulator()
        emulator.mapping = Mock(side_effect=[{ui.base.ENDPOINT: ui.base.ENDPOINT, "tcp:19001": "tcp:19002"}, {"tcp:19001": "tcp:19002"}])
        emulator.disconnect()
        emulator.command.assert_called_once_with("reverse", "--remove", ui.base.ENDPOINT, timeout=5)

    def test_wrong_mapping_or_unrelated_mapping_change_denied(self):
        for before, after in (({}, {}), ({ui.base.ENDPOINT: "tcp:123"}, {}),
                              ({ui.base.ENDPOINT: ui.base.ENDPOINT, "tcp:1": "tcp:2"}, {})):
            emulator = self.emulator()
            emulator.mapping = Mock(side_effect=[before, after])
            with self.assertRaises(ui.Error):
                emulator.disconnect()
            if before.get(ui.base.ENDPOINT) != ui.base.ENDPOINT:
                emulator.command.assert_not_called()

    def test_no_rebind_and_exact_restore_required(self):
        emulator = self.emulator()
        emulator.mapping = Mock(side_effect=[{}, {ui.base.ENDPOINT: ui.base.ENDPOINT}])
        emulator.reconnect()
        emulator.command.assert_called_once_with("reverse", "--no-rebind", ui.base.ENDPOINT, ui.base.ENDPOINT, timeout=5)
        emulator.command.reset_mock()
        emulator.mapping = Mock(return_value={ui.base.ENDPOINT: ui.base.ENDPOINT})
        with self.assertRaises(ui.Error):
            emulator.reconnect()
        emulator.command.assert_not_called()

    def test_credential_marker_does_not_bypass_actual_platform_target(self):
        emulator = self.emulator()
        emulator.credential_action = Mock(side_effect=ui.Error("PLATFORM_CREDENTIAL_WINDOW_DENIED"))
        with self.assertRaises(ui.Error):
            emulator.credential_return(Mock(return_value=True), 100)
        emulator.credential_action.assert_called_once_with("pin")
        emulator.command.assert_not_called()

    def test_unready_stream_denies_credential_action(self):
        emulator = self.emulator()
        emulator.credential_action = Mock()
        with self.assertRaisesRegex(ui.Error, "LIVE_UI_NATIVE_NOT_READY"):
            emulator.credential_return(Mock(return_value=False), 100)
        emulator.credential_action.assert_not_called()

    def test_tail_arriving_after_window_probe_denies_actual_pin_send(self):
        emulator = self.emulator()
        emulator.system_uids = Mock(return_value=(1000, 1001))
        watch = Mock(side_effect=[True, False])
        with patch.object(ui.platform, "credential_window") as window, patch.object(ui.platform.GuardedEmulator, "send_pin") as send:
            with self.assertRaisesRegex(ui.Error, "LIVE_UI_NATIVE_NOT_READY"):
                emulator.credential_return(watch, 100)
        window.assert_called_once()
        send.assert_not_called()
        emulator.command.assert_called_once_with("shell", "dumpsys", "window", "-a", timeout=5)
        self.assertIsNone(emulator._credential_watch)

    def test_returned_app_focus_and_owner_share_one_bounded_full_snapshot(self):
        emulator = self.emulator()
        emulator.credential_action = Mock()
        window = (f"  Window #0 Window{{a1 u0 {ui.platform.MAIN}}}:\n"
                  f"    mOwnerUid=10234 showForAllUsers=false package={ui.base.PACKAGE} appop=NONE\n"
                  f"  mCurrentFocus=Window{{a1 u0 {ui.platform.MAIN}}}\n")
        emulator.command.side_effect = [window, f"package:{ui.base.PACKAGE} uid:10234\n",
            'User "Owner" (id=0, flags=1) (current): deviceLocked=0, trusted=0']
        with patch.object(ui.time, "monotonic", return_value=1):
            emulator.credential_return(Mock(return_value=True), 10)
        first = emulator.command.call_args_list[0]
        self.assertEqual(first.args, ("shell", "dumpsys", "window", "-a"))
        self.assertEqual(first.kwargs, {"timeout": 5})
        self.assertEqual(emulator.command.call_count, 3)
        emulator.credential_action.assert_called_once_with("pin")


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.invocation = Mock(deadline=370.0)
        self.invocation.watch.return_value = True
        self.emulator = Mock()
        self.emulator.mapping.return_value = {ui.base.ENDPOINT: ui.base.ENDPOINT}
        self.proof = Mock()
        self.proof.inspect.side_effect = lambda enrolled, effects, done=False: {"jobs_done": effects}
        self.evidence = {"stage": "starting", "phases": []}
        self.protocol = ui.Protocol(self.emulator, self.proof, self.invocation, RUN, self.evidence,
                                    clock=lambda: self.now, sleep=lambda _: None)

    def test_full_ordered_protocol_acks_once_and_requires_native_completion(self):
        for number in range(1, 14):
            self.emulator.read_phase.return_value = phase(number)
            self.assertEqual(self.protocol.tick(), number == 13)
        self.assertEqual(self.emulator.acknowledge.call_count, 13)
        self.assertEqual(self.emulator.disconnect.call_count, 1)
        self.assertEqual(self.emulator.reconnect.call_count, 1)
        self.assertEqual(self.emulator.credential_return.call_count, 2)
        self.assertEqual(len(self.evidence["phases"]), 13)
        self.assertNotIn(RUN, json.dumps(self.evidence))
        self.invocation.finish.assert_not_called()

    def test_unchanged_poll_never_repeats_action_or_ack(self):
        self.emulator.read_phase.return_value = phase(1)
        self.protocol.tick()
        self.protocol.tick()
        self.emulator.acknowledge.assert_called_once_with(RUN, 1)

    def test_backward_skipped_and_foreign_run_phases_fail_before_ack(self):
        for raw in (phase(3), phase(1, run="f" * 32)):
            self.emulator.read_phase.return_value = raw
            with self.assertRaises(ui.Error):
                self.protocol.tick()
        self.protocol.sequence = 2
        self.emulator.read_phase.return_value = phase(1)
        with self.assertRaises(ui.Error):
            self.protocol.tick()
        self.emulator.acknowledge.assert_not_called()

    def test_absence_only_allowed_before_first_phase(self):
        self.emulator.read_phase.return_value = "absent"
        self.assertFalse(self.protocol.tick())
        self.protocol.sequence = 1
        with self.assertRaises(ui.Error):
            self.protocol.tick()

    def test_no_phase_ack_before_exact_instrumentation_start(self):
        self.invocation.watch.return_value = False
        self.assertFalse(self.protocol.tick())
        self.emulator.read_phase.assert_not_called()

    def test_start_ready_then_pending_tail_before_phase_denies_all_effects(self):
        for number in (1, 2, 3, 6, 10):
            with self.subTest(number=number):
                self.setUp()
                self.protocol.sequence = number - 1
                self.emulator.read_phase.return_value = phase(number)
                self.invocation.watch.side_effect = [True, False]
                with self.assertRaisesRegex(ui.Error, "LIVE_UI_NATIVE_NOT_READY"):
                    self.protocol.tick()
                self.emulator.credential_return.assert_not_called()
                self.emulator.disconnect.assert_not_called()
                self.emulator.reconnect.assert_not_called()
                self.emulator.acknowledge.assert_not_called()

    def test_pending_tail_after_server_check_denies_tunnel_mutation(self):
        for number in (3, 10):
            with self.subTest(number=number):
                self.setUp()
                self.protocol.sequence = number - 1
                self.emulator.read_phase.return_value = phase(number)
                self.invocation.watch.side_effect = [True, True, False]
                with self.assertRaisesRegex(ui.Error, "LIVE_UI_NATIVE_NOT_READY"):
                    self.protocol.tick()
                self.emulator.disconnect.assert_not_called()
                self.emulator.reconnect.assert_not_called()
                self.emulator.acknowledge.assert_not_called()

    def test_pending_tail_after_completed_action_denies_ack(self):
        self.emulator.read_phase.return_value = phase(1)
        self.invocation.watch.side_effect = [True, True, True, False]
        with self.assertRaisesRegex(ui.Error, "LIVE_UI_NATIVE_NOT_READY"):
            self.protocol.tick()
        self.emulator.acknowledge.assert_not_called()

    def test_expired_deadline_or_native_exit_denies_actions(self):
        self.now = 41
        with self.assertRaises(ui.Error):
            self.protocol.tick()
        self.emulator.read_phase.assert_not_called()
        self.now = 10
        self.invocation.watch.side_effect = ui.Error("LIVE_UI_NATIVE_EARLY_EXIT")
        with self.assertRaises(ui.Error):
            self.protocol.tick()

    def test_bad_server_effect_never_receives_ack_or_reconnect(self):
        self.protocol.sequence = 9
        self.emulator.read_phase.return_value = phase(10)
        self.proof.inspect.side_effect = ui.Error("LIVE_UI_SERVER_COUNTS")
        with self.assertRaises(ui.Error):
            self.protocol.tick()
        self.emulator.acknowledge.assert_not_called()
        self.emulator.reconnect.assert_not_called()

    def test_processing_wait_is_bounded_and_cannot_hide_extra_effect(self):
        self.protocol.sequence = 10
        self.emulator.read_phase.return_value = phase(11)
        self.proof.inspect.side_effect = [{"jobs_done": 0}, ui.Error("LIVE_UI_SERVER_COUNTS")]
        with self.assertRaises(ui.Error):
            self.protocol.tick()
        self.emulator.acknowledge.assert_not_called()

    def test_processing_wait_cannot_extend_phase_deadline(self):
        self.protocol.sequence = 10
        self.emulator.read_phase.return_value = phase(11)
        self.proof.inspect.return_value = {"jobs_done": 0}
        self.proof.inspect.side_effect = None
        self.protocol.sleep = lambda _: setattr(self, "now", self.now + 100)
        with self.assertRaisesRegex(ui.Error, "LIVE_UI_PHASE_DEADLINE"):
            self.protocol.tick()
        self.emulator.acknowledge.assert_not_called()

    def test_completion_marker_without_native_pass_cannot_pass(self):
        self.protocol.sequence = 12
        self.emulator.read_phase.return_value = phase(13)
        self.invocation.finish.side_effect = ui.Error("LIVE_UI_NATIVE_FAILED")
        with self.assertRaises(ui.Error):
            self.protocol.run_all()

    def test_phase_deadline_never_extends_whole_method_deadline(self):
        self.protocol.deadline = 370
        self.now = 360
        self.emulator.read_phase.return_value = phase(1)
        self.protocol.tick()
        self.assertEqual(self.protocol.deadline, 370)


class InvocationTests(unittest.TestCase):
    def invocation(self):
        value = ui.Invocation(Mock(), RUN, 1000, clock=lambda: 0)
        value.child = Mock()
        value.child.poll.return_value = None
        value.output = Mock(failed=False, data=bytearray(status(1).encode()))
        value.errors = Mock(failed=False)
        return value

    def test_new_360s_bound_does_not_change_original_helper(self):
        self.assertEqual(ui.Invocation(Mock(), RUN, 500, clock=lambda: 100).deadline, 460)
        self.assertEqual(ui.Invocation(Mock(), RUN, 200, clock=lambda: 100).deadline, 200)
        with self.assertRaisesRegex(ui.Error, "EMULATOR_COMMAND_BOUND"):
            ui.base.run_bounded([], timeout=360)

    def test_partial_utf8_waits_for_complete_line_but_invalid_final_fails(self):
        value = self.invocation()
        value.output.data.extend(b"\xc3")
        self.assertFalse(value.watch())
        with self.assertRaises(ui.Error):
            value.raw(final=True)

    def test_pending_byte_tail_survives_prefix_decoding_at_every_split(self):
        value = self.invocation()
        for tail in (b"INSTRUMENTATION_CODE: -1\n", b"INSTRUMENTATION_STATUS: stack=PRIVATE\n",
                     "progress: \u00e9\n".encode()):
            for split in range(1, len(tail)):
                value.output.data = bytearray(status(1).encode() + tail[:split])
                with self.subTest(length=len(tail), split=split):
                    self.assertFalse(value.watch())
                    self.assertTrue(value.pending_tail)
        value.output.data = bytearray(status(1).encode() + "progress: \u00e9\n".encode())
        self.assertTrue(value.watch())
        self.assertFalse(value.pending_tail)

    def test_bounded_output_and_dead_child_fail_before_progress(self):
        value = self.invocation()
        value.output.failed = True
        with self.assertRaises(ui.Error):
            value.watch()
        value.output.failed = False
        value.child.poll.return_value = 1
        with self.assertRaises(ui.Error):
            value.watch()

    def test_cleanup_targets_only_held_child_and_requires_join(self):
        value = self.invocation()
        value.child.poll.side_effect = [None, 0]
        thread = Mock()
        thread.is_alive.return_value = False
        value.threads = [thread]
        value.__exit__(None, None, None)
        value.child.kill.assert_called_once()
        value.child.wait.assert_called_once_with(timeout=5)
        thread.join.assert_called_once_with(timeout=2)
        self.assertTrue(value.closed)

    def test_body_and_cleanup_failures_remain_distinct(self):
        value = MagicMock()
        value.__exit__.side_effect = RuntimeError("PRIVATE_CLEANUP_CANARY")
        evidence = {"stage": "initial_queued"}
        with self.assertRaises(RuntimeError):
            with ui.observed_invocation(value, evidence):
                raise ui.Error("LIVE_UI_PHASE_ORDER")
        self.assertEqual(evidence["native_body_failure"]["exception_class"], "EmulatorError")
        self.assertEqual(evidence["native_cleanup_failure"]["exception_class"], "RuntimeError")
        self.assertFalse(evidence["native_client_cleanup_passed"])
        self.assertNotIn("CANARY", json.dumps(evidence))

    def test_failed_entry_never_claims_successful_cleanup(self):
        value = MagicMock()
        value.__enter__.side_effect = RuntimeError("PRIVATE_CANARY")
        evidence = {"stage": "native_start"}
        with self.assertRaises(RuntimeError):
            with ui.observed_invocation(value, evidence):
                self.fail("must not enter")
        self.assertNotIn("native_client_cleanup_passed", evidence)
        value.__exit__.assert_not_called()

    def test_real_entry_thread_failure_and_cleanup_failure_keep_both_attributions(self):
        emulator = Mock()
        emulator.tools.adb = "owned-adb.exe"
        emulator.target = {"transport": "1"}
        child = Mock()
        child.poll.return_value = None
        child.kill.side_effect = RuntimeError("PRIVATE_KILL_FAILURE")
        worker = Mock()
        worker.start.side_effect = ValueError("PRIVATE_START_FAILURE")
        evidence = {"stage": "native_start"}
        value = ui.Invocation(emulator, RUN, 1000, clock=lambda: 0)
        with patch.object(ui.subprocess, "Popen", return_value=child), patch.object(ui.threading, "Thread", return_value=worker):
            with self.assertRaisesRegex(ui.Error, "LIVE_UI_CLIENT_CLEANUP"):
                with ui.observed_invocation(value, evidence):
                    self.fail("entry must fail")
        self.assertEqual(evidence["native_body_failure"]["exception_class"], "ValueError")
        self.assertEqual(evidence["native_cleanup_failure"]["exception_class"], "EmulatorError")
        self.assertFalse(evidence["native_client_cleanup_passed"])
        self.assertNotIn("PRIVATE", json.dumps(evidence))
        child.kill.assert_called_once()

    def test_real_pipe_reader_bounds_memory(self):
        read_fd, write_fd = os.pipe()
        reader = ui.platform.StreamingOutput(os.fdopen(read_fd, "rb"), 64)
        thread = threading.Thread(target=reader.read, daemon=True)
        thread.start()
        try:
            os.write(write_fd, b"x" * 65)
        finally:
            os.close(write_fd)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(reader.failed)
        self.assertEqual(len(reader.data), 64)

    def test_real_pipe_start_is_visible_while_writer_is_still_open(self):
        read_fd, write_fd = os.pipe()
        reader = ui.platform.StreamingOutput(os.fdopen(read_fd, "rb"), 4096)
        thread = threading.Thread(target=reader.read, daemon=True)
        thread.start()
        try:
            os.write(write_fd, status(1).encode())
            deadline = time.monotonic() + 2
            while len(reader.data) < len(status(1).encode()) and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(thread.is_alive())
            self.assertTrue(ui.native_started(bytes(reader.data).decode()))
        finally:
            os.close(write_fd)
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_launcher_uses_only_owned_transport_exact_class_and_nonce(self):
        emulator = Mock()
        emulator.tools.adb = "owned-adb.exe"
        emulator.target = {"transport": "19"}
        child = Mock()
        child.poll.return_value = 0
        thread = Mock()
        thread.is_alive.return_value = False
        value = ui.Invocation(emulator, RUN, 1000, clock=lambda: 0)
        with patch.object(ui.subprocess, "Popen", return_value=child) as launch, patch.object(ui.threading, "Thread", return_value=thread):
            with ui.observed_invocation(value, {"stage": "native_start"}):
                pass
        emulator.identity.assert_called_once()
        command = launch.call_args.args[0]
        self.assertEqual(command, ["owned-adb.exe", "-t", "19", "shell", "am", "instrument", "-w", "-r",
            "-e", "class", ui.TEST_CLASS + "#" + ui.METHOD, "-e", "ownedEmulator", "true", "-e", "runId", RUN,
            f"{ui.base.TEST_PACKAGE}/{ui.base.RUNNER}"])
        self.assertEqual(launch.call_args.kwargs["stdin"], ui.subprocess.DEVNULL)


class PayloadTests(unittest.TestCase):
    def test_exact_payload_and_production_time_window(self):
        now = datetime(2026, 10, 19, 7, 0, tzinfo=timezone.utc)
        payload = {**ui.EXPECTED_EDITED, "observed_at": "2026-10-19T07:00:00Z"}
        digest = lambda x: hashlib.sha256(json.dumps(x, sort_keys=True).encode()).hexdigest()
        ui.payload_check(payload, now, digest(payload), now - timedelta(seconds=10), now, digest)
        for actual in ({**payload, "narrative": "wrong source"}, {**payload, "extra": True},
                       {**payload, "observed_at": "2026-10-19T07:00:00+00:00"},
                       {**payload, "observed_at": "2026-99-19T07:00:00Z"}):
            with self.assertRaises(ui.Error):
                ui.payload_check(actual, now, digest(actual), now, now, digest)
        for observed, start, end, expected_hash in ((now + timedelta(seconds=1), now, now, digest(payload)),
                (now, now + timedelta(seconds=6), now + timedelta(seconds=10), digest(payload)),
                (now, now - timedelta(seconds=30), now - timedelta(seconds=6), digest(payload)),
                (now, now, now, "wrong")):
            with self.assertRaises(ui.Error):
                ui.payload_check(payload, observed, expected_hash, start, end, digest)


class OwnershipTests(unittest.TestCase):
    def test_directory_adoption_marker_mutation_and_path_escape_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = root / ".cache/m1-runtime/mobile-live-ui" / ("a" * 24)
            run.parent.mkdir(parents=True)
            with patch.object(ui, "ROOT", root), patch.object(ui.base, "ROOT", root):
                with ui.RunOwnership(run) as lease:
                    with self.assertRaises(ui.Error):
                        ui.RunOwnership(run).__enter__()
                    lease.path.write_bytes(b"changed")
                    with self.assertRaises(ui.Error):
                        lease.assert_owned()
                with self.assertRaises(ui.Error):
                    ui.RunOwnership(root / "other" / ("b" * 24))

    def test_both_run_and_database_ownership_are_required(self):
        lease, harness = Mock(spec=["assert_owned"]), Mock(spec=["assert_owned"])
        ownership = ui.CombinedOwnership(lease, harness)
        ownership.assert_owned()
        lease.assert_owned.assert_called_once()
        harness.assert_owned.assert_called_once()
        lease.assert_owned.side_effect = ui.Error("A11Y_RUN_OWNERSHIP_LOST")
        harness.reset_mock()
        with self.assertRaises(ui.Error):
            ownership.assert_owned()
        harness.assert_owned.assert_not_called()

    def test_unfrozen_or_changed_sources_refuse_before_tools_or_database(self):
        for frozen in ({"some": None}, {"some": "a" * 64}):
            with patch.object(ui, "FROZEN", frozen), patch.object(ui.base, "digest", return_value="b" * 64), \
                    patch.object(ui.base, "AndroidTools") as tools, patch.object(ui.base, "observed_harness") as harness:
                with self.assertRaises(ui.Error):
                    ui.execute("app", "hash", "test", "hash")
                tools.assert_not_called()
                harness.assert_not_called()

    def test_disappeared_or_changed_source_is_false_without_losing_result_metadata(self):
        with patch.object(ui.base, "digest", side_effect=FileNotFoundError("PRIVATE_PATH")):
            self.assertFalse(ui.sources_unchanged({"source": "expected"}))
        with patch.object(ui.base, "digest", return_value="other"):
            self.assertFalse(ui.sources_unchanged({"source": "expected"}))
        with patch.object(ui.base, "digest", return_value="expected"):
            self.assertTrue(ui.sources_unchanged({"source": "expected"}))


class MemoryManager:
    """Only the query operations used by ServerProof; there is no DB adapter."""
    def __init__(self, rows):
        self.rows = rows

    def count(self):
        return len(self.rows)

    def select_related(self, *names):
        return self

    def filter(self, **fields):
        return MemoryManager([row for row in self.rows if all(getattr(row, key) == value for key, value in fields.items())])

    def get(self, **fields):
        rows = self.filter(**fields).rows if fields else self.rows
        if len(rows) != 1:
            raise ValueError("memory fixture expects exactly one row")
        return rows[0]


class ServerProofTests(unittest.TestCase):
    def prepare(self):
        item = types.SimpleNamespace
        now = datetime.now(timezone.utc).replace(microsecond=0)
        self.payload = {**ui.EXPECTED_EDITED, "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        self.digest = lambda value: hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.org = item(id="organization", code="SIM-ORG-01", active=True)
        self.actor = item(id="actor", username="submitter", is_active=True, role="submitter", organization=self.org, organization_id=self.org.id)
        self.unit = item(id="unit", active=True, code="SIM-UNIT-01", organization_id=self.org.id)
        self.membership = item(user=self.actor, role="submitter", active=True, valid_until=None, organization_id=self.org.id, unit=self.unit, unit_id=self.unit.id)
        self.enrollment = item(id="enrollment", owner_id=self.actor.id, organization_id=self.org.id, revoked_at=None)
        self.report = item(id="report", organization_id=self.org.id, author_id=self.actor.id, unit_id=self.unit.id, current_revision_no=1)
        self.revision = item(id="revision", report_id=self.report.id, report=self.report, organization_id=self.org.id,
            submitted_by_id=self.actor.id, accepted_device_id=self.enrollment.id, revision_no=1,
            template_version="demo-maintenance-v1", observed_at=now, content_digest=self.digest(self.payload),
            operation_id="operation", processing_state="AWAITING_REVIEW")
        request = {"operation_id": self.revision.operation_id, "report_id": self.report.id,
                   "expected_revision": 0, "template_version": "demo-maintenance-v1", "payload": self.payload}
        self.revision.request_hash = self.digest({"route": "POST /sync/operations/", "body": request})
        def receipt_body(revision):
            return {"operation_id": revision.operation_id, "report_id": revision.report_id, "revision_id": revision.id,
                    "revision_no": revision.revision_no, "delivery_status": "RECEIVED", "processing_status": "PENDING", "shared": False}
        self.receipt = item(id="receipt", organization_id=self.org.id, accepted_user_id=self.actor.id,
            accepted_device_id=self.enrollment.id, revision_id=self.revision.id, operation_id=self.revision.operation_id,
            request_hash=self.revision.request_hash, response_body=receipt_body(self.revision))
        self.job = item(id="job", organization_id=self.org.id, revision_id=self.revision.id, status="DONE")
        self.rows = {"User": [self.actor], "UnitMembership": [self.membership], "DeviceEnrollment": [self.enrollment],
                     "Report": [self.report], "ReportRevision": [self.revision], "SyncReceipt": [self.receipt],
                     "ProcessingJob": [self.job], "ReviewDecision": [], "Publication": []}
        self.modules = {}
        for module, names in {
            "apps.accounts.models": ("User", "DeviceEnrollment"), "apps.operations.models": ("ProcessingJob", "SyncReceipt"),
            "apps.publications.models": ("Publication",), "apps.review.models": ("ReviewDecision",),
            "apps.reports.models": ("Report", "ReportRevision"), "apps.scopes.models": ("UnitMembership",),
        }.items():
            self.modules[module] = item(**{name: item(objects=MemoryManager(self.rows[name])) for name in names})
        self.modules["apps.reports.crypto"] = item(source_payload=lambda revision: self.payload, digest=self.digest)
        self.modules["apps.reports.services"] = item(receipt_body=receipt_body)
        self.harness = Mock(spec=["assert_owned"])
        self.proof = ui.ServerProof(self.harness)
        self.proof.started = now - timedelta(seconds=10)

    def inspect(self, enrolled=True, effects=1, done=True):
        with patch.dict(ui.sys.modules, self.modules):
            return self.proof.inspect(enrolled, effects, done)

    def test_complete_original_source_and_receipt_binding_returns_counts_only(self):
        self.prepare()
        counts = self.inspect()
        self.assertEqual(counts, {"enrollments": 1, "reports": 1, "revisions": 1, "receipts": 1,
                                 "jobs": 1, "jobs_done": 1, "decisions": 0, "publications": 0})
        self.assertTrue(all(type(value) is int for value in counts.values()))
        self.harness.assert_owned.assert_called_once()

    def test_new_database_and_enrollment_only_require_zero_effects(self):
        self.prepare()
        for name in ("Report", "ReportRevision", "SyncReceipt", "ProcessingJob"):
            self.rows[name].clear()
        self.inspect(True, 0, False)
        self.rows["DeviceEnrollment"].clear()
        self.inspect(False, 0, False)
        self.rows["Publication"].append(types.SimpleNamespace())
        with self.assertRaises(ui.Error):
            self.inspect(False, 0, False)

    def test_wrong_scope_actor_device_revision_operation_and_receipt_binding_rejected(self):
        mutations = [
            ("org", "code", "OTHER"), ("org", "active", False), ("actor", "role", "reviewer"),
            ("actor", "is_active", False), ("membership", "organization_id", "foreign"),
            ("membership", "valid_until", datetime.now(timezone.utc)), ("unit", "active", False),
            ("unit", "organization_id", "foreign"), ("unit", "code", "OTHER"),
            ("enrollment", "owner_id", "foreign"), ("enrollment", "revoked_at", datetime.now(timezone.utc)),
            ("revision", "organization_id", "foreign"), ("report", "organization_id", "foreign"),
            ("receipt", "organization_id", "foreign"), ("job", "organization_id", "foreign"),
            ("revision", "submitted_by_id", "foreign"), ("report", "author_id", "foreign"),
            ("receipt", "accepted_user_id", "foreign"), ("revision", "accepted_device_id", "foreign"),
            ("receipt", "accepted_device_id", "foreign"), ("report", "unit_id", "foreign"),
            ("revision", "revision_no", 2), ("report", "current_revision_no", 2),
            ("revision", "template_version", "other"), ("receipt", "revision_id", "foreign"),
            ("job", "revision_id", "foreign"), ("receipt", "operation_id", "foreign"),
            ("receipt", "request_hash", "wrong"), ("receipt", "response_body", {"shared": True}),
        ]
        for target, field, value in mutations:
            with self.subTest(target=target, field=field):
                self.prepare()
                setattr(getattr(self, target), field, value)
                with self.assertRaises(ui.Error):
                    self.inspect()

    def test_duplicate_extra_publication_and_decision_counts_fail(self):
        for name in ("DeviceEnrollment", "Report", "ReportRevision", "SyncReceipt", "ProcessingJob", "ReviewDecision", "Publication"):
            with self.subTest(name=name):
                self.prepare()
                self.rows[name].append(self.rows[name][0] if self.rows[name] else types.SimpleNamespace())
                with self.assertRaises(ui.Error):
                    self.inspect()

    def test_pending_allowed_but_failed_or_incomplete_processing_is_not_done(self):
        for status in ("PENDING", "PROCESSING"):
            self.prepare()
            self.job.status = status
            self.assertEqual(self.inspect(done=False)["jobs_done"], 0)
            with self.assertRaises(ui.Error):
                self.inspect(done=True)
        for status in ("FAILED", "UNKNOWN"):
            self.prepare()
            self.job.status = status
            with self.assertRaises(ui.Error):
                self.inspect(done=False)
        self.prepare()
        self.revision.processing_state = "PROCESSING"
        with self.assertRaises(ui.Error):
            self.inspect()

    def test_content_hash_and_immutable_request_hash_are_independently_checked(self):
        for kind in ("payload", "content_digest", "request_hash"):
            with self.subTest(kind=kind):
                self.prepare()
                if kind == "payload":
                    self.payload["site_label"] = "changed private source"
                elif kind == "content_digest":
                    self.revision.content_digest = "wrong"
                else:
                    self.revision.request_hash = self.receipt.request_hash = "wrong"
                with self.assertRaises(ui.Error):
                    self.inspect()

    def test_enrollment_or_acceptance_identity_cannot_change_between_stages(self):
        for target in ("enrollment", "receipt", "job"):
            with self.subTest(target=target):
                self.prepare()
                self.inspect()
                getattr(self, target).id = "replacement"
                with self.assertRaises(ui.Error):
                    self.inspect()

    def test_lost_harness_ownership_denied_before_database_read(self):
        self.prepare()
        self.harness.assert_owned.side_effect = ui.Error("MOBILE_DATABASE_OWNERSHIP_LOST")
        self.modules["apps.accounts.models"].DeviceEnrollment.objects = Mock()
        with self.assertRaises(ui.Error):
            self.inspect()
        self.modules["apps.accounts.models"].DeviceEnrollment.objects.count.assert_not_called()



class NativeFailureStageTests(unittest.TestCase):
    def test_only_a_single_known_stage_token_is_returned(self):
        raw = "INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: MOBILE_LIVE_UI_FAILED_activity_recreation\n\tat x\n"
        self.assertEqual(ui.native_failure_stage(raw), "activity_recreation")
        self.assertEqual(ui.native_failure_stage(raw + raw), "activity_recreation")
        self.assertEqual(ui.native_failure_stage(raw.replace("activity_recreation", "reopen_prompt")), "reopen_prompt")

    def test_unknown_ambiguous_or_absent_tokens_are_not_echoed(self):
        for raw in ("", None, "stack=MOBILE_LIVE_UI_FAILED_secret_canary_value", "MOBILE_LIVE_UI_FAILED_draft_edit MOBILE_LIVE_UI_FAILED_draft_create",
                    "MOBILE_LIVE_UI_FAILED_draft_editX", "MOBILE_LIVE_UI_FAILED_DRAFT_EDIT"):
            with self.subTest(raw=raw):
                self.assertEqual(ui.native_failure_stage(raw), "UNKNOWN")

    def test_observed_invocation_records_stage_only_for_native_failure(self):
        invocation = MagicMock()
        invocation.raw.return_value = "stack=AssertionError: MOBILE_LIVE_UI_FAILED_activity_recreation\nPRIVATE_CANARY\n"
        evidence = {"stage": "draft_saved"}
        with self.assertRaisesRegex(ui.Error, "LIVE_UI_NATIVE_FAILED"):
            with ui.observed_invocation(invocation, evidence):
                raise ui.Error("LIVE_UI_NATIVE_FAILED")
        self.assertEqual(evidence["native_failure_stage"], "activity_recreation")
        self.assertNotIn("PRIVATE_CANARY", json.dumps(evidence))
        invocation.raw.assert_called_once_with(final=True)
        other = {"stage": "draft_saved"}
        with self.assertRaises(ui.Error):
            with ui.observed_invocation(MagicMock(), other):
                raise ui.Error("LIVE_UI_PHASE_DEADLINE")
        self.assertNotIn("native_failure_stage", other)

    def test_raw_failure_is_reported_as_unavailable(self):
        invocation = MagicMock()
        invocation.raw.side_effect = ui.Error("LIVE_UI_OUTPUT_BOUND")
        evidence = {"stage": "draft_saved"}
        with self.assertRaises(ui.Error):
            with ui.observed_invocation(invocation, evidence):
                raise ui.Error("LIVE_UI_NATIVE_FAILED")
        self.assertEqual(evidence["native_failure_stage"], "UNAVAILABLE")

    def test_main_hands_off_to_backend_venv_like_other_hosts(self):
        source = (ui.ROOT / "infra/mobile_live_ui.py").read_text(encoding="utf-8").split("def main():", 1)[1]
        self.assertLess(source.index("local.python_path()"), source.index("execute(args.app"))
        self.assertIn("managed_environment()", source)


if __name__ == "__main__":
    unittest.main()
