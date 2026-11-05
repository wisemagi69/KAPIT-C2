"""TASK095 pure guards. No Android, database, server or emulator is launched."""
import copy
import io
import json
import os
from pathlib import Path
import threading
import unittest
from unittest.mock import MagicMock, Mock, patch

from infra import mobile_platform as platform

PACKAGE = platform.PACKAGE
UID = 10234
PID = 4321
PREP = platform.CASES["abrupt"][0]
VERIFY = platform.CASES["abrupt"][1]


def marker(code, method=PREP, cls=platform.PLATFORM_CLASS):
    return (f"INSTRUMENTATION_STATUS: class={cls}\nINSTRUMENTATION_STATUS: test={method}\n"
            f"INSTRUMENTATION_STATUS: current=1\nINSTRUMENTATION_STATUS: numtests=1\n"
            f"INSTRUMENTATION_STATUS_CODE: {code}\n")


def package_dump(stopped=False):
    return (f"Packages:\n  Package [{PACKAGE}] (abc):\n    appId={UID}\n"
            f"    User 0: installed=true hidden=false suspended=false stopped={str(stopped).lower()} enabled=0\n")


def window(title, uid, token="a1"):
    package = title.split('/')[0] if '/' in title else 'com.android.systemui'
    return (f"  Window #0 Window{{{token} u0 {title}}}:\n"
            f"    mOwnerUid={uid} showForAllUsers=false package={package} appop=NONE\n"
            f"  mCurrentFocus=Window{{{token} u0 {title}}}\n")


def counts(effects, done=None):
    return dict(enrollments=1, revisions=effects, receipts=effects, jobs=effects,
                jobs_done=effects if done is None else done)


def prerequisites():
    def passed(method):
        return dict(method=method, passed=True, method_completed_count=1)
    return dict(phases=[passed(value[0]) for value in platform.base.PHASES], worker_completed=True,
                system_credential=dict(passed=True, handshake=dict(completed=True)),
                background_delivery=dict(passed=True, phases=[passed(value) for value in platform.base.BACKGROUND_METHODS]))


class IdentityTests(unittest.TestCase):
    def test_unique_user_zero_application_uid(self):
        self.assertEqual(platform.package_uid(f"package:{PACKAGE} uid:{UID}\npackage:{PACKAGE}.test uid:10235\n"), UID)

    def test_shared_application_uid_is_refused(self):
        with self.assertRaisesRegex(platform.Error, "SHARED_UID"):
            platform.package_uid(f"package:{PACKAGE} uid:{UID}\npackage:other uid:{UID}\n")

    def test_system_window_owner_may_have_platform_shared_uid(self):
        self.assertEqual(platform.package_uid("package:com.android.settings uid:1000\npackage:android uid:1000\n",
                                             "com.android.settings"), 1000)

    def test_missing_duplicate_wrong_user_system_app_and_malformed_uid_are_refused(self):
        for raw in ["", f"package:{PACKAGE} uid:1010234\n", f"package:{PACKAGE} uid:1000\n",
                    f"package:{PACKAGE} uid:{UID}\n" * 2, f"package:{PACKAGE} uid:no\n", "private unknown output"]:
            with self.subTest(raw=raw), self.assertRaises(platform.Error):
                platform.package_uid(raw)

    def test_package_stopped_is_not_process_absence(self):
        self.assertFalse(platform.package_stopped(package_dump(), UID))
        self.assertTrue(platform.package_stopped(package_dump(True), UID))

    def test_package_state_rejects_wrong_owner_user_and_duplicate_state(self):
        raw = package_dump()
        for value in [raw.replace(str(UID), "99999"), raw.replace("User 0", "User 10"), raw + raw,
                      raw.replace("installed=true", "installed=false"), raw.replace("hidden=false", "hidden=true"),
                      raw.replace("stopped=false", "stopped=false stopped=true"), raw.replace(PACKAGE, "other.app"),
                      raw.replace("stopped=false", "stopped=true stopped=falsex"),
                      raw.replace("stopped=false", "stopped=true stopped="),
                      raw.replace("stopped=false", "stopped=true stopped =false")]:
            with self.subTest(value=value), self.assertRaises(platform.Error):
                platform.package_stopped(value, UID)

    def test_process_table_requires_exact_name_and_uid(self):
        self.assertEqual(platform.owned_pid(f"PID UID NAME\n1 0 init\n{PID} {UID} {PACKAGE}\n", UID), PID)
        self.assertIsNone(platform.owned_pid("PID UID NAME\n1 0 init\n", UID))

    def test_process_table_rejects_ambiguous_side_process_wrong_owner_and_non_numeric_uid(self):
        for raw in [f"PID UID NAME\n{PID} {UID} {PACKAGE}\n4333 {UID} {PACKAGE}\n",
                    f"PID UID NAME\n{PID} {UID} {PACKAGE}:other\n",
                    f"PID UID NAME\n{PID} 99999 {PACKAGE}\n",
                    f"PID UID NAME\n{PID} u0_a234 {PACKAGE}\n", "USER PID NAME\n", ""]:
            with self.subTest(raw=raw), self.assertRaises(platform.Error):
                platform.owned_pid(raw, UID)

    def test_process_start_identity_is_exact(self):
        self.assertEqual(platform.process_identity(f"KAPIT_PROCESS {PID} {UID} 12345\n", PID, UID),
                         platform.ProcessIdentity(PID, UID, 12345))
        for raw in [f"KAPIT_PROCESS {PID} {UID} 0\n", f"KAPIT_PROCESS {PID + 1} {UID} 12345\n",
                    f"KAPIT_PROCESS {PID} {UID + 1} 12345\n", f"KAPIT_PROCESS {PID} {UID} 12345\n" * 2]:
            with self.assertRaises(platform.Error):
                platform.process_identity(raw, PID, UID)

    def test_kill_script_rechecks_uid_cmdline_and_start_before_numeric_sigkill(self):
        script = platform.process_script(PID, UID, 12345, kill=True).decode("ascii")
        self.assertIn("id -u", script)
        self.assertIn("/proc/$p/status", script)
        self.assertIn("/proc/$p/cmdline", script)
        self.assertIn("t=${20}", script)
        self.assertLess(script.index("test \"$t\" = '12345'"), script.index('kill -KILL "$p"'))
        self.assertNotIn("killall", script)
        self.assertNotIn("am force-stop", script)

    def test_kill_requires_valid_captured_identity_and_cannot_inject_shell_code(self):
        for args in [("1; evil", UID, 12), (1, UID, 12), (PID, 1000, 12), (PID, UID, None),
                     (PID, UID, "12; evil"), (True, UID, 12)]:
            with self.assertRaises(platform.Error):
                platform.process_script(*args, kill=True)


class ProtocolTests(unittest.TestCase):
    def test_only_case_specific_bounded_markers_are_allowed(self):
        for value in ["absent", "preparing", "abrupt_ready", "verified", "failed"]:
            self.assertEqual(platform.phase_value(value, "abrupt"), value)
        for value in ["force_stop_ready", "abrupt_ready\n", "x" * 33, "é", ""]:
            with self.assertRaises(platform.Error):
                platform.phase_value(value, "abrupt")

    def test_preparation_requires_actual_start_before_action(self):
        self.assertFalse(platform.preparation_started("", PREP))
        self.assertTrue(platform.preparation_started(marker(1), PREP))

    def test_live_start_split_at_every_pipe_boundary_is_not_a_parser_failure(self):
        raw = marker(1)
        for offset in range(len(raw)):
            self.assertFalse(platform.preparation_started(raw[:offset], PREP))
        self.assertTrue(platform.preparation_started(raw, PREP))
        for suffix in ["INSTRUMENTATION_STATUS_CODE:", "INSTRUMENTATION_CODE: 0", "java.lang.IllegalStateException:"]:
            self.assertFalse(platform.preparation_started(raw + suffix, PREP))
            with self.assertRaises(platform.Error):
                platform.preparation_started(raw + suffix + "\n", PREP)

    def test_preparation_success_failure_foreign_start_and_extra_records_cannot_be_killed(self):
        for raw in [marker(1) + marker(0), marker(1) + "OK (1 test)\n",
                    marker(1) + "INSTRUMENTATION_CODE: 0\n", marker(1, "foreign"), marker(1, cls="other"),
                    marker(1).replace("numtests=1", "numtests=2"), marker(1) + "INSTRUMENTATION_STATUS: stack=private\n"]:
            with self.assertRaises(platform.Error):
                platform.preparation_started(raw, PREP)

    def test_expected_interruption_is_not_native_pass(self):
        raw = marker(1) + "INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n"
        result = platform.expected_interruption(raw, PREP, 0)
        self.assertTrue(result["expected_interruption"])
        self.assertEqual(result["method_completed_count"], 0)
        self.assertNotIn("passed", result)

    def test_interruption_requires_exact_crash_terminal_after_only_start(self):
        raw = marker(1) + "INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n"
        for value, code in [(raw, 1), (raw.replace("Process crashed.", "unknown"), 0),
                            (raw.replace("CODE: 0", "CODE: -1"), 0), (raw + "OK (1 test)\n", 0),
                            (raw + marker(0), 0), (raw.replace("numtests=1", "numtests=2"), 0),
                            (raw + "INSTRUMENTATION_RESULT: shortMsg=Process crashed.\n", 0)]:
            with self.assertRaises(platform.Error):
                platform.expected_interruption(value, PREP, code)

    def test_verification_reuses_strict_base_success_parser(self):
        raw = marker(1, VERIFY) + marker(0, VERIFY) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        result = platform.verification_result(raw, VERIFY)
        self.assertTrue(result["passed"])
        self.assertEqual(result["method_completed_count"], 1)

    def test_verification_adapter_cannot_turn_foreign_or_extra_status_into_success(self):
        raw = marker(1, VERIFY) + marker(0, VERIFY) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        for value in [raw.replace(platform.PLATFORM_CLASS, platform.base.TEST_CLASS), raw + marker(0, VERIFY),
                      raw.replace("numtests=1", "numtests=2"), raw.replace(VERIFY, PREP), raw + "INSTRUMENTATION_STATUS: current=1\n"]:
            with self.assertRaises(platform.Error):
                platform.verification_result(value, VERIFY)

    def test_verification_failure_types_retained_without_messages_and_not_overridden(self):
        raw = marker(1, VERIFY) + marker(-2, VERIFY) + "java.lang.AssertionError: PRIVATE_CANARY\n"
        raw += "FAILURES!!!\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        result = platform.verification_result(raw, VERIFY)
        self.assertFalse(result["passed"])
        self.assertEqual(result["exception_types"], ["java.lang.AssertionError"])
        self.assertNotIn("CANARY", json.dumps(result))

    def test_malformed_extra_status_and_terminal_codes_never_hide_beside_success(self):
        raw = marker(1, VERIFY) + marker(0, VERIFY) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        for extra in ["INSTRUMENTATION_STATUS_CODE: error", "INSTRUMENTATION_CODE: -1 wrong",
                      "INSTRUMENTATION_CODE: 9999", "INSTRUMENTATION_STATUS_CODE : 0"]:
            with self.assertRaises(platform.Error):
                platform.verification_result(raw + extra + "\n", VERIFY)

    def test_standalone_exception_prevents_preparation_and_expected_interruption(self):
        raw = marker(1) + "java.lang.IllegalStateException: PRIVATE_CANARY\n"
        with self.assertRaises(platform.Error):
            platform.preparation_started(raw, PREP)
        with self.assertRaises(platform.Error):
            platform.expected_interruption(raw + "INSTRUMENTATION_RESULT: shortMsg=Process crashed.\nINSTRUMENTATION_CODE: 0\n", PREP, 0)


class CredentialTests(unittest.TestCase):
    def test_window_focus_requires_matching_current_user_owner_record(self):
        title = "com.android.settings/.password.ConfirmLockPassword$InternalActivity"
        self.assertEqual(platform.focus_window(window(title, 1000)), (title, 1000))
        platform.credential_window(window(title, 1000), 1000)

    def test_unknown_window_wrong_user_duplicate_focus_and_wrong_uid_are_refused(self):
        title = "com.android.settings/.password.ConfirmLockPassword$InternalActivity"
        raw = window(title, 1000)
        for value in [raw.replace("u0", "u10"), raw + f"mCurrentFocus=Window{{b2 u0 {title}}}\n",
                      raw.replace("mOwnerUid=1000", "mOwnerUid=9999"), raw.replace("ConfirmLockPassword", "Settings"),
                      raw.replace("Window #0", "Unknown #0")]:
            with self.assertRaises(platform.Error):
                platform.credential_window(value, 1000)

    def test_full_dump_extra_null_focus_and_foreign_window_owner_are_refused(self):
        title = 'com.android.settings/.password.ConfirmLockPassword'
        focus = f'mCurrentFocus=Window{{abc u0 {title}}}\n'
        header = f'  Window #0 Window{{abc u0 {title}}}:\n'
        owner = '    mOwnerUid=1000 showForAllUsers=false package=com.android.settings appop=NONE\n'
        for raw in (focus + header + owner + 'mCurrentFocus=null\n',
                focus + header + '  Window #1 Window{def u10 Other}:\n' + owner,
                focus + header + '  Window #malformed\n' + owner,
                focus + header + owner + '    mOwnerUid=bad\n',
                focus + header + owner + owner,
                (focus + header + owner).replace('package=com.android.settings', 'package=android')):
            with self.subTest(raw=raw), self.assertRaises(platform.Error):
                platform.credential_window(raw, 1000)
            emulator = object.__new__(platform.GuardedEmulator)
            emulator.system_uids = Mock(return_value=(10002, 1000))
            emulator.command = Mock(return_value=raw)
            emulator.send_pin = Mock()
            with self.assertRaises(platform.Error):
                emulator.credential_action('pin')
            emulator.send_pin.assert_not_called()

    def test_trust_requires_one_current_owner_actually_locked(self):
        raw = 'User "Owner" (id=0, flags=1) (current): deviceLocked=1, trusted=0'
        self.assertTrue(platform.locked_owner(raw))
        for value in [raw * 2, raw.replace("=1,", "=0,"), raw.replace("id=0", "id=10"), ""]:
            self.assertFalse(platform.locked_owner(value))

    def test_systemui_prompt_fallback_requires_literal_acceptance_and_keeps_original_refusal(self):
        raw = window("com.android.settings/.Settings", 1000)
        for accepted, expected in ((True, "systemui"), (False, None), (Mock(), None), (1, None)):
            emulator = Mock()
            emulator.systemui_prompt_focus.return_value = accepted
            with self.subTest(accepted=repr(accepted)[:20]):
                if expected:
                    self.assertEqual(platform.credential_target(emulator, raw, 1000), expected)
                else:
                    with self.assertRaisesRegex(platform.Error, "^PLATFORM_CREDENTIAL_WINDOW_DENIED$"):
                        platform.credential_target(emulator, raw, 1000)
        failing = Mock()
        failing.systemui_prompt_focus.side_effect = RuntimeError("PRIVATE_CANARY")
        with self.assertRaisesRegex(platform.Error, "^PLATFORM_CREDENTIAL_WINDOW_DENIED$"):
            platform.credential_target(failing, raw, 1000)

    def test_settings_component_still_decides_first_without_fallback(self):
        emulator = Mock()
        raw = window("com.android.settings/.password.ConfirmLockPassword", 1000)
        self.assertEqual(platform.credential_target(emulator, raw, 1000), "settings")
        emulator.systemui_prompt_focus.assert_not_called()

    def test_prompt_pin_sent_to_systemui_prompt_only_via_accepted_fallback(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.system_uids = Mock(return_value=(10055, 1000))
        emulator.command = Mock(return_value=window("BiometricPrompt", 10055))
        emulator.send_pin = Mock()
        for accepted in (False, True):
            emulator.systemui_prompt_focus = Mock(return_value=accepted)
            if accepted:
                emulator.credential_action("pin")
                emulator.send_pin.assert_called_once_with()
            else:
                with self.assertRaises(platform.Error):
                    emulator.credential_action("pin")
                emulator.send_pin.assert_not_called()

    def test_prompt_pin_not_sent_when_settings_window_is_unrelated(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.system_uids = Mock(return_value=(10002, 1000))
        emulator.command = Mock(return_value=window("com.android.settings/.Settings", 1000))
        emulator.send_pin = Mock()
        with self.assertRaises(platform.Error):
            emulator.credential_action("pin")
        emulator.send_pin.assert_not_called()

    def test_prompt_pin_requires_actual_credential_component_then_protected_path(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.system_uids = Mock(return_value=(10002, 1000))
        emulator.command = Mock(return_value=window("com.android.settings/.password.ConfirmLockPassword", 1000))
        emulator.send_pin = Mock()
        emulator.credential_action("pin")
        emulator.send_pin.assert_called_once_with()
        emulator.command.assert_called_once_with("shell", "dumpsys", "window", "-a", timeout=5)

    def test_device_pin_requires_locked_systemui_window_not_app(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.system_uids = Mock(return_value=(10002, 1000))
        emulator.send_pin = Mock()
        emulator.command = Mock(side_effect=["", "", "", window(PACKAGE + "/.MainActivity", UID)])
        with patch.object(platform, "wait_until"), self.assertRaisesRegex(platform.Error, "KEYGUARD_WINDOW"):
            emulator.device_unlock(99)
        emulator.send_pin.assert_not_called()
        self.assertEqual(emulator.command.call_args.args, ("shell", "dumpsys", "window", "-a"))
        self.assertEqual(emulator.command.call_args.kwargs, {"timeout": 5})

    def test_pin_only_appears_on_owned_stdin_not_argv_or_result(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.pin = "123456"
        emulator.command = Mock(return_value="")
        emulator.send_pin()
        call = emulator.command.call_args
        self.assertNotIn("123456", str(call.args))
        self.assertIn(b"123456", call.kwargs["stdin"])
        self.assertEqual(call.kwargs["timeout"], 5)

    def test_device_pin_also_requires_shared_secure_keyguard_policy_guard(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.system_uids = Mock(return_value=(10002, 1000))
        emulator.send_pin = Mock()
        emulator.command = Mock(side_effect=["", "", "", window("NotificationShade", 10002),
            'User "Owner" (id=0, flags=1) (current): deviceLocked=1, trusted=0'])
        emulator.require_unlock_target = Mock(side_effect=platform.Error("EMULATOR_UNLOCK_TARGET_DENIED"))
        with patch.object(platform, "wait_until"), self.assertRaisesRegex(platform.Error, "UNLOCK_TARGET_DENIED"):
            emulator.device_unlock(99)
        emulator.send_pin.assert_not_called()

    def test_device_unlock_timings_are_fixed_keys_and_bounded(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.pin = "123456"
        emulator.evidence = {}
        emulator.system_uids = Mock(return_value=(10002, 1000))
        emulator.command = Mock(side_effect=["", "", "", window(PACKAGE + "/.MainActivity", UID)] * 10)
        with patch.object(platform, "wait_until"), patch.object(platform.time, "sleep"):
            for _ in range(10):
                with self.assertRaisesRegex(platform.Error, "KEYGUARD_WINDOW"):
                    emulator.device_unlock(10**12)
        timings = emulator.evidence["device_unlock_timings"]
        self.assertEqual(len(timings), 8)
        self.assertEqual(set(timings[0]), {"locked", "swiped", "budget"})
        self.assertNotIn("123456", json.dumps(emulator.evidence))

    def test_ordinary_unlock_retries_only_a_deadline_once(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.device_unlock = Mock(side_effect=[platform.Error("PLATFORM_DEADLINE"), None])
        emulator.unlock()
        self.assertEqual(emulator.device_unlock.call_count, 2)
        emulator.device_unlock = Mock(side_effect=platform.Error("PLATFORM_DEADLINE"))
        with self.assertRaisesRegex(platform.Error, "PLATFORM_DEADLINE"):
            emulator.unlock()
        self.assertEqual(emulator.device_unlock.call_count, platform.UNLOCK_ATTEMPTS)
        for code in ("PLATFORM_KEYGUARD_WINDOW_DENIED", "EMULATOR_UNLOCK_TARGET_DENIED", "PLATFORM_UNLOCK_DEADLINE"):
            emulator.device_unlock = Mock(side_effect=platform.Error(code))
            with self.subTest(code=code), self.assertRaisesRegex(platform.Error, code):
                emulator.unlock()
            self.assertEqual(emulator.device_unlock.call_count, 1)

    def test_reauthorization_timings_use_their_own_bounded_slot(self):
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.pin = "123456"; emulator.evidence = {"device_unlock_timings": [{}] * 8}
        emulator.system_uids = Mock(return_value=(10002, 1000))
        emulator.command = Mock(side_effect=["", "", "", window(PACKAGE + "/.MainActivity", UID)])
        with patch.object(platform, "wait_until"), patch.object(platform.time, "sleep"):
            with self.assertRaisesRegex(platform.Error, "KEYGUARD_WINDOW"):
                emulator.device_unlock(10**12, slot="reauthorization_timings")
        self.assertEqual(len(emulator.evidence["reauthorization_timings"]), 1)
        self.assertEqual(len(emulator.evidence["device_unlock_timings"]), 8)
        source = (platform.ROOT / "infra/mobile_platform.py").read_text(encoding="utf-8")
        self.assertIn('device_unlock(ready_at + REAUTH_DEADLINE_SECONDS, slot="reauthorization_timings")', source)

    def test_results_record_their_own_host_hash(self):
        for name in ("infra/mobile_platform.py", "infra/mobile_emulator.py"):
            body = (platform.ROOT / name).read_text(encoding="utf-8").split("def execute(", 1)[1]
            self.assertIn('"host_sha256": ', body.split("try:", 1)[0])

    def test_device_pin_settles_after_wake_and_swipe_before_guards(self):
        events = []
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.system_uids = Mock(return_value=(10002, 1000))
        replies = iter(["", "", "", window("NotificationShade", 10002),
                        'User "Owner" (id=0, flags=1) (current): deviceLocked=1, trusted=0'])
        def command(*args, **kwargs):
            events.append(args[-1] if args[1] == "input" and args[2] == "keyevent" else args[2])
            return next(replies)
        emulator.command = command
        emulator.require_unlock_target = Mock(side_effect=lambda: events.append("guard"))
        emulator.send_pin = Mock(side_effect=lambda: events.append("pin"))
        with patch.object(platform, "wait_until"), \
                patch.object(platform.time, "sleep", side_effect=lambda seconds: events.append(("settle", seconds))):
            emulator.device_unlock(10**12)
        settle = ("settle", platform.UNLOCK_SETTLE_SECONDS)
        self.assertEqual(events, ["KEYCODE_SLEEP", "KEYCODE_WAKEUP", settle, "swipe", settle,
                                  "window", "trust", "guard", "pin"])


class BoundsAndPrerequisitesTests(unittest.TestCase):
    def test_failure_metadata_retains_safe_type_stage_and_fixed_code_only(self):
        self.assertEqual(platform.failure_metadata(RuntimeError("PRIVATE_PIN_CANARY"), "owned_process_action"),
                         {"stage": "owned_process_action", "exception_type": "RuntimeError", "code": "PLATFORM_INTEGRATION_FAILED", "owned_source_lines": []})
        self.assertEqual(platform.failure_metadata(platform.Error("PLATFORM_PROCESS_REUSED"), "owned_process_action")["code"],
                         "PLATFORM_PROCESS_REUSED")
        self.assertNotIn("CANARY", json.dumps(platform.failure_metadata(platform.Error("private PIN CANARY"), "owned_process_action")))

    def test_arbitrary_exception_class_names_are_not_exported(self):
        private_type = type("PRIVATE_CANARY_Error", (RuntimeError,), {})
        result = platform.failure_metadata(private_type("unused"), "owned_process_action")
        self.assertEqual(result["exception_type"], "Other")
        self.assertNotIn("CANARY", json.dumps(result))

    def test_wait_deadline_cannot_be_extended_by_slow_true_predicate(self):
        with self.assertRaisesRegex(platform.Error, "DEADLINE"):
            platform.wait_until(lambda: True, 10, clock=Mock(side_effect=[9, 11]), sleep=Mock())

    def test_wait_refuses_expired_deadline_without_action(self):
        action = Mock()
        with self.assertRaises(platform.Error):
            platform.wait_until(action, 10, clock=lambda: 10, sleep=Mock())
        action.assert_not_called()

    def test_stream_capture_is_bounded_and_errors_are_discarded(self):
        reader = platform.StreamingOutput(io.BytesIO(b"x" * 100), 8)
        reader.read()
        self.assertTrue(reader.failed)
        self.assertEqual(reader.data, b"x" * 8)
        reader = platform.StreamingOutput(io.BytesIO(b"private"), 10, retain=False)
        reader.read()
        self.assertEqual(reader.data, b"")

    def test_stream_start_available_before_eof_and_before4096bytes(self):
        read_fd, write_fd = os.pipe()
        stream = os.fdopen(read_fd, "rb")
        writer = os.fdopen(write_fd, "wb", buffering=0)
        reader = platform.StreamingOutput(stream, 262144)
        thread = threading.Thread(target=reader.read, daemon=True)
        thread.start()
        try:
            writer.write(marker(1).encode("ascii"))
            platform.wait_until(lambda: bool(reader.data), platform.time.monotonic() + 2)
            self.assertTrue(thread.is_alive())
            self.assertTrue(platform.preparation_started(bytes(reader.data).decode(), PREP))
        finally:
            writer.close()
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_all_original_live_credential_and_background_gates_required(self):
        evidence = prerequisites()
        platform.require_prerequisites(evidence)
        mutations = [lambda item: item["phases"].pop(), lambda item: item["phases"].reverse(),
                     lambda item: item["phases"][0].update(passed=False),
                     lambda item: item["system_credential"]["handshake"].update(completed=False),
                     lambda item: item["background_delivery"]["phases"][0].update(method_completed_count=0),
                     lambda item: item.update(worker_completed=False)]
        for mutation in mutations:
            changed = copy.deepcopy(evidence)
            mutation(changed)
            with self.assertRaises(platform.Error):
                platform.require_prerequisites(changed)

    PARTIAL = dict(passed=False, handshake=dict(completed=False, actions=["cancel", "current_pin"],
                   observed_markers=["absent", "starting", "cancel_ready", "unlock_ready", "recreate_ready"]))

    def test_proven_partial_credential_needs_recorded_limitation(self):
        evidence = prerequisites()
        evidence["system_credential"] = copy.deepcopy(self.PARTIAL)
        with self.assertRaisesRegex(platform.Error, "PLATFORM_PREREQUISITES_MISSING"):
            platform.require_prerequisites(evidence)
        evidence["credential_limitation"] = platform.base.CREDENTIAL_PARTIAL_LIMITATION
        platform.require_prerequisites(evidence)
        for change in ({"actions": ["cancel"]}, {"observed_markers": ["absent", "starting", "cancel_ready", "unlock_ready"]}):
            weak = copy.deepcopy(evidence)
            weak["system_credential"]["handshake"].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(platform.Error, "PLATFORM_PREREQUISITES_MISSING"):
                platform.require_prerequisites(weak)
        # A recorded limitation never weakens a run whose credential did pass.
        full = prerequisites()
        full["credential_limitation"] = platform.base.CREDENTIAL_PARTIAL_LIMITATION
        full["system_credential"]["handshake"]["completed"] = False
        with self.assertRaises(platform.Error):
            platform.require_prerequisites(full)

    def test_baseline_records_limitation_and_execute_still_fails_overall(self):
        source = (platform.ROOT / "infra/mobile_platform.py").read_text(encoding="utf-8")
        baseline = source.split("def baseline(", 1)[1].split("\ndef ", 1)[0]
        self.assertLess(baseline.index("credential_cancel_and_unlock_proven"), baseline.index("CREDENTIAL_PARTIAL_LIMITATION"))
        self.assertLess(baseline.index("CREDENTIAL_PARTIAL_LIMITATION"), baseline.index("background_delivery"))
        body = source.split("def execute(", 1)[1].split("\ndef main(", 1)[0]
        extension = body.index("platform_extension(harness, emulator, evidence)")
        final = body.index('require(evidence["system_credential"]["passed"], "EMULATOR_SYSTEM_CREDENTIAL_PARTIAL")')
        self.assertLess(extension, final)
        self.assertLess(final, body.index('evidence["ok"] = True'))

    def test_only_zero_or_one_new_server_effect_with_exact_enrollment_and_jobs(self):
        for value in [counts(2), counts(3, 2), counts(3)]:
            platform.require_transition_counts(value, 2)
        for value in [counts(1), counts(4), counts(3, 4), {**counts(3), "receipts": 2},
                      {**counts(3), "enrollments": 2}, {**counts(3), "jobs": 4}, {**counts(3), "extra": 0}]:
            with self.assertRaises(platform.Error):
                platform.require_transition_counts(value, 2)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.emulator, self.harness = Mock(), Mock()
        self.driver = platform.Driver(self.harness, self.emulator)

    def test_absence_rejects_spontaneous_restart_and_wrong_stopped_state(self):
        self.driver.counts = Mock()
        for state in [(False, PID), (True, None)]:
            self.driver.package = Mock(return_value=state)
            with self.assertRaises(platform.Error):
                self.driver.absent("abrupt", 2)
        self.driver.counts.assert_not_called()

    def test_absence_checks_counts_and_owned_reverse(self):
        self.driver.package = Mock(return_value=(True, None))
        self.driver.counts = Mock()
        self.emulator.command.return_value = ""
        with self.assertRaisesRegex(platform.Error, "NETWORK_TUNNEL"):
            self.driver.absent("stop", 3)
        self.driver.counts.assert_called_once_with(3)

    def test_package_uid_change_refuses_process_operation(self):
        self.driver.uid = UID
        self.emulator.command.return_value = f"package:{PACKAGE} uid:{UID + 1}\n"
        with self.assertRaisesRegex(platform.Error, "UID_CHANGED"):
            self.driver.package()
        self.assertEqual(self.emulator.command.call_count, 1)

    def test_preexisting_marker_refuses_instrumentation(self):
        self.driver.counts = Mock()
        self.driver.phase = Mock(return_value="abrupt_ready")
        with patch.object(platform, "Preparation") as preparation, self.assertRaisesRegex(platform.Error, "PREEXISTING"):
            self.driver.interrupt("abrupt", {})
        preparation.assert_not_called()

    def test_pid_reuse_after_readiness_refuses_both_kill_mechanisms(self):
        self.driver.counts = Mock()
        self.driver.phase = Mock(side_effect=["absent", "abrupt_ready", "abrupt_ready"])
        self.driver.process = Mock(side_effect=[platform.ProcessIdentity(PID, UID, 1), platform.ProcessIdentity(PID, UID, 2)])
        prep = Mock(started=0)
        prep.running.return_value = True
        with patch.object(platform, "Preparation") as preparation, patch.object(platform.time, "monotonic", return_value=1):
            preparation.return_value.__enter__.return_value = prep
            with self.assertRaisesRegex(platform.Error, "PROCESS_REUSED"):
                self.driver.interrupt("abrupt", {})
        self.emulator.command.assert_not_called()

    def test_force_stop_deadline_refuses_late_action(self):
        self.driver.counts = Mock()
        self.driver.phase = Mock(side_effect=["absent", "force_stop_ready", "force_stop_ready"])
        self.driver.process = Mock(return_value=platform.ProcessIdentity(PID, UID, 1))
        prep = Mock(started=0)
        prep.running.return_value = True
        with patch.object(platform, "Preparation") as preparation, patch.object(platform.time, "monotonic", side_effect=[29, 29, 31]):
            preparation.return_value.__enter__.return_value = prep
            with self.assertRaisesRegex(platform.Error, "TERMINATION_LATE"):
                self.driver.interrupt("stop", {})
        self.emulator.command.assert_not_called()

    def test_late_stopped_interval_reauthorization_refuses_pin(self):
        self.driver.absent = Mock()
        with patch.object(platform.time, "monotonic", return_value=31), self.assertRaisesRegex(platform.Error, "REAUTHORIZATION_LATE"):
            self.driver.observe_gap("stop", 0, {})
        self.emulator.device_unlock.assert_not_called()

    def test_stopped_interval_crosses_eligibility_with_one_bounded_device_only_unlock(self):
        now = [1.0]
        self.driver.absent = Mock()
        def unlock(deadline, slot=None):
            self.assertEqual(slot, "reauthorization_timings")
            self.assertEqual(deadline, platform.REAUTH_DEADLINE_SECONDS)
            self.assertGreaterEqual(now[0], platform.REAUTH_START_SECONDS)
            now[0] += 8
        self.emulator.device_unlock.side_effect = unlock
        with patch.object(platform.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(platform.time, "sleep", side_effect=lambda duration: now.__setitem__(0, now[0] + duration)):
            result = {}
            self.driver.observe_gap("stop", 0, result)
        self.emulator.device_unlock.assert_called_once()
        self.assertGreaterEqual(result["gap"]["seconds_after_ready"], 60)
        self.assertTrue(any(value >= 40 for value in result["gap"]["sample_seconds_after_ready"]))
        self.assertTrue(all(call.args == ("stop", 3) for call in self.driver.absent.call_args_list))
        self.emulator.command.assert_not_called()

    def test_reauthorization_window_fits_measured_unlock_and_precedes_eligibility(self):
        # Slowest measured emulator device_unlock was 16.7 s; delayed work becomes eligible at 40 s.
        self.assertGreaterEqual(platform.REAUTH_DEADLINE_SECONDS - platform.REAUTH_START_SECONDS - 2, 16.7)
        self.assertLess(platform.REAUTH_DEADLINE_SECONDS, 40)
        self.assertGreaterEqual(platform.REAUTH_START_SECONDS, 10)

    def test_device_reauthorization_deadline_overrun_fails_stopped_observation(self):
        now = [20.0]
        self.driver.absent = Mock()
        self.emulator.device_unlock.side_effect = lambda deadline, slot=None: now.__setitem__(0, 31.0)
        with patch.object(platform.time, "monotonic", side_effect=lambda: now[0]), self.assertRaisesRegex(platform.Error, "REAUTHORIZATION_LATE"):
            self.driver.observe_gap("stop", 0, {})

    def test_abrupt_gap_observes_ten_seconds_after_confirmed_interruption_without_device_action(self):
        now = [8.0]
        self.driver.absent = Mock()
        with patch.object(platform.time, "monotonic", side_effect=lambda: now[0]), \
             patch.object(platform.time, "sleep", side_effect=lambda duration: now.__setitem__(0, now[0] + duration)):
            result = {}
            self.driver.observe_gap("abrupt", 0, result)
        self.assertGreaterEqual(now[0], 18)
        self.assertFalse(result["gap"]["device_only_reauthorization"])
        self.emulator.device_unlock.assert_not_called()

    def test_launcher_never_runs_when_prelaunch_package_state_is_wrong(self):
        self.driver.absent = Mock(side_effect=platform.Error("PLATFORM_STOP_STATE_CHANGED"))
        with self.assertRaises(platform.Error):
            self.driver.launcher("stop", {})
        self.emulator.command.assert_not_called()

    def test_launcher_uses_single_keyboard_action_no_force_flag_or_instrumentation(self):
        self.driver.absent = Mock()
        self.driver.process = Mock()
        self.emulator.system_uids.return_value = (10002, 1000)
        self.emulator.command.side_effect = [f"Status: ok\nActivity: {platform.MAIN}\n", ""]
        with patch.object(platform, "wait_until"), patch.object(platform.base, "background_counts", return_value=counts(2)):
            result = {}
            self.driver.launcher("abrupt", result)
        calls = self.emulator.command.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertNotIn("-S", calls[0].args)
        self.assertIn("android.intent.category.LAUNCHER", calls[0].args)
        self.assertEqual(calls[1].args[-2:], ("KEYCODE_TAB", "KEYCODE_ENTER"))
        self.emulator.credential_action.assert_called_once_with("pin")
        self.assertFalse(result["launcher"]["prior_screen_or_control_identity_proven"])
        self.assertEqual(result["launcher"]["credential_prompt_rule"], "UNKNOWN")  # wait stubbed: no match observed

    def test_launcher_records_which_credential_rule_matched(self):
        for rule, expected in (("settings", "SETTINGS_COMPONENT"), ("systemui", "SYSTEMUI_FALLBACK")):
            self.driver.absent = Mock()
            self.driver.process = Mock()
            self.emulator.system_uids.return_value = (10002, 1000)
            self.emulator.command.side_effect = [f"Status: ok\nActivity: {platform.MAIN}\n", "", "window"]
            with self.subTest(rule=rule), patch.object(platform, "wait_until",
                    side_effect=lambda predicate, deadline: predicate()), \
                    patch.object(platform.base, "focused_package", return_value=None), \
                    patch.object(platform, "credential_target", return_value=rule), \
                    patch.object(platform.base, "background_counts", return_value=counts(2)):
                result = {}
                self.driver.launcher("abrupt", result)
                self.assertEqual(result["launcher"]["credential_prompt_rule"], expected)

    def test_launcher_cannot_send_pin_to_unrelated_settings_window(self):
        self.driver.absent = Mock()
        self.driver.process = Mock()
        self.emulator.system_uids.return_value = (10002, 1000)
        self.emulator.credential_focus.return_value = PACKAGE
        self.emulator.command.side_effect = [f"Status: ok\nActivity: {platform.MAIN}\n", "",
                                            window("com.android.settings/.Settings", 1000)]
        with patch.object(platform, "wait_until", side_effect=lambda predicate, deadline: predicate()):
            with self.assertRaisesRegex(platform.Error, "CREDENTIAL_WINDOW_DENIED"):
                self.driver.launcher("abrupt", {})
        self.emulator.credential_action.assert_not_called()
        self.assertEqual(self.emulator.command.call_args.args, ("shell", "dumpsys", "window", "-a"))
        self.assertEqual(self.emulator.command.call_args.kwargs, {"timeout": 5})

    def test_verification_cannot_dispatch_before_server_effect_and_real_ui_return(self):
        self.harness.wait.side_effect = platform.Error("PLATFORM_SERVER_EFFECT_MISMATCH")
        with self.assertRaises(platform.Error):
            self.driver.verify("abrupt", {"launcher": {"credential_returned": True}})
        self.emulator.command.assert_not_called()

    def test_verification_requires_native_pass_independent_of_verified_marker(self):
        self.harness.wait.side_effect = lambda fn, **kwargs: fn()
        self.driver.counts = Mock(return_value=counts(3))
        self.driver.phase = Mock(return_value="verified")
        raw = marker(1, VERIFY) + marker(-2, VERIFY) + "FAILURES!!!\nINSTRUMENTATION_CODE: -1\n"
        self.emulator.command.return_value = raw
        with patch.object(platform.base, "background_counts", return_value=counts(3)), patch.object(platform.time, "sleep"):
            with self.assertRaisesRegex(platform.Error, "VERIFICATION_FAILED"):
                self.driver.verify("abrupt", {"launcher": {"credential_returned": True}})

    def test_cleanup_is_nested_emulator_before_database_and_inherits_uncertainty_preservation(self):
        # Behavioral check of inherited ownership cleanup, not a source-text mirror.
        emulator = object.__new__(platform.GuardedEmulator)
        emulator.owner = Mock()
        emulator.owner.close.side_effect = RuntimeError("private diagnostic")
        emulator.child = Mock()
        emulator.evidence = {}
        emulator.pin = "123456"
        preserve = Mock()
        with patch.dict("sys.modules", {"tests.browser_runner": Mock(preserve_database=preserve)}):
            with self.assertRaisesRegex(platform.Error, "EMULATOR_CLEANUP_UNCERTAIN"):
                emulator.__exit__(None, None, None)
        preserve.assert_called_once_with()
        self.assertIsNone(emulator.pin)


class ExecutionFailureTests(unittest.TestCase):
    def exercise_failure(self, cleanup_error=None):
        parent, run = MagicMock(), MagicMock()
        body_error = ValueError("PRIVATE_BODY_CANARY")
        harness, emulator = MagicMock(), MagicMock()
        harness.__enter__.return_value = harness
        emulator.__enter__.return_value = emulator
        emulator.evidence = {"owned_emulator_stopped": cleanup_error is None,
                             "owned_emulator_ports_closed": cleanup_error is None}
        events = []
        def emulator_exit(*args):
            events.append("emulator_exit")
            if cleanup_error:
                raise cleanup_error
            return False
        def harness_exit(*args):
            events.append("harness_exit")
            return False
        emulator.__exit__.side_effect = emulator_exit
        harness.__exit__.side_effect = harness_exit
        with patch.object(platform.base, "AndroidTools"), patch.object(platform.base, "verify_artifacts", return_value=(("app", "test"), {})), \
             patch.object(platform.base, "checked_path", side_effect=[parent, run]), patch.object(platform.base, "digest", return_value="hash"), \
             patch.object(platform.base.integration, "MobileHarness", return_value=harness), \
             patch.object(platform, "GuardedEmulator", return_value=emulator), \
             patch.object(platform, "baseline", side_effect=body_error), patch("builtins.print"):
            with self.assertRaises(type(cleanup_error or body_error)):
                platform.execute("app", "hash", "test", "hash")
        evidence = json.loads(run.__truediv__.return_value.write_text.call_args.args[0])
        self.assertEqual(events, ["emulator_exit", "harness_exit"])
        self.assertNotIn("CANARY", json.dumps(evidence))
        return evidence

    def test_body_failure_is_not_mislabeled_as_successful_cleanup(self):
        evidence = self.exercise_failure()
        self.assertEqual(evidence["failure"], evidence["body_failure"])
        self.assertEqual(evidence["failure"]["exception_type"], "ValueError")
        self.assertNotIn("cleanup_failure", evidence)
        self.assertFalse(evidence["ok"])

    def test_cleanup_failure_retains_original_body_failure_and_both_stages(self):
        evidence = self.exercise_failure(platform.Error("EMULATOR_CLEANUP_UNCERTAIN"))
        self.assertEqual(evidence["body_failure"]["exception_type"], "ValueError")
        self.assertEqual(evidence["cleanup_failure"]["stage"], "owned_emulator_cleanup")
        self.assertEqual(evidence["failure"], evidence["cleanup_failure"])
        self.assertFalse(evidence["ok"])


if __name__ == "__main__":
    unittest.main()
