"""Host bridge guard checks; these do not execute Android or PostgreSQL."""
import io
import copy
import json
import re
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, MagicMock, call, patch

from infra import mobile_emulator as bridge

MANIFEST = '''E: manifest (line=1)
  E: instrumentation (line=9)
    A: http://schemas.android.com/apk/res/android:name(0x01010003)="androidx.test.runner.AndroidJUnitRunner" (Raw: "androidx.test.runner.AndroidJUnitRunner")
    A: http://schemas.android.com/apk/res/android:targetPackage(0x01010021)="org.kapit.c2.mobile.spike" (Raw: "org.kapit.c2.mobile.spike")
  E: application (line=16)
    A: http://schemas.android.com/apk/res/android:name(0x01010003)="unrelated.fixture"
'''
METHOD = bridge.PHASES[0][0]
LOCKED = 'User "Owner" (id=0, flags=c13) (current): deviceLocked=1, x=1'
UNLOCKED = LOCKED.replace("deviceLocked=1", "deviceLocked=0")
KEYGUARD = """  KeyguardServiceDelegate
    showing=true
    inputRestricted=true
    occluded=false
    secure=true
    currentUser=0
    KeyguardStateMonitor
      mIsShowing=true
      mCurrentUserId=0
"""
LOCK_WINDOW = """  Window #2 Window{a11 u0 NotificationShade}:
    mDisplayId=0 mSession=synthetic
    mOwnerUid=10055 showForAllUsers=true package=com.android.systemui appop=NONE
    mAttrs=synthetic
  mCurrentFocus=Window{a11 u0 NotificationShade}
"""


def credential_window(package="com.android.settings", uid=1000):
    title = package + "/.ConfirmLockPassword"
    return (f"mCurrentFocus=Window{{a11 u0 {title}}}\n"
            f"  Window #0 Window{{a11 u0 {title}}}:\n"
            f"    mOwnerUid={uid} showForAllUsers=false package={package} appop=NONE\n")


def marker(code, method=METHOD, test_class=bridge.TEST_CLASS):
    return (f"INSTRUMENTATION_STATUS: class={test_class}\n"
            f"INSTRUMENTATION_STATUS: test={method}\nINSTRUMENTATION_STATUS: current=1\n"
            f"INSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS_CODE: {code}\n")


def credential_failure_output(helper="waitLocked", line=101, caller=53):
    stack = ("androidx.compose.ui.test.ComposeTimeoutException: PRIVATE_MESSAGE_CANARY\n"
             "\tat androidx.compose.ui.test.junit4.AndroidComposeTestRule.waitUntil(AndroidComposeTestRule.android.kt:450)\n"
             f"\tat {bridge.CREDENTIAL_CLASS}.{helper}(SystemCredentialIntegrationTest.kt:{line})\n"
             f"\tat {bridge.CREDENTIAL_CLASS}.{bridge.CREDENTIAL_METHOD}(SystemCredentialIntegrationTest.kt:{caller})\n"
             "\tat java.lang.reflect.Method.invoke(Native Method)\n")
    initial = marker(1, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
    failure = marker(-2, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
    failure = failure.replace("INSTRUMENTATION_STATUS_CODE: -2\n",
                              "INSTRUMENTATION_STATUS: stack=" + stack + "INSTRUMENTATION_STATUS_CODE: -2\n")
    return initial + failure + "INSTRUMENTATION_CODE: -1\n", stack


class CredentialFailureSiteTests(unittest.TestCase):
    def result(self, raw):
        return {"class": bridge.CREDENTIAL_CLASS, "method": bridge.CREDENTIAL_METHOD,
                **bridge.instrumentation_result(raw, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS),
                "handshake": {"completed": False, "observed_markers": ["absent", "starting"], "actions": []}}

    def test_both_exact_initial_sites_and_crlf_keep_only_finite_value(self):
        for helper, line, caller, site in (("waitLocked", 101, 53, "INITIAL_LOCK_WAIT"),
                ("waitCredentialWindow", 90, 55, "INITIAL_CREDENTIAL_WINDOW_WAIT")):
            raw, _ = credential_failure_output(helper, line, caller)
            for body in (raw, raw.replace("\tat ", "    at ").replace("\n", "\r\n")):
                with self.subTest(site=site, crlf="\r" in body):
                    result = self.result(raw)
                    before = copy.deepcopy(result)
                    self.assertEqual(bridge.credential_failure_site(body, result), site)
                    self.assertEqual(result, before)
                    self.assertNotIn("CANARY", str(result))

    def test_stream_and_result_repetitions_are_not_another_owned_stack(self):
        raw, stack = credential_failure_output()
        raw = raw.replace("INSTRUMENTATION_STATUS_CODE: -2\n",
            "INSTRUMENTATION_STATUS: stream=\n" + stack + "INSTRUMENTATION_STATUS_CODE: -2\n")
        raw = raw.replace("INSTRUMENTATION_CODE: -1\n",
            "INSTRUMENTATION_RESULT: stream=\n" + stack + "FAILURES!!!\nINSTRUMENTATION_CODE: -1\n")
        self.assertEqual(bridge.credential_failure_site(raw, self.result(raw)), "INITIAL_LOCK_WAIT")

    def test_valid_pair_only_in_message_stream_or_summary_is_unknown(self):
        raw, stack = credential_failure_output()
        absent = raw.replace("INSTRUMENTATION_STATUS: stack=" + stack, "")
        for body in (absent.replace("INSTRUMENTATION_STATUS_CODE: -2\n",
                     "INSTRUMENTATION_STATUS: stream=" + stack + "INSTRUMENTATION_STATUS_CODE: -2\n"),
                absent.replace("INSTRUMENTATION_CODE: -1\n", "INSTRUMENTATION_RESULT: stream=" + stack
                               + "INSTRUMENTATION_CODE: -1\n"),
                raw.replace(stack, stack.replace("\n\tat ", " at ").rstrip() + "\n"),
                raw.replace(stack, stack.split("\n")[0] + "\nPRIVATE_MESSAGE_CANARY\n" + stack.split("\n", 1)[1])):
            with self.subTest(body=body[:25]):
                self.assertEqual(bridge.credential_failure_site(body, self.result(raw)), "UNKNOWN")

    def test_wrong_foreign_suffixed_missing_or_later_frames_are_unknown(self):
        raw, _ = credential_failure_output()
        for old, new in ((".kt:101", ".kt:104"), (".kt:101", ".kt"), (".kt:101", ".kt:0101"),
                ("SystemCredentialIntegrationTest.kt:101", "Unknown Source"),
                (bridge.CREDENTIAL_CLASS + ".waitLocked", "other.package.SystemCredentialIntegrationTest.waitLocked"),
                (bridge.CREDENTIAL_CLASS + ".waitLocked", bridge.CREDENTIAL_CLASS + "$Other.waitLocked"),
                ("SystemCredentialIntegrationTest.kt:101", "OtherSystemCredentialIntegrationTest.kt:101"),
                (".waitLocked(", ".otherWait("), (".kt:101)", ".kt:101) PRIVATE_CANARY"),
                (".kt:53", ".kt:55")):
            self.assertEqual(bridge.credential_failure_site(raw.replace(old, new), self.result(raw)), "UNKNOWN")
        for caller in (59, 62, 68, 71, 76, 83):
            body, _ = credential_failure_output(caller=caller)
            self.assertEqual(bridge.credential_failure_site(body, self.result(body)), "UNKNOWN")

    def test_duplicate_conflicting_reversed_or_nonadjacent_frames_are_unknown(self):
        raw, stack = credential_failure_output()
        parts = stack.splitlines(keepends=True)
        for replacement in (stack + "".join(parts[2:4]),
                stack + credential_failure_output("waitCredentialWindow", 90, 55)[1],
                "".join(parts[:2] + [parts[3], parts[2]] + parts[4:]),
                "".join(parts[:3] + [parts[1]] + parts[3:]),
                stack + parts[2].replace(bridge.CREDENTIAL_CLASS, "foreign.Class")):
            self.assertEqual(bridge.credential_failure_site(raw.replace(stack, replacement), self.result(raw)), "UNKNOWN")

    def test_missing_helper_or_caller_and_summary_inside_status_are_unknown(self):
        raw, stack = credential_failure_output()
        parts = stack.splitlines(keepends=True)
        for body in (raw.replace(parts[2], ""), raw.replace(parts[3], ""),
                raw.replace("INSTRUMENTATION_STATUS_CODE: -2\n",
                    "INSTRUMENTATION_RESULT: stream=PRIVATE_CANARY\nINSTRUMENTATION_STATUS_CODE: -2\n")):
            self.assertEqual(bridge.credential_failure_site(body, self.result(raw)), "UNKNOWN")

    def test_nested_suppressed_elided_and_nonframe_lines_are_unknown(self):
        raw, stack = credential_failure_output()
        for extra in ("Caused by: java.lang.IllegalStateException: PRIVATE_CANARY\n",
                "\tSuppressed: java.lang.AssertionError: PRIVATE_CANARY\n", "\t... 3 more\n",
                "PRIVATE_CANARY\n", "\n", "\tat foreign.Class.waitLocked(Other.kt:1)\n"):
            self.assertEqual(bridge.credential_failure_site(raw.replace(stack, stack + extra), self.result(raw)),
                             "INITIAL_LOCK_WAIT" if extra == "\n" else "UNKNOWN")

    def test_duplicate_stack_or_stack_on_wrong_record_is_unknown(self):
        raw, stack = credential_failure_output()
        for body in (raw.replace("INSTRUMENTATION_STATUS: stack=", "INSTRUMENTATION_STATUS: stack=" + stack
                                + "INSTRUMENTATION_STATUS: stack="),
                raw.replace("INSTRUMENTATION_STATUS: stack=" + stack, "").replace(
                    "INSTRUMENTATION_STATUS_CODE: 1\n", "INSTRUMENTATION_STATUS: stack=" + stack
                    + "INSTRUMENTATION_STATUS_CODE: 1\n"),
                raw.replace("INSTRUMENTATION_CODE: -1\n", "INSTRUMENTATION_STATUS: stack=" + stack
                            + "INSTRUMENTATION_CODE: -1\n")):
            self.assertEqual(bridge.credential_failure_site(body, self.result(raw)), "UNKNOWN")

    def test_record_identity_and_structure_are_independently_checked(self):
        raw, _ = credential_failure_output()
        for body in (raw.replace("current=1", "current=2"), raw.replace("numtests=1", "numtests=2"),
                raw.replace("class=" + bridge.CREDENTIAL_CLASS, "class=foreign.Class"),
                raw.replace("test=" + bridge.CREDENTIAL_METHOD, "test=other"),
                raw.replace("INSTRUMENTATION_STATUS_CODE: -2", "INSTRUMENTATION_STATUS_CODE: -1"),
                raw.replace("INSTRUMENTATION_STATUS: stack=", "INSTRUMENTATION_STATUS: stack ="),
                raw.replace("INSTRUMENTATION_STATUS: current=1\n", "INSTRUMENTATION_STATUS: current=1\n" * 2),
                raw + marker(-2, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)):
            self.assertEqual(bridge.credential_failure_site(body, self.result(raw)), "UNKNOWN")

    def test_missing_or_unexpected_root_exception_is_unknown(self):
        raw, stack = credential_failure_output()
        for replacement in ("", stack.replace("androidx.compose.ui.test.ComposeTimeoutException",
                "other.ComposeTimeoutException"), "\tat foreign.Class.method(Other.kt:1)\n"):
            self.assertEqual(bridge.credential_failure_site(raw.replace(stack, replacement), self.result(raw)), "UNKNOWN")

    def test_byte_line_stack_and_complete_output_bounds(self):
        raw, stack = credential_failure_output()
        for body in (raw.rstrip("\n"), raw + "PARTIAL_CANARY", raw + "x" * 262145,
                raw + "\u00e9" * 131073 + "\n", raw + "\n" * 513,
                raw.replace(stack, stack + "\tat foreign.Class.method(Other.kt:1)\n" * 129),
                raw.replace("\tat ", "\vat "), raw.replace("\tat ", "\rat "),
                raw.replace("\tat ", "\u2028at ")):
            self.assertEqual(bridge.credential_failure_site(body, self.result(raw)), "UNKNOWN")

    def test_success_incomplete_foreign_or_other_exception_context_is_unchanged(self):
        raw, _ = credential_failure_output()
        for field, value in (("passed", True), ("outcome", "incomplete"), ("method_completed_count", 0),
                ("class", bridge.TEST_CLASS), ("method", METHOD), ("status_codes", [1, 0]),
                ("instrumentation_codes", []), ("exception_types", []),
                ("exception_types", ["java.lang.AssertionError"]),
                ("exception_types", ["androidx.compose.ui.test.ComposeTimeoutException", "java.lang.AssertionError"])):
            result = self.result(raw)
            result[field] = value
            before = copy.deepcopy(result)
            self.assertIsNone(bridge.credential_failure_site(raw, result))
            self.assertEqual(result, before)

    def test_handshake_must_be_initial_starting_without_actions(self):
        raw, _ = credential_failure_output()
        for markers in ([], ["absent"], ["starting", "starting"], ["starting", "absent"],
                ["absent", "starting", "cancel_ready"], ["starting", "completed"], ["foreign", "starting"]):
            result = self.result(raw)
            result["handshake"]["observed_markers"] = markers
            self.assertIsNone(bridge.credential_failure_site(raw, result))
        for field, value in (("actions", ["cancel"]), ("completed", True)):
            result = self.result(raw)
            result["handshake"][field] = value
            self.assertIsNone(bridge.credential_failure_site(raw, result))
        result = self.result(raw)
        result["handshake"]["observed_markers"] = ["starting"]
        self.assertEqual(bridge.credential_failure_site(raw, result), "INITIAL_LOCK_WAIT")


class OutputTests(unittest.TestCase):
    def test_failure_metadata_is_allowlisted_without_messages_or_foreign_paths(self):
        try:
            bridge.require(False, "PRIVATE_REPORT_CANARY")
        except bridge.EmulatorError as error:
            result = bridge.failure_metadata(error)
        self.assertEqual(result["exception_class"], "EmulatorError")
        self.assertTrue(result["owned_source_lines"])
        self.assertTrue(all(item["source"] == "infra/mobile_emulator.py" for item in result["owned_source_lines"]))
        self.assertNotIn("CANARY", str(result))
        Custom = type("PRIVATE_CLASS_CANARY", (RuntimeError,), {})
        self.assertEqual(bridge.failure_metadata(Custom("PRIVATE_MESSAGE")),
                         {"exception_class": "Other", "owned_source_lines": []})
        self.assertEqual(bridge.failure_metadata(bridge.DeviceError("PRIVATE_MESSAGE"))["exception_class"], "DeviceError")

    def test_body_failure_and_successful_harness_cleanup_are_separate(self):
        harness, evidence = Mock(), {}
        harness.__enter__ = Mock(return_value=harness)
        harness.__exit__ = Mock(return_value=None)
        with patch.object(bridge.integration, "MobileHarness", return_value=harness):
            with self.assertRaises(bridge.DeviceError):
                with bridge.observed_harness(evidence):
                    evidence["stage"] = "emulator_install"
                    raise bridge.DeviceError("PRIVATE_CANARY")
        self.assertTrue(evidence["database_cleanup_passed"])
        self.assertEqual(evidence["body_failure"]["stage"], "emulator_install")
        self.assertEqual(evidence["body_failure"]["exception_class"], "DeviceError")
        self.assertNotIn("CANARY", str(evidence))
        harness.__exit__.assert_called_once()

    def test_harness_cleanup_failure_does_not_erase_body_failure(self):
        harness, evidence = MagicMock(), {}
        harness.__exit__.side_effect = RuntimeError("PRIVATE_CLEANUP_CANARY")
        with patch.object(bridge.integration, "MobileHarness", return_value=harness):
            with self.assertRaises(RuntimeError):
                with bridge.observed_harness(evidence):
                    evidence["stage"] = "live_fault_setup"
                    raise bridge.DeviceError("PRIVATE_BODY_CANARY")
        self.assertFalse(evidence["database_cleanup_passed"])
        self.assertEqual(evidence["body_failure"]["exception_class"], "DeviceError")
        self.assertEqual(evidence["cleanup_failure"]["exception_class"], "RuntimeError")
        self.assertNotIn("CANARY", str(evidence))

    def test_failed_harness_entry_cannot_claim_cleanup_pass_or_double_teardown(self):
        harness, evidence = MagicMock(), {}
        harness.__enter__.side_effect = bridge.integration.IntegrationError("PRIVATE_CANARY")
        with patch.object(bridge.integration, "MobileHarness", return_value=harness):
            with self.assertRaises(bridge.integration.IntegrationError):
                with bridge.observed_harness(evidence):
                    self.fail("entry must fail")
        self.assertNotIn("database_cleanup_passed", evidence)
        harness.__exit__.assert_not_called()
        self.assertEqual(evidence["body_failure"]["stage"], "harness_start")

    def test_exact_one_instrumented_method_is_required(self):
        prefix = marker(1) + marker(0)
        self.assertTrue(bridge.instrumentation_result(prefix + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n", METHOD)["passed"])
        for value in ["OK (0 tests)\nINSTRUMENTATION_CODE: -1\n", "OK (1 test)\n",
                      "OK (1 test)\nINSTRUMENTATION_CODE: 0\n",
                      "OK (1 test)\nINSTRUMENTATION_CODE: -1\nINSTRUMENTATION_FAILED: error",
                      "OK (1 test)\nINSTRUMENTATION_CODE: -1\nINSTRUMENTATION_RESULT: shortMsg=crash"]:
            self.assertFalse(bridge.instrumentation_result(prefix + value, METHOD)["passed"])

    def test_failure_retains_type_and_code_but_discards_message_and_canary(self):
        raw = marker(1) + marker(-2) + "INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: SECRET_CANARY\n"
        raw += "PRIVATE_REPORT_CANARY\nFAILURES!!!\nINSTRUMENTATION_CODE: -1\n"
        result = bridge.instrumentation_result(raw, METHOD)
        self.assertEqual(result, {"passed": False, "outcome": "failed", "method_completed_count": 1,
                                 "status_codes": [1, -2], "instrumentation_codes": [-1],
                                 "exception_types": ["java.lang.AssertionError"]})
        self.assertNotIn("CANARY", str(result))

    def test_failure_cannot_be_overridden_by_ok_substring(self):
        raw = "java.lang.IllegalStateException: source\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        self.assertFalse(bridge.instrumentation_result(raw, METHOD)["passed"])

    def test_store_failure_allowlist_matches_kotlin_enum(self):
        source = (bridge.ROOT / "android/app/src/main/java/org/kapit/c2/mobile/domain/"
                  "StoreModels.kt").read_text(encoding="utf-8")
        block = source.split("enum class StoreCode {", 1)[1].split("}", 1)[0]
        self.assertEqual(frozenset(re.findall(r"[A-Z_]+", block)), bridge.STORE_FAILURE_CODES)
        self.assertIn("class StoreFailure(val code: StoreCode) : RuntimeException(code.name)", source)

    def test_store_failure_retains_only_exact_allowlisted_code_on_failure(self):
        name = "org.kapit.c2.mobile.domain.StoreFailure"
        for code in sorted(bridge.STORE_FAILURE_CODES):
            for prefix in ("", "INSTRUMENTATION_STATUS: stack=", "Caused by: "):
                raw = (marker(1) + marker(-2) + prefix + name + ": " + code
                       + "\n\tat org.kapit.c2.mobile.domain.StoreModelsKt.requireStore(StoreModels.kt:18)"
                       + "\nPRIVATE_RESPONSE_CANARY\nFAILURES!!!\nINSTRUMENTATION_CODE: -1\n")
                with self.subTest(code=code, prefix=prefix):
                    result = bridge.instrumentation_result(raw, METHOD)
                    self.assertEqual(result["store_failure_code"], code)
                    self.assertEqual((result["passed"], result["outcome"]), (False, "failed"))
                    self.assertNotIn("CANARY", json.dumps(result))

    def test_store_failure_code_denies_malformed_unknown_conflicting_and_passing(self):
        name = "org.kapit.c2.mobile.domain.StoreFailure"
        tail = "\nFAILURES!!!\nINSTRUMENTATION_CODE: -1\n"
        for lines in ([name + ": PRIVATE_CANARY"], [name + ": KEY_UNAVAILABLE extra"], [name + ":KEY_UNAVAILABLE"],
                      [name + ": key_unavailable"], [name], [" " + name + ": KEY_UNAVAILABLE"],
                      [name + ": KEY_UNAVAILABLE", name + ": CLAIM_LOST"],
                      [name + ": KEY_UNAVAILABLE", "x" + name + ": KEY_UNAVAILABLE"]):
            raw = marker(1) + marker(-2) + "\n".join(lines) + tail
            with self.subTest(lines=lines):
                result = bridge.instrumentation_result(raw, METHOD)
                self.assertNotIn("store_failure_code", result)
                self.assertNotIn("CANARY", json.dumps(result))
        repeated = marker(1) + marker(-2) + (name + ": CLAIM_LOST\nCaused by: " + name + ": CLAIM_LOST") + tail
        self.assertEqual(bridge.instrumentation_result(repeated, METHOD)["store_failure_code"], "CLAIM_LOST")
        passing = marker(1) + marker(0) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        self.assertNotIn("store_failure_code", bridge.instrumentation_result(passing, METHOD))

    def test_live_failure_retains_only_each_exact_public_enum(self):
        codes = {"UNAVAILABLE", "OFFLINE", "AUTH_REQUIRED", "CREDENTIALS_REJECTED", "REVOKED",
                 "SCOPE_DENIED", "CONTEXT_CHANGED", "CONFLICT", "INVALID_RESPONSE", "THROTTLED"}
        self.assertEqual(bridge.LIVE_FAILURE_CODES, codes)
        for code in codes:
            for prefix in ("", "INSTRUMENTATION_STATUS: stack="):
                raw = (marker(1) + marker(-2) + prefix + "org.kapit.c2.mobile.ui.MobileLiveFailure: " + code
                       + "\nPRIVATE_RESPONSE_CANARY\nFAILURES!!!\nINSTRUMENTATION_CODE: -1\n")
                with self.subTest(code=code, prefix=prefix):
                    result = bridge.instrumentation_result(raw, METHOD)
                    self.assertEqual(result["live_failure_code"], code)
                    self.assertFalse(result["passed"])
                    self.assertEqual(result["method_completed_count"], 1)
                    self.assertEqual(result["exception_types"], ["org.kapit.c2.mobile.ui.MobileLiveFailure"])
                    self.assertNotIn("CANARY", str(result))

    def test_live_failure_unknown_trailing_private_or_wrong_line_omits_code(self):
        name = "org.kapit.c2.mobile.ui.MobileLiveFailure"
        for line in (name + ": PRIVATE_CANARY", name + ": UNAVAILABLE PRIVATE_CANARY",
                name + ": UNAVAILABLE: PRIVATE_CANARY", name + ": UNAVAILABLE ", name + ": unavailable",
                name + ":", name + ":UNAVAILABLE", name + ":\tUNAVAILABLE", name + ": UNAVAILABLE0",
                name + ": UNAVAILABLE\vPRIVATE_CANARY", name + ": UNAVAILABLE\rPRIVATE_CANARY",
                name + ": UNAVAILABLE\u2028PRIVATE_CANARY",
                " " + name + ": UNAVAILABLE", "Caused by: " + name + ": UNAVAILABLE",
                "INSTRUMENTATION_RESULT: stream=" + name + ": UNAVAILABLE",
                "other.package.MobileLiveFailure: UNAVAILABLE", name + "Other: UNAVAILABLE"):
            with self.subTest(line=line):
                raw = marker(1) + marker(-2) + line + "\nINSTRUMENTATION_CODE: -1\n"
                result = bridge.instrumentation_result(raw, METHOD)
                self.assertNotIn("live_failure_code", result)
                self.assertFalse(result["passed"])
                self.assertNotIn("CANARY", str(result))

    def test_live_failure_conflicting_or_malformed_candidates_omit_even_known_code(self):
        line = "org.kapit.c2.mobile.ui.MobileLiveFailure: UNAVAILABLE\n"
        for extra in (line.replace("UNAVAILABLE", "OFFLINE"), line.replace("UNAVAILABLE", "PRIVATE_CANARY"),
                line.rstrip() + " PRIVATE_CANARY\n", "Caused by: " + line):
            raw = marker(1) + marker(-2) + line + extra + "INSTRUMENTATION_CODE: -1\n"
            result = bridge.instrumentation_result(raw, METHOD)
            self.assertNotIn("live_failure_code", result)
            self.assertFalse(result["passed"])
            self.assertNotIn("CANARY", str(result))

    def test_live_failure_identical_stack_and_summary_values_have_one_enum(self):
        line = "org.kapit.c2.mobile.ui.MobileLiveFailure: OFFLINE\n"
        raw = marker(1) + marker(-2) + "INSTRUMENTATION_STATUS: stack=" + line + line + "INSTRUMENTATION_CODE: -1\n"
        result = bridge.instrumentation_result(raw, METHOD)
        self.assertEqual(result["live_failure_code"], "OFFLINE")
        self.assertFalse(result["passed"])
        self.assertEqual(result["status_codes"], [1, -2])

    def test_live_failure_enum_cannot_make_success_or_identity_gates_pass(self):
        line = "org.kapit.c2.mobile.ui.MobileLiveFailure: UNAVAILABLE\n"
        for prefix in (marker(1) + marker(0), "", marker(1) + marker(0, "differentMethod")):
            result = bridge.instrumentation_result(prefix + line + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n", METHOD)
            self.assertEqual(result["live_failure_code"], "UNAVAILABLE")
            self.assertFalse(result["passed"])
        unchanged_success = bridge.instrumentation_result(marker(1) + marker(0) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n", METHOD)
        self.assertTrue(unchanged_success["passed"])
        self.assertNotIn("live_failure_code", unchanged_success)

    def test_incomplete_wrong_method_and_absent_status_cannot_pass(self):
        for prefix in ["", marker(1), marker(1) + marker(0, "differentMethod"),
                       marker(1) + marker(0) + marker(0),
                       (marker(1) + marker(0)).replace("numtests=1", "numtests=2")]:
            outcome = bridge.instrumentation_result(prefix + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n", METHOD)
            self.assertEqual(outcome["outcome"], "incomplete")
            self.assertEqual(outcome["method_completed_count"], 0)

    def test_capture_limit_preserves_only_prefix_and_sets_failure(self):
        capture = bridge.BoundedOutput(io.BytesIO(b"x" * 100), 10)
        capture.read()
        self.assertTrue(capture.failed)
        self.assertEqual(capture.data, b"x" * 10)
        discard = bridge.BoundedOutput(io.BytesIO(b"private"), 20, retain=False)
        discard.read()
        self.assertEqual(discard.data, b"")

    def test_command_input_and_timeout_are_bounded_before_spawn(self):
        with patch.object(bridge.subprocess, "Popen") as popen:
            for kwargs in [{"stdin": b"x" * 4097}, {"timeout": 181}, {"maximum": 1000000}]:
                with self.assertRaises(bridge.EmulatorError):
                    bridge.run_bounded(["never-start"], **kwargs)
        popen.assert_not_called()

    def test_actual_bounded_reader_normalizes_windows_tool_lines(self):
        output = bridge.run_bounded([bridge.sys.executable, "-c",
            "import sys; sys.stdout.buffer.write(b'verified\\r\\n')"])
        self.assertEqual(output, "verified\n")

    def test_actual_output_overflow_is_safe_fixed_failure(self):
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_OUTPUT_BOUND"):
            bridge.run_bounded([bridge.sys.executable, "-c", "print('PRIVATE_CANARY'*1000)"], maximum=20)

    def test_actual_timeout_stops_owned_client_and_does_not_return_content(self):
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_COMMAND_TIMEOUT"):
            bridge.run_bounded([bridge.sys.executable, "-c", "import time; time.sleep(3)"], timeout=0.1)


class UnlockStateDiagnosticTests(unittest.TestCase):
    expected_commands = [
        call("shell", "pm", "list", "packages", "-U", "--user", "0", "com.android.systemui", timeout=5),
        call("shell", "dumpsys", "trust", timeout=5),
        call("shell", "am", "get-current-user", timeout=5),
        call("shell", "dumpsys", "window", "policy", timeout=5),
        call("shell", "dumpsys", "window", "-a", timeout=5),
    ]

    def emulator(self, trust=LOCKED, current_user="0\n"):
        emulator = object.__new__(bridge.OwnedEmulator)
        emulator.evidence = {}
        emulator.command = Mock(side_effect=["package:com.android.systemui uid:10055\n", trust,
                                            current_user, KEYGUARD, LOCK_WINDOW])
        return emulator

    def test_three_trust_states_are_separate_from_the_dependent_owner_predicate(self):
        for trust, state, structure in ((LOCKED, "LOCKED", "VALID"), (UNLOCKED, "UNLOCKED", "VALID"),
                                        ("unknown", "UNKNOWN", "CURRENT_MARKER_ABSENT")):
            with self.subTest(state=state):
                emulator = self.emulator(trust)
                if state == "LOCKED":
                    emulator.require_unlock_target()
                else:
                    with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_UNLOCK_TARGET_DENIED$"):
                        emulator.require_unlock_target()
                self.assertEqual(emulator.command.call_args_list, self.expected_commands)
                checks = emulator.evidence["unlock_preconditions"]
                self.assertEqual(len(checks), 7)
                self.assertEqual(checks["current_owner_locked"], state == "LOCKED")
                self.assertEqual(checks["keyguard_owner_user"], state == "LOCKED")
                self.assertTrue(all(value for key, value in checks.items()
                                    if key not in {"current_owner_locked", "keyguard_owner_user"}))
                self.assertEqual(emulator.evidence["unlock_state_diagnostic"],
                    {"schema": 1, "trust_state": state, "trust_structure": structure, "activity_owner_match": True})

    def test_unknown_structures_have_only_fixed_categories(self):
        cases = ((None, "INVALID_INPUT"), (b"private", "INVALID_INPUT"),
                 (LOCKED + "\x00", "INVALID_INPUT"), (LOCKED + "\ufffd", "INVALID_INPUT"),
                 ("", "CURRENT_MARKER_ABSENT"), (LOCKED + "\n" + LOCKED, "CURRENT_MARKER_AMBIGUOUS"),
                 (LOCKED.replace("id=0", "id=10"), "OWNER_HEADER_UNMATCHED"),
                 (LOCKED.replace('"Owner"', "Owner"), "OWNER_HEADER_UNMATCHED"),
                 (LOCKED.replace("flags=c13", "flags=wrong"), "OWNER_HEADER_UNMATCHED"),
                 (LOCKED.replace("deviceLocked=1, x=1", ""), "OWNER_HEADER_UNMATCHED"),
                 (LOCKED.replace("deviceLocked=1", "deviceLocked=1deviceLocked=0"), "SCALAR_MALFORMED"),
                 (LOCKED.replace(", x=1", ",deviceLocked=0"), "SCALAR_MALFORMED"),
                 (LOCKED + ", x=2", "SCALAR_DUPLICATE"),
                 (LOCKED + ", deviceLocked=0", "SCALAR_DUPLICATE"),
                 (LOCKED.replace("deviceLocked=1, ", ""), "LOCK_SCALAR_ABSENT"),
                 (LOCKED.replace("deviceLocked=1", "deviceLocked=true"), "LOCK_SCALAR_INVALID"))
        for raw, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(bridge.trust_diagnostic(raw), ("UNKNOWN", expected))

    def test_fixed_input_bounds_include_bytes_lines_current_line_and_scalar_count(self):
        for raw in ("x" * 262145, "\u00e9" * 131073, "\n" * 513,
                    LOCKED.replace('"Owner"', '"' + 'x' * 8193 + '"'),
                    LOCKED + ''.join(f", field{i}=1" for i in range(63))):
            self.assertEqual(bridge.trust_diagnostic(raw), ("UNKNOWN", "INPUT_BOUND"))
        for raw in ("x" * (262144 - len(LOCKED) - 1) + "\n" + LOCKED,
                    "\n" * 511 + LOCKED,
                    LOCKED + ''.join(f", field{i}=1" for i in range(62))):
            self.assertEqual(bridge.trust_diagnostic(raw), ("LOCKED", "VALID"))

    def test_existing_parser_remains_authoritative_after_structural_checks(self):
        with patch.object(bridge, "current_device_lock", return_value=None) as parser:
            self.assertEqual(bridge.trust_diagnostic(LOCKED), ("UNKNOWN", "PARSER_UNKNOWN"))
        parser.assert_called_once_with(LOCKED)

    def test_owner_activity_matches_only_the_existing_exact_owner_response(self):
        for current_user in ("0", "0\n", "0\r\n"):
            self.assertTrue(bridge.unlock_state_diagnostic(LOCKED, current_user)["activity_owner_match"])
        for current_user in (None, b"0", "10\n", "0\n0\n", " 0\n", "0\nPRIVATE_CANARY", "x" * 65):
            result = bridge.unlock_state_diagnostic(LOCKED, current_user)
            self.assertFalse(result["activity_owner_match"])
            self.assertNotIn("PRIVATE", json.dumps(result))
        emulator = self.emulator(current_user="10\n")
        with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_UNLOCK_TARGET_DENIED$"):
            emulator.require_unlock_target()
        self.assertTrue(emulator.evidence["unlock_preconditions"]["current_owner_locked"])
        self.assertFalse(emulator.evidence["unlock_preconditions"]["keyguard_owner_user"])
        self.assertFalse(emulator.evidence["unlock_state_diagnostic"]["activity_owner_match"])

    def test_private_labels_scalars_and_malformed_values_never_enter_evidence(self):
        for raw in (LOCKED.replace('"Owner"', '"PRIVATE_CANARY"') + ", private=PRIVATE_CANARY",
                    LOCKED.replace("deviceLocked=1", "deviceLocked=PRIVATE_CANARY"),
                    LOCKED.replace("id=0", "id=12345"),
                    LOCKED.replace("deviceLocked=1", "deviceLocked=/PRIVATE_CANARY")):
            result = bridge.unlock_state_diagnostic(raw, "0\n")
            self.assertEqual(set(result), {"schema", "trust_state", "trust_structure", "activity_owner_match"})
            self.assertIn(result["trust_state"], {"LOCKED", "UNLOCKED", "UNKNOWN"})
            encoded = json.dumps(result)
            self.assertNotIn("PRIVATE", encoded)
            self.assertNotIn("12345", encoded)
            self.assertLess(len(encoded.encode()), 256)

    def test_diagnostic_exceptions_preserve_exact_original_success_or_refusal_and_commands(self):
        for trust in (LOCKED, UNLOCKED, "unknown"):
            for helper in ("unlock_state_diagnostic", "trust_diagnostic"):
                for error in (ValueError("PRIVATE_CANARY"), bridge.EmulatorError("PRIVATE_CANARY")):
                    with self.subTest(locked=trust == LOCKED, helper=helper, error=type(error).__name__):
                        emulator = self.emulator(trust)
                        original = bridge.EmulatorError("EMULATOR_UNLOCK_TARGET_DENIED")
                        def require(value, _code):
                            if not value:
                                raise original
                        with patch.object(bridge, helper, side_effect=error), patch.object(bridge, "require", side_effect=require):
                            if trust == LOCKED:
                                emulator.require_unlock_target()
                            else:
                                with self.assertRaises(bridge.EmulatorError) as caught:
                                    emulator.require_unlock_target()
                                self.assertIs(caught.exception, original)
                        self.assertEqual(emulator.command.call_args_list, self.expected_commands)
                        self.assertEqual(emulator.evidence["unlock_state_diagnostic"],
                                         {"schema": 1, "code": "UNLOCK_DIAGNOSTICS_UNAVAILABLE"})
                        self.assertNotIn("PRIVATE", json.dumps(emulator.evidence))

    def test_diagnostic_cannot_grant_an_unlocked_target_permission(self):
        emulator = self.emulator(UNLOCKED)
        with patch.object(bridge, "unlock_state_diagnostic", return_value=
                {"schema": 1, "trust_state": "LOCKED", "trust_structure": "VALID", "activity_owner_match": True}):
            with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_UNLOCK_TARGET_DENIED$"):
                emulator.require_unlock_target()
        self.assertEqual(emulator.command.call_args_list, self.expected_commands)
        self.assertFalse(emulator.evidence["unlock_preconditions"]["current_owner_locked"])

    @patch.object(bridge, "UNLOCK_TARGET_OBSERVATIONS", 1)  # TASK-112 polling is covered separately
    def test_diagnostic_failure_keeps_unlock_timing_and_pin_gate_identical(self):
        for trust in (LOCKED, UNLOCKED):
            observed = []
            for diagnostic_error in (False, True):
                emulator = self.emulator(trust)
                emulator.pin = "123456"
                emulator.command.side_effect = ["", "", "", "package:com.android.systemui uid:10055\n",
                    trust, "0\n", KEYGUARD, LOCK_WINDOW, "", UNLOCKED]
                original_helper = bridge.unlock_state_diagnostic
                def diagnostic(*args):
                    if diagnostic_error:
                        raise ValueError("PRIVATE_CANARY")
                    return original_helper(*args)
                with patch.object(bridge, "unlock_state_diagnostic", side_effect=diagnostic), \
                        patch.object(bridge.time, "sleep") as sleep, patch.object(bridge.time, "monotonic", return_value=0) as clock:
                    if trust == LOCKED:
                        emulator.unlock()
                    else:
                        with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_UNLOCK_TARGET_DENIED$"):
                            emulator.unlock()
                observed.append((emulator.command.call_args_list, sleep.call_args_list, clock.call_args_list))
                self.assertEqual(sleep.call_args_list, [call(2), call(3), call(3)])
                self.assertEqual(sum("stdin" in invocation.kwargs for invocation in emulator.command.call_args_list),
                                 1 if trust == LOCKED else 0)
                self.assertNotIn("123456", json.dumps(emulator.evidence))
                self.assertNotIn("PRIVATE", json.dumps(emulator.evidence))
            self.assertEqual(observed[0], observed[1])


class ManifestTests(unittest.TestCase):
    def test_keyguard_parser_requires_unique_corroborated_delegate_and_monitor(self):
        self.assertTrue(all(bridge.keyguard_conditions(KEYGUARD, current_user="0\n", trust=LOCKED).values()))
        for raw in (KEYGUARD.replace("showing=true", "showing=false"),
                    KEYGUARD.replace("occluded=false", "occluded=true"),
                    KEYGUARD.replace("secure=true", "secure=false"),
                    KEYGUARD.replace("currentUser=0", "currentUser=10"),
                    KEYGUARD.replace("mCurrentUserId=0", "mCurrentUserId=10"),
                    KEYGUARD.replace("mIsShowing=true", "mIsShowing=false"),
                    KEYGUARD + KEYGUARD, KEYGUARD.replace("    secure=true", "    secure=true\n    secure=false")):
            self.assertFalse(all(bridge.keyguard_conditions(raw, current_user="0\n", trust=LOCKED).values()))

    def test_user_null_requires_monitor_activity_and_trust_owner_zero(self):
        sentinel = KEYGUARD.replace("currentUser=0", "currentUser=-10000")
        self.assertTrue(all(bridge.keyguard_conditions(sentinel, current_user="0\n", trust=LOCKED).values()))
        for current_user, trust in ((None, LOCKED), ("10\n", LOCKED), ("0\n0\n", LOCKED),
                ("0 other", LOCKED), ("0\n", None), ("0\n", UNLOCKED),
                ("0\n", LOCKED.replace("id=0", "id=10")), ("0\n", LOCKED + "\n" + LOCKED)):
            with self.subTest(current_user=current_user):
                self.assertFalse(bridge.keyguard_conditions(sentinel, current_user=current_user, trust=trust)["keyguard_owner_user"])

    def test_ambiguous_or_unrelated_monitor_and_delegate_users_fail_closed(self):
        for raw in (KEYGUARD.replace("currentUser=0", "currentUser=-1"),
                KEYGUARD.replace("currentUser=0", "currentUser=0\n    currentUser=-10000"),
                KEYGUARD.replace("mCurrentUserId=0", "mCurrentUserId=0\n      mCurrentUserId=0"),
                KEYGUARD.replace("    KeyguardStateMonitor", "  KeyguardStateMonitor"),
                KEYGUARD + "  KeyguardStateMonitor\n    mCurrentUserId=0\n",
                KEYGUARD.replace("KeyguardStateMonitor", "UnrelatedMonitor"),
                KEYGUARD.replace("      mCurrentUserId", "    mCurrentUserId")):
            with self.subTest(raw=raw):
                self.assertFalse(all(bridge.keyguard_conditions(raw, current_user="0\n", trust=LOCKED).values()))

    def test_systemui_uid_selects_exact_package_among_valid_unique_filter_rows(self):
        raw = ("package:com.android.systemui.overlay uid:10056\n"
               "package:com.android.systemui uid:10055\n"
               "package:com.android.systemui.other uid:10057\n")
        self.assertEqual(bridge.systemui_uid(raw), 10055)
        for invalid in (raw + "not a package row\n", raw + "package:com.android.systemui uid:10055\n",
                raw + "package:com.android.systemui uid:10058\n", raw + "package:com.android.systemui.overlay uid:10056\n",
                raw.replace("systemui uid:10055", "systemui uid:110055"),
                raw.replace("systemui uid:10055", "systemui uid:0"),
                raw.replace("package:com.android.systemui uid:10055\n", "")):
            with self.subTest(raw=invalid):
                self.assertIsNone(bridge.systemui_uid(invalid))

    def test_lock_focus_binds_exact_owner_window_and_installed_systemui_uid(self):
        self.assertEqual(bridge.systemui_uid("package:com.android.systemui uid:10055\n"), 10055)
        self.assertTrue(bridge.systemui_lock_focus(LOCK_WINDOW, 10055))
        for raw in (LOCK_WINDOW.replace("u0", "u10"), LOCK_WINDOW.replace("mOwnerUid=10055", "mOwnerUid=10056"),
                    LOCK_WINDOW.replace("package=com.android.systemui", "package=" + bridge.PACKAGE),
                    LOCK_WINDOW.replace("mCurrentFocus=Window{a11", "mCurrentFocus=Window{b22"),
                    LOCK_WINDOW + "  mCurrentFocus=Window{a11 u0 NotificationShade}\n",
                    LOCK_WINDOW.replace("    mOwnerUid=", "    mOwnerUid=0 extra="),
                    LOCK_WINDOW.replace("Window #2", "mFocusedApp #2")):
            self.assertFalse(bridge.systemui_lock_focus(raw, 10055))
        for raw in ("package:com.android.systemui uid:110055", "package:other uid:10055",
                    "package:com.android.systemui uid:10055\npackage:other uid:bad"):
            self.assertIsNone(bridge.systemui_uid(raw))
        self.assertFalse(bridge.systemui_lock_focus(LOCK_WINDOW, None))

    def test_test_manifest_requires_exact_runner_and_target_block(self):
        bridge.instrumentation_manifest(MANIFEST)
        for text in [MANIFEST.replace("mobile.spike", "mobile.demo"),
                     MANIFEST.replace("AndroidJUnitRunner", "OtherRunner"),
                     MANIFEST + MANIFEST,
                     MANIFEST.replace("E: instrumentation", "E: application")]:
            with self.assertRaises(bridge.EmulatorError):
                bridge.instrumentation_manifest(text)

    def test_other_element_target_cannot_satisfy_missing_instrumentation_target(self):
        value = MANIFEST.replace('    A: http://schemas.android.com/apk/res/android:targetPackage',
                                 '  E: unrelated (line=10)\n    A: http://schemas.android.com/apk/res/android:targetPackage')
        with self.assertRaises(bridge.EmulatorError):
            bridge.instrumentation_manifest(value)

    def test_trust_dump_requires_single_current_owner_unlocked(self):
        self.assertTrue(bridge.device_unlocked("User \"Owner\" (id=0, flags=c13) (current): deviceLocked=0, x=1"))
        for raw in ["User (id=0, flags=c13) (current): deviceLocked=1,",
                    "User (id=10, flags=c13) (current): deviceLocked=0,",
                    "User (id=0, flags=c13) (current): deviceLocked=01,",
                    "User (id=0, a) (current): deviceLocked=0,\nUser (id=0, a) (current): deviceLocked=0,"]:
            self.assertFalse(bridge.device_unlocked(raw))

    def test_trust_dump_rejects_duplicate_contradictory_concatenated_or_wrong_users(self):
        actual = ' User "Owner" (id=0, flags=0xc13) (current): trustState=UNTRUSTED, trustManaged=0, deviceLocked=1, isActiveUnlockRunning=0, strongAuthRequired=0x1'
        self.assertTrue(bridge.device_locked(actual))
        self.assertTrue(bridge.device_unlocked(actual.replace("deviceLocked=1", "deviceLocked=0")))
        for raw in (actual + ", deviceLocked=0", actual + ", deviceLocked=1", actual + " " + actual,
                    actual + "\n" + actual.replace("id=0", "id=10"), actual.replace("id=0", "id=10"),
                    actual.replace("deviceLocked=1", "deviceLocked=10"), actual + ", unknown=User (id=10, flags=0)"):
            self.assertFalse(bridge.device_locked(raw))
            self.assertFalse(bridge.device_unlocked(raw))


class BackgroundDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.harness, self.emulator = Mock(), Mock()
        self.evidence = {"phases": [dict(method=phase[0], **self.success(phase[0])) for phase in bridge.PHASES],
                         "worker_completed": True,
                         "system_credential": {"passed": True, "handshake": {"completed": True}}}
        self.emulator.instrument.side_effect = self.success
        self.harness.wait.side_effect = lambda predicate: predicate()
        self.capture = patch.object(bridge, "background_counts")
        self.counts = self.capture.start()
        self.addCleanup(self.capture.stop)
        self.counts.side_effect = [self.snapshot(1), self.snapshot(1), self.snapshot(2)]
        self.printing = patch("builtins.print")
        self.printing.start()
        self.addCleanup(self.printing.stop)

    @staticmethod
    def snapshot(effects, done=None):
        return {"enrollments": 1, "revisions": effects, "receipts": effects,
                "jobs": effects, "jobs_done": effects if done is None else done}

    @staticmethod
    def success(method):
        raw = marker(1, method) + marker(0, method) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        return bridge.instrumentation_result(raw, method)

    PARTIAL = {"passed": False, "outcome": "incomplete", "code": "EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT",
               "handshake": {"completed": False, "actions": ["cancel", "current_pin"],
                             "observed_markers": ["absent", "starting", "cancel_ready", "unlock_ready", "recreate_ready"]}}

    def test_cancel_and_unlock_proof_requires_real_actions_and_unlock_marker(self):
        self.assertTrue(bridge.credential_cancel_and_unlock_proven(self.PARTIAL))
        for change in ({"actions": ["cancel"]}, {"actions": []}, {"actions": ["current_pin", "cancel"]},
                       {"actions": ["cancel", "current_pin", "extra"]},
                       {"observed_markers": ["absent", "starting", "cancel_ready"]},
                       # QA R1: PIN typed but unlock not yet verified (attempt16 shape) must not qualify.
                       {"observed_markers": ["absent", "starting", "cancel_ready", "unlock_ready"]},
                       {"observed_markers": None}):
            credential = copy.deepcopy(self.PARTIAL)
            credential["handshake"].update(change)
            with self.subTest(change=change):
                self.assertFalse(bridge.credential_cancel_and_unlock_proven(credential))
        self.assertFalse(bridge.credential_cancel_and_unlock_proven({}))

    def test_partial_credential_allows_background_only_with_recorded_limitation(self):
        self.evidence["system_credential"] = copy.deepcopy(self.PARTIAL)
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_BACKGROUND_PREREQUISITES_MISSING"):
            bridge.background_delivery(self.harness, self.emulator, copy.deepcopy(self.evidence))
        self.emulator.instrument.assert_not_called()
        self.evidence["credential_limitation"] = bridge.CREDENTIAL_PARTIAL_LIMITATION
        result = bridge.background_delivery(self.harness, self.emulator, self.evidence)
        self.assertTrue(result["passed"])
        self.assertFalse(self.evidence["system_credential"]["passed"])
        self.assertEqual([c.args[0] for c in self.emulator.instrument.call_args_list], list(bridge.BACKGROUND_METHODS))

    def test_unproven_partial_credential_cannot_reach_background(self):
        weak = copy.deepcopy(self.PARTIAL)
        weak["handshake"]["actions"] = ["cancel"]
        self.evidence.update(system_credential=weak, credential_limitation=bridge.CREDENTIAL_PARTIAL_LIMITATION)
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_BACKGROUND_PREREQUISITES_MISSING"):
            bridge.background_delivery(self.harness, self.emulator, self.evidence)
        self.emulator.instrument.assert_not_called()

    def test_execute_still_fails_overall_after_partial_credential(self):
        source = (bridge.ROOT / "infra/mobile_emulator.py").read_text(encoding="utf-8")
        body = source.split("def execute(", 1)[1].split("\ndef main(", 1)[0]
        gate = body.index('require(credential["passed"] or credential_cancel_and_unlock_proven(credential)')
        background = body.index("background_delivery(harness, emulator, evidence)")
        final = body.index('require(credential["passed"], "EMULATOR_SYSTEM_CREDENTIAL_PARTIAL")')
        ok = body.index('evidence["ok"] = True')
        self.assertLess(gate, background)
        self.assertLess(background, final)
        self.assertLess(final, ok)

    def test_ordered_background_delivery_keeps_original_and_credential_results_separate(self):
        original = copy.deepcopy(self.evidence)
        self.counts.side_effect = [self.snapshot(1), self.snapshot(1), self.snapshot(2, 1), self.snapshot(2)]
        def wait(predicate):
            self.assertFalse(predicate())
            self.assertTrue(predicate())
        self.harness.wait.side_effect = wait
        result = bridge.background_delivery(self.harness, self.emulator, self.evidence)
        self.assertTrue(result["passed"])
        self.assertEqual([call.args[0] for call in self.emulator.instrument.call_args_list],
                         list(bridge.BACKGROUND_METHODS))
        self.assertEqual(result["before_queue"], self.snapshot(1))
        self.assertEqual(result["phases"][0]["server_counts"], self.snapshot(1))
        self.assertEqual(result["phases"][1]["server_counts"], self.snapshot(2))
        self.assertEqual({key: self.evidence[key] for key in original}, original)
        self.assertEqual([call.args for call in self.harness.fault.call_args_list], [("normal",), ("normal",)])
        self.assertEqual([call[0] for call in self.emulator.mock_calls], ["instrument", "instrument"])

    def test_prior_phases_and_credential_cannot_be_omitted_or_reordered(self):
        for change in ("omit", "reverse", "failed", "incomplete", "worker", "credential", "handshake"):
            evidence = copy.deepcopy(self.evidence)
            if change == "omit":
                evidence["phases"].pop()
            elif change == "reverse":
                evidence["phases"].reverse()
            elif change == "failed":
                evidence["phases"][0]["passed"] = False
            elif change == "incomplete":
                evidence["phases"][0]["method_completed_count"] = 0
            elif change == "worker":
                evidence["worker_completed"] = False
            elif change == "credential":
                evidence["system_credential"]["passed"] = False
            else:
                evidence["system_credential"]["handshake"]["completed"] = False
            with self.subTest(change=change), self.assertRaisesRegex(
                    bridge.EmulatorError, "EMULATOR_BACKGROUND_PREREQUISITES_MISSING"):
                bridge.background_delivery(self.harness, self.emulator, evidence)
        self.counts.assert_not_called()
        self.emulator.instrument.assert_not_called()

    def test_baseline_mismatch_refuses_queue_and_preserves_actual_safe_counts(self):
        for field in self.snapshot(1):
            actual = {**self.snapshot(1), field: 2}
            self.counts.side_effect = None
            self.counts.return_value = actual
            with self.subTest(field=field), self.assertRaisesRegex(
                    bridge.EmulatorError, "EMULATOR_BACKGROUND_EFFECT_MISMATCH"):
                bridge.background_delivery(self.harness, self.emulator, self.evidence)
            self.assertEqual(self.evidence["background_delivery"]["before_queue"], actual)
            self.assertFalse(self.evidence["background_delivery"]["passed"])
        self.emulator.instrument.assert_not_called()

    def test_queued_row_must_not_already_be_server_accepted(self):
        self.counts.side_effect = [self.snapshot(1), self.snapshot(2)]
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_BACKGROUND_EFFECT_MISMATCH"):
            bridge.background_delivery(self.harness, self.emulator, self.evidence)
        self.emulator.instrument.assert_called_once_with(bridge.BACKGROUND_METHODS[0])
        self.assertEqual(self.evidence["background_delivery"]["phases"][0]["server_counts"], self.snapshot(2))
        self.assertFalse(self.evidence["background_delivery"]["passed"])

    def test_queue_test_failure_cannot_be_masked_by_valid_server_counts(self):
        method = bridge.BACKGROUND_METHODS[0]
        raw = marker(1, method) + marker(-2, method) + "FAILURES!!!\nINSTRUMENTATION_CODE: -1\n"
        self.emulator.instrument.side_effect = None
        self.emulator.instrument.return_value = bridge.instrumentation_result(raw, method)
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_BACKGROUND_INSTRUMENTATION_FAILED"):
            bridge.background_delivery(self.harness, self.emulator, self.evidence)
        self.assertEqual(self.counts.call_count, 1)
        self.assertEqual(self.evidence["background_delivery"]["phases"][0]["outcome"], "failed")
        self.assertFalse(self.evidence["background_delivery"]["passed"])

    def test_missing_or_wrong_worker_completion_cannot_be_masked_by_two_server_receipts(self):
        queue, worker = bridge.BACKGROUND_METHODS
        for raw in ("OK (1 test)\nINSTRUMENTATION_CODE: -1\n",
                    marker(1, queue) + marker(0, queue) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n",
                    marker(1, worker) + marker(-2, worker) + "FAILURES!!!\nINSTRUMENTATION_CODE: -1\n"):
            self.counts.reset_mock()
            self.counts.side_effect = [self.snapshot(1), self.snapshot(1), self.snapshot(2)]
            self.emulator.instrument.side_effect = [self.success(queue), bridge.instrumentation_result(raw, worker)]
            with self.subTest(raw=raw[:25]), self.assertRaisesRegex(
                    bridge.EmulatorError, "EMULATOR_BACKGROUND_INSTRUMENTATION_FAILED"):
                bridge.background_delivery(self.harness, self.emulator, self.evidence)
            self.assertEqual(self.counts.call_count, 2)
            self.assertFalse(self.evidence["background_delivery"]["passed"])
            self.assertNotIn("server_counts", self.evidence["background_delivery"]["phases"][1])

    def test_worker_missing_extra_or_changed_effects_cannot_pass(self):
        invalid = [{**self.snapshot(2), field: value} for field, value in
                   (("enrollments", 2), ("revisions", 1), ("receipts", 3), ("jobs", 1),
                    ("jobs", 3), ("jobs_done", 0), ("jobs_done", 3))]
        for counts in invalid:
            self.counts.side_effect = [self.snapshot(1), self.snapshot(1), counts]
            with self.subTest(counts=counts), self.assertRaisesRegex(
                    bridge.EmulatorError, "EMULATOR_BACKGROUND_EFFECT_MISMATCH"):
                bridge.background_delivery(self.harness, self.emulator, self.evidence)
            result = self.evidence["background_delivery"]
            self.assertFalse(result["passed"])
            self.assertTrue(result["phases"][1]["passed"])
            self.assertEqual(result["phases"][1]["server_counts"], counts)

    def test_two_receipts_do_not_prove_both_backend_jobs_completed(self):
        self.counts.side_effect = [self.snapshot(1), self.snapshot(1), self.snapshot(2, 1)]
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_BACKGROUND_EFFECT_MISMATCH"):
            bridge.background_delivery(self.harness, self.emulator, self.evidence)
        self.assertFalse(self.evidence["background_delivery"]["passed"])

    def test_new_methods_still_require_exact_class_and_one_completed_method(self):
        for method in bridge.BACKGROUND_METHODS:
            self.assertTrue(self.success(method)["passed"])
            raw = marker(1, method) + marker(0, method) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
            for invalid in (raw.replace("current=1", "current=2"), raw.replace("numtests=1", "numtests=2"),
                            raw.replace(bridge.TEST_CLASS, bridge.CREDENTIAL_CLASS)):
                self.assertEqual(bridge.instrumentation_result(invalid, method)["outcome"], "incomplete")


class CredentialHandshakeTests(unittest.TestCase):
    def setUp(self):
        self.emulator = Mock()
        self.now = 0.0
        self.handshake = bridge.CredentialHandshake(self.emulator, clock=lambda: self.now)

    def step(self, phase):
        self.now += 1
        self.emulator.credential_marker.return_value = phase
        self.handshake.tick()

    def test_ordered_cancel_current_pin_and_stale_pin_are_each_once(self):
        for phase in ["absent", "starting", "cancel_ready", "cancel_ready", "unlock_ready",
                      "unlock_ready", "recreate_ready", "stale_ready"]:
            self.step(phase)
        self.emulator.credential_focus.return_value = "com.android.settings"
        self.step("stale_ready")
        self.emulator.credential_returned.assert_not_called()
        self.emulator.credential_focus.return_value = bridge.PACKAGE
        self.step("stale_ready")
        self.emulator.credential_returned.assert_called_once()
        self.step("stale_returned")
        self.step("completed")
        result = self.handshake.finish()
        self.assertEqual(result["actions"], ["cancel", "current_pin", "stale_pin"])
        self.assertEqual([call.args for call in self.emulator.credential_action.call_args_list],
                         [("cancel",), ("pin",), ("pin",)])
        self.assertTrue(result["completed"])

    def test_transient_start_and_recreate_markers_may_be_unobserved(self):
        for phase in ["cancel_ready", "unlock_ready", "stale_ready"]:
            self.step(phase)
        self.emulator.credential_focus.return_value = bridge.PACKAGE
        self.step("stale_ready")
        self.step("completed")
        self.assertTrue(self.handshake.finish()["completed"])

    def test_later_action_cannot_skip_cancellation(self):
        for phase in ["unlock_ready", "stale_ready", "stale_returned", "completed"]:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED"):
                self.step(phase)
        self.emulator.credential_action.assert_not_called()

    def test_invalid_private_marker_is_never_copied_to_error(self):
        for phase in ["PRIVATE_CANARY", "123456", "unlock_ready\n"]:
            with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_CREDENTIAL_MARKER_DENIED$"):
                self.step(phase)
        self.emulator.credential_action.assert_not_called()

    def test_regressed_marker_after_current_pin_is_rejected(self):
        self.step("cancel_ready")
        self.step("unlock_ready")
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED"):
            self.step("cancel_ready")

    def test_transient_markers_cannot_regress_or_restart_fixture(self):
        self.step("starting")
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED"):
            self.step("absent")

    def test_timeout_is_bounded_and_never_implies_completion(self):
        self.now = 45
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT"):
            self.handshake.tick()
        self.emulator.credential_action.assert_not_called()

    def test_marker_completion_requires_exact_credential_class_and_method(self):
        raw = marker(1, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
        raw += marker(0, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
        raw += "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"
        result = bridge.instrumentation_result(raw, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
        self.assertTrue(result["passed"])
        self.assertEqual(result["method_completed_count"], 1)
        self.assertFalse(bridge.instrumentation_result(raw, METHOD)["passed"])
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_TEST_METHOD_DENIED"):
            bridge.instrumentation_result(raw, METHOD, bridge.CREDENTIAL_CLASS)

    def test_actual_tick_callback_failure_stops_bounded_client(self):
        callback = Mock(side_effect=bridge.EmulatorError("EMULATOR_CREDENTIAL_FOCUS_DENIED"))
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_FOCUS_DENIED"):
            bridge.run_bounded([bridge.sys.executable, "-c", "import time; time.sleep(3)"], on_tick=callback)
        callback.assert_called_once()

    def test_focus_parser_rejects_other_user_ambiguous_and_nonwindow_lines(self):
        self.assertEqual(bridge.focused_package(credential_window()),
                         "com.android.settings")
        self.assertEqual(bridge.focused_package(credential_window("com.android.systemui", 10055)),
                         "com.android.systemui")
        for raw in ["mCurrentFocus=null", "mCurrentFocus=Window{a11 u10 com.android.settings/.ConfirmLockPassword}",
                    "mFocusedApp=ActivityRecord{a11 u0 com.android.settings/.ConfirmLockPassword}",
                    "mCurrentFocus=Window{a11 u0 com.android.settings/.ConfirmLockPassword}\n"
                    "mCurrentFocus=Window{a12 u0 com.android.settings/.ConfirmLockPassword}"]:
            self.assertIsNone(bridge.focused_package(raw))

    def test_focus_owner_cannot_be_ambiguous_malformed_or_borrowed(self):
        raw = credential_window()
        owner = "    mOwnerUid=1000 showForAllUsers=false package=com.android.settings appop=NONE\n"
        for invalid in (raw + "mCurrentFocus=null\n", raw + "mCurrentFocus = malformed\n",
                raw + "mCurrentFocus=Window{b22 u10 Other}\n", raw + "    mOwnerUid=invalid\n",
                raw + owner, raw.replace(owner, "      " + owner.lstrip()),
                raw.replace(owner, "  Window #1 Window{def u10 Other}:\n" + owner),
                raw.replace(owner, "  Window #broken\n" + owner),
                raw.replace(owner, "    Window #broken\n" + owner),
                raw.replace(owner, "  OtherSection\n" + owner),
                raw.replace("package=com.android.settings", "package=android"),
                raw.replace("mOwnerUid=1000", "mOwnerUid=1000 mOwnerUid=1000")):
            with self.subTest(raw=invalid):
                self.assertIsNone(bridge.focused_window(invalid))
                self.assertIsNone(bridge.focused_package(invalid))


class OwnedTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.run = self.root / ".cache/m1-runtime/mobile-emulator" / ("a" * 24)
        self.run.mkdir(parents=True)
        self.patch_root = patch.object(bridge, "ROOT", self.root)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)
        self.tools, self.harness = Mock(), Mock()
        self.harness.assert_owned = Mock()
        self.tools.adb = "adb.exe"
        self.target = {"serial": bridge.SERIAL, "state": "device", "transport": "7"}
        self.tools.discover.return_value = [self.target]
        self.emulator = bridge.OwnedEmulator(self.tools, self.harness, self.run)
        self.emulator.child = Mock()
        self.emulator.child.poll.return_value = None
        # TASK-110 default: no native stage file before or after a credential run.
        self.emulator.credential_stage = Mock(return_value="absent")
        # TASK-113 default: no native window census file before or after a credential run.
        self.emulator.credential_windows = Mock(return_value="absent")

    def test_command_pins_transport_and_checks_held_random_avd(self):
        with patch.object(bridge, "run_bounded", side_effect=[self.emulator.name + "\nOK\n", "36\n"]) as run:
            self.assertEqual(self.emulator.command("shell", "getprop", "ro.build.version.sdk"), "36\n")
        self.assertEqual(run.call_args_list[0].args[0], ["adb.exe", "-t", "7", "emu", "avd", "name"])
        self.assertEqual(run.call_args_list[1].args[0][:3], ["adb.exe", "-t", "7"])

    def test_mismatching_avd_refuses_target_command(self):
        with patch.object(bridge, "run_bounded", return_value="UserAvd\nOK\n") as run:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_AVD_IDENTITY"):
                self.emulator.command("shell", "settings", "put", "system", "a", "b")
        self.assertEqual(run.call_count, 1)

    def test_reconnected_transport_is_never_adopted(self):
        self.emulator.target = self.target.copy()
        self.tools.discover.return_value = [{**self.target, "transport": "8"}]
        with patch.object(bridge, "run_bounded") as run:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_TRANSPORT_CHANGED"):
                self.emulator.identity()
        run.assert_not_called()

    def test_phone_cannot_match_fixed_emulator_target(self):
        self.tools.discover.return_value = [{**self.target, "serial": "synthetic-phone"}]
        with patch.object(bridge, "run_bounded") as run:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_TRANSPORT_UNAVAILABLE"):
                self.emulator.command("shell", "locksettings", "unexpected")
        run.assert_not_called()

    def test_exited_owned_process_refuses_all_adb_commands(self):
        self.emulator.child.poll.return_value = 0
        with patch.object(bridge, "run_bounded") as run:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CHILD_STOPPED"):
                self.emulator.identity()
        run.assert_not_called()

    def test_existing_emulator_preflight_refuses_before_avd_creation(self):
        with patch.object(bridge, "ports_available"), patch.object(bridge, "OwnedProcessTree") as owner:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_TARGET_PREEXISTING"):
                self.emulator.__enter__()
        self.assertFalse((self.run / "avd").exists())
        owner.assert_not_called()

    def test_existing_package_is_not_replaced(self):
        self.emulator.command = Mock(return_value="package:" + bridge.PACKAGE)
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_PACKAGE_PREEXISTING"):
            self.emulator.install([], [])
        self.assertFalse(any(call.args[0] == "install" for call in self.emulator.command.call_args_list))

    def test_existing_reverse_is_not_rebound(self):
        self.emulator.command = Mock(side_effect=["", "", "usb tcp:18082 tcp:9999"])
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_REVERSE_PREEXISTING"):
            self.emulator.install([], [])
        self.assertEqual(self.emulator.command.call_count, 3)

    def test_only_agreed_live_methods_can_run(self):
        self.emulator.unlock = Mock()
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_TEST_METHOD_DENIED"):
            self.emulator.instrument("OtherTest#resetEverything")
        self.emulator.unlock.assert_not_called()

    def test_external_or_root_runtime_path_is_denied(self):
        for path in [self.root, self.root.parent / "outside", Path("relative")]:
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_PATH_DENIED"):
                bridge.checked_path(path)

    def test_bad_generated_avd_name_is_denied(self):
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_NAME_DENIED"):
            bridge.OwnedEmulator(self.tools, self.harness, self.run.parent / "existing-user-avd")

    def test_cleanup_closes_only_held_job_and_verifies_ports(self):
        self.emulator.owner = Mock()
        self.emulator.child.poll.return_value = 0
        sock = MagicMock()
        sock.__enter__.return_value.connect_ex.return_value = 1
        with patch.object(bridge.socket, "socket", return_value=sock):
            self.emulator.__exit__(None, None, None)
        self.emulator.owner.close.assert_called_once()
        self.assertTrue(self.emulator.evidence["owned_emulator_ports_closed"])
        self.tools.command.assert_not_called()

    def test_cleanup_uncertainty_preserves_database_and_never_selects_other_target(self):
        self.emulator.owner = Mock()
        self.emulator.owner.close.side_effect = RuntimeError("private failure")
        preserve = Mock()
        with patch.dict(bridge.sys.modules, {"tests.browser_runner": SimpleNamespace(preserve_database=preserve)}):
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CLEANUP_UNCERTAIN"):
                self.emulator.__exit__(None, None, None)
        preserve.assert_called_once()
        self.tools.command.assert_not_called()

    def test_pin_only_enters_stdin_after_system_focus_guard(self):
        self.emulator.pin = "123456"
        self.emulator.credential_focus = Mock(return_value="com.android.settings")
        self.emulator.command = Mock(return_value="")
        self.emulator.credential_action("pin")
        call = self.emulator.command.call_args
        self.assertEqual(call.args, ("shell",))
        self.assertIn(b"123456", call.kwargs["stdin"])
        self.assertNotIn("123456", str(call.args))
        self.assertEqual(call.kwargs["timeout"], 5)

    def test_unlock_requires_actual_keyguard_and_systemui_focus_before_pin(self):
        self.emulator.pin = "123456"
        trust_reads = 0
        def respond(*args, **kwargs):
            nonlocal trust_reads
            if args == ("shell", "pm", "list", "packages", "-U", "--user", "0", "com.android.systemui"):
                return "package:com.android.systemui uid:10055\n"
            if args == ("shell", "dumpsys", "trust"):
                trust_reads += 1
                return LOCKED if trust_reads == 1 else UNLOCKED
            if args == ("shell", "dumpsys", "window", "policy"):
                return KEYGUARD
            if args == ("shell", "am", "get-current-user"):
                return "0\n"
            if args == ("shell", "dumpsys", "window", "-a"):
                return LOCK_WINDOW
            if kwargs.get("stdin"):
                self.assertTrue(all(self.emulator.evidence["unlock_preconditions"].values()))
                self.assertEqual(args, ("shell",))
            return ""
        self.emulator.command = Mock(side_effect=respond)
        with patch.object(bridge.time, "sleep"):
            self.emulator.unlock()
        calls = self.emulator.command.call_args_list
        pin_index = next(i for i, call in enumerate(calls) if "stdin" in call.kwargs)
        self.assertEqual(calls[pin_index-1].args, ("shell", "dumpsys", "window", "-a"))
        self.assertEqual(calls[pin_index-1].kwargs, {"timeout": 5})
        self.assertEqual(sum("stdin" in call.kwargs for call in calls), 1)
        self.assertNotIn("123456", str(self.emulator.evidence))

    def test_unlock_denies_wrong_focus_unlocked_or_unknown_keyguard_without_pin(self):
        for condition in ("focus", "trust", "policy", "uid", "activity_user"):
            self.emulator.pin = "123456"
            def respond(*args, **kwargs):
                if args[:4] == ("shell", "pm", "list", "packages"):
                    return "" if condition == "uid" else "package:com.android.systemui uid:10055\n"
                if args == ("shell", "dumpsys", "trust"):
                    return UNLOCKED if condition == "trust" else LOCKED
                if args == ("shell", "dumpsys", "window", "policy"):
                    return "" if condition == "policy" else KEYGUARD
                if args == ("shell", "am", "get-current-user"):
                    return "10\n" if condition == "activity_user" else "0\n"
                if args == ("shell", "dumpsys", "window", "-a"):
                    return "" if condition == "focus" else LOCK_WINDOW
                return ""
            self.emulator.command = Mock(side_effect=respond)
            with self.subTest(condition=condition), patch.object(bridge.time, "sleep"):
                with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_UNLOCK_TARGET_DENIED"):
                    self.emulator.unlock()
            self.assertFalse(any("stdin" in call.kwargs for call in self.emulator.command.call_args_list))
            self.assertNotIn("123456", str(self.emulator.evidence))

    def unlock_responder(self, ready_after):
        """Keyguard policy/lock window appear only from observation `ready_after` (0-based)."""
        state = {"policy_reads": 0, "trust_reads": 0, "pin_sent": False}
        def respond(*args, **kwargs):
            if args[:4] == ("shell", "pm", "list", "packages"):
                return "package:com.android.systemui uid:10055\n"
            if args == ("shell", "dumpsys", "trust"):
                state["trust_reads"] += 1
                return UNLOCKED if state["pin_sent"] else LOCKED
            if args == ("shell", "dumpsys", "window", "policy"):
                state["policy_reads"] += 1
                return KEYGUARD if state["policy_reads"] > ready_after else ""
            if args == ("shell", "am", "get-current-user"):
                return "0\n"
            if args == ("shell", "dumpsys", "window", "-a"):
                return LOCK_WINDOW if state["policy_reads"] > ready_after else ""
            if kwargs.get("stdin"):
                self.assertTrue(all(self.emulator.evidence["unlock_preconditions"].values()))
                state["pin_sent"] = True
            return ""
        return respond, state

    def test_late_keyguard_is_accepted_within_bounded_observations(self):
        self.emulator.pin = "123456"
        respond, state = self.unlock_responder(ready_after=2)
        self.emulator.command = Mock(side_effect=respond)
        with patch.object(bridge.time, "sleep"):
            self.emulator.unlock()
        observations = self.emulator.evidence["unlock_target_observations"]
        self.assertEqual(len(observations), 3)
        self.assertEqual(observations[-1], [])
        self.assertTrue(observations[0] and set(observations[0]) <= set(self.emulator.evidence["unlock_preconditions"]))
        self.assertEqual(sum("stdin" in call.kwargs for call in self.emulator.command.call_args_list), 1)
        self.assertNotIn("123456", str(self.emulator.evidence))

    def test_absent_keyguard_refuses_after_exact_observation_bound_without_pin(self):
        self.emulator.pin = "123456"
        respond, state = self.unlock_responder(ready_after=10**6)
        self.emulator.command = Mock(side_effect=respond)
        with patch.object(bridge.time, "sleep") as sleep, \
                self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_UNLOCK_TARGET_DENIED$"):
            self.emulator.unlock()
        observations = self.emulator.evidence["unlock_target_observations"]
        self.assertEqual(len(observations), bridge.UNLOCK_TARGET_OBSERVATIONS)
        self.assertEqual(state["policy_reads"], bridge.UNLOCK_TARGET_OBSERVATIONS)
        self.assertTrue(all(item and set(item) <= set(self.emulator.evidence["unlock_preconditions"])
                            for item in observations))
        self.assertEqual(sleep.call_args_list.count(call(bridge.UNLOCK_TARGET_INTERVAL)),
                         bridge.UNLOCK_TARGET_OBSERVATIONS - 1)
        self.assertFalse(any("stdin" in c.kwargs for c in self.emulator.command.call_args_list))

    def test_other_guard_errors_are_not_retried(self):
        self.emulator.require_unlock_target = Mock(side_effect=bridge.EmulatorError("EMULATOR_COMMAND_TIMEOUT"))
        with patch.object(bridge.time, "sleep") as sleep, \
                self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_COMMAND_TIMEOUT$"):
            self.emulator.await_unlock_target()
        self.emulator.require_unlock_target.assert_called_once_with()
        sleep.assert_not_called()
        self.assertEqual(self.emulator.evidence["unlock_target_observations"], [])

    def test_credential_focus_queries_one_bounded_full_window_snapshot(self):
        self.emulator.command = Mock(side_effect=[
            "package:com.android.settings uid:1000\npackage:android uid:1000\n", credential_window()])
        self.assertEqual(self.emulator.credential_focus(), "com.android.settings")
        calls = self.emulator.command.call_args_list
        self.assertEqual([call.args for call in calls], [
            ("shell", "pm", "list", "packages", "-U", "--user", "0"),
            ("shell", "dumpsys", "window", "-a")])
        self.assertTrue(all(call.kwargs == {"timeout": 5} for call in calls))

    def test_credential_pin_and_cancel_require_actual_unique_window_and_installed_owner(self):
        packages = "package:com.android.settings uid:1000\n"
        raw = credential_window()
        for package_rows, window in ((packages, raw + "mCurrentFocus=null\n"),
                (packages, raw.replace("  Window #0", "  Unknown #0")),
                (packages, raw.replace("mOwnerUid=1000", "mOwnerUid=1001")),
                (packages, raw.replace("package=com.android.settings", "package=android")),
                (packages + packages, raw), (packages.replace("uid:1000", "uid:101000"), raw),
                ("package:android uid:1000\n", raw), (packages + "malformed\n", raw)):
            for action in ("pin", "cancel"):
                self.emulator.pin = "123456"
                self.emulator.command = Mock(side_effect=[package_rows, window])
                self.emulator.systemui_prompt_focus = Mock(return_value=False)  # TASK-117 fallback refuses here
                with self.subTest(action=action), self.assertRaisesRegex(
                        bridge.EmulatorError, "EMULATOR_CREDENTIAL_FOCUS_DENIED"):
                    self.emulator.credential_action(action)
                self.assertEqual(self.emulator.command.call_count, 2)
                self.emulator.systemui_prompt_focus.assert_called_once_with()
                self.assertFalse(any("stdin" in call.kwargs for call in self.emulator.command.call_args_list))

    def test_credential_pin_follows_same_snapshot_owner_proof_and_keeps_stdin_only(self):
        self.emulator.pin = "123456"
        self.emulator.command = Mock(side_effect=["package:com.android.settings uid:1000\n",
                                                  credential_window(), ""])
        self.emulator.credential_action("pin")
        calls = self.emulator.command.call_args_list
        self.assertEqual(calls[-2].args, ("shell", "dumpsys", "window", "-a"))
        self.assertEqual(calls[-1].args, ("shell",))
        self.assertIn(b"123456", calls[-1].kwargs['stdin'])
        self.assertNotIn("123456", str([call.args for call in calls]))

    def test_credential_return_identity_requires_exact_owned_package_and_window(self):
        for package, uid, expected in (("com.android.settings", 1000, "com.android.settings"),
                ("com.android.systemui", 10055, "com.android.systemui"),
                (bridge.PACKAGE, 10234, bridge.PACKAGE), ("other.app", 10235, None)):
            self.emulator.command = Mock(side_effect=[f"package:{package} uid:{uid}\n",
                                                      credential_window(package, uid)])
            with self.subTest(package=package):
                self.assertEqual(self.emulator.credential_focus(), expected)
        self.emulator.command = Mock(side_effect=[f"package:{bridge.PACKAGE} uid:10234\n",
                                                  credential_window(bridge.PACKAGE, 10235)])
        self.assertIsNone(self.emulator.credential_focus())

    def test_wrong_focus_prevents_pin_or_cancel_dispatch(self):
        self.emulator.pin = "123456"
        self.emulator.credential_focus = Mock(return_value=bridge.PACKAGE)
        self.emulator.systemui_prompt_focus = Mock(return_value=False)  # TASK-117 fallback refuses here
        self.emulator.command = Mock()
        for action in ("pin", "cancel"):
            with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_FOCUS_DENIED"):
                self.emulator.credential_action(action)
        self.emulator.command.assert_not_called()
        self.assertEqual(self.emulator.systemui_prompt_focus.call_count, 2)

    def test_host_acknowledgement_requires_stale_marker_and_returned_app_focus(self):
        self.emulator.credential_marker = Mock(return_value="stale_ready")
        self.emulator.credential_focus = Mock(return_value="com.android.settings")
        self.emulator.command = Mock()
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_RETURN_DENIED"):
            self.emulator.credential_returned()
        self.emulator.command.assert_not_called()
        self.emulator.credential_focus.return_value = bridge.PACKAGE
        self.emulator.credential_marker.side_effect = ["stale_ready", "stale_returned"]
        self.emulator.credential_returned()
        call = self.emulator.command.call_args
        self.assertEqual(call.args, ("shell", "run-as", bridge.PACKAGE, "sh"))
        self.assertIn(b"stale_returned", call.kwargs["stdin"])
        self.assertIn(b"mv -f", call.kwargs["stdin"])

    def test_marker_read_has_fixed_filename_and_byte_limit(self):
        self.emulator.command = Mock(return_value="cancel_ready")
        self.assertEqual(self.emulator.credential_marker(), "cancel_ready")
        call = self.emulator.command.call_args
        self.assertIn(b"head -c 33 no_backup/m2-credential-phase", call.kwargs["stdin"])
        self.assertEqual(call.kwargs["maximum"], 64)
        self.emulator.command.return_value = "completed\nPRIVATE_CANARY"
        with self.assertRaisesRegex(bridge.EmulatorError, "EMULATOR_CREDENTIAL_MARKER_DENIED"):
            self.emulator.credential_marker()

    def test_existing_credential_marker_refuses_to_adopt_prior_case(self):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="starting")
        with patch.object(bridge, "run_bounded") as run:
            result = self.emulator.instrument_credentials()
        run.assert_not_called()
        self.assertEqual(result["outcome"], "incomplete")
        self.assertEqual(result["code"], "EMULATOR_CREDENTIAL_MARKER_PREEXISTING")

    def test_credential_failure_is_not_replaced_by_marker_success(self):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        raw = marker(1, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
        raw += marker(-2, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
        raw += "FAILURES!!!\nINSTRUMENTATION_CODE: -1\n"
        hand = Mock(observed=["completed"], actions=["cancel", "current_pin", "stale_pin"])
        with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                patch.object(bridge, "run_bounded", return_value=raw):
            result = self.emulator.instrument_credentials()
        self.assertFalse(result["passed"])
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["method_completed_count"], 1)
        hand.finish.assert_not_called()

    def test_credential_incomplete_instrumentation_cannot_pass_completed_marker(self):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        hand = Mock(observed=["completed"], actions=["cancel", "current_pin", "stale_pin"])
        with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                patch.object(bridge, "run_bounded", return_value="OK (1 test)\n"):
            result = self.emulator.instrument_credentials()
        self.assertFalse(result["passed"])
        self.assertEqual(result["outcome"], "incomplete")
        self.assertEqual(result["method_completed_count"], 0)
        hand.finish.assert_not_called()

    def test_credential_diagnostic_attachment_preserves_failure_handshake_and_exact_command(self):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        raw, _ = credential_failure_output()
        for body, expected in ((raw, "INITIAL_LOCK_WAIT"),
                (raw.replace("SystemCredentialIntegrationTest.kt:101", "Unknown Source"), "UNKNOWN")):
            hand = Mock(observed=["absent", "starting"], actions=[])
            with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                    patch.object(bridge, "run_bounded", return_value=body) as run:
                result = self.emulator.instrument_credentials()
            self.assertEqual(result.pop("credential_failure_site"), expected)
            self.assertEqual(result.pop("credential_stage"), {"status": "absent"})
            self.assertEqual(result.pop("credential_windows"), {"status": "absent"})
            self.assertEqual(result, {"class": bridge.CREDENTIAL_CLASS, "method": bridge.CREDENTIAL_METHOD,
                **bridge.instrumentation_result(body, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS),
                "handshake": {"completed": False, "observed_markers": ["absent", "starting"], "actions": []}})
            self.assertNotIn("CANARY", str(result))
            hand.finish.assert_not_called()
            run.assert_called_once_with([self.emulator.tools.adb, "-t", self.target["transport"],
                "shell", "am", "instrument", "-w", "-r", "-e", "class",
                bridge.CREDENTIAL_CLASS + "#" + bridge.CREDENTIAL_METHOD, "-e", "ownedEmulator", "true",
                f"{bridge.TEST_PACKAGE}/{bridge.RUNNER}"], timeout=180, on_tick=hand.tick)

    def test_credential_later_failure_has_no_diagnostic_attachment(self):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        raw, _ = credential_failure_output()
        hand = Mock(observed=["absent", "starting", "cancel_ready"], actions=["cancel"])
        with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                patch.object(bridge, "run_bounded", return_value=raw):
            result = self.emulator.instrument_credentials()
        self.assertNotIn("credential_failure_site", result)
        self.assertFalse(result["passed"])
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["handshake"]["actions"], ["cancel"])
        hand.finish.assert_not_called()

    def test_credential_parser_error_keeps_completed_native_failure_and_no_actions(self):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        raw, _ = credential_failure_output()
        for error in (ValueError("PRIVATE_PARSER_CANARY"), bridge.EmulatorError("PRIVATE_PARSER_CANARY")):
            hand = Mock(observed=["absent", "starting"], actions=[])
            with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                    patch.object(bridge, "run_bounded", return_value=raw), \
                    patch.object(bridge, "credential_stack_site", side_effect=error):
                result = self.emulator.instrument_credentials()
            self.assertEqual(result.pop("credential_failure_site"), "UNKNOWN")
            self.assertEqual(result.pop("credential_stage"), {"status": "absent"})
            self.assertEqual(result.pop("credential_windows"), {"status": "absent"})
            self.assertEqual(result, {"class": bridge.CREDENTIAL_CLASS, "method": bridge.CREDENTIAL_METHOD,
                **bridge.instrumentation_result(raw, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS),
                "handshake": {"completed": False, "observed_markers": ["absent", "starting"], "actions": []}})
            hand.finish.assert_not_called()
            self.assertNotIn("CANARY", str(result))

    def credential_run(self, stage_reads, run_effect):
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.credential_stage = Mock(side_effect=stage_reads)
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        hand = Mock(observed=["absent", "starting"], actions=[])
        with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                patch.object(bridge, "run_bounded", side_effect=run_effect) as run:
            result = self.emulator.instrument_credentials()
        return result, hand, run

    def test_stage_read_uses_fixed_file_byte_limit_and_owned_package(self):
        command = Mock(return_value="absent")
        self.emulator.command = command
        self.assertEqual(bridge.OwnedEmulator.credential_stage(self.emulator), "absent")
        call_ = command.call_args
        self.assertEqual(call_.args, ("shell", "run-as", bridge.PACKAGE, "sh"))
        self.assertIn(b"head -c 161 no_backup/m2-credential-stage", call_.kwargs["stdin"])
        self.assertEqual((call_.kwargs["timeout"], call_.kwargs["maximum"]), (5, 192))

    def test_preexisting_stage_refuses_run_without_observation(self):
        result, _, run = self.credential_run([STAGE_RECORD], [AssertionError("not reached")])
        run.assert_not_called()
        self.assertEqual((result["outcome"], result["code"]), ("incomplete", "EMULATOR_CREDENTIAL_STAGE_PREEXISTING"))
        self.assertNotIn("credential_stage", result)

    def test_handshake_timeout_keeps_original_outcome_and_attaches_finite_stage(self):
        result, hand, _ = self.credential_run(
            ["absent", STAGE_RECORD], bridge.EmulatorError("EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT"))
        stage = result.pop("credential_stage")
        self.assertEqual(result.pop("credential_windows"), {"status": "absent"})
        self.assertEqual(result, {"class": bridge.CREDENTIAL_CLASS, "method": bridge.CREDENTIAL_METHOD,
            "passed": False, "outcome": "incomplete", "method_completed_count": 0,
            "code": "EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT",
            "handshake": {"completed": False, "observed_markers": ["absent", "starting"], "actions": []}})
        self.assertEqual(stage, {"status": "valid", **bridge.credential_stage_record(STAGE_RECORD)})
        self.assertEqual(stage["stage"], "window_wait_1")
        self.assertEqual(self.emulator.credential_stage.call_count, 2)
        hand.finish.assert_not_called()

    def test_stage_read_failure_or_garbage_cannot_change_outcome(self):
        for second, expected in ((bridge.EmulatorError("PRIVATE_CANARY"), "unavailable"),
                (ValueError("PRIVATE_CANARY"), "unavailable"), ("PRIVATE_CANARY", "invalid"),
                (STAGE_RECORD + "\nPRIVATE_CANARY", "invalid"), ("absent", "absent")):
            with self.subTest(expected=expected, second=repr(second)[:24]):
                result, _, _ = self.credential_run(
                    ["absent", second], bridge.EmulatorError("EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT"))
                self.assertEqual(result.pop("credential_stage"), {"status": expected})
                self.assertEqual(result.pop("credential_windows"), {"status": "absent"})
                self.assertEqual((result["passed"], result["outcome"], result["code"]),
                                 (False, "incomplete", "EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT"))
                self.assertNotIn("CANARY", str(result))

    def test_completed_failure_also_attaches_stage_and_keeps_site_rule(self):
        raw, _ = credential_failure_output()
        result, _, _ = self.credential_run(["absent", STAGE_RECORD], [raw])
        self.assertEqual(result["outcome"], "failed")
        self.assertEqual(result["credential_failure_site"], "INITIAL_LOCK_WAIT")
        self.assertEqual(result["credential_stage"]["status"], "valid")

    def test_passing_run_does_not_read_stage(self):
        raw = (marker(1, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
               + marker(0, bridge.CREDENTIAL_METHOD, bridge.CREDENTIAL_CLASS)
               + "\nOK (1 test)\n\nINSTRUMENTATION_CODE: -1\n")
        done = {"completed": True, "observed_markers": ["absent", "completed"],
                "actions": ["cancel", "current_pin", "stale_pin"]}
        self.emulator.unlock = Mock()
        self.emulator.credential_marker = Mock(return_value="absent")
        self.emulator.credential_stage = Mock(return_value="absent")
        self.emulator.identity = Mock()
        self.emulator.target = self.target
        hand = Mock(observed=["absent", "completed"], actions=done["actions"])
        hand.finish.return_value = done
        with patch.object(bridge, "CredentialHandshake", return_value=hand), \
                patch.object(bridge, "run_bounded", return_value=raw):
            result = self.emulator.instrument_credentials()
        self.assertTrue(result["passed"])
        self.assertNotIn("credential_stage", result)
        self.assertEqual(self.emulator.credential_stage.call_count, 1)


    def test_preexisting_window_census_refuses_run(self):
        self.emulator.credential_windows = Mock(return_value=WINDOWS_RECORD)
        result, _, run = self.credential_run(["absent"], [AssertionError("not reached")])
        run.assert_not_called()
        self.assertEqual(result["code"], "EMULATOR_CREDENTIAL_WINDOWS_PREEXISTING")
        self.assertNotIn("credential_windows", result)

    def test_timeout_attaches_window_census_and_contains_failures(self):
        for second, expected in ((WINDOWS_RECORD, "valid"), ("PRIVATE_CANARY", "invalid"),
                (bridge.EmulatorError("PRIVATE_CANARY"), "unavailable"), (ValueError("PRIVATE_CANARY"), "unavailable")):
            with self.subTest(expected=expected):
                self.emulator.credential_windows = Mock(side_effect=["absent", second])
                result, _, _ = self.credential_run(
                    ["absent", STAGE_RECORD], bridge.EmulatorError("EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT"))
                windows = result.pop("credential_windows")
                self.assertEqual(windows["status"], expected)
                if expected == "valid":
                    self.assertEqual(windows, {"status": "valid", **bridge.credential_windows_record(WINDOWS_RECORD)})
                self.assertEqual((result["outcome"], result["code"], result["credential_stage"]["status"]),
                                 ("incomplete", "EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT", "valid"))
                self.assertNotIn("CANARY", str(result) + str(windows))

    def test_passing_run_does_not_read_window_census(self):
        self.test_passing_run_does_not_read_stage()
        self.assertEqual(self.emulator.credential_windows.call_count, 1)


    def test_systemui_prompt_fallback_sends_pin_only_after_all_four_conditions(self):
        self.emulator.pin = "123456"
        self.emulator.credential_focus = Mock(return_value=None)
        self.emulator.command = Mock(side_effect=[PROMPT_WINDOW, SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, UNLOCKED, ""])
        self.emulator.credential_action("pin")
        calls = self.emulator.command.call_args_list
        self.assertEqual([c.args for c in calls[:4]], [("shell", "dumpsys", "window", "-a"),
            ("shell", "pm", "list", "packages", "-U", "--user", "0"), ("shell", "dumpsys", "window", "policy"),
            ("shell", "dumpsys", "trust")])
        self.assertEqual(calls[-1].args, ("shell",))
        self.assertIn(b"123456", calls[-1].kwargs["stdin"])
        self.assertEqual(self.emulator.evidence["credential_prompt_focus"], [{"rule": "SYSTEMUI",
            "title_form": "PLAIN", "owner": "SYSTEMUI", "uid_match": True, "keyguard_hidden": True,
            "device_unlocked": True, "accepted": True}])
        self.assertNotIn("123456", json.dumps(self.emulator.evidence))

    def test_systemui_prompt_fallback_refuses_when_any_condition_fails(self):
        cases = {
            "lock_screen_showing": (PROMPT_WINDOW, SYSTEMUI_PACKAGES, KEYGUARD, UNLOCKED),
            "keyguard_ambiguous": (PROMPT_WINDOW, SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD.replace("      mIsShowing=false\n", ""), UNLOCKED),
            "keyguard_missing": (PROMPT_WINDOW, SYSTEMUI_PACKAGES, "", UNLOCKED),
            "device_locked": (PROMPT_WINDOW, SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, LOCKED),
            "trust_unknown": (PROMPT_WINDOW, SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, ""),
            "uid_mismatch": (PROMPT_WINDOW.replace("mOwnerUid=10055", "mOwnerUid=10056"), SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, UNLOCKED),
            "uid_unknown": (PROMPT_WINDOW, "package:com.android.settings uid:1000\n", HIDDEN_KEYGUARD, UNLOCKED),
            "other_owner": (PROMPT_WINDOW.replace("package=com.android.systemui", "package=android"), SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, UNLOCKED),
            "activity_title": (credential_window("com.android.systemui", 10055), SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, UNLOCKED),
            "no_focus": ("", SYSTEMUI_PACKAGES, HIDDEN_KEYGUARD, UNLOCKED),
        }
        for name, reads in cases.items():
            with self.subTest(case=name):
                self.emulator.pin = "123456"
                self.emulator.evidence = {}
                self.emulator.credential_focus = Mock(return_value=None)
                self.emulator.command = Mock(side_effect=list(reads))
                with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_CREDENTIAL_FOCUS_DENIED$"):
                    self.emulator.credential_action("pin")
                self.assertEqual(self.emulator.command.call_count, 4)
                self.assertFalse(any("stdin" in c.kwargs for c in self.emulator.command.call_args_list))
                self.assertFalse(self.emulator.evidence["credential_prompt_focus"][0]["accepted"])

    def test_systemui_prompt_fallback_read_failure_or_garbage_refuses(self):
        for effect in (bridge.EmulatorError("EMULATOR_COMMAND_TIMEOUT"),
                       [PROMPT_WINDOW, None, HIDDEN_KEYGUARD, UNLOCKED]):
            with self.subTest(effect=repr(effect)[:30]):
                self.emulator.pin = "123456"
                self.emulator.evidence = {}
                self.emulator.credential_focus = Mock(return_value=None)
                self.emulator.command = Mock(side_effect=effect)
                with self.assertRaisesRegex(bridge.EmulatorError, "^EMULATOR_CREDENTIAL_FOCUS_DENIED$"):
                    self.emulator.credential_action("cancel")
                self.assertFalse(any(c.args[:3] == ("shell", "input", "keyevent")
                                     for c in self.emulator.command.call_args_list))

    def test_existing_activity_gate_still_decides_first_without_fallback_reads(self):
        self.emulator.credential_focus = Mock(return_value="com.android.settings")
        self.emulator.systemui_prompt_focus = Mock()
        self.emulator.command = Mock()
        self.emulator.credential_action("cancel")
        self.emulator.systemui_prompt_focus.assert_not_called()
        self.assertEqual(self.emulator.command.call_args.args, ("shell", "input", "keyevent", "KEYCODE_BACK"))

    def test_systemui_prompt_evidence_is_bounded_fixed_codes(self):
        self.emulator.command = Mock(side_effect=[PROMPT_WINDOW + "PRIVATE_CANARY\n", SYSTEMUI_PACKAGES,
                                                  HIDDEN_KEYGUARD, UNLOCKED] * 9)
        for _ in range(9):
            self.emulator.systemui_prompt_focus()
        records = self.emulator.evidence["credential_prompt_focus"]
        self.assertEqual(len(records), 8)
        self.assertNotIn("CANARY", json.dumps(records))
        self.assertTrue(all(set(r) <= {"rule", "title_form", "owner", "uid_match", "keyguard_hidden",
                                       "device_unlocked", "accepted", "code"} for r in records))


PROMPT_WINDOW = """  Window #3 Window{b22 u0 BiometricPrompt}:
    mDisplayId=0 mSession=synthetic
    mOwnerUid=10055 showForAllUsers=true package=com.android.systemui appop=NONE
    mAttrs=synthetic
  mCurrentFocus=Window{b22 u0 BiometricPrompt}
"""
SYSTEMUI_PACKAGES = "package:com.android.systemui uid:10055\npackage:com.android.settings uid:1000\n"
HIDDEN_KEYGUARD = KEYGUARD.replace("showing=true", "showing=false").replace("mIsShowing=true", "mIsShowing=false")
STAGE_RECORD = "v1 n=7 st=window_wait_1 b=0 p=0 a=LOCKED w=0 l=RESUMED r=1"
WINDOWS_RECORD = "v1 n=4 st=window_wait_1 k=3 w=A11a,S00u,X00n"


class CredentialWindowsRecordTests(unittest.TestCase):
    def test_valid_census_maps_only_fixed_enums(self):
        self.assertEqual(bridge.credential_windows_record(WINDOWS_RECORD), {
            "sequence": 4, "stage": "window_wait_1", "window_count": 3, "windows": [
                {"type": "APPLICATION", "active": True, "focused": True, "owner": "APP"},
                {"type": "SYSTEM", "active": False, "focused": False, "owner": "SYSTEMUI"},
                {"type": "OTHER", "active": False, "focused": False, "owner": "NONE"}]})
        self.assertEqual(bridge.credential_windows_record("v1 n=1 st=window_wait_2 k=0 w=-")["windows"], [])
        refined = bridge.credential_windows_record("v1 n=2 st=window_wait_1 k=6 w=S11y,S00p,A00g,A00l,S00q,S00r")
        self.assertEqual([item["owner"] for item in refined["windows"]],
                         ["SYSTEM_SERVER", "PERMISSION_CONTROLLER", "GMS", "LAUNCHER", "OTHER_GOOGLE", "OTHER_AOSP"])
        self.assertEqual(set(bridge.WINDOW_OWNERS.values()), {"APP", "SETTINGS", "SYSTEMUI", "OTHER", "NONE",
            "SYSTEM_SERVER", "PERMISSION_CONTROLLER", "GMS", "LAUNCHER", "OTHER_GOOGLE", "OTHER_AOSP"})
        many = "v1 n=9 st=window_wait_3 k=12 w=" + ",".join(["A00o"] * 8)
        self.assertEqual(len(bridge.credential_windows_record(many)["windows"]), 8)

    def test_rejects_malformed_inconsistent_and_private_census(self):
        for raw in (WINDOWS_RECORD.replace("v1", "v2"), WINDOWS_RECORD.replace("window_wait_1", "bogus"),
                WINDOWS_RECORD.replace("k=3", "k=2"), WINDOWS_RECORD.replace("k=3", "k=4"),
                WINDOWS_RECORD.replace("A11a", "Z11a"), WINDOWS_RECORD.replace("A11a", "A21a"),
                WINDOWS_RECORD.replace("A11a", "A11z"), WINDOWS_RECORD + ",A11a", WINDOWS_RECORD + "\n",
                "v1 n=1 st=window_wait_1 k=9 w=" + ",".join(["A00o"] * 9), "v1 n=0 st=window_wait_1 k=0 w=-",
                WINDOWS_RECORD + " PRIVATE_CANARY", WINDOWS_RECORD.replace("A11a", "com.android.settings"),
                "", "absent", None):
            with self.subTest(raw=repr(raw)[:40]):
                self.assertIsNone(bridge.credential_windows_record(raw))

    def test_native_credential_predicate_keeps_application_rule_and_guards_systemui_rule(self):
        source = (bridge.ROOT / "android/app/src/androidTest/java/org/kapit/c2/mobile/sync/"
                  "SystemCredentialIntegrationTest.kt").read_text(encoding="utf-8")
        body = source.split("private fun credentialWindowPresent(): Boolean {", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("window.type == AccessibilityWindowInfo.TYPE_APPLICATION && (window.isActive || window.isFocused)", body)
        self.assertIn("window.type == AccessibilityWindowInfo.TYPE_SYSTEM && window.isActive && window.isFocused"
                      " && !keyguardLocked", body)
        self.assertIn(".isKeyguardLocked", body)
        self.assertIn('if (application) owner == credentialPackage else owner == "com.android.systemui"', body)

    def test_native_recreation_precondition_requires_stopped_or_prompt_covered(self):
        source = (bridge.ROOT / "android/app/src/androidTest/java/org/kapit/c2/mobile/sync/"
                  "SystemCredentialIntegrationTest.kt").read_text(encoding="utf-8")
        body = source.split("private fun coveredByPrompt(", 1)[1].split("\n    }\n", 1)[0]
        self.assertIn("Lifecycle.State.CREATED -> true", body)
        self.assertIn("Lifecycle.State.STARTED -> credentialWindowPresent()", body)
        self.assertIn("else -> false", body)
        self.assertEqual(source.count("coveredByPrompt(scenario)"), 2)
        self.assertNotIn("scenario.state == Lifecycle.State.CREATED", source)

    def test_native_census_codes_match_host_and_run_only_in_window_waits(self):
        source = (bridge.ROOT / "android/app/src/androidTest/java/org/kapit/c2/mobile/sync/"
                  "SystemCredentialIntegrationTest.kt").read_text(encoding="utf-8")
        body = source.split("private fun census()", 1)[1]
        self.assertEqual(set(re.findall(r'-> "([A-Z])"', body)), set(bridge.WINDOW_TYPES))
        self.assertEqual(set(re.findall(r'-> "([a-z])"', body)), set(bridge.WINDOW_OWNERS))
        self.assertEqual(source.count("census()"), 2)  # one definition, one call inside waitCredentialWindow
        wait = source.split("private fun waitCredentialWindow", 1)[1].split("\n    }", 1)[0]
        self.assertIn("census()", wait)
        self.assertIn("credentialWindowPresent().also", wait)


class CredentialStageRecordTests(unittest.TestCase):
    def test_valid_record_maps_only_fixed_fields(self):
        self.assertEqual(bridge.credential_stage_record(STAGE_RECORD), {"sequence": 7, "stage": "window_wait_1",
            "busy": False, "protected_content": False, "access": "LOCKED", "credential_window": False,
            "lifecycle": "RESUMED", "unlock_pending": True})
        early = bridge.credential_stage_record("v1 n=1 st=launch b=u p=u a=u w=u l=u r=u")
        self.assertEqual((early["stage"], early["busy"], early["access"], early["lifecycle"]),
                         ("launch", None, None, None))

    def test_every_native_stage_is_accepted(self):
        for stage in sorted(bridge.CREDENTIAL_STAGES):
            with self.subTest(stage=stage):
                self.assertEqual(bridge.credential_stage_record(
                    STAGE_RECORD.replace("window_wait_1", stage))["stage"], stage)

    def test_native_stage_list_matches_kotlin_source(self):
        source = (bridge.ROOT / "android/app/src/androidTest/java/org/kapit/c2/mobile/sync/"
                  "SystemCredentialIntegrationTest.kt").read_text(encoding="utf-8")
        block = source.split("val STAGES = setOf(", 1)[1].split(")", 1)[0]
        self.assertEqual(frozenset(re.findall(r'"([a-z0-9_]+)"', block)), bridge.CREDENTIAL_STAGES)
        self.assertNotIn("observedScenario", source)  # F1: no blocking lifecycle read in the observer

    def test_access_allowlist_matches_kotlin_enum(self):
        source = (bridge.ROOT / "android/app/src/main/java/org/kapit/c2/mobile/ui/"
                  "MobileUiState.kt").read_text(encoding="utf-8")
        block = source.split("enum class MobileAccess {", 1)[1].split("}", 1)[0]
        self.assertEqual(frozenset(re.findall(r"[A-Z_]+", block)), bridge.MOBILE_ACCESS)

    def test_rejects_unknown_malformed_oversize_and_private_values(self):
        for raw in (STAGE_RECORD.replace("v1", "v2"), STAGE_RECORD.replace("window_wait_1", "unknown_stage"),
                STAGE_RECORD.replace("LOCKED", "ROOT"), STAGE_RECORD.replace("RESUMED", "PAUSED"),
                STAGE_RECORD.replace("n=7", "n=0"), STAGE_RECORD.replace("n=7", "n=123456"),
                STAGE_RECORD.replace("b=0", "b=2"), STAGE_RECORD.replace(" r=1", ""),
                STAGE_RECORD + " r=1", STAGE_RECORD + "\n", " " + STAGE_RECORD,
                STAGE_RECORD.replace("w=0", "r=0"), STAGE_RECORD.replace("LOCKED", "LOCKÉD"),
                STAGE_RECORD + " " + "x" * 160, STAGE_RECORD + " PRIVATE_CANARY", "", "absent", None, b"v1"):
            with self.subTest(raw=repr(raw)[:40]):
                self.assertIsNone(bridge.credential_stage_record(raw))


if __name__ == "__main__":
    unittest.main()
