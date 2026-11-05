"""Pure CLI/result cleanup regressions; no ADB, harness, network or device."""
import ast
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from android.tools import phone_journey as journey


class FakePhone:
    def __init__(self, mode="success", preexisting=False, verify_failure=False):
        self.mode, self.mapping = mode, preexisting
        self.verify_failure, self.removal_attempted = verify_failure, False
        self.calls, self.list_queries = [], 0

    def verify(self):
        if self.verify_failure:
            raise journey.JourneyError("PHONE_APP_HASH_MISMATCH")
        return {"physical": True, "api": 35, "app_sha256": journey.APP_SHA256}

    def command(self, *parts, **kwargs):
        self.calls.append(parts)
        endpoint = journey.ENDPOINT
        if parts == ("reverse", "--no-rebind", endpoint, endpoint):
            self.mapping = True
            return ""
        if parts == ("reverse", "--remove", endpoint):
            self.removal_attempted = True
            if self.mode == "remove_failure":
                raise RuntimeError("PRIVATE_ADB_CANARY")
            if self.mode != "still_present":
                self.mapping = False
            return ""
        if parts == ("reverse", "--list"):
            self.list_queries += 1
            if self.list_queries == 3:
                if self.mode == "changed_target":
                    return f"synthetic {endpoint} tcp:19999\n"
                if self.mode == "already_absent":
                    self.mapping = False
                if self.mode == "pre_list_failure":
                    raise RuntimeError("PRIVATE_ADB_CANARY")
                if self.mode == "pre_malformed_list":
                    return "PRIVATE_ADB_CANARY"
            if self.removal_attempted and self.mode == "list_failure":
                raise RuntimeError("PRIVATE_ADB_CANARY")
            if self.removal_attempted and self.mode == "malformed_list":
                return "PRIVATE_ADB_CANARY"
            return f"synthetic {endpoint} {endpoint}\n" if self.mapping else ""
        raise AssertionError("Unexpected fake ADB command")


class FakeHarness:
    def __init__(self, exit_failure=False):
        self.exit_failure = exit_failure

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.exit_failure:
            raise journey.integration.IntegrationError("MOBILE_HARNESS_CLEANUP_UNCONFIRMED")
        return False

    def fault(self, mode):
        assert mode == "normal"

    def assert_owned(self):
        pass


class PhoneJourneyCleanupTests(unittest.TestCase):
    def invoke(self, mode="success", *, primary_failure=False,
               harness_exit_failure=False, preexisting=False, verify_failure=False):
        phone = FakePhone(mode, preexisting, verify_failure)
        empty = dict.fromkeys(("enrollments", "reports", "revisions", "receipts", "jobs",
                               "jobs_done", "decisions", "publications"), 0)
        complete = empty | dict.fromkeys(("enrollments", "reports", "revisions", "receipts",
                                         "jobs", "jobs_done"), 1)
        # Execute the actual file's __main__ guard and actual main/execute. Only
        # external boundaries are fake; result.json is produced by real finally.
        guard = ast.parse(Path(journey.__file__).read_text(encoding="utf-8")).body[-1]
        self.assertIsInstance(guard, ast.If)
        cli = compile(ast.Module(body=[guard], type_ignores=[]), journey.__file__, "exec")
        stdout = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="kapit-phone-cleanup-test-") as folder, ExitStack() as stack:
            root = Path(folder)
            stack.enter_context(patch.object(journey, "ROOT", root))
            stack.enter_context(patch.object(journey, "Phone", return_value=phone))
            stack.enter_context(patch.object(journey.integration, "MobileHarness",
                                            return_value=FakeHarness(harness_exit_failure)))
            stack.enter_context(patch.object(journey, "counts", side_effect=[empty, complete, complete]))
            stack.enter_context(patch.object(journey, "bindings", return_value={"synthetic": True},
                side_effect=journey.JourneyError("JOURNEY_BINDING_MISMATCH") if primary_failure else None))
            stack.enter_context(patch.object(journey.time, "sleep"))
            stack.enter_context(patch.object(journey.integration.local, "python_path", return_value=sys.executable))
            stack.enter_context(patch.object(sys, "argv", ["phone_journey.py", "--serial", "synthetic-test"]))
            stack.enter_context(patch.object(journey.subprocess, "run",
                                            side_effect=AssertionError("No real subprocess allowed")))
            with redirect_stdout(stdout), self.assertRaises(SystemExit) as exited:
                exec(cli, {"__name__": "__main__", "main": journey.main})
            files = list(root.glob(".cache/m1-runtime/phone-journey/*/result.json"))
            self.assertEqual(len(files), 1)
            result = json.loads(files[0].read_text(encoding="utf-8"))
        output = stdout.getvalue()
        self.assertNotIn("PRIVATE_ADB_CANARY", output + json.dumps(result))
        messages = [json.loads(line) for line in output.splitlines()]
        saved = next(item for item in messages if "result" in item)
        self.assertIs(saved["ok"], result["ok"])
        return result, exited.exception.code, phone, messages

    def test_success_requires_confirmed_owned_mapping_absence_and_cli_zero(self):
        result, status, phone, _ = self.invoke()
        self.assertEqual(status, 0)
        self.assertTrue(result["ok"])
        self.assertTrue(result["reverse_removed"])
        self.assertEqual(result["stage"], "complete")
        self.assertEqual(phone.calls[-3:], [("reverse", "--list"),
            ("reverse", "--remove", journey.ENDPOINT), ("reverse", "--list")])

    def test_absent_mapping_is_confirmed_without_removing_any_mapping(self):
        result, status, phone, _ = self.invoke("already_absent")
        self.assertEqual(status, 0)
        self.assertTrue(result["ok"])
        self.assertTrue(result["reverse_removed"])
        self.assertFalse(phone.removal_attempted)
        self.assertEqual(phone.list_queries, 3)

    def test_changed_or_unreadable_current_mapping_is_never_removed(self):
        for mode in ("changed_target", "pre_list_failure", "pre_malformed_list"):
            with self.subTest(mode=mode):
                result, status, phone, messages = self.invoke(mode)
                self.assertEqual(status, 1)
                self.assertFalse(result["ok"])
                self.assertFalse(result["reverse_removed"])
                self.assertEqual(result["code"], "JOURNEY_REVERSE_CLEANUP_UNCONFIRMED")
                self.assertFalse(phone.removal_attempted)
                self.assertNotIn(("reverse", "--remove", journey.ENDPOINT), phone.calls)
                self.assertEqual(messages[-1]["code"], result["code"])

    def test_uncertain_removal_dominates_success_in_result_and_actual_cli(self):
        for mode in ("remove_failure", "still_present", "list_failure", "malformed_list"):
            with self.subTest(mode=mode):
                result, status, phone, messages = self.invoke(mode)
                self.assertEqual(status, 1)
                self.assertFalse(result["ok"])
                self.assertFalse(result["reverse_removed"])
                self.assertEqual(result["code"], "JOURNEY_REVERSE_CLEANUP_UNCONFIRMED")
                self.assertEqual(messages[-1], {"ok": False, "code": result["code"]})
                self.assertTrue(phone.removal_attempted)

    def test_primary_failure_is_preserved_when_cleanup_is_confirmed(self):
        result, status, _, _ = self.invoke(primary_failure=True)
        self.assertEqual(status, 1)
        self.assertFalse(result["ok"])
        self.assertTrue(result["reverse_removed"])
        self.assertEqual(result["code"], "JOURNEY_BINDING_MISMATCH")
        self.assertNotIn("primary_code", result)

    def test_cleanup_failure_dominates_and_retains_primary_fixed_code(self):
        result, status, _, messages = self.invoke("remove_failure", primary_failure=True)
        self.assertEqual(status, 1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "JOURNEY_REVERSE_CLEANUP_UNCONFIRMED")
        self.assertEqual(result["primary_code"], "JOURNEY_BINDING_MISMATCH")
        self.assertEqual(messages[-1]["code"], result["code"])

    def test_primary_harness_exit_failure_cannot_leave_saved_success(self):
        result, status, _, _ = self.invoke(harness_exit_failure=True)
        self.assertEqual(status, 1)
        self.assertFalse(result["ok"])
        self.assertTrue(result["reverse_removed"])
        self.assertEqual(result["code"], "MOBILE_HARNESS_CLEANUP_UNCONFIRMED")

    def test_never_created_or_preexisting_mapping_is_never_removed(self):
        for arguments, code in (({"verify_failure": True}, "PHONE_APP_HASH_MISMATCH"),
                                ({"preexisting": True}, "JOURNEY_REVERSE_PREEXISTING")):
            with self.subTest(code=code):
                result, status, phone, _ = self.invoke(**arguments)
                self.assertEqual(status, 1)
                self.assertFalse(result["ok"])
                self.assertEqual(result["code"], code)
                self.assertNotIn("reverse_removed", result)
                self.assertNotIn("primary_code", result)
                self.assertFalse(phone.removal_attempted)


if __name__ == "__main__":
    unittest.main()
