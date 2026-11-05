"""Synthetic closed-output/fail-stop tests; never read a native cluster."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

from infra import start_local as startup
from infra import startup_failure_diagnostics as diagnostic

CANARY = "PRIVATE_CANARY_CREDENTIAL_PATH_COORDINATE"


def report():
    return {"schema_version": 1, "ownership": "VERIFIED", "initialization": "READY",
            "pid_file": "ABSENT", "log": "OBSERVED", "log_conditions": [],
            "log_attribution": "EXISTING_LOG_NOT_BOUND_TO_FAILED_ATTEMPT",
            "current_token": "NOT_RESTRICTED", "cause": "UNCONFIRMED", "readiness": "UNVERIFIED",
            "next_actions": ["SHARE_FINITE_DIAGNOSTIC_FOR_REVIEW"]}


class FormatterTests(unittest.TestCase):
    def setUp(self):
        self.real_collect = diagnostic.collect
        collector = patch.object(diagnostic, "collect", return_value=report())
        self.collect = collector.start()
        self.addCleanup(collector.stop)

    def reject(self, value):
        self.collect.return_value = value
        output = diagnostic.failure_observation()
        self.assertEqual(output, diagnostic.UNAVAILABLE)
        self.assertNotIn(CANARY, output)

    def test_valid_output_is_bounded_finite_and_collected_once(self):
        output = diagnostic.failure_observation()
        self.collect.assert_called_once_with()
        self.assertLessEqual(len(output.encode("utf-8")), 4096)
        self.assertEqual(json.loads(output.removeprefix(diagnostic.PREFIX)), report())

    def test_all_ordered_log_conditions_and_token_variants(self):
        for token in diagnostic.ENUMS["current_token"]:
            value = report()
            value["current_token"] = token
            value["log_conditions"] = list(diagnostic.CONDITIONS)
            self.collect.return_value = value
            self.assertNotEqual(diagnostic.failure_observation(), diagnostic.UNAVAILABLE)

    def test_unavailable_ownership_retains_unknown_and_not_inspected(self):
        value = report()
        value.update(ownership="UNAVAILABLE", initialization="UNKNOWN", pid_file="NOT_INSPECTED", log="NOT_INSPECTED")
        self.collect.return_value = value
        self.assertNotEqual(diagnostic.failure_observation(), diagnostic.UNAVAILABLE)

    def test_unknown_or_missing_keys_fail_closed(self):
        value = report()
        value[CANARY] = CANARY
        self.reject(value)
        value = report()
        del value["cause"]
        self.reject(value)

    def test_top_level_and_schema_types_fail_closed(self):
        for value in (None, [], CANARY, 1, True):
            with self.subTest(value_type=type(value).__name__):
                self.reject(value)
        for version in (True, False, 1.0, "1", 2, float("nan"), float("inf"), {CANARY: CANARY}):
            value = report()
            value["schema_version"] = version
            self.reject(value)

    def test_all_scalar_fields_reject_private_unknown_and_nested_values(self):
        for key in diagnostic.ENUMS:
            for invalid in (CANARY, True, None, [CANARY], {CANARY: CANARY}, float("nan"), "X" * 100000):
                with self.subTest(key=key, invalid_type=type(invalid).__name__):
                    value = report()
                    value[key] = invalid
                    self.reject(value)

    def test_collection_fields_reject_nonlists(self):
        for key in ("log_conditions", "next_actions"):
            for invalid in (None, CANARY, (), {CANARY}, {CANARY: CANARY}, True):
                value = report()
                value[key] = invalid
                self.reject(value)

    def test_log_conditions_reject_duplicates_reordering_unknown_and_oversize(self):
        for invalid in ([CANARY], [[CANARY]], [True], ["READY_RECORDED", "TOKEN_RESTRICTION"],
                        ["READY_RECORDED"] * 2, ["READY_RECORDED"] * 10000):
            value = report()
            value["log_conditions"] = invalid
            self.reject(value)

    def test_actions_reject_arbitrary_empty_duplicate_and_nested_values(self):
        for invalid in ([], [CANARY], [diagnostic.ACTION, diagnostic.ACTION], [[diagnostic.ACTION]], [True]):
            value = report()
            value["next_actions"] = invalid
            self.reject(value)

    def test_causal_readiness_and_attribution_claims_rejected(self):
        for key, claim in (("cause", "TOKEN_RESTRICTION"), ("readiness", "READY"), ("log_attribution", "CURRENT_ATTEMPT")):
            value = report()
            value[key] = claim
            self.reject(value)

    def test_inconsistent_authentication_and_observation_rejected(self):
        for changes in ({"ownership": "INVALID"}, {"initialization": "UNKNOWN"},
                        {"pid_file": "NOT_INSPECTED"}, {"log": "NOT_INSPECTED"},
                        {"log": "ABSENT", "log_conditions": ["READY_RECORDED"]}):
            value = report()
            value.update(changes)
            self.reject(value)

    def test_collector_errors_never_emit_exception_data(self):
        for error in (RuntimeError(CANARY), OSError(CANARY), ImportError(CANARY), TypeError(CANARY),
                      ValueError(CANARY), SystemExit(0)):
            self.collect.side_effect = error
            self.assertEqual(diagnostic.failure_observation(), diagnostic.UNAVAILABLE)

    def test_optional_module_import_failure_is_unavailable(self):
        self.collect.side_effect = self.real_collect
        with patch.object(diagnostic.importlib, "import_module", side_effect=ImportError(CANARY)):
            self.assertEqual(diagnostic.failure_observation(), diagnostic.UNAVAILABLE)

    def test_serialization_errors_and_oversize_fail_closed(self):
        for error in (ValueError(CANARY), TypeError(CANARY), RecursionError(CANARY), SystemExit(0)):
            with patch.object(diagnostic.json, "dumps", side_effect=error):
                self.assertEqual(diagnostic.failure_observation(), diagnostic.UNAVAILABLE)
        for invalid in ("X" * 4097, None):
            with patch.object(diagnostic.json, "dumps", return_value=invalid):
                self.assertEqual(diagnostic.failure_observation(), diagnostic.UNAVAILABLE)

    def test_keyboard_interrupt_propagates_from_collection_and_serialization(self):
        self.collect.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            diagnostic.failure_observation()
        self.collect.side_effect = None
        with patch.object(diagnostic.json, "dumps", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                diagnostic.failure_observation()


class StartupIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.native = Mock()
        self.native_patch = patch.object(startup.local, "native_module", return_value=self.native)
        self.native_patch.start()
        self.addCleanup(self.native_patch.stop)
        collector = patch.object(diagnostic, "collect", return_value=report())
        self.collect = collector.start()
        self.addCleanup(collector.stop)
        output = redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def test_success_and_invalid_action_never_collect(self):
        for action in ("init", "start", "status"):
            self.assertIs(startup.native_phase(action), getattr(self.native, action).return_value)
        with self.assertRaises(startup.StartupError):
            startup.native_phase("stop")
        self.collect.assert_not_called()

    def test_failure_collects_once_preserves_original_code_stage_and_hidden_suffix(self):
        for action, stage in (("init", "initialization"), ("start", "startup"), ("status", "verification")):
            self.collect.reset_mock()
            getattr(self.native, action).side_effect = RuntimeError("NATIVE_COMMAND: " + CANARY)
            with self.assertRaises(startup.StartupError) as failure:
                startup.native_phase(action)
            self.assertTrue(str(failure.exception).startswith("NATIVE_COMMAND: PostgreSQL " + stage + " failed."))
            self.assertIn(diagnostic.PREFIX, str(failure.exception))
            self.assertNotIn(CANARY, str(failure.exception))
            self.assertTrue(failure.exception.__suppress_context__)
            self.collect.assert_called_once_with()

    def test_secondary_failure_cannot_replace_primary_error(self):
        self.native.start.side_effect = RuntimeError("NATIVE_PORT: " + CANARY)
        for error in (RuntimeError(CANARY), SystemExit(0), ImportError(CANARY)):
            self.collect.side_effect = error
            with self.assertRaisesRegex(startup.StartupError, "^NATIVE_PORT: PostgreSQL startup failed") as failure:
                startup.native_phase("start")
            self.assertTrue(str(failure.exception).endswith(diagnostic.UNAVAILABLE))
            self.assertNotIn(CANARY, str(failure.exception))

    def test_native_keyboard_interrupt_never_collects(self):
        self.native.start.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            startup.native_phase("start")
        self.collect.assert_not_called()

    def test_helper_import_failure_does_not_replace_primary_failure(self):
        self.native.start.side_effect = RuntimeError("NATIVE_COMMAND: " + CANARY)
        for error in (ImportError(CANARY), SystemExit(0)):
            with patch.object(startup.importlib, "import_module", side_effect=error):
                with self.assertRaisesRegex(startup.StartupError, "^NATIVE_COMMAND: PostgreSQL startup failed") as failure:
                    startup.native_phase("start")
            self.assertTrue(str(failure.exception).endswith(diagnostic.UNAVAILABLE))
            self.assertNotIn(CANARY, str(failure.exception))

    def test_collector_keyboard_interrupt_propagates(self):
        self.native.start.side_effect = RuntimeError("NATIVE_COMMAND")
        self.collect.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            startup.native_phase("start")

    def test_wrapper_retains_exit_pause_and_disables_bytecode(self):
        source = (Path(__file__).parent / "Start KAPIT.cmd").read_text()
        self.assertIn("python -B infra\\start_local.py\nset \"KAPIT_START_EXIT=%ERRORLEVEL%\"", source)
        self.assertIn("pause\nexit /b %KAPIT_START_EXIT%", source)


if __name__ == "__main__":
    unittest.main()
