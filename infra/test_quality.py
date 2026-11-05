import json
import subprocess
import unittest
from unittest.mock import patch

from infra import quality


class QualityTests(unittest.TestCase):
    def run_mocked(self, stage="pure", **kwargs):
        with patch.object(quality.Path, "is_file", return_value=True), patch.object(quality.shutil, "which", return_value="node"), patch.object(quality.subprocess, "run", **kwargs) as execute:
            result = quality.run_checks(stage)
        return result, execute

    def test_default_only_pure_no_output_and_incomplete_required_gates(self):
        result, execute = self.run_mocked(return_value=subprocess.CompletedProcess([], 0))
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(execute.call_count, len([c for c in quality.CHECKS if c.stage == "pure"]))
        for call in execute.call_args_list:
            self.assertIsInstance(call.args[0], tuple)
            self.assertIs(call.kwargs["shell"], False)
            self.assertEqual(call.kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(call.kwargs["stderr"], subprocess.DEVNULL)
            self.assertFalse(any(part in {"install", "npx", "npm", "browser-native", "test-native"} for part in call.args[0]))
        self.assertTrue(all(c["status"] == "NOT_RUN" for c in result["checks"] if c["check"] in quality.EXTERNAL_GATES))

    def test_web_direct_local_no_package_hooks(self):
        result, execute = self.run_mocked("web", return_value=subprocess.CompletedProcess([], 0))
        self.assertEqual(execute.call_count, 2)
        self.assertTrue(all(call.args[0][0] == "node" for call in execute.call_args_list))
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_nonzero_and_timeout_fail(self):
        for kwargs in ({"return_value": subprocess.CompletedProcess([], 1)}, {"side_effect": subprocess.TimeoutExpired("secret command", 1, output="SECRET")}):
            with self.subTest(kwargs=kwargs):
                result, _ = self.run_mocked(**kwargs)
                self.assertEqual(result["status"], "FAILED")
                self.assertNotIn("SECRET", json.dumps(result))

    def test_unavailable_never_green_or_exception_details(self):
        result, _ = self.run_mocked(side_effect=OSError("SECRET path"))
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertTrue(any(c["status"] == "UNAVAILABLE" for c in result["checks"]))

    def test_missing_local_tool_not_installed(self):
        with patch.object(quality.Path, "is_file", return_value=False), patch.object(quality.subprocess, "run") as execute:
            result = quality.run_checks("web")
        execute.assert_not_called()
        self.assertEqual(result["status"], "INCOMPLETE")

    def test_reject_arbitrary_stage_workspace_and_timeout(self):
        for args in ({"stage": "install"}, {"root": quality.ROOT.parent}, {"timeout": 0}, {"timeout": True}):
            with self.subTest(args=args), patch.object(quality.subprocess, "run") as execute:
                with self.assertRaises(ValueError):
                    quality.run_checks(**args)
                execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
