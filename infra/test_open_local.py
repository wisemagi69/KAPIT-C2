"""Opener boundaries and process lifecycle using controlled local doubles."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from infra import open_local as opener


BUILD = {"/": b"compiled index", "/assets/site-a.js": b"compiled javascript", "/assets/site-b.css": b"compiled styles"}


class OpenerTests(unittest.TestCase):
    def test_full_application_requires_matching_assets_and_api(self):
        with patch.object(opener, "verify_site", return_value=True) as verify, patch.object(opener, "api_ready", return_value=True), patch.object(opener, "start_preview") as start:
            target = opener.select_target(BUILD)
        self.assertEqual((target.mode, target.url, target.process), ("application", "http://127.0.0.1:8000/", None))
        verify.assert_called_once_with(8000, BUILD)
        start.assert_not_called()

    def test_index_without_api_falls_back_to_verified_existing_preview(self):
        with patch.object(opener, "verify_site", return_value=True), patch.object(opener, "api_ready", return_value=False), patch.object(opener, "start_preview") as start:
            target = opener.select_target(BUILD)
        self.assertEqual((target.mode, target.url, target.process), ("preview", "http://127.0.0.1:18081/", None))
        start.assert_not_called()

    def test_matching_preview_reused_without_new_process(self):
        with patch.object(opener, "verify_site", side_effect=[False, True]), patch.object(opener, "api_ready") as api, patch.object(opener.subprocess, "Popen") as spawn:
            target = opener.select_target(BUILD)
        self.assertEqual(target.mode, "preview")
        self.assertIsNone(target.process)
        api.assert_not_called()
        spawn.assert_not_called()

    def test_unrelated_preview_listener_never_opens_or_starts_anything(self):
        with patch.object(opener, "verify_site", return_value=False), patch.object(opener, "port_available", return_value=False), patch.object(opener.subprocess, "Popen") as spawn, patch.object(opener.webbrowser, "open") as browser:
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_PORT_BUSY"):
                opener.select_target(BUILD)
        spawn.assert_not_called()
        browser.assert_not_called()

    def test_asset_mismatch_prevents_ready(self):
        with patch.object(opener, "get", side_effect=[BUILD["/"], b"different javascript"]) as get:
            self.assertFalse(opener.verify_site(18081, BUILD))
        self.assertEqual(get.call_count, 2)

    def test_missing_build_fails_before_network_or_browser(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(opener, "DIST", Path(directory)), patch.object(opener, "get") as get, patch.object(opener.webbrowser, "open") as browser, patch.object(opener.sys, "argv", ["open_local.py"]):
            with self.assertRaisesRegex(opener.OpenError, "BUILD_MISSING"):
                opener.main()
        get.assert_not_called()
        browser.assert_not_called()

    def test_compiled_asset_paths_cannot_redirect_fetches(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(opener, "DIST", Path(directory)):
            (Path(directory) / "index.html").write_text('<script src="https://other.example/x.js"></script>')
            with self.assertRaisesRegex(opener.OpenError, "BUILD_INVALID"):
                opener.expected_build()

    def test_successful_child_is_retained_with_hidden_direct_vite_process(self):
        child = Mock(pid=100, poll=Mock(return_value=None))
        with patch.object(opener, "port_available", return_value=True), patch.object(opener, "preview_command", return_value=["node", "vite.js", "preview", "--strictPort"]), patch.object(opener.subprocess, "Popen", return_value=child) as spawn, patch.object(opener, "verify_site", return_value=True), patch.dict(opener.os.environ, {"NODE_OPTIONS": "unrelated options", "NODE_PATH": "unrelated path"}):
            self.assertIs(opener.start_preview(18081, BUILD), child)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()
        options = spawn.call_args.kwargs
        self.assertEqual(options["stdout"], subprocess.DEVNULL)
        self.assertEqual(options["stderr"], subprocess.DEVNULL)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertNotIn("NODE_OPTIONS", options["env"])
        self.assertNotIn("NODE_PATH", options["env"])
        if opener.os.name == "nt":
            self.assertEqual(options["creationflags"], subprocess.CREATE_NO_WINDOW)

    def test_failed_startup_cleans_only_owned_child(self):
        child = Mock(pid=100, poll=Mock(return_value=None))
        with patch.object(opener, "port_available", return_value=True), patch.object(opener, "preview_command", return_value=["node", "vite.js"]), patch.object(opener.subprocess, "Popen", return_value=child), patch.object(opener.time, "monotonic", side_effect=[0, 16]):
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_TIMEOUT"):
                opener.start_preview(18081, BUILD)
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=5)

    def test_exited_child_cannot_be_ready_even_if_matching_page_appears(self):
        child = Mock(pid=100, poll=Mock(return_value=1))
        with patch.object(opener, "port_available", return_value=True), patch.object(opener, "preview_command", return_value=["node", "vite.js"]), patch.object(opener.subprocess, "Popen", return_value=child), patch.object(opener, "verify_site", return_value=True) as verify:
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_START_FAILED"):
                opener.start_preview(18081, BUILD)
        verify.assert_not_called()
        child.terminate.assert_not_called()

    def test_missing_vite_does_not_install_or_spawn(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(opener, "ROOT", Path(directory)), patch.object(opener.shutil, "which", return_value="node"), patch.object(opener.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_TOOLS_MISSING"):
                opener.preview_command(18081)
        spawn.assert_not_called()

    def test_browser_opening_happens_after_successful_verification(self):
        events = []

        def verify(build):
            events.append("verified")
            return opener.Target("http://127.0.0.1:18081/", "preview")

        with patch.object(opener, "expected_build", return_value=BUILD), patch.object(opener, "select_target", side_effect=verify), patch.object(opener.webbrowser, "open", side_effect=lambda *args, **kwargs: events.append("browser")), patch.object(opener.sys, "argv", ["open_local.py"]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(opener.main(), 0)
        self.assertEqual(events, ["verified", "browser"])
        self.assertIn("Sign-in requires the backend", output.getvalue())

    def test_no_browser_verifies_and_prints_preview_without_opening(self):
        with patch.object(opener, "expected_build", return_value=BUILD), patch.object(opener, "select_target", return_value=opener.Target("http://127.0.0.1:18081/", "preview")), patch.object(opener.webbrowser, "open") as browser, patch.object(opener.sys, "argv", ["open_local.py", "--no-browser"]), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(opener.main(), 0)
        self.assertIn("Website preview ready", output.getvalue())
        browser.assert_not_called()

    def test_arbitrary_port_is_not_exposed_by_cli(self):
        with patch.object(opener.sys, "argv", ["open_local.py", "--port", "8123"]), patch.object(opener, "select_target") as select, patch.object(opener.argparse.ArgumentParser, "error", side_effect=ValueError("unsupported argument")):
            with self.assertRaises(ValueError):
                opener.main()
        select.assert_not_called()

    def test_launcher_uses_its_own_location_and_keeps_failures_readable(self):
        content = (opener.ROOT / "infra/Open KAPIT.cmd").read_text()
        self.assertIn('python "%~dp0open_local.py" %*', content)
        self.assertIn("if errorlevel 1", content)
        self.assertIn("pause", content)
        self.assertNotIn("C:\\Users", content)


if __name__ == "__main__":
    unittest.main()
