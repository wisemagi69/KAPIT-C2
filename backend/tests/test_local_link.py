"""Independent link-opener checks, including real isolated preview processes.

Explicit opt-in: KAPIT_RUN_LOCAL_LINK_QA=1. Ordinary Django discovery skips this
local process suite. It never stops the retained user preview at port 18081,
installs tools, initializes a database, or submits credentials.
"""
from contextlib import contextmanager, redirect_stdout
import ctypes
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import open_local as opener


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def preview_owners():
    """Read listener identity only; never use the returned PIDs for mutation."""
    import struct
    size = ctypes.c_uint32()
    table = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    table.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    table.restype = ctypes.c_uint32
    if table(None, ctypes.byref(size), False, socket.AF_INET, 3, 0) not in {0, 122} or not 4 <= size.value <= 8 * 1024 * 1024:
        raise RuntimeError("QA_LISTENER_IDENTITY_UNAVAILABLE")
    data = ctypes.create_string_buffer(size.value)
    if table(data, ctypes.byref(size), False, socket.AF_INET, 3, 0):
        raise RuntimeError("QA_LISTENER_IDENTITY_UNAVAILABLE")
    count = struct.unpack_from("<I", data.raw)[0]
    if count > (len(data.raw) - 4) // 24:
        raise RuntimeError("QA_LISTENER_IDENTITY_UNAVAILABLE")
    result = set()
    for index in range(count):
        state, address, port, _, _, pid = struct.unpack_from("<6I", data.raw, 4 + index * 24)
        if state == 2 and address == int.from_bytes(socket.inet_aton("127.0.0.1"), "little") and socket.ntohs(port & 0xffff) == 18081:
            result.add(pid)
    return result


@contextmanager
def http_fixture(responses):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            status, body = responses.get(self.path, (404, b"missing"))
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers(); self.wfile.write(body)
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


class OwnedJob:
    """Windows test-only ownership of bootstrap and its retained child tree."""
    def __init__(self):
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t), ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in ["read", "write", "other", "read_bytes", "write_bytes", "other_bytes"]]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", Io), ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        limits = Extended(); limits.basic.flags = 0x2000
        if not self.handle or not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise RuntimeError("QA_PROCESS_OWNERSHIP_UNAVAILABLE")
    def attach(self, child):
        if not self.api.AssignProcessToJobObject(self.handle, int(child._handle)):
            child.kill(); child.wait(timeout=5)
            raise RuntimeError("QA_PROCESS_OWNERSHIP_UNAVAILABLE")
    def close(self):
        if self.handle:
            if not self.api.CloseHandle(self.handle):
                raise RuntimeError("QA_PROCESS_CLEANUP_FAILED")
            self.handle = None


class LocalLinkChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("KAPIT_RUN_LOCAL_LINK_QA") != "1":
            raise unittest.SkipTest("Explicit local-link QA requires KAPIT_RUN_LOCAL_LINK_QA=1 and the retained preview")
        cls.retained_owners = preview_owners() if os.name == "nt" else None
        if cls.retained_owners is not None and len(cls.retained_owners) != 1:
            raise RuntimeError("QA_RETAINED_PREVIEW_IDENTITY_UNAVAILABLE")

    @classmethod
    def tearDownClass(cls):
        if cls.retained_owners is not None and preview_owners() != cls.retained_owners:
            raise AssertionError("Retained user preview listener changed during QA")

    def test_current_preview_is_reused_without_spawn_or_browser(self):
        build = opener.expected_build()
        self.assertTrue(opener.verify_site(18081, build))
        with patch.object(opener, "start_preview") as start, patch.object(opener.webbrowser, "open") as browser:
            target = opener.select_target(build, application_port=free_port())
        self.assertEqual(target.mode, "preview"); self.assertIsNone(target.process)
        self.assertEqual(target.url, "http://127.0.0.1:18081/")
        start.assert_not_called(); browser.assert_not_called()

    def test_page_and_every_asset_must_match_before_reuse(self):
        build = {"/": b"index", "/assets/app.js": b"javascript", "/assets/app.css": b"style"}
        responses = {path: (200, content) for path, content in build.items()}
        with http_fixture(responses) as port:
            self.assertTrue(opener.verify_site(port, build))
            responses["/assets/app.css"] = (200, b"other")
            self.assertFalse(opener.verify_site(port, build))
            responses["/assets/app.css"] = (302, b"style")
            self.assertFalse(opener.verify_site(port, build))
            responses["/assets/app.css"] = (200, b"style-extra")
            self.assertFalse(opener.verify_site(port, build))

    def test_full_application_requires_matching_build_and_anonymous_api(self):
        build = {"/": b"index", "/assets/app.js": b"javascript"}
        responses = {path: (200, content) for path, content in build.items()}
        responses["/api/v1/auth/csrf/"] = (200, json.dumps({"csrf_token": "x" * 64}).encode())
        with http_fixture(responses) as port, patch.object(opener, "start_preview") as start:
            target = opener.select_target(build, application_port=port, preview_port=free_port())
            self.assertEqual(target.mode, "application"); start.assert_not_called()
            responses["/api/v1/auth/csrf/"] = (200, b"not an API")
            self.assertFalse(opener.api_ready(port))

    def test_unrelated_occupied_listener_is_preserved_and_rejected(self):
        with http_fixture({"/": (200, b"unrelated application")}) as port, patch.object(opener, "start_preview") as start:
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_PORT_BUSY"):
                opener.select_target({"/": b"expected"}, application_port=free_port(), preview_port=port)
            self.assertEqual(opener.get(port, "/", 100), b"unrelated application")
            start.assert_not_called()

    def test_missing_tools_and_invalid_ports_never_spawn(self):
        with patch.object(opener.shutil, "which", return_value=None), patch.object(opener.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_TOOLS_MISSING"):
                opener.start_preview(free_port(), {"/": b"expected"}, timeout=0.2)
            popen.assert_not_called()
        for value in [0, -1, 65536, True, "18081"]:
            with self.subTest(value=value), self.assertRaises(opener.OpenError): opener.check_port(value)

    def test_missing_build_and_external_asset_path_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            dist = Path(directory)
            with patch.object(opener, "DIST", dist):
                with self.assertRaises(opener.OpenError): opener.expected_build()
                (dist / "index.html").write_text('<script src="https://example.invalid/app.js"></script>')
                with self.assertRaises(opener.OpenError): opener.expected_build()

    def test_browser_open_occurs_only_after_verified_target_and_no_browser_is_honored(self):
        order = []
        target = opener.Target("http://127.0.0.1:18081/", "preview")
        def select(build): order.append("verified"); return target
        with patch.object(opener, "expected_build", return_value={"/": b"x"}), patch.object(opener, "select_target", side_effect=select), patch.object(opener.webbrowser, "open", side_effect=lambda *args, **kwargs: order.append("browser") or True), patch.object(sys, "argv", ["open_local.py"]), redirect_stdout(io.StringIO()):
            self.assertEqual(opener.main(), 0)
        self.assertEqual(order, ["verified", "browser"])
        with patch.object(opener, "expected_build", return_value={"/": b"x"}), patch.object(opener, "select_target", return_value=target), patch.object(opener.webbrowser, "open") as browser, patch.object(sys, "argv", ["open_local.py", "--no-browser"]), redirect_stdout(io.StringIO()):
            self.assertEqual(opener.main(), 0)
        browser.assert_not_called()

    def test_real_failed_child_is_stopped_without_changing_existing_preview(self):
        port = free_port()
        owned = []
        original_stop = opener.stop_owned
        def stop(child): owned.append(child); original_stop(child)
        with patch.object(opener, "preview_command", return_value=[sys.executable, "-c", "import time; time.sleep(30)"]), patch.object(opener, "stop_owned", side_effect=stop):
            with self.assertRaisesRegex(opener.OpenError, "PREVIEW_TIMEOUT"):
                opener.start_preview(port, {"/": b"expected"}, timeout=0.3)
        self.assertEqual(len(owned), 1); self.assertIsNotNone(owned[0].poll())
        self.assertTrue(opener.port_available(port))
        self.assertTrue(opener.verify_site(18081, opener.expected_build()))

    def test_real_cold_preview_and_deep_link_then_owned_cleanup(self):
        build, port = opener.expected_build(), free_port()
        child = opener.start_preview(port, build)
        try:
            self.assertIsNone(child.poll())
            self.assertTrue(opener.verify_site(port, build))
            self.assertEqual(opener.get(port, "/reports", len(build["/"])), build["/"])
            with patch.object(opener, "start_preview") as start:
                reused = opener.select_target(build, application_port=free_port(), preview_port=port)
            self.assertIsNone(reused.process); start.assert_not_called()
        finally:
            opener.stop_owned(child)
        self.assertIsNotNone(child.poll())
        self.assertTrue(opener.port_available(port))

    @unittest.skipUnless(os.name == "nt", "Windows Explorer launcher lifecycle")
    def test_real_preview_survives_opener_exit_and_job_cleans_only_owned_tree(self):
        port = free_port()
        script = "import json,sys; from infra.open_local import expected_build,start_preview; port=json.loads(sys.stdin.readline())['port']; child=start_preview(port,expected_build()); print(json.dumps({'ready':True}),flush=True)"
        job, bootstrap = OwnedJob(), None
        try:
            bootstrap = subprocess.Popen([sys.executable, "-c", script], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
            job.attach(bootstrap)
            output, errors = bootstrap.communicate(json.dumps({"port": port}).encode(), timeout=25)
            self.assertEqual(bootstrap.returncode, 0, "Isolated bootstrap failed")
            self.assertEqual(json.loads(output), {"ready": True})
            self.assertEqual(errors, b"")
            self.assertTrue(opener.verify_site(port, opener.expected_build()), "Preview stopped after parent exit")
        finally:
            job.close()
            if bootstrap is not None and bootstrap.poll() is None:
                bootstrap.kill(); bootstrap.wait(timeout=5)
        deadline = time.monotonic() + 5
        while True:
            with socket.socket() as probe:
                probe.settimeout(1)
                listening = probe.connect_ex(("127.0.0.1", port)) == 0
            if not listening or time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        self.assertFalse(listening, "Owned preview did not stop after Job Object cleanup")
        self.assertTrue(opener.verify_site(18081, opener.expected_build()))

    @unittest.skipUnless(os.name == "nt", "Windows double-click wrapper")
    def test_double_click_wrapper_resolves_its_location_from_different_directory(self):
        wrapper = ROOT / "infra/Open KAPIT.cmd"
        result = subprocess.run([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(wrapper), "--no-browser"], cwd=tempfile.gettempdir(), capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, "Wrapper failed from another current directory")
        self.assertIn(b"Website preview ready: http://127.0.0.1:18081/", result.stdout)
        self.assertIn(b"Sign-in requires the backend", result.stdout)
        self.assertEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()
