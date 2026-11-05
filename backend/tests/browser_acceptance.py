"""Explicit real browser test; invoke only through infra/local.py browser-native.

This filename deliberately does not match ordinary test discovery. It never
uses fixture HTTP responses, shared demo accounts, or a hosted database.
"""
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import threading
import time

from django.core.management import call_command
from django.db import connection, connections
from django.test import LiveServerTestCase

from tests.browser_runner import BrowserGuardError, preserve_database, require_target


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "web/tests/live-journey.mjs"
GATES = ["real_login", "private_submission", "real_worker", "exact_review", "approved_projection", "private_denial", "client_reconnect", "return_correction", "rejection_private", "report_filters_pagination", "feed_filters_pagination", "account_create_reset", "account_scope_sessions", "password_sessions", "recipient_revocation"]
STAGES = {"INPUT", "BROWSER", "LOGIN", "PRIVATE_SUBMISSION", "WORKER_REVIEW", "PUBLICATION", "PERSISTENCE", "CORRECTION", "REJECTION", "PAGINATION", "ADMINISTRATION", "PASSWORD", "REVOCATION", "COMPLETE"}


def require_actual_database():
    from tests import browser_runner
    lease = browser_runner.ACTIVE_DATABASE_LEASE
    if lease is None or not lease.locked or lease.owned_oid is None:
        raise BrowserGuardError("BROWSER_GUARDED_RUNNER_REQUIRED")
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(), oid FROM pg_database WHERE datname = current_database()")
            identity = cursor.fetchone()
        if identity is None or tuple(identity) != ("test_kapit_m1", lease.owned_oid):
            raise BrowserGuardError("BROWSER_ACTUAL_DATABASE_DENIED")
    except BrowserGuardError:
        raise
    except Exception:
        raise BrowserGuardError("BROWSER_ACTUAL_DATABASE_UNAVAILABLE") from None


class BoundedReader:
    def __init__(self, stream, limit=4096, retain=True):
        self.stream, self.limit, self.retain = stream, limit, retain
        self.data = bytearray()
        self.overflow = False
        self.failed = False

    def read(self):
        total = 0
        try:
            while chunk := self.stream.read(1024):
                total += len(chunk)
                if total > self.limit:
                    self.overflow = True
                if self.retain and len(self.data) < self.limit:
                    self.data.extend(chunk[:self.limit - len(self.data)])
        except Exception:
            self.failed = True
        finally:
            try:
                self.stream.close()
            except Exception:
                self.failed = True


class ChildOwnership:
    """Own the Node process tree, including browser children, before input."""
    def __init__(self):
        self.job = None
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            class Limits(ctypes.Structure):
                _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", wintypes.DWORD), ("min_working", ctypes.c_size_t), ("max_working", ctypes.c_size_t), ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
            class Counters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in ["read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes"]]
            class Extended(ctypes.Structure):
                _fields_ = [("basic", Limits), ("io", Counters), ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
            self.api = ctypes.WinDLL("kernel32", use_last_error=True)
            self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
            self.api.CreateJobObjectW.restype = wintypes.HANDLE
            self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
            self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
            self.api.CloseHandle.argtypes = [wintypes.HANDLE]
            self.job = self.api.CreateJobObjectW(None, None)
            limits = Extended(); limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE
            if not self.job or not self.api.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                self.close(None)
                raise BrowserGuardError("BROWSER_PROCESS_OWNERSHIP_UNAVAILABLE")

    def attach(self, process):
        if self.job and not self.api.AssignProcessToJobObject(self.job, int(process._handle)):
            process.kill(); process.wait(timeout=5)
            raise BrowserGuardError("BROWSER_PROCESS_OWNERSHIP_UNAVAILABLE")

    def close(self, process):
        if self.job:
            if not self.api.CloseHandle(self.job):
                preserve_database()
                raise BrowserGuardError("BROWSER_PROCESS_OWNERSHIP_CLEANUP_FAILED")
            self.job = None
        elif os.name != "nt" and process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def browser_result(raw, returncode):
    try:
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("stage") not in STAGES:
            raise ValueError
        if returncode or result.get("ok") is not True:
            if set(result) != {"ok", "stage"} or result.get("ok") is not False:
                raise ValueError
            raise BrowserGuardError("BROWSER_JOURNEY_FAILED_" + result["stage"])
        if set(result) != {"ok", "stage", "scanned_responses", "gates"} or result["stage"] != "COMPLETE" or result["gates"] != GATES or type(result["scanned_responses"]) is not int or not 5 <= result["scanned_responses"] <= 1000:
            raise ValueError
        return result
    except BrowserGuardError:
        raise
    except (ValueError, TypeError, UnicodeError):
        raise BrowserGuardError("BROWSER_OUTPUT_INVALID") from None


def run_browser(url, channel_id):
    node = shutil.which("node")
    if not node or not SCRIPT.is_file() or not (ROOT / "web/node_modules/playwright/package.json").is_file():
        raise BrowserGuardError("BROWSER_DEPENDENCIES_UNAVAILABLE")
    payload = json.dumps({"url": url, "channel_id": str(channel_id)}).encode("utf8")
    if len(payload) > 1024:
        raise BrowserGuardError("BROWSER_INPUT_INVALID")
    # No inherited Node injection, debug logging, URLs or application secrets.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "HOME", "DISPLAY", "XDG_RUNTIME_DIR"}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    owner, process, threads = None, None, []
    try:
        try:
            owner = ChildOwnership()
        except Exception:
            raise BrowserGuardError("BROWSER_PROCESS_OWNERSHIP_UNAVAILABLE") from None
        process = subprocess.Popen([node, str(SCRIPT)], cwd=ROOT / "web", env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, start_new_session=os.name != "nt")
        owner.attach(process)
        output, errors = BoundedReader(process.stdout), BoundedReader(process.stderr, retain=False)
        for reader in [output, errors]:
            thread = threading.Thread(target=reader.read, daemon=True)
            thread.start(); threads.append(thread)
        process.stdin.write(payload); process.stdin.close()
        deadline = time.monotonic() + 300
        while process.poll() is None:
            if output.overflow or errors.overflow or output.failed or errors.failed:
                raise BrowserGuardError("BROWSER_OUTPUT_LIMIT")
            if time.monotonic() >= deadline:
                raise BrowserGuardError("BROWSER_PROCESS_TIMEOUT")
            time.sleep(0.05)
        for thread in threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads) or output.overflow or errors.overflow or output.failed or errors.failed:
            raise BrowserGuardError("BROWSER_OUTPUT_LIMIT")
        return browser_result(bytes(output.data), process.returncode)
    except BrowserGuardError:
        raise
    except Exception:
        raise BrowserGuardError("BROWSER_PROCESS_FAILED") from None
    finally:
        try:
            if owner is not None:
                owner.close(process)
            for thread in threads:
                thread.join(timeout=5)
        except Exception:
            raise BrowserGuardError("BROWSER_PROCESS_CLEANUP_FAILED") from None


class BrowserAcceptanceTests(LiveServerTestCase):
    host = "127.0.0.1"
    databases = {"default"}

    @classmethod
    def setUpClass(cls):
        require_target(connection.settings_dict, os.environ, running_test=True)
        if connection.vendor != "postgresql":
            raise BrowserGuardError("BROWSER_DATABASE_DENIED")
        from tests import browser_runner
        if not browser_runner.ACTIVE_DATABASE_LEASE:
            raise BrowserGuardError("BROWSER_GUARDED_RUNNER_REQUIRED")
        browser_runner.ACTIVE_DATABASE_LEASE.assert_owned()
        require_actual_database()
        if not (ROOT / "web/dist/index.html").is_file():
            raise BrowserGuardError("BROWSER_BUILD_UNAVAILABLE")
        super().setUpClass()

    def setUp(self):
        self.worker_stop = threading.Event()
        self.worker_failed = threading.Event()
        self.worker = None
        self.unsafe_cleanup = False
        try:
            require_target(connection.settings_dict, os.environ, running_test=True)
            require_actual_database()
        except Exception:
            self.unsafe_cleanup = True
            preserve_database()
            raise
        try:
            call_command("seed_demo", stdout=io.StringIO(), stderr=io.StringIO(), verbosity=0)
        except Exception:
            raise BrowserGuardError("BROWSER_FIXTURE_FAILED") from None
        from apps.scopes.models import SharingChannel
        self.channel_id = SharingChannel.objects.get(code="CH-DEMO-01").id

    def worker_loop(self):
        try:
            from apps.operations.worker import process_one
            connections.close_all()
            require_target(connection.settings_dict, os.environ, running_test=True)
            require_actual_database()
            with connection.cursor() as cursor:
                cursor.execute("SET statement_timeout = '5s'")
                cursor.execute("SET lock_timeout = '2s'")
            while not self.worker_stop.is_set():
                if not process_one():
                    self.worker_stop.wait(0.1)
        except Exception:
            self.worker_failed.set()
        finally:
            try:
                connections.close_all()
            except Exception:
                self.worker_failed.set()

    def stop_worker(self):
        self.worker_stop.set()
        if self.worker is not None:
            self.worker.join(timeout=15)
            if self.worker.is_alive():
                self.unsafe_cleanup = True
                preserve_database()
                raise BrowserGuardError("BROWSER_WORKER_STOP_FAILED_DATABASE_RETAINED")
            if self.worker_failed.is_set():
                raise BrowserGuardError("BROWSER_WORKER_FAILED")

    def _post_teardown(self):
        from tests import browser_runner
        if getattr(self, "unsafe_cleanup", True) or browser_runner.PRESERVE_DATABASE:
            # Do not flush a database still used by our worker. Runner likewise
            # refuses destruction and retains it for explicit investigation.
            try:
                connections.close_all()
            except Exception:
                raise BrowserGuardError("BROWSER_CONNECTION_CLEANUP_FAILED") from None
            return
        super()._post_teardown()

    def test_real_roles_worker_review_password_and_revocation(self):
        self.worker = threading.Thread(target=self.worker_loop, name="kapit-browser-worker", daemon=True)
        self.worker.start()
        try:
            result = run_browser(self.live_server_url, self.channel_id)
            if self.worker_failed.is_set():
                raise BrowserGuardError("BROWSER_WORKER_FAILED")
            self.assertTrue(result["ok"], "BROWSER_JOURNEY_FAILED")
        finally:
            self.stop_worker()

    def test_real_m3_seven_ordered_journeys(self):
        """Separate M3 deadline/result protocol; original M1 method is unchanged."""
        require_target(connection.settings_dict, os.environ, running_test=True)
        require_actual_database()
        try:
            # Fresh isolated database only. No reports, reviews, approvals or keys
            # are provisioned; all those writes happen through the genuine UI.
            call_command("seed_m3_demo", stdout=io.StringIO(), stderr=io.StringIO(), verbosity=0)
            from apps.scopes.models import PolicyVersion, SharingChannel, Unit
            payload = json.dumps({"url": self.live_server_url,
                "channel_ids": [str(SharingChannel.objects.get(code=f"CH-DEMO-0{n}").id) for n in (1, 2, 3)],
                "unit_ids": [str(Unit.objects.get(code=f"SIM-UNIT-0{n}").id) for n in (1, 2, 3)],
                "policy_ids": [str(PolicyVersion.objects.get(version=f"demo-policy-v{n}").id) for n in (1, 2)]}).encode("utf8")
        except Exception:
            raise BrowserGuardError("BROWSER_M3_FIXTURE_FAILED") from None
        if len(payload) > 4096:
            raise BrowserGuardError("BROWSER_M3_INPUT_INVALID")
        script = ROOT / "web/tests/m3-live-journey.mjs"
        node = shutil.which("node")
        if not node or not shutil.which("python") or not script.is_file() or not (ROOT / "web/node_modules/playwright/package.json").is_file():
            raise BrowserGuardError("BROWSER_M3_DEPENDENCIES_UNAVAILABLE")
        gates = ["m3_review", "m3_isolation", "m3_recipients", "m3_correction", "m3_withdrawal", "m3_policy", "m3_integration"]
        stages = {"INPUT", "BROWSER", "REVIEW", "ISOLATION", "RECIPIENTS", "CORRECTION", "WITHDRAWAL", "POLICY", "INTEGRATION", "COMPLETE"}

        def confirmed(raw, code):
            try:
                result = json.loads(raw)
                if not isinstance(result, dict) or result.get("stage") not in stages:
                    raise ValueError
                if code or result.get("ok") is not True:
                    if set(result) != {"ok", "stage"} or result.get("ok") is not False:
                        raise ValueError
                    raise BrowserGuardError("BROWSER_M3_JOURNEY_FAILED_" + result["stage"])
                if (set(result) != {"ok", "stage", "scanned_responses", "gates"}
                        or result["stage"] != "COMPLETE" or result["gates"] != gates
                        or type(result["scanned_responses"]) is not int
                        or not 20 <= result["scanned_responses"] <= 3000):
                    raise ValueError
                return result
            except BrowserGuardError:
                raise
            except (ValueError, TypeError, UnicodeError):
                raise BrowserGuardError("BROWSER_M3_OUTPUT_INVALID") from None

        allowed = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "HOME", "DISPLAY", "XDG_RUNTIME_DIR"}
        env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
        owner, process, threads = None, None, []
        self.worker = threading.Thread(target=self.worker_loop, name="kapit-m3-browser-worker", daemon=True)
        self.worker.start()
        try:
            owner = ChildOwnership()
            process = subprocess.Popen([node, str(script)], cwd=ROOT / "web", env=env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0, start_new_session=os.name != "nt")
            owner.attach(process)
            output, errors = BoundedReader(process.stdout), BoundedReader(process.stderr, retain=False)
            for reader in (output, errors):
                thread = threading.Thread(target=reader.read, daemon=True)
                thread.start()
                threads.append(thread)
            process.stdin.write(payload)
            process.stdin.close()
            deadline = time.monotonic() + 360
            while process.poll() is None:
                if output.overflow or errors.overflow or output.failed or errors.failed:
                    raise BrowserGuardError("BROWSER_M3_OUTPUT_LIMIT")
                if self.worker_failed.is_set():
                    raise BrowserGuardError("BROWSER_WORKER_FAILED")
                if time.monotonic() >= deadline:
                    raise BrowserGuardError("BROWSER_M3_PROCESS_TIMEOUT")
                time.sleep(0.05)
            for thread in threads:
                thread.join(timeout=5)
            if any(thread.is_alive() for thread in threads) or output.overflow or errors.overflow or output.failed or errors.failed:
                raise BrowserGuardError("BROWSER_M3_OUTPUT_LIMIT")
            result = confirmed(bytes(output.data), process.returncode)
            self.assertTrue(result["ok"], "BROWSER_M3_JOURNEY_FAILED")
        except BrowserGuardError:
            raise
        except Exception:
            raise BrowserGuardError("BROWSER_M3_PROCESS_FAILED") from None
        finally:
            try:
                if owner is not None:
                    owner.close(process)
                for thread in threads:
                    thread.join(timeout=5)
            finally:
                self.stop_worker()
