"""Explicit destructive-test lifecycle in a newly owned synthetic database only.

Run with the project Python after the other native gates have released their
lease. Existing demo data is never used for fixture writes. Failures during a
restart retain the test database whenever ownership cannot be established.
"""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import http.cookiejar
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
from infra import local, native_postgres, start_local

PORT = None
URL = None
ACTIVE_SERVER = None
GATES = ["fresh_owned_database", "real_http_login", "worker_process", "exact_test_review",
         "password_change", "permission_change", "queued_before_stop", "application_process_stop",
         "postgres_process_restart", "database_identity_retained", "immutable_data_retained",
         "fresh_application_processes", "password_and_permission_retained", "pending_job_resumed",
         "owned_database_cleanup"]


class AcceptanceError(RuntimeError):
    pass


def require(condition):
    if not condition:
        raise AcceptanceError("RESTART_ASSERTION_FAILED")


def setup():
    env = local.managed_environment()
    env["DJANGO_SETTINGS_MODULE"] = "config.test_settings"
    os.environ.clear()
    os.environ.update(env)
    import django
    django.setup()


def actual_database(oid):
    from django.db import connection
    from tests.browser_runner import require_target
    require_target(connection.settings_dict, os.environ, running_test=True)
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), oid FROM pg_database WHERE datname=current_database()")
        require(tuple(cursor.fetchone()) == ("test_kapit_m1", oid))


def child(mode):
    # No generic database or endpoint override is accepted by this child.
    payload = json.loads(sys.stdin.buffer.read(256))
    require(isinstance(payload, dict) and set(payload) == {"oid", "port"})
    require(type(payload["oid"]) is int and payload["oid"] > 0)
    require(type(payload["port"]) is int and 1024 <= payload["port"] <= 65535)
    setup()
    from django.db import connection
    connection.settings_dict["NAME"] = "test_kapit_m1"
    actual_database(payload["oid"])
    if mode == "worker":
        from django.core.management import call_command
        call_command("process_jobs", interval=0.1, verbosity=0)
    else:
        from django.core.wsgi import get_wsgi_application
        from wsgiref.simple_server import make_server
        from infra.server import LocalServer, QuietHandler
        with make_server("127.0.0.1", payload["port"], get_wsgi_application(),
                         server_class=LocalServer, handler_class=QuietHandler) as server:
            server.serve_forever()


class ApplicationChild:
    def __init__(self, mode, oid):
        from tests.browser_acceptance import ChildOwnership
        self.owner, self.process = ChildOwnership(), None
        try:
            self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", mode],
                cwd=ROOT, env=dict(os.environ), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, creationflags=(subprocess.CREATE_NO_WINDOW | 0x4) if os.name == "nt" else 0,
                start_new_session=os.name != "nt")
            # Windows venv redirectors can spawn the real interpreter before
            # it reads stdin. Attach the still-suspended process first, so all
            # later descendants are in our kill-on-close job from creation.
            self.owner.attach(self.process)
            if os.name == "nt":
                resume_owned_process(self.process)
            self.process.stdin.write(json.dumps({"oid": oid, "port": PORT}).encode("ascii"))
            self.process.stdin.close()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.owner is not None:
            self.owner.close(self.process)
            self.owner = None
        if self.process is not None:
            self.process.wait(timeout=5)


def resume_owned_process(process):
    """Resume only the sole initial thread of our CREATE_SUSPENDED child."""
    import ctypes
    from ctypes import wintypes

    class ThreadEntry(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("usage", wintypes.DWORD),
                    ("id", wintypes.DWORD), ("owner", wintypes.DWORD),
                    ("base_priority", wintypes.LONG), ("delta_priority", wintypes.LONG),
                    ("flags", wintypes.DWORD)]

    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    api.Thread32First.argtypes = api.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ThreadEntry)]
    api.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenThread.restype = wintypes.HANDLE
    api.ResumeThread.argtypes = [wintypes.HANDLE]
    api.ResumeThread.restype = wintypes.DWORD
    api.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
    api.GetProcessIdOfThread.restype = wintypes.DWORD
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    require(process.poll() is None)
    snapshot = api.CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
    require(snapshot and snapshot != ctypes.c_void_p(-1).value)
    matching = []
    try:
        entry = ThreadEntry(size=ctypes.sizeof(ThreadEntry))
        found = api.Thread32First(snapshot, ctypes.byref(entry))
        while found:
            if entry.owner == process.pid:
                matching.append(entry.id)
            found = api.Thread32Next(snapshot, ctypes.byref(entry))
    finally:
        api.CloseHandle(snapshot)
    require(len(matching) == 1 and process.poll() is None)
    thread = api.OpenThread(0x2 | 0x800, False, matching[0])  # SUSPEND_RESUME | QUERY_LIMITED_INFORMATION
    require(thread)
    try:
        require(api.GetProcessIdOfThread(thread) == process.pid and process.poll() is None)
        require(api.ResumeThread(thread) == 1)
    finally:
        api.CloseHandle(thread)


def free_port():
    global PORT, URL
    with socket.socket() as probe:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(("127.0.0.1", 0))
        PORT = probe.getsockname()[1]
        URL = f"http://127.0.0.1:{PORT}"


def listener_closed():
    with socket.socket() as probe:
        probe.settimeout(1)
        return probe.connect_ex(("127.0.0.1", PORT)) != 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def server_owned():
    return (ACTIVE_SERVER is not None and ACTIVE_SERVER.process.poll() is None
            and start_local.owned_listener(start_local.listener_owners(PORT), ACTIVE_SERVER.process))


class Client:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.token = None

    def request(self, path, data=None, *, method=None):
        require(path.startswith("/api/v1/") and "?" not in path)
        require(server_owned())
        headers = {"Accept": "application/json"}
        body = None
        if data is not None:
            headers.update({"Content-Type": "application/json", "X-CSRFToken": self.token or ""})
            if "operation_id" in data:
                headers["Idempotency-Key"] = data["operation_id"]
            body = json.dumps(data).encode("utf8")
        request = urllib.request.Request(URL + path, body, headers, method=method)
        try:
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(128 * 1024 + 1)
            require(len(raw) <= 128 * 1024)
            require(server_owned())
            return response.status, json.loads(raw)

    def login(self, username, password="DemoMaintenance!2026", *, expected=200):
        code, value = self.request("/api/v1/auth/csrf/")
        require(code == 200)
        self.token = value["csrf_token"]
        code, value = self.request("/api/v1/auth/login/", {"username": username, "password": password})
        require(code == expected)
        if code == 200:
            self.token = self.request("/api/v1/auth/csrf/")[1]["csrf_token"]
        return value


def wait_until(predicate, children=(), timeout=25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require(all(item.process.poll() is None for item in children))
        if predicate():
            return
        time.sleep(0.1)
    raise AcceptanceError("RESTART_TIMEOUT")


def ready():
    try:
        return server_owned() and Client().request("/api/v1/auth/csrf/")[0] == 200
    except (OSError, urllib.error.URLError):
        return False


def reconnect_lease(lease, advisory_lock):
    """Reacquire serialization after restart, retaining the pre-restart OID."""
    require(lease.owned_oid is not None)
    lease.connection.close()
    lease.connection.ensure_connection()
    lease.connection.set_autocommit(True)
    with lease.connection.cursor() as cursor:
        cursor.execute("SELECT pg_try_advisory_lock(%s)", [advisory_lock])
        lease.locked = cursor.fetchone()[0] is True
    require(lease.locked)
    lease.assert_owned()


def run():
    global ACTIVE_SERVER
    setup()
    from django.core.management import call_command
    from django.db import connections
    from apps.operations.models import ProcessingJob
    from apps.reports.models import ReportRevision, ReportVariant
    from apps.review.models import ReviewDecision
    from tests import browser_runner
    from tests.browser_runner import BrowserAcceptanceRunner
    from tests.test_workflow import operation

    native_postgres.status(require_running=True)
    free_port()
    runner = BrowserAcceptanceRunner(verbosity=0, interactive=True)
    config, children, completed = None, [], []
    restart_in_progress = False
    try:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            config = runner.setup_databases()
            actual_database(runner._browser_lease.owned_oid)
            call_command("seed_demo", verbosity=0)
        completed.append("fresh_owned_database")
        oid = runner._browser_lease.owned_oid
        server = ApplicationChild("server", oid); children.append(server)
        ACTIVE_SERVER = server
        worker = ApplicationChild("worker", oid); children.append(worker)
        wait_until(ready, children)
        submitter, reviewer, recipient, admin = [Client() for _ in range(4)]
        for client, name in zip([submitter, reviewer, recipient, admin],
                                ["submitter", "reviewer", "recipient", "administrator"]):
            client.login(name)
        completed.append("real_http_login")
        first = operation()
        code, receipt = submitter.request("/api/v1/sync/operations/", first)
        require(code == 201)
        wait_until(lambda: ReportVariant.objects.filter(revision__report_id=first["report_id"]).exists(), children)
        completed.append("worker_process")
        variant = ReportVariant.objects.get(revision__report_id=first["report_id"])
        code, review = reviewer.request(f"/api/v1/variants/{variant.id}/review/")
        require(code == 200)
        decision = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": review["binding"], "reason": ""}
        code, approved = reviewer.request(f"/api/v1/variants/{variant.id}/decisions/", decision)
        require(code == 200)
        publication_id = approved["publication_ids"][0]
        code, projected = recipient.request(f"/api/v1/publications/{publication_id}/")
        require(code == 200 and "PRIVATE_" not in json.dumps(projected))
        completed.append("exact_test_review")
        changed_password = "FictionalRestart!Changed2026"
        code, changed = submitter.request("/api/v1/auth/password/", {
            "current_password": "DemoMaintenance!2026", "new_password": changed_password})
        require(code == 200 and changed == {"changed": True, "reauthenticate": True})
        submitter.login("submitter", changed_password)
        completed.append("password_change")
        code, users = admin.request("/api/v1/administration/users/")
        require(code == 200)
        target = next(user for user in users["results"] if user["username"] == "recipient")
        code, _ = admin.request(f"/api/v1/administration/users/{target['id']}/", {
            "expected_permission_version": target["permission_version"], "is_active": False}, method="PATCH")
        require(code == 200)
        require(recipient.request(f"/api/v1/publications/{publication_id}/")[0] == 403)
        completed.append("permission_change")
        worker.close()
        second = operation()
        require(submitter.request("/api/v1/sync/operations/", second)[0] == 201)
        require(ProcessingJob.objects.get(revision__report_id=second["report_id"]).status == "PENDING")
        completed.append("queued_before_stop")
        before = list(ReportRevision.objects.order_by("id").values("id", "payload_ciphertext", "content_digest"))
        decisions = list(ReviewDecision.objects.values())
        original_pids = [item.process.pid for item in children]
        server.close()
        wait_until(listener_closed)
        completed.append("application_process_stop")
        connections.close_all()
        runner._browser_lease.close()
        browser_runner.PRESERVE_DATABASE = True
        restart_in_progress = True
        old_identity = native_postgres.ownership()["process"]
        native_postgres.stop()
        time.sleep(1.1)
        native_postgres.start()
        require(native_postgres.ownership()["process"] != old_identity)
        completed.append("postgres_process_restart")
        reconnect_lease(runner._browser_lease, browser_runner.ADVISORY_LOCK)
        actual_database(oid)
        restart_in_progress = False
        browser_runner.PRESERVE_DATABASE = False
        completed.append("database_identity_retained")
        require(list(ReportRevision.objects.order_by("id").values("id", "payload_ciphertext", "content_digest")) == before)
        require(list(ReviewDecision.objects.values()) == decisions)
        completed.append("immutable_data_retained")
        free_port()
        server = ApplicationChild("server", oid); children.append(server)
        ACTIVE_SERVER = server
        worker = ApplicationChild("worker", oid); children.append(worker)
        require(all(item.process.pid not in original_pids for item in [server, worker]))
        wait_until(ready, [server, worker])
        completed.append("fresh_application_processes")
        Client().login("submitter", expected=401)
        Client().login("recipient", expected=401)
        fresh_submitter = Client()
        fresh_submitter.login("submitter", changed_password)
        code, saved = fresh_submitter.request(f"/api/v1/reports/{first['report_id']}/revisions/1/")
        require(code == 200 and saved["receipt"] == receipt and saved["payload"] == first["payload"])
        require(saved["workflow"]["review"]["state"] == "APPROVED")
        fresh_admin = Client(); fresh_admin.login("administrator")
        code, users_after = fresh_admin.request("/api/v1/administration/users/")
        require(code == 200)
        target_after = next(user for user in users_after["results"] if user["id"] == target["id"])
        require(target_after["is_active"] is False)
        completed.append("password_and_permission_retained")
        wait_until(lambda: ReportVariant.objects.filter(revision__report_id=second["report_id"]).exists(), [server, worker])
        require(ProcessingJob.objects.get(revision__report_id=second["report_id"]).status == "DONE")
        require(ReviewDecision.objects.count() == 1)
        completed.append("pending_job_resumed")
    finally:
        cleanup_safe = True
        for item in reversed(children):
            try:
                item.close()
            except BaseException:
                cleanup_safe = False
        if not cleanup_safe or restart_in_progress:
            browser_runner.PRESERVE_DATABASE = True
        connections.close_all()
        if config is not None:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                runner.teardown_databases(config)
        require(cleanup_safe)
    completed.append("owned_database_cleanup")
    require(completed == GATES)
    return {"ok": True, "gates": completed, "postgres": "18.3", "database": "fresh_test_kapit_m1",
            "application_generations": 2, "postgres_restarts": 1, "demo_data_modified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", choices=("server", "worker"))
    args = parser.parse_args()
    try:
        if args.child:
            child(args.child)
        else:
            print(json.dumps(run(), indent=2))
        return 0
    except BaseException as error:
        # Neither assertion values nor child/database output may escape.
        import traceback
        frames = traceback.extract_tb(error.__traceback__)
        own_lines = [frame.lineno for frame in frames if Path(frame.filename).resolve() == Path(__file__).resolve()]
        print(json.dumps({"ok": False, "code": "RESTART_ACCEPTANCE_FAILED", "harness_line": own_lines[-1] if own_lines else None}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
