"""Owned disposable M2 loopback runtime. Never adopts data or the main service.

`python infra/mobile_integration.py smoke` verifies real HTTP and PostgreSQL.
`python infra/mobile_integration.py serve` retains this test runtime until stopped.
The test accounts are synthetic; all test data is removed only after verified cleanup.
"""
import argparse
import base64
from contextlib import redirect_stderr, redirect_stdout
import http.client
import http.cookiejar
import io
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
from infra import local, native_postgres, start_local

PORT = 18082
BASE = f"http://127.0.0.1:{PORT}"
MODES = frozenset({"normal", "offline", "throttle", "unavailable", "drop_after_commit"})
STATE_PATH = "/__m2_harness__/state/"
SOURCE_PATH = "/api/v1/mobile/sync/operations/"


class IntegrationError(RuntimeError):
    """Fixed metadata only; never propagate response, credential or SQL values."""


def require(condition, code="MOBILE_INTEGRATION_ASSERTION"):
    if not condition:
        raise IntegrationError(code)


def fresh_secrets():
    return {
        "django": secrets.token_urlsafe(48),
        "source": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        "mobile": secrets.token_urlsafe(32),
    }


def validate_secrets(value):
    require(isinstance(value, dict) and set(value) == {"django", "source", "mobile"})
    require(all(isinstance(item, str) and 40 <= len(item) <= 128 for item in value.values()))
    require(len(value["django"]) >= 50)
    try:
        source = base64.b64decode(value["source"], altchars=b"-_", validate=True)
        mobile = base64.b64decode(value["mobile"] + "=", altchars=b"-_", validate=True)
        require(len(source) == len(mobile) == 32 and source != mobile)
        require(base64.urlsafe_b64encode(source).decode("ascii") == value["source"])
        require(base64.urlsafe_b64encode(mobile).rstrip(b"=").decode("ascii") == value["mobile"])
    except (ValueError, UnicodeError):
        raise IntegrationError("MOBILE_SECRET_FORMAT") from None
    require(len(set(value.values())) == 3)
    return value


def setup(key_set):
    validate_secrets(key_set)
    from django.conf import settings
    require(not settings.configured, "MOBILE_SETTINGS_ALREADY_LOADED")
    env = local.managed_environment()
    env.update(DJANGO_SETTINGS_MODULE="config.test_settings", KAPIT_SECRET_KEY=key_set["django"],
               KAPIT_SOURCE_KEY=key_set["source"], KAPIT_MOBILE_ENABLED="1",
               KAPIT_MOBILE_SIGNING_KEY=key_set["mobile"])
    os.environ.clear()
    os.environ.update(env)
    import django
    django.setup()
    settings.KAPIT_MOBILE_AUTH.require_available()
    settings.ROOT_URLCONF = "config.mobile_integration_urls"


def actual_database(oid):
    from django.db import connection
    from tests.browser_runner import require_target
    require_target(connection.settings_dict, os.environ, running_test=True)
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), oid FROM pg_database WHERE datname=current_database()")
        require(tuple(cursor.fetchone()) == ("test_kapit_m1", oid), "MOBILE_DATABASE_IDENTITY")


def port_available():
    with socket.socket() as probe:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("127.0.0.1", PORT))
        except OSError:
            raise IntegrationError("MOBILE_PORT_BUSY") from None


class FaultState:
    def __init__(self):
        self.lock = threading.Lock()
        self.mode, self.generation = "normal", 0

    def set(self, value):
        require(value in MODES, "MOBILE_FAULT_DENIED")
        with self.lock:
            self.mode = value
            self.generation += 1

    def get(self):
        with self.lock:
            return {"mode": self.mode, "generation": self.generation}

    def take(self):
        with self.lock:
            mode = self.mode
            if mode == "drop_after_commit":
                self.mode = "normal"
                self.generation += 1
            return mode


class FaultApplication:
    """Fault controls exist only in this isolated host, never in Django routes."""
    def __init__(self, application, state):
        self.application, self.state = application, state

    @staticmethod
    def response(start, status, value, extra=()):
        body = json.dumps(value, separators=(",", ":")).encode("ascii")
        start(status, [("Content-Type", "application/json"), ("Cache-Control", "private, no-store"),
                       ("Content-Length", str(len(body))), *extra])
        return [body]

    def __call__(self, environ, start_response):
        if environ.get("PATH_INFO") == STATE_PATH and environ.get("REQUEST_METHOD") == "GET":
            return self.response(start_response, "200 OK", self.state.get())
        if environ.get("PATH_INFO") != SOURCE_PATH or environ.get("REQUEST_METHOD") != "POST":
            return self.application(environ, start_response)
        mode = self.state.take()
        if mode == "offline":
            environ["kapit.owned_disconnect"]()
            return self.response(start_response, "503 Service Unavailable", {"code": "MOBILE_UNAVAILABLE", "message": "Unavailable."})
        if mode in {"throttle", "unavailable"}:
            status, code = ("429 Too Many Requests", "THROTTLED") if mode == "throttle" else ("503 Service Unavailable", "MOBILE_UNAVAILABLE")
            return self.response(start_response, status, {"code": code, "message": "Retry later."}, [("Retry-After", "2")])
        if mode != "drop_after_commit":
            return self.application(environ, start_response)
        captured = []
        def capture(status, headers, exc_info=None):
            require(not captured, "MOBILE_FAULT_RESPONSE")
            captured.append((status, headers))
        response = self.application(environ, capture)
        try:
            size = 0
            for part in response:
                size += len(part)
                require(size <= 20 * 1024, "MOBILE_FAULT_RESPONSE")
        finally:
            close = getattr(response, "close", None)
            if close:
                close()
        require(len(captured) == 1 and captured[0][0].startswith(("200 ", "201 ")), "MOBILE_FAULT_NOT_COMMITTED")
        # The real Django transaction has returned successfully. Lose the actual
        # socket response, retaining only server-side committed evidence.
        environ["kapit.owned_disconnect"]()
        return self.response(start_response, "503 Service Unavailable", {"code": "MOBILE_UNAVAILABLE", "message": "Unavailable."})


def child(mode):
    raw = sys.stdin.buffer.readline(4097)
    require(len(raw) <= 4096 and raw.endswith(b"\n"), "MOBILE_CHILD_INPUT")
    payload = json.loads(raw)
    require(isinstance(payload, dict) and set(payload) == {"oid", "keys"}, "MOBILE_CHILD_INPUT")
    require(type(payload["oid"]) is int and payload["oid"] > 0, "MOBILE_CHILD_INPUT")
    setup(payload["keys"])
    from django.db import connection
    connection.settings_dict["NAME"] = "test_kapit_m1"
    actual_database(payload["oid"])
    if mode == "worker":
        from django.core.management import call_command
        call_command("process_jobs", interval=0.1, verbosity=0)
        return
    from django.core.wsgi import get_wsgi_application
    from wsgiref.simple_server import make_server
    from infra.server import LocalServer, QuietHandler
    state = FaultState()
    class Handler(QuietHandler):
        def get_environ(self):
            result = super().get_environ()
            def disconnect():
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.close_connection = True
            result["kapit.owned_disconnect"] = disconnect
            return result
    with make_server("127.0.0.1", PORT, FaultApplication(get_wsgi_application(), state),
                     server_class=LocalServer, handler_class=Handler) as server:
        def control():
            try:
                while True:
                    line = sys.stdin.buffer.readline(129)
                    if not line:
                        break
                    require(len(line) <= 128 and line.endswith(b"\n"), "MOBILE_CONTROL_INPUT")
                    value = json.loads(line)
                    require(isinstance(value, dict) and set(value) == {"fault"}, "MOBILE_CONTROL_INPUT")
                    state.set(value["fault"])
            except Exception:
                pass
            finally:
                server.shutdown()
        threading.Thread(target=control, daemon=True).start()
        server.serve_forever(poll_interval=0.1)


class ApplicationChild:
    def __init__(self, mode, oid, key_set):
        from tests.browser_acceptance import ChildOwnership
        from infra.restart_acceptance import resume_owned_process
        self.owner, self.process = ChildOwnership(), None
        try:
            # Secrets use the owned anonymous pipe, not argv or child environment.
            env = dict(os.environ)
            for key in ("KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_MOBILE_SIGNING_KEY"):
                env.pop(key, None)
            self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", mode],
                cwd=ROOT, env=env, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=(subprocess.CREATE_NO_WINDOW | 0x4) if os.name == "nt" else 0,
                start_new_session=os.name != "nt")
            self.owner.attach(self.process)
            if os.name == "nt":
                resume_owned_process(self.process)
            self.process.stdin.write(json.dumps({"oid": oid, "keys": key_set}).encode("ascii") + b"\n")
            self.process.stdin.flush()
        except BaseException:
            self.close()
            raise

    def configure(self, fault):
        require(fault in MODES and self.process.poll() is None, "MOBILE_FAULT_DENIED")
        self.process.stdin.write(json.dumps({"fault": fault}).encode("ascii") + b"\n")
        self.process.stdin.flush()

    def close(self):
        if self.owner is not None:
            self.owner.close(self.process)
            self.owner = None
        if self.process is not None:
            self.process.wait(timeout=5)
            if self.process.stdin is not None:
                self.process.stdin.close()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, harness):
        self.harness, self.csrf = harness, None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, path, data=None, *, access=None, csrf=True):
        require(path.startswith("/api/v1/") or path == STATE_PATH, "MOBILE_CLIENT_PATH")
        require("?" not in path and "#" not in path, "MOBILE_CLIENT_PATH")
        self.harness.assert_owned()
        headers, body = {"Accept": "application/json"}, None
        if access is not None:
            headers["Authorization"] = "Bearer " + access
        if data is not None:
            headers["Content-Type"] = "application/json"
            if csrf:
                headers["X-CSRFToken"] = self.csrf or ""
            if "operation_id" in data:
                headers["Idempotency-Key"] = data["operation_id"]
            body = json.dumps(data).encode("utf8")
        request = urllib.request.Request(BASE + path, body, headers)
        try:
            response = self.opener.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(1024 * 1024 + 1)
            require(len(raw) <= 1024 * 1024, "MOBILE_RESPONSE_BOUND")
            self.harness.assert_owned()
            require("no-store" in response.headers.get("Cache-Control", ""), "MOBILE_RESPONSE_CACHE")
            return response.status, json.loads(raw)

    def login(self, username="submitter"):
        self.csrf = self.request("/api/v1/auth/csrf/")[1]["csrf_token"]
        code, _ = self.request("/api/v1/auth/login/", {"username": username, "password": "DemoMaintenance!2026"})
        require(code == 200)
        self.csrf = self.request("/api/v1/auth/csrf/")[1]["csrf_token"]


class MobileHarness:
    def __init__(self):
        self.runner, self.config, self.server = None, None, None
        self.children = []
        self.keys = fresh_secrets()

    def __enter__(self):
        port_available()
        setup(self.keys)
        from django.core.management import call_command
        from tests.browser_runner import BrowserAcceptanceRunner
        native_postgres.status(require_running=True)
        self.runner = BrowserAcceptanceRunner(verbosity=0, interactive=True)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.config = self.runner.setup_databases()
                actual_database(self.runner._browser_lease.owned_oid)
                call_command("seed_demo", verbosity=0)
            oid = self.runner._browser_lease.owned_oid
            self.server = ApplicationChild("server", oid, self.keys)
            self.children.append(self.server)
            self.children.append(ApplicationChild("worker", oid, self.keys))
            self.wait(lambda: self.ready())
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def assert_owned(self):
        require(self.server is not None and self.server.process.poll() is None, "MOBILE_SERVER_STOPPED")
        self.runner._browser_lease.assert_owned()
        require(start_local.owned_listener(start_local.listener_owners(PORT), self.server.process), "MOBILE_LISTENER_OWNERSHIP")

    def ready(self):
        try:
            client = Client(self)
            return client.request(STATE_PATH)[0] == 200 and client.request("/api/v1/mobile/me/")[0] == 401
        except (IntegrationError, OSError, urllib.error.URLError):
            return False

    def wait(self, predicate, seconds=25):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            require(all(item.process.poll() is None for item in self.children), "MOBILE_CHILD_STOPPED")
            if predicate():
                return
            time.sleep(0.1)
        raise IntegrationError("MOBILE_WAIT_TIMEOUT")

    def fault(self, mode):
        self.assert_owned()
        before = Client(self).request(STATE_PATH)[1]["generation"]
        self.server.configure(mode)
        self.wait(lambda: (value := Client(self).request(STATE_PATH)[1])["generation"] > before and value["mode"] == mode)

    def __exit__(self, *args):
        from django.db import connections
        from tests import browser_runner
        cleanup_safe = True
        for item in reversed(self.children):
            try:
                item.close()
            except BaseException:
                cleanup_safe = False
        if not cleanup_safe:
            browser_runner.preserve_database()
        connections.close_all()
        if self.config is not None:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.runner.teardown_databases(self.config)
            self.config = None
        self.keys.clear()
        require(cleanup_safe, "MOBILE_CLEANUP_UNCERTAIN")


def smoke():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    completed = []
    with MobileHarness() as harness:
        from apps.accounts.models import DeviceEnrollment
        from apps.operations.models import ProcessingJob, SyncReceipt
        from apps.reports.models import ReportRevision, ReportVariant
        from tests.test_workflow import operation
        completed.append("fresh_owned_database")
        client = Client(harness)
        require(client.request("/api/v1/mobile/me/")[0] == 401)
        web = Client(harness)
        web.login()
        require(web.request("/api/v1/account/devices/")[1]["count"] == 0)
        completed.append("web_login_and_mobile_denial")
        key = ec.generate_private_key(ec.SECP256R1())
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        code, challenge = client.request("/api/v1/mobile/auth/challenge/", {
            "username": "submitter", "password": "DemoMaintenance!2026", "installation_id": str(uuid.uuid4()),
            "enrollment_id": None, "public_key_spki": encode(public), "label": "Synthetic harness"})
        require(code == 200)
        code, session = client.request("/api/v1/mobile/auth/token/", {
            "challenge_id": challenge["challenge_id"], "nonce": challenge["nonce"],
            "signature": encode(key.sign(challenge["proof_message"].encode("ascii"), ec.ECDSA(hashes.SHA256())))})
        require(code == 200 and client.request("/api/v1/mobile/me/", access=session["access_token"])[0] == 200)
        completed.append("real_mobile_enrollment")
        submitted = operation()
        harness.fault("throttle")
        require(client.request(SOURCE_PATH, submitted, access=session["access_token"])[0] == 429)
        require(not ReportRevision.objects.filter(report_id=submitted["report_id"]).exists())
        harness.fault("unavailable")
        require(client.request(SOURCE_PATH, submitted, access=session["access_token"])[0] == 503)
        require(not ReportRevision.objects.filter(report_id=submitted["report_id"]).exists())
        harness.fault("offline")
        try:
            client.request(SOURCE_PATH, submitted, access=session["access_token"])
            raise IntegrationError("MOBILE_EXPECTED_DISCONNECT")
        except (urllib.error.URLError, http.client.RemoteDisconnected, ConnectionResetError):
            pass
        require(not ReportRevision.objects.filter(report_id=submitted["report_id"]).exists())
        completed.append("precommit_faults_preserve_queue")
        harness.fault("drop_after_commit")
        try:
            client.request(SOURCE_PATH, submitted, access=session["access_token"])
            raise IntegrationError("MOBILE_EXPECTED_DISCONNECT")
        except (urllib.error.URLError, http.client.RemoteDisconnected, ConnectionResetError):
            pass
        code, receipt = client.request(f"/api/v1/mobile/sync/receipts/{submitted['operation_id']}/", access=session["access_token"])
        require(code == 200 and receipt["shared"] is False)
        replay_code, replay = client.request(SOURCE_PATH, submitted, access=session["access_token"])
        require(replay_code == 200 and replay == receipt)
        require(ReportRevision.objects.filter(report_id=submitted["report_id"]).count() == 1)
        require(SyncReceipt.objects.filter(operation_id=submitted["operation_id"]).count() == 1)
        completed.append("lost_response_receipt_and_exact_replay")
        harness.wait(lambda: ReportVariant.objects.filter(revision__report_id=submitted["report_id"]).exists())
        require(ProcessingJob.objects.get(revision__report_id=submitted["report_id"]).status == "DONE")
        require(client.request("/api/v1/mobile/reports/", access=session["access_token"])[1]["count"] == 1)
        require(client.request(f"/api/v1/mobile/reports/{submitted['report_id']}/revisions/1/", access=session["access_token"])[0] == 200)
        completed.append("real_worker_and_scoped_reads")
        code, refreshed = client.request("/api/v1/mobile/auth/refresh/", {"refresh_token": session["refresh_token"]})
        require(code == 200 and refreshed["context"]["enrollment_id"] == session["context"]["enrollment_id"])
        enrollment = str(DeviceEnrollment.objects.get().id)
        require(web.request(f"/api/v1/account/devices/{enrollment}/revoke/", {}, csrf=False)[0] == 403)
        require(web.request(f"/api/v1/account/devices/{enrollment}/revoke/", {})[0] == 200)
        require(client.request("/api/v1/mobile/me/", access=refreshed["access_token"])[0] == 401)
        require(web.request("/api/v1/account/devices/")[0] == 200)
        completed.append("refresh_and_owner_csrf_revocation")
    completed.append("owned_cleanup")
    return {"ok": True, "gates": completed, "port": PORT, "retained_main_modified": False,
            "android_client_executed": False, "physical_phone_executed": False}


def serve(harness):
    """Own faults through this process's console/pipe, never an HTTP control API."""
    print(json.dumps({"ready": True, "url": BASE, "database": "owned disposable test database",
                      "retained_main_modified": False, "commands": sorted(MODES) + ["quit"]}), flush=True)
    # A bounded queue reader permits ownership/child monitoring even while a
    # human terminal has no input. EOF ends the owned runtime safely.
    import queue
    commands = queue.Queue(maxsize=1)
    def read_commands():
        while True:
            line = sys.stdin.readline(129)
            commands.put(line)
            if not line:
                return
    threading.Thread(target=read_commands, daemon=True).start()
    while True:
        harness.assert_owned()
        require(all(item.process.poll() is None for item in harness.children), "MOBILE_CHILD_STOPPED")
        try:
            line = commands.get(timeout=0.5)
        except queue.Empty:
            continue
        if not line or line.strip() == "quit":
            return
        require(len(line) <= 128 and line.endswith("\n"), "MOBILE_CONSOLE_INPUT")
        command = line.strip()
        require(command in MODES, "MOBILE_FAULT_DENIED")
        harness.fault(command)
        print(json.dumps({"fault": command}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=("smoke", "serve"), default="smoke")
    parser.add_argument("--child", choices=("server", "worker"), help=argparse.SUPPRESS)
    parser.add_argument("--phone", action="store_true", help="Attach the sole authorized physical USB phone; never an emulator")
    parser.add_argument("--apk", type=Path, help="Reviewed isolated spike APK under android/")
    parser.add_argument("--sha256", help="Expected reviewed APK SHA-256, required with --phone")
    args = parser.parse_args()
    if Path(sys.executable).resolve() != Path(local.python_path()).resolve():
        return subprocess.run([local.python_path(), str(Path(__file__).resolve()), *sys.argv[1:]],
                              cwd=ROOT, env=local.managed_environment(), check=False).returncode
    try:
        require((not args.phone and args.apk is None and args.sha256 is None) or
                (args.phone and args.mode == "serve" and not args.child and args.apk and args.sha256),
                "MOBILE_PHONE_OPTIONS")
        if args.child:
            child(args.child)
        elif args.mode == "smoke":
            print(json.dumps(smoke(), indent=2))
        else:
            with MobileHarness() as harness:
                try:
                    if args.phone:
                        from infra.mobile_device import PhysicalSession, AndroidTools
                        with PhysicalSession(AndroidTools(), harness, args.apk, args.sha256) as phone:
                            print(json.dumps(phone.evidence), flush=True)
                            serve(harness)
                    else:
                        serve(harness)
                except KeyboardInterrupt:
                    pass
        return 0
    except BaseException as error:
        import traceback
        frames = traceback.extract_tb(error.__traceback__)
        lines = [frame.lineno for frame in frames if Path(frame.filename).resolve() == Path(__file__).resolve()]
        code = str(error) if isinstance(error, IntegrationError) else "MOBILE_INTEGRATION_FAILED"
        print(json.dumps({"ok": False, "code": code, "harness_line": lines[-1] if lines else None}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
