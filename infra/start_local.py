"""Prepare and supervise the local synthetic website; run in a normal terminal."""
import argparse
import ctypes
import importlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from infra import local

URL = "http://127.0.0.1:8000/"


class StartupError(RuntimeError):
    pass


def phase(name):
    print(f"LOCAL_START: {name}", flush=True)


def native_phase(action):
    """Expose fixed native failure metadata without replaying exception details."""
    stages = {"init": "initialization", "start": "startup", "status": "verification"}
    if action not in stages:
        raise StartupError("INVALID_NATIVE_PHASE: unsupported PostgreSQL setup phase.")
    diagnostics = {
        "POSTGRES_BINARIES": "PostgreSQL 17 or 18 binaries were not found.",
        "NATIVE_PATH": "A runtime path or link is outside the owned workspace boundary.",
        "NATIVE_OWNER": "The database ownership marker is absent or does not match this project.",
        "NATIVE_CONFIG": "Recorded database binaries or configuration have changed and need review.",
        "NATIVE_INIT_INCOMPLETE": "The owned database has not finished initialization.",
        "NATIVE_INIT_PARTIAL": "Partial database files need review; no files were removed or replaced.",
        "NATIVE_TOKEN_RESTRICTED": "PostgreSQL could not create its Windows token. Run the diagnostic command in a normal user terminal.",
        "NATIVE_COMMAND": "An owned PostgreSQL command failed or timed out; raw database output was withheld.",
        "NATIVE_PORT": "Local port 55436 is unavailable; no existing service was changed.",
        "NATIVE_PROCESS": "The database process identity could not be verified.",
        "NATIVE_DATABASE": "The database connection did not match the owned project cluster.",
        "NATIVE_STOPPED": "The owned PostgreSQL server is not running.",
    }
    phase(f"PostgreSQL {stages[action]}")
    try:
        native = local.native_module()
        if action == "init":
            return native.init()
        if action == "start":
            return native.start()
        return native.status(require_running=True)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        # Only an exact known prefix is used. Exception suffixes may be private.
        code = str(error).partition(":")[0] if isinstance(error, RuntimeError) else ""
        if code not in diagnostics:
            code = "POSTGRES_SETUP_FAILED"
        detail = diagnostics.get(code, "Local PostgreSQL setup could not complete; no later setup step ran.")
        try:
            helper = importlib.import_module("infra.startup_failure_diagnostics")
            observation = helper.failure_observation()
        except (Exception, SystemExit):
            observation = "POSTGRES_FAILURE_OBSERVATION: UNAVAILABLE"
        raise StartupError(f"{code}: PostgreSQL {stages[action]} failed. {detail} "
                           "Read-only diagnostic command: python -B infra/local.py native-diagnose "
                           "(or infra/Diagnose KAPIT.cmd). Earlier startup cause remains unconfirmed.\n"
                           f"{observation}") from None


def require_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            probe.bind(("127.0.0.1", 8000))
        except OSError:
            raise StartupError("PORT_8000_IN_USE: stop the existing listener yourself or keep using it; no process was changed.") from None


def web_dependencies_ready():
    try:
        manifest = json.loads((local.ROOT / "web/package.json").read_text(encoding="utf-8"))
        expected = {**manifest["dependencies"], **manifest["devDependencies"]}
        return all(json.loads((local.ROOT / "web/node_modules" / name / "package.json").read_text(encoding="utf-8"))["version"] == version
                   for name, version in expected.items())
    except (OSError, ValueError, KeyError, TypeError):
        return False


def private_phase(command, environment):
    """Run only fixed reviewed local gates without emitting private failure data."""
    codes = {"test-native": "FRAMEWORK_GATE_FAILED", "browser-native": "BROWSER_GATE_FAILED", "seed-native": "PROVISIONING_FAILED"}
    if command not in codes:
        raise StartupError("INVALID_PRIVATE_PHASE: unsupported setup phase.")
    # M1 and M3 browser children have separate 300/360-second ceilings.
    # Reserve 60 seconds for framework setup/teardown around both children.
    timeout = {"test-native": 600, "browser-native": 720, "seed-native": 60}[command]

    def quiet_direct(arguments, *, environment):
        if arguments[:2] != [local.python_path(), str(local.ROOT / "backend/manage.py")]:
            raise StartupError("INVALID_PRIVATE_PHASE: expected direct project management command.")
        label = None
        if command == "test-native":
            labels = {
                ("check", "--settings=config.test_settings"): "framework check",
                ("makemigrations", "--check", "--dry-run", "--settings=config.test_settings"): "framework migration-consistency",
                ("test", "tests", "--settings=config.test_settings", "--testrunner=tests.browser_runner.BrowserAcceptanceRunner"): "framework full-suite",
            }
            label = labels.get(tuple(arguments[2:]))
            if label is None:
                raise StartupError("INVALID_PRIVATE_PHASE: unsupported framework substage.")
            phase(label + " started")
        children = []
        options = {"cwd": local.ROOT, "env": environment, "stdin": subprocess.DEVNULL,
                   "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
                   "creationflags": subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0}
        try:
            child = spawn_registered(arguments, children, options)
            if label is None:
                exit_code = child.wait(timeout=timeout)
            else:
                started = time.monotonic()
                deadline = started + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired("framework gate", timeout)
                    try:
                        exit_code = child.wait(timeout=min(30, remaining))
                    except subprocess.TimeoutExpired:
                        elapsed = time.monotonic() - started
                        if elapsed >= timeout:
                            raise subprocess.TimeoutExpired("framework gate", timeout) from None
                        phase(label + f" running (elapsed {int(elapsed)}s)")
                        continue
                    if time.monotonic() > deadline:
                        raise subprocess.TimeoutExpired("framework gate", timeout)
                    break
            if exit_code:
                raise StartupError(f"{codes[command]}: run python infra/local.py {command} separately to inspect that step.")
            if label is not None:
                phase(label + f" passed (elapsed {int(time.monotonic() - started)}s)")
        except subprocess.TimeoutExpired:
            raise StartupError(f"{codes[command]}: the step timed out; database data is retained for review.") from None
        finally:
            stop_children(children)

    {"test-native": local.native_test, "browser-native": local.native_browser, "seed-native": local.seed_native}[command](command_runner=quiet_direct)


def prepare():
    # Context and listener checks precede any install, initialization or seed.
    environment = local.managed_environment()
    local.checked_cache()
    require_free_port()
    if listener_owners():
        raise StartupError("PORT_8000_IN_USE: a listener appeared during preflight; no process was changed.")
    phase("checking Python packages")
    if not all(local.dependency_status()["modules"].values()):
        local.run([sys.executable, str(local.ROOT / "infra/local.py"), "prepare-python"], environment=environment)
        if not all(local.dependency_status()["modules"].values()):
            raise StartupError("PYTHON_PACKAGES_MISSING: project Python packages remain unavailable after preparation.")
    npm = local.npm_command()
    if not web_dependencies_ready():
        phase("installing locked website packages")
        local.run(npm + ["ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(local.CACHE / "npm-cache")],
                  cwd=local.ROOT / "web", environment=environment)
        if not web_dependencies_ready():
            raise StartupError("WEBSITE_PACKAGES_MISSING: locked website packages remain unavailable.")
    phase("building website")
    local.run(npm + ["run", "build"], cwd=local.ROOT / "web", environment=environment)
    phase("verifying owned PostgreSQL")
    native_phase("init")
    native_phase("start")
    native_phase("status")
    phase("running PostgreSQL and framework tests")
    private_phase("test-native", environment)
    phase("running real browser acceptance")
    private_phase("browser-native", environment)
    # Refuse a listener that appeared while the acceptance gates ran.
    require_free_port()
    phase("provisioning the exercise organization and operator accounts without resetting existing accounts")
    private_phase("seed-native", environment)
    return environment


def listener_owners(port=8000):
    """Windows IP Helper metadata; fail closed if listener ownership is unknown."""
    if os.name != "nt":
        raise StartupError("LISTENER_OWNER_UNAVAILABLE: this launcher currently requires Windows listener ownership support.")
    size = ctypes.c_uint32(0)
    table = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    table.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
                      ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32]
    table.restype = ctypes.c_uint32
    code = table(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)
    if code not in {0, 122} or not 4 <= size.value <= 8 * 1024 * 1024:
        raise StartupError("LISTENER_OWNER_UNAVAILABLE: local listener ownership could not be checked.")
    buffer = ctypes.create_string_buffer(size.value)
    if table(buffer, ctypes.byref(size), False, socket.AF_INET, 3, 0) != 0:
        raise StartupError("LISTENER_OWNER_UNAVAILABLE: local listener ownership could not be checked.")
    return parse_listener_owners(buffer.raw, port)


def parse_listener_owners(raw, expected_port=8000):
    # MIB_TCPTABLE_OWNER_PID: DWORD count followed by six-DWORD rows.
    import struct
    if len(raw) < 4:
        raise StartupError("LISTENER_OWNER_UNAVAILABLE: invalid local listener metadata.")
    count = struct.unpack_from("<I", raw)[0]
    if count > (len(raw) - 4) // 24:
        raise StartupError("LISTENER_OWNER_UNAVAILABLE: incomplete local listener metadata.")
    owners = set()
    for index in range(count):
        state, address, port, _, _, pid = struct.unpack_from("<6I", raw, 4 + index * 24)
        if state == 2 and address in {0, int.from_bytes(socket.inet_aton("127.0.0.1"), "little")} and socket.ntohs(port & 0xffff) == expected_port:
            owners.add(pid)
    return owners


def server_pids(server):
    """The server PID plus its direct children.

    A Windows venv python.exe is a launcher that runs the real interpreter as a
    child process, so the listening socket belongs to that child, not the PID we
    spawned. Only direct children of our own process are accepted.
    """
    if os.name != "nt":
        return {server.pid}

    class Entry(ctypes.Structure):
        _fields_ = [("dwSize", ctypes.c_uint32), ("cntUsage", ctypes.c_uint32), ("th32ProcessID", ctypes.c_uint32),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", ctypes.c_uint32), ("cntThreads", ctypes.c_uint32),
                    ("th32ParentProcessID", ctypes.c_uint32), ("pcPriClassBase", ctypes.c_long), ("dwFlags", ctypes.c_uint32),
                    ("szExeFile", ctypes.c_wchar * 260)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    kernel.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
    kernel.Process32FirstW.argtypes = kernel.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    snapshot = kernel.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise StartupError("LISTENER_OWNER_UNAVAILABLE: local process ownership could not be checked.")
    pids = {server.pid}
    try:
        entry = Entry(dwSize=ctypes.sizeof(Entry))
        found = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while found:
            if entry.th32ParentProcessID == server.pid:
                pids.add(entry.th32ProcessID)
            found = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    return pids


def owned_listener(owners, server):
    return bool(owners) and owners <= server_pids(server)


def require_alive(children):
    if any(child.poll() is not None for child in children):
        raise StartupError("CHILD_EXITED: the website or worker stopped; their owned processes will be closed.")


def wait_ready(children, server, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        require_alive(children)
        owners = listener_owners()
        if owners and not owned_listener(owners, server):
            raise StartupError("LISTENER_CHANGED: port 8000 belongs to another process; it was not changed.")
        if owned_listener(owners, server) and local.api_available():
            require_alive(children)
            if not owned_listener(listener_owners(), server):
                raise StartupError("LISTENER_CHANGED: local listener ownership changed during startup.")
            return
        time.sleep(0.2)
    raise StartupError("API_TIMEOUT: the owned website did not become ready in time.")


def stop_children(children):
    failed = False
    prior = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        for child in reversed(children):
            try:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                failed = True
    finally:
        signal.signal(signal.SIGINT, prior)
    if failed:
        raise StartupError("CHILD_STOP_FAILED: an owned child did not confirm shutdown; PostgreSQL was retained.")


def spawn_registered(command, children, options):
    # A terminal Ctrl+C must not land between child creation and registration.
    prior = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        child = subprocess.Popen(command, **options)
        children.append(child)
        return child
    finally:
        signal.signal(signal.SIGINT, prior)


def supervise(environment, *, open_browser=True):
    require_free_port()
    children = []
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    common = {"cwd": local.ROOT, "env": environment, "stdin": subprocess.DEVNULL,
              "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL, "creationflags": flags}
    backups = BackupScheduler()
    try:
        phase("starting website and worker")
        server = spawn_registered([local.python_path(), str(local.ROOT / "infra/server.py")], children, common)
        spawn_registered([local.python_path(), str(local.ROOT / "backend/manage.py"), "process_jobs"], children, common)
        wait_ready(children, server)
        print(f"Website ready: {URL}\nKeep this terminal open. Ctrl+C stops this website and worker; PostgreSQL data is retained.", flush=True)
        if open_browser:
            try:
                webbrowser.open(URL, new=2)
            except (OSError, webbrowser.Error):
                phase("browser opening unavailable; use the printed localhost URL")
        next_backup_check = 0.0
        while True:
            require_alive(children)
            if not owned_listener(listener_owners(), server):
                raise StartupError("LISTENER_CHANGED: local listener ownership changed; only owned children will stop.")
            time.sleep(0.5)
            if time.monotonic() >= next_backup_check:
                backups.tick()
                next_backup_check = time.monotonic() + BACKUP_CHECK_SECONDS
    finally:
        stop_children(children)
        backups.finish()


# Approved RPO is 24 h (ai/reports/M4-completion-user-decisions.json); back up well inside it.
BACKUP_INTERVAL_SECONDS = 20 * 3600
BACKUP_CHECK_SECONDS = 3600
BACKUP_FINISH_SECONDS = 660  # pg_dump's own timeout is 600 s


def backup_if_due(now=None):
    """Keep a verified database backup newer than the interval while supervising; failure is shown, never fatal.

    Returns (status, epoch of the newest verified backup or None).
    """
    now = time.time() if now is None else now
    try:
        latest = local.latest_verified_backup()
        if latest is not None and now - latest["created_epoch"] < BACKUP_INTERVAL_SECONDS:
            return "CURRENT", latest["created_epoch"]
        local.native_backup()
    except Exception:
        phase("scheduled database backup failed; the website keeps running. Run python infra/local.py native-backup")
        return "FAILED", None
    phase("scheduled verified database backup created")
    return "CREATED", now


class BackupScheduler:
    """Runs backup_if_due off the supervisor loop so child health checks continue during a dump.

    Remembers the newest verified backup time, so routine checks don't re-hash retained dumps.
    """
    def __init__(self):
        self.thread = None
        self.known_epoch = None

    def tick(self, now=None):
        if self.thread is not None and self.thread.is_alive():
            return "RUNNING"
        now = time.time() if now is None else now
        if self.known_epoch is not None and now - self.known_epoch < BACKUP_INTERVAL_SECONDS:
            return "CURRENT"
        # Not a daemon: interpreter exit must never cut a dump off before its credential cleanup.
        self.thread = threading.Thread(target=self._run, name="kapit-backup")
        self.thread.start()
        return "STARTED"

    def finish(self, timeout=BACKUP_FINISH_SECONDS):
        """Let a running dump finish its own cleanup (it removes its temporary credential file)."""
        if self.thread is not None and self.thread.is_alive():
            phase("waiting for the running database backup to finish before exiting")
            self.thread.join(timeout)
            if self.thread.is_alive():
                phase("database backup still running; check the owned cluster folder for a leftover client.pass")
                return "STILL_RUNNING"
        return "IDLE"

    def _run(self):
        _, epoch = backup_if_due()
        if epoch is not None:
            self.known_epoch = epoch


def check():
    local.managed_environment()
    local.checked_cache()
    try:
        require_free_port()
        port_available = True
    except StartupError:
        port_available = False
    report = local.doctor()
    report["startup_port_available"] = port_available
    report["website_packages_ready"] = web_dependencies_ready()
    try:
        listener_owners()
        report["listener_owner_support"] = True
    except (StartupError, OSError):
        report["listener_owner_support"] = False
    report["prerequisites_ready"] = report["launch_ready"]
    report["launch_ready"] = report["launch_ready"] and port_available and report["website_packages_ready"] and report["listener_owner_support"]
    report["ready"] = report["launch_ready"]
    report["readiness_kind"] = "startup_prerequisites_only"
    report["website_running_verified"] = False
    for component in report.get("checks", []):
        if component["component"] == "api":
            component["code"] = "API_RESPONSE_OBSERVED_UNVERIFIED" if component["ready"] else "API_UNAVAILABLE"
            component["ready"] = False
            component["ownership_verified"] = False
    print(json.dumps(report, indent=2))
    return 0 if report["ready"] else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Report current prerequisites without installs, initialization or launching.")
    parser.add_argument("--no-browser", action="store_true", help="Print the localhost URL without opening a browser.")
    args = parser.parse_args()
    if args.check:
        return check()
    environment = prepare()
    supervise(environment, open_browser=not args.no_browser)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        phase("stopped owned processes; database retained")
        raise SystemExit(0) from None
    except StartupError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
    except (RuntimeError, OSError, ValueError, KeyError):
        print("LOCAL_SETUP_FAILED: a required step failed; no subsequent step was attempted. Check the preceding safe diagnostic and run --check.", file=sys.stderr)
        raise SystemExit(2) from None
