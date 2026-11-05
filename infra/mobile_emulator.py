"""TASK088 fresh owned API36 emulator bridge to the isolated M2 server.

Requires reviewed TASK087 app/test APK hashes and the orchestrator's heavy slot.
Never selects a phone, existing AVD, normal demo app or retained M1 database.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "android/tools"))
from infra import mobile_integration as integration
from infra.mobile_device import AndroidTools, DeviceError, PACKAGE, ENDPOINT, parse_reverse, safe_environment
from android.tools.owned_process import OwnedProcessTree

PORT = 5572
SERIAL = f"emulator-{PORT}"
WINDOW_SNAPSHOT = ("shell", "dumpsys", "window", "-a")
TEST_PACKAGE = PACKAGE + ".test"
RUNNER = "androidx.test.runner.AndroidJUnitRunner"
TEST_CLASS = "org.kapit.c2.mobile.sync.LiveRuntimeIntegrationTest"
CREDENTIAL_CLASS = "org.kapit.c2.mobile.sync.SystemCredentialIntegrationTest"
CREDENTIAL_METHOD = "actualCredentialCancelSuccessAndRecreation"
CREDENTIAL_MARKER = "no_backup/m2-credential-phase"
CREDENTIAL_PHASES = frozenset({"absent", "starting", "cancel_ready", "unlock_ready", "recreate_ready",
                               "stale_ready", "stale_returned", "completed"})
CREDENTIAL_ORDER = {name: index for index, name in enumerate(("absent", "starting", "cancel_ready",
    "unlock_ready", "recreate_ready", "stale_ready", "stale_returned", "completed"))}
# TASK-112: bounded re-observation of the unchanged unlock-target guard (count, not clock).
UNLOCK_TARGET_OBSERVATIONS = 8
UNLOCK_TARGET_INTERVAL = 1.0
# TASK-110: diagnostic native stage checkpoint written by TASK-109; never input or acceptance.
CREDENTIAL_STAGE_FILE = "no_backup/m2-credential-stage"
CREDENTIAL_STAGES = frozenset({"launch", "controller", "lock_wait_1", "click_unlock_1", "window_wait_1",
    "cancel_wait", "lock_wait_2", "click_unlock_2", "window_wait_2", "unlock_wait", "click_lock", "lock_wait_3",
    "click_unlock_3", "window_wait_3", "created_wait", "recreate", "controller_2", "window_wait_4",
    "stale_wait", "resumed_wait", "idle_wait", "lock_wait_4", "done"})
MOBILE_ACCESS = frozenset({"STARTING", "SIGNED_OUT", "READY", "LOCKED", "UNLOCK_REQUIRED", "LEASE_EXPIRED",
    "KEY_UNAVAILABLE", "ENROLLMENT_SUSPENDED", "CONTEXT_CHANGED", "UNSUPPORTED_DEVICE", "STORAGE_UNAVAILABLE",
    "TEMPLATE_UNSUPPORTED"})
LIFECYCLE_STATES = frozenset({"DESTROYED", "INITIALIZED", "CREATED", "STARTED", "RESUMED"})
# TASK-113: finite accessibility-window census written during credential-window waits.
CREDENTIAL_WINDOWS_FILE = "no_backup/m2-credential-windows"
WINDOW_TYPES = {"A": "APPLICATION", "S": "SYSTEM", "I": "INPUT_METHOD", "O": "ACCESSIBILITY_OVERLAY",
                "D": "SPLIT_DIVIDER", "M": "MAGNIFICATION", "X": "OTHER"}
WINDOW_OWNERS = {"a": "APP", "s": "SETTINGS", "u": "SYSTEMUI", "o": "OTHER", "n": "NONE",
                 # TASK-116 refinement of the former OTHER class.
                 "y": "SYSTEM_SERVER", "p": "PERMISSION_CONTROLLER", "g": "GMS", "l": "LAUNCHER",
                 "q": "OTHER_GOOGLE", "r": "OTHER_AOSP"}
PHASES = (
    ("enrollAndQueue", "normal", 0),
    ("droppedAcknowledgementKeepsImmutableQueue", "drop_after_commit", 1),
    ("reconcileCommittedReceiptAndExactReplay", "normal", 1),
    ("refreshRotationKeepsEnrollmentAndReadsOwnReport", "normal", 1),
    ("backgroundFenceAndAuthorizedRestart", "normal", 1),
)
BACKGROUND_METHODS = ("queuePendingBackgroundReport", "deliverPendingWithActualWorker")
LIVE_METHODS = frozenset(phase[0] for phase in PHASES) | frozenset(BACKGROUND_METHODS)
LIVE_FAILURE_CODES = frozenset({"UNAVAILABLE", "OFFLINE", "AUTH_REQUIRED", "CREDENTIALS_REJECTED", "REVOKED",
    "SCOPE_DENIED", "CONTEXT_CHANGED", "CONFLICT", "INVALID_RESPONSE", "THROTTLED"})


class EmulatorError(RuntimeError):
    """Fixed metadata only; raw command output never crosses this boundary."""


def failure_metadata(error):
    """Only owned source locations and an exact class allowlist; no error text."""
    classes = {EmulatorError: "EmulatorError", DeviceError: "DeviceError",
               integration.IntegrationError: "IntegrationError", RuntimeError: "RuntimeError",
               ValueError: "ValueError", TypeError: "TypeError", KeyError: "KeyError",
               OSError: "OSError", AssertionError: "AssertionError", TimeoutError: "TimeoutError",
               subprocess.TimeoutExpired: "TimeoutExpired", KeyboardInterrupt: "KeyboardInterrupt"}
    allowed = {str((ROOT / name).resolve()): name for name in
               ("infra/mobile_emulator.py", "infra/mobile_device.py", "infra/mobile_integration.py",
                "infra/native_postgres.py", "infra/start_local.py", "backend/tests/browser_runner.py")}
    frames, trace = [], error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        source = allowed.get(str(Path(trace.tb_frame.f_code.co_filename).resolve()))
        if source and 0 < trace.tb_lineno <= 100000:
            frames.append({"source": source, "line": trace.tb_lineno})
        trace = trace.tb_next
    foreign = {("tests.browser_runner", "BrowserGuardError"): "BrowserGuardError",
               ("django.db.utils", "OperationalError"): "DjangoOperationalError",
               ("django.db.utils", "InterfaceError"): "DjangoInterfaceError",
               ("django.db.utils", "IntegrityError"): "DjangoIntegrityError"}
    kind = classes.get(type(error), foreign.get((type(error).__module__, type(error).__name__), "Other"))
    return {"exception_class": kind, "owned_source_lines": frames[-6:]}


@contextmanager
def observed_harness(evidence):
    """Keep body failure and cleanup outcome distinct without changing063."""
    evidence["stage"] = "harness_start"
    harness = integration.MobileHarness()
    entered = False
    try:
        harness.__enter__()
        entered = True
        evidence["stage"] = "harness_ready"
        yield harness
    except BaseException as error:
        evidence["body_failure"] = {"stage": evidence["stage"], **failure_metadata(error)}
        raise
    finally:
        if entered:
            evidence["harness_cleanup_attempted"] = True
            try:
                harness.__exit__(*sys.exc_info())
                evidence["database_cleanup_passed"] = True
            except BaseException as error:
                evidence["database_cleanup_passed"] = False
                evidence["cleanup_failure"] = failure_metadata(error)
                raise


def require(value, code):
    if not value:
        raise EmulatorError(code)


def checked_path(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve().is_relative_to(ROOT.resolve())
            and path.resolve() != ROOT.resolve(), "EMULATOR_PATH_DENIED")
    current = path
    while current != ROOT:
        require(not current.is_symlink() and not (hasattr(current, "is_junction") and current.is_junction()),
                "EMULATOR_PATH_DENIED")
        require(current.parent != current, "EMULATOR_PATH_DENIED")
        current = current.parent
    return path


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class BoundedOutput:
    def __init__(self, stream, maximum, retain=True):
        self.stream, self.maximum, self.retain = stream, maximum, retain
        self.data = bytearray()
        self.failed = False

    def read(self):
        count = 0
        try:
            while chunk := self.stream.read(4096):
                count += len(chunk)
                if count > self.maximum:
                    self.failed = True
                if self.retain:
                    self.data.extend(chunk[:max(0, self.maximum - len(self.data))])
        except Exception:
            self.failed = True
        finally:
            try:
                self.stream.close()
            except Exception:
                self.failed = True


def run_bounded(argv, *, env=None, stdin=None, timeout=20, maximum=262144, on_tick=None):
    """Drain bounded buffers; report no command output on failure."""
    require(stdin is None or isinstance(stdin, bytes) and len(stdin) <= 4096,
            "EMULATOR_INPUT_BOUND")
    require(0 < timeout <= 180 and 0 < maximum <= 262144, "EMULATOR_COMMAND_BOUND")
    child = None
    threads = []
    try:
        child = subprocess.Popen([str(item) for item in argv], cwd=ROOT,
            env=env or safe_environment(), stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        output, errors = BoundedOutput(child.stdout, maximum), BoundedOutput(child.stderr, 16384, retain=False)
        for reader in (output, errors):
            thread = threading.Thread(target=reader.read, daemon=True)
            thread.start()
            threads.append(thread)
        if stdin is not None:
            child.stdin.write(stdin)
            child.stdin.close()
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            require(not output.failed and not errors.failed, "EMULATOR_OUTPUT_BOUND")
            require(time.monotonic() < deadline, "EMULATOR_COMMAND_TIMEOUT")
            if on_tick is not None:
                on_tick()
            time.sleep(0.05)
        for thread in threads:
            thread.join(timeout=2)
        require(not any(thread.is_alive() for thread in threads) and not output.failed and not errors.failed,
                "EMULATOR_OUTPUT_BOUND")
        require(child.returncode == 0, "EMULATOR_COMMAND_FAILED")
        return bytes(output.data).decode("utf-8", errors="replace").replace("\r\n", "\n")
    except EmulatorError:
        raise
    except Exception:
        raise EmulatorError("EMULATOR_COMMAND_UNAVAILABLE") from None
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=2)


def live_failure_code(raw):
    """Only the public enum from exact known exception lines; never free text."""
    name = "org.kapit.c2.mobile.ui.MobileLiveFailure"
    candidates = [line for line in raw.replace("\r\n", "\n").split("\n") if name in line]
    values = set()
    for line in candidates:
        match = re.fullmatch(r"(?:INSTRUMENTATION_STATUS: stack=)?" + re.escape(name) + r": ([A-Z_]+)", line)
        if match is None or match[1] not in LIVE_FAILURE_CODES:
            return None
        values.add(match[1])
    return next(iter(values)) if len(values) == 1 else None


# TASK-114: StoreFailure's message is exactly its StoreCode enum name (domain/StoreModels.kt).
STORE_FAILURE_CODES = frozenset({"READY", "SIGNED_OUT", "LOCKED", "UNLOCK_REQUIRED", "UNSUPPORTED_DEVICE",
    "LEASE_EXPIRED", "CLOCK_UNTRUSTED", "KEY_UNAVAILABLE", "STORAGE_UNAVAILABLE", "AUTH_REQUIRED", "REVOKED",
    "SCOPE_DENIED", "CONTEXT_CHANGED", "STALE_GENERATION", "STALE_DRAFT", "COMMAND_CONFLICT", "VALIDATION_ERROR",
    "TEMPLATE_UNSUPPORTED", "CLAIM_LOST", "RECEIPT_INVALID", "NOT_FOUND", "ALREADY_RECEIVED"})


def store_failure_code(raw):
    """Only the StoreCode enum from exact StoreFailure exception lines; never free text."""
    name = "org.kapit.c2.mobile.domain.StoreFailure"
    candidates = [line for line in raw.replace("\r\n", "\n").split("\n") if name in line]
    values = set()
    for line in candidates:
        match = re.fullmatch(r"(?:INSTRUMENTATION_STATUS: stack=|Caused by: )?" + re.escape(name) + r": ([A-Z_]+)",
                             line)
        if match is None or match[1] not in STORE_FAILURE_CODES:
            return None
        values.add(match[1])
    return next(iter(values)) if len(values) == 1 else None


def instrumentation_result(raw, method, test_class=TEST_CLASS):
    """Keep bounded status/type and exact public enum, never free-text messages."""
    require((test_class == TEST_CLASS and method in LIVE_METHODS) or
            (test_class == CREDENTIAL_CLASS and method == CREDENTIAL_METHOD), "EMULATOR_TEST_METHOD_DENIED")
    codes = re.findall(r"^INSTRUMENTATION_CODE: (-?\d{1,3})\s*$", raw, re.MULTILINE)
    records, current = [], {}
    for line in raw.splitlines():
        field = re.fullmatch(r"INSTRUMENTATION_STATUS: (class|test|current|numtests)=(.*)", line)
        if field:
            current.setdefault(field[1], []).append(field[2])
        status = re.fullmatch(r"INSTRUMENTATION_STATUS_CODE: (-?\d{1,3})", line)
        if status:
            records.append((int(status[1]), current))
            current = {}
    expected = {"class": [test_class], "test": [method], "current": ["1"], "numtests": ["1"]}
    exact_records = len(records) == 2 and all(fields == expected for _, fields in records)
    status_codes = [code for code, _ in records]
    completed = exact_records and status_codes[0] == 1 and status_codes[1] in {0, -1, -2, -3, -4}
    exceptions = re.findall(
        r"^(?:INSTRUMENTATION_STATUS: stack=)?((?:[A-Za-z_$][A-Za-z0-9_$]*\.){1,12}[A-Za-z_$][A-Za-z0-9_$]*(?:Error|Exception|Failure))(?::|\s*$)",
        raw, re.MULTILINE)
    exceptions = [name for name in dict.fromkeys(exceptions) if len(name) <= 160][:4]
    ok = (completed and status_codes == [1, 0] and codes == ["-1"]
          and len(re.findall(r"^OK \(1 test\)\s*$", raw, re.MULTILINE)) == 1
          and not any(value in raw for value in ("FAILURES", "INSTRUMENTATION_FAILED", "shortMsg="))
          and not exceptions)
    outcome = "passed" if ok else "failed" if completed and codes == ["-1"] else "incomplete"
    result = {"passed": ok, "outcome": outcome, "method_completed_count": int(completed),
            "status_codes": status_codes[:4], "instrumentation_codes": [int(code) for code in codes[:4]],
            "exception_types": exceptions}
    code = live_failure_code(raw)
    if code is not None and not ok:
        result["live_failure_code"] = code
    if not ok:
        store = store_failure_code(raw)
        if store is not None:
            result["store_failure_code"] = store
    return result


def credential_failure_site(raw, result):
    """Diagnostic only: exact086 ordinary DEX frames in one failed status stack."""
    timeout = "androidx.compose.ui.test.ComposeTimeoutException"
    handshake = result.get("handshake", {})
    if not (result.get("class") == CREDENTIAL_CLASS and result.get("method") == CREDENTIAL_METHOD
            and result.get("passed") is False and result.get("outcome") == "failed"
            and result.get("method_completed_count") == 1 and result.get("status_codes") == [1, -2]
            and result.get("instrumentation_codes") == [-1] and result.get("exception_types") == [timeout]
            and handshake.get("completed") is False and handshake.get("actions") == []
            and handshake.get("observed_markers") in (["starting"], ["absent", "starting"])):
        return None
    try:
        return credential_stack_site(raw)
    except Exception:
        # A diagnostic failure cannot replace the original completed failure.
        return "UNKNOWN"


def credential_stack_site(raw):
    """Select one owned stack; return only a fixed enum, never its contents."""
    timeout = "androidx.compose.ui.test.ComposeTimeoutException"
    # Keep a smaller diagnostic line budget inside the existing capture bound.
    if (len(raw) > 262144 or len(raw.encode("utf-8")) > 262144
            or not raw.endswith("\n") or raw.count("\n") > 512):
        return "UNKNOWN"
    lines = raw.replace("\r\n", "\n").split("\n")[:-1]
    if any("\r" in line or any(ord(c) < 32 and c != "\t" for c in line) for line in lines):
        return "UNKNOWN"
    records, fields, stacks, selected = [], {}, [], None
    for line in lines:
        status = re.fullmatch(r"INSTRUMENTATION_STATUS_CODE: (-?\d{1,3})", line)
        field = re.fullmatch(r"INSTRUMENTATION_STATUS: ([A-Za-z][A-Za-z0-9_]*)=(.*)", line)
        if status:
            records.append((int(status[1]), fields, stacks))
            fields, stacks, selected = {}, [], None
        elif field:
            selected = None
            if field[1] in {"class", "test", "current", "numtests"}:
                fields.setdefault(field[1], []).append(field[2])
            elif field[1] == "stack":
                selected = [field[2]]
                stacks.append(selected)
        elif line.startswith("INSTRUMENTATION_STATUS"):
            return "UNKNOWN"
        elif line.startswith(("INSTRUMENTATION_RESULT:", "INSTRUMENTATION_CODE:")):
            if fields or stacks:
                return "UNKNOWN"
            selected = None
        elif selected is not None:
            selected.append(line)
    expected = {"class": [CREDENTIAL_CLASS], "test": [CREDENTIAL_METHOD], "current": ["1"], "numtests": ["1"]}
    if (len(records) != 2 or [record[0] for record in records] != [1, -2]
            or any(record[1] != expected for record in records) or records[0][2]
            or len(records[1][2]) != 1 or fields or stacks):
        return "UNKNOWN"
    stack = records[1][2][0]
    if len(stack) > 128 or not re.fullmatch(re.escape(timeout) + r"(?::[^\r\n]*)?", stack[0]):
        return "UNKNOWN"
    while stack and stack[-1] == "":
        stack.pop()
    frames = []
    for line in stack[1:]:
        frame = re.fullmatch(r"[ \t]*at ((?:[A-Za-z_$][A-Za-z0-9_$]*\.)+[A-Za-z_$][A-Za-z0-9_$]*)"
            r"\.([A-Za-z_$][A-Za-z0-9_$]*)\(([A-Za-z0-9_$.-]+:\d{1,6}|Native Method|Unknown Source)\)", line)
        if frame is None:
            return "UNKNOWN"
        frames.append(frame.groups())
    relevant = [(index, frame) for index, frame in enumerate(frames)
        if "SystemCredentialIntegrationTest" in frame[0] or "SystemCredentialIntegrationTest" in frame[2]
        or frame[1] in {"waitLocked", "waitCredentialWindow", CREDENTIAL_METHOD}]
    if len(relevant) != 2 or relevant[1][0] != relevant[0][0] + 1:
        return "UNKNOWN"
    for helper, line, caller, site in (("waitLocked", 101, 53, "INITIAL_LOCK_WAIT"),
            ("waitCredentialWindow", 90, 55, "INITIAL_CREDENTIAL_WINDOW_WAIT")):
        if [frame for _, frame in relevant] == [
                (CREDENTIAL_CLASS, helper, f"SystemCredentialIntegrationTest.kt:{line}"),
                (CREDENTIAL_CLASS, CREDENTIAL_METHOD, f"SystemCredentialIntegrationTest.kt:{caller}")]:
            return site
    return "UNKNOWN"


def credential_stage_record(raw):
    """Strict fixed-schema parse of one native stage line; None for anything else."""
    if not isinstance(raw, str) or len(raw) > 160 or not raw.isascii():
        return None
    match = re.fullmatch(r"v1 n=([1-9][0-9]{0,4}) st=([a-z0-9_]{1,16}) b=([01u]) p=([01u]) a=([A-Z_]{1,24}|u)"
                         r" w=([01u]) l=([A-Z]{1,12}|u) r=([01u])", raw)
    if match is None:
        return None
    sequence, stage, busy, protected, access, window, lifecycle, pending = match.groups()
    if (stage not in CREDENTIAL_STAGES or (access != "u" and access not in MOBILE_ACCESS)
            or (lifecycle != "u" and lifecycle not in LIFECYCLE_STATES)):
        return None
    flag = {"1": True, "0": False, "u": None}
    return {"sequence": int(sequence), "stage": stage, "busy": flag[busy], "protected_content": flag[protected],
            "access": None if access == "u" else access, "credential_window": flag[window],
            "lifecycle": None if lifecycle == "u" else lifecycle, "unlock_pending": flag[pending]}


def credential_windows_record(raw):
    """Strict fixed-schema parse of one native window census line; None for anything else."""
    if not isinstance(raw, str) or len(raw) > 160 or not raw.isascii():
        return None
    item = r"[ASIODMX][01][01][" + "".join(sorted(WINDOW_OWNERS)) + "]"
    match = re.fullmatch(r"v1 n=([1-9][0-9]{0,4}) st=([a-z0-9_]{1,16}) k=([0-9]{1,2}) w=(-|" + item
                         + r"(?:," + item + r"){0,7})", raw)
    if match is None or match[2] not in CREDENTIAL_STAGES:
        return None
    items = [] if match[4] == "-" else match[4].split(",")
    if len(items) > int(match[3]) or (int(match[3]) <= 8 and len(items) != int(match[3])):
        return None
    return {"sequence": int(match[1]), "stage": match[2], "window_count": int(match[3]),
            "windows": [{"type": WINDOW_TYPES[code[0]], "active": code[1] == "1", "focused": code[2] == "1",
                         "owner": WINDOW_OWNERS[code[3]]} for code in items]}


def instrumentation_manifest(raw):
    lines = raw.splitlines()
    starts = [(index, len(line) - len(line.lstrip())) for index, line in enumerate(lines)
              if re.fullmatch(r"\s*E: instrumentation \(line=\d+\)", line)]
    require(len(starts) == 1, "EMULATOR_TEST_MANIFEST_DENIED")
    index, depth = starts[0]
    block = []
    for line in lines[index + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= depth:
            break
        block.append(line)
    content = "\n".join(block)
    names = re.findall(r'android:name\([^)]*\)="([^"]+)"', content)
    targets = re.findall(r'android:targetPackage\([^)]*\)="([^"]+)"', content)
    require(names == [RUNNER] and targets == [PACKAGE], "EMULATOR_TEST_MANIFEST_DENIED")


def verify_artifacts(tools, app, app_sha256, test, test_sha256):
    app, app_proof = tools.verify_apk(app, app_sha256)
    test = Path(test).resolve()
    require(test.is_relative_to((ROOT / "android").resolve()) and test.is_file() and test.suffix == ".apk",
            "EMULATOR_TEST_APK_PATH_DENIED")
    require(re.fullmatch(r"[0-9a-f]{64}", test_sha256 or "") and digest(test) == test_sha256,
            "EMULATOR_TEST_APK_HASH_DENIED")
    build = tools.sdk / "build-tools/36.1.0"
    badging = run_bounded([build / "aapt2.exe", "dump", "badging", test])
    require(re.findall(r"^package: name='([^']+)'", badging, re.MULTILINE) == [TEST_PACKAGE]
            and "application-debuggable" in badging.splitlines()
            and "targetSdkVersion:'36'" in badging.splitlines(), "EMULATOR_TEST_APK_IDENTITY_DENIED")
    manifest = run_bounded([build / "aapt2.exe", "dump", "xmltree", "--file", "AndroidManifest.xml", test])
    instrumentation_manifest(manifest)
    signed = run_bounded([tools.java / "bin/java.exe", "-jar", build / "lib/apksigner.jar",
                          "verify", "--verbose", "--print-certs", test], timeout=30)
    certificates = re.findall(r"^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$", signed, re.MULTILINE)
    require("Verified using v2 scheme (APK Signature Scheme v2): true" in signed.splitlines()
            and certificates == [app_proof["certificate_sha256"]]
            and not re.search(r"^Signer #[2-9]", signed, re.MULTILINE), "EMULATOR_TEST_SIGNATURE_DENIED")
    require(digest(app) == app_sha256 and digest(test) == test_sha256, "EMULATOR_APK_CHANGED")
    return (app, test), {"app": app_proof, "test": {"package": TEST_PACKAGE,
            "sha256": test_sha256, "certificate_sha256": certificates[0], "runner": RUNNER}}


def ports_available():
    for port in (PORT, PORT + 1):
        with socket.socket() as probe:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                raise EmulatorError("EMULATOR_PORT_PREEXISTING") from None


def current_device_lock(raw):
    current = [line.strip() for line in raw.splitlines() if "(current)" in line]
    if len(current) != 1:
        return None
    match = re.fullmatch(r'User "[^"\r\n]*" \(id=0, flags=(?:0x)?[0-9a-fA-F]+\) '
                         r'\(current\): (.+)', current[0])
    if not match:
        return None
    fields = {}
    for scalar in match[1].split(", "):
        pair = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)=([A-Za-z0-9_]+)", scalar)
        if not pair or pair[1] in fields:
            return None
        fields[pair[1]] = pair[2]
    return fields.get("deviceLocked") if fields.get("deviceLocked") in {"0", "1"} else None


def device_unlocked(raw):
    return current_device_lock(raw) == "0"


def device_locked(raw):
    return current_device_lock(raw) == "1"


def trust_diagnostic(raw):
    """Finite structure from the existing capture; never an acceptance rule."""
    if type(raw) is not str or "\x00" in raw or "\ufffd" in raw:
        return "UNKNOWN", "INVALID_INPUT"
    if len(raw) > 262144 or len(raw.encode("utf-8")) > 262144:
        return "UNKNOWN", "INPUT_BOUND"
    lines = raw.splitlines()
    if len(lines) > 512:
        return "UNKNOWN", "INPUT_BOUND"
    current = [line.strip() for line in lines if "(current)" in line]
    if not current:
        return "UNKNOWN", "CURRENT_MARKER_ABSENT"
    if len(current) != 1:
        return "UNKNOWN", "CURRENT_MARKER_AMBIGUOUS"
    if len(current[0]) > 8192:
        return "UNKNOWN", "INPUT_BOUND"
    match = re.fullmatch(r'User "[^"\r\n]*" \(id=0, flags=(?:0x)?[0-9a-fA-F]+\) '
                         r'\(current\): (.+)', current[0])
    if match is None:
        return "UNKNOWN", "OWNER_HEADER_UNMATCHED"
    scalars = match[1].split(", ")
    if len(scalars) > 64:
        return "UNKNOWN", "INPUT_BOUND"
    fields = {}
    for scalar in scalars:
        pair = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)=([A-Za-z0-9_]+)", scalar)
        if pair is None:
            return "UNKNOWN", "SCALAR_MALFORMED"
        if pair[1] in fields:
            return "UNKNOWN", "SCALAR_DUPLICATE"
        fields[pair[1]] = pair[2]
    if "deviceLocked" not in fields:
        return "UNKNOWN", "LOCK_SCALAR_ABSENT"
    if fields["deviceLocked"] not in {"0", "1"}:
        return "UNKNOWN", "LOCK_SCALAR_INVALID"
    # The unchanged parser remains authoritative even after structural checks.
    parsed = current_device_lock(raw)
    if parsed not in {"0", "1"}:
        return "UNKNOWN", "PARSER_UNKNOWN"
    return ("LOCKED" if parsed == "1" else "UNLOCKED"), "VALID"


def unlock_state_diagnostic(trust, current_user):
    state, structure = trust_diagnostic(trust)
    return {"schema": 1, "trust_state": state, "trust_structure": structure,
            "activity_owner_match": type(current_user) is str and len(current_user) <= 64 and
                re.fullmatch(r"0(?:\r?\n)?", current_user) is not None}


def keyguard_conditions(raw, *, current_user=None, trust=None):
    fields, monitor_fields = keyguard_fields(raw)
    owner = (fields.get("currentUser") in (["0"], ["-10000"])
             and monitor_fields.get("mCurrentUserId") == ["0"]
             and isinstance(current_user, str) and re.fullmatch(r"0(?:\r?\n)?", current_user) is not None
             and isinstance(trust, str) and current_device_lock(trust) == "1")
    return {"keyguard_showing": fields.get("showing") == ["true"] and monitor_fields.get("mIsShowing") == ["true"],
            "keyguard_secure": fields.get("secure") == ["true"],
            "keyguard_unoccluded": fields.get("occluded") == ["false"],
            "keyguard_owner_user": owner}


def keyguard_hidden(raw):
    """TASK-117: positive evidence only; any missing or ambiguous field is not hidden."""
    fields, monitor_fields = keyguard_fields(raw)
    return fields.get("showing") == ["false"] and monitor_fields.get("mIsShowing") == ["false"]


def keyguard_fields(raw):
    lines = raw.splitlines()
    starts = [i for i, line in enumerate(lines) if line.strip() == "KeyguardServiceDelegate"]
    monitors = [i for i, line in enumerate(lines) if line.strip() == "KeyguardStateMonitor"]
    fields, monitor_fields = {}, {}
    if len(starts) == 1:
        index = starts[0]
        depth = len(lines[index]) - len(lines[index].lstrip())
        end = len(lines)
        for position in range(index + 1, len(lines)):
            line = lines[position]
            indent = len(line) - len(line.lstrip())
            if line.strip() and indent <= depth:
                end = position
                break
            if indent == depth + 2 and "=" in line:
                key, value = line.strip().split("=", 1)
                fields.setdefault(key, []).append(value)
        if len(monitors) == 1 and index < monitors[0] < end:
            monitor = monitors[0]
            monitor_depth = len(lines[monitor]) - len(lines[monitor].lstrip())
            if monitor_depth == depth + 2:
                for line in lines[monitor + 1:end]:
                    indent = len(line) - len(line.lstrip())
                    if line.strip() and indent <= monitor_depth:
                        break
                    if indent == monitor_depth + 2 and "=" in line:
                        key, value = line.strip().split("=", 1)
                        monitor_fields.setdefault(key, []).append(value)
    return fields, monitor_fields


def package_owner_uid(raw, package):
    packages = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"package:([A-Za-z0-9_.]+) uid:([0-9]{1,6})", line)
        if not match or match[1] in packages:
            return None
        packages[match[1]] = int(match[2])
    uid = packages.get(package)
    return uid if uid is not None and 0 < uid < 100000 else None


def systemui_uid(raw):
    return package_owner_uid(raw, "com.android.systemui")


def current_window_focus(raw):
    focus = [line.strip() for line in raw.splitlines() if line.strip().startswith("mCurrentFocus")]
    if len(focus) != 1:
        return None
    return re.fullmatch(r"mCurrentFocus=(Window\{[0-9a-fA-F]+ u0 ([^\r\n}]{1,160})\})", focus[0])


def focused_window(raw):
    """One focus and its own direct owner record; no owner from another block."""
    match = current_window_focus(raw)
    if not match:
        return None
    lines = raw.splitlines()
    starts = [i for i, line in enumerate(lines)
              if re.fullmatch(r"\s*Window #[0-9]+ " + re.escape(match[1]) + ":", line)]
    if len(starts) != 1:
        return None
    index = starts[0]
    depth = len(lines[index]) - len(lines[index].lstrip())
    owners = []
    for line in lines[index + 1:]:
        indent = len(line) - len(line.lstrip())
        if line.strip() and (indent <= depth or line.strip().startswith("Window #")):
            break
        if re.search(r"\bmOwnerUid\b", line):
            owners.append((indent, line.strip()))
    if len(owners) != 1 or owners[0][0] != depth + 2:
        return None
    owner = re.fullmatch(r"mOwnerUid=([0-9]{1,6}) showForAllUsers=(?:true|false) "
                         r"package=([A-Za-z0-9_.]+) appop=[A-Za-z0-9_]+", owners[0][1])
    if not owner or not 0 < int(owner[1]) < 100000:
        return None
    title, package = match[2], owner[2]
    if "/" in title:
        component = re.fullmatch(r"([A-Za-z0-9_.]+)/[A-Za-z0-9_.$]+", title)
        if not component or component[1] != package:
            return None
    return title, int(owner[1]), package


def systemui_lock_focus(raw, uid):
    if type(uid) is not int or not 0 < uid < 100000:
        return False
    value = focused_window(raw)
    return value is not None and value[1:] == (uid, "com.android.systemui")


def systemui_prompt_decision(window_raw, packages_raw, policy_raw, trust_raw):
    """TASK-117 (user-approved): a focused SystemUI system prompt may receive BACK/PIN only
    with all four positive conditions. Pure over captured output; returns fixed codes only."""
    try:
        value = focused_window(window_raw)
        owner = None if value is None else value[2]
        observation = {
            "rule": "SYSTEMUI",
            "title_form": "NONE" if value is None else "ACTIVITY" if "/" in value[0] else "PLAIN",
            "owner": {None: "NONE", PACKAGE: "APP", "com.android.settings": "SETTINGS",
                      "com.android.systemui": "SYSTEMUI"}.get(owner, "OTHER"),
            "uid_match": value is not None and package_owner_uid(packages_raw, "com.android.systemui") == value[1],
            "keyguard_hidden": keyguard_hidden(policy_raw),
            "device_unlocked": device_unlocked(trust_raw)}
    except Exception:
        return {"rule": "SYSTEMUI", "code": "PROMPT_EVIDENCE_UNAVAILABLE", "accepted": False}
    observation["accepted"] = (observation["title_form"] == "PLAIN" and observation["owner"] == "SYSTEMUI"
                               and observation["uid_match"] is True and observation["keyguard_hidden"] is True
                               and observation["device_unlocked"] is True)
    return observation


def focused_package(raw):
    """Read only one actual owner window's package; never retain window text."""
    value = focused_window(raw)
    if value is None:
        return None
    return value[2] if "/" in value[0] else None


class CredentialHandshake:
    """A monotonic fixed-marker protocol, independent from test completion."""
    def __init__(self, emulator, clock=time.monotonic):
        self.emulator, self.clock = emulator, clock
        self.state = "cancel"
        self.next_poll = 0.0
        self.deadline = clock() + 45
        self.observed = []
        self.actions = []

    def advance(self, state):
        self.state = state
        self.deadline = self.clock() + 45

    def tick(self):
        now = self.clock()
        require(now < self.deadline or self.state == "done", "EMULATOR_CREDENTIAL_HANDSHAKE_TIMEOUT")
        if now < self.next_poll or self.state == "done":
            return
        self.next_poll = now + 0.25
        phase = self.emulator.credential_marker()
        require(phase in CREDENTIAL_PHASES, "EMULATOR_CREDENTIAL_MARKER_DENIED")
        if not self.observed or self.observed[-1] != phase:
            require(not self.observed or CREDENTIAL_ORDER[phase] > CREDENTIAL_ORDER[self.observed[-1]],
                    "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
            self.observed.append(phase)
            require(len(self.observed) <= 8, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
        if self.state == "cancel":
            require(phase in {"absent", "starting", "cancel_ready"}, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
            if phase == "cancel_ready":
                self.emulator.credential_action("cancel")
                self.actions.append("cancel")
                self.advance("unlock")
        elif self.state == "unlock":
            require(phase in {"cancel_ready", "unlock_ready"}, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
            if phase == "unlock_ready":
                self.emulator.credential_action("pin")
                self.actions.append("current_pin")
                self.advance("stale")
        elif self.state == "stale":
            require(phase in {"unlock_ready", "recreate_ready", "stale_ready"}, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
            if phase == "stale_ready":
                self.emulator.credential_action("pin")
                self.actions.append("stale_pin")
                self.advance("return")
        elif self.state == "return":
            require(phase == "stale_ready", "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
            if self.emulator.credential_focus() == PACKAGE:
                self.emulator.credential_returned()
                self.advance("complete")
        elif self.state == "complete":
            require(phase in {"stale_returned", "completed"}, "EMULATOR_CREDENTIAL_SEQUENCE_DENIED")
            if phase == "completed":
                self.advance("done")

    def finish(self):
        # The final marker can arrive between the last poll and process exit.
        self.next_poll = 0.0
        self.tick()
        require(self.state == "done" and self.actions == ["cancel", "current_pin", "stale_pin"],
                "EMULATOR_CREDENTIAL_HANDSHAKE_INCOMPLETE")
        return {"completed": True, "observed_markers": self.observed, "actions": self.actions}


class OwnedEmulator:
    def __init__(self, tools, harness, run_dir):
        self.tools, self.harness, self.run_dir = tools, harness, checked_path(run_dir)
        self.name = "KapitLive_" + self.run_dir.name
        require(re.fullmatch(r"KapitLive_[0-9a-f]{24}", self.name), "EMULATOR_NAME_DENIED")
        self.child, self.owner, self.target = None, None, None
        self.pin = None
        self.evidence = {"physical_phone": False, "fresh_owned_emulator": True}

    def identity(self):
        self.harness.assert_owned()
        require(self.child is not None and self.child.poll() is None, "EMULATOR_CHILD_STOPPED")
        devices = self.tools.discover()
        if self.target is None:
            targets = [item for item in devices if item["serial"] == SERIAL and item["state"] == "device"]
            require(len(targets) == 1, "EMULATOR_TRANSPORT_UNAVAILABLE")
            target = targets[0]
        else:
            require(self.target in devices, "EMULATOR_TRANSPORT_CHANGED")
            target = self.target
        result = run_bounded([self.tools.adb, "-t", target["transport"], "emu", "avd", "name"], timeout=10)
        require(result.splitlines() == [self.name, "OK"], "EMULATOR_AVD_IDENTITY")
        self.target = target

    def command(self, *parts, stdin=None, timeout=20, maximum=262144):
        self.identity()
        return run_bounded([self.tools.adb, "-t", self.target["transport"], *parts],
                           stdin=stdin, timeout=timeout, maximum=maximum)

    def __enter__(self):
        self.evidence["stage"] = "emulator_preflight"
        self.harness.assert_owned()
        ports_available()
        require(not any(item["serial"] == SERIAL for item in self.tools.discover()), "EMULATOR_TARGET_PREEXISTING")
        image = self.tools.sdk / "system-images/android-36/google_apis/x86_64"
        require((image / "system.img").is_file() and (self.tools.sdk / "emulator/emulator.exe").is_file(),
                "EMULATOR_IMAGE_UNAVAILABLE")
        avdhome = checked_path(self.run_dir / "avd")
        avdhome.mkdir(exist_ok=False)
        avd = avdhome / (self.name + ".avd")
        avd.mkdir(exist_ok=False)
        (avdhome / (self.name + ".ini")).write_text(
            f"avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-36\n", encoding="utf-8")
        (avd / "config.ini").write_text("\n".join([
            f"AvdId={self.name}", f"avd.ini.displayname={self.name}", "avd.ini.encoding=UTF-8",
            f"image.sysdir.1={image}", "abi.type=x86_64", "hw.cpu.arch=x86_64", "hw.cpu.ncore=2",
            "hw.ramSize=2048", "hw.lcd.width=720", "hw.lcd.height=1280", "hw.lcd.density=320",
            "hw.keyboard=yes", "hw.gpu.enabled=yes", "hw.gpu.mode=swiftshader_indirect",
            "disk.dataPartition.size=2147483648", "fastboot.forceColdBoot=yes", "showDeviceFrame=no",
            "tag.id=google_apis", "tag.display=Google APIs", "PlayStore.enabled=false", "target=android-36", ""
        ]), encoding="utf-8")
        env = safe_environment()
        env.update(ANDROID_AVD_HOME=str(avdhome), ANDROID_USER_HOME=str(self.run_dir / "android-user"))
        env.pop("ANDROID_SDK_HOME", None)
        try:
            self.evidence["stage"] = "emulator_boot"
            self.owner = OwnedProcessTree()
            self.child = subprocess.Popen([str(self.tools.sdk / "emulator/emulator.exe"), "-avd", self.name,
                "-port", str(PORT), "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot",
                "-gpu", "swiftshader_indirect", "-no-metrics"], env=env, cwd=ROOT,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
            self.owner.attach_and_resume(self.child)
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                require(self.child.poll() is None, "EMULATOR_CHILD_STOPPED")
                try:
                    if self.command("shell", "getprop", "sys.boot_completed").strip() == "1":
                        break
                except EmulatorError as error:
                    if str(error) not in {"EMULATOR_TRANSPORT_UNAVAILABLE", "EMULATOR_COMMAND_FAILED",
                                          "EMULATOR_COMMAND_UNAVAILABLE"}:
                        raise
                time.sleep(1)
            else:
                raise EmulatorError("EMULATOR_BOOT_TIMEOUT")
            require(self.command("shell", "getprop", "ro.kernel.qemu").strip() == "1", "EMULATOR_PHYSICAL_DENIED")
            require(self.command("shell", "getprop", "ro.build.version.sdk").strip() == "36"
                    and self.command("shell", "getprop", "ro.product.cpu.abi").strip() == "x86_64",
                    "EMULATOR_PLATFORM_DENIED")
            page = self.command("shell", "getconf", "PAGESIZE").strip()
            require(page in {"4096", "16384"}, "EMULATOR_PAGE_SIZE_UNKNOWN")
            self.evidence.update(observed_api=36, observed_abi="x86_64", observed_page_size=int(page))
            self.evidence["stage"] = "emulator_ready"
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def install(self, artifacts, expected_hashes):
        self.evidence["stage"] = "package_preflight"
        for package in (PACKAGE, TEST_PACKAGE):
            require(not self.command("shell", "pm", "list", "packages", "-u", package).strip(),
                    "EMULATOR_PACKAGE_PREEXISTING")
        self.evidence["stage"] = "reverse_preflight"
        require(ENDPOINT not in parse_reverse(self.command("reverse", "--list")), "EMULATOR_REVERSE_PREEXISTING")
        for index, (path, expected) in enumerate(zip(artifacts, expected_hashes, strict=True)):
            self.evidence["stage"] = "app_install" if index == 0 else "test_install"
            require(digest(path) == expected, "EMULATOR_APK_CHANGED")
            require("Success" in self.command("install", "--user", "0", str(path), timeout=120).splitlines(),
                    "EMULATOR_INSTALL_FAILED")
            require(digest(path) == expected, "EMULATOR_APK_CHANGED")
        self.evidence["stage"] = "installed_runner_check"
        installed = self.command("shell", "pm", "list", "instrumentation").splitlines()
        expected = f"instrumentation:{TEST_PACKAGE}/{RUNNER} (target={PACKAGE})"
        require(installed == [expected], "EMULATOR_INSTALLED_RUNNER_DENIED")
        self.evidence["stage"] = "reverse_setup"
        self.command("reverse", "--no-rebind", ENDPOINT, ENDPOINT)
        require(parse_reverse(self.command("reverse", "--list")).get(ENDPOINT) == ENDPOINT,
                "EMULATOR_REVERSE_UNCERTAIN")
        self.evidence["stage"] = "credential_setup"
        self.command("shell", "settings", "put", "system", "screen_off_timeout", "180000")
        self.pin = str(secrets.randbelow(900000) + 100000)
        # A new synthetic emulator credential goes over this owned ADB stdin;
        # no credential value enters host argv, tool messages or saved logs.
        result = self.command("shell", stdin=f"locksettings set-pin {self.pin}\n".encode("ascii"))
        require("Pin set to" in result, "EMULATOR_CREDENTIAL_SETUP_FAILED")
        self.evidence["stage"] = "install_ready"

    def require_unlock_target(self):
        # Read only bounded platform/window metadata. No hierarchy, text field,
        # credential value, raw dump or UID is retained in evidence.
        uid = systemui_uid(self.command("shell", "pm", "list", "packages", "-U", "--user", "0",
                                       "com.android.systemui", timeout=5))
        trust = self.command("shell", "dumpsys", "trust", timeout=5)
        current_user = self.command("shell", "am", "get-current-user", timeout=5)
        conditions = {"systemui_owner_uid_known": uid is not None,
                      "current_owner_locked": device_locked(trust)}
        conditions.update(keyguard_conditions(self.command("shell", "dumpsys", "window", "policy", timeout=5),
                                             current_user=current_user, trust=trust))
        conditions["systemui_lock_window_focused"] = systemui_lock_focus(
            self.command(*WINDOW_SNAPSHOT, timeout=5), uid)
        self.evidence["unlock_preconditions"] = conditions
        try:
            self.evidence["unlock_state_diagnostic"] = unlock_state_diagnostic(trust, current_user)
        except Exception:
            # Best-effort metadata cannot replace the original success/refusal.
            self.evidence["unlock_state_diagnostic"] = {"schema": 1, "code": "UNLOCK_DIAGNOSTICS_UNAVAILABLE"}
        require(all(conditions.values()), "EMULATOR_UNLOCK_TARGET_DENIED")

    def await_unlock_target(self):
        """TASK-112: repeat the unchanged guard for a bounded count before refusing.

        Only fixed predicate names that were false are kept per observation; the
        original refusal code and every predicate are those of require_unlock_target.
        """
        observations = []
        self.evidence["unlock_target_observations"] = observations
        for index in range(UNLOCK_TARGET_OBSERVATIONS):
            try:
                self.require_unlock_target()
                observations.append([])
                return
            except EmulatorError as error:
                if str(error) != "EMULATOR_UNLOCK_TARGET_DENIED":
                    raise
                observations.append(sorted(name for name, value in self.evidence["unlock_preconditions"].items()
                                           if not value))
                if index + 1 == UNLOCK_TARGET_OBSERVATIONS:
                    raise
            time.sleep(UNLOCK_TARGET_INTERVAL)

    def unlock(self):
        require(self.pin is not None, "EMULATOR_CREDENTIAL_MISSING")
        for _ in range(2):
            self.evidence["stage"] = "unlock_wake"
            self.command("shell", "input", "keyevent", "KEYCODE_SLEEP")
            time.sleep(2)
            self.command("shell", "input", "keyevent", "KEYCODE_WAKEUP")
            time.sleep(3)
            self.command("shell", "input", "swipe", "360", "1100", "360", "300", "400")
            time.sleep(3)
            script = "input keyevent " + " ".join(["KEYCODE_DEL"] * 6) + "\n"
            script += f"input text {self.pin}\ninput keyevent KEYCODE_ENTER\n"
            self.evidence["stage"] = "unlock_target_check"
            self.await_unlock_target()
            self.evidence["stage"] = "unlock_pin"
            self.command("shell", stdin=script.encode("ascii"))
            self.evidence["stage"] = "unlock_verify"
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if device_unlocked(self.command("shell", "dumpsys", "trust")):
                    return
                time.sleep(1)
        raise EmulatorError("EMULATOR_UNLOCK_UNCONFIRMED")

    def instrument(self, method):
        require(method in LIVE_METHODS, "EMULATOR_TEST_METHOD_DENIED")
        self.unlock()
        self.evidence["stage"] = "live_instrumentation"
        result = self.command("shell", "am", "instrument", "-w", "-r", "-e", "class", TEST_CLASS + "#" + method,
            "-e", "ownedEmulator", "true", f"{TEST_PACKAGE}/{RUNNER}", timeout=180)
        return instrumentation_result(result, method)

    def credential_marker(self):
        script = (f"if [ -f {CREDENTIAL_MARKER} ]; then head -c 33 {CREDENTIAL_MARKER}; "
                  "else printf absent; fi\n")
        result = self.command("shell", "run-as", PACKAGE, "sh", stdin=script.encode("ascii"), timeout=5, maximum=64)
        require(len(result) <= 32 and result.isascii() and result in CREDENTIAL_PHASES,
                "EMULATOR_CREDENTIAL_MARKER_DENIED")
        return result

    def credential_stage(self):
        script = (f"if [ -f {CREDENTIAL_STAGE_FILE} ]; then head -c 161 {CREDENTIAL_STAGE_FILE}; "
                  "else printf absent; fi\n")
        return self.command("shell", "run-as", PACKAGE, "sh", stdin=script.encode("ascii"), timeout=5, maximum=192)

    def credential_windows(self):
        script = (f"if [ -f {CREDENTIAL_WINDOWS_FILE} ]; then head -c 161 {CREDENTIAL_WINDOWS_FILE}; "
                  "else printf absent; fi\n")
        return self.command("shell", "run-as", PACKAGE, "sh", stdin=script.encode("ascii"), timeout=5, maximum=192)

    def credential_windows_observation(self):
        """Diagnostic only: a read or parse failure never alters the original outcome."""
        try:
            raw = self.credential_windows()
        except Exception:
            return {"status": "unavailable"}
        if raw == "absent":
            return {"status": "absent"}
        record = credential_windows_record(raw)
        return {"status": "invalid"} if record is None else {"status": "valid", **record}

    def credential_stage_observation(self):
        """Diagnostic only: a read or parse failure never alters the original outcome."""
        try:
            raw = self.credential_stage()
        except Exception:
            return {"status": "unavailable"}
        if raw == "absent":
            return {"status": "absent"}
        record = credential_stage_record(raw)
        return {"status": "invalid"} if record is None else {"status": "valid", **record}

    def credential_focus(self):
        packages = self.command("shell", "pm", "list", "packages", "-U", "--user", "0", timeout=5)
        value = focused_window(self.command(*WINDOW_SNAPSHOT, timeout=5))
        if value is None or "/" not in value[0]:
            return None
        _, uid, package = value
        if package not in {"com.android.settings", "com.android.systemui", PACKAGE}:
            return None
        return package if package_owner_uid(packages, package) == uid else None

    def systemui_prompt_focus(self):
        """Fresh bounded reads for systemui_prompt_decision; evidence keeps fixed codes only."""
        observation = systemui_prompt_decision(
            self.command(*WINDOW_SNAPSHOT, timeout=5),
            self.command("shell", "pm", "list", "packages", "-U", "--user", "0", timeout=5),
            self.command("shell", "dumpsys", "window", "policy", timeout=5),
            self.command("shell", "dumpsys", "trust", timeout=5))
        records = self.evidence.setdefault("credential_prompt_focus", [])
        if len(records) < 8:
            records.append(observation)
        return observation["accepted"]

    def credential_prompt_focus(self):
        # The existing activity-titled gate is unchanged and decides first.
        focus = self.credential_focus()
        if focus in {"com.android.settings", "com.android.systemui"}:
            return focus
        try:
            accepted = self.systemui_prompt_focus() is True
        except EmulatorError:
            accepted = False  # Fallback read failure keeps the original refusal.
        return "com.android.systemui" if accepted else None

    def credential_action(self, action):
        require(action in {"cancel", "pin"}, "EMULATOR_CREDENTIAL_ACTION_DENIED")
        require(self.credential_prompt_focus() in {"com.android.settings", "com.android.systemui"},
                "EMULATOR_CREDENTIAL_FOCUS_DENIED")
        if action == "cancel":
            self.command("shell", "input", "keyevent", "KEYCODE_BACK", timeout=5)
            return
        require(self.pin is not None and re.fullmatch(r"[0-9]{6}", self.pin), "EMULATOR_CREDENTIAL_MISSING")
        script = "input keyevent " + " ".join(["KEYCODE_DEL"] * 6) + "\n"
        script += f"input text {self.pin}\ninput keyevent KEYCODE_ENTER\n"
        self.command("shell", stdin=script.encode("ascii"), timeout=5)

    def credential_returned(self):
        require(self.credential_marker() == "stale_ready" and self.credential_focus() == PACKAGE,
                "EMULATOR_CREDENTIAL_RETURN_DENIED")
        script = (f"printf %s stale_returned > {CREDENTIAL_MARKER}.host\n"
                  f"mv -f {CREDENTIAL_MARKER}.host {CREDENTIAL_MARKER}\n")
        self.command("shell", "run-as", PACKAGE, "sh", stdin=script.encode("ascii"), timeout=5, maximum=64)
        require(self.credential_marker() in {"stale_returned", "completed"}, "EMULATOR_CREDENTIAL_RETURN_DENIED")

    def instrument_credentials(self):
        result = {"class": CREDENTIAL_CLASS, "method": CREDENTIAL_METHOD, "passed": False,
                  "outcome": "incomplete", "method_completed_count": 0, "handshake": {"completed": False}}
        handshake = CredentialHandshake(self)
        started = False
        try:
            self.unlock()
            require(self.credential_marker() == "absent", "EMULATOR_CREDENTIAL_MARKER_PREEXISTING")
            require(self.credential_stage() == "absent", "EMULATOR_CREDENTIAL_STAGE_PREEXISTING")
            require(self.credential_windows() == "absent", "EMULATOR_CREDENTIAL_WINDOWS_PREEXISTING")
            self.identity()
            self.evidence["stage"] = "credential_instrumentation"
            handshake = CredentialHandshake(self)
            started = True
            raw = run_bounded([self.tools.adb, "-t", self.target["transport"], "shell", "am", "instrument", "-w", "-r",
                "-e", "class", CREDENTIAL_CLASS + "#" + CREDENTIAL_METHOD, "-e", "ownedEmulator", "true",
                f"{TEST_PACKAGE}/{RUNNER}"], timeout=180, on_tick=handshake.tick)
            result.update(instrumentation_result(raw, CREDENTIAL_METHOD, CREDENTIAL_CLASS))
            # Exact test failure remains distinct from interrupted/missing
            # completion, and a completed marker alone can never grant success.
            if result["passed"]:
                result["handshake"] = handshake.finish()
            else:
                result["handshake"] = {"completed": False, "observed_markers": handshake.observed,
                                       "actions": handshake.actions}
                site = credential_failure_site(raw, result)
                if site is not None:
                    result["credential_failure_site"] = site
        except EmulatorError as error:
            result.update(passed=False, outcome="incomplete", code=str(error),
                          handshake={"completed": False, "observed_markers": handshake.observed,
                                     "actions": handshake.actions})
        if started and not result["passed"]:
            # Read while the owned emulator is still running, before teardown.
            result["credential_stage"] = self.credential_stage_observation()
            result["credential_windows"] = self.credential_windows_observation()
        return result

    def __exit__(self, *args):
        if len(args) >= 2 and args[1] is not None:
            self.evidence["body_failure"] = {"stage": self.evidence.get("stage", "emulator_preflight"),
                                             **failure_metadata(args[1])}
        self.pin = None
        if self.owner is None:
            return
        try:
            self.evidence["cleanup_attempted"] = True
            self.owner.close()
            if self.child is not None:
                self.child.wait(timeout=20)
            self.evidence["owned_emulator_stopped"] = self.child is None or self.child.poll() is not None
            deadline = time.monotonic() + 10
            while True:
                closed = True
                for port in (PORT, PORT + 1):
                    with socket.socket() as probe:
                        probe.settimeout(0.2)
                        closed = closed and probe.connect_ex(("127.0.0.1", port)) != 0
                if closed or time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
            self.evidence["owned_emulator_ports_closed"] = closed
            require(self.evidence["owned_emulator_stopped"] and closed, "EMULATOR_CLEANUP_UNCERTAIN")
        except BaseException as error:
            self.evidence["cleanup_failure"] = failure_metadata(error)
            from tests.browser_runner import preserve_database
            preserve_database()
            raise EmulatorError("EMULATOR_CLEANUP_UNCERTAIN") from None


def server_counts(harness, expected_revisions):
    harness.assert_owned()
    from apps.accounts.models import DeviceEnrollment
    from apps.operations.models import SyncReceipt
    from apps.reports.models import ReportRevision
    counts = {"enrollments": DeviceEnrollment.objects.count(), "revisions": ReportRevision.objects.count(),
              "receipts": SyncReceipt.objects.count()}
    require(counts == {"enrollments": 1, "revisions": expected_revisions, "receipts": expected_revisions},
            "EMULATOR_SERVER_EFFECT_MISMATCH")
    return counts


def background_counts(harness):
    harness.assert_owned()
    from apps.accounts.models import DeviceEnrollment
    from apps.operations.models import ProcessingJob, SyncReceipt
    from apps.reports.models import ReportRevision
    return {"enrollments": DeviceEnrollment.objects.count(), "revisions": ReportRevision.objects.count(),
            "receipts": SyncReceipt.objects.count(), "jobs": ProcessingJob.objects.count(),
            "jobs_done": ProcessingJob.objects.filter(status="DONE").count()}


def require_background_counts(counts, effects, done):
    require(counts == {"enrollments": 1, "revisions": effects, "receipts": effects,
                       "jobs": effects, "jobs_done": done}, "EMULATOR_BACKGROUND_EFFECT_MISMATCH")


CREDENTIAL_PARTIAL_LIMITATION = "STALE_RECREATION_NOT_VERIFIED_API36_OVERLAY"


def credential_cancel_and_unlock_proven(credential):
    """TASK-119: the real prompt was cancelled and then unlocked with the PIN; nothing less.

    unlock_ready is written before the PIN is typed; recreate_ready only after the native test
    verified the unlock (protected content, local data, one RECEIVED outbox row), the lock and
    the third prompt (QA R1)."""
    handshake = credential.get("handshake", {})
    markers = handshake.get("observed_markers")
    return (isinstance(markers, list) and "recreate_ready" in markers
            and handshake.get("actions") in (["cancel", "current_pin"], ["cancel", "current_pin", "stale_pin"]))


def background_delivery(harness, emulator, evidence):
    """Keep genuine pending-worker delivery separate from earlier acceptance."""
    prior = evidence.get("phases", [])
    credential = evidence.get("system_credential", {})
    full = credential.get("passed") is True and credential.get("handshake", {}).get("completed") is True
    partial = (credential.get("passed") is not True and credential_cancel_and_unlock_proven(credential)
               and evidence.get("credential_limitation") == CREDENTIAL_PARTIAL_LIMITATION)
    require([phase.get("method") for phase in prior] == [phase[0] for phase in PHASES]
            and all(phase.get("passed") is True and phase.get("method_completed_count") == 1 for phase in prior)
            and evidence.get("worker_completed") is True and (full or partial),
            "EMULATOR_BACKGROUND_PREREQUISITES_MISSING")
    result = {"passed": False, "phases": []}
    evidence["background_delivery"] = result
    result["before_queue"] = background_counts(harness)
    require_background_counts(result["before_queue"], 1, 1)
    for index, method in enumerate(BACKGROUND_METHODS):
        evidence.update(stage="background_fault_setup", active_method=method)
        harness.fault("normal")
        evidence["stage"] = "background_instrumentation"
        outcome = {"method": method, "fault": "normal", **emulator.instrument(method)}
        result["phases"].append(outcome)
        require(outcome["passed"], "EMULATOR_BACKGROUND_INSTRUMENTATION_FAILED")
        evidence["stage"] = "background_server_counts"
        if index == 0:
            outcome["server_counts"] = background_counts(harness)
            require_background_counts(outcome["server_counts"], 1, 1)
        else:
            def completed():
                counts = background_counts(harness)
                outcome["server_counts"] = counts
                # No missing/extra accepted effects may wait their way to a pass.
                require(counts["jobs_done"] in {1, 2}, "EMULATOR_BACKGROUND_EFFECT_MISMATCH")
                require_background_counts(counts, 2, counts["jobs_done"])
                return counts["jobs_done"] == 2
            harness.wait(completed)
            require_background_counts(outcome["server_counts"], 2, 2)
        print(json.dumps({"method": method, "passed": True}), flush=True)
    result["passed"] = True
    return result


def execute(app, app_sha256, test, test_sha256):
    # Verification precedes database creation and emulator launch.
    tools = AndroidTools()
    artifacts, proof = verify_artifacts(tools, app, app_sha256, test, test_sha256)
    parent = checked_path(ROOT / ".cache/m1-runtime/mobile-emulator")
    parent.mkdir(parents=True, exist_ok=True)
    run = checked_path(parent / secrets.token_hex(12))
    run.mkdir(exist_ok=False)
    evidence = {"task": "TASK-088", "ok": False, "physical_phone": False, "artifacts": proof, "phases": [],
                "server_library_sha256": digest(ROOT / "infra/mobile_integration.py"),
                "host_sha256": digest(Path(__file__).resolve())}  # QA F3: bind the result to its own host bytes.
    try:
        with observed_harness(evidence) as harness:
            evidence["stage"] = "emulator_boot"
            emulator = OwnedEmulator(tools, harness, run)
            try:
                with emulator:
                    evidence["stage"] = "emulator_install"
                    emulator.install(artifacts, (app_sha256, test_sha256))
                    for method, fault, revisions in PHASES:
                        evidence.update(stage="live_fault_setup", active_method=method)
                        harness.fault(fault)
                        evidence["stage"] = "live_instrumentation"
                        outcome = {"method": method, "fault": fault, **emulator.instrument(method)}
                        evidence["phases"].append(outcome)
                        require(outcome["passed"], "EMULATOR_INSTRUMENTATION_FAILED")
                        evidence["stage"] = "live_server_counts"
                        outcome["server_counts"] = server_counts(harness, revisions)
                        print(json.dumps({"method": method, "passed": True}), flush=True)
                    evidence["stage"] = "processing_completion"
                    from apps.operations.models import ProcessingJob
                    harness.wait(lambda: ProcessingJob.objects.filter(status="DONE").count() == 1)
                    require(ProcessingJob.objects.count() == 1, "EMULATOR_WORKER_EFFECT_MISMATCH")
                    evidence["worker_completed"] = True
                    evidence["stage"] = "credential_fault_setup"
                    harness.fault("normal")
                    evidence.update(stage="system_credential", active_method=CREDENTIAL_METHOD)
                    evidence["system_credential"] = emulator.instrument_credentials()
                    credential = evidence["system_credential"]
                    # TASK-119: proven cancel+unlock lets background delivery run; the overall run
                    # still fails below unless the credential method fully passed.
                    require(credential["passed"] or credential_cancel_and_unlock_proven(credential),
                            "EMULATOR_SYSTEM_CREDENTIAL_FAILED")
                    if not credential["passed"]:
                        evidence["credential_limitation"] = CREDENTIAL_PARTIAL_LIMITATION
                    credential["server_counts"] = server_counts(harness, 1)
                    print(json.dumps({"method": CREDENTIAL_METHOD, "passed": credential["passed"]}), flush=True)
                    evidence["stage"] = "background_delivery"
                    background_delivery(harness, emulator, evidence)
                    require(credential["passed"], "EMULATOR_SYSTEM_CREDENTIAL_PARTIAL")
            finally:
                evidence["emulator"] = emulator.evidence
        require(evidence["server_library_sha256"] == digest(ROOT / "infra/mobile_integration.py"),
                "EMULATOR_SERVER_SOURCE_CHANGED")
        evidence["ok"] = True
    except BaseException as error:
        evidence["code"] = str(error) if isinstance(error, EmulatorError) else "EMULATOR_INTEGRATION_FAILED"
        evidence["failure"] = failure_metadata(error)
        raise
    finally:
        # No raw instrumentation/stdout/stderr, credentials or app-private IDs.
        (run / "result.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--app-sha256", required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--test-sha256", required=True)
    args = parser.parse_args()
    if Path(sys.executable).resolve() != Path(integration.local.python_path()).resolve():
        return subprocess.run([integration.local.python_path(), str(Path(__file__).resolve()), *sys.argv[1:]],
                              cwd=ROOT, env=integration.local.managed_environment(), check=False).returncode
    try:
        execute(args.app, args.app_sha256, args.test, args.test_sha256)
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "code": str(error) if isinstance(error, EmulatorError) else "EMULATOR_INTEGRATION_FAILED"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
