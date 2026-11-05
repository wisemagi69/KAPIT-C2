"""TASK103: one owned enrollment diagnostic; source review precedes execution.

Native enrollment, diagnostic collection and cleanup are independent outcomes.
Only a fresh owned emulator/database is eligible. No route repair or retry.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_emulator as base
from infra.mobile_accessibility import RunLease

require, Error = base.require, base.EmulatorError
TEST_CLASS = "org.kapit.c2.mobile.sync.EnrollmentTransportDiagnosticTest"
METHOD = "diagnoseEnrollmentTransport"
MARKER = "no_backup/m2-enrollment-transport.json"
NATIVE_SOURCE = "android/app/src/androidTest/java/org/kapit/c2/mobile/sync/EnrollmentTransportDiagnosticTest.kt"
PROTOCOL = "ai/reports/android-m2-network-protocol.json"
FROZEN = {
    "infra/mobile_emulator.py": "961c528051e6d70c9456723f935d7140d317ecad7f5cc34c80112713f2ca3e6c",
    "infra/mobile_device.py": "8df9b50002f5fc65a97e5624e35f7ea8be39acbdd4c48b79714d8997aa933012",
    "infra/mobile_integration.py": "8aa5c44ffe8e60b277a7496fc4d9557f624a868386c672fc9d77d5182faf03ab",
    "infra/mobile_accessibility.py": "1bb76e9d89968015770e3e264655074914459a68bb791f146343f88fcccfa8ee",
    "android/tools/owned_process.py": "bee293c26831a964a8b88fba75570c6bd2cacb1887ffc2e5435a5af967ed8257",
    PROTOCOL: "5ee2181c43409ad0a1d799282f33e497d46fc87e72d383be20eb195e84a2981e",
    NATIVE_SOURCE: "e0ab19b2c31d505b77a20811704e778de40af5a0dcb3db9fb9b7b9044ac7cc15",
}
OWN_SOURCES = ("infra/mobile_network_diagnostic.py", "infra/test_mobile_network_diagnostic.py")
FAILURES = frozenset("NONE INVALID_REQUEST INVALID_RESPONSE NETWORK TIMEOUT HTTP CONTEXT_CHANGED EXPIRED_RESPONSE UNAVAILABLE STORE OUTER_BUDGET CANCELLED OTHER".split())
STAGES = frozenset("START DNS CONNECT CONNECTED REQUEST_HEADERS REQUEST_BODY RESPONSE_HEADERS RESPONSE_BODY".split())
IO = frozenset("NONE CONNECT SOCKET_TIMEOUT INTERRUPTED_IO UNKNOWN_HOST TLS PROTOCOL SOCKET EOF OTHER_IO".split())
ERRNO = frozenset("NONE EACCES EPERM ECONNREFUSED ETIMEDOUT ENETUNREACH EHOSTUNREACH ECONNRESET EPIPE OTHER_ERRNO".split())
ROUTES = (("CHALLENGE", "TOKEN"), ("CHALLENGE", "CHALLENGE", "TOKEN"),
          ("CHALLENGE", "TOKEN", "CHALLENGE", "TOKEN"),
          ("CHALLENGE", "CHALLENGE", "TOKEN", "CHALLENGE", "TOKEN"))
POLICIES = frozenset(("target_package", "internet_permission", "fixed_endpoint", "cleartext_loopback"))
TEARDOWN = frozenset(("client_closed", "runtime_closed", "container_closed"))
COUNTERS = ("enrollments", "families", "reports", "revisions", "receipts", "jobs")
FAILURE_CODES = frozenset("""
NETWORK_AUTH_READINESS NETWORK_BOOLEAN_FIELDS NETWORK_COUNTER_BOUND NETWORK_DISK_REQUIRED
NETWORK_DUPLICATE_FIELD NETWORK_ENROLLMENT_NOT_ACCEPTED NETWORK_FAILURE_COHERENCE NETWORK_FAILURE_STAGE
NETWORK_HTTP_STATUS NETWORK_IO_COHERENCE NETWORK_MARKER_PREEXISTING NETWORK_NATIVE_BOUND
NETWORK_NATIVE_FAILURE_MARKER NETWORK_NATIVE_FAILURE_STATUS NETWORK_NATIVE_INCOMPLETE NETWORK_NATIVE_MISSING
NETWORK_NATIVE_RECORD_MISMATCH NETWORK_POLICY_COHERENCE NETWORK_PRECHECK_COHERENCE NETWORK_PRIOR_REQUEST_FAILED
NETWORK_PROGRESS_COHERENCE NETWORK_RECORD_BOUND NETWORK_RECORD_ENUM NETWORK_RECORD_FIELDS NETWORK_RECORD_INCOMPLETE
NETWORK_RECORD_JSON NETWORK_RECORD_OWNER NETWORK_RECORD_TYPES NETWORK_REQUEST_COUNT NETWORK_REQUEST_ENUM
NETWORK_REQUEST_FIELDS NETWORK_REQUEST_SEQUENCE NETWORK_RESULT_BOUND NETWORK_REVERSE_MISMATCH NETWORK_ROUTE_DENIED
NETWORK_RUN_ID NETWORK_RUN_PATH NETWORK_SERVER_NOT_EMPTY NETWORK_SOURCE_CHANGED NETWORK_SOURCES_NOT_FROZEN
NETWORK_STATE_UNREADY NETWORK_SUCCESS_CHAIN NETWORK_SUCCESS_COHERENCE NETWORK_TEARDOWN_COHERENCE
NETWORK_VALIDATION_COHERENCE NETWORK_WINDOWS_REQUIRED NETWORK_POSTFLIGHT_FAILED
""".split())


def failure(error, stage):
    # Never retain arbitrary exception messages, class names, locals or dumps.
    value = {"stage": stage, **base.failure_metadata(error)}
    if type(error) is Error and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in FAILURE_CODES:
        value["code"] = error.args[0]
    return value


def valid_run(run):
    require(type(run) is str and re.fullmatch(r"[0-9a-f]{32}", run) is not None, "NETWORK_RUN_ID")


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "NETWORK_DUPLICATE_FIELD")
        value[key] = item
    return value


def boolean_map(value, keys):
    require(type(value) is dict and set(value) == keys and
            all(type(item) is bool for item in value.values()), "NETWORK_BOOLEAN_FIELDS")


def parse_record(raw, run):
    """Only finite schema values survive parsing; coherence is checked separately."""
    valid_run(run)
    require(type(raw) is str and raw.isascii() and 0 < len(raw) <= 2048, "NETWORK_RECORD_BOUND")
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, TypeError, RecursionError):
        raise Error("NETWORK_RECORD_JSON") from None
    require(type(value) is dict and set(value) == {"schema", "run", "completed", "enrollment_succeeded",
            "failure_kind", "failed_at", "policies", "overflow", "teardown", "requests"}, "NETWORK_RECORD_FIELDS")
    require(type(value["schema"]) is int and value["schema"] == 1 and value["run"] == run,
            "NETWORK_RECORD_OWNER")
    require(all(type(value[key]) is bool for key in ("completed", "enrollment_succeeded", "overflow")),
            "NETWORK_RECORD_TYPES")
    require(type(value["failure_kind"]) is str and value["failure_kind"] in FAILURES and
            type(value["failed_at"]) is str and value["failed_at"] in {"NONE", "PRECHECK", "AUTHENTICATE", "VALIDATION", "TEARDOWN"},
            "NETWORK_RECORD_ENUM")
    boolean_map(value["policies"], POLICIES)
    boolean_map(value["teardown"], TEARDOWN)
    rows = value["requests"]
    require(type(rows) is list and len(rows) <= 5, "NETWORK_REQUEST_COUNT")
    for index, row in enumerate(rows, 1):
        require(type(row) is dict and set(row) == {"seq", "route", "stage", "terminal", "io", "errno", "status"},
                "NETWORK_REQUEST_FIELDS")
        require(type(row["seq"]) is int and row["seq"] == index, "NETWORK_REQUEST_SEQUENCE")
        for name, allowed in (("route", {"CHALLENGE", "TOKEN", "OTHER"}), ("stage", STAGES),
                              ("terminal", {"NONE", "END", "FAIL"}), ("io", IO), ("errno", ERRNO)):
            require(type(row[name]) is str and row[name] in allowed, "NETWORK_REQUEST_ENUM")
        require(type(row["status"]) is int and (row["status"] == 0 or 100 <= row["status"] <= 599),
                "NETWORK_HTTP_STATUS")
    return value


def clean_end(row, status):
    return row["terminal"] == "END" and row["io"] == "NONE" and row["errno"] == "NONE" and row["status"] == status


def validate_record(value):
    """Reject impossible chains even when JUnit failed. No HTTP event grants auth."""
    kind, at, success = value["failure_kind"], value["failed_at"], value["enrollment_succeeded"]
    rows = value["requests"]
    route = tuple(row["route"] for row in rows)
    require(value["completed"] is True, "NETWORK_RECORD_INCOMPLETE")
    require(not value["overflow"] and any(route == whole[:len(route)] for whole in ROUTES), "NETWORK_ROUTE_DENIED")
    require((kind == "NONE") == (at == "NONE") and (success or kind != "NONE"), "NETWORK_FAILURE_COHERENCE")
    require(not success or kind == "NONE" or at in {"VALIDATION", "TEARDOWN"}, "NETWORK_FAILURE_COHERENCE")
    if at == "PRECHECK":
        require(not success and not rows and kind in {"UNAVAILABLE", "STORE", "CANCELLED", "OTHER"}, "NETWORK_PRECHECK_COHERENCE")
    if kind not in {"NONE", "OTHER"}:
        require(at == "AUTHENTICATE" or (kind in {"UNAVAILABLE", "STORE", "CANCELLED"} and at == "PRECHECK"), "NETWORK_FAILURE_STAGE")
    if at == "TEARDOWN":
        require(kind == "OTHER" and not all(value["teardown"].values()), "NETWORK_TEARDOWN_COHERENCE")
    if at == "VALIDATION":
        require(kind == "OTHER" and success, "NETWORK_VALIDATION_COHERENCE")
    if not all(value["policies"].values()):
        require(at == "PRECHECK" and kind in {"UNAVAILABLE", "OTHER"} and not rows, "NETWORK_POLICY_COHERENCE")
    for index, row in enumerate(rows):
        terminal, io, errno, status = (row[name] for name in ("terminal", "io", "errno", "status"))
        require(terminal != "FAIL" or io != "NONE", "NETWORK_IO_COHERENCE")
        require(terminal != "END" or (io == "NONE" and errno == "NONE"), "NETWORK_IO_COHERENCE")
        require(terminal != "END" or status > 0, "NETWORK_PROGRESS_COHERENCE")
        require(terminal != "NONE" or io == "NONE" or
                (not success and kind in {"OUTER_BUDGET", "CANCELLED"}), "NETWORK_IO_COHERENCE")
        require(errno == "NONE" or io != "NONE", "NETWORK_IO_COHERENCE")
        require(status == 0 or row["stage"] in {"RESPONSE_HEADERS", "RESPONSE_BODY"}, "NETWORK_PROGRESS_COHERENCE")
        require(row["stage"] != "RESPONSE_BODY" or status > 0, "NETWORK_PROGRESS_COHERENCE")
        if index < len(rows) - 1:
            require(clean_end(row, 200 if row["route"] == "CHALLENGE" else 409), "NETWORK_PRIOR_REQUEST_FAILED")
    if success:
        require(route in ROUTES and all(clean_end(row, 200 if row["route"] == "CHALLENGE" or index == len(rows) - 1 else 409)
                for index, row in enumerate(rows)), "NETWORK_SUCCESS_CHAIN")
    if kind == "NONE":
        require(success and all(value["policies"].values()) and all(value["teardown"].values()), "NETWORK_SUCCESS_COHERENCE")
    return value


def native_result(raw):
    """Exact102 method only; never adapt base allowlists or retain stack text."""
    require(type(raw) is str and len(raw.encode("utf-8")) <= 262144, "NETWORK_NATIVE_BOUND")
    expected = {"class": [TEST_CLASS], "test": [METHOD], "current": ["1"], "numtests": ["1"]}
    records, current, codes = [], {}, []
    malformed = not raw.endswith("\n")
    for line in raw.replace("\r\n", "\n").split("\n"):
        if line.startswith("INSTRUMENTATION_STATUS:") and re.fullmatch(r"INSTRUMENTATION_STATUS: [A-Za-z][A-Za-z0-9_]*=.*", line) is None:
            malformed = True
        field = re.fullmatch(r"INSTRUMENTATION_STATUS: (class|test|current|numtests)=(.*)", line)
        if field:
            malformed = malformed or bool(codes)
            current.setdefault(field[1], []).append(field[2])
        elif re.match(r"INSTRUMENTATION_STATUS: (?:class|test|current|numtests)(?:=|\s|$)", line):
            malformed = True
        if line.startswith("INSTRUMENTATION_STATUS_CODE:"):
            malformed = malformed or bool(codes)
            match = re.fullmatch(r"INSTRUMENTATION_STATUS_CODE: (-?\d{1,3})", line)
            if match:
                records.append((int(match[1]), current))
                current = {}
            else:
                malformed = True
        if line.startswith("INSTRUMENTATION_CODE:"):
            malformed = malformed or len(records) != 2
            match = re.fullmatch(r"INSTRUMENTATION_CODE: (-?\d{1,3})", line)
            if match:
                codes.append(int(match[1]))
            else:
                malformed = True
    exact = not malformed and not current and len(records) == 2 and all(fields == expected for _, fields in records)
    statuses = [code for code, _ in records]
    complete = exact and statuses[0] == 1 and statuses[1] in {0, -1, -2, -3, -4} and codes == [-1]
    marker_lines = [line for line in raw.replace("\r\n", "\n").split("\n") if "ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED" in line]
    failed_marker = bool(marker_lines) and all(re.fullmatch(
        r"(?:INSTRUMENTATION_STATUS: stack=)?java\.lang\.AssertionError: ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED", line)
        for line in marker_lines)
    exceptions = re.search(r"^(?:INSTRUMENTATION_STATUS: stack=)?(?:[A-Za-z_$][A-Za-z0-9_$]*\.){1,12}[A-Za-z_$][A-Za-z0-9_$]*(?:Error|Exception|Failure)(?::|\s*$)", raw, re.MULTILINE) is not None
    passed = complete and statuses == [1, 0] and len(re.findall(r"^OK \(1 test\)\s*$", raw, re.MULTILINE)) == 1 and not marker_lines and not exceptions and not any(item in raw for item in ("FAILURES", "INSTRUMENTATION_FAILED", "shortMsg="))
    return {"passed": passed, "outcome": "passed" if passed else "failed" if complete else "incomplete",
            "method_completed_count": int(complete), "status_codes": statuses[:4], "instrumentation_codes": codes[:4],
            "failure_marker_present": failed_marker}


def validate_native_record(native, value):
    require(native["method_completed_count"] == 1 and native["outcome"] != "incomplete", "NETWORK_NATIVE_INCOMPLETE")
    clean = value["enrollment_succeeded"] and value["failure_kind"] == "NONE"
    require(native["passed"] == clean, "NETWORK_NATIVE_RECORD_MISMATCH")
    require(native["passed"] or native["failure_marker_present"], "NETWORK_NATIVE_FAILURE_MARKER")
    require(native["passed"] or native["status_codes"] in ([1, -1], [1, -2]), "NETWORK_NATIVE_FAILURE_STATUS")


class RunOwnership(RunLease):
    def __init__(self, run):
        self.run = base.checked_path(run)
        require(self.run.parent == ROOT / ".cache/m1-runtime/mobile-network" and
                re.fullmatch(r"[0-9a-f]{24}", self.run.name) is not None, "NETWORK_RUN_PATH")
        self.file = None


class CombinedOwnership:
    def __init__(self, lease, harness):
        self.lease, self.harness = lease, harness

    def assert_owned(self):
        self.lease.assert_owned()
        self.harness.assert_owned()


class NetworkEmulator(base.OwnedEmulator):
    def marker_absent(self):
        script = "set -eu\n"
        for suffix in ("", ".new", ".bak"):
            script += f"test ! -e {MARKER}{suffix}\ntest ! -L {MARKER}{suffix}\n"
        script += "printf absent\n"
        require(self.command("shell", "run-as", base.PACKAGE, "--user", "0", "sh", stdin=script.encode("ascii"),
                             timeout=5, maximum=64) == "absent", "NETWORK_MARKER_PREEXISTING")

    def read_record(self):
        script = f"set -eu\ntest -f {MARKER}\ntest ! -L {MARKER}\n"
        for suffix in (".new", ".bak"):
            script += f"test ! -e {MARKER}{suffix}\ntest ! -L {MARKER}{suffix}\n"
        script += f"head -c 2049 {MARKER}\n"
        return self.command("shell", "run-as", base.PACKAGE, "--user", "0", "sh",
                            stdin=script.encode("ascii"), timeout=5, maximum=2049)

    def invoke(self, run):
        valid_run(run)
        return native_result(self.command("shell", "am", "instrument", "-w", "-r", "-e", "class", TEST_CLASS + "#" + METHOD,
            "-e", "ownedEmulator", "true", "-e", "diagnosticRun", run,
            base.TEST_PACKAGE + "/" + base.RUNNER, timeout=180))


def observe_health(emulator, owner, evidence):
    """No repair. Partial fixed observations survive a later failed observation."""
    owner.assert_owned()
    evidence["held_api_and_listener_owned"] = True
    mapping = base.parse_reverse(emulator.command("reverse", "--list", timeout=5, maximum=4096))
    evidence["reverse_count"] = len(mapping)
    evidence["reverse_exact"] = mapping == {base.ENDPOINT: base.ENDPOINT}
    require(evidence["reverse_exact"], "NETWORK_REVERSE_MISMATCH")
    client = base.integration.Client(owner)
    state_status, state = client.request(base.integration.STATE_PATH)
    evidence["state_status"] = state_status if type(state_status) is int and 100 <= state_status <= 599 else 0
    evidence["normal_mode"] = type(state) is dict and state.get("mode") == "normal"
    require(state_status == 200 and evidence["normal_mode"], "NETWORK_STATE_UNREADY")
    me_status, _ = client.request("/api/v1/mobile/me/")
    evidence["me_status"] = me_status if type(me_status) is int and 100 <= me_status <= 599 else 0
    require(me_status == 401, "NETWORK_AUTH_READINESS")
    owner.assert_owned()
    evidence["complete"] = True


def observe_counts(owner):
    owner.assert_owned()
    from apps.accounts.models import DeviceEnrollment, DeviceFamily
    from apps.reports.models import Report, ReportRevision
    from apps.operations.models import SyncReceipt, ProcessingJob
    values = {}
    for name, model in zip(COUNTERS, (DeviceEnrollment, DeviceFamily, Report, ReportRevision, SyncReceipt, ProcessingJob)):
        owner.assert_owned()
        count = model.objects.count()
        require(type(count) is int and 0 <= count <= 100000, "NETWORK_COUNTER_BOUND")
        values[name] = count
    owner.assert_owned()
    return values


def expected_counts(enrolled):
    return {key: int(enrolled) if key in {"enrollments", "families"} else 0 for key in COUNTERS}


def run_diagnostic(emulator, owner, run, evidence):
    evidence.update(native_invocations=0, diagnostic_collected=False, enrollment_accepted=False)
    emulator.marker_absent()
    evidence["before"] = {}
    evidence["stage"] = "before_health"
    observe_health(emulator, owner, evidence["before"])
    evidence["before_counts"] = observe_counts(owner)
    require(evidence["before_counts"] == expected_counts(False), "NETWORK_SERVER_NOT_EMPTY")
    evidence["stage"] = "native_invocation"
    evidence["native_invocations"] = 1
    try:
        evidence["native"] = emulator.invoke(run)
    except BaseException as error:
        evidence["native_invocation_failure"] = failure(error, "native_invocation")
    # Preserve the original native outcome if any independent observation fails.
    for stage, action in (
        ("record", lambda: parse_record(emulator.read_record(), run)),
        ("after_health", lambda: observe_health(emulator, owner, evidence.setdefault("after", {}))),
        ("after_counts", lambda: observe_counts(owner)),
    ):
        evidence["stage"] = stage
        try:
            owner.assert_owned()
            value = action()
            if stage != "after_health":
                evidence[stage] = value
        except BaseException as error:
            evidence[stage + "_failure"] = failure(error, stage)
    if "record" in evidence:
        try:
            validate_record(evidence["record"])
            require("native" in evidence, "NETWORK_NATIVE_MISSING")
            validate_native_record(evidence["native"], evidence["record"])
            evidence["diagnostic_collected"] = True
        except BaseException as error:
            evidence["record_validation_failure"] = failure(error, "record_validation")
    evidence["enrollment_accepted"] = (evidence["diagnostic_collected"] and evidence["native"]["passed"] and
        evidence.get("after", {}).get("complete") is True and not any(key.endswith("_failure") for key in evidence) and
        evidence.get("after_counts") == expected_counts(True))
    # Failed native method remains a failed invocation, even with useful evidence.
    require(evidence["enrollment_accepted"], "NETWORK_ENROLLMENT_NOT_ACCEPTED")


def verify_sources():
    require(all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in FROZEN.values()),
            "NETWORK_SOURCES_NOT_FROZEN")
    observed = {name: base.digest(ROOT / name) for name in FROZEN}
    require(observed == FROZEN, "NETWORK_SOURCE_CHANGED")
    return observed


def unchanged(sources):
    try:
        return all(base.digest(ROOT / name) == value for name, value in sources.items())
    except (OSError, Error):
        return False


def final_guards(evidence, sources, own_sources, artifacts, hashes):
    evidence["sources_unchanged"] = unchanged(sources)
    evidence["own_sources_unchanged"] = unchanged(own_sources)
    try:
        evidence["artifacts_unchanged"] = all(base.digest(path) == expected for path, expected in zip(artifacts, hashes))
    except (OSError, Error):
        evidence["artifacts_unchanged"] = False
    evidence["cleanup_verified"] = (evidence.get("database_cleanup_passed") is True and
        evidence.get("emulator", {}).get("owned_emulator_stopped") is True and
        evidence.get("emulator", {}).get("owned_emulator_ports_closed") is True)
    if not all(evidence[key] for key in ("sources_unchanged", "own_sources_unchanged", "artifacts_unchanged", "cleanup_verified")):
        evidence["ok"] = False


def execute(app, app_hash, test, test_hash):
    require(os.name == "nt", "NETWORK_WINDOWS_REQUIRED")
    sources = verify_sources()
    require(shutil.disk_usage(ROOT).free >= 12 * 1024**3, "NETWORK_DISK_REQUIRED")
    own_sources = {name: base.digest(ROOT / name) for name in OWN_SOURCES}
    tools = base.AndroidTools()
    artifacts, proof = base.verify_artifacts(tools, app, app_hash, test, test_hash)
    parent = base.checked_path(ROOT / ".cache/m1-runtime/mobile-network")
    parent.mkdir(parents=True, exist_ok=True)
    run, nonce = base.checked_path(parent / secrets.token_hex(12)), secrets.token_hex(16)
    evidence = {"task": "TASK-103", "ok": False, "run": nonce, "physical_phone": False,
                "sources": sources, "own_sources": own_sources, "artifacts": proof, "method": METHOD, "stage": "preflight"}
    with RunOwnership(run) as lease:
        print(json.dumps({"task": "TASK-103", "run": run.name, "stage": "starting"}), flush=True)
        try:
            with base.observed_harness(evidence) as harness:
                owner = CombinedOwnership(lease, harness)
                emulator = NetworkEmulator(tools, owner, run)
                try:
                    evidence["stage"] = "emulator_boot"
                    with emulator:
                        evidence["stage"] = "emulator_install"
                        emulator.install(artifacts, (app_hash, test_hash))
                        evidence["stage"] = "emulator_unlock"
                        emulator.unlock()
                        run_diagnostic(emulator, owner, nonce, evidence)
                finally:
                    evidence["emulator"] = emulator.evidence
            evidence["ok"] = True
        except BaseException as error:
            evidence["failure"] = failure(error, evidence["stage"])
            raise
        finally:
            final_guards(evidence, sources, own_sources, artifacts, (app_hash, test_hash))
            lease.assert_owned()
            encoded = json.dumps(evidence, indent=2) + "\n"
            require(len(encoded.encode("utf-8")) <= 32768, "NETWORK_RESULT_BOUND")
            with base.checked_path(run / "result.json").open("x", encoding="utf-8") as output:
                output.write(encoded)
            print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    require(evidence["ok"], "NETWORK_POSTFLIGHT_FAILED")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "app-sha256", "test", "test-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        if Path(sys.executable).resolve() != Path(base.integration.local.python_path()).resolve():
            return subprocess.run([base.integration.local.python_path(), str(Path(__file__).resolve()), *sys.argv[1:]],
                                  cwd=ROOT, env=base.integration.local.managed_environment(), check=False).returncode
        execute(args.app, args.app_sha256, args.test, args.test_sha256)
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "failure": failure(error, "terminal")}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
