"""TASK098: genuine MainActivity Slice A; root review precedes any execution.

Only a new owned emulator and isolated service database are eligible. The host
never authenticates the app, submits source, changes product rows or runs UI
controller commands. Private source/identities remain in bounded memory.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_emulator as base
from infra import mobile_platform as platform
from infra.mobile_accessibility import RunLease

require, Error = base.require, base.EmulatorError
TEST_CLASS = "org.kapit.c2.mobile.sync.MobileLiveUiIntegrationTest"
METHOD = "actualUiEnrollmentOfflineQueueAndReceipt"
NATIVE_SOURCE = "android/app/src/androidTest/java/org/kapit/c2/mobile/sync/MobileLiveUiIntegrationTest.kt"
PHASE_PATH = "no_backup/m2-ui-native-phase"
ACK_PATH = "no_backup/m2-ui-host-ack"
STEPS = (
    ("starting", "ready"), ("enrollment_prompt", "credential_returned"),
    ("enrolled", "offline"), ("offline_checked", "offline_verified"),
    ("draft_saved", "draft_checked"), ("reopen_prompt", "credential_returned"),
    ("draft_reopened", "draft_checked"), ("queue_cancelled", "no_effects"),
    ("initial_queued", "queued_checked"), ("offline_attempted", "reconnected"),
    ("receipt_observed", "server_received"), ("reports_verified", "server_verified"),
    ("completed", "finished"),
)
# Fixed native stage names (MobileLiveUiIntegrationTest `stage`); only these may enter evidence.
NATIVE_STAGES = frozenset({"preflight", "account_sign_in", "offline_read", "draft_create", "draft_edit",
                           "activity_recreation", "queue_cancel", "queue_commit", "offline_sync",
                           "online_delivery", "duplicate_sync", "reports_read"} | {step[0] for step in STEPS})
# Frozen only after the separately owned parser repair and native review.
FROZEN = {
    "infra/mobile_emulator.py": "b5a67fba453052b9ed6e68b9dd5baecee8778a576a958ef1a973ced954e3eb56",
    "infra/mobile_platform.py": "19f73ec9d5aad6c41f9649c48ce41e052ed8de92c3bd0935acadb49e022c99bc",
    "infra/mobile_integration.py": "8aa5c44ffe8e60b277a7496fc4d9557f624a868386c672fc9d77d5182faf03ab",
    "infra/mobile_accessibility.py": "16384672e40e91d4bda0cd159eb1682a46e4a1062e5cf5a1e8dd51e82d34664a",
    "infra/mobile_device.py": "8df9b50002f5fc65a97e5624e35f7ea8be39acbdd4c48b79714d8997aa933012",
    "android/tools/owned_process.py": "bee293c26831a964a8b88fba75570c6bd2cacb1887ffc2e5435a5af967ed8257",
    NATIVE_SOURCE: "b8c85c8025d4b6645a14a7cab8d3352f823beb07c0948e55c293dd1b61a8ac5c",
}
EXPECTED_EDITED = {
    "category": "WATER_SUPPLY", "urgency": "ROUTINE", "area_label": "Area A",
    "site_label": "Synthetic edited UI water station", "reporter_label": "Synthetic edited UI reporter",
    "narrative": "PRIVATE_M2_UI_EDITED_NARRATIVE: fictional water pump needs repair.",
    "assistance_requested": "Repair assistance",
}


def fail_metadata(error, stage):
    value = base.failure_metadata(error)
    own = []
    trace = error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        if Path(trace.tb_frame.f_code.co_filename).resolve() == Path(__file__).resolve():
            own.append({"source": "infra/mobile_live_ui.py", "line": trace.tb_lineno})
        trace = trace.tb_next
    return {"stage": stage, **value, "owned_source_lines": (value["owned_source_lines"] + own)[-6:]}


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "LIVE_UI_DUPLICATE_FIELD")
        value[key] = item
    return value


def marker(raw, run, *, ack=False):
    require(re.fullmatch(r"[0-9a-f]{32}", run or "") is not None, "LIVE_UI_RUN_ID")
    require(isinstance(raw, str) and raw.isascii() and 0 < len(raw) <= 256,
            "LIVE_UI_MARKER_BOUND")
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, TypeError):
        raise Error("LIVE_UI_MARKER_FORMAT") from None
    field = "ack" if ack else "phase"
    require(isinstance(value, dict) and set(value) == {"schema", "run", "seq", field}, "LIVE_UI_MARKER_FIELDS")
    require(type(value["schema"]) is int and value["schema"] == 1 and value["run"] == run,
            "LIVE_UI_MARKER_OWNER")
    number = value["seq"]
    require(type(number) is int and 1 <= number <= len(STEPS), "LIVE_UI_MARKER_SEQUENCE")
    require(value[field] == STEPS[number - 1][int(ack)], "LIVE_UI_MARKER_PHASE")
    return number


def ack_bytes(run, number):
    require(type(number) is int and 1 <= number <= len(STEPS), "LIVE_UI_MARKER_SEQUENCE")
    raw = json.dumps({"schema": 1, "run": run, "seq": number, "ack": STEPS[number - 1][1]},
                     separators=(",", ":"))
    marker(raw, run, ack=True)
    return raw.encode("ascii")


def expected_record():
    return {"class": [TEST_CLASS], "test": [METHOD], "current": ["1"], "numtests": ["1"]}


def native_failure_stage(raw):
    """Return only a known native stage named by MOBILE_LIVE_UI_FAILED_<stage>; nothing else from the output."""
    names = set(re.findall(r"MOBILE_LIVE_UI_FAILED_([a-z_]{1,40})(?![A-Za-z0-9_])", raw or ""))
    return names.pop() if len(names) == 1 and names <= NATIVE_STAGES else "UNKNOWN"


def native_started(raw):
    # A partial final line is not a complete status record.
    pending_tail = bool(raw) and not raw.endswith("\n")
    complete = raw if raw.endswith("\n") else raw[:raw.rfind("\n") + 1]
    require(not any(token in complete for token in ("FAILURES", "stack=", "INSTRUMENTATION_FAILED", "shortMsg=", "OK (")),
            "LIVE_UI_NATIVE_FAILED")
    require(not platform.standalone_exception(complete), "LIVE_UI_NATIVE_FAILED")
    require(not re.search(r"^INSTRUMENTATION_(?:CODE|RESULT):", complete, re.MULTILINE), "LIVE_UI_NATIVE_PREMATURE_END")
    observed, pending = platform.records(complete)
    require(not observed or observed == [(1, expected_record())], "LIVE_UI_NATIVE_START_IDENTITY")
    if observed:
        require(not pending, "LIVE_UI_NATIVE_EXTRA_RECORD")
    return bool(observed) and not pending_tail


def native_result(raw, exit_code):
    require(raw.endswith("\n") and "\ufffd" not in raw and exit_code == 0, "LIVE_UI_NATIVE_TERMINAL")
    records, pending = platform.records(raw)
    require(records == [(1, expected_record()), (0, expected_record())] and not pending,
            "LIVE_UI_NATIVE_FINAL_IDENTITY")
    # Preserve every terminal/error byte while adapting only exact checked names
    # to the accepted success parser. Do not retain exception names or raw output.
    mapped = [f"INSTRUMENTATION_STATUS: class={base.TEST_CLASS}" if line == f"INSTRUMENTATION_STATUS: class={TEST_CLASS}"
              else f"INSTRUMENTATION_STATUS: test={base.PHASES[0][0]}" if line == f"INSTRUMENTATION_STATUS: test={METHOD}"
              else line for line in raw.splitlines()]
    outcome = base.instrumentation_result("\n".join(mapped) + "\n", base.PHASES[0][0])
    require(outcome["passed"] and outcome["method_completed_count"] == 1, "LIVE_UI_NATIVE_FAILED")
    return {"passed": True, "method_completed_count": 1, "status_codes": [1, 0], "instrumentation_codes": [-1]}


class RunOwnership(RunLease):
    def __init__(self, run):
        self.run = base.checked_path(run)
        require(self.run.parent == ROOT / ".cache/m1-runtime/mobile-live-ui" and
                re.fullmatch(r"[0-9a-f]{24}", self.run.name), "LIVE_UI_RUN_PATH")
        self.file = None


class CombinedOwnership:
    def __init__(self, lease, harness):
        self.lease, self.harness = lease, harness

    def assert_owned(self):
        self.lease.assert_owned()
        self.harness.assert_owned()


class UiEmulator(platform.GuardedEmulator):
    def markers_absent(self):
        script = "set -eu\n"
        for path in (PHASE_PATH, ACK_PATH):
            for suffix in ("", ".new", ".bak", ".host-tmp"):
                script += f"test ! -e {path}{suffix}\ntest ! -L {path}{suffix}\n"
        script += "printf absent\n"
        require(self.command("shell", "run-as", base.PACKAGE, "--user", "0", "sh", stdin=script.encode("ascii"),
                             timeout=5, maximum=64) == "absent", "LIVE_UI_MARKER_PREEXISTING")

    def read_phase(self):
        script = (f"set -eu\ntest ! -L {PHASE_PATH}\n"
                  f"if [ -f {PHASE_PATH} ]; then head -c 257 {PHASE_PATH}; else printf absent; fi\n")
        return self.command("shell", "run-as", base.PACKAGE, "--user", "0", "sh",
                            stdin=script.encode("ascii"), timeout=5, maximum=257)

    def acknowledge(self, run, number):
        value = ack_bytes(run, number).decode("ascii")
        previous = (f"test ! -e {ACK_PATH}\n" if number == 1 else
                    f"test \"$(cat {ACK_PATH})\" = '{ack_bytes(run, number - 1).decode('ascii')}'\n")
        # Exact safe JSON values are validated before entering this fixed script.
        script = (f"set -eu\ntest ! -L {ACK_PATH}\n{previous}test ! -e {ACK_PATH}.host-tmp\n"
                  f"test ! -L {ACK_PATH}.host-tmp\numask 077\nprintf '%s' '{value}' > {ACK_PATH}.host-tmp\n"
                  f"mv {ACK_PATH}.host-tmp {ACK_PATH}\nprintf acknowledged\n")
        require(self.command("shell", "run-as", base.PACKAGE, "--user", "0", "sh",
                             stdin=script.encode("ascii"), timeout=5, maximum=64) == "acknowledged",
                "LIVE_UI_ACK_WRITE")

    def mapping(self):
        return base.parse_reverse(self.command("reverse", "--list"))

    def disconnect(self):
        before = self.mapping()
        require(before.get(base.ENDPOINT) == base.ENDPOINT, "LIVE_UI_REVERSE_OWNER")
        self.command("reverse", "--remove", base.ENDPOINT, timeout=5)
        require(self.mapping() == {key: value for key, value in before.items() if key != base.ENDPOINT},
                "LIVE_UI_REVERSE_REMOVAL")

    def reconnect(self):
        before = self.mapping()
        require(base.ENDPOINT not in before, "LIVE_UI_REVERSE_PREEXISTING")
        self.command("reverse", "--no-rebind", base.ENDPOINT, base.ENDPOINT, timeout=5)
        require(self.mapping() == {**before, base.ENDPOINT: base.ENDPOINT}, "LIVE_UI_REVERSE_RESTORE")

    def offline(self):
        require(base.ENDPOINT not in self.mapping(), "LIVE_UI_REVERSE_NOT_OFFLINE")

    def send_pin(self):
        # Initial device unlock has no instrumentation. During the UI journey,
        # recheck stream readiness after the actual credential-window probe and
        # immediately before the inherited bounded PIN command.
        watch = getattr(self, "_credential_watch", None)
        if watch is not None:
            require(watch() is True, "LIVE_UI_NATIVE_NOT_READY")
        return super().send_pin()

    def credential_return(self, watch, deadline):
        require(watch() is True, "LIVE_UI_NATIVE_NOT_READY")
        self._credential_watch = watch
        try:
            self.credential_action("pin")  # Exact Settings component/UID gate, else the TASK-117 SystemUI rule; then stream recheck before PIN.
        finally:
            self._credential_watch = None
        while time.monotonic() < deadline:
            require(watch() is True, "LIVE_UI_NATIVE_NOT_READY")
            raw = self.command(*base.WINDOW_SNAPSHOT, timeout=5)
            title, uid = platform.focus_window(raw)
            app_uid = platform.package_uid(self.command("shell", "pm", "list", "packages", "-U", "--user", "0", timeout=5))
            if title == platform.MAIN and uid == app_uid:
                require(base.device_unlocked(self.command("shell", "dumpsys", "trust", timeout=5)), "LIVE_UI_CREDENTIAL_RETURN")
                require(watch() is True, "LIVE_UI_NATIVE_NOT_READY")
                return
            time.sleep(0.1)
        raise Error("LIVE_UI_CREDENTIAL_TIMEOUT")


class Invocation:
    """Own one streaming adb client; 360s applies to this new test only.

    Output stays bounded in memory. The existing 180s helper remains unchanged.
    Remote instrumentation is always contained by the outer owned emulator.
    """
    def __init__(self, emulator, run, overall_deadline, clock=time.monotonic):
        self.emulator, self.run, self.clock = emulator, run, clock
        self.deadline = min(overall_deadline, clock() + 360)
        self.child, self.threads = None, []
        self.closed = False
        self.entry_evidence = {}

    def __enter__(self):
        require(re.fullmatch(r"[0-9a-f]{32}", self.run), "LIVE_UI_RUN_ID")
        self.emulator.identity()
        self.child = subprocess.Popen([str(self.emulator.tools.adb), "-t", self.emulator.target["transport"],
            "shell", "am", "instrument", "-w", "-r", "-e", "class", TEST_CLASS + "#" + METHOD,
            "-e", "ownedEmulator", "true", "-e", "runId", self.run, f"{base.TEST_PACKAGE}/{base.RUNNER}"],
            cwd=ROOT, env=base.safe_environment(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            self.output = platform.StreamingOutput(self.child.stdout, 262144)
            self.errors = platform.StreamingOutput(self.child.stderr, 16384, retain=False)
            for reader in (self.output, self.errors):
                thread = threading.Thread(target=reader.read, daemon=True)
                self.threads.append(thread)
                thread.start()
            return self
        except BaseException as error:
            self.entry_evidence["native_body_failure"] = fail_metadata(error, "native_start")
            self.entry_evidence["native_client_cleanup_attempted"] = True
            try:
                self.__exit__(*sys.exc_info())
                self.entry_evidence["native_client_cleanup_passed"] = True
            except BaseException as cleanup_error:
                self.entry_evidence["native_client_cleanup_passed"] = False
                self.entry_evidence["native_cleanup_failure"] = fail_metadata(cleanup_error, "native_start")
                raise
            raise

    def raw(self, final=False):
        require(not self.output.failed and not self.errors.failed, "LIVE_UI_OUTPUT_BOUND")
        data = bytes(self.output.data)
        self.pending_tail = bool(data) and not data.endswith(b"\n")
        # Do not mistake an incomplete UTF-8 character/line for a terminal error.
        if not final:
            data = data[:data.rfind(b"\n") + 1]
        try:
            return data.decode("utf-8", errors="strict").replace("\r\n", "\n")
        except UnicodeError:
            raise Error("LIVE_UI_OUTPUT_ENCODING") from None

    def watch(self):
        require(self.clock() < self.deadline, "LIVE_UI_OVERALL_DEADLINE")
        require(self.child.poll() is None, "LIVE_UI_NATIVE_EARLY_EXIT")
        started = native_started(self.raw())
        return started and not self.pending_tail

    def finish(self):
        while self.child.poll() is None:
            require(self.clock() < self.deadline, "LIVE_UI_OVERALL_DEADLINE")
            self.raw()
            time.sleep(0.1)
        for thread in self.threads:
            thread.join(timeout=2)
        require(not any(thread.is_alive() for thread in self.threads), "LIVE_UI_OUTPUT_INCOMPLETE")
        return native_result(self.raw(final=True), self.child.returncode)

    def __exit__(self, *args):
        if self.closed:
            return
        self.closed = True
        try:
            if self.child is not None and self.child.poll() is None:
                self.child.kill()
                self.child.wait(timeout=5)
            for thread in self.threads:
                thread.join(timeout=2)
            require(self.child is None or self.child.poll() is not None, "LIVE_UI_CLIENT_CLEANUP")
            require(not any(thread.is_alive() for thread in self.threads), "LIVE_UI_CLIENT_CLEANUP")
        except BaseException:
            raise Error("LIVE_UI_CLIENT_CLEANUP") from None


@contextmanager
def observed_invocation(invocation, evidence):
    entered = False
    try:
        invocation.__enter__()
        entered = True
        yield invocation
    except BaseException as error:
        entry = getattr(invocation, "entry_evidence", None)
        if not entered and isinstance(entry, dict) and "native_body_failure" in entry:
            evidence.update(entry)
        else:
            evidence["native_body_failure"] = fail_metadata(error, evidence["stage"])
            if str(error) == "LIVE_UI_NATIVE_FAILED":
                try:
                    evidence["native_failure_stage"] = native_failure_stage(invocation.raw(final=True))
                except Exception:
                    evidence["native_failure_stage"] = "UNAVAILABLE"
        raise
    finally:
        if entered:
            evidence["native_client_cleanup_attempted"] = True
            try:
                invocation.__exit__(*sys.exc_info())
                evidence["native_client_cleanup_passed"] = True
            except BaseException as error:
                evidence["native_client_cleanup_passed"] = False
                evidence["native_cleanup_failure"] = fail_metadata(error, evidence["stage"])
                raise


def payload_check(payload, observed_at, content_digest, started, now, digest):
    require(set(EXPECTED_EDITED) == {"category", "urgency", "area_label", "site_label", "reporter_label", "narrative", "assistance_requested"},
            "LIVE_UI_EXPECTED_CONTENT_UNREVIEWED")
    require(isinstance(payload, dict) and set(payload) == set(EXPECTED_EDITED) | {"observed_at"}, "LIVE_UI_SERVER_PAYLOAD")
    require(all(payload[key] == value for key, value in EXPECTED_EDITED.items()), "LIVE_UI_SERVER_PAYLOAD")
    timestamp = payload["observed_at"]
    require(isinstance(timestamp, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", timestamp), "LIVE_UI_SERVER_TIME")
    try:
        parsed = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Error("LIVE_UI_SERVER_TIME") from None
    require(parsed == observed_at and started - timedelta(seconds=5) <= parsed <= now + timedelta(seconds=5),
            "LIVE_UI_SERVER_TIME")
    require(digest(payload) == content_digest, "LIVE_UI_SERVER_PAYLOAD_DIGEST")


class ServerProof:
    def __init__(self, harness):
        self.harness = harness
        self.started = datetime.now(timezone.utc)
        self.enrollment = None
        self.accepted = None

    def inspect(self, enrolled, effects, done=False):
        self.harness.assert_owned()
        from apps.accounts.models import User, DeviceEnrollment
        from apps.operations.models import ProcessingJob, SyncReceipt
        from apps.publications.models import Publication
        from apps.review.models import ReviewDecision
        from apps.reports.models import Report, ReportRevision
        from apps.reports.crypto import source_payload, digest
        from apps.reports.services import receipt_body
        from apps.scopes.models import UnitMembership
        counts = {"enrollments": DeviceEnrollment.objects.count(), "reports": Report.objects.count(),
                  "revisions": ReportRevision.objects.count(), "receipts": SyncReceipt.objects.count(),
                  "jobs": ProcessingJob.objects.count(), "jobs_done": ProcessingJob.objects.filter(status="DONE").count(),
                  "decisions": ReviewDecision.objects.count(), "publications": Publication.objects.count()}
        require({k: v for k, v in counts.items() if k != "jobs_done"} == {
            "enrollments": int(enrolled), "reports": effects, "revisions": effects, "receipts": effects,
            "jobs": effects, "decisions": 0, "publications": 0}, "LIVE_UI_SERVER_COUNTS")
        require(0 <= counts["jobs_done"] <= effects and (not done or counts["jobs_done"] == effects), "LIVE_UI_SERVER_PROCESSING")
        if not enrolled:
            return counts
        actor = User.objects.select_related("organization").get(username="submitter")
        require(actor.is_active and actor.role == "submitter" and actor.organization.active and
                actor.organization.code == "SIM-ORG-01", "LIVE_UI_SERVER_ACTOR")
        membership = UnitMembership.objects.select_related("unit").get(user=actor, role="submitter", active=True)
        require(membership.organization_id == actor.organization_id and membership.valid_until is None and
                membership.unit.active and membership.unit.code == "SIM-UNIT-01" and
                membership.unit.organization_id == actor.organization_id, "LIVE_UI_SERVER_ACTOR")
        enrollment = DeviceEnrollment.objects.get()
        require(enrollment.owner_id == actor.id and enrollment.organization_id == actor.organization_id and
                enrollment.revoked_at is None, "LIVE_UI_SERVER_ENROLLMENT")
        if self.enrollment is None:
            self.enrollment = enrollment.id
        require(enrollment.id == self.enrollment, "LIVE_UI_SERVER_ENROLLMENT_CHANGED")
        if effects:
            revision = ReportRevision.objects.select_related("report").get()
            receipt, job = SyncReceipt.objects.get(), ProcessingJob.objects.get()
            require(revision.organization_id == revision.report.organization_id == receipt.organization_id == job.organization_id == actor.organization_id and
                    revision.submitted_by_id == revision.report.author_id == receipt.accepted_user_id == actor.id and
                    revision.accepted_device_id == receipt.accepted_device_id == enrollment.id and
                    revision.report.unit_id == membership.unit_id and revision.revision_no == revision.report.current_revision_no == 1 and
                    revision.template_version == "demo-maintenance-v1" and receipt.revision_id == job.revision_id == revision.id and
                    receipt.operation_id == revision.operation_id and receipt.request_hash == revision.request_hash and
                    receipt.response_body == receipt_body(revision), "LIVE_UI_SERVER_BINDING")
            require(job.status in {"PENDING", "PROCESSING", "DONE"} and
                    (not done or job.status == "DONE" and revision.processing_state == "AWAITING_REVIEW"), "LIVE_UI_SERVER_PROCESSING")
            payload = source_payload(revision)
            payload_check(payload, revision.observed_at, revision.content_digest, self.started, datetime.now(timezone.utc), digest)
            body = {"operation_id": str(revision.operation_id), "report_id": str(revision.report_id),
                    "expected_revision": 0, "template_version": revision.template_version, "payload": payload}
            require(digest({"route": "POST /sync/operations/", "body": body}) == revision.request_hash, "LIVE_UI_SERVER_REQUEST_HASH")
            identity = (revision.id, revision.report_id, revision.operation_id, revision.request_hash, revision.content_digest,
                        receipt.id, job.id, revision.accepted_device_id)
            require(self.accepted is None or self.accepted == identity, "LIVE_UI_SERVER_ACCEPTANCE_CHANGED")
            self.accepted = identity
        return counts


class Protocol:
    def __init__(self, emulator, proof, invocation, run, evidence, clock=time.monotonic, sleep=time.sleep):
        self.emulator, self.proof, self.invocation, self.run = emulator, proof, invocation, run
        self.evidence, self.clock, self.sleep = evidence, clock, sleep
        self.sequence = 0
        self.deadline = min(invocation.deadline, clock() + 30)

    def watch(self):
        require(self.clock() < self.deadline, "LIVE_UI_PHASE_DEADLINE")
        return self.invocation.watch()

    def require_ready(self):
        require(self.watch() is True, "LIVE_UI_NATIVE_NOT_READY")
        return True

    def act(self, number):
        self.require_ready()
        if number in {2, 6}:
            self.emulator.credential_return(self.require_ready, min(self.deadline, self.clock() + 60))
        if number == 3:
            self.proof.inspect(True, 0)
            self.require_ready()
            self.emulator.disconnect()
        elif 4 <= number <= 10:
            self.emulator.offline()
        counts = self.proof.inspect(number >= 3, int(number >= 11))
        if number >= 11:
            while counts["jobs_done"] != 1:
                self.require_ready()
                self.sleep(0.1)
                counts = self.proof.inspect(True, 1)
            counts = self.proof.inspect(True, 1, done=True)
        if number == 10:
            self.require_ready()
            self.emulator.reconnect()
        if number >= 11:
            require(self.emulator.mapping().get(base.ENDPOINT) == base.ENDPOINT, "LIVE_UI_REVERSE_OWNER")
        self.require_ready()
        return counts

    def tick(self):
        if not self.watch():
            return False
        raw = self.emulator.read_phase()
        if raw == "absent":
            require(self.sequence == 0, "LIVE_UI_PHASE_DISAPPEARED")
            return False
        number = marker(raw, self.run)
        if number == self.sequence:
            return False  # Identical polling observation; action/ack never repeats.
        require(number == self.sequence + 1, "LIVE_UI_PHASE_ORDER")
        self.evidence["stage"] = STEPS[number - 1][0]
        counts = self.act(number)
        self.require_ready()
        self.emulator.acknowledge(self.run, number)
        self.sequence = number
        self.evidence["phases"].append({"sequence": number, "phase": STEPS[number - 1][0],
                                       "ack": STEPS[number - 1][1], "server_counts": counts})
        # Time for the next UI action is fixed in advance, bounded by one method deadline.
        next_bound = 90 if number in {4, 7, 10, 11} else 60
        self.deadline = min(self.invocation.deadline, self.clock() + next_bound)
        return number == len(STEPS)

    def run_all(self):
        while not self.tick():
            self.sleep(0.2)
        result = self.invocation.finish()
        require(marker(self.emulator.read_phase(), self.run) == len(STEPS), "LIVE_UI_FINAL_MARKER")
        self.proof.inspect(True, 1, done=True)
        return result


def verify_sources():
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in FROZEN.values()),
            "LIVE_UI_SOURCES_NOT_FROZEN")
    observed = {name: base.digest(ROOT / name) for name in FROZEN}
    require(observed == FROZEN, "LIVE_UI_SOURCE_CHANGED")
    return observed


def sources_unchanged(expected):
    try:
        return all(base.digest(ROOT / name) == value for name, value in expected.items())
    except (OSError, Error):
        return False


def execute(app, app_hash, test, test_hash):
    require(os.name == "nt", "LIVE_UI_WINDOWS_REQUIRED")
    overall_deadline = time.monotonic() + 900
    sources = verify_sources()
    require(shutil.disk_usage(ROOT).free >= 12 * 1024**3, "LIVE_UI_DISK_REQUIRED")
    own_sources = {name: base.digest(ROOT / name) for name in ("infra/mobile_live_ui.py", "infra/test_mobile_live_ui.py")}
    tools = base.AndroidTools()
    artifacts, proof = base.verify_artifacts(tools, app, app_hash, test, test_hash)
    parent = base.checked_path(ROOT / ".cache/m1-runtime/mobile-live-ui")
    parent.mkdir(parents=True, exist_ok=True)
    run = base.checked_path(parent / secrets.token_hex(12))
    run_id = secrets.token_hex(16)
    evidence = {"task": "TASK-098", "ok": False, "artifacts": proof, "sources": sources,
                "own_sources": own_sources, "phases": [], "physical_phone": False,
                "browser_started": False, "stage": "preflight", "method": METHOD}
    with RunOwnership(run) as lease:
        try:
            with base.observed_harness(evidence) as harness:
                require(time.monotonic() < overall_deadline, "LIVE_UI_OVERALL_DEADLINE")
                server = ServerProof(harness)
                evidence["empty_server"] = server.inspect(False, 0)
                emulator = UiEmulator(tools, CombinedOwnership(lease, harness), run)
                try:
                    evidence["stage"] = "emulator_boot"
                    with emulator:
                        require(time.monotonic() < overall_deadline, "LIVE_UI_OVERALL_DEADLINE")
                        evidence["stage"] = "emulator_install"
                        emulator.install(artifacts, (app_hash, test_hash))
                        evidence["stage"] = "emulator_unlock"
                        emulator.unlock()
                        emulator.markers_absent()
                        evidence["stage"] = "native_start"
                        with observed_invocation(Invocation(emulator, run_id, overall_deadline), evidence) as invocation:
                            evidence["native"] = Protocol(emulator, server, invocation, run_id, evidence).run_all()
                finally:
                    evidence["emulator"] = emulator.evidence
            require(time.monotonic() < overall_deadline, "LIVE_UI_OVERALL_DEADLINE")
            verify_sources()
            evidence["ok"] = True
        except BaseException as error:
            evidence["failure"] = fail_metadata(error, evidence["stage"])
            raise
        finally:
            evidence["sources_unchanged"] = sources_unchanged(sources)
            evidence["own_sources_unchanged"] = sources_unchanged(own_sources)
            if not evidence["sources_unchanged"] or not evidence["own_sources_unchanged"]:
                evidence["ok"] = False
            lease.assert_owned()
            encoded = json.dumps(evidence, indent=2) + "\n"
            require(len(encoded.encode("utf-8")) <= 32768, "LIVE_UI_RESULT_BOUND")
            with base.checked_path(run / "result.json").open("x", encoding="utf-8") as output:
                output.write(encoded)
            print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    require(evidence["ok"], "LIVE_UI_SOURCE_CHANGED")
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "app-sha256", "test", "test-sha256"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    # Same backend-venv hand-off as mobile_emulator.main and mobile_platform.main.
    if Path(sys.executable).resolve() != Path(base.integration.local.python_path()).resolve():
        return subprocess.run([base.integration.local.python_path(), "-B", str(Path(__file__).resolve()), *sys.argv[1:]],
            cwd=ROOT, env=base.integration.local.managed_environment(), check=False).returncode
    try:
        execute(args.app, args.app_sha256, args.test, args.test_sha256)
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "failure": fail_metadata(error, "terminal")}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
