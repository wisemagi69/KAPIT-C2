"""TASK095 source-only preparation: owned Android process recovery acceptance.

Requires a separately reviewed platform APK and the orchestrator's heavy slot.
No phone, existing AVD, main M1 data, raw UI tree or app checkpoint is selected.
"""
import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_emulator as base

require = base.require
Error = base.EmulatorError
PACKAGE = base.PACKAGE
PLATFORM_CLASS = "org.kapit.c2.mobile.sync.PlatformRecoveryIntegrationTest"
# Settle after wake and swipe before the bouncer accepts keys. Bounded so the stop case's
# device-only reauthorization (ready+REAUTH_START_SECONDS..ready+30) still fits; timings are kept as evidence.
UNLOCK_SETTLE_SECONDS = 1.5
# Stop case: one device-only reauthorization after this much observed absence, finished before the
# 30 s bound that keeps it ahead of the 40 s delayed-work eligibility. Measured emulator unlocks took
# 7.8-16.7 s (devops-m2-platform-run-handoff.md), so a 20 s start could not fit.
REAUTH_START_SECONDS = 10
UNLOCK_ATTEMPTS = 2
REAUTH_DEADLINE_SECONDS = 30
# The launched activity must be able to take key focus, and a cold start after force-stop must finish
# restoring (the controller ignores Unlock while busy), before the single Tab/Enter.
LAUNCHER_SETTLE_SECONDS = 6.0
CASES = {
    "abrupt": ("commitBeforeSchedulingAndAwaitAbruptDeath", "verifyAfterUserRelaunchFromAbruptDeath", "abrupt_ready", 2),
    "stop": ("queueDelayedWorkerAndAwaitForceStop", "verifyAfterUserRelaunchFromForceStop", "force_stop_ready", 3),
}
MAIN = PACKAGE + "/org.kapit.c2.mobile.MainActivity"
LIBRARIES = ("infra/mobile_emulator.py", "infra/mobile_integration.py", "infra/mobile_device.py",
             "android/tools/owned_process.py")


def package_uid(raw, package=PACKAGE):
    """Require a unique user0 package UID, rejecting shared-UID authority."""
    rows = []
    for line in raw.splitlines():
        match = re.fullmatch(r"package:([A-Za-z0-9_.]+) uid:([0-9]{1,6})", line)
        require(match is not None, "PLATFORM_PACKAGE_UID_FORMAT")
        rows.append((match[1], int(match[2])))
    values = [uid for name, uid in rows if name == package]
    require(len(values) == 1 and 1000 <= values[0] < 100000, "PLATFORM_PACKAGE_UID_UNKNOWN")
    if package == PACKAGE:
        require(values[0] >= 10000, "PLATFORM_APPLICATION_UID_DENIED")
        require(sum(uid == values[0] for _, uid in rows) == 1, "PLATFORM_SHARED_UID_DENIED")
    return values[0]


def package_stopped(raw, uid):
    packages = re.findall(r"^\s*Package \[([^]]+)\] \([^)]+\):\s*$", raw, re.MULTILINE)
    # Android16 Settings.dumpPackageLPr prints appId, independently bound to user0.
    users = re.findall(r"^\s*appId=([0-9]+)\s*$", raw, re.MULTILINE)
    states = re.findall(r"^\s*User 0: ([^\r\n]+)$", raw, re.MULTILINE)
    require(packages == [PACKAGE] and users == [str(uid)] and len(states) == 1,
            "PLATFORM_PACKAGE_STATE_IDENTITY")
    fields = re.findall(r"\b(installed|hidden|suspended|stopped)=([^\s]+)", states[0])
    mentions = re.findall(r"\b(installed|hidden|suspended|stopped)\s*=", states[0])
    require(len(fields) == len(mentions) == 4 and len(dict(fields)) == 4 and
            all(value in {"true", "false"} for _, value in fields), "PLATFORM_PACKAGE_STATE_FORMAT")
    values = dict(fields)
    require(values["installed"] == "true" and values["hidden"] == values["suspended"] == "false",
            "PLATFORM_PACKAGE_INELIGIBLE")
    return values["stopped"] == "true"


def owned_pid(raw, uid):
    lines = raw.splitlines()
    require(lines and lines[0].split() == ["PID", "UID", "NAME"], "PLATFORM_PROCESS_FORMAT")
    matches = []
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit(), "PLATFORM_PROCESS_FORMAT")
        if int(fields[1]) == uid or fields[2] == PACKAGE:
            require(int(fields[1]) == uid and fields[2] == PACKAGE, "PLATFORM_PROCESS_OWNER_CHANGED")
            matches.append(int(fields[0]))
    require(len(matches) <= 1 and all(pid > 1 for pid in matches), "PLATFORM_PROCESS_AMBIGUOUS")
    return matches[0] if matches else None


@dataclass(frozen=True, repr=False)
class ProcessIdentity:
    pid: int
    uid: int
    start: int


def process_script(pid, uid, start=None, kill=False):
    require(type(pid) is int and 1 < pid < 2**31 and type(uid) is int and 10000 <= uid < 100000,
            "PLATFORM_PROCESS_ARGUMENT")
    require(start is None or type(start) is int and 0 < start < 2**63, "PLATFORM_PROCESS_ARGUMENT")
    require(not kill or start is not None, "PLATFORM_KILL_WITHOUT_IDENTITY")
    # Only reviewed numeric values enter code. run-as drops to the exact debuggable
    # package UID; no privileged/global/name-wide kill is used. Field22 is starttime.
    script = (f"set -eu\ntest \"$(id -u)\" = '{uid}'\np={pid}\n"
              f"test \"$(awk '/^Uid:/ {{print $2, $3, $4, $5}}' /proc/$p/status)\" = '{uid} {uid} {uid} {uid}'\n"
              f"test \"$(tr '\\000' '\\n' < /proc/$p/cmdline)\" = '{PACKAGE}'\n"
              "s=$(cat /proc/$p/stat)\nf=${s##*) }\nset -- $f\ntest $# -ge 20\nt=${20}\n"
              "case $t in ''|*[!0-9]*) exit 41;; esac\n")
    if start is not None:
        script += f"test \"$t\" = '{start}'\n"
    if kill:
        script += "kill -KILL \"$p\"\nprintf 'KAPIT_KILLED\\n'\n"
    else:
        script += f"printf 'KAPIT_PROCESS %s {uid} %s\\n' \"$p\" \"$t\"\n"
    return script.encode("ascii")


def process_identity(raw, pid, uid):
    match = re.fullmatch(r"KAPIT_PROCESS ([0-9]+) ([0-9]+) ([0-9]+)\n", raw)
    require(match is not None, "PLATFORM_PROCESS_IDENTITY_FORMAT")
    value = ProcessIdentity(*(int(match[index]) for index in (1, 2, 3)))
    require(value.pid == pid and value.uid == uid and 0 < value.start < 2**63,
            "PLATFORM_PROCESS_IDENTITY_CHANGED")
    return value


def phase_value(raw, case):
    require(case in CASES and len(raw) <= 32 and raw.isascii(), "PLATFORM_PHASE_FORMAT")
    require(raw in {"absent", "preparing", CASES[case][2], "verified", "failed"}, "PLATFORM_PHASE_FORMAT")
    return raw


def records(raw):
    values, current = [], {}
    for line in raw.splitlines():
        if line.startswith("INSTRUMENTATION_STATUS_CODE"):
            require(re.fullmatch(r"INSTRUMENTATION_STATUS_CODE: -?\d{1,3}", line) is not None,
                    "PLATFORM_STATUS_CODE_FORMAT")
        elif line.startswith("INSTRUMENTATION_CODE"):
            require(re.fullmatch(r"INSTRUMENTATION_CODE: -?\d{1,3}", line) is not None,
                    "PLATFORM_TERMINAL_CODE_FORMAT")
        field = re.fullmatch(r"INSTRUMENTATION_STATUS: (class|test|current|numtests)=(.*)", line)
        if field:
            current.setdefault(field[1], []).append(field[2])
        code = re.fullmatch(r"INSTRUMENTATION_STATUS_CODE: (-?\d{1,3})", line)
        if code:
            values.append((int(code[1]), current))
            current = {}
    return values, current


def standalone_exception(raw):
    return re.search(r"^(?:INSTRUMENTATION_STATUS: stack=)?(?:[A-Za-z_$][A-Za-z0-9_$]*\.){1,12}"
                     r"[A-Za-z_$][A-Za-z0-9_$]*(?:Error|Exception|Failure)(?::|\s*$)", raw, re.MULTILINE) is not None


def expected_record(method):
    return {"class": [PLATFORM_CLASS], "test": [method], "current": ["1"], "numtests": ["1"]}


def preparation_started(raw, method):
    require(method in {value[0] for value in CASES.values()}, "PLATFORM_METHOD_DENIED")
    incomplete_line = bool(raw) and not raw.endswith("\n")
    if incomplete_line:
        raw = raw[:raw.rfind("\n") + 1]
    observed, pending = records(raw)
    require(not any(value in raw for value in ("FAILURES", "stack=", "INSTRUMENTATION_FAILED", "OK (")),
            "PLATFORM_PREPARATION_FAILED")
    require(not standalone_exception(raw), "PLATFORM_PREPARATION_FAILED")
    require(not re.search(r"^INSTRUMENTATION_(?:CODE|RESULT):", raw, re.MULTILINE),
            "PLATFORM_PREPARATION_ENDED")
    require(not observed or observed == [(1, expected_record(method))], "PLATFORM_START_IDENTITY")
    if observed:
        require(not pending, "PLATFORM_PREPARATION_EXTRA_RECORD")
    return bool(observed) and not incomplete_line


def expected_interruption(raw, method, exit_code):
    observed, pending = records(raw)
    require(observed == [(1, expected_record(method))] and not pending, "PLATFORM_INTERRUPTION_RECORD")
    require(exit_code == 0 and re.findall(r"^INSTRUMENTATION_CODE: (-?\d+)\s*$", raw, re.MULTILINE) == ["0"],
            "PLATFORM_INTERRUPTION_TERMINAL")
    require(re.findall(r"^INSTRUMENTATION_RESULT: shortMsg=(.*)$", raw, re.MULTILINE) == ["Process crashed."],
            "PLATFORM_INTERRUPTION_REASON")
    require(not any(value in raw for value in ("FAILURES", "stack=", "INSTRUMENTATION_FAILED", "OK (")),
            "PLATFORM_INTERRUPTION_FAILED")
    require(not standalone_exception(raw), "PLATFORM_INTERRUPTION_FAILED")
    return {"expected_interruption": True, "method_completed_count": 0,
            "status_codes": [1], "instrumentation_codes": [0]}


def verification_result(raw, method):
    """Reuse088's exact success/failure parser through a strictly checked adapter.

    Only the two exact status identity fields are translated; foreign, duplicate,
    pending, wrong-count or wrong-status records fail before this translation.
    All terminal/error/exception bytes remain untouched for the accepted parser.
    """
    require(method in {value[1] for value in CASES.values()}, "PLATFORM_METHOD_DENIED")
    observed, pending = records(raw)
    require(len(observed) == 2 and not pending and all(fields == expected_record(method) for _, fields in observed),
            "PLATFORM_VERIFY_IDENTITY")
    mapped_method = base.PHASES[0][0]
    lines = raw.splitlines()
    mapped = [f"INSTRUMENTATION_STATUS: class={base.TEST_CLASS}" if line == f"INSTRUMENTATION_STATUS: class={PLATFORM_CLASS}"
              else f"INSTRUMENTATION_STATUS: test={mapped_method}" if line == f"INSTRUMENTATION_STATUS: test={method}"
              else line for line in lines]
    return base.instrumentation_result("\n".join(mapped) + "\n", mapped_method)


def focus_window(raw):
    """Return only exact current user0 focus title and matching owner UID metadata."""
    require(base.current_window_focus(raw) is not None, "PLATFORM_WINDOW_FOCUS_UNKNOWN")
    value = base.focused_window(raw)
    require(value is not None, "PLATFORM_WINDOW_OWNER_UNKNOWN")
    return value[0], value[1]


def credential_window(raw, settings_uid):
    title, uid = focus_window(raw)
    component = re.fullmatch(r"com\.android\.settings/(?:com\.android\.settings)?\.password\.(?:ConfirmLockPassword|ConfirmDeviceCredentialActivity)(?:\$InternalActivity)?", title)
    require(component is not None and uid == settings_uid, "PLATFORM_CREDENTIAL_WINDOW_DENIED")


def credential_target(emulator, raw_window, settings_uid):
    """TASK-117: the unchanged Settings component gate first; only if it refuses, the shared
    user-approved SystemUI prompt rule on fresh reads. Otherwise the original refusal stands."""
    try:
        credential_window(raw_window, settings_uid)
        return "settings"
    except Error as refusal:
        try:
            accepted = emulator.systemui_prompt_focus() is True
        except Exception:
            accepted = False  # Fallback failure keeps the original refusal.
        if accepted:
            return "systemui"
        raise refusal


def locked_owner(raw):
    return base.device_locked(raw)


class GuardedEmulator(base.OwnedEmulator):
    """Local wrapper; shared088 source stays unchanged and no blind PIN path is used."""
    def system_uids(self):
        raw = self.command("shell", "pm", "list", "packages", "-U", "--user", "0")
        return package_uid(raw, "com.android.systemui"), package_uid(raw, "com.android.settings")

    def credential_action(self, action):
        require(action in {"pin", "cancel"}, "PLATFORM_CREDENTIAL_ACTION_DENIED")
        _, settings = self.system_uids()
        credential_target(self, self.command(*base.WINDOW_SNAPSHOT, timeout=5), settings)
        if action == "cancel":
            self.command("shell", "input", "keyevent", "KEYCODE_BACK", timeout=5)
        else:
            self.send_pin()

    def send_pin(self):
        # Only callers that just proved the corresponding platform focus may call.
        require(self.pin is not None and re.fullmatch(r"[0-9]{6}", self.pin), "PLATFORM_CREDENTIAL_MISSING")
        script = "input keyevent " + " ".join(["KEYCODE_DEL"] * 6) + "\n"
        script += f"input text {self.pin}\ninput keyevent KEYCODE_ENTER\n"
        self.command("shell", stdin=script.encode("ascii"), timeout=5)

    def device_unlock(self, deadline, slot="device_unlock_timings"):
        started, marks = time.monotonic(), {}
        mark = lambda name: marks.__setitem__(name, round(time.monotonic() - started, 2))
        try:
            systemui, _ = self.system_uids()
            self.command("shell", "input", "keyevent", "KEYCODE_SLEEP", timeout=5)
            wait_until(lambda: locked_owner(self.command("shell", "dumpsys", "trust", timeout=5)), deadline)
            mark("locked")
            self.command("shell", "input", "keyevent", "KEYCODE_WAKEUP", timeout=5)
            time.sleep(UNLOCK_SETTLE_SECONDS)
            self.command("shell", "input", "swipe", "360", "1100", "360", "300", "400", timeout=5)
            time.sleep(UNLOCK_SETTLE_SECONDS)
            mark("swiped")
            # No repeated taps, traversal, or PIN into an app field. A window-format
            # mismatch fails closed and needs source review before another mechanism.
            title, owner = focus_window(self.command(*base.WINDOW_SNAPSHOT, timeout=5))
            require(owner == systemui and (title == "NotificationShade" or title.startswith("com.android.systemui/")),
                    "PLATFORM_KEYGUARD_WINDOW_DENIED")
            require(locked_owner(self.command("shell", "dumpsys", "trust", timeout=5)), "PLATFORM_KEYGUARD_NOT_LOCKED")
            # Reuse088's independently reviewed policy/secure/unoccluded/user0 and
            # exact SystemUI window-owner check as an additional pre-PIN gate.
            self.require_unlock_target()
            mark("guarded")
            require(time.monotonic() < deadline, "PLATFORM_UNLOCK_DEADLINE")
            self.send_pin()
            mark("pin_sent")
            wait_until(lambda: base.device_unlocked(self.command("shell", "dumpsys", "trust", timeout=5)), deadline)
            mark("unlocked")
        finally:
            # Fixed step names and elapsed seconds only; bounded.
            evidence = getattr(self, "evidence", None)
            if isinstance(evidence, dict):
                # QA F4: the stop-case reauthorization keeps its own slot so baseline unlocks cannot crowd it out.
                require(slot in {"device_unlock_timings", "reauthorization_timings"}, "PLATFORM_TIMING_SLOT")
                timings = evidence.setdefault(slot, [])
                if len(timings) < 8:
                    timings.append({**marks, "budget": round(deadline - started, 2)})

    def unlock(self):
        # Ordinary, not time-critical unlock. Like the shared088 unlock, a bouncer that did not take the PIN on a slow
        # emulator gets one more full wake/swipe/guard/PIN cycle; every guard re-runs. Only the final timing failure
        # is retried. The stop-case device-only reauthorization calls device_unlock directly and stays single-attempt.
        for attempt in range(UNLOCK_ATTEMPTS):
            try:
                self.device_unlock(time.monotonic() + 30)
                return
            except Error as error:
                if str(error) != "PLATFORM_DEADLINE" or attempt + 1 == UNLOCK_ATTEMPTS:
                    raise


def wait_until(predicate, deadline, clock=time.monotonic, sleep=time.sleep):
    while clock() < deadline:
        if predicate():
            require(clock() < deadline, "PLATFORM_DEADLINE")
            return
        sleep(0.1)
    raise Error("PLATFORM_DEADLINE")


class StreamingOutput(base.BoundedOutput):
    """read1 makes the start record visible without waiting for4096 bytes/EOF."""
    def read(self):
        count = 0
        try:
            read = getattr(self.stream, "read1", self.stream.read)
            while chunk := read(4096):
                count += len(chunk)
                if count > self.maximum:
                    self.failed = True
                if self.retain:
                    self.data.extend(chunk[:max(0, self.maximum - len(self.data))])
        except Exception:
            self.failed = True
        finally:
            self.stream.close()


class Preparation:
    """Own only the asynchronous adb client; emulator ownership stays with088."""
    def __init__(self, emulator, method):
        require(method in {value[0] for value in CASES.values()}, "PLATFORM_METHOD_DENIED")
        self.emulator, self.method = emulator, method
        self.child, self.threads = None, []
        self.started = 0.0

    def __enter__(self):
        self.emulator.identity()
        self.started = time.monotonic()
        self.child = subprocess.Popen([str(self.emulator.tools.adb), "-t", self.emulator.target["transport"],
            "shell", "am", "instrument", "-w", "-r", "-e", "class", PLATFORM_CLASS + "#" + self.method,
            "-e", "ownedEmulator", "true", f"{base.TEST_PACKAGE}/{base.RUNNER}"], cwd=ROOT,
            env=base.safe_environment(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            self.output = StreamingOutput(self.child.stdout, 262144)
            self.errors = StreamingOutput(self.child.stderr, 16384, retain=False)
            for reader in (self.output, self.errors):
                thread = threading.Thread(target=reader.read, daemon=True)
                self.threads.append(thread)
                thread.start()
            return self
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise

    def raw(self):
        require(not self.output.failed and not self.errors.failed, "PLATFORM_OUTPUT_BOUND")
        return bytes(self.output.data).decode("utf-8", errors="replace").replace("\r\n", "\n")

    def running(self):
        require(self.child.poll() is None, "PLATFORM_PREMATURE_INSTRUMENTATION_EXIT")
        return preparation_started(self.raw(), self.method)

    def interrupted(self, deadline):
        wait_until(lambda: self.child.poll() is not None, deadline)
        for thread in self.threads:
            thread.join(timeout=2)
        require(not any(thread.is_alive() for thread in self.threads), "PLATFORM_OUTPUT_INCOMPLETE")
        return expected_interruption(self.raw(), self.method, self.child.returncode)

    def __exit__(self, *args):
        if self.child is not None and self.child.poll() is None:
            self.child.kill()
            self.child.wait(timeout=5)
        for thread in self.threads:
            thread.join(timeout=2)


class Driver:
    def __init__(self, harness, emulator):
        self.harness, self.emulator = harness, emulator
        self.uid = None

    def counts(self, effects):
        value = base.background_counts(self.harness)
        base.require_background_counts(value, effects, effects)
        return value

    def package(self):
        raw = self.emulator.command("shell", "pm", "list", "packages", "-U", "--user", "0")
        uid = package_uid(raw)
        require(self.uid is None or uid == self.uid, "PLATFORM_PACKAGE_UID_CHANGED")
        self.uid = uid
        stopped = package_stopped(self.emulator.command("shell", "dumpsys", "package", PACKAGE), uid)
        pid = owned_pid(self.emulator.command("shell", "ps", "-A", "-o", "PID,UID,NAME"), uid)
        return stopped, pid

    def process(self):
        stopped, pid = self.package()
        require(not stopped and pid is not None, "PLATFORM_PROCESS_NOT_RUNNING")
        raw = self.emulator.command("shell", "run-as", PACKAGE, "--user", "0", "sh",
                                    stdin=process_script(pid, self.uid), timeout=5, maximum=128)
        return process_identity(raw, pid, self.uid)

    def phase(self, case):
        require(case in CASES, "PLATFORM_CASE_DENIED")
        path = f"no_backup/m2-platform-{case}.phase"
        script = f"if [ -f {path} ]; then head -c 33 {path}; else printf absent; fi\n"
        raw = self.emulator.command("shell", "run-as", PACKAGE, "--user", "0", "sh",
                                    stdin=script.encode("ascii"), timeout=5, maximum=64)
        return phase_value(raw, case)

    def absent(self, case, effects):
        stopped, pid = self.package()
        require(stopped == (case == "stop") and pid is None, "PLATFORM_STOP_STATE_CHANGED")
        self.counts(effects)
        require(base.parse_reverse(self.emulator.command("reverse", "--list")).get(base.ENDPOINT) == base.ENDPOINT,
                "PLATFORM_NETWORK_TUNNEL_CHANGED")

    def interrupt(self, case, result):
        method, _, ready, effects = CASES[case]
        result["stage"] = "preparation_device_unlock"
        self.emulator.unlock()
        self.counts(effects)
        require(self.phase(case) == "absent", "PLATFORM_PHASE_PREEXISTING")
        result["stage"] = "preparation_readiness"
        with Preparation(self.emulator, method) as preparation:
            deadline = preparation.started + (30 if case == "stop" else 35)
            previous_phase = "absent"
            while True:
                require(time.monotonic() < deadline, "PLATFORM_PREPARATION_DEADLINE")
                started = preparation.running()
                phase = self.phase(case)
                require(phase in {"absent", "preparing", ready}, "PLATFORM_PREPARATION_FAILED")
                order = {"absent": 0, "preparing": 1, ready: 2}
                require(order[phase] >= order[previous_phase], "PLATFORM_PHASE_REGRESSION")
                previous_phase = phase
                if started and phase == ready:
                    break
                time.sleep(0.1)
            ready_at = time.monotonic()
            result["readiness_seconds"] = ready_at - preparation.started
            identity = self.process()
            self.counts(effects)
            require(self.phase(case) == ready and preparation.running(), "PLATFORM_READY_CHANGED")
            require(self.process() == identity, "PLATFORM_PROCESS_REUSED")
            require(preparation.running(), "PLATFORM_READY_CHANGED")
            limit = min(ready_at + 10, preparation.started + 30) if case == "stop" else ready_at + 10
            require(time.monotonic() < limit, "PLATFORM_TERMINATION_LATE")
            result["stage"] = "owned_process_action"
            if case == "abrupt":
                raw = self.emulator.command("shell", "run-as", PACKAGE, "--user", "0", "sh",
                    stdin=process_script(identity.pid, identity.uid, identity.start, kill=True), timeout=5, maximum=64)
                require(raw == "KAPIT_KILLED\n", "PLATFORM_ABRUPT_ACTION_UNCERTAIN")
            else:
                self.emulator.command("shell", "am", "force-stop", "--user", "0", PACKAGE, timeout=5)
            action_at = time.monotonic()
            require(action_at < limit, "PLATFORM_TERMINATION_LATE")
            wait_until(lambda: self.package() == (case == "stop", None), limit)
            confirmed_at = time.monotonic()
            result["stage"] = "expected_instrumentation_interruption"
            result["interruption"] = preparation.interrupted(time.monotonic() + 10)
            result.update(identity_revalidated=True, process_absent=True, package_stopped=(case == "stop"),
                          action_after_ready_seconds=action_at - ready_at,
                          confirmed_stop_from_launch_seconds=confirmed_at - preparation.started)
        self.absent(case, effects)
        return ready_at

    def observe_gap(self, case, ready_at, result):
        result["stage"] = "stopped_observation" if case == "stop" else "abrupt_observation"
        effects = CASES[case][3]
        deadline = ready_at + 60 if case == "stop" else time.monotonic() + 10
        sample_times, renewed = [], False
        while True:
            self.absent(case, effects)
            now = time.monotonic()
            sample_times.append(now - ready_at)
            require(len(sample_times) <= 80, "PLATFORM_SAMPLE_BOUND")
            if case == "stop" and not renewed and now >= ready_at + REAUTH_START_SECONDS:
                require(now < ready_at + REAUTH_DEADLINE_SECONDS, "PLATFORM_REAUTHORIZATION_LATE")
                # Device-only system credential action: no app component/target
                # instrumentation starts in the stopped interval.
                self.emulator.device_unlock(ready_at + REAUTH_DEADLINE_SECONDS, slot="reauthorization_timings")
                self.absent(case, effects)
                require(time.monotonic() < ready_at + REAUTH_DEADLINE_SECONDS, "PLATFORM_REAUTHORIZATION_LATE")
                renewed = True
            if time.monotonic() >= deadline:
                break
            time.sleep(1)
        require(case != "stop" or renewed, "PLATFORM_REAUTHORIZATION_MISSING")
        self.absent(case, effects)
        result["gap"] = {"passed": True, "samples": len(sample_times), "sample_seconds_after_ready": sample_times,
                         "device_only_reauthorization": renewed, "seconds_after_ready": time.monotonic() - ready_at}

    def launcher(self, case, result):
        result["stage"] = "explicit_launcher"
        self.absent(case, CASES[case][3])
        started = time.monotonic()
        raw = self.emulator.command("shell", "am", "start", "-W", "--user", "0", "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER", "-n", MAIN, timeout=20, maximum=4096)
        require(re.findall(r"^Status: (.*)$", raw, re.MULTILINE) == ["ok"] and
                re.findall(r"^Activity: (.*)$", raw, re.MULTILINE) == [MAIN], "PLATFORM_LAUNCH_FAILED")
        wait_until(lambda: self.emulator.credential_focus() == PACKAGE, started + 30)
        self.process()
        result["stage"] = "single_keyboard_activation"
        # Behavioral activation only: this does not assert prior screen/button
        # identity. Exactly one Tab/Enter, then an independently owned credential
        # component is required. No input traversal or coordinate fallback.
        time.sleep(LAUNCHER_SETTLE_SECONDS)
        self.emulator.command("shell", "input", "keyevent", "KEYCODE_TAB", "KEYCODE_ENTER", timeout=5)
        _, settings = self.emulator.system_uids()
        matched = []
        def prompt():
            raw_window = self.emulator.command(*base.WINDOW_SNAPSHOT, timeout=5)
            if base.focused_package(raw_window) == PACKAGE:
                return False
            matched.append(credential_target(self.emulator, raw_window, settings))
            return True
        wait_until(prompt, started + 40)
        result["stage"] = "credential_prompt_return"
        # TASK-117 F1: report which gate matched; the SystemUI rule is not the exact Settings screen.
        result["launcher"] = {"explicit_launcher": True, "single_tab_enter": True,
                              "prior_screen_or_control_identity_proven": False, "credential_prompt_observed": True,
                              "credential_prompt_rule": {"settings": "SETTINGS_COMPONENT", "systemui": "SYSTEMUI_FALLBACK"}
                                                        .get(matched[-1] if matched else None, "UNKNOWN"),
                              "credential_returned": False}
        before_return = base.background_counts(self.harness)
        require_transition_counts(before_return, CASES[case][3])
        result["launcher"]["server_effect_visible_before_prompt_return"] = before_return["revisions"] > CASES[case][3]
        self.emulator.credential_action("pin")
        wait_until(lambda: self.emulator.credential_focus() == PACKAGE and
                   base.device_unlocked(self.emulator.command("shell", "dumpsys", "trust", timeout=5)), started + 55)
        result["launcher"]["credential_returned"] = True
        result["launcher"]["return_after_launch_seconds"] = time.monotonic() - started

    def verify(self, case, result):
        result["stage"] = "post_launcher_server_effect"
        prior = CASES[case][3]
        def complete():
            value = base.background_counts(self.harness)
            require_transition_counts(value, prior)
            result["server_counts"] = value
            return value["revisions"] == prior + 1 and value["jobs_done"] == prior + 1
        self.harness.wait(complete, seconds=60)
        # Give the ordinary worker a bounded quiescence interval without creating
        # work/reading protected data. Native verification independently requires
        # already persisted SUCCEEDED plus exact local receipts BEFORE unwrap.
        time.sleep(2)
        self.counts(prior + 1)
        require(result["launcher"]["credential_returned"], "PLATFORM_UI_RETURN_MISSING")
        method = CASES[case][1]
        result["stage"] = "separate_native_verification"
        raw = self.emulator.command("shell", "am", "instrument", "-w", "-r", "-e", "class",
            PLATFORM_CLASS + "#" + method, "-e", "ownedEmulator", "true",
            f"{base.TEST_PACKAGE}/{base.RUNNER}", timeout=120)
        result["verification"] = {"method": method, **verification_result(raw, method)}
        require(result["verification"]["passed"], "PLATFORM_VERIFICATION_FAILED")
        require(self.phase(case) == "verified", "PLATFORM_VERIFICATION_PHASE")
        result["server_counts_after_verification"] = self.counts(prior + 1)
        result["passed"] = True
        result["stage"] = "complete"


def require_transition_counts(value, prior):
    require(isinstance(value, dict) and prior in {2, 3}, "PLATFORM_SERVER_EFFECT_MISMATCH")
    require(all(type(item) is int for item in value.values()), "PLATFORM_SERVER_EFFECT_MISMATCH")
    require(value.get("revisions") in {prior, prior + 1} and value.get("jobs_done") in {prior, prior + 1},
            "PLATFORM_SERVER_EFFECT_MISMATCH")
    effects, done = value["revisions"], value["jobs_done"]
    require(done <= effects, "PLATFORM_SERVER_EFFECT_MISMATCH")
    base.require_background_counts(value, effects, done)


def credential_prerequisite(evidence):
    """Full credential pass, or (TASK-119 rule) proven real cancel+unlock with the recorded limitation."""
    credential = evidence.get("system_credential", {})
    full = credential.get("passed") is True and credential.get("handshake", {}).get("completed") is True
    partial = (credential.get("passed") is not True and base.credential_cancel_and_unlock_proven(credential)
               and evidence.get("credential_limitation") == base.CREDENTIAL_PARTIAL_LIMITATION)
    return full or partial


def require_prerequisites(evidence):
    phases = evidence.get("phases", [])
    background = evidence.get("background_delivery", {})
    require([phase.get("method") for phase in phases] == [phase[0] for phase in base.PHASES] and
            all(phase.get("passed") is True and phase.get("method_completed_count") == 1 for phase in phases) and
            evidence.get("worker_completed") is True and credential_prerequisite(evidence) and
            background.get("passed") is True and
            [phase.get("method") for phase in background.get("phases", [])] == list(base.BACKGROUND_METHODS) and
            all(phase.get("passed") is True and phase.get("method_completed_count") == 1 for phase in background["phases"]),
            "PLATFORM_PREREQUISITES_MISSING")


def platform_extension(harness, emulator, evidence):
    require_prerequisites(evidence)
    result = {"passed": False, "cases": []}
    evidence["platform_recovery"] = result
    driver = Driver(harness, emulator)
    for case in CASES:
        harness.fault("normal")
        current = {"case": case, "passed": False}
        result["cases"].append(current)
        ready_at = driver.interrupt(case, current)
        driver.observe_gap(case, ready_at, current)
        driver.launcher(case, current)
        driver.verify(case, current)
        print(json.dumps({"platform_case": case, "passed": True}), flush=True)
    result["passed"] = True


def baseline(harness, emulator, evidence):
    """Exact088 phase order, fault modes, parsers, counts and completion gates."""
    for method, fault, revisions in base.PHASES:
        evidence["stage"] = "baseline_" + method
        harness.fault(fault)
        outcome = {"method": method, "fault": fault, **emulator.instrument(method)}
        evidence["phases"].append(outcome)
        require(outcome["passed"], "EMULATOR_INSTRUMENTATION_FAILED")
        outcome["server_counts"] = base.server_counts(harness, revisions)
    from apps.operations.models import ProcessingJob
    harness.wait(lambda: ProcessingJob.objects.filter(status="DONE").count() == 1)
    require(ProcessingJob.objects.count() == 1, "EMULATOR_WORKER_EFFECT_MISMATCH")
    evidence["worker_completed"] = True
    evidence["stage"] = "baseline_system_credential"
    harness.fault("normal")
    evidence["system_credential"] = credential = emulator.instrument_credentials()
    # TASK-119 rule: proven cancel+unlock lets later phases run; execute still fails overall below.
    require(credential["passed"] or base.credential_cancel_and_unlock_proven(credential),
            "EMULATOR_SYSTEM_CREDENTIAL_FAILED")
    if not credential["passed"]:
        evidence["credential_limitation"] = base.CREDENTIAL_PARTIAL_LIMITATION
    credential["server_counts"] = base.server_counts(harness, 1)
    evidence["stage"] = "baseline_pending_background"
    base.background_delivery(harness, emulator, evidence)


def failure_metadata(error, stage):
    safe = base.failure_metadata(error)
    code = str(error) if type(error) is Error and re.fullmatch(r"(?:PLATFORM|EMULATOR|MOBILE|DEVICE)_[A-Z0-9_]{1,80}", str(error)) else "PLATFORM_INTEGRATION_FAILED"
    local = []
    trace = error.__traceback__
    for _ in range(64):
        if trace is None:
            break
        if Path(trace.tb_frame.f_code.co_filename).resolve() == Path(__file__).resolve() and 0 < trace.tb_lineno <= 100000:
            local.append({"source": "infra/mobile_platform.py", "line": trace.tb_lineno})
        trace = trace.tb_next
    return {"stage": stage, "exception_type": safe["exception_class"], "code": code,
            "owned_source_lines": (safe["owned_source_lines"] + local)[-6:]}


def execute(app, app_hash, test, test_hash):
    tools = base.AndroidTools()
    artifacts, proof = base.verify_artifacts(tools, app, app_hash, test, test_hash)
    parent = base.checked_path(ROOT / ".cache/m1-runtime/mobile-platform")
    parent.mkdir(parents=True, exist_ok=True)
    run = base.checked_path(parent / secrets.token_hex(12))
    run.mkdir(exist_ok=False)
    hashes = {path: base.digest(ROOT / path) for path in LIBRARIES}
    evidence = {"task": "TASK-095", "ok": False, "physical_phone": False, "artifacts": proof,
                "phases": [], "library_sha256": hashes, "stage": "isolated_harness_setup",
                "host_sha256": base.digest(Path(__file__).resolve())}  # QA F3: bind the result to its own host bytes.
    body_error = emulator_error = None
    try:
        with base.integration.MobileHarness() as harness:
            emulator = GuardedEmulator(tools, harness, run)
            try:
                evidence["stage"] = "owned_emulator_setup"
                with emulator:
                    try:
                        evidence["stage"] = "owned_apk_install"
                        emulator.install(artifacts, (app_hash, test_hash))
                        baseline(harness, emulator, evidence)
                        evidence["stage"] = "platform_extension"
                        platform_extension(harness, emulator, evidence)
                        require(evidence["system_credential"]["passed"], "EMULATOR_SYSTEM_CREDENTIAL_PARTIAL")
                    except BaseException as error:
                        body_error = error
                        evidence["body_failure"] = failure_metadata(error, evidence["stage"])
                        raise
                    finally:
                        evidence["stage"] = "owned_emulator_cleanup"
            except BaseException as error:
                if error is not body_error:
                    emulator_error = error
                    key = "cleanup_failure" if evidence["stage"] == "owned_emulator_cleanup" else "emulator_failure"
                    evidence[key] = failure_metadata(error, evidence["stage"])
                raise
            finally:
                evidence["emulator"] = emulator.evidence
                if emulator.evidence.get("owned_emulator_stopped") and emulator.evidence.get("owned_emulator_ports_closed"):
                    evidence["stage"] = "isolated_harness_cleanup"
        evidence["database_cleanup_passed"] = True
        require(all(base.digest(ROOT / path) == value for path, value in hashes.items()), "PLATFORM_LIBRARY_CHANGED")
        evidence["ok"] = True
        evidence["stage"] = "complete"
        return evidence
    except BaseException as error:
        if error is body_error:
            evidence["failure"] = evidence["body_failure"]
        elif error is emulator_error:
            evidence["failure"] = evidence.get("cleanup_failure", evidence.get("emulator_failure"))
        else:
            evidence["failure"] = failure_metadata(error, evidence["stage"])
            if evidence["stage"] == "isolated_harness_cleanup":
                evidence["harness_cleanup_failure"] = evidence["failure"]
        raise
    finally:
        # No raw child output, PIN, UI tree, protected checkpoint or source IDs.
        (run / "result.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--app-sha256", required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--test-sha256", required=True)
    args = parser.parse_args()
    if Path(sys.executable).resolve() != Path(base.integration.local.python_path()).resolve():
        return subprocess.run([base.integration.local.python_path(), "-B", str(Path(__file__).resolve()), *sys.argv[1:]],
            cwd=ROOT, env=base.integration.local.managed_environment(), check=False).returncode
    try:
        execute(args.app, args.app_sha256, args.test, args.test_sha256)
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, **failure_metadata(error, "cli")}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
