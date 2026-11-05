"""TASK100: bounded owned lock-screen diagnosis; never enter a PIN into UI."""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_boot_diagnostic as boot

base = boot.base
require = base.require
FROZEN = {**boot.FROZEN,
    "infra/mobile_device.py": "8df9b50002f5fc65a97e5624e35f7ea8be39acbdd4c48b79714d8997aa933012",
    "infra/mobile_boot_diagnostic.py": "4fb0441476d0c7a94c3a3aa00f8d34040f2484de201b0d9e08d7f8bdb9e1dd40"}
READS = {
    "packages": ("shell", "pm", "list", "packages", "-U", "--user", "0", "com.android.systemui"),
    "trust": ("shell", "dumpsys", "trust"),
    "policy": ("shell", "dumpsys", "window", "policy"),
    "windows": ("shell", "dumpsys", "window", "windows"),
    "current_user": ("shell", "am", "get-current-user"),
}
ERRORS = frozenset({"UNLOCK_RUN_PATH_DENIED", "UNLOCK_SOURCE_CHANGED", "UNLOCK_METADATA_BOUND",
    "UNLOCK_SNAPSHOT_COMMAND_DENIED", "UNLOCK_ALREADY_PREPARED", "UNLOCK_NOT_PREPARED",
    "UNLOCK_ALREADY_COLLECTED", "UNLOCK_PIN_SETUP_FAILED", "UNLOCK_RESULT_BOUND"})


def error_code(error):
    value = str(error)
    return value if type(error) is base.EmulatorError and value in ERRORS else boot.failure_code(error)


def lines(raw):
    require(len(raw) <= 262144, "UNLOCK_METADATA_BOUND")
    result = raw.splitlines()
    require(len(result) <= 4096, "UNLOCK_METADATA_BOUND")
    return result


def package_summary(raw):
    """Return fixed metadata plus an ephemeral exact-package UID candidate."""
    rows = [line for line in lines(raw) if line.strip()]
    exact, valid, other, invalid = [], [], 0, 0
    for line in rows:
        match = re.fullmatch(r"package:([A-Za-z0-9_.]+) uid:([0-9]{1,6})", line)
        is_exact = re.match(r"package:com\.android\.systemui(?:\s|$)", line) is not None
        if is_exact:
            exact.append(line)
        if not match:
            invalid += 1
        elif match[1] == "com.android.systemui":
            valid.append(int(match[2]))
        else:
            other += 1
    candidate = valid[0] if len(exact) == len(valid) == 1 and 0 < valid[0] < 100000 else None
    category = "absent" if not exact else "ambiguous" if len(exact) != 1 else (
        "invalid" if len(valid) != 1 or valid[0] == 0 else "owner0" if valid[0] < 100000 else "other_user")
    return {"nonblank_rows": len(rows), "exact_package_rows": len(exact),
            "exact_valid_uid_rows": len(valid), "distinct_exact_uids": len(set(valid)),
            "other_package_rows": other, "malformed_rows": invalid, "candidate_category": category,
            "old_single_row_parser_accepts": base.systemui_uid(raw) is not None}, candidate


def section(raw, title):
    data = lines(raw)
    starts = [i for i, line in enumerate(data) if line.strip() == title]
    if len(starts) != 1:
        return len(starts), []
    index = starts[0]
    depth = len(data[index]) - len(data[index].lstrip())
    fields = []
    for line in data[index + 1:]:
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent <= depth:
            break
        if indent == depth + 2:
            fields.append(line.strip())
    return 1, fields


def scalar(fields, key, *, boolean=False):
    values = [line.split("=", 1)[1] for line in fields if line.startswith(key + "=")]
    if not values:
        category = "absent"
    elif len(values) != 1:
        category = "ambiguous"
    elif boolean:
        category = values[0] if values[0] in {"true", "false"} else "invalid"
    elif not re.fullmatch(r"-?[0-9]{1,9}", values[0]):
        category = "invalid"
    else:
        number = int(values[0])
        category = "zero" if number == 0 else "user_null" if number == -10000 else "negative" if number < 0 else "positive"
    return {"count": len(values), "category": category}


def policy_summary(raw):
    delegate_count, delegate = section(raw, "KeyguardServiceDelegate")
    monitor_count, monitor = section(raw, "KeyguardStateMonitor")
    return {"delegate_sections": delegate_count, "monitor_sections": monitor_count,
        "delegate_current_user": scalar(delegate, "currentUser"),
        "delegate_current_user_id": scalar(delegate, "mCurrentUserId"),
        "monitor_current_user": scalar(monitor, "currentUser"),
        "monitor_current_user_id": scalar(monitor, "mCurrentUserId"),
        "monitor_showing": scalar(monitor, "mIsShowing", boolean=True),
        "monitor_input_restricted": scalar(monitor, "mInputRestricted", boolean=True),
        "old_delegate_conditions": base.keyguard_conditions(raw)}


def focus_summary(raw, candidate):
    data = lines(raw)
    focuses = [line.strip() for line in data if line.strip().startswith("mCurrentFocus=")]
    result = {"focus_rows": len(focuses), "focus_user": "absent" if not focuses else "ambiguous",
        "matching_window_records": 0, "owner_rows": 0, "owner_row_shape": "absent",
        "owner_package": "unknown", "owner_uid_category": "unknown", "candidate_uid_match": "unknown",
        "old_focus_parser_with_exact_candidate": base.systemui_lock_focus(raw, candidate)}
    if len(focuses) != 1:
        return result
    match = re.fullmatch(r"mCurrentFocus=(Window\{[0-9a-fA-F]+ u([0-9]{1,6}) [^\r\n}]{1,160}\})", focuses[0])
    result["focus_user"] = "unparsed" if not match else "owner0" if match[2] == "0" else "other_user"
    if not match:
        return result
    starts = [i for i, line in enumerate(data)
              if re.fullmatch(r"\s*Window #[0-9]+ " + re.escape(match[1]) + ":", line)]
    result["matching_window_records"] = len(starts)
    if len(starts) != 1:
        return result
    index = starts[0]
    depth = len(data[index]) - len(data[index].lstrip())
    owners = []
    for line in data[index + 1:]:
        indent = len(line) - len(line.lstrip())
        if line.strip() and indent <= depth:
            break
        if indent == depth + 2 and line.strip().startswith("mOwnerUid="):
            owners.append(line.strip())
    result["owner_rows"] = len(owners)
    result["owner_row_shape"] = "absent" if not owners else "ambiguous"
    if len(owners) != 1:
        return result
    owner = re.fullmatch(r"mOwnerUid=([0-9]{1,6}) showForAllUsers=(?:true|false) "
                         r"package=([A-Za-z0-9_.]+) appop=[A-Za-z0-9_]+", owners[0])
    result["owner_row_shape"] = "expected" if owner else "unparsed"
    if owner:
        uid = int(owner[1])
        result["owner_package"] = "systemui" if owner[2] == "com.android.systemui" else "other"
        result["owner_uid_category"] = "owner0" if 0 < uid < 100000 else "other"
        if candidate is not None:
            result["candidate_uid_match"] = "equal" if uid == candidate else "different"
    return result


class ReadSnapshot:
    """Replay only already captured fixed reads into the unchanged guard."""
    def __init__(self, captured):
        self.captured = captured
        self.evidence = {}

    def command(self, *parts, **kwargs):
        names = [name for name, command in READS.items() if parts == command]
        require(len(names) == 1 and kwargs == {"timeout": 5}, "UNLOCK_SNAPSHOT_COMMAND_DENIED")
        return self.captured[names[0]]


def summarize(captured):
    require(set(captured) == set(READS), "UNLOCK_SNAPSHOT_COMMAND_DENIED")
    for raw in captured.values():
        lines(raw)
    snapshot = ReadSnapshot(captured)
    try:
        base.OwnedEmulator.require_unlock_target(snapshot)
        guard = "accepted"
    except base.EmulatorError as error:
        if str(error) != "EMULATOR_UNLOCK_TARGET_DENIED":
            raise
        guard = "denied"
    package, candidate = package_summary(captured["packages"])
    return {"existing_guard_result": guard, "existing_guard_conditions": snapshot.evidence["unlock_preconditions"],
        "package": package, "policy": policy_summary(captured["policy"]),
        "focus": focus_summary(captured["windows"], candidate),
        "activity_current_user": scalar(["id=" + captured["current_user"].strip()], "id"),
        "trust_current_records": sum("(current)" in row for row in lines(captured["trust"])),
        "trust_owner_lock": {"0": "unlocked", "1": "locked"}.get(base.current_device_lock(captured["trust"]), "unknown")}


class UnlockLease(boot.RunLease):
    def __init__(self, run):
        self.run = base.checked_path(run)
        require(self.run.parent == ROOT / ".cache/m1-runtime/mobile-unlock" and
                re.fullmatch(r"[0-9a-f]{24}", self.run.name), "UNLOCK_RUN_PATH_DENIED")
        self.file = None


class UnlockDiagnostic(boot.BootEmulator):
    def __init__(self, tools, lease, run):
        super().__init__(tools, lease, run)
        self.preparation_started = self.prepared = self.collected = False

    def final_probe(self):
        # This diagnostic explicitly collects its only lock snapshot before
        # cleanup. Reuse the reviewed held-job cleanup without another read.
        return

    def prepare(self):
        require(not self.preparation_started, "UNLOCK_ALREADY_PREPARED")
        self.preparation_started = True
        self.evidence["stage"] = "synthetic_pin_setup"
        pin = str(secrets.randbelow(900000) + 100000)
        script = f"locksettings set-pin {pin}\n".encode("ascii")
        output = base.OwnedEmulator.command(self, "shell", stdin=script, timeout=20, maximum=1024)
        require(output.startswith("Pin set to"), "UNLOCK_PIN_SETUP_FAILED")
        del pin, script, output
        self.evidence["synthetic_pin_configured"] = True
        self.evidence["stage"] = "fixed_lock_preparation"
        for command, pause in ((('shell', 'input', 'keyevent', 'KEYCODE_SLEEP'), 2),
                               (('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP'), 3),
                               (('shell', 'input', 'swipe', '360', '1100', '360', '300', '400'), 3)):
            base.OwnedEmulator.command(self, *command, timeout=5, maximum=1024)
            time.sleep(pause)
        self.prepared = True
        self.evidence["ui_pin_entered"] = False

    def collect(self):
        require(self.prepared, "UNLOCK_NOT_PREPARED")
        require(not self.collected, "UNLOCK_ALREADY_COLLECTED")
        self.collected = True
        self.evidence["stage"] = "lock_metadata_capture"
        captured = {name: base.OwnedEmulator.command(self, *command, timeout=5, maximum=262144)
                    for name, command in READS.items()}
        self.evidence["lock_metadata"] = summarize(captured)
        captured.clear()
        self.evidence["stage"] = "lock_metadata_complete"


def verify_sources():
    observed = {name: base.digest(ROOT / name) for name in FROZEN}
    require(observed == FROZEN, "UNLOCK_SOURCE_CHANGED")
    return observed


def execute():
    require(os.name == "nt", "BOOT_WINDOWS_REQUIRED")
    libraries = verify_sources()
    require(shutil.disk_usage(ROOT).free >= 12 * 1024**3, "BOOT_DISK_REQUIRED")
    own = {name: base.digest(ROOT / name) for name in
           ("infra/mobile_unlock_diagnostic.py", "infra/test_mobile_unlock_diagnostic.py")}
    tools = base.AndroidTools()
    parent = base.checked_path(ROOT / ".cache/m1-runtime/mobile-unlock")
    parent.mkdir(parents=True, exist_ok=True)
    run = base.checked_path(parent / secrets.token_hex(12))
    evidence = {"task": "TASK-100", "ok": False, "libraries": libraries, "diagnostic_sources_sha256": own,
                "database_started": False, "api_started": False, "packages_installed": False,
                "ui_pin_entered": False, "physical_phone": False}
    with UnlockLease(run) as lease:
        emulator = UnlockDiagnostic(tools, lease, run)
        try:
            with emulator:
                evidence["boot_gate_passed"] = True
                emulator.prepare()
                emulator.collect()
            require(emulator.evidence.get("owned_emulator_stopped") is True and
                    emulator.evidence.get("owned_emulator_ports_closed") is True, "BOOT_CLEANUP_UNCERTAIN")
            evidence["ok"] = True
        except BaseException as error:
            evidence.update(code=error_code(error), failure=base.failure_metadata(error))
            raise
        finally:
            if not emulator.closed:
                emulator.__exit__(*sys.exc_info())
            evidence.update(emulator=emulator.evidence, boot_diagnostic=emulator.diagnostic)
            evidence["libraries_unchanged"] = {name: base.digest(ROOT / name) for name in FROZEN} == libraries
            evidence["diagnostic_sources_unchanged"] = {name: base.digest(ROOT / name) for name in own} == own
            if not evidence["libraries_unchanged"] or not evidence["diagnostic_sources_unchanged"]:
                evidence.update(ok=False, code="UNLOCK_SOURCE_CHANGED")
            lease.assert_owned()
            encoded = json.dumps(evidence, indent=2) + "\n"
            require(len(encoded.encode("utf-8")) <= 16384, "UNLOCK_RESULT_BOUND")
            with base.checked_path(run / "result.json").open("x", encoding="utf-8") as stream:
                stream.write(encoded)
            print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    require(evidence["ok"], evidence.get("code", "UNLOCK_SOURCE_CHANGED"))
    return evidence


def main():
    try:
        execute()
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "code": error_code(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
