"""TASK096: one owned emulator boot diagnostic, without DB/API/APK/PIN work."""
import ctypes
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_emulator as base
from infra.mobile_accessibility import RunLease

FROZEN = {
    "infra/mobile_emulator.py": "0aef978039cda5ee26e95b2469cafa59529a0dc258056869b4ad98261ababc83",
    "infra/mobile_accessibility.py": "a629d70c07a594d6557d5d6c3de9c592c7d48b42f8b6eeb7bf4e9269eec395c4",
    "infra/mobile_device.py": "ca8f6f9908ee1f9f60a56cffe7acf0bd23a136df1d87ac2eef5fcca0fa3f0df4",
    "infra/mobile_integration.py": "8aa5c44ffe8e60b277a7496fc4d9557f624a868386c672fc9d77d5182faf03ab",
    "android/tools/owned_process.py": "bee293c26831a964a8b88fba75570c6bd2cacb1887ffc2e5435a5af967ed8257",
}
BOOT_COMMANDS = {
    ("shell", "getprop", "sys.boot_completed"): "boot_completed",
    ("shell", "getprop", "ro.kernel.qemu"): "qemu",
    ("shell", "getprop", "ro.build.version.sdk"): "api",
    ("shell", "getprop", "ro.product.cpu.abi"): "abi",
    ("shell", "getconf", "PAGESIZE"): "page_size",
}
PROPERTIES = ("sys.boot_completed", "dev.bootcomplete", "init.svc.bootanim", "init.svc.zygote",
              "init.svc.surfaceflinger", "init.svc.servicemanager")
PROPERTY_INPUT = ("\n".join("getprop " + name for name in PROPERTIES) + "\n").encode("ascii")
ERROR_CODES = frozenset({"EMULATOR_TRANSPORT_UNAVAILABLE", "EMULATOR_TRANSPORT_CHANGED",
    "EMULATOR_AVD_IDENTITY", "EMULATOR_CHILD_STOPPED", "EMULATOR_COMMAND_FAILED",
    "EMULATOR_COMMAND_UNAVAILABLE", "EMULATOR_COMMAND_TIMEOUT", "EMULATOR_OUTPUT_BOUND",
    "EMULATOR_BOOT_TIMEOUT", "EMULATOR_PHYSICAL_DENIED", "EMULATOR_PLATFORM_DENIED",
    "EMULATOR_PAGE_SIZE_UNKNOWN", "EMULATOR_PORT_PREEXISTING", "EMULATOR_TARGET_PREEXISTING",
    "EMULATOR_IMAGE_UNAVAILABLE", "DEVICE_COMMAND_UNAVAILABLE", "DEVICE_COMMAND_FAILED",
    "DEVICE_DISCOVERY_INVALID", "A11Y_RUN_OWNERSHIP_LOST", "A11Y_RUN_PREEXISTING",
    "BOOT_WINDOWS_REQUIRED", "BOOT_DISK_REQUIRED", "BOOT_SOURCE_CHANGED", "BOOT_RUN_PATH_DENIED",
    "BOOT_COMMAND_DENIED", "BOOT_PROBE_BOUND", "BOOT_PROPERTY_FORMAT", "BOOT_CLEANUP_UNCERTAIN",
    "BOOT_RESULT_BOUND"})
require = base.require


def failure_code(error):
    value = str(error)
    return value if value in ERROR_CODES and isinstance(error, (base.EmulatorError, base.DeviceError)) else "BOOT_OTHER_FAILURE"


def fixed_properties(raw):
    require(len(raw) <= 512, "BOOT_PROPERTY_FORMAT")
    lines = raw.splitlines()
    require(len(lines) == len(PROPERTIES), "BOOT_PROPERTY_FORMAT")
    result = {}
    for index, (name, value) in enumerate(zip(PROPERTIES, lines, strict=True)):
        choices = {"": "unset", "0": "not_complete", "1": "complete"} if index < 2 else {
            "": "unset", "running": "running", "stopped": "stopped", "restarting": "restarting"}
        result[name] = choices.get(value, "unexpected")
    return result


class MemoryStatus(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong), ("available_physical", ctypes.c_ulonglong),
                ("total_pagefile", ctypes.c_ulonglong), ("available_pagefile", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong), ("available_virtual", ctypes.c_ulonglong),
                ("available_extended", ctypes.c_ulonglong)]


def host_sample():
    """Aggregate host facts only. No process names, command lines or user data."""
    sample = {"cpu_count": min(1024, max(1, os.cpu_count() or 1)),
              "workspace_disk_free_bytes": shutil.disk_usage(ROOT).free,
              "memory_observed": False, "cpu_observed": False}
    if os.name != "nt":
        return sample
    try:
        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            sample.update(memory_observed=True, memory_load_percent=int(status.load),
                          physical_total_bytes=int(status.total_physical),
                          physical_available_bytes=int(status.available_physical),
                          pagefile_total_bytes=int(status.total_pagefile),
                          pagefile_available_bytes=int(status.available_pagefile))
        idle, kernel, user = (ctypes.c_ulonglong() for _ in range(3))
        if ctypes.windll.kernel32.GetSystemTimes(ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)):
            sample.update(cpu_observed=True, cpu_idle_ticks=idle.value,
                          cpu_total_ticks=kernel.value + user.value)
    except (AttributeError, OSError):
        pass
    return sample


def cpu_interval(before, after):
    if before.get("cpu_observed") is not True or after.get("cpu_observed") is not True:
        return None
    total = after["cpu_total_ticks"] - before["cpu_total_ticks"]
    idle = after["cpu_idle_ticks"] - before["cpu_idle_ticks"]
    if total <= 0 or not 0 <= idle <= total:
        return None
    return round(100 * (total - idle) / total, 2)


class BootLease(RunLease):
    """Reuse reviewed directory/held-marker lease; narrow only its parent path."""
    def __init__(self, run):
        self.run = base.checked_path(run)
        require(self.run.parent == ROOT / ".cache/m1-runtime/mobile-boot" and
                re.fullmatch(r"[0-9a-f]{24}", self.run.name), "BOOT_RUN_PATH_DENIED")
        self.file = None


class BootEmulator(base.OwnedEmulator):
    # Inherit the exact reviewed 240-second loop and API/ABI/page/process gates.
    def __init__(self, tools, lease, run):
        super().__init__(tools, lease, run)
        self.started = time.monotonic()
        self.closed = False
        self.diagnostic = {"boot_deadline_seconds": 240, "commands": {}, "final_properties": None}

    def command(self, *parts, **kwargs):
        require(parts in BOOT_COMMANDS and not kwargs, "BOOT_COMMAND_DENIED")
        name = BOOT_COMMANDS[parts]
        record = self.diagnostic["commands"].setdefault(name, {"attempts": 0, "succeeded": 0, "errors": 0})
        require(record["attempts"] < 1000, "BOOT_PROBE_BOUND")
        record["attempts"] += 1
        started = time.monotonic()
        try:
            value = super().command(*parts)
            record["succeeded"] += 1
            record["last_code"] = "OK"
            if name == "boot_completed":
                record["last_value"] = {"": "unset", "0": "not_complete", "1": "complete"}.get(value.strip(), "unexpected")
            return value
        except BaseException as error:
            record["errors"] += 1
            record["last_code"] = failure_code(error)
            record["failure"] = base.failure_metadata(error)
            raise
        finally:
            record["last_duration_ms"] = min(600000, max(0, round((time.monotonic() - started) * 1000)))
            self.diagnostic["elapsed_ms"] = min(900000, max(0, round((time.monotonic() - self.started) * 1000)))

    def install(self, *args, **kwargs):
        raise base.EmulatorError("BOOT_COMMAND_DENIED")

    def unlock(self):
        raise base.EmulatorError("BOOT_COMMAND_DENIED")

    def final_probe(self):
        # One fixed metadata-only probe after the readiness decision. It never
        # changes that result or extends its 240-second gate. Existing held
        # ownership/transport discovery is bounded 15+10s; this probe is 5s.
        # adb joins shell argv without escaping, so pass the fixed six lines
        # through stdin to a non-PTY shell instead of unquoted sh -c arguments.
        started = time.monotonic()
        try:
            raw = base.OwnedEmulator.command(self, "shell", "-T", "sh", stdin=PROPERTY_INPUT,
                                            timeout=5, maximum=512)
            self.diagnostic["final_properties"] = fixed_properties(raw)
            self.diagnostic["final_probe_code"] = "OK"
        except BaseException as error:
            self.diagnostic["final_probe_code"] = failure_code(error)
        finally:
            self.diagnostic["final_probe_duration_ms"] = min(600000, max(0, round((time.monotonic() - started) * 1000)))

    def __exit__(self, *args):
        # The parent uncertain-cleanup branch imports the DB preservation hook.
        # This boot-only run has no database, so use only held-job/port cleanup.
        if self.closed:
            return
        self.closed = True
        self.evidence["cleanup_attempted"] = True
        if len(args) > 1 and args[1] is not None:
            self.evidence["body_failure"] = {"code": failure_code(args[1]), **base.failure_metadata(args[1])}
        if self.owner is None:
            self.evidence.update(owned_process_never_started=self.child is None, cleanup_required=False)
            return
        try:
            if self.child is not None and self.child.poll() is None:
                self.final_probe()
            self.owner.close()
            if self.child is not None:
                self.child.wait(timeout=20)
            stopped = self.child is None or self.child.poll() is not None
            self.evidence["owned_emulator_stopped"] = stopped
            deadline = time.monotonic() + 10
            while True:
                closed = True
                for port in (base.PORT, base.PORT + 1):
                    with socket.socket() as probe:
                        probe.settimeout(0.2)
                        closed = closed and probe.connect_ex(("127.0.0.1", port)) != 0
                if closed or time.monotonic() >= deadline:
                    break
                time.sleep(0.2)
            self.evidence["owned_emulator_ports_closed"] = closed
            require(stopped and closed, "BOOT_CLEANUP_UNCERTAIN")
        except BaseException as error:
            self.evidence["cleanup_failure"] = base.failure_metadata(error)
            raise base.EmulatorError("BOOT_CLEANUP_UNCERTAIN") from None


def verify_sources():
    observed = {name: base.digest(ROOT / name) for name in FROZEN}
    require(observed == FROZEN, "BOOT_SOURCE_CHANGED")
    return observed


def execute():
    require(os.name == "nt", "BOOT_WINDOWS_REQUIRED")
    libraries = verify_sources()
    before = host_sample()
    require(before["workspace_disk_free_bytes"] >= 12 * 1024**3, "BOOT_DISK_REQUIRED")
    tools = base.AndroidTools()
    parent = base.checked_path(ROOT / ".cache/m1-runtime/mobile-boot")
    parent.mkdir(parents=True, exist_ok=True)
    run = base.checked_path(parent / secrets.token_hex(12))
    own_sources = {name: base.digest(ROOT / name) for name in
                   ("infra/mobile_boot_diagnostic.py", "infra/test_mobile_boot_diagnostic.py")}
    evidence = {"task": "TASK-096", "ok": False, "libraries": libraries, "host_before": before,
                "diagnostic_sources_sha256": own_sources,
                "database_started": False, "api_started": False, "packages_installed": False,
                "credentials_configured": False, "physical_phone": False}
    with BootLease(run) as lease:
        emulator = BootEmulator(tools, lease, run)
        try:
            with emulator:
                evidence["boot_gate_passed"] = True
            require(emulator.evidence.get("owned_emulator_stopped") is True and
                    emulator.evidence.get("owned_emulator_ports_closed") is True, "BOOT_CLEANUP_UNCERTAIN")
            verify_sources()
            evidence["ok"] = True
        except BaseException as error:
            evidence["code"] = failure_code(error)
            evidence["failure"] = base.failure_metadata(error)
            raise
        finally:
            if not emulator.closed:
                emulator.__exit__(*sys.exc_info())
            evidence["emulator"] = emulator.evidence
            evidence["diagnostic"] = emulator.diagnostic
            evidence["host_after"] = host_sample()
            evidence["host_cpu_busy_percent_over_interval"] = cpu_interval(before, evidence["host_after"])
            evidence["libraries_unchanged"] = {name: base.digest(ROOT / name) for name in FROZEN} == libraries
            evidence["diagnostic_sources_unchanged"] = {name: base.digest(ROOT / name) for name in own_sources} == own_sources
            if not evidence["libraries_unchanged"] or not evidence["diagnostic_sources_unchanged"]:
                evidence.update(ok=False, code="BOOT_SOURCE_CHANGED")
            lease.assert_owned()
            encoded = json.dumps(evidence, indent=2) + "\n"
            require(len(encoded.encode("utf-8")) <= 16384, "BOOT_RESULT_BOUND")
            with base.checked_path(run / "result.json").open("x", encoding="utf-8") as output:
                output.write(encoded)
            print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    require(evidence["ok"], evidence.get("code", "BOOT_OTHER_FAILURE"))
    return evidence


def main():
    try:
        execute()
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "code": failure_code(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
