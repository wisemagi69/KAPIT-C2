"""Finite read-only observations of the workspace-owned PostgreSQL installation.

Never connects to PostgreSQL, prepares credentials, or changes runtime files.
Existing log categories are historical observations, not launch attribution.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import stat

from infra import native_postgres as native

CONFIG_NAMES = {"postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"}
LOG_LIMIT = 65536
CONDITIONS = {
    "TOKEN_RESTRICTION": (b"restricted token", b"createrestrictedtoken", b"restricting privileges"),
    "PERMISSION_DENIED": (b"permission denied", b"access is denied"),
    "PORT_UNAVAILABLE": (b"address already in use", b"could not bind"),
    "PID_LOCK_PRESENT": (b'lock file "postmaster.pid" already exists',),
    "SHUTDOWN_RECORDED": (b"database system is shut down",),
    "READY_RECORDED": (b"database system is ready to accept connections",),
}


class Unavailable(Exception):
    """Internal fixed finite state; never contains input or an exception string."""


def _stamp(value):
    # Windows lstat and fstat expose different ctime semantics after a rewrite.
    # Compare ctime separately on the same descriptor, never across these APIs.
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)


def _plain(path, *, directory=False):
    value = path.lstat()
    if (stat.S_ISLNK(value.st_mode)
            or getattr(value, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
            or not directory and value.st_nlink != 1):
        raise Unavailable("UNSAFE")
    return value


def _parents(path):
    # Include every existing ancestor, also for external authenticated binaries.
    return [(parent, _plain(parent, directory=True)) for parent in reversed(path.parents)]


def _read_bound(path, limit):
    """Reject nonregular/link/reparse/oversized/changing inputs; no writes."""
    path = Path(path).absolute()
    parents = _parents(path)
    before = _plain(path)
    if before.st_size > limit:
        raise Unavailable("OVERSIZED")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _stamp(before) != _stamp(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise Unavailable("CHANGED")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if (len(content) > limit or _stamp(opened) != _stamp(after)
                or opened.st_ctime_ns != after.st_ctime_ns or _stamp(after) != _stamp(_plain(path))):
            raise Unavailable("CHANGED")
        for parent, previous in parents:
            current = _plain(parent, directory=True)
            if (previous.st_dev, previous.st_ino) != (current.st_dev, current.st_ino):
                raise Unavailable("CHANGED")
        return content, _stamp(after)
    finally:
        os.close(descriptor)


def read_bounded(path, limit):
    return _read_bound(path, limit)[0]


def authenticate():
    """Bound all reads before using the existing public version readback only."""
    for path in (native.CLUSTER_ROOT, native.DATA, native.MARKER):
        native.checked_path(path)
    marker, marker_stamp = _read_bound(native.MARKER, 16384)
    info = json.loads(marker)
    expected = {"schema": 1, "workspace": str(native.ROOT.resolve()),
                "data": str(native.DATA.resolve()), "port": native.PORT}
    if (not isinstance(info, dict) or any(info.get(key) != value for key, value in expected.items())
            or info.get("phase") not in {"initializing", "ready"}):
        raise ValueError
    binaries = info["binaries"]
    if (not isinstance(binaries, dict) or set(binaries) != {"directory", "version", "hashes"}
            or not isinstance(binaries["directory"], str) or not Path(binaries["directory"]).is_absolute()
            or not isinstance(binaries["version"], str)
            or not any(binaries["version"].startswith(f"postgres (PostgreSQL) {major}.") for major in (17, 18))
            or not isinstance(binaries["hashes"], dict) or set(binaries["hashes"]) != set(native.TOOLS)):
        raise ValueError
    snapshots = [(native.MARKER, marker_stamp)]
    for name in native.TOOLS:
        path = Path(native.binary(info, name))
        content, bound_stamp = _read_bound(path, 128 * 1024 * 1024)
        if hashlib.sha256(content).hexdigest() != binaries["hashes"][name]:
            raise ValueError
        snapshots.append((path, bound_stamp))
    if info["phase"] == "ready":
        configs = info["config_hashes"]
        if not isinstance(configs, dict) or set(configs) != CONFIG_NAMES:
            raise ValueError
        for name in sorted(CONFIG_NAMES):
            path = native.DATA / name
            content, bound_stamp = _read_bound(path, 1048576)
            if hashlib.sha256(content).hexdigest() != configs[name]:
                raise ValueError
            snapshots.append((path, bound_stamp))
    # This is the sole child command: a pinned public executable's --version.
    # It is never a daemon, pg_ctl, SQL, process inspection, or credential setup.
    if any(_stamp(_plain(path)) != stamp for path, stamp in snapshots):
        raise Unavailable("CHANGED")
    version = native.execute([native.binary(info, "postgres"), "--version"], timeout=5).stdout.strip()
    if version != binaries["version"] or read_bounded(native.MARKER, 16384) != marker:
        raise ValueError
    if any(_stamp(_plain(path)) != stamp for path, stamp in snapshots):
        raise Unavailable("CHANGED")
    return info


def token_restriction():
    """Observe the current token only; never enumerate users, groups or IDs."""
    if os.name != "nt":
        return "NOT_SUPPORTED"
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.IsTokenRestricted.argtypes = [wintypes.HANDLE]
    advapi.IsTokenRestricted.restype = wintypes.BOOL
    handle = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(handle)):
        return "UNAVAILABLE"
    try:
        return "RESTRICTED" if advapi.IsTokenRestricted(handle) else "NOT_RESTRICTED"
    finally:
        kernel.CloseHandle(handle)


def _observation(path, limit):
    try:
        return "OBSERVED", read_bounded(path, limit)
    except FileNotFoundError:
        return "ABSENT", None
    except Unavailable as error:
        return ("OVERSIZED" if error.args == ("OVERSIZED",) else "UNAVAILABLE"), None
    except (OSError, ValueError, RuntimeError):
        return "UNAVAILABLE", None


def diagnose():
    report = {"schema_version": 1, "ownership": "UNAVAILABLE", "initialization": "UNKNOWN",
              "pid_file": "NOT_INSPECTED", "log": "NOT_INSPECTED", "log_conditions": [],
              "log_attribution": "EXISTING_LOG_NOT_BOUND_TO_FAILED_ATTEMPT",
              "current_token": "UNAVAILABLE", "cause": "UNCONFIRMED", "readiness": "UNVERIFIED",
              "next_actions": ["SHARE_FINITE_DIAGNOSTIC_FOR_REVIEW"]}
    try:
        report["current_token"] = token_restriction()
    except (OSError, ValueError, AttributeError):
        pass
    try:
        info = authenticate()
    except FileNotFoundError:
        report["ownership"] = "ABSENT"
        return report
    except (ValueError, KeyError, TypeError, RuntimeError, RecursionError):
        report["ownership"] = "INVALID"
        return report
    except (OSError, Unavailable):
        return report
    report["ownership"] = "VERIFIED"
    report["initialization"] = "READY" if info["phase"] == "ready" else "INCOMPLETE"
    if info["phase"] != "ready":
        return report
    state, content = _observation(native.DATA / "postmaster.pid", 4096)
    report["pid_file"] = state
    if content is not None:
        try:
            rows = content.decode("utf-8").splitlines()
            if (not 0 < int(rows[0]) <= 2147483647 or Path(rows[1]) != native.DATA.resolve()
                    or int(rows[2]) <= 0 or int(rows[3]) != native.PORT or rows[5] != "127.0.0.1"):
                raise ValueError
            report["pid_file"] = "PRESENT_VALIDATED_PROCESS_UNVERIFIED"
        except (ValueError, IndexError, UnicodeError):
            report["pid_file"] = "INVALID"
    state, content = _observation(native.CLUSTER_ROOT / "server.log", LOG_LIMIT)
    report["log"] = state
    if content is not None:
        lowered = content.lower()
        report["log_conditions"] = [name for name, phrases in CONDITIONS.items() if any(p in lowered for p in phrases)]
    return report


def exit_code(report):
    return 0 if (report["ownership"] == "VERIFIED" and report["initialization"] == "READY"
                 and report["pid_file"] in {"ABSENT", "PRESENT_VALIDATED_PROCESS_UNVERIFIED"}
                 and report["log"] in {"ABSENT", "OBSERVED"}
                 and report["current_token"] != "UNAVAILABLE") else 2


def main():
    report = diagnose()
    print(json.dumps(report, indent=2))
    raise SystemExit(exit_code(report))
