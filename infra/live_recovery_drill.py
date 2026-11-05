"""Fixed opt-in recovery drill. Preparation does not read keys or contact runtime.

Only the orchestrator may execute while all application writers are quiescent.
Fault adapters below are explicit test capabilities, never production options.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import restore_rehearsal as restore
from infra.evidence_tools import Windows

RUNNER_SHA256 = "c062ed846d58aa55ff33c9ce1900d803f33b002c074619e86132f6c790ba92d6"
SCENARIOS = ("MISSING_RECOVERY_KEY", "WRONG_RECOVERY_KEY", "CORRUPT_COPY_PARSER", "INTERRUPTED_COPY")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_PRIVATE = 65536
PARSER_REJECTIONS = frozenset({
    b"pg_restore: error: input file does not appear to be a valid archive",
    b"pg_restore: error: input file does not appear to be a valid archive (too short?)",
})


class DrillError(RuntimeError):
    """Internal fixed codes; CLI never reflects exception messages."""


def require(value, code):
    if not value:
        raise DrillError(code)


def preparation():
    return {"schema": 1, "status": "PREPARED_NOT_EXECUTED", "application": "CLOSED", "scope": "DATABASE_ONLY",
            "scenarios": ["POSITIVE", *SCENARIOS], "native_validation": "DISABLED",
            "requires": ["EXCLUSIVE_ROOT_RUNTIME_RESERVATION", "ALL_APPLICATION_WRITERS_QUIESCENT",
                         "UNCHANGED_REVIEWED_RUNNER", "FRESH_OWNED_CHILD_PER_CASE", "PRESERVE_ORIGINAL_KEYS_AND_ARCHIVES"]}


def fingerprint(runtime, path, limit):
    """Checked regular private file; only equality booleans may leave the drill."""
    path = runtime.checked(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, "PRESERVATION_UNAVAILABLE")
    with path.open("rb") as source:
        opened = os.fstat(source.fileno())
        raw = source.read(limit + 1)
        after_open = os.fstat(source.fileno())
    after = runtime.checked(path).stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
    require(len(raw) <= limit and len({identity(s) for s in (before, opened, after_open, after)}) == 1,
            "PRESERVATION_UNAVAILABLE")
    return hashlib.sha256(raw).hexdigest()


def runner_unchanged():
    require(hashlib.sha256(Path(restore.__file__).read_bytes()).hexdigest() == RUNNER_SHA256, "RUNNER_CHANGED")


def exclusive_binary(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600), "wb")


class PrivateDirectory(Windows):
    """Create only a fresh child with its protected DACL atomically, never repair."""
    def __init__(self):
        super().__init__()
        self.k.CreateDirectoryW.argtypes = [w.LPCWSTR, c.c_void_p]
        self.k.CreateDirectoryW.restype = w.BOOL

    def descriptor_text(self):
        sids = list(dict.fromkeys((self.user, "S-1-5-18", "S-1-5-32-544")))
        return "O:" + self.user + "D:P" + "".join("(A;OICI;FA;;;" + sid + ")" for sid in sids)

    def create(self, path):
        descriptor = c.c_void_p()
        require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(self.descriptor_text(), 1, c.byref(descriptor), None),
                "PRIVATE_DIRECTORY_UNAVAILABLE")
        class SecurityAttributes(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]
        attributes = SecurityAttributes(c.sizeof(SecurityAttributes), descriptor, False)
        try:
            require(self.k.CreateDirectoryW(str(path), c.byref(attributes)), "PRIVATE_DIRECTORY_UNAVAILABLE")
        finally:
            self.k.LocalFree(descriptor)

    def verify_acl(self, handle, directory=False):
        require(directory, "PRIVATE_DIRECTORY_UNAVAILABLE")
        owner, dacl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        require(self.a.GetSecurityInfo(handle, 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(descriptor)) == 0,
                "PRIVATE_DIRECTORY_UNAVAILABLE")
        try:
            control, revision = w.WORD(), w.DWORD()
            require(self.a.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)), "PRIVATE_DIRECTORY_UNAVAILABLE")
            require(control.value & 0x1000 and dacl.value and self.sid(owner) == self.user, "PRIVATE_DIRECTORY_UNAVAILABLE")
            count = c.c_ushort.from_address(dacl.value + 4).value
            expected = list(dict.fromkeys((self.user, "S-1-5-18", "S-1-5-32-544")))
            require(count == len(expected), "PRIVATE_DIRECTORY_UNAVAILABLE")
            actual = []
            for index in range(count):
                ace = c.c_void_p()
                require(self.a.GetAce(dacl, index, c.byref(ace)), "PRIVATE_DIRECTORY_UNAVAILABLE")
                require(c.c_ubyte.from_address(ace.value).value == 0 and c.c_ubyte.from_address(ace.value + 1).value == 3
                        and w.DWORD.from_address(ace.value + 4).value == 0x1f01ff, "PRIVATE_DIRECTORY_UNAVAILABLE")
                actual.append(self.sid(ace.value + 8))
            require(actual == expected, "PRIVATE_DIRECTORY_UNAVAILABLE")
        finally:
            self.k.LocalFree(descriptor)


class PrivateRuntime(restore.LocalRuntime):
    """Reviewed lifecycle with a stronger new-child reservation only."""
    def __init__(self, reservation):
        super().__init__(reservation)
        self.private_pin = None

    def reserve(self):
        root = self.checked(ROOT / ".cache/m4-recovery")
        if not root.exists():
            root.mkdir()
            self.local.write_private(root / "owner.json", json.dumps({"schema": 1, "owner": restore.OWNER, "workspace": str(ROOT.resolve())}))
        marker = self.checked(root / "owner.json")
        require(marker.is_file() and marker.stat().st_size <= 4096, "RECOVERY_ROOT_OWNER_INVALID")
        owner = json.loads(marker.read_text(encoding="utf-8"))
        require(isinstance(owner, dict) and type(owner.get("schema")) is int and
                owner == {"schema": 1, "owner": restore.OWNER, "workspace": str(ROOT.resolve())}, "RECOVERY_ROOT_OWNER_INVALID")
        token = restore.secrets.token_hex(16)
        target = self.checked(root / token)
        api = PrivateDirectory()
        api.create(target)  # Atomic CREATE; no existing target is ever adopted.
        self.target, self.token, self.data = target, token, target / "data"
        self.private_pin = api.pin(target, private=True, directory=True)
        self.private_pin.__enter__()  # DACL/owner proof BEFORE any child content.
        self.user, self.database = "kapit_restore_" + token[:16], "kapit_recovery_" + token
        self.password = restore.secrets.token_urlsafe(40)
        self.port_socket = restore.socket.socket(restore.socket.AF_INET, restore.socket.SOCK_STREAM)
        if hasattr(restore.socket, "SO_EXCLUSIVEADDRUSE"):
            self.port_socket.setsockopt(restore.socket.SOL_SOCKET, restore.socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            self.port_socket.bind(("127.0.0.1", 56000 + restore.secrets.randbelow(1000)))
        except OSError:
            self.port_socket.close()
            self.port_socket = None
            raise DrillError("RECOVERY_PORT_UNAVAILABLE") from None
        self.port = self.port_socket.getsockname()[1]
        self.marker = {"schema": 1, "owner": restore.CHILD_OWNER, "workspace": str(ROOT.resolve()), "target": token,
            "data": str(self.data.resolve()), "port": self.port, "reservation_sha256": hashlib.sha256(self.reservation.encode()).hexdigest()}
        self.local.write_private(target / "owner.json", json.dumps(self.marker))
        self.local.write_private(target / "bootstrap.pass", self.password + "\n")
        self.local.write_private(target / "pgpass", f"127.0.0.1:{self.port}:*:{self.user}:{self.password}\n")

    def stop_owned(self):
        try:
            return super().stop_owned()
        finally:
            if self.private_pin is not None:
                pin, self.private_pin = self.private_pin, None
                pin.__exit__(None, None, None)


class FaultRuntime(PrivateRuntime):
    """Fixed fault adapters over the unchanged guarded lifecycle; execution only."""
    def __init__(self, reservation, scenario):
        require(scenario in SCENARIOS, "SCENARIO_REFUSED")
        super().__init__(reservation)
        self.scenario, self.proof = scenario, None
        self.client, self.client_reaped = None, False

    def owned_path(self, name):
        self.check_owner()
        path = self.checked(self.target / name)
        require(path.parent == self.target, "CHILD_PATH_REFUSED")
        return path

    def command_environment(self):
        self.verify_child()
        path, expected = self.tools["pg_restore"]
        require(self.native.digest(Path(path)) == expected, "BINARY_CHANGED")
        passfile = self.owned_path("pgpass")
        fingerprint(self, passfile, 4096)
        env = {key: value for key, value in self.native.clean_environment().items() if not key.upper().startswith("KAPIT_")}
        env.update(PGPASSFILE=str(passfile), PGAPPNAME="kapit-drill-" + self.token, LC_ALL="C", LANG="C")
        return path, env

    def args(self, *options, archive=None):
        return ["--exit-on-error", "--no-owner", "--no-acl", "-w", "-h", "127.0.0.1", "-p", str(self.port),
                "-U", self.user, "-d", self.database, *options, str(self.archive if archive is None else archive)]

    def parser_failure(self):
        original = fingerprint(self, self.archive, MAX_ARCHIVE)
        require(original == self.archive_hash, "ORIGINAL_ARCHIVE_CHANGED")
        copy = self.owned_path("corrupt-copy.dump")
        log = self.owned_path("parser.stderr")
        # Only the owned test copy is deliberately damaged. Its digest is then
        # accepted by this explicit fault capability to reach the native parser.
        with self.archive.open("rb") as source, exclusive_binary(copy) as target:
            target.write(b"BAD!!")
            require(len(source.read(5)) == 5, "COPY_UNAVAILABLE")
            copied = 5
            while chunk := source.read(65536):
                copied += len(chunk)
                require(copied <= MAX_ARCHIVE, "COPY_UNAVAILABLE")
                target.write(chunk)
        copy_hash = fingerprint(self, copy, MAX_ARCHIVE)
        require(copy_hash != original, "COPY_UNAVAILABLE")
        path, env = self.command_environment()
        with exclusive_binary(log) as diagnostic:
            completed = subprocess.run([path, *self.args(archive=copy)], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=diagnostic, timeout=30, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        require(fingerprint(self, copy, MAX_ARCHIVE) == copy_hash and fingerprint(self, self.archive, MAX_ARCHIVE) == original,
                "ORIGINAL_ARCHIVE_CHANGED")
        require(log.stat().st_size <= MAX_PRIVATE, "PARSER_RECEIPT_UNAVAILABLE")
        with self.checked(log).open("rb") as source:
            message = source.read(MAX_PRIVATE + 1).strip()
        require(completed.returncode == 1 and message in PARSER_REJECTIONS, "PARSER_RECEIPT_UNAVAILABLE")
        self.proof = "NATIVE_ARCHIVE_HEADER_REJECTED"
        raise restore.RehearsalError("REHEARSAL_UNAVAILABLE")

    def stop_client(self):
        if self.client is None:
            return None
        if self.client.poll() is None:
            self.client.terminate()  # Direct owned Popen handle only; no PID lookup.
        result = self.client.wait(timeout=10)
        require(result is not None and self.client.poll() is not None, "CLIENT_STOP_UNCONFIRMED")
        self.client_reaped = True
        return result

    def interrupted_copy(self):
        # Schema-only setup has no restored rows; the selected COPY must be
        # observed waiting on our relation lock before any table data is written.
        require(fingerprint(self, self.archive, MAX_ARCHIVE) == self.archive_hash, "ORIGINAL_ARCHIVE_CHANGED")
        self.command("pg_restore", self.args("--schema-only"), timeout=120)
        self.verify_child()
        lock, observer = None, None
        try:
            lock = self.connection()
            observer = self.connection()
            observer.autocommit = True
            with lock.cursor() as cursor:
                cursor.execute("SET LOCAL statement_timeout='10s'")
                cursor.execute("SET LOCAL lock_timeout='5s'")
                cursor.execute("LOCK TABLE public.reports_reportrevision IN ACCESS EXCLUSIVE MODE")
            path, env = self.command_environment()
            require(fingerprint(self, self.archive, MAX_ARCHIVE) == self.archive_hash, "ORIGINAL_ARCHIVE_CHANGED")
            self.client = subprocess.Popen([path, *self.args("--data-only", "--table=reports_reportrevision")],
                cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            deadline, observed = time.monotonic() + 15, False
            while time.monotonic() < deadline:
                require(self.client.poll() is None, "COPY_WAIT_NOT_OBSERVED")
                with observer.cursor() as cursor:
                    cursor.execute("SET statement_timeout='2s'")
                    cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE datname=%s AND usename=%s AND application_name=%s "
                        "AND client_addr='127.0.0.1'::inet AND backend_type='client backend' AND state='active' "
                        "AND wait_event_type='Lock' AND wait_event='relation' AND query LIKE 'COPY public.reports_reportrevision %%'",
                        (self.database, self.user, env["PGAPPNAME"]))
                    observed = cursor.fetchone()[0] == 1
                if observed:
                    break
                time.sleep(0.1)
            require(observed and self.client.poll() is None, "COPY_WAIT_NOT_OBSERVED")
            # Qualifying interruption requires a real live client at the exact
            # observed phase, successful direct terminate and bounded reap.
            self.client.terminate()
            exit_code = self.client.wait(timeout=10)
            require(exit_code is not None and exit_code != 0 and self.client.poll() is not None, "CLIENT_STOP_UNCONFIRMED")
            self.client_reaped = True
            lock.rollback()
            deadline = time.monotonic() + 5
            while True:
                with observer.cursor() as cursor:
                    cursor.execute("SELECT count(*) FROM pg_stat_activity WHERE datname=%s AND usename=%s AND application_name=%s",
                                   (self.database, self.user, env["PGAPPNAME"]))
                    absent = cursor.fetchone()[0] == 0
                if absent or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            require(absent, "CLIENT_BACKEND_UNCONFIRMED")
            with observer.cursor() as cursor:
                cursor.execute("SELECT count(*) FROM public.reports_reportrevision")
                require(cursor.fetchone()[0] == 0, "UNEXPECTED_COPY_EFFECT")
            self.proof = "OWNED_COPY_INTERRUPTED_BEFORE_DATA_WRITE"
        finally:
            try:
                if self.client is not None and not self.client_reaped:
                    self.stop_client()
            finally:
                try:
                    if lock is not None:
                        lock.rollback()
                finally:
                    try:
                        if lock is not None:
                            lock.close()
                    finally:
                        if observer is not None:
                            observer.close()
        raise restore.RehearsalError("REHEARSAL_UNAVAILABLE")

    def restore(self):
        if self.scenario == "CORRUPT_COPY_PARSER":
            return self.parser_failure()
        if self.scenario == "INTERRUPTED_COPY":
            return self.interrupted_copy()
        return super().restore()

    def verify_decryption(self):
        require(self.scenario in {"MISSING_RECOVERY_KEY", "WRONG_RECOVERY_KEY"}, "SCENARIO_REFUSED")
        path = self.owned_path("recovery.key")
        require(not path.exists(), "RECOVERY_KEY_PREEXISTS")
        if self.scenario == "MISSING_RECOVERY_KEY":
            try:
                with path.open("rb") as source:
                    source.read(45)
            except FileNotFoundError:
                self.proof = "OWNED_RECOVERY_KEY_FILE_MISSING_AFTER_RESTORE"
                raise restore.RehearsalError("RESTORE_KEYS_UNAVAILABLE") from None
            raise DrillError("MISSING_KEY_NOT_OBSERVED")
        from cryptography.fernet import InvalidToken
        generated = self.Fernet.generate_key()
        require(generated != self.values["KAPIT_SOURCE_KEY"].encode("ascii"), "KEY_GENERATION_UNAVAILABLE")
        self.local.write_private(path, generated.decode("ascii"))
        require(path.stat().st_size == 44, "KEY_COPY_UNAVAILABLE")
        with self.checked(path).open("rb") as source:
            wrong = source.read(45)
        original = self.source_key
        try:
            self.source_key = self.Fernet(wrong)
            super().verify_decryption()
        except InvalidToken:
            self.proof = "REAL_FERNET_WRONG_RECOVERY_KEY_DENIED"
            raise restore.RehearsalError("RESTORED_SOURCE_INTEGRITY") from None
        finally:
            self.source_key = original
        raise DrillError("WRONG_KEY_NOT_DENIED")

    def stop_owned(self):
        client_ok = True
        try:
            try:
                if self.client is not None and not self.client_reaped:
                    self.stop_client()
            except Exception:
                client_ok = False
        finally:
            # Even a user interrupt during client cleanup must attempt the
            # independently guarded cluster stop, then propagate normally.
            cleanup = super().stop_owned()
        require(client_ok, "CLIENT_STOP_UNCONFIRMED")
        return cleanup


EXPECTED = {"MISSING_RECOVERY_KEY": ("RESTORE_KEYS_UNAVAILABLE", "OWNED_RECOVERY_KEY_FILE_MISSING_AFTER_RESTORE"),
            "WRONG_RECOVERY_KEY": ("RESTORED_SOURCE_INTEGRITY", "REAL_FERNET_WRONG_RECOVERY_KEY_DENIED"),
            "CORRUPT_COPY_PARSER": ("REHEARSAL_UNAVAILABLE", "NATIVE_ARCHIVE_HEADER_REJECTED"),
            "INTERRUPTED_COPY": ("REHEARSAL_UNAVAILABLE", "OWNED_COPY_INTERRUPTED_BEFORE_DATA_WRITE")}


def run(*, execute=False, reservation=None):
    if execute is not True:
        return preparation()
    result = {"schema": 1, "status": "UNAVAILABLE", "application": "CLOSED", "scope": "DATABASE_ONLY",
              "native_validation": "DISABLED", "cases": [], "original_private_files_preserved": False,
              "original_archives_preserved": False, "current_source_equal": False}
    if not isinstance(reservation, str) or not restore.TOKEN.fullmatch(reservation):
        return result | {"code": "RESERVATION_REQUIRED"}
    guard, baseline, private, archives = None, None, {}, {}
    try:
        runner_unchanged()
        from infra import start_local
        require(not start_local.listener_owners(), "APPLICATION_NOT_QUIESCENT")
        guard = restore.LocalRuntime(reservation)
        guard.preflight()
        baseline = guard.source_snapshot()
        private_paths = (guard.local.SECRET_FILE, guard.local.CACHE / "backend.env", guard.local.CACHE / "db.env",
                         guard.native.MARKER, *(guard.native.DATA / name for name in
                         ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")))
        private = {path: fingerprint(guard, path, MAX_PRIVATE) for path in private_paths}
        for scenario in ("POSITIVE", *SCENARIOS):
            runner_unchanged()
            require(not start_local.listener_owners(), "APPLICATION_NOT_QUIESCENT")
            require(guard.source_snapshot() == baseline, "CURRENT_SOURCE_CHANGED")
            require(all(fingerprint(guard, p, MAX_PRIVATE) == h for p, h in private.items()), "PRIVATE_FILES_CHANGED")
            driver = PrivateRuntime(reservation) if scenario == "POSITIVE" else FaultRuntime(reservation, scenario)
            outcome = restore.rehearse(execute=True, reservation=reservation, driver=driver)
            if hasattr(driver, "archive"):
                archives[driver.archive] = driver.archive_hash
            private_equal = all(fingerprint(guard, p, MAX_PRIVATE) == h for p, h in private.items())
            archive_equal = all(fingerprint(guard, p, MAX_ARCHIVE) == h for p, h in archives.items())
            source_equal = guard.source_snapshot() == baseline
            result.update(original_private_files_preserved=private_equal, original_archives_preserved=archive_equal,
                          current_source_equal=source_equal)
            require(private_equal and archive_equal and source_equal, "PRESERVATION_FAILED")
            accepted = outcome["cleanup"] == "STOPPED_VERIFIED"
            if scenario == "POSITIVE":
                accepted = accepted and outcome["status"] == "DATABASE_REHEARSAL_PASSED_CLOSED"
                proof = "PINNED_RUNNER_WITH_PRIVATE_RESERVATION_FULL_RESTORE" if accepted else None
            else:
                code, proof = EXPECTED[scenario]
                accepted = accepted and outcome["status"] == "UNAVAILABLE" and outcome["code"] == code and driver.proof == proof
            result["cases"].append({"scenario": scenario, "expected_behavior_observed": bool(accepted),
                                    "proof": proof if accepted else None, "rehearsal": outcome})
            print(json.dumps({"phase": scenario, "expected_behavior_observed": bool(accepted)}, sort_keys=True), flush=True)
            require(accepted, "SCENARIO_NOT_PROVEN")
        result.update(status="DRILL_PASSED_CLOSED", code="FIXED_FIVE_CASES_VERIFIED")
    except Exception:
        # Fixed envelope only, including driver/probe/parser/SQL/path failures.
        result["code"] = "DRILL_UNAVAILABLE"
    finally:
        if guard is not None and baseline is not None and private:
            try:
                result.update(original_private_files_preserved=all(fingerprint(guard, p, MAX_PRIVATE) == h for p, h in private.items()),
                              original_archives_preserved=bool(archives) and all(fingerprint(guard, p, MAX_ARCHIVE) == h for p, h in archives.items()),
                              current_source_equal=guard.source_snapshot() == baseline)
                require(result["original_private_files_preserved"] and result["original_archives_preserved"] and result["current_source_equal"],
                        "PRESERVATION_FAILED")
                runner_unchanged()
            except Exception:
                result.update(status="UNAVAILABLE", code="FINAL_PRESERVATION_UNAVAILABLE",
                              original_private_files_preserved=False, original_archives_preserved=False, current_source_equal=False)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    result = run(execute=args.execute, reservation=os.environ.get("KAPIT_RESTORE_RESERVATION"))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "DRILL_PASSED_CLOSED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
