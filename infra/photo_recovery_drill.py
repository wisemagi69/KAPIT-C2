"""Opt-in encrypted photo recovery over the genuinely leased disposable test DB.

Default preparation has no DB/key/native side effects. Only the orchestrator runs
the opted-in Django TransactionTestCase; no target, path, PID or key CLI exists.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from infra import live_recovery_drill as live
from infra import restore_rehearsal as restore

LIVE_SHA256 = "cd6d9608399f0995b865da142611432b0c8a95ea1a9501b143dabebdc004388c"
COUNTS = ("originals_verified", "legacy_verified", "capture_verified", "located_verified",
          "derivatives_verified", "provenance_verified")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_OUTPUT = 65536
OPT_IN = "KAPIT_PHOTO_RECOVERY_DRILL"


class PhotoRecoveryError(RuntimeError):
    """Fixed codes, never native/SQL/key/ciphertext exception messages."""


def require(condition, code="PHOTO_RECOVERY_UNAVAILABLE"):
    if not condition:
        raise PhotoRecoveryError(code)


def preparation():
    return {"schema": 1, "status": "PREPARED_NOT_EXECUTED", "scope": "DISPOSABLE_TEST_COHORT",
            "application": "CLOSED", "native_validation": "NOT_PROVEN_BY_THIS_TEST",
            "requires": ["ROOT_EXCLUSIVE_RESERVATION", "EXPLICIT_OPT_IN", "ACTUAL_DATABASE_LEASE_AND_ADVISORY_LOCK",
                         "EXACT_TEST_DATABASE_OID", "COMMITTED_SYNTHETIC_COHORT", "FRESH_PRIVATE_RESTORE_CHILD"]}


def unchanged_runners():
    live.runner_unchanged()
    require(hashlib.sha256(Path(live.__file__).read_bytes()).hexdigest() == LIVE_SHA256, "REVIEWED_RUNNER_CHANGED")


def summary_closed(value):
    require(type(value) is dict and set(value) == set(COUNTS) | {"integrity", "current_delivery", "native_validation"})
    require(all(type(value[name]) is int and 0 < value[name] <= 100 for name in COUNTS))
    require(value["integrity"] == "VERIFIED" and value["current_delivery"] == "NOT_EVALUATED"
            and value["native_validation"] == "NOT_PROVEN_BY_THIS_TEST")
    return dict(value)


def pgpass_value(value):
    require(type(value) is str and 0 < len(value) <= 4096 and not any(c in value for c in "\r\n\x00"))
    return value.replace("\\", "\\\\").replace(":", "\\:")


class _PipeReader:
    """Bounded pipe draining; raw output is never retained or reflected."""
    def __init__(self, stream, *, destination=None, limit=MAX_OUTPUT):
        self.stream, self.destination, self.limit = stream, destination, limit
        self.count, self.failed, self.overflow = 0, False, False

    def read(self):
        try:
            while chunk := self.stream.read(65536):
                self.count += len(chunk)
                if self.count > self.limit:
                    self.overflow = True
                    break
                if self.destination is not None:
                    self.destination.write(chunk)
            if self.destination is not None:
                self.destination.flush()
        except Exception:
            self.failed = True
        finally:
            try:
                self.stream.close()
            except Exception:
                self.failed = True


def stop_client(client):
    """Only the direct Popen handle; no PID lookup, process adoption or tree kill."""
    if client.poll() is None:
        client.terminate()
        try:
            client.wait(timeout=10)
        except subprocess.TimeoutExpired:
            client.kill()
            client.wait(timeout=10)
    else:
        client.wait(timeout=10)
    require(client.poll() is not None, "ARCHIVE_CLIENT_STOP_UNCONFIRMED")


def bounded_command(runtime, name, args, *, env, timeout, destination=None, output_limit=MAX_OUTPUT):
    """Actual pinned native client, bounded pipes/file and owned direct cleanup."""
    path, digest = runtime.tools[name]
    require(runtime.native.digest(Path(path)) == digest, "RESTORE_BINARY_CHANGED")
    require(type(timeout) is int and 1 <= timeout <= 600)
    client, threads, readers = None, [], []
    try:
        client = subprocess.Popen([path, *args], cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        readers = [_PipeReader(client.stdout, destination=destination, limit=output_limit), _PipeReader(client.stderr)]
        for reader in readers:
            thread = threading.Thread(target=reader.read, daemon=True)
            thread.start()
            threads.append(thread)
        deadline = time.monotonic() + timeout
        while client.poll() is None:
            require(not any(r.failed or r.overflow for r in readers), "ARCHIVE_OUTPUT_LIMIT")
            require(time.monotonic() < deadline, "ARCHIVE_COMMAND_TIMEOUT")
            time.sleep(0.02)
        for thread in threads:
            thread.join(timeout=5)
        require(not any(t.is_alive() for t in threads) and not any(r.failed or r.overflow for r in readers), "ARCHIVE_OUTPUT_LIMIT")
        require(client.returncode == 0 and time.monotonic() <= deadline, "ARCHIVE_COMMAND_FAILED")
    finally:
        # BaseException propagates only after the direct client and readers have
        # been handled; an uncertain stop cannot become a positive receipt.
        if client is not None:
            try:
                stop_client(client)
            finally:
                for stream in (client.stdout, client.stderr):
                    try:
                        stream.close()
                    except Exception:
                        pass
                for thread in threads:
                    thread.join(timeout=5)
                require(not any(t.is_alive() for t in threads), "ARCHIVE_CLIENT_STOP_UNCONFIRMED")


class PhotoRuntime(live.PrivateRuntime):
    """Only source/archive capabilities differ; reviewed child guards are reused."""
    def __init__(self, reservation):
        super().__init__(reservation)
        self.archive = None
        self.archive_hash = None

    def guard_source(self):
        from django.db import connection
        from tests import browser_runner as guard
        lease = guard.ACTIVE_DATABASE_LEASE
        require(type(lease) is guard.DatabaseLease and lease.locked and type(lease.owned_oid) is int,
                "PHOTO_DATABASE_LEASE_REQUIRED")
        require(lease is self.lease and lease.owned_oid == self.source_oid, "PHOTO_DATABASE_LEASE_CHANGED")
        guard.require_target(connection.settings_dict, os.environ, running_test=True)
        require(not connection.in_atomic_block and connection.get_autocommit(), "PHOTO_COMMITTED_SOURCE_REQUIRED")
        lease.assert_owned()
        with lease.connection.cursor() as cursor:
            cursor.execute("SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND pid=pg_backend_pid() "
                           "AND classid=0 AND objid=%s AND objsubid=1 AND granted", [guard.ADVISORY_LOCK])
            require(cursor.fetchone() == (1,), "PHOTO_ADVISORY_LOCK_REQUIRED")
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(),d.oid,pg_get_userbyid(d.datdba),current_user "
                           "FROM pg_database d WHERE d.datname=current_database()")
            require(tuple(cursor.fetchone() or ()) == (guard.TEST_DATABASE, self.source_oid, "kapit_m1", "kapit_m1"),
                    "PHOTO_SOURCE_IDENTITY_CHANGED")
        require(self.native.ownership() == self.info, "SOURCE_OWNER_CHANGED")
        self.native.status(require_running=True)

    def preflight(self):
        require(os.environ.get(OPT_IN) == "1", "PHOTO_EXPLICIT_OPT_IN_REQUIRED")
        require(not any(key.upper().startswith("PG") for key in os.environ), "LIBPQ_ENVIRONMENT_UNSAFE")
        from django.db import connection
        from tests import browser_runner as guard
        guard.require_target(connection.settings_dict, os.environ, running_test=True)
        lease = guard.ACTIVE_DATABASE_LEASE
        require(type(lease) is guard.DatabaseLease and lease.locked and type(lease.owned_oid) is int,
                "PHOTO_DATABASE_LEASE_REQUIRED")
        self.lease, self.source_oid = lease, lease.owned_oid
        self.info = self.native.ownership()
        self.guard_source()
        with connection.cursor() as cursor:
            cursor.execute("SELECT oid,pg_get_userbyid(datdba) FROM pg_database WHERE datname='kapit_m1'")
            retained = cursor.fetchone()
            require(retained is not None and type(retained[0]) is int and retained[1] == "kapit_m1", "PHOTO_RETAINED_IDENTITY_CHANGED")
            self.retained_oid = retained[0]
        import psycopg
        self.psycopg = psycopg
        self.source_password = connection.settings_dict.get("PASSWORD")
        pgpass_value(self.source_password)
        self.tools = {}
        for name in ("postgres", "initdb", "pg_ctl", "createdb", "pg_dump", "pg_restore"):
            path = Path(self.native.binary(self.info, name))
            require(path.is_file() and not path.is_symlink()
                    and path.parent.resolve() == Path(self.info["binaries"]["directory"]).resolve(), "RESTORE_BINARY_PROVENANCE")
            version = self.native.execute([str(path), "--version"], timeout=10).stdout
            match = re.search(r"\(PostgreSQL\) (\d+)\.", version)
            require(match is not None and int(match.group(1)) in (17, 18), "RESTORE_BINARY_PROVENANCE")
            major = int(match.group(1))
            require(not self.tools or major == self.major, "RESTORE_BINARY_PROVENANCE")
            self.major = major
            digest = self.native.digest(path)
            require(self.info["binaries"]["hashes"].get(name, digest) == digest, "RESTORE_BINARY_PROVENANCE")
            self.tools[name] = (str(path), digest)
        self.tree, self.code_hash = restore.migration_inventory(), restore.code_fingerprint()
        self.source_snapshot()

    @contextmanager
    def source_connection(self, *, retained=False):
        self.guard_source()
        with self.psycopg.connect(host="127.0.0.1", hostaddr="127.0.0.1", port=self.native.PORT,
                dbname="kapit_m1" if retained else "test_kapit_m1", user="kapit_m1", password=self.source_password,
                sslmode="disable", connect_timeout=5,
                options="-c default_transaction_read_only=on -c timezone=UTC -c datestyle=ISO,YMD") as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                cursor.execute("SELECT current_database(),current_setting('data_directory'),current_setting('port'),"
                               "current_setting('listen_addresses'),current_user,extract(epoch from pg_postmaster_start_time())::bigint,"
                               "d.oid,pg_get_userbyid(d.datdba) FROM pg_database d WHERE d.datname=current_database()")
                name, directory, port, bind, user, started, actual_oid, owner = cursor.fetchone()
                require(name == ("kapit_m1" if retained else "test_kapit_m1")
                        and type(actual_oid) is int and actual_oid == (self.retained_oid if retained else self.source_oid)
                        and owner == "kapit_m1"
                        and Path(directory).resolve() == self.native.DATA.resolve() and port == str(self.native.PORT)
                        and bind == "127.0.0.1" and user == "kapit_m1"
                        and abs(started - self.info["process"]["started"]) <= 2, "PHOTO_SOURCE_IDENTITY_CHANGED")
            yield connection

    def source_snapshot(self, *, retained=False):
        with self.source_connection(retained=retained) as connection:
            value = restore.database_snapshot(connection)
        apps = {app for app, _ in self.tree}
        require(sorted(tuple(row) for row in value["migrations"] if row[0] in apps) == self.tree
                and restore.code_fingerprint() == self.code_hash, "CURRENT_CODE_SCHEMA_MISMATCH")
        self.guard_source()
        return value

    def private_baseline(self):
        paths = (self.local.SECRET_FILE, self.local.CACHE / "backend.env", self.local.CACHE / "db.env", self.native.MARKER,
                 *(self.native.DATA / name for name in ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")))
        return {path: live.fingerprint(self, path, live.MAX_PRIVATE) for path in paths}

    def old_archives(self):
        directory = self.checked(self.local.BACKUP_DIR)
        require(directory.is_dir(), "BACKUP_DIRECTORY_INVALID")
        paths = sorted(directory.iterdir())
        require(len(paths) <= 256, "ARCHIVE_INVENTORY_LIMIT")
        result, total = {}, 0
        for path in paths:
            self.checked(path)
            require(path.is_file(), "ARCHIVE_INVENTORY_INVALID")
            total += path.stat().st_size
            require(total <= 512 * 1024 * 1024, "ARCHIVE_INVENTORY_LIMIT")
            result[path] = live.fingerprint(self, path, MAX_ARCHIVE)
        return result

    def environment(self, *, source=False):
        self.check_owner()
        env = {key: value for key, value in self.native.clean_environment().items()
               if not key.upper().startswith(("PG", "KAPIT_"))}
        env.update(PGPASSFILE=str(self.target / ("source.pgpass" if source else "pgpass")),
                   PGAPPNAME="kapit-photo-recovery-" + self.token, LC_ALL="C", LANG="C")
        return env

    def dump(self):
        self.guard_source()
        self.check_owner()
        self.archive = self.checked(self.target / "photo-cohort.dump")
        require(self.archive.parent == self.target and not self.archive.exists(), "ARCHIVE_PREEXISTS")
        passfile = self.checked(self.target / "source.pgpass")
        self.local.write_private(passfile, "127.0.0.1:55436:test_kapit_m1:kapit_m1:" + pgpass_value(self.source_password) + "\n")
        args = ["--format=custom", "--no-owner", "--no-acl", "--no-blobs", "-w", "-h", "127.0.0.1", "-p", "55436",
                "-U", "kapit_m1", "--dbname=test_kapit_m1"]
        with live.exclusive_binary(self.archive) as destination:
            bounded_command(self, "pg_dump", args, env=self.environment(source=True), timeout=180,
                            destination=destination, output_limit=MAX_ARCHIVE)
            destination.flush()
            os.fsync(destination.fileno())
        self.archive_hash = live.fingerprint(self, self.archive, MAX_ARCHIVE)
        require(self.archive.stat().st_size >= 5, "ARCHIVE_INVALID")
        with self.archive.open("rb") as source:
            require(source.read(5) == b"PGDMP", "ARCHIVE_INVALID")
        bounded_command(self, "pg_restore", ["--list", str(self.archive)], env=self.environment(), timeout=30)
        self.guard_source()

    def restore(self):
        self.guard_source()
        self.verify_child()
        require(live.fingerprint(self, self.archive, MAX_ARCHIVE) == self.archive_hash, "BACKUP_CHANGED")
        bounded_command(self, "pg_restore", ["--exit-on-error", "--no-owner", "--no-acl", "-w", "-h", "127.0.0.1",
                "-p", str(self.port), "-U", self.user, "-d", self.database, str(self.archive)],
                env=self.environment(), timeout=600)
        self.guard_source()

    @contextmanager
    def restored_connection(self):
        self.verify_child()
        with self.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            yield connection

    def verify(self, *, key, expected_cohort):
        from cryptography.fernet import Fernet
        from apps.operations.evidence_recovery import verify_restored_evidence
        with self.restored_connection() as connection:
            return summary_closed(verify_restored_evidence(connection, decrypt_bytes=Fernet(key).decrypt,
                                                           expected_cohort=expected_cohort).as_dict())

    def recovery_key(self, name):
        require(name in {"recovery.key", "missing-recovery.key", "wrong-recovery.key"})
        self.check_owner()
        path = self.checked(self.target / name)
        require(path.parent == self.target, "RECOVERY_KEY_INVALID")
        try:
            live.fingerprint(self, path, 44)
        except FileNotFoundError:
            raise
        except Exception:
            raise PhotoRecoveryError("RECOVERY_KEY_INVALID") from None
        with path.open("rb") as stream:
            key = stream.read(45)
        require(type(key) is bytes and len(key) == 44, "RECOVERY_KEY_INVALID")
        return key

    def negative_integrity(self, *, key, expected_cohort):
        """Corrupt private copied records AFTER actual restore; never UPDATE SQL."""
        from cryptography.fernet import Fernet
        from apps.operations import evidence_recovery as verifier
        crypto = Fernet(key)
        cases = []
        def denied(name, action):
            try:
                action()
            except verifier.RecoveryError:
                cases.append(name)
                return
            raise PhotoRecoveryError("NEGATIVE_INTEGRITY_NOT_DENIED")
        try:
            self.recovery_key("missing-recovery.key")
        except FileNotFoundError:
            cases.append("OWNED_RECOVERY_KEY_FILE_MISSING")
        else:
            raise PhotoRecoveryError("MISSING_KEY_NOT_OBSERVED")
        wrong = Fernet.generate_key()
        require(wrong != key)
        self.local.write_private(self.target / "wrong-recovery.key", wrong.decode("ascii"))
        denied("WRONG_KEY_RESTORED_EVIDENCE_DENIED",
               lambda: self.verify(key=self.recovery_key("wrong-recovery.key"), expected_cohort=expected_cohort))
        with self.restored_connection() as connection:
            located_id = next(identifier for identifier, item in expected_cohort.items()
                              if item.capture_json is not None and json.loads(item.capture_json)["location"] is not None)
            original = verifier.read_original(connection, located_id)
            binding = verifier.verify_original(original, decrypt_bytes=crypto.decrypt)
            value = json.loads(crypto.decrypt(original.payload_ciphertext))
            latitude = value["capture"]["location"]["latitude_e7"]
            value["capture"]["location"]["latitude_e7"] = latitude + 1 if latitude < 900000000 else latitude - 1
            changed = replace(original, payload_ciphertext=crypto.encrypt(verifier.canonical(value)))
            denied("REENCRYPTED_CAPTURE_BINDING_DENIED", lambda: verifier.verify_original(changed, decrypt_bytes=crypto.decrypt))
            changed = replace(original, revision_id="00000000-0000-4000-8000-000000000000")
            denied("REVISION_BINDING_DENIED", lambda: verifier.verify_original(changed, decrypt_bytes=crypto.decrypt))
            evidence_id, expected = next((identifier, item) for identifier, item in expected_cohort.items() if item.derivatives)
            validation = verifier.read_validation(connection, expected.derivatives[0][0])
            actual_original = verifier.read_original(connection, evidence_id)
            actual_binding = verifier.verify_original(actual_original, decrypt_bytes=crypto.decrypt)
            denied("PROVENANCE_BINDING_DENIED", lambda: verifier.verify_validation(
                replace(validation, manifest_hash="0" * 64 if validation.manifest_hash != "0" * 64 else "1" * 64),
                actual_binding, decrypt_bytes=crypto.decrypt))
            different_id = next(identifier for identifier in expected_cohort if identifier != evidence_id)
            different = verifier.verify_original(verifier.read_original(connection, different_id), decrypt_bytes=crypto.decrypt)
            denied("SWAPPED_VALIDATION_SOURCE_DENIED", lambda: verifier.verify_validation(validation, different, decrypt_bytes=crypto.decrypt))
            damaged = bytearray(validation.derivative_ciphertext)
            damaged[-1] ^= 1
            denied("TAMPERED_DERIVATIVE_DENIED", lambda: verifier.verify_validation(
                replace(validation, derivative_ciphertext=bytes(damaged)), actual_binding, decrypt_bytes=crypto.decrypt))
        return cases


def archive_restore(*, execute=False, reservation=None, expected_cohort=None, recovery_key=None):
    if execute is not True:
        return preparation()
    result = {"schema": 1, "status": "UNAVAILABLE", "scope": "DISPOSABLE_TEST_COHORT", "application": "CLOSED",
              "native_validation": "NOT_PROVEN_BY_THIS_TEST", "current_delivery": "NOT_EVALUATED",
              "cleanup": "NOT_STARTED", "phases": [], "negative_cases": [], "source_preserved": False,
              "retained_preserved": False, "private_files_preserved": False, "archives_preserved": False,
              "fixture_key_preserved": False}
    if os.environ.get(OPT_IN) != "1":
        return result | {"code": "PHOTO_EXPLICIT_OPT_IN_REQUIRED"}
    if type(reservation) is not str or not restore.TOKEN.fullmatch(reservation):
        return result | {"code": "RESERVATION_REQUIRED"}
    if type(recovery_key) is not bytes or len(recovery_key) != 44 or type(expected_cohort) is not dict or not 1 <= len(expected_cohort) <= 16:
        return result | {"code": "GUARDED_TEST_COHORT_REQUIRED"}
    driver, source, retained, private, archives, reserved = None, None, None, None, None, False
    success = False
    try:
        unchanged_runners()
        driver = PhotoRuntime(reservation)
        driver.preflight()
        source, retained = driver.source_snapshot(), driver.source_snapshot(retained=True)
        private, archives = driver.private_baseline(), driver.old_archives()
        result["phases"].append("LEASED_SOURCE_AND_PRESERVATION_CAPTURED")
        reserved = True
        driver.reserve()
        driver.local.write_private(driver.target / "recovery.key", recovery_key.decode("ascii"))
        require(driver.recovery_key("recovery.key") == recovery_key, "RECOVERY_KEY_INVALID")
        fixture_key_hash = live.fingerprint(driver, driver.target / "recovery.key", 44)
        driver.dump()
        require(driver.source_snapshot() == source, "PHOTO_SOURCE_CHANGED")
        result["phases"].append("FRESH_PRIVATE_TEST_ARCHIVE_VERIFIED")
        driver.initialize()
        driver.start()
        driver.restore()
        require(driver.restored_snapshot() == source, "RESTORED_SNAPSHOT_MISMATCH")
        result["phases"].append("FRESH_CHILD_RESTORED_SNAPSHOT_EQUAL")
        result["summary"] = driver.verify(key=driver.recovery_key("recovery.key"), expected_cohort=expected_cohort)
        summary_closed(result["summary"])
        result["phases"].append("RESTORED_CIPHERTEXT_DECRYPTED_AND_BOUND")
        result["negative_cases"] = driver.negative_integrity(key=driver.recovery_key("recovery.key"), expected_cohort=expected_cohort)
        require(result["negative_cases"] == ["OWNED_RECOVERY_KEY_FILE_MISSING", "WRONG_KEY_RESTORED_EVIDENCE_DENIED",
            "REENCRYPTED_CAPTURE_BINDING_DENIED", "REVISION_BINDING_DENIED", "PROVENANCE_BINDING_DENIED",
            "SWAPPED_VALIDATION_SOURCE_DENIED", "TAMPERED_DERIVATIVE_DENIED"], "NEGATIVE_INTEGRITY_NOT_DENIED")
        success = True
    except Exception:
        result["code"] = "PHOTO_RECOVERY_UNAVAILABLE"
    finally:
        if reserved:
            try:
                result["cleanup"] = driver.stop_owned()
                require(result["cleanup"] in {"NOT_STARTED", "STOPPED_VERIFIED"})
            except Exception:
                result["cleanup"] = "STOP_UNCONFIRMED"
            if result["cleanup"] != "STOPPED_VERIFIED":
                success = False
                result["code"] = "CHILD_STOP_UNCONFIRMED"
        if driver is not None and source is not None and retained is not None and private is not None and archives is not None:
            try:
                unchanged_runners()
                result["source_preserved"] = driver.source_snapshot() == source
                result["retained_preserved"] = driver.source_snapshot(retained=True) == retained
                result["private_files_preserved"] = driver.private_baseline() == private
                result["archives_preserved"] = driver.old_archives() == archives and driver.archive is not None and driver.archive_hash is not None \
                    and live.fingerprint(driver, driver.archive, MAX_ARCHIVE) == driver.archive_hash
                result["fixture_key_preserved"] = reserved and "fixture_key_hash" in locals() and \
                    live.fingerprint(driver, driver.target / "recovery.key", 44) == fixture_key_hash
                require(all(result[name] for name in ("source_preserved", "retained_preserved", "private_files_preserved", "archives_preserved", "fixture_key_preserved")))
            except Exception:
                success = False
                result.update(code="FINAL_PRESERVATION_UNAVAILABLE", source_preserved=False, retained_preserved=False,
                              private_files_preserved=False, archives_preserved=False, fixture_key_preserved=False)
    if success:
        result.update(status="ENCRYPTED_EVIDENCE_ARCHIVE_RECOVERY_VERIFIED", code="DISPOSABLE_ENCRYPTED_EVIDENCE_VERIFIED")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    # Execution is available only to the genuine guarded Django test capability;
    # no CLI request can supply a target, key, fixture, driver or fault switch.
    print(json.dumps(preparation(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
