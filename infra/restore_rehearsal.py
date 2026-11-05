"""Isolated database-only restore rehearsal. Default preparation never accesses DB/keys.

Execute only during the orchestrator's exclusive runtime reservation. A successful
database rehearsal never starts/reopens an application or certifies file recovery.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OWNER = "KAPIT-C2 isolated recovery v1"
CHILD_OWNER = "KAPIT-C2 isolated restore rehearsal v1"
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
NAME = re.compile(r"[a-z][a-z0-9_]{0,100}\Z")
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
REQUIRED_FUNCTIONS = {"kapit_org_guard", "kapit_frozen_guard", "kapit_source_link_guard", "kapit_decision_guard",
                      "kapit_publication_guard", "kapit_epoch_guard", "kapit_policy_activation_guard", "kapit_client_issue_guard"}
SAFE_CODES = frozenset({"SOURCE_CHANGED_DURING_BACKUP", "RESTORED_SNAPSHOT_MISMATCH", "CURRENT_AUTHORIZATION_CHANGED",
    "REHEARSAL_UNAVAILABLE", "DATABASE_SCHEMA_UNSUPPORTED", "DATABASE_SNAPSHOT_LIMIT", "DATABASE_UNVALIDATED_CONSTRAINT",
    "DATABASE_GUARDS_MISSING", "RESTORE_DEPENDENCIES_UNAVAILABLE", "RESTORE_BINARIES_UNAVAILABLE", "RESTORE_BINARY_PROVENANCE",
    "RESTORE_KEYS_UNAVAILABLE", "RESTORE_BINARY_CHANGED", "SOURCE_OWNER_CHANGED", "CURRENT_CODE_SCHEMA_MISMATCH",
    "FRESH_BACKUP_UNVERIFIED", "RECOVERY_ROOT_OWNER_INVALID", "RECOVERY_PORT_UNAVAILABLE", "CHILD_NOT_RESERVED",
    "CHILD_OWNER_CHANGED", "CHILD_DATA_PREEXISTS", "CHILD_CONFIG_CHANGED", "CHILD_PROCESS_MISMATCH", "CHILD_DATABASE_MISMATCH",
    "CHILD_PROCESS_PREEXISTS", "BACKUP_CHANGED", "SOURCE_CIPHERTEXT_LIMIT", "RESTORED_SOURCE_INTEGRITY", "CHILD_STOP_UNCONFIRMED",
    "INITDB_PERMISSION_UNAVAILABLE", "LIBPQ_ENVIRONMENT_UNSAFE", "RESTORED_NO_SOURCE_ROWS", "BACKUP_DIRECTORY_INVALID"})


class RehearsalError(RuntimeError):
    """Fixed codes only; subprocess/SQL/key errors must never be reflected."""


def _fail(code):
    raise RehearsalError(code)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _restored_json(plaintext):
    """Read the canonical UTF-8 format without ambiguous/invalid JSON values."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("RESTORED_SOURCE_INTEGRITY")
            result[key] = value
        return result
    def nonfinite(_):
        _fail("RESTORED_SOURCE_INTEGRITY")
    return json.loads(plaintext.decode("utf-8"), object_pairs_hook=pairs, parse_constant=nonfinite)


def preparation():
    """Static intent only: no database connection, import of drivers, key read or command."""
    return {"schema": 1, "status": "PREPARED_NOT_EXECUTED", "application": "CLOSED", "restore": "NOT_RUN",
            "scope": "DATABASE_ONLY", "file_storage": "NOT_REHEARSED", "cleanup": "NOT_RUN",
            "requires": ["EXCLUSIVE_ORCHESTRATOR_RESERVATION", "CURRENT_OWNED_NATIVE_RUNTIME", "CHECKED_BINARY_PROVENANCE",
                         "CURRENT_MIGRATION_TREE", "FRESH_BACKUP_AND_STABLE_CURRENT_SNAPSHOT", "PRIVATE_SOURCE_KEY",
                         "EXCLUSIVE_NEW_CLUSTER", "ACTUAL_RESTORE_AND_SOURCE_DECRYPTION", "CURRENT_AUTHORIZATION_EQUALITY"]}


def rehearse(*, execute=False, reservation=None, driver=None):
    """Coordinate fixed phases; injected drivers are trusted test capabilities only."""
    if execute is not True:
        return preparation()
    if not isinstance(reservation, str) or not TOKEN.fullmatch(reservation):
        return {"schema": 1, "status": "UNAVAILABLE", "code": "RESERVATION_REQUIRED", "application": "CLOSED", "restore": "NOT_RUN", "cleanup": "NOT_RUN"}
    started = time.monotonic()
    steps, reserved, success, code = [], False, False, None
    cleanup = "NOT_STARTED"
    try:
        driver = driver or LocalRuntime(reservation)
        driver.preflight()
        steps.append("OWNED_PREREQUISITES_VERIFIED")
        before = driver.source_snapshot()
        driver.fresh_backup()
        if driver.source_snapshot() != before:
            _fail("SOURCE_CHANGED_DURING_BACKUP")
        steps.append("FRESH_BACKUP_STABLE_SNAPSHOT")
        # Even a partially failed reservation must release its own bound socket.
        reserved = True
        driver.reserve()
        driver.initialize()
        driver.start()
        steps.append("ISOLATED_CLUSTER_VERIFIED")
        driver.restore()
        steps.append("ARCHIVE_RESTORED")
        restored = driver.restored_snapshot()
        if restored != before:
            _fail("RESTORED_SNAPSHOT_MISMATCH")
        driver.verify_decryption()
        steps.append("SOURCE_DECRYPTION_AND_SCHEMA_VERIFIED")
        # A stale backup must not resurrect later revocations/policies/withdrawals.
        if driver.source_snapshot() != before:
            _fail("CURRENT_AUTHORIZATION_CHANGED")
        steps.append("CURRENT_AUTHORIZATION_EQUALITY_VERIFIED")
        success = True
    except RehearsalError as error:
        code = str(error) if str(error) in SAFE_CODES else "REHEARSAL_UNAVAILABLE"
    except Exception:
        # Do not expose even a trusted adapter's exception, SQL, path or key.
        code = "REHEARSAL_UNAVAILABLE"
    finally:
        if reserved:
            try:
                cleanup = driver.stop_owned()
                if cleanup not in {"STOPPED_VERIFIED", "NOT_STARTED"}:
                    cleanup = "STOP_UNCONFIRMED"
            except Exception:
                cleanup = "STOP_UNCONFIRMED"
    if success and cleanup != "STOPPED_VERIFIED":
        success, code = False, "STOP_UNCONFIRMED"
    recovery_id = getattr(driver, "token", None)
    if not isinstance(recovery_id, str) or not TOKEN.fullmatch(recovery_id):
        recovery_id = None
    return {"schema": 1, "status": "DATABASE_REHEARSAL_PASSED_CLOSED" if success else "UNAVAILABLE",
            "code": "DATABASE_ONLY_VERIFIED" if success else code, "application": "CLOSED",
            "scope": "DATABASE_ONLY", "file_storage": "NOT_REHEARSED", "phases": steps,
            "restore": "PASSED" if success else "INCOMPLETE", "cleanup": cleanup,
            "private_artifacts": "PRESERVED_IF_CREATED",
            "recovery_id": recovery_id,
            "elapsed_seconds": round(time.monotonic() - started, 3)}


def migration_inventory(root=ROOT):
    return sorted((path.parent.parent.name, path.stem) for path in (root / "backend/apps").glob("*/migrations/*.py") if path.name != "__init__.py")


def code_fingerprint(root=ROOT):
    paths = sorted((root / "backend/apps").rglob("*.py"))
    paths += sorted((root / "backend/config").glob("*.py"))
    return _hash([(str(path.relative_to(root)).replace("\\", "/"), hashlib.sha256(path.read_bytes()).hexdigest()) for path in paths])


PROFILES = ("DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY")
# PostgreSQL 18 dump/reparse distributes the text[] cast over varchar literals.
# Only these exact, reviewed full CHECK definitions have equivalent spellings.
# Do not generalize this into SQL whitespace/cast/parenthesis normalization.
ENUM_CHECKS = {
    ("scopes_adminauthority", "authority_kind_valid"): ("kind", ("POLICY", "INTEGRATION"), False),
    ("review_decisionbatch", "batch_action_valid"): ("action", ("APPROVE", "RETURN", "REJECT"), False),
    ("scopes_sharingchannel", "channel_max_profile_valid"): ("max_profile", PROFILES, True),
    ("accounts_integrationclient", "client_profile_valid"): ("profile_ceiling", PROFILES, False),
    ("accounts_integrationclientrequest", "client_request_profile_valid"): ("profile_ceiling", PROFILES, False),
    ("review_reviewdecision", "decision_action_valid"): ("action", ("APPROVE", "RETURN", "REJECT"), False),
    ("publications_publicationdelivery", "delivery_profile_valid"): ("profile", PROFILES, False),
    ("operations_privateevidence", "evidence_media_valid"): ("media_type", ("image/jpeg", "image/png"), False),
    ("scopes_channelmember", "member_profile_ceiling_valid"): ("profile_ceiling", PROFILES, False),
    ("scopes_unitmembership", "membership_role_valid"): ("role", ("submitter", "reviewer"), False),
    ("scopes_policyproposal", "proposal_kind_valid"): ("kind", ("ACTIVATE", "DEACTIVATE"), False),
    ("publications_publication", "publication_profile_valid"): ("profile", PROFILES, False),
    ("publications_publicationremoval", "removal_cause_valid"): ("cause", ("WITHDRAWAL", "CORRECTION", "POLICY", "SCOPE", "REAPPROVAL"), False),
    ("publications_publicationremoval", "removal_kind_valid"): ("kind", ("WITHDRAWN", "SUPERSEDED"), False),
    ("scopes_channelsource", "source_max_profile_valid"): ("max_profile", PROFILES, True),
    ("accounts_user", "user_business_role"): ("role", ("submitter", "reviewer", "recipient", "administrator"), False),
    ("reports_reportvariant", "variant_profile_valid"): ("profile", PROFILES, False),
}


def enum_check_spellings(column, values, nullable):
    literals = ["'" + value + "'::character varying" for value in values]
    arrays = ("(ARRAY[" + ", ".join(literals) + "])::text[]",
              "ARRAY[" + ", ".join("(" + value + ")::text" for value in literals) + "]")
    checks = []
    for array in arrays:
        expression = "((" + column + ")::text = ANY (" + array + "))"
        if nullable:
            expression = "((" + column + " IS NULL) OR " + expression + ")"
        checks.append("CHECK (" + expression + ")")
    return tuple(checks)


def canonical_constraint(row):
    relation, name, kind, validated, definition = row
    specification = ENUM_CHECKS.get((relation, name))
    if specification is not None and kind == "c" and validated is True:
        spellings = enum_check_spellings(*specification)
        if definition in spellings:
            return relation, name, kind, validated, spellings[0]
    return row


def database_snapshot(connection):
    """Hash current DB contents and guard definitions in memory; never return rows.

    Whole-table fingerprints include grants, epochs, policies, permanent removals,
    withdrawals, enrollment/family/client revocations and session/receipt identities.
    A stable freshly owned source is required, not a caller-written snapshot file.
    """
    total, tables = 0, {}
    with connection.cursor() as cursor:
        cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
        names = [row[0] for row in cursor.fetchall()]
        if not names or any(not isinstance(name, str) or not NAME.fullmatch(name) for name in names):
            _fail("DATABASE_SCHEMA_UNSUPPORTED")
        for name in names:
            cursor.execute('SELECT row_to_json(t)::text FROM public."' + name + '" t ORDER BY row_to_json(t)::text COLLATE "C"')
            value, count = hashlib.sha256(), 0
            while batch := cursor.fetchmany(100):
                for row in batch:
                    payload = row[0].encode("utf-8")
                    total += len(payload)
                    if total > MAX_SNAPSHOT_BYTES:
                        _fail("DATABASE_SNAPSHOT_LIMIT")
                    value.update(len(payload).to_bytes(8, "big"))
                    value.update(payload)
                    count += 1
            tables[name] = {"rows": count, "sha256": value.hexdigest()}
        cursor.execute("SELECT app,name FROM django_migrations ORDER BY app,name")
        migrations = cursor.fetchall()
        cursor.execute("SELECT r.relname,c.conname,c.contype,c.convalidated,pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace LEFT JOIN pg_class r ON r.oid=c.conrelid WHERE n.nspname='public' ORDER BY r.relname,c.conname,pg_get_constraintdef(c.oid)")
        constraints = [canonical_constraint(row) for row in cursor.fetchall()]
        if any(row[3] is not True for row in constraints):
            _fail("DATABASE_UNVALIDATED_CONSTRAINT")
        cursor.execute("SELECT p.proname,pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'kapit_%' ORDER BY p.proname,pg_get_functiondef(p.oid)")
        functions = cursor.fetchall()
        if not REQUIRED_FUNCTIONS.issubset({row[0] for row in functions}):
            _fail("DATABASE_GUARDS_MISSING")
        cursor.execute("SELECT c.relname,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname")
        triggers = cursor.fetchall()
        if len(triggers) < 20 or any(row[2] != "O" for row in triggers):
            _fail("DATABASE_GUARDS_MISSING")
        cursor.execute("SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname='public' ORDER BY tablename,indexname")
        indexes = cursor.fetchall()
        cursor.execute("SELECT sequencename,last_value,start_value,increment_by,min_value,max_value,cycle,cache_size FROM pg_sequences WHERE schemaname='public' ORDER BY sequencename")
        sequences = cursor.fetchall()
    return {"tables": tables, "migrations": sorted([list(row) for row in migrations]),
            "schema_sha256": _hash([constraints, functions, triggers, indexes]), "sequences_sha256": _hash(sequences)}


class LocalRuntime:
    """Explicit execution only. All destructive lifecycle calls target a fresh child."""
    def __init__(self, reservation):
        from infra import local, native_postgres
        self.local, self.native = local, native_postgres
        self.reservation = reservation
        self.target = self.marker = self.port_socket = self.process = None
        self.launch_attempted = False

    def checked(self, path):
        return self.native.checked_path(path)

    def preflight(self):
        if any(key.upper().startswith("PG") for key in os.environ):
            _fail("LIBPQ_ENVIRONMENT_UNSAFE")
        try:
            import psycopg
            from cryptography.fernet import Fernet
        except ImportError:
            _fail("RESTORE_DEPENDENCIES_UNAVAILABLE")
        self.psycopg, self.Fernet = psycopg, Fernet
        self.info = self.native.ownership()
        self.native.status(require_running=True)
        self.tools = {}
        for name in ("postgres", "initdb", "pg_ctl", "createdb", "pg_dump", "pg_restore"):
            path = Path(self.native.binary(self.info, name))
            if not path.is_file() or path.is_symlink() or path.parent.resolve() != Path(self.info["binaries"]["directory"]).resolve():
                _fail("RESTORE_BINARIES_UNAVAILABLE")
            result = self.native.execute([str(path), "--version"], timeout=10)
            match = re.search(r"\(PostgreSQL\) (\d+)\.", result.stdout)
            if match is None or int(match.group(1)) not in (17, 18):
                _fail("RESTORE_BINARY_PROVENANCE")
            major = int(match.group(1))
            if self.tools and major != self.major:
                _fail("RESTORE_BINARY_PROVENANCE")
            self.major = major
            self.tools[name] = (str(path), self.native.digest(path))
            approved = self.info["binaries"]["hashes"].get(name)
            if approved is not None and self.tools[name][1] != approved:
                _fail("RESTORE_BINARY_PROVENANCE")
        key_file = self.checked(self.local.SECRET_FILE)
        if not key_file.is_file() or key_file.stat().st_size > 16384:
            _fail("RESTORE_KEYS_UNAVAILABLE")
        self.values = json.loads(key_file.read_text(encoding="utf-8"))
        self.local.validate_secrets(self.values)
        self.source_key = self.Fernet(self.values["KAPIT_SOURCE_KEY"].encode("ascii"))
        self.tree, self.code_hash = migration_inventory(), code_fingerprint()
        self.source_snapshot()  # refuse a retained DB behind/ahead of the exact current custom-app tree

    def command(self, name, args, *, timeout=60, capture=True):
        path, fingerprint = self.tools[name]
        if self.native.digest(Path(path)) != fingerprint:
            _fail("RESTORE_BINARY_CHANGED")
        env = {key: value for key, value in self.native.clean_environment().items() if not key.startswith("KAPIT_")}
        if self.target is not None:
            env["PGPASSFILE"] = str(self.target / "pgpass")
        return self.native.execute([path, *args], env=env, timeout=timeout, capture=capture)

    def connection(self, *, source=False):
        if source:
            # Native owner status verifies process/data/listener, rather than trusting a port alone.
            if self.native.ownership() != self.info:
                _fail("SOURCE_OWNER_CHANGED")
            self.native.status(require_running=True)
            return self.psycopg.connect(host="127.0.0.1", port=self.native.PORT, dbname="kapit_m1", user="kapit_m1",
                hostaddr="127.0.0.1", sslmode="disable", password=self.values["KAPIT_DB_PASSWORD"], connect_timeout=5,
                options="-c default_transaction_read_only=on -c timezone=UTC -c datestyle=ISO,YMD")
        return self.psycopg.connect(host="127.0.0.1", port=self.port, dbname=self.database,
            hostaddr="127.0.0.1", sslmode="disable", user=self.user, password=self.password, connect_timeout=5,
            options="-c timezone=UTC -c datestyle=ISO,YMD")

    def source_snapshot(self):
        with self.connection(source=True) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                cursor.execute("SELECT current_setting('data_directory'),current_setting('port'),current_setting('listen_addresses'),current_user,extract(epoch from pg_postmaster_start_time())::bigint")
                data, port, bind, user, stamp = cursor.fetchone()
                if (Path(data).resolve() != self.native.DATA.resolve() or port != str(self.native.PORT)
                        or bind != "127.0.0.1" or user != "kapit_m1" or abs(stamp - self.info["process"]["started"]) > 2):
                    _fail("SOURCE_OWNER_CHANGED")
            snapshot = database_snapshot(connection)
        apps = {app for app, _ in self.tree}
        installed = sorted(tuple(row) for row in snapshot["migrations"] if row[0] in apps)
        if installed != self.tree or code_fingerprint() != self.code_hash:
            _fail("CURRENT_CODE_SCHEMA_MISMATCH")
        return snapshot

    def fresh_backup(self):
        started = time.time()
        # Validate the destination BEFORE the shared helper can mkdir or invoke
        # pg_dump. Its own guard remains necessary against later path changes.
        backup_dir = self.checked(self.local.BACKUP_DIR)
        expected_dir = ROOT.resolve() / ".cache/m1-runtime/backups"
        if (backup_dir != expected_dir or backup_dir.resolve() != expected_dir
                or backup_dir.parent != expected_dir.parent or backup_dir.exists() and not backup_dir.is_dir()):
            _fail("BACKUP_DIRECTORY_INVALID")
        # Existing owned helper writes pg_dump + digest record and verifies its TOC.
        record = self.local.native_backup()
        self.checked(backup_dir)
        archive = self.checked(backup_dir / record["file"])
        if (archive.parent != backup_dir or not record.get("verified") or not archive.is_file() or self.native.digest(archive) != record["sha256"]
                or archive.stat().st_mtime < started - 2):
            _fail("FRESH_BACKUP_UNVERIFIED")
        self.archive, self.archive_hash = archive, record["sha256"]

    def reserve(self):
        root = self.checked(ROOT / ".cache/m4-recovery")
        if not root.exists():
            root.mkdir()
            self.local.write_private(root / "owner.json", json.dumps({"schema": 1, "owner": OWNER, "workspace": str(ROOT.resolve())}))
        marker = self.checked(root / "owner.json")
        if not marker.is_file() or marker.stat().st_size > 4096:
            _fail("RECOVERY_ROOT_OWNER_INVALID")
        owner = json.loads(marker.read_text(encoding="utf-8"))
        if (not isinstance(owner, dict) or type(owner.get("schema")) is not int
                or owner != {"schema": 1, "owner": OWNER, "workspace": str(ROOT.resolve())}):
            _fail("RECOVERY_ROOT_OWNER_INVALID")
        token = secrets.token_hex(16)
        target = self.checked(root / token)
        target.mkdir()  # Exclusive reservation: no exist_ok, adoption, overwrite or recursive cleanup.
        self.target, self.token, self.data = target, token, target / "data"
        self.user, self.database = "kapit_restore_" + token[:16], "kapit_recovery_" + token
        self.password = secrets.token_urlsafe(40)
        self.port_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.port_socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            self.port_socket.bind(("127.0.0.1", 56000 + secrets.randbelow(1000)))
        except OSError:
            self.port_socket.close()
            self.port_socket = None
            _fail("RECOVERY_PORT_UNAVAILABLE")
        self.port = self.port_socket.getsockname()[1]
        self.marker = {"schema": 1, "owner": CHILD_OWNER, "workspace": str(ROOT.resolve()), "target": token,
            "data": str(self.data.resolve()), "port": self.port, "reservation_sha256": hashlib.sha256(self.reservation.encode()).hexdigest()}
        self.local.write_private(target / "owner.json", json.dumps(self.marker))
        self.local.write_private(target / "bootstrap.pass", self.password + "\n")
        self.local.write_private(target / "pgpass", f"127.0.0.1:{self.port}:*:{self.user}:{self.password}\n")

    def check_owner(self):
        if self.target is None or self.marker is None:
            _fail("CHILD_NOT_RESERVED")
        for path in (self.target, self.data, self.target / "owner.json"):
            self.checked(path)
        owner = json.loads((self.target / "owner.json").read_text(encoding="utf-8"))
        if not isinstance(owner, dict) or type(owner.get("schema")) is not int or owner != self.marker:
            _fail("CHILD_OWNER_CHANGED")
        if self.target.name != self.token or self.data.parent != self.target or self.port == self.native.PORT:
            _fail("CHILD_OWNER_CHANGED")

    def initialize(self):
        self.check_owner()
        if self.data.exists():
            _fail("CHILD_DATA_PREEXISTS")
        try:
            self.command("initdb", ["--pgdata", str(self.data), "--username=" + self.user, "--auth=scram-sha-256", "--encoding=UTF8", "--locale=C", "--no-clean", "--no-instructions", "--pwfile", str(self.target / "bootstrap.pass")], timeout=90)
        except RuntimeError as error:
            if str(error).startswith("NATIVE_TOKEN_RESTRICTED:"):
                _fail("INITDB_PERMISSION_UNAVAILABLE")
            raise
        configuration = (f"listen_addresses='127.0.0.1'\nport={self.port}\nunix_socket_directories=''\npassword_encryption='scram-sha-256'\n"
            "max_connections=15\nshared_buffers='32MB'\nlogging_collector=off\nlog_statement='none'\nlog_min_error_statement='panic'\n"
            "log_min_messages='panic'\nlog_connections=off\nlog_disconnections=off\nlog_parameter_max_length=0\nlog_parameter_max_length_on_error=0\nshared_preload_libraries=''\n")
        (self.data / "postgresql.conf").write_text(configuration, encoding="utf-8")
        (self.data / "pg_hba.conf").write_text(f"host all {self.user} 127.0.0.1/32 scram-sha-256\n", encoding="utf-8")
        (self.data / "pg_ident.conf").write_text("# No external identity mappings.\n", encoding="utf-8")
        self.config_hashes = {name: self.native.digest(self.checked(self.data / name)) for name in
            ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")}

    def check_configuration(self):
        """Shared pre-launch and live guard; never start changed configuration."""
        self.check_owner()
        required = {"postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"}
        if (not hasattr(self, "config_hashes") or set(self.config_hashes) != required
                or any(self.native.digest(self.checked(self.data / name)) != fingerprint for name, fingerprint in self.config_hashes.items())
                or (self.data / "PG_VERSION").read_text(encoding="ascii").strip() != str(self.major)):
            _fail("CHILD_CONFIG_CHANGED")

    def verify_child(self):
        self.check_configuration()
        pidfile = self.checked(self.data / "postmaster.pid")
        lines = pidfile.read_text(encoding="utf-8").splitlines()
        pid, started, port = int(lines[0]), int(lines[2]), int(lines[3])
        if pid <= 0 or Path(lines[1]).resolve() != self.data.resolve() or port != self.port or lines[5] != "127.0.0.1":
            _fail("CHILD_PROCESS_MISMATCH")
        identity = self.native.process_identity(pid)
        if (Path(identity["path"]).resolve() != Path(self.tools["postgres"][0]).resolve() or abs(identity["started"] - started) > 2
                or self.process is not None and self.process != {"pid": pid, "started": started}):
            _fail("CHILD_PROCESS_MISMATCH")
        with self.psycopg.connect(host="127.0.0.1", port=self.port, dbname="postgres", user=self.user,
            hostaddr="127.0.0.1", sslmode="disable", password=self.password, connect_timeout=5) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_setting('data_directory'),current_setting('port'),current_setting('listen_addresses'),current_user,extract(epoch from pg_postmaster_start_time())::bigint")
                data, listener, bind, user, stamp = cursor.fetchone()
                if Path(data).resolve() != self.data.resolve() or listener != str(self.port) or bind != "127.0.0.1" or user != self.user or abs(stamp - started) > 2:
                    _fail("CHILD_DATABASE_MISMATCH")
        self.process = {"pid": pid, "started": started}

    def start(self):
        # Keep the reserved socket held until every config/major/path check passes.
        self.check_configuration()
        if self.checked(self.data / "postmaster.pid").exists():
            _fail("CHILD_PROCESS_PREEXISTS")
        self.port_socket.close()
        self.port_socket = None
        # A failed/interrupted pg_ctl may already have created a child, even if
        # verify_child never recorded its identity. Missing pidfile is uncertain.
        self.launch_attempted = True
        self.command("pg_ctl", ["-D", str(self.data), "-l", str(self.target / "server.log"), "-w", "-t", "30", "start"], timeout=40, capture=False)
        self.verify_child()
        self.command("createdb", ["-w", "-h", "127.0.0.1", "-p", str(self.port), "-U", self.user, "--maintenance-db=postgres", self.database])

    def restore(self):
        self.verify_child()
        if self.native.digest(self.checked(self.archive)) != self.archive_hash:
            _fail("BACKUP_CHANGED")
        self.command("pg_restore", ["--exit-on-error", "--no-owner", "--no-acl", "-w", "-h", "127.0.0.1", "-p", str(self.port), "-U", self.user, "-d", self.database, str(self.archive)], timeout=600)

    def restored_snapshot(self):
        self.verify_child()
        with self.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            return database_snapshot(connection)

    def verify_decryption(self):
        self.verify_child()
        checked = 0
        with self.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT payload_ciphertext,content_digest,correction_reason_ciphertext FROM reports_reportrevision ORDER BY id")
                while batch := cursor.fetchmany(100):
                    for ciphertext, expected, reason in batch:
                        if len(ciphertext) > 100000:
                            _fail("SOURCE_CIPHERTEXT_LIMIT")
                        plaintext = self.source_key.decrypt(bytes(ciphertext))
                        if len(plaintext) > 20 * 1024 or _hash(_restored_json(plaintext)) != expected:
                            _fail("RESTORED_SOURCE_INTEGRITY")
                        if reason is not None:
                            if len(reason) > 100000:
                                _fail("SOURCE_CIPHERTEXT_LIMIT")
                            reason_plaintext = self.source_key.decrypt(bytes(reason))
                            if len(reason_plaintext) > 20 * 1024:
                                _fail("RESTORED_SOURCE_INTEGRITY")
                            reason_value = _restored_json(reason_plaintext)
                            if not isinstance(reason_value, str) or len(reason_value) > 500:
                                _fail("RESTORED_SOURCE_INTEGRITY")
                        checked += 1
        if checked == 0:
            _fail("RESTORED_NO_SOURCE_ROWS")

    def stop_owned(self):
        if self.port_socket is not None:
            self.port_socket.close()
            self.port_socket = None
        if self.target is None:
            return "NOT_STARTED"
        self.check_owner()
        pidfile = self.checked(self.data / "postmaster.pid")
        if not pidfile.exists():
            if self.process is not None or getattr(self, "launch_attempted", False):
                _fail("CHILD_STOP_UNCONFIRMED")
            return "NOT_STARTED"
        # PID/data/listen/start/config/OS executable and authenticated connection all
        # match before pg_ctl stop. Unknown or inaccessible children are preserved.
        self.verify_child()
        self.command("pg_ctl", ["-D", str(self.data), "-m", "fast", "-w", "-t", "30", "stop"], timeout=40)
        if pidfile.exists():
            _fail("CHILD_STOP_UNCONFIRMED")
        return "STOPPED_VERIFIED"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    result = rehearse(execute=args.execute, reservation=os.environ.get("KAPIT_RESTORE_RESERVATION"))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "DATABASE_REHEARSAL_PASSED_CLOSED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
