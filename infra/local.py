"""Project-local synthetic runtime commands; no secrets are printed."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache/m1-runtime"
SECRET_FILE = CACHE / "secrets.json"
BACKUP_DIR = CACHE / "backups"
OPERATOR_FILE = CACHE / "operator-accounts.json"
MIGRATION_APPROVAL = ROOT / "ai/reports/M3-migration-approval.md"
sys.path.insert(0, str(ROOT / "backend"))
from config.runtime_boundary import native_boundary


def write_private(path, value):
    # Exclusive creation never replaces a user's existing local key.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(value)


def checked_cache():
    if not CACHE.resolve().is_relative_to(ROOT.resolve()):
        raise RuntimeError("Local runtime directory resolves outside this workspace.")
    for name in ("secrets.json", "backend.env", "db.env", "operator-accounts.json", "venv", "pip-cache", "wheelhouse"):
        path = CACHE / name
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise RuntimeError("Local runtime artifacts cannot be symbolic links or junctions.")


def validate_secrets(value):
    if not isinstance(value, dict) or set(value) != {"KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_DB_PASSWORD"}:
        raise RuntimeError("Local secrets have an invalid format. No existing key has been changed.")
    if not isinstance(value["KAPIT_SECRET_KEY"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{50,128}", value["KAPIT_SECRET_KEY"]):
        raise RuntimeError("Local signing key has an invalid format. No existing key has been changed.")
    if not isinstance(value["KAPIT_DB_PASSWORD"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value["KAPIT_DB_PASSWORD"]):
        raise RuntimeError("Local database key has an invalid format. No existing key has been changed.")
    try:
        source = value["KAPIT_SOURCE_KEY"]
        if not isinstance(source, str) or len(base64.b64decode(source.encode("ascii"), altchars=b"-_", validate=True)) != 32:
            raise ValueError
    except (ValueError, UnicodeError):
        raise RuntimeError("Local encryption key has an invalid format. No existing key has been changed.") from None


def initialize():
    checked_cache()
    CACHE.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        CACHE.chmod(0o700)
    if not SECRET_FILE.exists():
        value = {
            "KAPIT_SECRET_KEY": secrets.token_urlsafe(64),
            "KAPIT_SOURCE_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
            "KAPIT_DB_PASSWORD": secrets.token_urlsafe(32),
        }
        write_private(SECRET_FILE, json.dumps(value, indent=2) + "\n")
    else:
        value = json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    validate_secrets(value)
    expected_files = {
        CACHE / "backend.env": "".join(f"{name}={value[name]}\n" for name in ("KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_DB_PASSWORD")),
        CACHE / "db.env": "POSTGRES_PASSWORD=" + value["KAPIT_DB_PASSWORD"] + "\n",
    }
    for path, expected in expected_files.items():
        if not path.exists():
            write_private(path, expected)
        elif path.read_text(encoding="utf-8") != expected:
            raise RuntimeError("Local configuration files differ. Review the existing files; no key has been replaced.")
    print("Local synthetic keys prepared. Values remain in ignored runtime files.")


def run(command, cwd=ROOT, environment=None):
    result = subprocess.run(command, cwd=cwd, env=environment, check=False)
    if result.returncode:
        raise RuntimeError(f"Runtime command failed (exit {result.returncode}). See the preceding safe command output.")


def python_path():
    interpreter = CACHE / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    return str(interpreter) if interpreter.exists() else sys.executable


def npm_command():
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm:
        raise RuntimeError("Node/npm is required to build the website before the local image.")
    if os.name != "nt":
        return [npm]
    # Execute npm's installed JS entry through node.exe rather than composing
    # a shell command or passing a batch file to CreateProcess.
    node = shutil.which("node")
    entry = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
    if not node or not entry.is_file():
        raise RuntimeError("The installed Windows npm entry point is unavailable.")
    return [node, str(entry)]


def local_docker_endpoint(value=None):
    endpoint = value or ("npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock")
    if endpoint in {"npipe:////./pipe/docker_engine", "npipe:////./pipe/dockerDesktopLinuxEngine"}:
        return endpoint
    parsed = urlsplit(endpoint)
    if parsed.scheme == "unix" and not parsed.netloc and parsed.path.startswith("/") and not parsed.query and not parsed.fragment:
        if ".." not in parsed.path.split("/") and "%" not in parsed.path and "\x00" not in parsed.path:
            return endpoint
    if parsed.scheme == "tcp" and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment and parsed.path in {"", "/"}:
        try:
            if ipaddress.ip_address(parsed.hostname).is_loopback and parsed.port is not None:
                return endpoint
        except (ValueError, TypeError):
            pass
    raise RuntimeError("M1 Docker endpoint must be an explicit local named pipe, Unix socket or loopback-IP TCP address. Remote daemon access is not authorized.")


def docker_environment():
    env = dict(os.environ)
    # Select a checked endpoint explicitly; neither the inherited process nor
    # the user's current global context may silently redirect local M1 work.
    for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "BUILDKIT_HOST", "BUILDX_BUILDER"):
        env.pop(key, None)
    # The default Docker-driver builder follows this invocation's explicit
    # local daemon, instead of selecting a persisted named remote builder.
    env["BUILDX_BUILDER"] = "default"
    return env


def docker_command(args):
    docker = shutil.which("docker")
    if not docker:
        raise RuntimeError("Docker is unavailable.")
    command = [docker, "--host", local_docker_endpoint(args.docker_host)]
    command += ["compose", "--project-name", "kapit-c2-m1", "--file", str(ROOT / "infra/compose.yaml")]
    return command


def environment():
    env = dict(os.environ)
    selected = native_boundary(env)
    env["KAPIT_SECRETS_FILE"] = str(SECRET_FILE)
    env["KAPIT_DB_HOST"] = selected.db_host
    env["KAPIT_DB_PORT"] = selected.db_port
    env["KAPIT_RUNTIME_CONTEXT"] = "native"
    env["KAPIT_LOCAL_CONTAINER"] = "0"
    env["DJANGO_SETTINGS_MODULE"] = "config.settings"
    # Native mode uses the dedicated local key file, not unrelated inherited
    # credentials from another application's environment.
    for name in ("KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_DB_PASSWORD"):
        env.pop(name, None)
    return env


def dependency_status():
    probe = "import importlib.util,json,sys; print(json.dumps({'python':sys.version.split()[0],'modules':{name:bool(importlib.util.find_spec(name)) for name in ['django','rest_framework','psycopg','cryptography']}}))"
    try:
        result = subprocess.run([python_path(), "-c", probe], cwd=ROOT, check=False, capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ValueError
        return json.loads(result.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise RuntimeError("PYTHON_UNAVAILABLE: the selected project Python environment could not be checked.") from None


def api_available():
    connection = http.client.HTTPConnection("127.0.0.1", 8000, timeout=2)
    try:
        connection.request("GET", "/api/v1/auth/csrf/", headers={"Accept": "application/json"})
        response = connection.getresponse()
        # Discard this anonymous token immediately; never report response values.
        body = response.read(4097)
        value = json.loads(body) if response.status == 200 and len(body) <= 4096 else None
        return isinstance(value, dict) and set(value) == {"csrf_token"} and isinstance(value["csrf_token"], str) and 32 <= len(value["csrf_token"]) <= 128
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def native_module():
    sys.path.insert(0, str(ROOT))
    from infra import native_postgres
    return native_postgres


def doctor():
    """Readiness is metadata only; no initialization, login or mutation."""
    checked_cache()
    checks = []
    try:
        dependency = dependency_status()
        missing = [name for name, present in dependency["modules"].items() if not present]
        checks.append({"component": "python", "ready": not missing, "code": "READY" if not missing else "PYTHON_PACKAGES_MISSING",
                       "missing": missing, "next": None if not missing else "python infra/local.py prepare-python"})
    except RuntimeError:
        checks.append({"component": "python", "ready": False, "code": "PYTHON_UNAVAILABLE", "next": "python infra/local.py prepare-python"})
    keys_ready = SECRET_FILE.is_file()
    keys_code = "READY" if keys_ready else "LOCAL_KEYS_MISSING"
    if keys_ready:
        try:
            validate_secrets(json.loads(SECRET_FILE.read_text(encoding="utf-8")))
        except (OSError, ValueError, RuntimeError):
            keys_ready, keys_code = False, "LOCAL_KEYS_INVALID"
    checks.append({"component": "local_keys", "ready": keys_ready, "code": keys_code,
                   "next": None if keys_ready else "python infra/local.py init"})
    built = (ROOT / "web/dist/index.html").is_file()
    checks.append({"component": "website_assets", "ready": built, "code": "READY" if built else "WEBSITE_BUILD_MISSING",
                   "next": None if built else "npm.cmd --prefix web run build"})
    try:
        state = native_module().status()
        ready = state["state"] == "running"
        checks.append({"component": "owned_database", "ready": ready, "code": "READY" if ready else "NATIVE_STOPPED",
                       "next": None if ready else "python infra/local.py native-start"})
    except (RuntimeError, OSError, ValueError) as error:
        code = str(error).split(":", 1)[0] if isinstance(error, RuntimeError) else "NATIVE_UNAVAILABLE"
        allowed = {"NATIVE_OWNER", "NATIVE_INIT_INCOMPLETE", "NATIVE_CONFIG", "NATIVE_PROCESS", "NATIVE_PATH", "NATIVE_DATABASE", "NATIVE_COMMAND", "NATIVE_TOKEN_RESTRICTED", "POSTGRES_BINARIES"}
        code = code if code in allowed else "NATIVE_UNAVAILABLE"
        checks.append({"component": "owned_database", "ready": False, "code": code,
                       "next": "python infra/local.py native-init" if code in {"NATIVE_OWNER", "NATIVE_INIT_INCOMPLETE", "NATIVE_TOKEN_RESTRICTED"} else "python infra/local.py native-status"})
    launch_ready = all(check["ready"] for check in checks)
    available = api_available()
    checks.append({"component": "api", "ready": available, "code": "READY" if available else "API_UNAVAILABLE",
                   "next": None if available else "python infra/local.py backend-native"})
    return {"ready": launch_ready and available, "launch_ready": launch_ready, "checks": checks,
            "website": "http://127.0.0.1:8000", "preview": "http://127.0.0.1:18081", "preview_has_api": False}


def managed_environment():
    if os.environ.get("KAPIT_RUNTIME_CONTEXT", "native") != "native":
        raise RuntimeError("NATIVE_CONTEXT: managed native commands cannot inherit a hosted or container context.")
    env = environment()
    if env["KAPIT_DB_HOST"] != "127.0.0.1":
        raise RuntimeError("NATIVE_HOST: managed native commands require the owned cluster at 127.0.0.1:55436.")
    for key in list(env):
        if key.upper().startswith("PG") or key in {"DATABASE_URL", "DB_URL"}:
            env.pop(key)
    return env


def native_test(command_runner=None):
    execute = command_runner or run
    env = managed_environment()
    native_module().status(require_running=True)
    if not all(dependency_status()["modules"].values()):
        raise RuntimeError("PYTHON_PACKAGES_MISSING: run python infra/local.py prepare-python before test-native.")
    base = [python_path(), str(ROOT / "backend/manage.py")]
    execute(base + ["check", "--settings=config.test_settings"], environment=env)
    execute(base + ["makemigrations", "--check", "--dry-run", "--settings=config.test_settings"], environment=env)
    execute(base + ["test", "tests", "--settings=config.test_settings", "--testrunner=tests.browser_runner.BrowserAcceptanceRunner"], environment=env)


def native_browser(command_runner=None):
    """Explicit real-browser gate; its guarded runner owns the test database."""
    execute = command_runner or run
    env = managed_environment()
    native_module().status(require_running=True)
    if not all(dependency_status()["modules"].values()):
        raise RuntimeError("PYTHON_PACKAGES_MISSING: run python infra/local.py prepare-python before browser-native.")
    if not (ROOT / "web/dist/index.html").is_file():
        raise RuntimeError("WEBSITE_BUILD_MISSING: run npm.cmd --prefix web run build before browser-native.")
    execute([
        python_path(), str(ROOT / "backend/manage.py"), "test", "tests.browser_acceptance",
        "--settings=config.test_settings", "--testrunner=tests.browser_runner.BrowserAcceptanceRunner",
    ], environment=env)


def capture(command, environment=None):
    result = subprocess.run(command, cwd=ROOT, env=environment, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"Runtime command failed (exit {result.returncode}).")
    return result.stdout


def pending_migrations(environment, capture_runner=None):
    """Names of migrations not yet applied to the retained database (read-only plan)."""
    output = (capture_runner or capture)([python_path(), str(ROOT / "backend/manage.py"), "migrate", "--plan"], environment)
    if "No planned migration operations." in output:
        return []
    names = []
    for line in output.splitlines():
        match = re.match(r"^([a-z][a-z0-9_]*)\.(\d{4}_[A-Za-z0-9_]+)\s*$", line.strip())
        if match:
            names.append(f"{match.group(1)}.{match.group(2)}")
    if not names:
        raise RuntimeError("MIGRATION_GUARD: the pending migration plan could not be read; refusing to migrate.")
    return names


def fresh_database(environment, capture_runner=None, pending=None):
    """True only when every listed migration is unapplied (a newly initialized database).

    Any line that looks like a migration entry but does not parse, or a listed set that differs
    from the pending plan, fails closed: a retained database must never be classified as fresh.
    """
    output = (capture_runner or capture)([python_path(), str(ROOT / "backend/manage.py"), "showmigrations", "--plan"], environment)
    entries = []
    for line in output.splitlines():
        if not line.strip().startswith("["):
            continue
        match = re.match(r"^\[( |X)\]\s+([a-z][a-z0-9_]*\.\d{4}_[A-Za-z0-9_]+)(\s.*)?$", line.strip())
        if match is None:
            raise RuntimeError("MIGRATION_GUARD: the applied-migration list could not be read; refusing to migrate.")
        entries.append((match.group(1), match.group(2)))
    if not entries:
        raise RuntimeError("MIGRATION_GUARD: the applied-migration list could not be read; refusing to migrate.")
    if any(state == "X" for state, _ in entries):
        return False
    if pending is not None and {name for _, name in entries} != set(pending):
        raise RuntimeError("MIGRATION_GUARD: the applied-migration list differs from the pending plan; refusing to migrate.")
    return True


def operator_accounts():
    """Private generated passwords for the exercise administrator and operator check accounts; never printed."""
    checked_cache()
    if not OPERATOR_FILE.exists():
        value = {"schema": 1, "admin": {"username": "admin", "password": secrets.token_urlsafe(18)},
                 "operator": {"usernames": ["ops-submitter", "ops-recipient"], "password": secrets.token_urlsafe(18)}}
        write_private(OPERATOR_FILE, json.dumps(value, indent=2) + "\n")
    value = json.loads(OPERATOR_FILE.read_text(encoding="utf-8"))
    try:
        valid = (value["schema"] == 1 and value["admin"]["username"] == "admin"
                 and value["operator"]["usernames"] == ["ops-submitter", "ops-recipient"]
                 and all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9_-]{20,128}", item)
                         for item in (value["admin"]["password"], value["operator"]["password"])))
    except (KeyError, TypeError):
        valid = False
    if not valid:
        raise RuntimeError("OPERATOR_ACCOUNTS: the private operator-accounts file has an invalid format. Nothing was changed.")
    return value


def migration_tree_time():
    files = [path for path in (ROOT / "backend/apps").glob("*/migrations/*.py") if path.name != "__init__.py"]
    return max(path.stat().st_mtime for path in files) if files else 0.0


def latest_verified_backup():
    """Newest backup record whose dump still matches its recorded digest and passed pg_restore --list."""
    module = native_module()
    try:
        module.checked_path(BACKUP_DIR)
    except RuntimeError:
        return None
    best = None
    for record in sorted(BACKUP_DIR.glob("kapit_m1-*.json")) if BACKUP_DIR.exists() else []:
        try:
            module.checked_path(record)
            if not record.is_file() or record.stat().st_size > 16384:
                continue
            value = json.loads(record.read_text(encoding="utf-8"))
            dump = BACKUP_DIR / value["file"]
            module.checked_path(dump)
            if (value.get("verified") is True and dump.is_file() and dump.parent == BACKUP_DIR
                    and hashlib.sha256(dump.read_bytes()).hexdigest() == value["sha256"]):
                best = value
        except (OSError, ValueError, KeyError, TypeError, RuntimeError):
            continue
    return best


def approved_migrations():
    """Exact migration names listed by the human approval record, one per `- app.0001_name` line."""
    if not MIGRATION_APPROVAL.is_file():
        return set()
    names = set()
    for line in MIGRATION_APPROVAL.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^- `?([a-z][a-z0-9_]*\.\d{4}_[A-Za-z0-9_]+)`?\s*$", line.strip())
        if match:
            names.add(match.group(1))
    return names


def require_migration_approval(environment, capture_runner=None):
    """TASK-121: never migrate the retained database past its applied heads without a backup and a human approval."""
    pending = pending_migrations(environment, capture_runner)
    if not pending:
        return []
    if fresh_database(environment, capture_runner, pending):
        # Nothing is applied, so there is no retained data to lose or protect.
        return pending
    backup = latest_verified_backup()
    if backup is None or backup.get("created_epoch", 0) <= migration_tree_time():
        raise RuntimeError("MIGRATION_GUARD_BACKUP: unapplied migrations exist; run python infra/local.py native-backup first.")
    if set(pending) != approved_migrations():
        raise RuntimeError("MIGRATION_GUARD_APPROVAL: unapplied migrations are not exactly listed in ai/reports/M3-migration-approval.md.")
    return pending


def native_backup():
    """Custom-format pg_dump of the retained database, verified with pg_restore --list; no secrets are printed."""
    module = native_module()
    # Validate BEFORE mkdir/pg_dump: redirected backup directories must never
    # receive data, even if a later digest/restore check would reject the path.
    module.checked_path(BACKUP_DIR)
    if BACKUP_DIR.exists() and not BACKUP_DIR.is_dir():
        raise RuntimeError("BACKUP_PATH: backup storage is not an owned directory.")
    managed_environment()
    info = module.ownership()
    module.status(require_running=True)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc)
    name = f"kapit_m1-{stamp.strftime('%Y%m%dT%H%M%S%fZ')}.dump"
    dump = BACKUP_DIR / name
    module.checked_path(dump)
    with module.password_file(libpq=True) as password:
        env = module.clean_environment()
        env["PGPASSFILE"] = str(password)
        module.execute([module.binary(info, "pg_dump"), "-w", "-h", "127.0.0.1", "-p", str(module.PORT), "-U", "kapit_m1",
                        "-Fc", "-f", str(dump), "kapit_m1"], env=env, timeout=600)
    listing = module.execute([module.binary(info, "pg_restore"), "--list", str(dump)], timeout=120).stdout
    entries = sum(1 for line in listing.splitlines() if line and not line.startswith(";"))
    if entries == 0:
        raise RuntimeError("BACKUP_UNVERIFIED: pg_restore --list found no entries.")
    record = {"file": name, "sha256": hashlib.sha256(dump.read_bytes()).hexdigest(), "bytes": dump.stat().st_size,
              "created_utc": stamp.isoformat(), "created_epoch": stamp.timestamp(), "restore_list_entries": entries, "verified": True}
    write_private(BACKUP_DIR / (name[:-5] + ".json"), json.dumps(record, indent=2) + "\n")
    return {key: record[key] for key in ("file", "sha256", "bytes", "created_utc", "restore_list_entries", "verified")}


def seed_native(command_runner=None, capture_runner=None):
    """Event provisioning: organization, Los Baños scope and operator accounts only; existing accounts are retained."""
    execute = command_runner or run
    env = managed_environment()
    native_module().status(require_running=True)
    if not all(dependency_status()["modules"].values()):
        raise RuntimeError("PYTHON_PACKAGES_MISSING: run python infra/local.py prepare-python before native application startup.")
    require_migration_approval(env, capture_runner)
    base = [python_path(), str(ROOT / "backend/manage.py")]
    execute(base + ["migrate", "--noinput"], environment=env)
    accounts = operator_accounts()
    seed_env = dict(env, KAPIT_EVENT_ADMIN_PASSWORD=accounts["admin"]["password"], KAPIT_OPERATOR_PASSWORD=accounts["operator"]["password"])
    execute(base + ["seed_event"], environment=seed_env)


def seed_m3_native(command_runner=None, capture_runner=None):
    """Manual-only M3 topology seed (SN3); never called by the starter. Behind the same backup/approval guard."""
    execute = command_runner or run
    env = managed_environment()
    native_module().status(require_running=True)
    if not all(dependency_status()["modules"].values()):
        raise RuntimeError("PYTHON_PACKAGES_MISSING: run python infra/local.py prepare-python before seed-m3-native.")
    require_migration_approval(env, capture_runner)
    base = [python_path(), str(ROOT / "backend/manage.py")]
    execute(base + ["migrate", "--noinput"], environment=env)
    execute(base + ["seed_m3_demo"], environment=env)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init", "up", "stop", "test", "check", "doctor", "prepare-python", "seed-demo", "seed-compose", "backend", "worker", "native-init", "native-start", "native-status", "native-stop", "native-diagnose", "test-native", "browser-native", "backend-native", "worker-native", "seed-native", "native-backup", "seed-m3-native"])
    parser.add_argument("--docker-host", help="Use an existing Docker endpoint without changing global context.")
    parser.add_argument("--offline", action="store_true", help="Install Python wheels from the local wheelhouse only.")
    parser.add_argument("--postgres-bin", help="Existing local PostgreSQL 17/18 binary directory; used only by native-init.")
    args = parser.parse_args()
    if args.command == "native-diagnose":
        sys.path.insert(0, str(ROOT))
        from infra import postgres_diagnostics
        postgres_diagnostics.main()
        return
    if args.command in {"up", "stop", "test", "seed-compose"} or args.docker_host:
        local_docker_endpoint(args.docker_host)
    native_env = environment() if args.command in {"backend", "worker", "seed-demo"} else None
    checked_cache()
    if args.command == "doctor":
        result = doctor()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["ready"] else 2)
    if args.command == "native-backup":
        print(json.dumps(native_backup(), indent=2))
        return
    if args.command == "seed-m3-native":
        seed_m3_native()
        return
    if args.command.startswith("native-"):
        managed_environment()
        module = native_module()
        action = args.command.removeprefix("native-")
        result = module.init(args.postgres_bin) if action == "init" else {"start": module.start, "status": module.status, "stop": module.stop}[action]()
        print(json.dumps(result, indent=2))
        return
    if args.command == "test-native":
        native_test()
        return
    if args.command == "browser-native":
        native_browser()
        return
    if args.command == "seed-native":
        seed_native()
        return
    if args.command in {"backend-native", "worker-native"}:
        env = managed_environment()
        native_module().status(require_running=True)
        if not all(dependency_status()["modules"].values()):
            raise RuntimeError("PYTHON_PACKAGES_MISSING: run python infra/local.py prepare-python before native application startup.")
        base = [python_path(), str(ROOT / "backend/manage.py")]
        if args.command != "worker-native":
            require_migration_approval(env)
            run(base + ["migrate", "--noinput"], environment=env)
        command = base + ["process_jobs"] if args.command == "worker-native" else [python_path(), str(ROOT / "infra/server.py")]
        run(command, environment=env)
        return
    if args.command == "init":
        initialize()
        return
    if args.command == "check":
        availability = dependency_status()
        availability.update({"secrets_prepared": SECRET_FILE.exists(), "web_build": (ROOT / "web/dist/index.html").is_file()})
        print(json.dumps(availability, indent=2))
        return
    if args.command == "prepare-python":
        if not (CACHE / "venv").exists():
            run([sys.executable, "-m", "venv", str(CACHE / "venv")])
        command = [python_path(), "-m", "pip", "--isolated", "install", "--keyring-provider", "disabled", "--no-input", "--only-binary=:all:", "--disable-pip-version-check", "--retries", "0", "--timeout", "15", "--cache-dir", str(CACHE / "pip-cache")]
        if args.offline:
            command += ["--no-index", "--find-links", str(CACHE / "wheelhouse")]
        else:
            command += ["--index-url", "https://pypi.org/simple"]
        command += ["-r", str(ROOT / "backend/requirements.txt")]
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("PIP_")}
        env["PIP_CONFIG_FILE"] = os.devnull
        run(command, environment=env)
        return
    initialize()
    if args.command == "up":
        npm = npm_command()
        npm_install = npm + ["ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(CACHE / "npm-cache")]
        if args.offline:
            npm_install.append("--offline")
        run(npm_install, cwd=ROOT / "web")
        run(npm + ["run", "build"], cwd=ROOT / "web")
        command = docker_command(args)
        run(command + ["up", "--build", "--detach", "--wait"], environment=docker_environment())
        print("Open http://127.0.0.1:8000. Use separate synthetic demo accounts.")
    elif args.command == "stop":
        # Stop this project only. Never remove database volumes or external containers.
        run(docker_command(args) + ["stop"], environment=docker_environment())
    elif args.command == "test":
        run(docker_command(args) + ["exec", "--no-TTY", "backend", "python", "backend/manage.py", "test", "tests", "--settings=config.test_settings", "--noinput"], environment=docker_environment())
    elif args.command == "seed-compose":
        run(docker_command(args) + ["exec", "--no-TTY", "backend", "python", "backend/manage.py", "seed_demo"], environment=docker_environment())
    elif args.command == "seed-demo":
        require_migration_approval(native_env)
        run([python_path(), str(ROOT / "backend/manage.py"), "migrate", "--noinput"], environment=native_env)
        run([python_path(), str(ROOT / "backend/manage.py"), "seed_demo"], environment=native_env)
    elif args.command == "backend":
        require_migration_approval(native_env)
        run([python_path(), str(ROOT / "backend/manage.py"), "migrate", "--noinput"], environment=native_env)
        run([python_path(), str(ROOT / "infra/server.py")], environment=native_env)
    elif args.command == "worker":
        run([python_path(), str(ROOT / "backend/manage.py"), "process_jobs"], environment=native_env)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, KeyError) as error:
        # Runtime errors contain controlled command/setting names, not secret values.
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
