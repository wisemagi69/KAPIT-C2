"""Owned, loopback-only PostgreSQL for the synthetic M1 workspace.

Never adopts an existing service, repairs an unknown directory, or deletes data.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import local as runtime

# "postgres" (no suffix) was created by an earlier sandboxed session with a
# creator-only Windows ACL and is unreadable by the user; it held no data and
# is left untouched rather than adopted or removed.
CLUSTER_ROOT = ROOT / ".cache/m1-runtime/postgres-native"
DATA = CLUSTER_ROOT / "data"
MARKER = CLUSTER_ROOT / "owner.json"
PORT = 55436
TOOLS = ("postgres", "initdb", "pg_ctl", "psql", "createdb")
CONFIG = """# Owned KAPIT-C2 synthetic runtime; changes require review.
listen_addresses = '127.0.0.1'
port = 55436
unix_socket_directories = ''
password_encryption = 'scram-sha-256'
max_connections = 40
shared_buffers = '32MB'
logging_collector = off
log_statement = 'none'
log_min_error_statement = 'panic'
log_min_messages = 'panic'
log_connections = off
log_disconnections = off
log_parameter_max_length = 0
log_parameter_max_length_on_error = 0
shared_preload_libraries = ''
"""
HBA = "host all kapit_m1 127.0.0.1/32 scram-sha-256\n"


def checked_path(path):
    root = ROOT.resolve()
    path = Path(path)
    if not path.resolve().is_relative_to(root) or path.resolve() == root:
        raise RuntimeError("NATIVE_PATH: runtime artifact resolves outside the workspace.")
    current = path
    while current != ROOT:
        if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
            raise RuntimeError("NATIVE_PATH: runtime links and junctions are not allowed.")
        if current.parent == current:
            raise RuntimeError("NATIVE_PATH: runtime artifact is not a workspace child.")
        current = current.parent
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def clean_environment():
    # libpq defaults, external service/pass files and redirected data directories
    # must not select an unrelated installation or credential source.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("PG")}
    env.update({"PGCONNECT_TIMEOUT": "5", "PGSSLMODE": "disable", "PGAPPNAME": "kapit-c2-native"})
    return env


def execute(command, *, env=None, timeout=30, permitted=(0,), capture=True):
    kwargs = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
    # A server launched by pg_ctl inherits captured pipes and never closes them,
    # so callers that start a daemon pass capture=False to avoid waiting forever.
    streams = {"capture_output": True} if capture else {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    try:
        result = subprocess.run(command, cwd=ROOT, env=env or clean_environment(), **streams,
                                text=True, check=False, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("NATIVE_COMMAND: local PostgreSQL command unavailable or timed out.") from None
    if result.returncode not in permitted:
        # Never replay a database exception, SQL text, password or server log.
        diagnostic = ((result.stdout or "") + (result.stderr or "")).lower()
        if any(phrase in diagnostic for phrase in ("restricted token", "createrestrictedtoken", "restricting privileges")):
            raise RuntimeError("NATIVE_TOKEN_RESTRICTED: PostgreSQL initialization cannot create its Windows token here; run native-init in a normal user terminal.")
        raise RuntimeError(f"NATIVE_COMMAND: local PostgreSQL command failed (exit {result.returncode}).")
    return result


def discover(bin_dir=None):
    suffix = ".exe" if os.name == "nt" else ""
    candidates = [Path(bin_dir)] if bin_dir else []
    if not bin_dir:
        if os.name == "nt":
            candidates += [Path("C:/Program Files/PostgreSQL") / version / "bin" for version in ("18", "17")]
        installed = shutil.which("postgres")
        if installed:
            candidates.append(Path(installed).parent)
    for directory in candidates:
        directory = directory.resolve()
        paths = {name: directory / (name + suffix) for name in TOOLS}
        if all(path.is_file() and not path.is_symlink() for path in paths.values()):
            version = execute([str(paths["postgres"]), "--version"]).stdout.strip()
            if not any(version.startswith(f"postgres (PostgreSQL) {major}.") for major in (17, 18)):
                continue
            return {"directory": str(directory), "version": version,
                    "hashes": {name: digest(path) for name, path in paths.items()}}
    raise RuntimeError("POSTGRES_BINARIES: install PostgreSQL 17 or 18 locally, or supply --postgres-bin; no service is used.")


def binary(info, name):
    return str(Path(info["binaries"]["directory"]) / (name + (".exe" if os.name == "nt" else "")))


def save_marker(info, *, first=False):
    checked_path(MARKER)
    value = json.dumps(info, indent=2) + "\n"
    if first:
        runtime.write_private(MARKER, value)
    else:
        temporary = checked_path(CLUSTER_ROOT / "owner.pending.json")
        runtime.write_private(temporary, value)
        os.replace(temporary, MARKER)


def ownership(*, initializing=False):
    for path in (CLUSTER_ROOT, DATA, MARKER):
        checked_path(path)
    try:
        info = json.loads(MARKER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("NATIVE_OWNER: owned cluster absent; run native-init. Unknown directories are never adopted.") from None
    expected = {"schema": 1, "workspace": str(ROOT.resolve()), "data": str(DATA.resolve()), "port": PORT}
    if not isinstance(info, dict) or any(info.get(key) != value for key, value in expected.items()) or info.get("phase") not in {"initializing", "ready"}:
        raise RuntimeError("NATIVE_OWNER: cluster ownership or initialization state does not match.")
    if not initializing and info["phase"] == "initializing":
        raise RuntimeError("NATIVE_INIT_INCOMPLETE: run native-init in a normal user terminal; only an owned empty initialization can resume.")
    try:
        discovered = discover(info["binaries"]["directory"])
        if discovered != info["binaries"]:
            raise ValueError
        if info["phase"] == "ready":
            for name, expected_hash in info["config_hashes"].items():
                if name not in {"postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"}:
                    raise ValueError
                if digest(checked_path(DATA / name)) != expected_hash:
                    raise ValueError
            if set(info["config_hashes"]) != {"postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"}:
                raise ValueError
    except (KeyError, TypeError, ValueError, OSError):
        raise RuntimeError("NATIVE_CONFIG: cluster binaries or configuration changed; review before proceeding.") from None
    return info


@contextmanager
def password_file(*, libpq=False):
    runtime.checked_cache()
    values = json.loads(runtime.SECRET_FILE.read_text(encoding="utf-8"))
    runtime.validate_secrets(values)
    path = checked_path(CLUSTER_ROOT / ("client.pass" if libpq else "bootstrap.pass"))
    password = values["KAPIT_DB_PASSWORD"]
    value = f"127.0.0.1:{PORT}:*:kapit_m1:{password}\n" if libpq else password + "\n"
    runtime.write_private(path, value)
    try:
        yield path
    finally:
        # Exact checked temporary file only; never recursively clean a cluster.
        checked_path(path).unlink()


def init(bin_dir=None):
    checked_path(CLUSTER_ROOT)
    if CLUSTER_ROOT.exists():
        info = ownership(initializing=True)
        if info["phase"] == "ready":
            return {"state": "initialized", "retained": True}
        if DATA.exists() and (not DATA.is_dir() or any(DATA.iterdir())):
            raise RuntimeError("NATIVE_INIT_PARTIAL: existing partial database files require review; no data is replaced or removed.")
        if bin_dir and Path(bin_dir).resolve() != Path(info["binaries"]["directory"]):
            raise RuntimeError("NATIVE_CONFIG: empty initialization must use its recorded PostgreSQL binaries.")
        binaries = info["binaries"]
        runtime.initialize()
    else:
        binaries = discover(bin_dir)
        runtime.initialize()
        # On Windows, Python 3.13+ turns mode=0o700 into an ACL bound to the creating
        # token, which can lock out the same user from a different terminal. Inherit
        # the workspace cache ACL there instead.
        if os.name == "nt":
            CLUSTER_ROOT.mkdir()
        else:
            CLUSTER_ROOT.mkdir(mode=0o700)
        info = {"schema": 1, "workspace": str(ROOT.resolve()), "data": str(DATA.resolve()),
                "port": PORT, "binaries": binaries, "phase": "initializing", "process": None}
        save_marker(info, first=True)
    with password_file() as password:
        execute([binary(info, "initdb"), "--pgdata", str(DATA), "--username=kapit_m1",
                 "--auth=scram-sha-256", "--encoding=UTF8", "--locale=C", "--no-clean", "--no-instructions",
                 "--pwfile", str(password)], timeout=55)
    # These files were just created by our exclusive initdb; no existing cluster
    # is ever rewritten. All five are verified before any later lifecycle action.
    (DATA / "postgresql.conf").write_text(CONFIG, encoding="utf-8")
    (DATA / "pg_hba.conf").write_text(HBA, encoding="utf-8")
    (DATA / "pg_ident.conf").write_text("# No external identity mappings.\n", encoding="utf-8")
    info["config_hashes"] = {name: digest(DATA / name) for name in
                             ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION")}
    info["phase"] = "ready"
    save_marker(info)
    return {"state": "initialized", "postgres": binaries["version"], "retained": False}


def pid_record():
    path = checked_path(DATA / "postmaster.pid")
    if not path.exists():
        return None
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        pid, started, port = int(lines[0]), int(lines[2]), int(lines[3])
        if pid <= 0 or Path(lines[1]).resolve() != DATA.resolve() or port != PORT or lines[5] != "127.0.0.1":
            raise ValueError
        return {"pid": pid, "started": started}
    except (OSError, ValueError, IndexError):
        raise RuntimeError("NATIVE_PROCESS: PostgreSQL process file does not match the owned cluster.") from None


def process_identity(pid):
    if os.name == "nt":
        # Get-Process can inspect our child without WMI/CIM service permission.
        command = (f"$p=Get-Process -Id {int(pid)} -ErrorAction Stop; "
                   "@{path=$p.Path;started=([DateTimeOffset]$p.StartTime.ToUniversalTime()).ToUnixTimeSeconds()} | ConvertTo-Json -Compress")
        shell = str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
        try:
            return json.loads(execute([shell, "-NoProfile", "-NonInteractive", "-Command", command], timeout=8).stdout)
        except (ValueError, TypeError):
            raise RuntimeError("NATIVE_PROCESS: owned process identity is unavailable.") from None
    try:
        import datetime
        raw = execute(["ps", "-p", str(pid), "-o", "lstart=", "-o", "comm="], timeout=8).stdout.strip()
        stamp = datetime.datetime.strptime(raw[:24], "%a %b %d %H:%M:%S %Y").timestamp()
        return {"path": str(Path(f"/proc/{pid}/exe").resolve(strict=True)), "started": int(stamp)}
    except (ValueError, OSError):
        raise RuntimeError("NATIVE_PROCESS: owned process identity is unavailable.") from None


def process_absent(pid):
    """Positive Windows absence only; inaccessible or ambiguous is never absent."""
    if os.name != "nt":
        # The bounded recovery is for the demonstrated Windows shutdown case.
        # Other platforms retain the existing process-identity/status path.
        return False
    if type(pid) is not int or not 0 < pid <= 2147483647:
        raise RuntimeError("NATIVE_PROCESS: invalid recorded process identity.")
    command = ("$ErrorActionPreference='Stop'; $p=$null; try { "
               f"$p=[System.Diagnostics.Process]::GetProcessById({pid}); "
               "'present' } catch [System.ArgumentException] { 'absent' } "
               "catch { 'unknown' } finally { if ($null -ne $p) { $p.Dispose() } }")
    shell = str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    try:
        result = execute([shell, "-NoProfile", "-NonInteractive", "-Command", command], timeout=8)
        answer = result.stdout.strip()
    except (RuntimeError, AttributeError):
        raise RuntimeError("NATIVE_PROCESS: recorded process absence is unverified.") from None
    if answer not in {"absent", "present"}:
        raise RuntimeError("NATIVE_PROCESS: recorded process absence is unverified.")
    return answer == "absent"


def stale_owner_matches(info, record):
    retained = info.get("process")
    if (not isinstance(retained, dict)
            or set(retained) != {"pid", "started", "executable", "process_started"}
            or type(retained["pid"]) is not int or type(retained["started"]) is not int
            or type(retained["process_started"]) is not int
            or retained["pid"] != record["pid"] or retained["started"] != record["started"]
            or retained["started"] <= 0
            or not isinstance(retained["executable"], str)
            or Path(retained["executable"]).resolve() != Path(binary(info, "postgres")).resolve()
            or abs(retained["process_started"] - record["started"]) > 2):
        raise RuntimeError("NATIVE_PROCESS: stale process record does not match retained ownership.")


def startup_snapshot():
    """Fingerprint owner/PID/config bytes; never write or remove these files."""
    try:
        pid = checked_path(DATA / "postmaster.pid")
        configs = tuple(digest(checked_path(DATA / name)) for name in
                        ("postgresql.conf", "postgresql.auto.conf", "pg_hba.conf", "pg_ident.conf", "PG_VERSION"))
        return (digest(checked_path(MARKER)), digest(pid) if pid.exists() else None, configs)
    except OSError:
        raise RuntimeError("NATIVE_PROCESS: startup inputs are unavailable.") from None


def verify_process(info, *, new=False):
    record = pid_record()
    if record is None:
        return None
    identity = process_identity(record["pid"])
    if Path(identity.get("path", "")).resolve() != Path(binary(info, "postgres")).resolve() or abs(identity.get("started", 0) - record["started"]) > 2:
        raise RuntimeError("NATIVE_PROCESS: process executable or start time does not match.")
    result = {**record, "executable": identity["path"], "process_started": identity["started"]}
    if not new and result != info.get("process"):
        raise RuntimeError("NATIVE_PROCESS: process identity differs from the retained ownership marker.")
    return result


def sql(info, statement, database="postgres"):
    if database not in {"postgres", "kapit_m1"}:
        raise RuntimeError("NATIVE_DATABASE: unsupported database.")
    with password_file(libpq=True) as password:
        env = clean_environment()
        env["PGPASSFILE"] = str(password)
        result = execute([binary(info, "psql"), "-X", "-w", "-A", "-t", "-h", "127.0.0.1",
                          "-p", str(PORT), "-U", "kapit_m1", "-d", database, "-v", "ON_ERROR_STOP=1", "-c", statement], env=env, timeout=10)
    return result.stdout.strip()


def verify_connection(info):
    result = sql(info, "SELECT json_build_object('data',current_setting('data_directory'),'port',current_setting('port'),'listen',current_setting('listen_addresses'),'user',current_user,'started',extract(epoch from pg_postmaster_start_time())::bigint,'version',current_setting('server_version'))")
    try:
        value = json.loads(result)
        if Path(value["data"]).resolve() != DATA.resolve() or value["port"] != str(PORT) or value["listen"] != "127.0.0.1" or value["user"] != "kapit_m1" or abs(value["started"] - info["process"]["started"]) > 2:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise RuntimeError("NATIVE_DATABASE: connected database does not match the owned cluster.") from None
    return value["version"]


def status(*, require_running=False):
    info = ownership()
    process = verify_process(info)
    if process is None:
        if require_running:
            raise RuntimeError("NATIVE_STOPPED: run python infra/local.py native-start.")
        return {"state": "stopped", "port": PORT, "postgres": info["binaries"]["version"]}
    version = verify_connection(info)
    return {"state": "running", "port": PORT, "postgres": version, "owned": True}


def start():
    info = ownership()
    record = pid_record()
    recovering = record is not None
    if recovering:
        if not process_absent(record["pid"]):
            return status(require_running=True)
        stale_owner_matches(info, record)
    snapshot = startup_snapshot()
    with socket.socket() as probe:
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            probe.bind(("127.0.0.1", PORT))
        except OSError:
            raise RuntimeError("NATIVE_PORT: port 55436 is unavailable; no existing service was touched.") from None
        # Validate again while the requested port is held. PostgreSQL performs
        # the final lock-file arbitration after this socket is released; this
        # helper never removes a PID file, even after a failed launch.
        if ownership() != info or pid_record() != record or startup_snapshot() != snapshot:
            raise RuntimeError("NATIVE_PROCESS: startup ownership inputs changed.")
        if recovering and not process_absent(record["pid"]):
            raise RuntimeError("NATIVE_PROCESS: recorded process is no longer absent.")
        if startup_snapshot() != snapshot:
            raise RuntimeError("NATIVE_PROCESS: startup ownership inputs changed.")
    log = checked_path(CLUSTER_ROOT / "server.log")
    execute([binary(info, "pg_ctl"), "-D", str(DATA), "-l", str(log), "-w", "-t", "20", "start"], timeout=25, capture=False)
    info = {**info, "process": verify_process(info, new=True)}
    if info["process"] is None:
        raise RuntimeError("NATIVE_PROCESS: new owned process was not established.")
    verify_connection(info)
    retained_database = sql(info, "SELECT count(*) FROM pg_database WHERE datname='kapit_m1'")
    if retained_database not in {"0", "1"} or recovering and retained_database != "1":
        raise RuntimeError("NATIVE_DATABASE: retained workspace database is unavailable; no replacement was created.")
    if retained_database == "0":
        with password_file(libpq=True) as password:
            env = clean_environment()
            env["PGPASSFILE"] = str(password)
            execute([binary(info, "createdb"), "-w", "-h", "127.0.0.1", "-p", str(PORT),
                     "-U", "kapit_m1", "--maintenance-db=postgres", "kapit_m1"], env=env, timeout=15)
    save_marker(info)
    return status(require_running=True)


def stop():
    info = ownership()
    if verify_process(info) is None:
        return {"state": "stopped", "retained": True}
    verify_connection(info)
    execute([binary(info, "pg_ctl"), "-D", str(DATA), "-m", "fast", "-w", "-t", "20", "stop"], timeout=25)
    if pid_record() is not None:
        raise RuntimeError("NATIVE_STOP: shutdown was not confirmed; inspect the owned cluster.")
    info["process"] = None
    save_marker(info)
    return {"state": "stopped", "retained": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "start", "status", "stop"))
    parser.add_argument("--postgres-bin")
    args = parser.parse_args()
    result = init(args.postgres_bin) if args.command == "init" else {"start": start, "status": status, "stop": stop}[args.command]()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, RuntimeError) else "NATIVE_RUNTIME: local runtime files are unavailable or invalid."
        print(message, file=sys.stderr)
        raise SystemExit(2) from None
