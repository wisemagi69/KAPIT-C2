"""Pure, exact-project database configuration. No Supabase browser/Auth client."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re

PROJECT_REF = "vdemkykykybnxlixondr"
SCHEMA = "kapit_m1"
ROLE = "kapit_m1_app"
PROJECT_DIR = Path(__file__).resolve().parents[2]
PRIVATE_DIR = PROJECT_DIR / ".cache/m1-runtime/supabase"
CONFIG_FILE = PRIVATE_DIR / "database.json"
CA_FILE = PRIVATE_DIR / "root.crt"
CREATE_SEARCH_PATH = "kapit_m1,pg_catalog,pg_temp"
FUNCTION_SEARCH_PATH = "pg_catalog,kapit_m1,pg_temp"


@dataclass(frozen=True)
class Target:
    mode: str
    host: str
    username: str


def validate_target(mode, host, username, project_ref=PROJECT_REF, port="5432"):
    if project_ref != PROJECT_REF or str(port) != "5432":
        raise RuntimeError("Only the approved Supabase project and direct/session port 5432 are permitted.")
    if mode == "direct" and host == f"db.{PROJECT_REF}.supabase.co" and username == ROLE:
        return Target(mode, host, username)
    if mode == "session" and re.fullmatch(r"(?:aws|gcp|azure)-[0-9]+-[a-z0-9-]+\.pooler\.supabase\.com", host or "") and username == f"{ROLE}.{PROJECT_REF}":
        return Target(mode, host, username)
    raise RuntimeError("Supabase connection must name the exact approved project and dedicated backend role. Transaction pooling and other targets are not permitted.")


def checked_private_paths():
    runtime_dir = PROJECT_DIR / ".cache/m1-runtime"
    if not runtime_dir.resolve().is_relative_to(PROJECT_DIR.resolve()):
        raise RuntimeError("Supabase runtime directory resolves outside this workspace.")
    if not PRIVATE_DIR.resolve().is_relative_to((PROJECT_DIR / ".cache/m1-runtime").resolve()):
        raise RuntimeError("Supabase configuration resolves outside the dedicated runtime directory.")
    for path in (PRIVATE_DIR, CONFIG_FILE, CA_FILE):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise RuntimeError("Supabase configuration cannot use symlinks or junctions.")


def load_config():
    checked_private_paths()
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        certificate = CA_FILE.read_bytes()
    except (OSError, ValueError):
        raise RuntimeError("Private Supabase configuration/certificate is unavailable. Use the hidden local setup command.") from None
    if not isinstance(data, dict) or set(data) != {"project_ref", "mode", "host", "username", "port", "password", "certificate_sha256"}:
        raise RuntimeError("Private Supabase configuration has an invalid format.")
    validate_target(data["mode"], data["host"], data["username"], data["project_ref"], data["port"])
    if not isinstance(data["password"], str) or not data["password"] or "\x00" in data["password"] or len(data["password"]) > 1024:
        raise RuntimeError("The private backend database password is unavailable or invalid.")
    if b"-----BEGIN CERTIFICATE-----" not in certificate or hashlib.sha256(certificate).hexdigest() != data["certificate_sha256"]:
        raise RuntimeError("The dashboard CA certificate differs from the configured fingerprint.")
    return data


def database_settings():
    validate_hosted_environment(os.environ)
    data = load_config()
    return {
        "ENGINE": "config.supabase_backend",
        "NAME": "postgres",
        "USER": data["username"],
        "PASSWORD": data["password"],
        "HOST": data["host"],
        "PORT": "5432",
        "CONN_MAX_AGE": 0,
        "DISABLE_SERVER_SIDE_CURSORS": True,
        "OPTIONS": {
            "connect_timeout": 10,
            "sslmode": "verify-full",
            "sslrootcert": str(CA_FILE),
            "options": "-c search_path=" + CREATE_SEARCH_PATH,
        },
    }


def refuse_destructive_operation():
    raise RuntimeError("Django test database creation, cloning, destruction and flush are not authorized on the shared Supabase project. Use the reviewed local disposable test profile.")


def require_local_test_context(env):
    if env.get("KAPIT_RUNTIME_CONTEXT", "native") not in {"native", "compose-m1"}:
        raise RuntimeError("The local Django test settings cannot use an inherited hosted database context.")


def validate_hosted_environment(env):
    if any(name.startswith("PG") for name in env) or any(env.get(name) for name in ("DATABASE_URL", "DB_URL", "KAPIT_DB_HOST", "KAPIT_DB_PORT", "KAPIT_DB_PASSWORD", "KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY")):
        raise RuntimeError("Inherited database/libpq/key overrides are not permitted in the explicit hosted profile. Use the reviewed Supabase launcher.")
    source_file = env.get("KAPIT_SECRETS_FILE")
    if source_file and Path(source_file).resolve() != (PROJECT_DIR / ".cache/m1-runtime/secrets.json").resolve():
        raise RuntimeError("The hosted source key must come from the dedicated local runtime file.")
