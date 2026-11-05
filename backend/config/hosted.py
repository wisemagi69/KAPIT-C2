"""Public synthetic demonstration profile: Render API + Vercel front end + Supabase DB.

Authorized 2026-11-05 (ai/reports/hosted-demo-authorization.md): fresh synthetic data
only, approved project vdemkykykybnxlixondr only, session pooler 5432 only, verified TLS.
Every value arrives through the host's environment; nothing falls back to local files,
and the local event database/keys are never read by this profile.
"""
import hashlib
import os
from pathlib import Path
import re
import tempfile

from .supabase import CREATE_SEARCH_PATH, PROJECT_REF, ROLE, validate_target

CONTEXT = "hosted-demo"
REQUIRED = (
    "KAPIT_HOSTED_DB_HOST", "KAPIT_HOSTED_DB_PASSWORD", "KAPIT_HOSTED_DB_CA", "KAPIT_HOSTED_DB_CA_SHA256",
    "KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_PUBLIC_ORIGIN", "KAPIT_BACKEND_HOST",
)
FORBIDDEN = ("DATABASE_URL", "DB_URL", "KAPIT_DB_HOST", "KAPIT_DB_PORT", "KAPIT_DB_PASSWORD", "KAPIT_SECRETS_FILE")
HOST_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+")


def public_origin(value):
    match = re.fullmatch(r"https://([a-z0-9.-]+)", value or "")
    if not match or not HOST_PATTERN.fullmatch(match.group(1)):
        raise RuntimeError("KAPIT_PUBLIC_ORIGIN must be an exact https:// origin with no path, port or trailing slash.")
    return value, match.group(1)


def backend_host(value):
    if not HOST_PATTERN.fullmatch(value or ""):
        raise RuntimeError("KAPIT_BACKEND_HOST must be a bare DNS hostname.")
    return value


def certificate_bytes(env):
    # Hosts store multi-line values unchanged; a single-line paste may carry literal \n.
    text = env["KAPIT_HOSTED_DB_CA"].replace("\\n", "\n").strip() + "\n"
    data = text.encode("ascii", "strict")
    if b"-----BEGIN CERTIFICATE-----" not in data or hashlib.sha256(data).hexdigest() != env["KAPIT_HOSTED_DB_CA_SHA256"]:
        raise RuntimeError("The hosted database CA certificate differs from its pinned fingerprint.")
    return data


def validate_environment(env):
    if any(name.startswith("PG") for name in env) or any(env.get(name) for name in FORBIDDEN):
        raise RuntimeError("Inherited libpq/local database overrides are not permitted in the hosted profile.")
    missing = [name for name in REQUIRED if not env.get(name)]
    if missing:
        raise RuntimeError("Hosted configuration is incomplete: " + ", ".join(missing))
    validate_target("session", env["KAPIT_HOSTED_DB_HOST"], f"{ROLE}.{PROJECT_REF}")
    password = env["KAPIT_HOSTED_DB_PASSWORD"]
    if len(password) < 24 or len(password) > 1024 or "\x00" in password:
        raise RuntimeError("The hosted database password is invalid.")
    public_origin(env["KAPIT_PUBLIC_ORIGIN"])
    backend_host(env["KAPIT_BACKEND_HOST"])
    certificate_bytes(env)
    return env


def certificate_path(env):
    data = certificate_bytes(env)
    directory = Path(tempfile.gettempdir()) / "kapit-hosted"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / (hashlib.sha256(data).hexdigest()[:16] + ".crt")
    if not path.is_file() or path.read_bytes() != data:
        path.write_bytes(data)
    return path


def database_settings(env=None):
    env = validate_environment(os.environ if env is None else env)
    return {
        "ENGINE": "config.supabase_backend",
        "NAME": "postgres",
        "USER": f"{ROLE}.{PROJECT_REF}",
        "PASSWORD": env["KAPIT_HOSTED_DB_PASSWORD"],
        "HOST": env["KAPIT_HOSTED_DB_HOST"],
        "PORT": "5432",
        "CONN_MAX_AGE": 0,
        "DISABLE_SERVER_SIDE_CURSORS": True,
        "OPTIONS": {
            "connect_timeout": 10,
            "sslmode": "verify-full",
            "sslrootcert": str(certificate_path(env)),
            "options": "-c search_path=" + CREATE_SEARCH_PATH,
        },
    }


def web_settings(env=None):
    env = validate_environment(os.environ if env is None else env)
    origin, origin_host = public_origin(env["KAPIT_PUBLIC_ORIGIN"])
    host = backend_host(env["KAPIT_BACKEND_HOST"])
    return {
        # Vercel's /api rewrite reaches the backend under its own host; the
        # public origin is also accepted in case the proxy preserves Host.
        "ALLOWED_HOSTS": sorted({host, origin_host}),
        "CSRF_TRUSTED_ORIGINS": [origin],
    }
