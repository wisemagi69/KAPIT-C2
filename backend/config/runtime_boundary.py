"""Pure local-only network/context checks, independent of Django imports."""
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path


@dataclass(frozen=True)
class Boundary:
    context: str
    db_host: str
    db_port: str
    bind_host: str


def native_boundary(env):
    host = env.get("KAPIT_DB_HOST", "127.0.0.1")
    if host == "localhost":
        host = "127.0.0.1"
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise ValueError
    except (ValueError, TypeError):
        raise RuntimeError("Native M1 database host must be a numeric loopback address. Remote database access is not authorized.") from None
    if env.get("KAPIT_DB_PORT", "55436") != "55436":
        raise RuntimeError("Native M1 database port must be the project's isolated port 55436.")
    return Boundary("native", host, "55436", "127.0.0.1")


RECOVERY_ROOT = Path(__file__).resolve().parents[2] / ".cache" / "m4-recovery"
RECOVERY_CHILD_OWNER = "KAPIT-C2 isolated restore rehearsal v1"


def recovery_boundary(env):
    """Disposable restored child only: its owned marker must name this exact loopback drill port."""
    token, port = env.get("KAPIT_RECOVERY_TARGET", ""), env.get("KAPIT_DB_PORT", "")
    if (env.get("KAPIT_DB_HOST") != "127.0.0.1" or len(token) != 32 or any(c not in "0123456789abcdef" for c in token)
            or not port.isdigit() or not 56000 <= int(port) <= 56999):
        raise RuntimeError("Recovery drill context requires an owned loopback restore child.")
    try:
        import json
        marker = json.loads((RECOVERY_ROOT / token / "owner.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("Recovery drill context requires an owned loopback restore child.") from None
    if (not isinstance(marker, dict) or marker.get("owner") != RECOVERY_CHILD_OWNER or marker.get("target") != token
            or marker.get("port") != int(port)):
        raise RuntimeError("Recovery drill context requires an owned loopback restore child.")
    return Boundary("recovery-drill", "127.0.0.1", port, "127.0.0.1")


def verified_container_image():
    # An inherited process flag alone is never sufficient to open a bind or
    # select the private compose database. These markers belong to Docker and
    # the specifically built image, not a user's native environment.
    if not Path("/.dockerenv").is_file():
        return False
    try:
        return Path("/app/.kapit-m1-container").read_text(encoding="ascii").strip() == "kapit-c2-local-m1"
    except OSError:
        return False


def boundary(env=None):
    env = os.environ if env is None else env
    context = env.get("KAPIT_RUNTIME_CONTEXT", "native")
    if context == "native":
        return native_boundary(env)
    if context == "recovery-drill":
        return recovery_boundary(env)
    if context == "supabase-m1":
        from .supabase import load_config, validate_hosted_environment
        validate_hosted_environment(env)
        data = load_config()
        return Boundary("supabase-m1", data["host"], "5432", "127.0.0.1")
    if context == "hosted-demo":
        from .hosted import validate_environment
        validate_environment(env)
        return Boundary("hosted-demo", env["KAPIT_HOSTED_DB_HOST"], "5432", "0.0.0.0")
    if context != "compose-m1" or not verified_container_image():
        raise RuntimeError("Container M1 context requires the reviewed local Docker image and entrypoint.")
    if env.get("KAPIT_DB_HOST") != "db" or env.get("KAPIT_DB_PORT") != "5432":
        raise RuntimeError("Container M1 database must be the private compose service db:5432.")
    return Boundary("compose-m1", "db", "5432", "0.0.0.0")
