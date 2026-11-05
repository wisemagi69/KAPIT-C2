"""Hosted synthetic demonstration: Supabase database, Render API/worker, Vercel front end.

Laptop commands (private values stay in .cache/hosted-demo/, never printed):
  init      --pooler-host HOST --ca-file FILE     generate fresh keys/passwords and setup files
  set-urls  --origin https://APP.vercel.app --backend-host API.onrender.com
  check | migrate | seed                         verify / apply Django schema / fictional accounts
Container command (Render):
  serve                                          verify schema, run worker + web on $PORT

Scope: ai/reports/hosted-demo-authorization.md. Fresh synthetic data only; the local event
database, its keys and backups are never read or copied by this tool.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / ".cache" / "hosted-demo"
CONFIG = PRIVATE / "config.json"
VERCEL = ROOT / "web" / "vercel.json"
ACCOUNT_VARS = ("KAPIT_HOSTED_SUBMITTER_PASSWORD", "KAPIT_HOSTED_REVIEWER_PASSWORD",
                "KAPIT_HOSTED_RECIPIENT_PASSWORD", "KAPIT_HOSTED_ADMINISTRATOR_PASSWORD")
SERVICE_VARS = ("KAPIT_HOSTED_DB_HOST", "KAPIT_HOSTED_DB_PASSWORD", "KAPIT_HOSTED_DB_CA", "KAPIT_HOSTED_DB_CA_SHA256",
                "KAPIT_SECRET_KEY", "KAPIT_SOURCE_KEY", "KAPIT_PUBLIC_ORIGIN", "KAPIT_BACKEND_HOST")
PLACEHOLDER_BACKEND = "REPLACE-WITH-RENDER-HOST.onrender.com"


def scram_verifier(password, salt=None, iterations=4096):
    """PostgreSQL SCRAM-SHA-256 verifier (RFC 5802/7677); the plaintext never reaches SQL."""
    salt = os.urandom(16) if salt is None else salt
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda value: base64.b64encode(value).decode("ascii")
    return f"SCRAM-SHA-256${iterations}:{b64(salt)}${b64(stored_key)}:{b64(server_key)}"


def normalized_certificate(data):
    text = data.decode("ascii", "strict").replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    if "-----BEGIN CERTIFICATE-----" not in text:
        raise RuntimeError("The CA file is not a PEM certificate. Download it from the Supabase dashboard (Database settings > SSL).")
    return text


def load():
    try:
        return json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise RuntimeError("Hosted configuration is missing. Run: python infra/hosted/hosted.py init --pooler-host HOST --ca-file FILE") from None


def write_private(path, text):
    PRIVATE.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def service_env(config):
    ca = config["ca"]
    return {
        "KAPIT_RUNTIME_CONTEXT": "hosted-demo",
        "KAPIT_HOSTED_DB_HOST": config["pooler_host"],
        "KAPIT_HOSTED_DB_PASSWORD": config["db_password"],
        "KAPIT_HOSTED_DB_CA": ca,
        "KAPIT_HOSTED_DB_CA_SHA256": hashlib.sha256(ca.encode("ascii")).hexdigest(),
        "KAPIT_SECRET_KEY": config["secret_key"],
        "KAPIT_SOURCE_KEY": config["source_key"],
        "KAPIT_PUBLIC_ORIGIN": config.get("origin") or "",
        "KAPIT_BACKEND_HOST": config.get("backend_host") or "",
    }


def write_outputs(config):
    env = service_env(config)
    lines = ["# Paste into Render > Environment > Add from .env. PRIVATE: do not share or commit."]
    for name in ("KAPIT_RUNTIME_CONTEXT",) + SERVICE_VARS:
        value = env[name].replace("\n", "\\n") if name == "KAPIT_HOSTED_DB_CA" else env[name]
        lines.append(f"{name}={value}")
    write_private(PRIVATE / "render.env", "\n".join(lines) + "\n")
    write_private(PRIVATE / "activate-role.sql", "\n".join([
        "-- Run ONCE in Supabase SQL Editor after infra/supabase/schema.sql. PRIVATE: contains a credential verifier.",
        f"ALTER ROLE kapit_m1_app WITH LOGIN PASSWORD '{scram_verifier(config['db_password'])}';",
        "",
    ]))
    names = ("submitter", "reviewer", "recipient", "administrator")
    write_private(PRIVATE / "accounts.txt", "Hosted demo sign-in (PRIVATE; synthetic accounts only)\n" + "".join(
        f"{name}: {config['accounts'][variable]}\n" for name, variable in zip(names, ACCOUNT_VARS)))
    write_vercel(config.get("backend_host") or PLACEHOLDER_BACKEND)


def write_vercel(backend):
    security = [
        {"key": "X-Content-Type-Options", "value": "nosniff"},
        {"key": "X-Frame-Options", "value": "DENY"},
        {"key": "Referrer-Policy", "value": "no-referrer"},
        {"key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()"},
        {"key": "Strict-Transport-Security", "value": "max-age=86400"},
        {"key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'"},
    ]
    document = {
        "$schema": "https://openapi.vercel.sh/vercel.json",
        "framework": "vite",
        "buildCommand": "npm run build",
        "outputDirectory": "dist",
        # Same-origin proxy: cookies stay SameSite=Strict and no CORS is opened.
        "rewrites": [
            {"source": "/api/(.*)", "destination": f"https://{backend}/api/$1"},
            {"source": "/workspace", "destination": "/index.html"},
            {"source": "/workspace/(.*)", "destination": "/index.html"},
        ],
        "headers": [{"source": "/(.*)", "headers": security}],
    }
    VERCEL.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n")


def init(args):
    from config.supabase import PROJECT_REF, ROLE, validate_target
    validate_target("session", args.pooler_host, f"{ROLE}.{PROJECT_REF}")
    ca = normalized_certificate(Path(args.ca_file).read_bytes())
    config = json.loads(CONFIG.read_text(encoding="utf-8")) if CONFIG.is_file() else {}
    # Fresh keys, distinct from the local event runtime; existing hosted keys are kept.
    config.setdefault("db_password", secrets.token_urlsafe(32))
    config.setdefault("secret_key", secrets.token_urlsafe(64))
    config.setdefault("source_key", base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"))
    config.setdefault("accounts", {name: secrets.token_urlsafe(18) for name in ACCOUNT_VARS})
    config.update(pooler_host=args.pooler_host, ca=ca)
    write_private(CONFIG, json.dumps(config, indent=2))
    write_outputs(config)
    print(f"Hosted setup files written to {PRIVATE} (render.env, activate-role.sql, accounts.txt) and {VERCEL}. No connection was made.")


def set_urls(args):
    from config.hosted import backend_host, public_origin
    config = load()
    config["origin"] = public_origin(args.origin)[0]
    config["backend_host"] = backend_host(args.backend_host)
    write_private(CONFIG, json.dumps(config, indent=2))
    write_outputs(config)
    print("Updated render.env and web/vercel.json. Re-paste render.env into Render and redeploy both services.")


def run_django(command):
    try:
        import django  # noqa: F401
    except ImportError:
        venv = ROOT / ".cache" / "m1-runtime" / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        if not venv.is_file() or Path(sys.executable).resolve() == venv.resolve():
            raise RuntimeError("Django is unavailable. Run the local website setup once (infra/Start KAPIT.cmd) to create the project venv.")
        raise SystemExit(subprocess.call([str(venv), str(Path(__file__).resolve()), command]))
    config = load()
    env = service_env(config)
    if not env["KAPIT_PUBLIC_ORIGIN"] or not env["KAPIT_BACKEND_HOST"]:
        # Local schema work does not serve web traffic; placeholders satisfy validation only.
        env["KAPIT_PUBLIC_ORIGIN"] = env["KAPIT_PUBLIC_ORIGIN"] or "https://placeholder.invalid"
        env["KAPIT_BACKEND_HOST"] = env["KAPIT_BACKEND_HOST"] or "placeholder.invalid"
    for key in list(os.environ):
        if key.startswith(("PG", "KAPIT_")) or key in {"DATABASE_URL", "DB_URL"}:
            del os.environ[key]
    os.environ.update(env)
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
    from infra.supabase.prepare import django_bootstrap
    if command == "seed":
        django_bootstrap(apply_migrations=False)
        os.environ.update(config["accounts"])
        from django.core.management import call_command
        call_command("seed_hosted_demo")
        print(f"Sign-in passwords are in {PRIVATE / 'accounts.txt'}.")
    else:
        django_bootstrap(apply_migrations=command == "migrate")


def serve():
    if os.environ.get("KAPIT_RUNTIME_CONTEXT") != "hosted-demo":
        raise RuntimeError("serve runs only inside the hosted container.")
    env = dict(os.environ, DJANGO_SETTINGS_MODULE="config.settings")
    from config.hosted import validate_environment
    validate_environment(env)
    python = sys.executable
    worker = subprocess.Popen([python, str(ROOT / "backend/manage.py"), "process_jobs"], env=env)
    web = subprocess.Popen([python, str(ROOT / "infra/server.py")], env=env)
    # One container, two supervised children: if either exits, stop both so the
    # platform restarts a consistent pair instead of serving without a worker.
    import time
    try:
        while worker.poll() is None and web.poll() is None:
            time.sleep(2)
    finally:
        for child in (web, worker):
            if child.poll() is None:
                child.terminate()
        for child in (web, worker):
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                child.kill()
    raise SystemExit(1)


def main(argv=None):
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "backend"))
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init")
    p.add_argument("--pooler-host", required=True, help="Supabase Connect > Session pooler host, e.g. aws-0-ap-southeast-1.pooler.supabase.com")
    p.add_argument("--ca-file", required=True, help="Supabase Database settings > SSL certificate download")
    p = sub.add_parser("set-urls")
    p.add_argument("--origin", required=True)
    p.add_argument("--backend-host", required=True)
    for name in ("check", "migrate", "seed", "serve"):
        sub.add_parser(name)
    args = parser.parse_args(argv)
    if args.command == "init":
        init(args)
    elif args.command == "set-urls":
        set_urls(args)
    elif args.command == "serve":
        serve()
    else:
        run_django(args.command)
        print("Done." if args.command != "check" else "Hosted database verified.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
    except SystemExit:
        raise
    except Exception as error:
        if type(error).__name__ == "ImproperlyConfigured":
            print(str(error), file=sys.stderr)  # Fixed settings messages; no values.
            raise SystemExit(1) from None
        # Driver errors can embed connection details; report only the category.
        print(f"Hosted command failed ({type(error).__name__}). Check the pooler host, role activation and network.", file=sys.stderr)
        raise SystemExit(1) from None
