"""Application reconstruction probe for a restored recovery-drill child.

Runs the real Django application in-process against the owned restored child only:
system checks, migration currency, real password sign-in and scoped API reads
through Django's test client. Opens no listener; prints fixed codes and counts only.
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Operator check accounts provisioned by seed_event; the password stays in the private file.
OPERATOR_FILE = ROOT / ".cache/m1-runtime/operator-accounts.json"
SUBMITTER, RECIPIENT = "ops-submitter", "ops-recipient"


def operator_password():
    try:
        value = json.loads(OPERATOR_FILE.read_text(encoding="utf-8"))["operator"]["password"]
        # Same shape local.operator_accounts() generates; anything else is unusable.
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]{20,128}", value) is None:
            raise ValueError
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


API = "/api/v1/"


def probe():
    if os.environ.get("KAPIT_RUNTIME_CONTEXT") != "recovery-drill":
        return {"ok": False, "code": "CONTEXT_REFUSED"}
    password = operator_password()
    if password is None:
        return {"ok": False, "code": "OPERATOR_ACCOUNTS_UNAVAILABLE"}
    sys.path.insert(0, str(ROOT / "backend"))
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
    import django
    django.setup()
    from django.conf import settings
    from django.core.management import call_command
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor
    from django.test import Client
    from config.runtime_boundary import boundary

    selected = boundary()
    db = settings.DATABASES["default"]
    if selected.context != "recovery-drill" or db["PORT"] != selected.db_port or db["HOST"] != "127.0.0.1":
        return {"ok": False, "code": "CONTEXT_REFUSED"}
    call_command("check", verbosity=0)
    executor = MigrationExecutor(connection)
    pending = len(executor.migration_plan(executor.loader.graph.leaf_nodes()))
    result = {"ok": False, "code": None, "pending_migrations": pending, "accounts": {}}
    if pending:
        result["code"] = "RESTORED_SCHEMA_BEHIND_CODE"
        return result

    def session(username):
        client = Client(HTTP_HOST="127.0.0.1")
        response = client.post(API + "auth/login/", {"username": username, "password": password}, content_type="application/json")
        return client, response.status_code

    checks = {}
    submitter, status = session(SUBMITTER)
    checks["submitter"] = {"login": status}
    if status == 200:
        reports = submitter.get(API + "reports/", {"status": "ALL"})
        checks["submitter"]["reports"] = reports.status_code
        checks["submitter"]["report_count"] = reports.json().get("count") if reports.status_code == 200 else None
    recipient, status = session(RECIPIENT)
    checks["recipient"] = {"login": status}
    if status == 200:
        me = recipient.get(API + "me/").json()["user"]
        feed = recipient.get(API + f"channels/{me['channel']['id']}/feed/")
        checks["recipient"]["role"] = me.get("role")
        checks["recipient"]["feed"] = feed.status_code
        checks["recipient"]["feed_count"] = feed.json().get("count") if feed.status_code == 200 else None
        # Scope still applies after restore: a recipient never reads the private report list.
        checks["recipient"]["private_reports"] = recipient.get(API + "reports/").status_code
    _, status = session(SUBMITTER + "-not-an-account")
    checks["unknown_account_login"] = status
    result["accounts"] = checks
    passed = (checks["submitter"].get("reports") == 200 and checks["recipient"].get("feed") == 200
              and checks["recipient"].get("role") == "recipient" and checks["recipient"].get("private_reports") in (403, 404)
              and checks["unknown_account_login"] == 401)
    result["ok"], result["code"] = passed, "APPLICATION_RECONSTRUCTED" if passed else "APPLICATION_CHECK_FAILED"
    return result


def fault_probe():
    """After the drill stopped the child database: sign-in fails with a generic error and leaks nothing.

    workflow_health is native-only and refuses here before any database access, so it is
    recorded as not exercised; the anonymous reports/ refusal is recorded but proves no DB effect.
    """
    if os.environ.get("KAPIT_RUNTIME_CONTEXT") != "recovery-drill":
        return {"ok": False, "code": "CONTEXT_REFUSED"}
    password = operator_password()
    if password is None:
        return {"ok": False, "code": "OPERATOR_ACCOUNTS_UNAVAILABLE"}
    sys.path.insert(0, str(ROOT / "backend"))
    os.environ["DJANGO_SETTINGS_MODULE"] = "config.settings"
    import django
    django.setup()
    from django.conf import settings
    from django.core.management import call_command
    from django.core.management.base import CommandError
    from django.test import Client
    from config.runtime_boundary import boundary

    selected = boundary()
    db = settings.DATABASES["default"]
    if selected.context != "recovery-drill" or db["PORT"] != selected.db_port or db["HOST"] != "127.0.0.1":
        return {"ok": False, "code": "CONTEXT_REFUSED"}
    # Markers that must never reach a response body: driver/exception names, the port and the credential.
    private = [b"psycopg", b"OperationalError", b"Traceback", b"connection to server", db["PORT"].encode(), db["PASSWORD"].encode(), password.encode()]
    client = Client(HTTP_HOST="127.0.0.1", raise_request_exception=False)
    login = client.post(API + "auth/login/", {"username": SUBMITTER, "password": password}, content_type="application/json")
    reports = client.get(API + "reports/")
    responses = {"login": login, "reports": reports}
    checks = {name: {"status": response.status_code, "private_marker": any(marker in response.content for marker in private),
                     "no_store": "no-store" in response.get("Cache-Control", "")} for name, response in responses.items()}
    try:
        call_command("workflow_health")
        checks["health"] = "REPORTED_HEALTHY"
    except CommandError as error:
        checks["health"] = "NOT_EXERCISED_NATIVE_ONLY" if str(error) == "NATIVE_ONLY" else "OTHER_COMMAND_ERROR"
    # Only the sign-in path is evidence of database-fault containment.
    passed = (login.status_code >= 500 and not checks["login"]["private_marker"] and checks["login"]["no_store"]
              and not checks["reports"]["private_marker"] and checks["health"] != "REPORTED_HEALTHY")
    return {"ok": passed, "code": "LOGIN_DATABASE_FAULT_CONTAINED" if passed else "DATABASE_FAULT_EXPOSED", "accounts": checks}


if __name__ == "__main__":
    try:
        outcome = fault_probe() if sys.argv[1:] == ["--database-stopped"] else probe()
    except Exception:
        # Never reflect SQL, paths, settings or credentials.
        outcome = {"ok": False, "code": "PROBE_UNAVAILABLE"}
    print(json.dumps(outcome, sort_keys=True))
    raise SystemExit(0 if outcome.get("ok") else 2)
