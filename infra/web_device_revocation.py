"""TASK-068 criterion 3: real browser/server revocation of a real enrollment.

Uses the isolated M2 harness (own database, server on 18082, seed_demo). Two genuine
enrollments are created through the mobile challenge/proof protocol with fresh P-256
keys; real Chromium revokes one from Account security; the server is then checked
directly. Evidence keeps fixed booleans/counts only: no token, key, password or page text.
"""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import sys
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_emulator as base

integration = base.integration
require = base.require
MOBILE = integration.BASE + "/api/v1/mobile/"
PASSWORD = "DemoMaintenance!2026"
LABELS = ("Synthetic live phone A", "Synthetic live phone B")


def call(method, url, body=None, headers=None, opener=None):
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with (opener or urllib.request.build_opener()).open(request, timeout=15) as response:
            return response.status, json.loads(response.read(65536) or b"null")
    except urllib.error.HTTPError as error:
        return error.code, None


def enroll(label):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from apps.accounts.mobile_protocol import encode64
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    status, challenge = call("POST", MOBILE + "auth/challenge/", dict(
        username="submitter", password=PASSWORD, installation_id=str(uuid.uuid4()), enrollment_id=None,
        public_key_spki=encode64(public), label=label))
    require(status == 200 and isinstance(challenge, dict), "REVOCATION_CHALLENGE_FAILED")
    signature = key.sign(challenge["proof_message"].encode("ascii"), ec.ECDSA(hashes.SHA256()))
    status, session = call("POST", MOBILE + "auth/token/", dict(
        challenge_id=challenge["challenge_id"], nonce=challenge["nonce"], signature=encode64(signature)))
    require(status == 200 and isinstance(session, dict) and session.get("access_token"), "REVOCATION_ENROLL_FAILED")
    return session


def me(session):
    return call("GET", MOBILE + "me/", headers={"Authorization": "Bearer " + session["access_token"]})[0]


def refresh(session):
    return call("POST", MOBILE + "auth/refresh/", {"refresh_token": session["refresh_token"]})[0]


def web_devices(username):
    import http.cookiejar
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    _, csrf = call("GET", integration.BASE + "/api/v1/auth/csrf/", opener=opener)
    status, _ = call("POST", integration.BASE + "/api/v1/auth/login/", {"username": username, "password": PASSWORD},
                     {"X-CSRFToken": csrf["csrf_token"]}, opener)
    require(status == 200, "REVOCATION_WEB_LOGIN_FAILED")
    return call("GET", integration.BASE + "/api/v1/account/devices/", opener=opener)


def browser(revoke, keep):
    node = subprocess.run(["node", str(ROOT / "web/tests/mobile-devices-live.mjs")], cwd=ROOT / "web",
                          input=json.dumps({"url": integration.BASE, "revoke": revoke, "keep": keep}).encode(),
                          capture_output=True, timeout=180, check=False)
    lines = node.stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        value = json.loads(lines[-1]) if lines else {}
    except ValueError:
        value = {}
    allowed = {"ok", "stage", "revoked_shown", "other_still_active_shown", "revoke_control_removed"}
    return {key: value[key] for key in value if key in allowed and isinstance(value[key], (bool, str))}


def execute():
    evidence = {"task": "TASK-068", "criterion": 3, "ok": False, "stage": "harness"}
    run = base.checked_path(ROOT / ".cache/m1-runtime/web-device-revocation" / secrets.token_hex(12))
    run.mkdir(parents=True, exist_ok=False)
    try:
        with base.observed_harness(evidence) as harness:
            harness.fault("normal")
            from apps.accounts.models import DeviceEnrollment
            evidence["stage"] = "enroll"
            sessions = [enroll(label) for label in LABELS]
            rows = {row.label: row for row in DeviceEnrollment.objects.filter(owner__username="submitter")}
            require(set(rows) == set(LABELS) and all(rows[label].revoked_at is None for label in LABELS), "REVOCATION_SETUP")
            require([me(session) for session in sessions] == [200, 200], "REVOCATION_SETUP_AUTH")
            evidence["before"] = {"enrollments": 2, "both_authenticate": True}
            evidence["stage"] = "foreign_owner"
            status, listing = web_devices("reviewer")
            foreign = json.dumps(listing or {})
            evidence["foreign_owner_hidden"] = status in {200, 403, 404} and not any(
                str(rows[label].id) in foreign or label in foreign for label in LABELS)
            require(evidence["foreign_owner_hidden"], "REVOCATION_FOREIGN_VISIBLE")
            evidence["stage"] = "browser"
            evidence["browser"] = browser(LABELS[0], LABELS[1])
            require(evidence["browser"].get("ok") is True, "REVOCATION_BROWSER_FAILED")
            evidence["stage"] = "server_after"
            for row in rows.values():
                row.refresh_from_db()
            after = {"revoked_marked": rows[LABELS[0]].revoked_at is not None,
                     "other_not_revoked": rows[LABELS[1]].revoked_at is None,
                     "revoked_access_denied": me(sessions[0]) == 401,
                     "revoked_refresh_denied": refresh(sessions[0]) in {400, 401},
                     "other_access_ok": me(sessions[1]) == 200,
                     "enrollment_count": DeviceEnrollment.objects.filter(owner__username="submitter").count()}
            evidence["after"] = after
            require(all(after[key] is True for key in after if key != "enrollment_count") and after["enrollment_count"] == 2,
                    "REVOCATION_SERVER_STATE")
            evidence["stage"] = "complete"
        evidence["ok"] = True
    except BaseException as error:
        evidence["failure"] = {"code": str(error) if isinstance(error, base.EmulatorError) else "REVOCATION_FAILED",
                               "stage": evidence["stage"], **base.failure_metadata(error)}
        raise
    finally:
        (run / "result.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    return evidence


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    if Path(sys.executable).resolve() != Path(integration.local.python_path()).resolve():
        return subprocess.run([integration.local.python_path(), "-B", str(Path(__file__).resolve()), *sys.argv[1:]],
                              cwd=ROOT, env=integration.local.managed_environment(), check=False).returncode
    try:
        execute()
        return 0
    except BaseException:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
