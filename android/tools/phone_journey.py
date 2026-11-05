"""TASK-075/064: user-driven live journey on the user's own phone over Wireless debugging.

The user operates the real spike app; this runner never types, taps, unlocks or enters any credential. It owns only:
an isolated MobileHarness (own database, server on 18082, seed_demo) and its own `adb reverse tcp:18082` mapping
(created only if absent, removed only if still matching under exclusive device reservation). It verifies the installed app bytes, then observes independent
server state. Evidence keeps fixed counts, booleans and timings; no serial, address, token or report content.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import secrets
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from infra import mobile_integration as integration
from infra.mobile_device import AndroidTools, PACKAGE, ENDPOINT, parse_reverse, safe_environment

EMULATOR_HARDWARE = {"ranchu", "goldfish"}
APP_SHA256 = "f6ea61a3431e8cf1e2de914ebf2eb5c7873ea64d56e4927bbe2e02e86fcee96f"
DEADLINE_SECONDS = 1800


class JourneyError(RuntimeError):
    """Only fixed codes leave this boundary."""


def require(value, code):
    if not value:
        raise JourneyError(code)


class Phone:
    def __init__(self, serial):
        require(re.fullmatch(r"[A-Za-z0-9._:-]{1,96}", serial), "PHONE_SERIAL_FORMAT")
        self.adb, self.serial = AndroidTools().adb, serial

    def command(self, *parts, timeout=30):
        result = subprocess.run([str(self.adb), "-s", self.serial, *parts], capture_output=True, text=True,
                                timeout=timeout, env=safe_environment(), check=False)
        require(result.returncode == 0, "PHONE_COMMAND_FAILED")
        return result.stdout

    def verify(self):
        require(self.command("shell", "getprop", "ro.hardware").strip() not in EMULATOR_HARDWARE, "PHONE_IS_EMULATOR")
        require(int(self.command("shell", "getprop", "ro.build.version.sdk").strip()) >= 35, "PHONE_API")
        paths = [line.split(":", 1)[1] for line in self.command("shell", "pm", "path", PACKAGE).splitlines() if line.startswith("package:")]
        base = [p for p in paths if p.endswith("/base.apk")]
        require(len(base) == 1, "PHONE_APP_NOT_INSTALLED")
        digest = self.command("shell", "sha256sum", base[0]).split()[0]
        require(digest == APP_SHA256, "PHONE_APP_HASH_MISMATCH")
        return {"physical": True, "api": int(self.command("shell", "getprop", "ro.build.version.sdk").strip()), "app_sha256": digest}


def counts():
    from apps.accounts.models import DeviceEnrollment
    from apps.operations.models import ProcessingJob, SyncReceipt
    from apps.publications.models import Publication
    from apps.review.models import ReviewDecision
    from apps.reports.models import Report, ReportRevision
    return {"enrollments": DeviceEnrollment.objects.count(), "reports": Report.objects.count(),
            "revisions": ReportRevision.objects.count(), "receipts": SyncReceipt.objects.count(),
            "jobs": ProcessingJob.objects.count(), "jobs_done": ProcessingJob.objects.filter(status="DONE").count(),
            "decisions": ReviewDecision.objects.count(), "publications": Publication.objects.count()}


def bindings():
    """Independent identity checks once one revision exists; fixed booleans only."""
    from apps.accounts.models import User, DeviceEnrollment
    from apps.operations.models import ProcessingJob, SyncReceipt
    from apps.reports.models import ReportRevision
    actor = User.objects.get(username="submitter")
    enrollment = DeviceEnrollment.objects.get()
    revision = ReportRevision.objects.select_related("report").get()
    receipt, job = SyncReceipt.objects.get(), ProcessingJob.objects.get()
    return {"enrollment_owner_is_submitter": enrollment.owner_id == actor.id and enrollment.revoked_at is None,
            "revision_by_submitter": revision.submitted_by_id == revision.report.author_id == actor.id,
            "revision_from_this_enrollment": revision.accepted_device_id == enrollment.id == receipt.accepted_device_id,
            "receipt_matches_revision": receipt.revision_id == revision.id and receipt.operation_id == revision.operation_id
                and receipt.request_hash == revision.request_hash,
            "job_for_revision": job.revision_id == revision.id, "first_revision": revision.revision_no == 1,
            "template": revision.template_version == "demo-maintenance-v1"}


def web_session(username):
    """A real website session for a seeded synthetic account; returns a bounded JSON caller."""
    import http.cookiejar, urllib.request, urllib.error
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(method, path, body=None, csrf=None):
        request = urllib.request.Request(integration.BASE + path, method=method,
            data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json", **({"X-CSRFToken": csrf} if csrf else {})})
        try:
            with opener.open(request, timeout=15) as response:
                return response.status, response.read(262144).decode("utf-8")
        except urllib.error.HTTPError as error:
            return error.code, error.read(65536).decode("utf-8", "replace")
    _, token = call("GET", "/api/v1/auth/csrf/")
    status, _ = call("POST", "/api/v1/auth/login/", {"username": username, "password": "DemoMaintenance!2026"}, json.loads(token)["csrf_token"])
    require(status == 200, "JOURNEY_WEB_LOGIN_FAILED")
    return call


def browser_review(evidence):
    """Real Chromium: reviewer approves the phone's report; recipient sees only the approved reduced projection."""
    from apps.reports.models import ReportRevision
    from apps.reports.crypto import source_payload
    from apps.publications.models import Publication
    from apps.review.models import ReviewDecision
    revision = ReportRevision.objects.select_related("report").get()
    payload = source_payload(revision)
    raw = {k: str(payload.get(k) or "") for k in ("site_label", "reporter_label", "narrative")}
    # Non-revealing shape only: which private fields were empty, too short to test, or tested.
    evidence["private_field_shape"] = {k: "empty" if not v.strip() else "short" if len(v.strip()) < 3 else "tested" for k, v in raw.items()}
    private = [v for v in raw.values() if len(v.strip()) >= 3]
    require(private, "JOURNEY_NO_PRIVATE_VALUE_TO_TEST")  # fail closed: a leak check with nothing to compare proves nothing
    recipient = web_session("recipient")
    status, me = recipient("GET", "/api/v1/me/")
    require(status == 200, "JOURNEY_RECIPIENT_ME")
    channel = json.loads(me)["user"]["channel"]["id"]
    node = subprocess.run(["node", str(ROOT / "web/tests/phone-review-live.mjs")], cwd=ROOT / "web", capture_output=True, timeout=240, check=False,
        input=json.dumps({"url": integration.BASE, "channel_id": channel, "reference": "R-" + revision.report.id.hex[:8].upper()}).encode())  # reports/selectors.py:33
    lines = node.stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        result = json.loads(lines[-1]) if lines else {}
    except ValueError:
        result = {}
    keep = {"ok", "stage", "recipient_responses_scanned", "projection_equals_approved_candidate", "recipient_source_denied"}
    evidence["browser"] = {k: result[k] for k in result if k in keep}
    require(result.get("ok") is True, "JOURNEY_BROWSER_REVIEW_FAILED")
    publication = Publication.objects.get()
    decision = ReviewDecision.objects.get()
    stored = json.dumps(publication.projection)
    status, feed = recipient("GET", f"/api/v1/channels/{channel}/feed/")
    require(status == 200, "JOURNEY_RECIPIENT_FEED")
    status, detail = recipient("GET", f"/api/v1/publications/{publication.id}/")
    require(status == 200, "JOURNEY_RECIPIENT_DETAIL")
    evidence["publication_checks"] = {
        "one_approve_decision_by_reviewer": decision.action == "APPROVE" and decision.reviewer.username == "reviewer",
        "publication_id_matches_browser": str(publication.id) == result.get("publication_id"),
        "private_fields_checked": len(private),
        "no_private_value_in_stored_projection": not any(v in stored for v in private),
        "no_private_value_in_recipient_feed_or_detail": not any(v in feed or v in detail for v in private),
        "recipient_feed_count_one": json.loads(feed).get("count") == 1}
    require(all(v for k, v in evidence["publication_checks"].items() if k != "private_fields_checked"), "JOURNEY_PUBLICATION_CHECK")


def revoke_via_owner_web_session(enrollment_id):
    """The owner's own website session revokes the enrollment through the Account security API (TASK-068 endpoint)."""
    import http.cookiejar, urllib.request, urllib.error
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def call(method, path, body=None, csrf=None):
        request = urllib.request.Request(integration.BASE + path, method=method,
            data=None if body is None else json.dumps(body).encode(), headers={"Content-Type": "application/json", **({"X-CSRFToken": csrf} if csrf else {})})
        try:
            with opener.open(request, timeout=15) as response:
                return response.status, json.loads(response.read(65536) or b"null")
        except urllib.error.HTTPError as error:
            return error.code, None
    _, token = call("GET", "/api/v1/auth/csrf/")
    status, _ = call("POST", "/api/v1/auth/login/", {"username": "submitter", "password": "DemoMaintenance!2026"}, token["csrf_token"])
    require(status == 200, "JOURNEY_WEB_LOGIN_FAILED")
    _, token = call("GET", "/api/v1/auth/csrf/")
    status, body = call("POST", f"/api/v1/account/devices/{enrollment_id}/revoke/", {}, token["csrf_token"])
    require(status == 200 and isinstance(body, dict) and body.get("revoked") is True, "JOURNEY_REVOKE_FAILED")


def execute(serial, scenario="happy"):
    run = ROOT / ".cache/m1-runtime/phone-journey" / secrets.token_hex(12)
    run.mkdir(parents=True, exist_ok=False)
    evidence = {"task": "TASK-075/TASK-064", "ok": False, "physical_phone": True, "transport": "wireless_adb_reverse_test_deviation",
                "host_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "milestones": {}, "stage": "verify_phone",
                "scenario": scenario}
    resume = run / "resume"
    phone, created_reverse = Phone(serial), False
    started = time.monotonic()
    try:
        evidence["phone"] = phone.verify()
        evidence["stage"] = "harness"
        with integration.MobileHarness() as harness:
            harness.fault("normal")
            initial = counts()
            require(all(value == 0 for value in initial.values()), "JOURNEY_SERVER_NOT_EMPTY")
            evidence["stage"] = "reverse"
            require(ENDPOINT not in parse_reverse(phone.command("reverse", "--list")), "JOURNEY_REVERSE_PREEXISTING")
            phone.command("reverse", "--no-rebind", ENDPOINT, ENDPOINT)
            created_reverse = True
            require(parse_reverse(phone.command("reverse", "--list")).get(ENDPOINT) == ENDPOINT, "JOURNEY_REVERSE_FAILED")
            evidence["stage"] = "waiting_for_user"
            print(json.dumps({"ready": True, "server": "isolated synthetic", "account": "submitter", "run": run.name}), flush=True)
            last, offline = None, None
            while time.monotonic() - started < DEADLINE_SECONDS:
                harness.assert_owned()
                now = counts()
                require(now["decisions"] == 0 and now["publications"] == 0 or (scenario == "review" and "processed" in evidence["milestones"]),
                        "JOURNEY_UNEXPECTED_PUBLICATION")
                require(now["enrollments"] <= 1 and now["revisions"] <= 1 and now["receipts"] <= now["revisions"], "JOURNEY_EFFECT_MISMATCH")
                for name, reached in (("enrolled", now["enrollments"] == 1), ("received", now["revisions"] == 1 and now["receipts"] == 1),
                                      ("processed", now["jobs_done"] == 1)):
                    if reached and name not in evidence["milestones"]:
                        evidence["milestones"][name] = round(time.monotonic() - started, 1)
                        print(json.dumps({"milestone": name}), flush=True)
                if now != last:
                    evidence["server_counts"] = now; last = now
                if scenario == "dropped_ack":
                    # One-shot harness fault: the first sync commits server-side and its response is lost. The user's
                    # next sync must replay the identical operation; the server may never create a second revision.
                    if offline is None and "enrolled" in evidence["milestones"]:
                        harness.fault("drop_after_commit"); offline = True
                        evidence["milestones"]["drop_armed"] = round(time.monotonic() - started, 1)
                        print(json.dumps({"phase": "drop_armed"}), flush=True)
                    if offline is True and now["revisions"] == 1:
                        offline = "committed"
                        evidence["milestones"]["committed_response_dropped"] = round(time.monotonic() - started, 1)
                        print(json.dumps({"phase": "committed_response_dropped"}), flush=True)
                    if offline == "committed":
                        require(now["revisions"] == 1 and now["receipts"] == 1 and now["reports"] == 1, "JOURNEY_DUPLICATE_AFTER_REPLAY")
                        if not resume.exists():
                            time.sleep(2)
                            continue
                        evidence["user_reported_received_after_retry"] = True
                    elif offline is True:
                        time.sleep(2)
                        continue
                if scenario == "revoke":
                    # After enrollment the owner revokes it via the website API; any later app sync must create nothing.
                    from apps.accounts.models import DeviceEnrollment
                    if offline is None and "enrolled" in evidence["milestones"]:
                        enrollment = DeviceEnrollment.objects.get()
                        revoke_via_owner_web_session(enrollment.id)
                        enrollment.refresh_from_db()
                        require(enrollment.revoked_at is not None, "JOURNEY_REVOKE_NOT_RECORDED")
                        offline = True
                        evidence["milestones"]["revoked"] = round(time.monotonic() - started, 1)
                        print(json.dumps({"phase": "revoked"}), flush=True)
                    if offline is True:
                        require(now["revisions"] == 0 and now["receipts"] == 0 and now["reports"] == 0, "JOURNEY_EFFECT_AFTER_REVOCATION")
                        require(DeviceEnrollment.objects.get().revoked_at is not None, "JOURNEY_REVOCATION_UNDONE")
                        if resume.exists():
                            time.sleep(5)
                            final = counts()
                            require(final["revisions"] == 0 and final["receipts"] == 0 and final["enrollments"] == 1, "JOURNEY_EFFECT_AFTER_REVOCATION")
                            evidence.update(server_counts=final, no_effect_after_revocation=True, user_reported_access_lost=True, ok=True)
                            evidence["milestones"]["user_confirmed"] = round(time.monotonic() - started, 1)
                            break
                        time.sleep(2)
                        continue
                if scenario == "force_stop":
                    # Unreachable server; on `stop` the runner force-stops the app and proves it stopped; the user then
                    # reopens and unlocks; on `resume` the server is restored. No effect may occur before `resume`.
                    if offline is None and "enrolled" in evidence["milestones"]:
                        harness.fault("unavailable"); offline = True
                        evidence["milestones"]["server_unreachable"] = round(time.monotonic() - started, 1)
                        print(json.dumps({"phase": "server_unreachable"}), flush=True)
                    if offline is True:
                        require(now["revisions"] == 0 and now["receipts"] == 0, "JOURNEY_EFFECT_WHILE_UNREACHABLE")
                        if (run / "stop").exists() and "force_stopped" not in evidence["milestones"]:
                            phone.command("shell", "am", "force-stop", PACKAGE)
                            state = phone.command("shell", "dumpsys", "package", PACKAGE, timeout=60)
                            require(re.search(r"(?<![A-Za-z])stopped=true(?![A-Za-z])", state) is not None, "JOURNEY_FORCE_STOP_UNCONFIRMED")
                            require(phone.command("shell", f"pidof {PACKAGE} || true").strip() == "", "JOURNEY_PROCESS_ALIVE")
                            evidence["milestones"]["force_stopped"] = round(time.monotonic() - started, 1)
                            evidence["force_stop_confirmed"] = True
                            print(json.dumps({"phase": "force_stopped"}), flush=True)
                        if resume.exists() and "force_stopped" in evidence["milestones"]:
                            evidence["no_effect_while_unreachable"] = True
                            harness.fault("normal"); offline = False
                            evidence["milestones"]["server_restored"] = round(time.monotonic() - started, 1)
                            print(json.dumps({"phase": "server_normal"}), flush=True)
                        time.sleep(2)
                        continue
                if scenario == "offline":
                    # Server-side unreachable fault after enrollment, held until the orchestrator writes `resume`
                    # (the user reports the report is queued). No server effect may occur while unreachable.
                    if offline is None and "enrolled" in evidence["milestones"]:
                        harness.fault("unavailable"); offline = True
                        evidence["milestones"]["server_unreachable"] = round(time.monotonic() - started, 1)
                        print(json.dumps({"phase": "server_unreachable"}), flush=True)
                    if offline is True:
                        require(now["revisions"] == 0 and now["receipts"] == 0, "JOURNEY_EFFECT_WHILE_UNREACHABLE")
                        if resume.exists():
                            evidence["no_effect_while_unreachable"] = True
                            harness.fault("normal"); offline = False
                            evidence["milestones"]["server_restored"] = round(time.monotonic() - started, 1)
                            print(json.dumps({"phase": "server_normal"}), flush=True)
                        time.sleep(2)
                        continue
                if "processed" in evidence["milestones"]:
                    evidence["bindings"] = bindings()
                    require(all(evidence["bindings"].values()), "JOURNEY_BINDING_MISMATCH")
                    if scenario == "review":
                        require(now["decisions"] == 0 and now["publications"] == 0, "JOURNEY_UNEXPECTED_PUBLICATION")
                        print(json.dumps({"phase": "browser_review_started"}), flush=True)
                        browser_review(evidence)
                        evidence["milestones"]["browser_approved"] = round(time.monotonic() - started, 1)
                        now = counts()
                        require(now["decisions"] == 1 and now["publications"] == 1 and now["revisions"] == 1, "JOURNEY_PUBLICATION_COUNTS")
                    time.sleep(5)
                    final = counts()
                    require(final == now, "JOURNEY_LATE_EFFECT")
                    evidence["server_counts"] = final
                    evidence["ok"] = True
                    break
                time.sleep(2)
            require(evidence["ok"], "JOURNEY_DEADLINE")
            evidence["stage"] = "complete"
    except BaseException as error:
        evidence["ok"] = False
        evidence["code"] = str(error) if isinstance(error, (JourneyError, integration.IntegrationError)) else "JOURNEY_FAILED"
        raise
    finally:
        if created_reverse:
            try:
                current_reverse = parse_reverse(phone.command("reverse", "--list"))
                if ENDPOINT not in current_reverse:
                    evidence["reverse_removed"] = True
                elif current_reverse[ENDPOINT] != ENDPOINT:
                    evidence["reverse_removed"] = False
                else:
                    # ADB has no compare-and-remove primitive. This fresh check
                    # still requires the journey's exclusive device reservation.
                    phone.command("reverse", "--remove", ENDPOINT)
                    evidence["reverse_removed"] = ENDPOINT not in parse_reverse(phone.command("reverse", "--list"))
            except BaseException:
                evidence["reverse_removed"] = False
        cleanup_failed = created_reverse and not evidence["reverse_removed"]
        if cleanup_failed:
            if "code" in evidence:
                evidence["primary_code"] = evidence["code"]
            evidence.update(ok=False, code="JOURNEY_REVERSE_CLEANUP_UNCONFIRMED")
        evidence["elapsed_seconds"] = round(time.monotonic() - started, 1)
        (run / "result.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"result": str((run / "result.json").relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
        if cleanup_failed:
            raise JourneyError("JOURNEY_REVERSE_CLEANUP_UNCONFIRMED") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--scenario", choices=("happy", "offline", "dropped_ack", "force_stop", "revoke", "review"), default="happy")
    args = parser.parse_args()
    if Path(sys.executable).resolve() != Path(integration.local.python_path()).resolve():
        return subprocess.run([integration.local.python_path(), "-B", str(Path(__file__).resolve()), *sys.argv[1:]],
                              cwd=ROOT, env=integration.local.managed_environment(), check=False).returncode
    try:
        execute(args.serial, args.scenario)
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "code": str(error) if isinstance(error, (JourneyError, integration.IntegrationError)) else "JOURNEY_FAILED"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
