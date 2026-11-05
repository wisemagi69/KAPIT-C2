"""Real PostgreSQL checks for the administrator-only, content-free operations health panel."""
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.operations import health
from apps.operations.models import ProcessingJob
from apps.scopes.models import Organization

from . import test_workflow as workflow


TOP_KEYS = {"schema_version", "scope", "generated_utc", "jobs", "backup"}
JOB_KEYS = {"by_status", "unknown_status", "expired_leases", "missing_leases",
            "oldest_pending_available_age_seconds", "failures_by_code", "unclassified_failures"}
BACKUP_KEYS = {"status", "last_verified_utc", "age_seconds", "interval_hours", "rpo_hours", "basis"}
NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=dt_timezone.utc)


def write_backup(directory, created, *, verified=True, size=64, dump_size=None, file=None, epoch=None):
    stamp = created.strftime("%Y%m%dT%H%M%S%fZ")
    name = f"kapit_m1-{stamp}.dump"
    if dump_size is not False:
        (directory / name).write_bytes(b"x" * (size if dump_size is None else dump_size))
    record = {"file": file or name, "sha256": "0" * 64, "bytes": size, "created_utc": created.isoformat(),
              "created_epoch": created.timestamp() if epoch is None else epoch, "restore_list_entries": 3, "verified": verified}
    (directory / f"kapit_m1-{stamp}.json").write_text(json.dumps(record), encoding="utf-8")
    return name


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class OperationsHealthTests(TestCase):
    sign_in = workflow.WorkflowTests.sign_in
    submit = workflow.WorkflowTests.submit

    def setUp(self):
        workflow.WorkflowTests.setUp(self)
        backups = tempfile.TemporaryDirectory()
        self.addCleanup(backups.cleanup)
        self.backups = Path(backups.name)
        patcher = patch.object(health, "BACKUP_DIR", self.backups)
        patcher.start()
        self.addCleanup(patcher.stop)

    def health(self):
        response = self.client.get("/api/v1/administration/health/")
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        self.assertEqual(set(result), TOP_KEYS)
        self.assertEqual(set(result["jobs"]), JOB_KEYS)
        self.assertEqual(set(result["backup"]), BACKUP_KEYS)
        return response, result

    def accepted(self, count):
        self.sign_in("submitter")
        bodies = []
        for _ in range(count):
            body, response = self.submit()
            self.assertEqual(response.status_code, 201, response.content)
            bodies.append(body)
        return bodies

    def test_administrator_sees_exact_organization_counts_without_identifiers_or_labels(self):
        bodies = self.accepted(5)
        jobs = [ProcessingJob.objects.get(revision__report_id=body["report_id"]) for body in bodies]
        now = timezone.now()
        ProcessingJob.objects.filter(pk=jobs[0].pk).update(available_at=now - timedelta(seconds=300))
        ProcessingJob.objects.filter(pk=jobs[2].pk).update(status="PROCESSING", lease_until=now - timedelta(seconds=1))
        ProcessingJob.objects.filter(pk=jobs[3].pk).update(status="FAILED", error_code="ATTEMPTS_EXHAUSTED")
        ProcessingJob.objects.filter(pk=jobs[4].pk).update(status="FAILED", error_code="PRIVATE_CODE_CANARY")
        write_backup(self.backups, now - timedelta(hours=2))
        self.sign_in("administrator")
        with patch("apps.accounts.administration.timezone.now", return_value=now):
            response, result = self.health()
        self.assertEqual((result["schema_version"], result["scope"]), (1, "ORGANIZATION"))
        self.assertEqual(result["jobs"], {
            "by_status": {"PENDING": 2, "PROCESSING": 1, "DONE": 0, "FAILED": 2}, "unknown_status": 0,
            "expired_leases": 1, "missing_leases": 0, "oldest_pending_available_age_seconds": 300,
            "failures_by_code": {"RULE_PROCESSING_FAILED": 0, "ATTEMPTS_EXHAUSTED": 1, "STALE_CONTEXT": 0},
            "unclassified_failures": 1})
        self.assertEqual((result["backup"]["status"], result["backup"]["age_seconds"]), ("CURRENT", 7200))
        text = response.content.decode()
        for body, job in zip(bodies, jobs):
            for value in (body["report_id"], body["operation_id"], str(job.id), str(job.revision_id)):
                self.assertNotIn(str(value), text)
        for value in ("PRIVATE_CODE_CANARY", "kapit_m1-", "0" * 64, str(self.org.id), "SIM-ORG-01"):
            self.assertNotIn(value, text)

    def test_another_organization_administrator_sees_none_of_these_jobs(self):
        self.accepted(2)
        foreign = Organization.objects.create(code="HEALTH-FOREIGN", name="Foreign synthetic organization")
        get_user_model().objects.create_user(username="health-foreign", password="DemoMaintenance!2026",
                                             organization=foreign, display_name="Foreign admin", role="administrator")
        self.sign_in("administrator")
        self.assertEqual(self.health()[1]["jobs"]["by_status"]["PENDING"], 2)
        self.sign_in("health-foreign")
        _, result = self.health()
        self.assertEqual(result["jobs"]["by_status"], dict.fromkeys(health.STATUSES, 0))
        self.assertIsNone(result["jobs"]["oldest_pending_available_age_seconds"])

    def test_only_live_administrators_without_filters_may_read(self):
        self.client.post("/api/v1/auth/logout/", {}, format="json")
        self.assertIn(self.client.get("/api/v1/administration/health/").status_code, {401, 403})
        for role in ("submitter", "reviewer", "recipient"):
            with self.subTest(role=role):
                self.sign_in(role)
                self.assertEqual(self.client.get("/api/v1/administration/health/").status_code, 403)
        self.sign_in("administrator")
        self.assertEqual(self.client.get("/api/v1/administration/health/?scope=ALL").status_code, 400)
        self.assertEqual(self.client.post("/api/v1/administration/health/", {}, format="json", HTTP_X_CSRFTOKEN=self.token).status_code, 405)
        self.assertFalse(AuditEvent.objects.filter(action="OPERATIONS_HEALTH_READ").exists())
        get_user_model().objects.filter(username="administrator").update(role="reviewer")
        self.assertIn(self.client.get("/api/v1/administration/health/").status_code, {401, 403})

    def test_each_read_is_audited_without_target_or_metadata(self):
        self.sign_in("administrator")
        self.health()
        event = AuditEvent.objects.get(action="OPERATIONS_HEALTH_READ")
        self.assertEqual((event.organization_id, event.actor.username, event.outcome, event.target_id, event.safe_metadata),
                         (self.org.id, "administrator", "ALLOWED", None, {}))


class BackupStatusTests(SimpleTestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.dir = Path(folder.name)

    def status(self, directory=None):
        with patch.dict(os.environ, {"KAPIT_RUNTIME_CONTEXT": "native"}):
            return health.backup_status(NOW, self.dir if directory is None else directory)

    def test_missing_or_empty_folder_is_none(self):
        self.assertEqual(self.status(self.dir / "absent")["status"], "NONE")
        self.assertEqual(self.status()["status"], "NONE")

    def test_age_bands_follow_twenty_hour_interval_and_twenty_four_hour_rpo(self):
        for hours, expected in [(1, "CURRENT"), (19.9, "CURRENT"), (20, "DUE"), (23.9, "DUE"), (24, "OVERDUE"), (30, "OVERDUE")]:
            with self.subTest(hours=hours):
                for path in self.dir.iterdir():
                    path.unlink()
                write_backup(self.dir, NOW - timedelta(hours=hours))
                result = self.status()
                self.assertEqual((result["status"], result["age_seconds"]), (expected, int(hours * 3600)))
                self.assertEqual((result["interval_hours"], result["rpo_hours"], result["basis"]),
                                 (20, 24, "RECORDED_VERIFIED_AT_CREATION"))

    def test_newest_valid_record_wins_and_unverifiable_records_are_ignored(self):
        write_backup(self.dir, NOW - timedelta(hours=30))
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=1), verified=False)
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=2), dump_size=False)
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=3), dump_size=63)
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=4), file="kapit_m1-20200101T000000000000Z.dump")
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=5), file="../outside.dump")
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=6), epoch=(NOW + timedelta(hours=1)).timestamp())
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=7), epoch=True)
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=8), epoch=-1)
        write_backup(self.dir, NOW - timedelta(hours=1, minutes=9), epoch=-10 ** 400)
        stamp = (NOW - timedelta(hours=1, minutes=10)).strftime("%Y%m%dT%H%M%S%fZ")
        (self.dir / f"kapit_m1-{stamp}.dump").write_bytes(b"x" * 64)
        (self.dir / f"kapit_m1-{stamp}.json").write_text(json.dumps({"file": f"kapit_m1-{stamp}.dump", "bytes": 64, "verified": True}).replace(
            '"verified"', '"created_epoch": -1e400, "verified"'), encoding="utf-8")
        (self.dir / "kapit_m1-20261030T105000000000Z.json").write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
        (self.dir / "kapit_m1-20261030T110000000000Z.json").write_text("{not json", encoding="utf-8")
        (self.dir / "kapit_m1-latest.json").write_text(json.dumps({"verified": True}), encoding="utf-8")
        result = self.status()
        self.assertEqual((result["status"], result["age_seconds"]), ("OVERDUE", 30 * 3600))
        write_backup(self.dir, NOW - timedelta(hours=3))
        result = self.status()
        self.assertEqual(result, {"status": "CURRENT", "last_verified_utc": "2026-10-30T09:00:00Z", "age_seconds": 3 * 3600,
                                  "interval_hours": 20, "rpo_hours": 24, "basis": "RECORDED_VERIFIED_AT_CREATION"})

    def test_non_native_context_is_unavailable_not_none(self):
        write_backup(self.dir, NOW - timedelta(hours=1))
        with patch.dict(os.environ, {"KAPIT_RUNTIME_CONTEXT": "compose-m1"}):
            result = health.backup_status(NOW, self.dir)
        self.assertEqual((result["status"], result["last_verified_utc"], result["age_seconds"]), ("UNAVAILABLE", None, None))
