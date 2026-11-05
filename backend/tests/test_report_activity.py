"""Real PostgreSQL checks for content-free, authorized activity summaries."""
import uuid
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.reports.activity import ACTIVITY_STATUSES
from apps.reports.crypto import source_payload
from apps.reports.models import Report, ReportRevision
from apps.scopes.models import Organization, Unit, UnitMembership

from . import test_workflow as workflow


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class ReportActivityTests(TestCase):
    setUp = workflow.WorkflowTests.setUp
    sign_in = workflow.WorkflowTests.sign_in
    submit = workflow.WorkflowTests.submit
    candidate = workflow.WorkflowTests.candidate
    decision = workflow.WorkflowTests.decision

    def accepted(self):
        body, response = self.submit()
        self.assertEqual(response.status_code, 201, response.content)
        return body

    def activity(self, url="/api/v1/reports/?status=ALL"):
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, response.content)
        result = response.json()
        activity = result["activity"]
        self.assertEqual(set(activity), {"total", "by_status", "unclassified"})
        self.assertEqual(set(activity["by_status"]), set(ACTIVITY_STATUSES))
        self.assertEqual(activity["total"], sum(activity["by_status"].values()) + activity["unclassified"])
        return result

    def test_counts_ignore_page_and_status_but_only_requested_page_is_decrypted(self):
        # Every state is reached through the same workflow the list describes.
        for action in ["APPROVE", "RETURN", "REJECT"]:
            _, _, variant, review = self.candidate()
            _, decided = self.decision(variant, review, action, "Synthetic review reason")
            self.assertEqual(decided.status_code, 200, decided.content)
        self.candidate()  # AWAITING_REVIEW
        self.sign_in("submitter")
        self.accepted()  # PENDING
        for state in ["PROCESSING", "FAILED"]:
            body = self.accepted()
            ReportRevision.objects.filter(report_id=body["report_id"]).update(processing_state=state)
        with patch("apps.reports.selectors.source_payload", wraps=source_payload) as decrypt:
            page = self.activity("/api/v1/reports/?status=ALL&page=2&page_size=2")
        self.assertEqual(decrypt.call_count, 2)
        self.assertEqual((page["count"], len(page["results"])), (7, 2))
        expected = {"total": 7, "by_status": dict.fromkeys(ACTIVITY_STATUSES, 1), "unclassified": 0}
        self.assertEqual(page["activity"], expected)
        for status in ACTIVITY_STATUSES:
            with self.subTest(status=status):
                result = self.activity(f"/api/v1/reports/?status={status}&page_size=1")
                self.assertEqual(result["count"], 1)
                self.assertEqual(result["activity"], expected)
                self.assertEqual(result["results"][0]["status"], status)
        with patch("apps.reports.selectors.source_payload", wraps=source_payload) as decrypt:
            empty_page = self.activity("/api/v1/reports/?page=99&page_size=2")
        self.assertEqual(decrypt.call_count, 0)
        self.assertEqual(empty_page["activity"], expected)

    def test_activity_uses_utc_creation_date_boundaries(self):
        self.sign_in("submitter")
        day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=2)
        stamps = [day - timedelta(microseconds=1), day,
                  day + timedelta(days=1) - timedelta(microseconds=1), day + timedelta(days=1)]
        for stamp in stamps:
            body = workflow.operation()
            body["payload"]["observed_at"] = (day - timedelta(days=1)).isoformat()
            with patch("django.utils.timezone.now", return_value=stamp):
                _, response = self.submit(body)
            self.assertEqual(response.status_code, 201, response.content)
        result = self.activity(f"/api/v1/reports/?status=APPROVED&date_from={day.date()}&date_to={day.date()}")
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["activity"]["total"], 2)
        self.assertEqual(result["activity"]["by_status"]["PENDING"], 2)

    def test_unknown_processing_labels_are_only_unclassified(self):
        self.sign_in("submitter")
        body = self.accepted()
        ReportRevision.objects.filter(report_id=body["report_id"]).update(processing_state="PRIVATE_UNKNOWN_CANARY")
        result = self.activity("/api/v1/reports/?status=PENDING")
        self.assertEqual(result["results"], [])
        self.assertEqual(result["activity"], {"total": 1, "by_status": dict.fromkeys(ACTIVITY_STATUSES, 0), "unclassified": 1})
        self.assertNotIn("PRIVATE_", str(result))

    def test_submitter_counts_exclude_other_author_unit_and_organization(self):
        self.sign_in("submitter")
        self.accepted()
        other = get_user_model().objects.create_user(username="activity-other", organization=self.org, role="submitter")
        other_unit = Unit.objects.create(organization=self.org, code="ACTIVITY-OTHER", name="Other synthetic unit")
        foreign = Organization.objects.create(code="ACTIVITY-FOREIGN", name="Foreign synthetic organization")
        foreign_unit = Unit.objects.create(organization=foreign, code="ACTIVITY-FOREIGN", name="Foreign synthetic unit")
        foreign_user = get_user_model().objects.create_user(username="activity-foreign", organization=foreign, role="submitter")
        # Out-of-scope sentinels deliberately have no revision. Any accidental
        # inclusion changes counts or fails serialization instead of hiding it.
        for org, unit, author in [(self.org, self.unit, other), (self.org, other_unit, self.submitter),
                                  (foreign, foreign_unit, foreign_user)]:
            Report.objects.create(id=uuid.uuid4(), organization=org, unit=unit, author=author)
        self.assertEqual(self.activity()["activity"]["total"], 1)
        UnitMembership.objects.filter(user=self.submitter).update(active=False)
        result = self.activity()
        self.assertEqual((result["count"], result["activity"]["total"]), (0, 0))

    def test_reviewer_counts_all_statuses_but_excludes_self_and_unassigned_units(self):
        self.sign_in("submitter")
        self.accepted()
        other_unit = Unit.objects.create(organization=self.org, code="ACTIVITY-OTHER", name="Other synthetic unit")
        Report.objects.create(id=uuid.uuid4(), organization=self.org, unit=self.unit, author=self.reviewer)
        Report.objects.create(id=uuid.uuid4(), organization=self.org, unit=other_unit, author=self.submitter)
        foreign = Organization.objects.create(code="ACTIVITY-FOREIGN", name="Foreign synthetic organization")
        foreign_unit = Unit.objects.create(organization=foreign, code="ACTIVITY-FOREIGN", name="Foreign synthetic unit")
        foreign_user = get_user_model().objects.create_user(username="activity-foreign", organization=foreign, role="submitter")
        Report.objects.create(id=uuid.uuid4(), organization=foreign, unit=foreign_unit, author=foreign_user)
        self.sign_in("reviewer")
        result = self.activity("/api/v1/review/queue/")
        self.assertEqual(result["count"], 0)  # default AWAITING_REVIEW
        self.assertEqual(result["activity"]["by_status"]["PENDING"], 1)
        UnitMembership.objects.filter(user=self.reviewer).update(active=False)
        result = self.activity("/api/v1/review/queue/?status=ALL")
        self.assertEqual((result["count"], result["activity"]["total"]), (0, 0))

    def test_other_roles_and_anonymous_requests_receive_no_activity(self):
        for role in ["recipient", "administrator"]:
            self.sign_in(role)
            for url in ["/api/v1/reports/", "/api/v1/review/queue/"]:
                with self.subTest(role=role, url=url):
                    response = self.client.get(url)
                    self.assertEqual(response.status_code, 403)
                    self.assertNotIn("activity", response.json())
        self.client.logout()
        for url in ["/api/v1/reports/", "/api/v1/review/queue/"]:
            response = self.client.get(url)
            self.assertIn(response.status_code, [401, 403])
            self.assertNotIn("activity", response.json())

    def test_activity_rechecks_live_unit_and_account_state(self):
        self.sign_in("submitter")
        self.accepted()
        self.assertEqual(self.activity()["activity"]["total"], 1)
        Unit.objects.filter(pk=self.unit.pk).update(active=False)
        self.assertEqual(self.activity()["activity"]["total"], 0)
        get_user_model().objects.filter(pk=self.submitter.pk).update(is_active=False)
        denied = self.client.get("/api/v1/reports/")
        self.assertIn(denied.status_code, [401, 403])
        self.assertNotIn("activity", denied.json())

    def test_empty_scope_reports_fixed_zero_statuses(self):
        self.sign_in("submitter")
        result = self.activity()
        self.assertEqual(result["activity"], {"total": 0, "by_status": dict.fromkeys(ACTIVITY_STATUSES, 0), "unclassified": 0})

    def test_audit_failure_releases_no_activity_response(self):
        self.sign_in("submitter")
        self.accepted()
        with patch("apps.operations.views.audit.record", side_effect=RuntimeError("Synthetic audit failure")):
            response = self.client.get("/api/v1/reports/")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b'"activity"', response.content)
