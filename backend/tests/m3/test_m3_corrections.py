"""Website approved corrections remain distinct from frozen mobile return-only input."""
import copy
import uuid
from unittest.mock import patch

from django.db import transaction
from django.test import SimpleTestCase, TestCase, override_settings

from apps.operations.errors import ApiError
from apps.operations.mobile_serializers import MobileOperationSerializer
from apps.operations.serializers import WebOperationSerializer
from apps.publications.models import Publication, PublicationRemoval
from apps.reports.crypto import decrypt
from apps.reports.models import ReportRevision
from apps.reports.services import _accept_locked, accept_operation, web_can_correct
from apps.scopes.access import lock_identity
from tests.test_workflow import operation
from .test_m3_review import ReviewFixture, SETTINGS


class CorrectionSerializerTests(SimpleTestCase):
    def test_web_reason_required_only_for_corrections_mobile_rejects_field(self):
        body = operation()
        self.assertTrue(WebOperationSerializer(data=body).is_valid())
        body["expected_revision"] = 1
        self.assertFalse(WebOperationSerializer(data=body).is_valid())
        body["correction_reason"] = "PRIVATE_CORRECTION_REASON_CANARY"
        self.assertTrue(WebOperationSerializer(data=body).is_valid())
        self.assertFalse(MobileOperationSerializer(data=body).is_valid())


@override_settings(**SETTINGS)
class M3CorrectionTests(ReviewFixture, TestCase):
    def correction(self, body):
        result = copy.deepcopy(body)
        result.update(operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason="PRIVATE_CORRECTION_REASON_CANARY")
        return result

    def test_approved_web_correction_encrypts_reason_and_removes_only_its_report(self):
        revision, body = self.submit_source()
        self.batch(revision)
        another, _ = self.submit_source()
        self.batch(another)
        other_ids = set(Publication.objects.filter(report=another.report).values_list("id", flat=True))
        original = bytes(revision.payload_ciphertext)
        correction = self.correction(body)
        self.assertTrue(web_can_correct(self.author, revision.report, revision))
        response, created = accept_operation(self.author, correction, correction)
        self.assertTrue(created)
        new = ReportRevision.objects.get(pk=response["revision_id"])
        self.assertEqual(new.revision_no, 2)
        self.assertEqual(decrypt(new.correction_reason_ciphertext), correction["correction_reason"])
        self.assertEqual(bytes(ReportRevision.objects.get(pk=revision.id).payload_ciphertext), original)
        self.assertTrue(all(row.revoked_at is not None for row in Publication.objects.filter(report=revision.report)))
        self.assertEqual(set(PublicationRemoval.objects.filter(publication__report=revision.report).values_list("cause", flat=True)), {"CORRECTION"})
        self.assertEqual(set(Publication.objects.filter(report=another.report, revoked_at__isnull=True).values_list("id", flat=True)), other_ids)
        self.assertEqual(accept_operation(self.author, correction, correction), (response, False))
        conflicting = copy.deepcopy(correction)
        conflicting["correction_reason"] = "Different private reason"
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, conflicting, conflicting)
        self.assertEqual(caught.exception.safe_body["code"], "IDEMPOTENCY_CONFLICT")
        competing = self.correction(body)
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, competing, competing)
        self.assertEqual(caught.exception.safe_body["code"], "REVISION_CONFLICT")

    def test_never_reviewed_and_mobile_approved_corrections_remain_refused(self):
        revision, body = self.submit_source()
        correction = self.correction(body)
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, correction, correction)
        self.assertEqual(caught.exception.safe_body["code"], "CORRECTION_UNAVAILABLE")
        self.batch(revision)
        with transaction.atomic():
            actor, org = lock_identity(self.author)
            # Non-NULL origin selects the frozen mobile correction policy; no
            # device DB write is reached because an approved source is refused.
            with self.assertRaises(ApiError) as caught:
                _accept_locked(actor, org, uuid.uuid4(), correction, correction)
            self.assertEqual(caught.exception.safe_body["code"], "CORRECTION_UNAVAILABLE")

    def test_correction_audit_failure_restores_old_publications_and_pointer(self):
        revision, body = self.submit_source()
        self.batch(revision)
        ids = set(Publication.objects.filter(report=revision.report).values_list("id", flat=True))
        correction = self.correction(body)
        with patch("apps.reports.services.audit.record", side_effect=RuntimeError("PRIVATE_AUDIT_CANARY")):
            with self.assertRaises(RuntimeError):
                accept_operation(self.author, correction, correction)
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 1)
        revision.report.refresh_from_db()
        self.assertEqual(revision.report.current_revision_no, 1)
        self.assertFalse(PublicationRemoval.objects.filter(publication__report=revision.report).exists())
        self.assertEqual(set(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).values_list("id", flat=True)), ids)

    def test_withdrawn_approved_revision_can_correct_without_reviving_old_outputs(self):
        from apps.publications.services import withdraw_report
        revision, body = self.submit_source()
        self.batch(revision)
        withdrawal = self.withdrawal_body(revision)
        withdraw_report(self.reviewer, revision.report_id, withdrawal, withdrawal)
        previous_removals = list(PublicationRemoval.objects.order_by("id").values())
        correction = self.correction(body)
        receipt, _ = accept_operation(self.author, correction, correction)
        self.assertEqual(receipt["revision_no"], 2)
        self.assertEqual(list(PublicationRemoval.objects.order_by("id").values()), previous_removals)
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())

    def regenerated_approved_source(self):
        from apps.operations.worker import process_one
        from apps.reports.regeneration import invalidate_scope, latest_job
        from apps.scopes.models import Organization
        revision, original = self.submit_source()
        self.batch(revision)
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.id)
            invalidate_scope(org, [revision.report.unit_id])
        self.assertTrue(web_can_correct(self.author, revision.report, revision))
        for _ in range(20):
            if latest_job(revision).status == "DONE":
                break
            process_one()
        self.assertTrue(web_can_correct(self.author, revision.report, revision))
        return revision, original

    def test_new_terminal_rejection_overrides_older_approval_for_flag_and_acceptance(self):
        revision, original = self.regenerated_approved_source()
        self.batch(revision, self.batch_body(revision, action="REJECT"))
        self.assertFalse(web_can_correct(self.author, revision.report, revision))
        self.client.force_authenticate(user=self.author)
        response = self.client.get(f"/api/v1/reports/{revision.report_id}/revisions/1/")
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.json()["can_correct"], False)
        correction = self.correction(original)
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, correction, correction)
        self.assertEqual(caught.exception.safe_body["code"], "CORRECTION_UNAVAILABLE")
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 1)

    def test_failed_replacement_does_not_inherit_old_approval_permission(self):
        from apps.operations.models import ProcessingJob
        from apps.reports.regeneration import latest_job
        revision, original = self.regenerated_approved_source()
        ProcessingJob.objects.filter(pk=latest_job(revision).id).update(status="FAILED", error_code="RULE_PROCESSING_FAILED")
        self.assertFalse(web_can_correct(self.author, revision.report, revision))
        correction = self.correction(original)
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, correction, correction)
        self.assertEqual(caught.exception.safe_body["code"], "CORRECTION_UNAVAILABLE")
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 1)

    def assert_uncommitted_correction_denied(self, revision, original):
        self.assertFalse(web_can_correct(self.author, revision.report, revision))
        correction = self.correction(original)
        with self.assertRaises(ApiError) as caught:
            accept_operation(self.author, correction, correction)
        self.assertEqual(caught.exception.safe_body["code"], "CORRECTION_UNAVAILABLE")
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 1)

    def test_approved_state_without_committed_decision_does_not_allow_correction(self):
        revision, original = self.submit_source()
        revision.variants.update(state="APPROVED")
        self.assert_uncommitted_correction_denied(revision, original)

    def test_returned_set_without_committed_decisions_does_not_allow_correction(self):
        revision, original = self.submit_source()
        revision.variants.update(state="RETURNED")
        self.assert_uncommitted_correction_denied(revision, original)

    def test_historical_approved_state_without_decision_cannot_authorize_pending_replacement(self):
        from apps.reports.regeneration import invalidate_scope, latest_job
        from apps.scopes.models import Organization
        revision, original = self.submit_source()
        revision.variants.update(state="APPROVED")
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.id)
            invalidate_scope(org, [revision.report.unit_id])
        self.assertEqual(latest_job(revision).status, "PENDING")
        self.assert_uncommitted_correction_denied(revision, original)
