"""Private web DTO reasons share the original's current authorization boundary."""
import copy
import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from apps.operations.worker import process_one
from apps.reports.models import ReportRevision
from apps.reports.selectors import summary
from apps.reports.services import accept_operation
from .test_m3_review import ReviewFixture, SETTINGS


@override_settings(**SETTINGS)
class M3CorrectionReasonTests(ReviewFixture, TestCase):
    def test_reason_is_only_in_authorized_corrected_web_dtos(self):
        revision, body = self.submit_source()
        original_url = f"/api/v1/reports/{revision.report_id}/revisions/1/"
        self.assertNotIn("correction_reason", self.client.get(original_url).json())
        initial_candidates = self.client.get(f"/api/v1/revisions/{revision.id}/candidates/")
        self.assertNotIn("correction_reason", initial_candidates.json())
        self.batch(revision)
        corrected = copy.deepcopy(body)
        corrected.update(operation_id=str(uuid.uuid4()), expected_revision=1,
                         correction_reason="Clarified the fictional maintenance area after review.")
        receipt, _ = accept_operation(self.author, corrected, corrected)
        current = ReportRevision.objects.get(pk=receipt["revision_id"])
        url = f"/api/v1/reports/{revision.report_id}/revisions/2/"
        self.client.force_authenticate(user=self.author)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["correction_reason"], corrected["correction_reason"])
        self.assertNotIn("correction_reason", summary(current.report, current))
        self.assertTrue(process_one())
        self.client.force_authenticate(user=self.reviewer)
        response = self.client.get(f"/api/v1/revisions/{current.id}/candidates/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["correction_reason"], corrected["correction_reason"])
        self.assertNotIn("correction_reason", self.client.get(original_url).json())
        for username in ("reviewer", "recipient-full", "administrator"):
            self.client.force_authenticate(user=get_user_model().objects.get(username=username))
            self.assertEqual(self.client.get(url).status_code, 404)
            self.assertIn(self.client.get(f"/api/v1/revisions/{current.id}/candidates/").status_code, (403, 404))
