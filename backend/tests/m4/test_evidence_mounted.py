"""Main URL/session/CSRF quarantine integration; no real photos or downloads."""
import json
import uuid

from cryptography.fernet import Fernet
from django.core.management import call_command
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from apps.operations.models import PrivateEvidence
from tests import test_workflow as workflow


@override_settings(ROOT_URLCONF="config.urls", KAPIT_SOURCE_KEY=Fernet.generate_key(),
                   PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class MountedEvidenceTests(TestCase):
    sign_in = workflow.WorkflowTests.sign_in

    def setUp(self):
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.raise_request_exception = False
        self.sign_in("submitter2")
        body = workflow.operation()
        response = self.client.post("/api/v1/sync/operations/", body, format="json",
            HTTP_X_CSRFTOKEN=self.token, HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(response.status_code, 201, response.content)
        self.revision_id = response.json()["revision_id"]
        self.route = f"/api/v1/revisions/{self.revision_id}/evidence/"
        self.image = b"\xff\xd8PRIVATE_MOUNTED_EVIDENCE_CANARY\xff\xd9"

    def upload(self, operation_id, *, csrf=True, image=None):
        headers = {"HTTP_IDEMPOTENCY_KEY": operation_id,
                   "HTTP_X_EVIDENCE_FILENAME": "PRIVATE_FILENAME_CANARY.jpg"}
        if csrf:
            headers["HTTP_X_CSRFTOKEN"] = self.token
        return self.client.generic("POST", self.route, data=image or self.image,
                                   content_type="image/jpeg", **headers)

    def assert_private(self, response):
        value = json.dumps(response.json())
        for canary in ("PRIVATE_MOUNTED_EVIDENCE_CANARY", "PRIVATE_FILENAME_CANARY", "payload_ciphertext", "filename_ciphertext"):
            self.assertNotIn(canary, value)
        self.assertIn("no-store", response["Cache-Control"])

    def test_mounted_upload_requires_csrf_and_retries_exactly_while_download_stays_closed(self):
        operation = str(uuid.uuid4())
        refused = self.upload(operation, csrf=False)
        self.assertEqual(refused.status_code, 403)
        self.assert_private(refused)
        self.assertEqual(PrivateEvidence.objects.count(), 0)
        first = self.upload(operation)
        self.assertEqual(first.status_code, 201, first.content)
        self.assert_private(first)
        self.assertEqual(first.json()["state"], "QUARANTINED")
        self.assertEqual(first.json()["validation_code"], "DECODER_REQUIRED")
        retry = self.upload(operation)
        self.assertEqual(retry.status_code, 200, retry.content)
        self.assertEqual(retry.json(), first.json())
        conflict = self.upload(operation, image=b"\xff\xd8OTHER_PRIVATE_CANARY\xff\xd9")
        self.assertEqual(conflict.status_code, 409, conflict.content)
        self.assert_private(conflict)
        self.assertEqual(PrivateEvidence.objects.count(), 1)
        evidence = first.json()["id"]
        for account, expected in (("submitter2", 200), ("reviewer2", 200), ("reviewer3", 404),
                                  ("administrator", 404), ("recipient-full", 404)):
            self.sign_in(account)
            response = self.client.get(f"/api/v1/evidence/{evidence}/")
            self.assertEqual(response.status_code, expected, response.content)
            self.assert_private(response)
            closed = self.client.get(f"/api/v1/evidence/{evidence}/download/")
            missing = self.client.get(f"/api/v1/evidence/{uuid.uuid4()}/download/")
            self.assertEqual(closed.status_code, 404)
            self.assertEqual(closed.json(), missing.json())
            self.assert_private(closed)

    def test_other_unit_reviewer_recipient_and_account_admin_cannot_upload(self):
        for account in ("reviewer2", "submitter3", "recipient-full", "administrator"):
            self.sign_in(account)
            response = self.upload(str(uuid.uuid4()))
            self.assertEqual(response.status_code, 404, response.content)
            self.assert_private(response)
        self.assertFalse(PrivateEvidence.objects.exists())
