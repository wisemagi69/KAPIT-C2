"""Private capture policy + PostgreSQL/API tests. Direct script runs pure policy only.

Root alone executes Django tests in its owned disposable PostgreSQL reservation.
No synthetic image is claimed decoded/scanned or a real phone/GPS observation.
"""
import copy
import hashlib
from datetime import datetime, timedelta, timezone as utc
import json
from pathlib import Path
import sys
import unittest
import uuid
from unittest.mock import patch

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from apps.operations.evidence_capture import CaptureError, parse_capture_header, validate_capture


def capture_at(instant):
    return {"version": 1, "captured_at": instant.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "location": {"latitude_e7": 145000001, "longitude_e7": 1205000001, "accuracy_mm": 25000,
            "fix_at": (instant - timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "age_ms": 1000, "mock": False}}


class CapturePolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 22, 1, 2, 3, tzinfo=utc.utc)
        self.value = capture_at(self.now)

    def parse(self, value):
        return parse_capture_header(json.dumps(value, separators=(",", ":")), now=self.now)

    def test_absent_location_approximate_mock_and_old_offline_capture_are_preserved(self):
        self.assertIsNone(parse_capture_header(None, now=self.now))
        self.assertEqual(self.parse(self.value), self.value)
        value = capture_at(self.now - timedelta(days=400))
        value["location"].update(mock=True, accuracy_mm=100000000)
        self.assertEqual(self.parse(value), value)
        value["location"] = None
        self.assertEqual(self.parse(value), value)

    def test_returns_a_fresh_closed_object_not_mutable_input_alias(self):
        result = validate_capture(self.value, now=self.now)
        self.value["location"]["latitude_e7"] = 1
        self.assertEqual(result["location"]["latitude_e7"], 145000001)

    def test_numeric_types_ranges_and_boolean_fields_are_exact(self):
        for field, values in {
            "latitude_e7": [True, 1.0, -900000001, 900000001],
            "longitude_e7": [False, 1.0, -1800000001, 1800000001],
            "accuracy_mm": [True, 0, 100000001, "20"],
            "age_ms": [False, -1, 30001, 1.0], "mock": [0, 1, "false", None]}.items():
            for value in values:
                with self.subTest(field=field, value_type=type(value).__name__):
                    changed = copy.deepcopy(self.value)
                    changed["location"][field] = value
                    with self.assertRaises(CaptureError): self.parse(changed)
        for bad in (True, 1.0, 2):
            with self.assertRaises(CaptureError): self.parse(self.value | {"version": bad})

    def test_exact_keys_duplicate_nonfinite_and_header_size_are_refused(self):
        for raw in ("", "null", "[]", '{"version":1,"version":1}', '{"x":NaN}', '{"x":Infinity}',
                    " " * 1025, "\u00e9", "[" * 1024):
            with self.subTest(size=len(raw)), self.assertRaises(CaptureError):
                parse_capture_header(raw, now=self.now)
        for changed in (self.value | {"extra": 1}, {"version": 1},
                        self.value | {"location": self.value["location"] | {"source": "GPS"}}):
            with self.assertRaises(CaptureError): self.parse(changed)
        raw = json.dumps(self.value).replace('"mock": false', '"mock":false,"mock":true')
        with self.assertRaises(CaptureError): parse_capture_header(raw, now=self.now)

    def test_utc_only_fractional_precision_and_real_calendar_dates(self):
        for stamp in ("2026-10-22T01:02:03+00:00", "2026-10-22T01:02:03", "2026-10-22T01:02:03.1234Z",
                      "2026-02-30T01:02:03Z", "2026-10-22T01:02:60Z", "2026-10-22 01:02:03Z"):
            with self.subTest(stamp=stamp), self.assertRaises(CaptureError):
                self.parse(self.value | {"captured_at": stamp})
        for suffix in ("", ".1", ".12", ".123"):
            value = self.value | {"captured_at": "2026-10-22T01:02:03" + suffix + "Z", "location": None}
            self.assertEqual(self.parse(value), value)

    def test_future_clock_rounding_and_age_agreement(self):
        self.assertEqual(self.parse(capture_at(self.now + timedelta(minutes=5)))["version"], 1)
        with self.assertRaises(CaptureError): self.parse(capture_at(self.now + timedelta(minutes=5, milliseconds=1)))
        for seconds, age in ((31, 30000), (-1.001, 0), (10, 1), (0, 2000)):
            changed = copy.deepcopy(self.value)
            changed["location"]["fix_at"] = (self.now - timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            changed["location"]["age_ms"] = age
            with self.subTest(seconds=seconds, age=age), self.assertRaises(CaptureError): self.parse(changed)
        changed = copy.deepcopy(self.value)
        changed["location"].update(fix_at=(self.now + timedelta(seconds=1)).isoformat(timespec="milliseconds").replace("+00:00", "Z"), age_ms=0)
        self.assertEqual(self.parse(changed), changed)


# Explicit direct-script seam is policy-only: Django/ORM tests below are loaded
# by manage.py after settings/setup, never by this no-DB invocation.
if __name__ == "__main__":
    unittest.main()

from cryptography.hazmat.primitives.asymmetric import ec
from django.db import DatabaseError, connection
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from apps.accounts.mobile_services import revoke_device
from apps.accounts.models import DeviceEnrollment
from apps.audit.models import AuditEvent
from apps.operations import mobile_evidence as mobile
from apps.operations.evidence import accept_evidence
from apps.operations.evidence_processing import _original, strict_original
from apps.operations.errors import ApiError
from apps.operations.models import PrivateEvidence, ProcessingJob, SyncReceipt
from apps.reports.crypto import decrypt, encrypt
from apps.reports.canonical import digest
from apps.reports.models import ReportRevision
from apps.scopes.models import UnitMembership
from tests.mobile.helpers import MOBILE, MOBILE_SETTINGS, MobileFixtures
from tests.test_workflow import operation
from tests.m4.test_evidence_decoder import png


JPEG = b"\xff\xd8PRIVATE_CAPTURE_PHOTO_CANARY\xff\xd9"
REFERENCE_KEYS = {"id", "operation_id", "state", "validation_code", "created_at"}
STATUS_KEYS = {"evidence_id", "state", "validation_code", "can_download"}


@override_settings(**MOBILE_SETTINGS)
class PhotoGeotagAPITests(MobileFixtures, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.session = self.enroll()
        self.body = operation()
        response = self.client.post(MOBILE + "sync/operations/", self.body, format="json",
            HTTP_AUTHORIZATION="Bearer " + self.session["access_token"], HTTP_IDEMPOTENCY_KEY=self.body["operation_id"])
        self.assertEqual(response.status_code, 201)
        self.revision = ReportRevision.objects.get(pk=response.json()["revision_id"])
        self.capture = capture_at(timezone.now() - timedelta(seconds=1))

    def upload(self, *, session=None, revision=None, operation_id=None, data=JPEG, capture=True,
               filename="capture.jpg", media_type="image/jpeg"):
        headers = {"HTTP_AUTHORIZATION": "Bearer " + (session or self.session)["access_token"],
                   "HTTP_IDEMPOTENCY_KEY": str(operation_id or uuid.uuid4()), "HTTP_X_EVIDENCE_FILENAME": filename}
        if capture is True:
            headers["HTTP_X_EVIDENCE_CAPTURE"] = json.dumps(self.capture, separators=(",", ":"))
        elif capture is not None:
            headers["HTTP_X_EVIDENCE_CAPTURE"] = capture
        return self.client.generic("POST", MOBILE + f"revisions/{revision or self.revision.id}/evidence/",
            data, content_type=media_type, **headers)

    def read(self, evidence_id, suffix="capture", session=None):
        return self.client.get(MOBILE + f"evidence/{evidence_id}/{suffix}/",
                              HTTP_AUTHORIZATION="Bearer " + (session or self.session)["access_token"])

    def test_upload_capture_status_are_private_and_text_receipt_is_unchanged(self):
        before = (ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count())
        response = self.upload()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(set(response.json()), REFERENCE_KEYS)
        item = PrivateEvidence.objects.get()
        self.assertEqual(self.read(item.id).json(), {"capture": self.capture})
        self.assertIn("no-store", self.read(item.id)["Cache-Control"])
        status = self.read(item.id, "validation")
        self.assertEqual(status.status_code, 200)
        self.assertEqual(set(status.json()), STATUS_KEYS)
        self.assertEqual(status.json()["state"], "QUARANTINED")
        self.assertFalse(status.json()["can_download"])
        self.assertEqual((ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count()), before)
        self.assertEqual(strict_original(item), (JPEG, hashlib.sha256(JPEG).hexdigest(), self.capture))
        self.assertNotIn(JPEG, bytes(item.payload_ciphertext))
        self.assertNotIn("latitude_e7", response.content.decode())
        self.assertNotIn("latitude_e7", json.dumps(list(AuditEvent.objects.values_list("safe_metadata", flat=True))))
        self.assertEqual(self.client.get(MOBILE + f"evidence/{item.id}/download/",
            HTTP_AUTHORIZATION="Bearer " + self.session["access_token"]).status_code, 404)

    def test_retry_binds_capture_bytes_actor_revision_and_absence(self):
        op = uuid.uuid4()
        first = self.upload(operation_id=op)
        self.assertEqual(first.status_code, 201)
        replay = self.upload(operation_id=op)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), first.json())
        changed = copy.deepcopy(self.capture)
        changed["location"]["latitude_e7"] += 1
        for changes in ({"capture": json.dumps(changed)}, {"capture": None}, {"data": b"\xff\xd8different\xff\xd9"}):
            with self.subTest(changes=list(changes)):
                response = self.upload(operation_id=op, **changes)
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(PrivateEvidence.objects.count(), 1)

    def test_mobile_jpeg_fixed_name_bounds_and_malformed_metadata(self):
        for changes in ({"filename": "other.jpg"}, {"media_type": "image/png", "data": png()},
                        {"capture": "null"}, {"capture": " " * 1025},
                        {"capture": '{"version":1,"version":1}'}, {"capture": json.dumps(self.capture | {"extra": True})}):
            with self.subTest(changes=list(changes)):
                self.assertEqual(self.upload(**changes).status_code, 400)
        self.assertEqual(self.upload(data=b"x" * (5 * 1024 * 1024 + 1)).status_code, 413)
        self.assertEqual(PrivateEvidence.objects.count(), 0)
        self.assertEqual(ReportRevision.objects.count(), 1)

    def test_existing_web_png_without_capture_preserves_legacy_envelope_hash(self):
        web, csrf = self.web()
        image, op = png(), uuid.uuid4()
        response = web.generic("POST", f"/api/v1/revisions/{self.revision.id}/evidence/", image,
            content_type="image/png", HTTP_X_CSRFTOKEN=csrf, HTTP_IDEMPOTENCY_KEY=str(op), HTTP_X_EVIDENCE_FILENAME="legacy.png")
        self.assertEqual(response.status_code, 201)
        item = PrivateEvidence.objects.get()
        value = decrypt(item.payload_ciphertext)
        self.assertEqual(set(value), {"purpose", "id", "actor_id", "revision_id", "operation_id", "media_type", "filename", "bytes_base64"})
        self.assertEqual(value["purpose"], "private-evidence-v1")
        self.assertEqual(item.request_hash, digest({"purpose": "private-evidence-v1", "actor_id": str(self.owner.id),
            "revision_id": str(self.revision.id), "media_type": "image/png", "filename": "legacy.png",
            "bytes_sha256": hashlib.sha256(image).hexdigest()}))
        self.assertEqual(_original(item)[0], image)
        self.assertEqual(self.read(item.id).json(), {"capture": None})

    def test_web_capture_header_is_bound_and_reviewer_only_current_source_can_read(self):
        web, csrf = self.web()
        response = web.generic("POST", f"/api/v1/revisions/{self.revision.id}/evidence/", JPEG, content_type="image/jpeg",
            HTTP_X_CSRFTOKEN=csrf, HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()), HTTP_X_EVIDENCE_FILENAME="capture.jpg",
            HTTP_X_EVIDENCE_CAPTURE=json.dumps(self.capture))
        self.assertEqual(response.status_code, 201)
        item = PrivateEvidence.objects.get()
        reviewer, _ = self.web("reviewer")
        self.assertEqual(reviewer.get(f"/api/v1/evidence/{item.id}/capture/").json(), {"capture": self.capture})
        for username in ("recipient", "administrator"):
            client, _ = self.web(username)
            known = client.get(f"/api/v1/evidence/{item.id}/capture/")
            unknown = client.get(f"/api/v1/evidence/{uuid.uuid4()}/capture/")
            self.assertEqual((known.status_code, known.json()), (404, unknown.json()))

    def test_other_account_same_org_or_other_org_cannot_read_or_upload(self):
        evidence_id = self.upload().json()["id"]
        for same_org in (True, False):
            owner = self.another_owner(suffix="same" if same_org else "other", same_org=same_org)
            session = self.enroll(owner=owner, key=ec.generate_private_key(ec.SECP256R1()), installation=str(uuid.uuid4()))
            for suffix in ("capture", "validation"):
                known, unknown = self.read(evidence_id, suffix, session), self.read(uuid.uuid4(), suffix, session)
                self.assertEqual((known.status_code, known.json()), (404, unknown.json()))
            self.assertEqual(self.upload(session=session).status_code, 404)

    def test_revoked_device_denies_all_new_surfaces(self):
        evidence_id = self.upload().json()["id"]
        revoke_device(self.owner, self.session["context"]["enrollment_id"])
        self.assert_auth_denied(self.upload())
        self.assert_auth_denied(self.read(evidence_id))
        self.assert_auth_denied(self.read(evidence_id, "validation"))

    def test_revocation_after_early_upload_authorization_wins_before_commit(self):
        real = mobile.authorize_mobile_upload
        def early(claims, revision_id):
            real(claims, revision_id)
            revoke_device(self.owner, claims.enrollment_id)
        with patch.object(mobile, "authorize_mobile_upload", side_effect=early):
            self.assert_auth_denied(self.upload())
        self.assertEqual(PrivateEvidence.objects.count(), 0)

    def test_status_calls_tool_service_outside_atomic_and_revocation_wins_final_check(self):
        evidence_id = self.upload().json()["id"]
        real = mobile.validation_status
        def status(actor, identity):
            self.assertFalse(connection.in_atomic_block)
            result = real(actor, identity)
            revoke_device(self.owner, self.session["context"]["enrollment_id"])
            return result
        with patch.object(mobile, "validation_status", side_effect=status):
            self.assert_auth_denied(self.read(evidence_id, "validation"))

    def test_status_error_does_not_override_later_revoked_original_claims(self):
        evidence_id = self.upload().json()["id"]
        def status(actor, identity):
            self.assertFalse(connection.in_atomic_block)
            revoke_device(self.owner, self.session["context"]["enrollment_id"])
            raise RuntimeError("PRIVATE_STATUS_ERROR_CANARY")
        with patch.object(mobile, "validation_status", side_effect=status):
            response = self.read(evidence_id, "validation")
        self.assert_auth_denied(response)
        self.assertNotIn(b"PRIVATE_STATUS_ERROR_CANARY", response.content)

    def test_current_source_scope_loss_between_status_stages_prevents_disclosure(self):
        evidence_id = self.upload().json()["id"]
        real = mobile.validation_status
        def status(actor, identity):
            result = real(actor, identity)
            UnitMembership.objects.filter(user=self.owner, role="submitter").update(active=False)
            return result
        with patch.object(mobile, "validation_status", side_effect=status):
            response = self.read(evidence_id, "validation")
        self.assertIn(response.status_code, (401, 403, 404))
        self.assertNotIn("evidence_id", response.json())

    def test_malformed_status_success_is_never_forwarded(self):
        evidence_id = self.upload().json()["id"]
        wrong = {"evidence_id": evidence_id, "state": "QUARANTINED", "validation_code": "DECODER_REQUIRED",
                 "can_download": False, "latitude_e7": 145000001}
        with patch.object(mobile, "validation_status", return_value=wrong):
            response = self.read(evidence_id, "validation")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("latitude_e7", response.content.decode())

    def test_audit_failure_rolls_back_upload_without_private_error(self):
        with patch("apps.operations.evidence.audit.record", side_effect=DatabaseError("PRIVATE_CAPTURE_AUDIT_CANARY")):
            response = self.upload()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"PRIVATE_CAPTURE_AUDIT_CANARY", response.content)
        self.assertEqual(PrivateEvidence.objects.count(), 0)

    def test_token_expiry_during_upload_audit_rolls_back_acceptance(self):
        from apps.accounts.mobile_protocol import decode_access
        from apps.audit import service as audit
        claims = decode_access(self.session["access_token"])
        original_time, original_audit = timezone.now(), audit.record
        late = {"value": False}
        def clock():
            return datetime.fromtimestamp(claims.expires_at + 1, utc.utc) if late["value"] else original_time
        def record(*args, **kwargs):
            result = original_audit(*args, **kwargs)
            if args[2] == "EVIDENCE_QUARANTINED":
                late["value"] = True
            return result
        with patch("apps.accounts.mobile_services.now", side_effect=clock), patch.object(audit, "record", side_effect=record):
            response = self.upload()
        self.assert_auth_denied(response)
        self.assertEqual(PrivateEvidence.objects.count(), 0)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_QUARANTINED").count(), 0)

    def test_private_capture_audit_failure_returns_no_location(self):
        evidence_id = self.upload().json()["id"]
        with patch.object(mobile.audit, "record", side_effect=DatabaseError("PRIVATE_CAPTURE_READ_CANARY")):
            response = self.read(evidence_id)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("capture", response.json())
        self.assertNotIn(b"PRIVATE_CAPTURE_READ_CANARY", response.content)

    def test_stored_metadata_tamper_or_ciphertext_rebinding_is_unavailable(self):
        self.assertEqual(self.upload().status_code, 201)
        item = PrivateEvidence.objects.get()
        value = decrypt(item.payload_ciphertext)
        self.assertEqual(value["purpose"], "private-evidence-capture-v1")
        for field, change in (("actor_id", str(uuid.uuid4())), ("revision_id", str(uuid.uuid4())),
                              ("operation_id", str(uuid.uuid4())), ("capture", self.capture | {"version": True})):
            fake = copy.copy(item)
            fake.payload_ciphertext = encrypt(value | {field: change})
            with self.subTest(field=field), self.assertRaises(ApiError): strict_original(fake)
        fake = copy.copy(item)
        changed = copy.deepcopy(value)
        changed["capture"]["location"]["latitude_e7"] += 1
        fake.payload_ciphertext = encrypt(changed)
        with self.assertRaises(ApiError): strict_original(fake)
        from cryptography.fernet import Fernet
        from django.conf import settings
        key = settings.KAPIT_SOURCE_KEY
        raw = json.dumps(value, separators=(",", ":")).replace('"version":1', '"version":1,"version":1')
        fake.payload_ciphertext = Fernet(key.encode("ascii") if isinstance(key, str) else key).encrypt(raw.encode())
        with self.assertRaises(ApiError): strict_original(fake)
        self.assertEqual(PrivateEvidence.objects.get().payload_ciphertext, item.payload_ciphertext)

    def test_stored_capture_uses_original_created_at_not_later_server_clock(self):
        old = capture_at(timezone.now() - timedelta(days=400))
        response = self.upload(capture=json.dumps(old))
        self.assertEqual(response.status_code, 201)
        item = PrivateEvidence.objects.get()
        with patch("django.utils.timezone.now", return_value=timezone.now() - timedelta(days=1000)):
            self.assertEqual(strict_original(item)[2], old)

    def test_approved_recipient_feed_and_detail_never_receive_photo_or_coordinates(self):
        from apps.operations.worker import process_one, binding_for
        from apps.operations.serializers import DecisionSerializer
        from apps.reports.models import ReportVariant
        from apps.review.services import decide
        from apps.accounts.models import User
        from apps.publications.models import Publication
        self.assertEqual(self.upload().status_code, 201)
        self.assertTrue(process_one())
        variant = ReportVariant.objects.get(revision=self.revision)
        raw = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant),
               "reason": "Synthetic reviewed maintenance update."}
        serializer = DecisionSerializer(data=raw)
        serializer.is_valid(raise_exception=True)
        decide(User.objects.get(username="reviewer"), variant.id, serializer.validated_data, raw)
        publication = Publication.objects.get(report=self.revision.report)
        recipient, _ = self.web("recipient")
        feed = recipient.get(f"/api/v1/channels/{publication.channel_id}/feed/")
        detail = recipient.get(f"/api/v1/publications/{publication.id}/")
        self.assertEqual((feed.status_code, detail.status_code), (200, 200))
        self.assertEqual(feed.json()["count"], 1)
        output = feed.content + detail.content
        for private in (b"latitude_e7", b"longitude_e7", b"captured_at", b"capture.jpg", JPEG,
                        str(self.capture["location"]["latitude_e7"]).encode()):
            self.assertNotIn(private, output)
