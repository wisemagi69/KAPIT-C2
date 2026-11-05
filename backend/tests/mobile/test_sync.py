"""Real PostgreSQL mobile origin, receipt and authorized source HTTP checks."""
import copy
from datetime import timedelta
import json
from pathlib import Path
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from django.db import DatabaseError, transaction
from django.test import TestCase, override_settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.accounts.models import DeviceEnrollment, User
from apps.accounts.mobile_protocol import decode_access
from apps.accounts.mobile_services import lock_mobile_identity, revoke_device
from apps.audit import service as audit
from apps.audit.models import AuditEvent
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.operations.mobile_serializers import MobileOperationSerializer
from apps.operations.serializers import DecisionSerializer
from apps.operations.worker import binding_for, claim_job, finish_job, process_one
from apps.publications.models import Publication
from apps.reports.canonical import canonical, digest
from apps.reports.crypto import encrypt, source_payload
from apps.reports.models import Report, ReportRevision, ReportVariant
from apps.reports.services import receipt_body
from apps.review.services import decide
from apps.scopes.models import ChannelSource, UnitMembership
from tests.test_workflow import operation
from .helpers import MOBILE, MOBILE_SETTINGS, PASSWORD, MobileFixtures


class SyncFixtures(MobileFixtures):
    def setUp(self):
        super().setUp()
        self.session = self.enroll()

    def submit(self, body=None, *, session=None, client=None):
        body = body or operation()
        response = (client or self.client).post(MOBILE+"sync/operations/", body, format="json",
            HTTP_AUTHORIZATION="Bearer "+(session or self.session)["access_token"], HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        return body, response

    def read(self, path, *, session=None, client=None):
        return (client or self.client).get(MOBILE+path, HTTP_AUTHORIZATION="Bearer "+(session or self.session)["access_token"])

    def new_session(self, owner=None):
        return self.enroll(owner=owner, key=ec.generate_private_key(ec.SECP256R1()), installation=str(uuid.uuid4()))

    def decision(self, body, action="RETURN"):
        self.assertTrue(process_one())
        variant = ReportVariant.objects.select_related("revision", "policy").get(revision__report_id=body["report_id"])
        request = {"operation_id": str(uuid.uuid4()), "action": action, "expected": binding_for(variant), "reason": "Correct the synthetic maintenance detail."}
        serializer = DecisionSerializer(data=request)
        serializer.is_valid(raise_exception=True)
        decide(User.objects.get(username="reviewer"), variant.id, serializer.validated_data, request)
        return variant

    def retained_acceptance_without_receipt(self, body, *, web_origin=False):
        """Retained ledger fixture; no receipt deletion or retention job exists."""
        data = MobileOperationSerializer(data=body)
        data.is_valid(raise_exception=True)
        with transaction.atomic():
            actor, org, enrollment, _ = lock_mobile_identity(decode_access(self.session["access_token"]))
            unit = UnitMembership.objects.get(user=actor, active=True, role="submitter").unit
            report = Report.objects.create(id=body["report_id"], organization=org, author=actor, unit=unit)
            revision = ReportRevision.objects.create(organization=org, report=report, revision_no=1, submitted_by=actor,
                accepted_device=None if web_origin else enrollment, template_version=body["template_version"], observed_at=parse_datetime(body["payload"]["observed_at"]),
                payload_ciphertext=encrypt(body["payload"]), content_digest=digest(body["payload"]), operation_id=body["operation_id"],
                request_hash=digest({"body": body, "route": "POST /sync/operations/"}))
            ProcessingJob.objects.create(organization=org, revision=revision, policy=org.active_policy,
                channel_ids=[str(ChannelSource.objects.get(unit=unit, active=True).channel_id)], available_at=timezone.now())
            audit.record(org.id, actor, "SOURCE_ACCEPTED", report.id, operation_id=body["operation_id"], revision_no=1)
            return revision


@override_settings(**MOBILE_SETTINGS)
class MobileSyncTests(SyncFixtures, TestCase):
    def test_acceptance_twenty_exact_replays_commit_one_immutable_bundle(self):
        body, first = self.submit()
        self.assertEqual(first.status_code, 201)
        original = first.json()
        self.assertEqual(set(original), {"operation_id", "report_id", "revision_id", "revision_no", "delivery_status", "processing_status", "shared"})
        for _ in range(20):
            _, response = self.submit(body)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), original)
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="SOURCE_ACCEPTED").count(), 1)
        revision = ReportRevision.objects.get()
        self.assertEqual(str(revision.accepted_device_id), self.session["context"]["enrollment_id"])
        self.assertEqual(SyncReceipt.objects.get().accepted_device_id, revision.accepted_device_id)
        self.assertEqual(revision.request_hash, digest({"route": "POST /sync/operations/", "body": body}))
        self.assertFalse(Publication.objects.exists())

    def test_changed_payload_conflicts_without_mutating_acceptance(self):
        body, first = self.submit()
        self.assertEqual(first.status_code, 201)
        revision = ReportRevision.objects.get()
        original_cipher = bytes(revision.payload_ciphertext)
        changed = copy.deepcopy(body)
        changed["payload"]["narrative"] += " Altered synthetic observation."
        _, response = self.submit(changed)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "IDEMPOTENCY_CONFLICT")
        revision.refresh_from_db()
        self.assertEqual(bytes(revision.payload_ciphertext), original_cipher)
        self.assertEqual(ReportRevision.objects.count(), 1)

    def test_reauthentication_keeps_operation_namespace_and_receipt(self):
        body, first = self.submit()
        recovered = self.enroll(enrollment=self.session["context"]["enrollment_id"])
        self.assertNotEqual(self.session["context"]["family_id"], recovered["context"]["family_id"])
        self.assertEqual(recovered["context"]["enrollment_id"], self.session["context"]["enrollment_id"])
        _, replay = self.submit(body, session=recovered)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), first.json())
        self.assertEqual(self.read("sync/receipts/"+body["operation_id"]+"/", session=recovered).json(), first.json())

    def test_devices_and_web_have_independent_operation_namespaces(self):
        body, first = self.submit()
        self.assertEqual(first.status_code, 201)
        other = self.new_session()
        lookup = "sync/receipts/"+body["operation_id"]+"/"
        self.assertEqual(self.read(lookup, session=other).status_code, 404)
        second_body = dict(body, report_id=str(uuid.uuid4()))
        _, second = self.submit(second_body, session=other)
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(first.json()["revision_id"], second.json()["revision_id"])
        web, csrf = self.web()
        self.assertEqual(web.get("/api/v1/"+lookup).status_code, 404)
        web_body = dict(body, report_id=str(uuid.uuid4()))
        web_first = web.post("/api/v1/sync/operations/", web_body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"], HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(web_first.status_code, 201)
        web_again = web.post("/api/v1/sync/operations/", web_body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"], HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(web_again.status_code, 200)
        self.assertEqual(web_again.json(), web_first.json())
        self.assertEqual(web.get("/api/v1/"+lookup).json(), web_first.json())
        self.assertEqual(self.read(lookup).json(), first.json())
        self.assertEqual(self.read(lookup, session=other).json(), second.json())
        self.assertEqual(ReportRevision.objects.filter(accepted_device__isnull=True).count(), 1)
        self.assertEqual(ReportRevision.objects.filter(accepted_device__isnull=False).count(), 2)

    def test_own_history_crosses_origin_but_operation_lookup_does_not(self):
        body, first = self.submit()
        other = self.new_session()
        self.assertEqual(self.read("sync/receipts/"+body["operation_id"]+"/", session=other).status_code, 404)
        detail = self.read("reports/"+body["report_id"]+"/revisions/1/", session=other)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json()["receipt"], first.json())
        self.assertEqual(self.read("reports/", session=other).json()["count"], 1)

    def test_permanent_identity_reconstructs_receipt_and_blocks_changed_replay(self):
        body = operation()
        revision = self.retained_acceptance_without_receipt(body)
        self.assertFalse(SyncReceipt.objects.exists())
        result = self.read("sync/receipts/"+body["operation_id"]+"/")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), receipt_body(revision))
        for _ in range(20):
            _, replay = self.submit(body)
            self.assertEqual(replay.status_code, 200)
            self.assertEqual(replay.json(), result.json())
        altered = copy.deepcopy(body)
        altered["payload"]["site_label"] += " changed"
        _, conflict = self.submit(altered)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(ReportRevision.objects.count(), 1)
        self.assertEqual(ProcessingJob.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="SOURCE_ACCEPTED").count(), 1)
        self.assertFalse(SyncReceipt.objects.exists())
        other = self.new_session()
        self.assertEqual(self.read("sync/receipts/"+body["operation_id"]+"/", session=other).status_code, 404)
        web, _ = self.web()
        self.assertEqual(web.get("/api/v1/sync/receipts/"+body["operation_id"]+"/").status_code, 404)

    def test_web_permanent_receipt_fallback_stays_in_null_origin_namespace(self):
        body = operation()
        revision = self.retained_acceptance_without_receipt(body, web_origin=True)
        web, csrf = self.web()
        lookup = "/api/v1/sync/receipts/"+body["operation_id"]+"/"
        self.assertEqual(web.get(lookup).json(), receipt_body(revision))
        replay = web.post("/api/v1/sync/operations/", body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"], HTTP_X_CSRFTOKEN=csrf)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), receipt_body(revision))
        self.assertEqual(self.read("sync/receipts/"+body["operation_id"]+"/").status_code, 404)
        mobile = dict(body, report_id=str(uuid.uuid4()))
        self.assertEqual(self.submit(mobile)[1].status_code, 201)
        self.assertEqual(web.get(lookup).json(), receipt_body(revision))
        self.assertEqual(ReportRevision.objects.count(), 2)

    def test_mobile_preserves_whitespace_unicode_and_equivalent_wire_replay(self):
        body = operation()
        body["payload"].update(site_label="  Synthetic pump  ", reporter_label=" Synthetic reporter ", narrative="  Synthetic cafe\u0301 \U0001f527 detail.  ")
        _, first = self.submit(body)
        self.assertEqual(first.status_code, 201)
        revision = ReportRevision.objects.get()
        self.assertEqual(source_payload(revision), body["payload"])
        wire = json.dumps(dict(reversed(list(body.items()))), ensure_ascii=True, indent=2)
        response = self.client.post(MOBILE+"sync/operations/", wire, content_type="application/json",
            HTTP_AUTHORIZATION="Bearer "+self.session["access_token"], HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), first.json())
        normalized = copy.deepcopy(body)
        normalized["payload"]["narrative"] = normalized["payload"]["narrative"].replace("e\u0301", "\u00e9")
        self.assertEqual(self.submit(normalized)[1].status_code, 409)

    def test_frozen_canonical_vectors_match_python_digest_and_schema(self):
        fixtures = json.loads((Path(__file__).resolve().parents[3]/"contracts/fixtures/sync/mobile-canonical.json").read_text(encoding="utf-8"))
        for vector in fixtures["vectors"]:
            with self.subTest(vector=vector["id"]):
                serializer = MobileOperationSerializer(data=vector["body"])
                self.assertTrue(serializer.is_valid(), "Frozen valid vector failed schema.")
                envelope = {"body": vector["body"], "route": "POST /sync/operations/"}
                self.assertEqual(canonical(envelope).hex(), vector["canonical_utf8_hex"])
                self.assertEqual(digest(envelope), vector["sha256"])

    def test_mobile_validation_does_not_reserve_operation_or_reflect_values(self):
        original = operation()
        invalid = []
        for value in [True, 1.0, "0", -1, 2147483647]:
            invalid.append(dict(original, expected_revision=value))
        invalid.extend([dict(original, operation_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"),
            dict(original, report_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"), dict(original, accepted_device="PRIVATE_ORIGIN_CANARY")])
        for body in invalid:
            response = self.submit(body)[1]
            self.assertEqual(response.status_code, 422)
            self.assertNotIn("PRIVATE_ORIGIN_CANARY", response.content.decode())
        self.assertFalse(ReportRevision.objects.exists())
        self.assertEqual(self.submit(original)[1].status_code, 201)

    def test_template_errors_and_json_boundaries_are_mobile_specific(self):
        body = operation()
        for value in ["", "unsupported-synthetic-template"]:
            response = self.submit(dict(body, template_version=value))[1]
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["code"], "TEMPLATE_UNSUPPORTED")
        for changed in [dict(body, template_version=None), dict(body, template_version=1), {k:v for k,v in body.items() if k != "template_version"}]:
            response = self.submit(changed)[1]
            self.assertEqual(response.status_code, 422)
            self.assertEqual(response.json()["code"], "VALIDATION_ERROR")
        for raw, expected in [(b'{"x":0,"x":1}', 400), (b'{"x":"\\ud800"}', 422), (b'[]', 400), (b'{"x":Infinity}', 400), (b'x'*20481, 413)]:
            response = self.client.post(MOBILE+"sync/operations/", raw, content_type="application/json", HTTP_AUTHORIZATION="Bearer "+self.session["access_token"])
            self.assertEqual(response.status_code, expected)
        self.assertFalse(ReportRevision.objects.exists())

    def test_all_frozen_negative_source_fixtures_match_http_error_contract(self):
        fixtures = json.loads((Path(__file__).resolve().parents[3]/"contracts/fixtures/sync/mobile-canonical.json").read_text(encoding="utf-8"))
        for case in fixtures["negative_validation_cases"]:
            with self.subTest(case=case["id"]):
                raw = case["raw_json"] if "raw_json" in case else json.dumps(case["body"], ensure_ascii=True)
                response = self.client.post(MOBILE+"sync/operations/", raw, content_type="application/json",
                    HTTP_AUTHORIZATION="Bearer "+self.session["access_token"], HTTP_IDEMPOTENCY_KEY="11111111-1111-4111-8111-111111111111")
                self.assertEqual(response.status_code, case["expected_status"])
                self.assertEqual(response.json()["code"], case["expected_code"])
        self.assertFalse(ReportRevision.objects.exists())
        self.assertFalse(SyncReceipt.objects.exists())

    def test_idempotency_header_and_query_validation_happen_before_acceptance(self):
        body = operation()
        response = self.client.post(MOBILE+"sync/operations/", body, format="json", HTTP_AUTHORIZATION="Bearer "+self.session["access_token"])
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "INVALID_IDEMPOTENCY_KEY")
        response = self.client.post(MOBILE+"sync/operations/?extra=private", body, format="json", HTTP_AUTHORIZATION="Bearer "+self.session["access_token"], HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(response.status_code, 400)
        self.assertFalse(ReportRevision.objects.exists())

    def test_current_author_scope_applies_to_lists_counts_receipts_and_detail(self):
        body, _ = self.submit()
        foreign = self.another_owner()
        foreign_session = self.new_session(owner=foreign)
        own = self.read("reports/", session=foreign_session)
        self.assertEqual(own.status_code, 200)
        self.assertEqual(own.json()["count"], 0)
        known = self.read("reports/"+body["report_id"]+"/revisions/1/", session=foreign_session)
        unknown = self.read("reports/"+str(uuid.uuid4())+"/revisions/1/", session=foreign_session)
        self.assertEqual(known.status_code, 404)
        self.assertEqual(known.json(), unknown.json())
        receipt = self.read("sync/receipts/"+body["operation_id"]+"/", session=foreign_session)
        self.assertEqual(receipt.status_code, 404)
        self.assertEqual(receipt.json(), unknown.json())
        for response in [known, unknown, receipt, own]:
            self.assertNotIn("PRIVATE_", response.content.decode())
            self.assertIn("no-store", response.get("Cache-Control", ""))

    def test_scope_removal_denies_even_replays_and_cached_receipt_reads(self):
        body, _ = self.submit()
        UnitMembership.objects.filter(user=self.owner, role="submitter").update(active=False)
        for response in [self.submit(body)[1], self.read("reports/"), self.read("sync/receipts/"+body["operation_id"]+"/"), self.read("reports/"+body["report_id"]+"/revisions/1/")]:
            self.assertEqual(response.status_code, 403)
            self.assertNotIn("PRIVATE_", response.content.decode())
        self.assertEqual(ReportRevision.objects.count(), 1)

    def test_same_unit_other_author_never_sees_source_or_counts(self):
        body, _ = self.submit()
        other = User.objects.create_user(username="same-unit-synthetic", password=PASSWORD,
            organization=self.org, display_name="Synthetic same-unit owner", role="submitter")
        unit = UnitMembership.objects.get(user=self.owner, role="submitter", active=True).unit
        UnitMembership.objects.create(organization=self.org, user=other, unit=unit, role="submitter")
        session = self.new_session(owner=other)
        self.assertEqual(self.read("reports/", session=session).json()["count"], 0)
        self.assertEqual(self.read("reports/"+body["report_id"]+"/revisions/1/", session=session).status_code, 404)
        self.assertEqual(self.read("sync/receipts/"+body["operation_id"]+"/", session=session).status_code, 404)

    def test_report_filter_pagination_and_current_status_remain_scoped(self):
        returned, _ = self.submit()
        self.decision(returned)
        awaiting, _ = self.submit()
        self.assertTrue(process_one())
        pending, _ = self.submit()
        first = self.read("reports/?page=1&page_size=2")
        second = self.read("reports/?page=2&page_size=2")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.json()["count"], 3)
        self.assertEqual([first.json()["total_pages"], len(first.json()["results"]), len(second.json()["results"])], [2,2,1])
        ids = [row["id"] for row in first.json()["results"]+second.json()["results"]]
        self.assertCountEqual(ids, [returned["report_id"], awaiting["report_id"], pending["report_id"]])
        filtered = self.read("reports/?status=RETURNED")
        self.assertEqual(filtered.json()["count"], 1)
        self.assertEqual(filtered.json()["results"][0]["id"], returned["report_id"])
        for query in ["page=1&page=2", "status=OTHER", "page_size=51", "date_from=2026-02-30", "date_from=2026-10-18&date_to=2026-10-17", "unknown=private"]:
            response = self.read("reports/?"+query)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()["code"], "INVALID_FILTER")

    def test_returned_correction_keeps_original_and_requires_new_review(self):
        body, original = self.submit()
        self.decision(body)
        before = self.read("reports/"+body["report_id"]+"/revisions/1/").json()
        self.assertTrue(before["can_correct"])
        old_cipher = bytes(ReportRevision.objects.get().payload_ciphertext)
        correction = operation(report_id=body["report_id"], expected_revision=1)
        correction["payload"]["narrative"] = "Corrected synthetic maintenance observation."
        _, accepted = self.submit(correction)
        self.assertEqual(accepted.status_code, 201)
        self.assertEqual(accepted.json()["revision_no"], 2)
        self.assertEqual(bytes(ReportRevision.objects.get(revision_no=1).payload_ciphertext), old_cipher)
        self.assertEqual(self.submit(body)[1].json(), original.json())
        self.assertEqual(self.submit(correction)[1].json(), accepted.json())
        stale = operation(report_id=body["report_id"], expected_revision=1)
        self.assertEqual(self.submit(stale)[1].json()["code"], "REVISION_CONFLICT")
        detail = self.read("reports/"+body["report_id"]+"/revisions/2/").json()
        self.assertEqual([row["revision_no"] for row in detail["history"]], [2,1])
        self.assertFalse(detail["can_correct"])
        self.assertEqual(detail["report"]["status"], "PENDING")
        self.assertFalse(Publication.objects.exists())

    def test_rejected_report_cannot_be_corrected(self):
        body, _ = self.submit()
        self.decision(body, "REJECT")
        response = self.submit(operation(report_id=body["report_id"], expected_revision=1))[1]
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "CORRECTION_UNAVAILABLE")
        self.assertEqual(ReportRevision.objects.count(), 1)

    def test_worker_failure_changes_status_but_not_historical_receipt_or_publication(self):
        body, accepted = self.submit()
        lease = claim_job()
        self.assertTrue(finish_job(lease, error_code="synthetic-failure"))
        self.assertEqual(self.read("reports/?status=FAILED").json()["count"], 1)
        self.assertEqual(self.read("sync/receipts/"+body["operation_id"]+"/").json(), accepted.json())
        self.assertEqual(self.submit(body)[1].json(), accepted.json())
        self.assertFalse(Publication.objects.exists())

    def test_audit_failure_rolls_back_entire_source_acceptance(self):
        with patch("apps.reports.services.audit.record", side_effect=RuntimeError("PRIVATE_AUDIT_CANARY")):
            _, response = self.submit()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("PRIVATE_AUDIT_CANARY", response.content.decode())
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 0)

    def test_bearer_cannot_use_web_review_or_administration_and_cookie_cannot_submit_mobile(self):
        web, _ = self.web()
        body = operation()
        response = web.post(MOBILE+"sync/operations/", body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assert_auth_denied(response)
        for path in ["/api/v1/review/queue/", "/api/v1/administration/users/"]:
            response = self.client.get(path, HTTP_AUTHORIZATION="Bearer "+self.session["access_token"])
            self.assertEqual(response.status_code, 403)
        self.assertFalse(ReportRevision.objects.exists())

    def test_sql_guards_freeze_source_and_receipt_origins(self):
        self.submit()
        other = self.new_session()
        for model in [ReportRevision, SyncReceipt]:
            for origin in [None, other["context"]["enrollment_id"]]:
                with self.assertRaises(DatabaseError), transaction.atomic():
                    model.objects.all().update(accepted_device_id=origin)
        self.assertEqual(ReportRevision.objects.count(), 1)
        self.assertEqual(SyncReceipt.objects.count(), 1)

    def test_sql_receipt_nullable_origin_mismatch_is_rejected(self):
        body = operation()
        revision = self.retained_acceptance_without_receipt(body)
        with self.assertRaises(DatabaseError), transaction.atomic():
            SyncReceipt.objects.create(organization=self.org, accepted_user=self.owner, accepted_device=None,
                operation_id=revision.operation_id, request_hash=revision.request_hash, revision=revision, response_body=receipt_body(revision))
        other = self.new_session()
        with self.assertRaises(DatabaseError), transaction.atomic():
            SyncReceipt.objects.create(organization=self.org, accepted_user=self.owner, accepted_device_id=other["context"]["enrollment_id"],
                operation_id=revision.operation_id, request_hash=revision.request_hash, revision=revision, response_body=receipt_body(revision))
        web_revision = self.retained_acceptance_without_receipt(operation(), web_origin=True)
        with self.assertRaises(DatabaseError), transaction.atomic():
            SyncReceipt.objects.create(organization=self.org, accepted_user=self.owner, accepted_device_id=self.session["context"]["enrollment_id"],
                operation_id=web_revision.operation_id, request_hash=web_revision.request_hash, revision=web_revision, response_body=receipt_body(web_revision))
        self.assertFalse(SyncReceipt.objects.exists())

    def test_sql_revision_origin_must_match_immutable_owner_org(self):
        body = operation()
        unit = UnitMembership.objects.get(user=self.owner, active=True).unit
        report = Report.objects.create(id=body["report_id"], organization=self.org, author=self.owner, unit=unit)
        for same_org in [True, False]:
            foreign = self.another_owner(suffix="same" if same_org else "foreign", same_org=same_org)
            foreign_session = self.new_session(owner=foreign)
            with self.assertRaises(DatabaseError), transaction.atomic():
                ReportRevision.objects.create(organization=self.org, report=report, submitted_by=self.owner,
                    accepted_device_id=foreign_session["context"]["enrollment_id"], template_version=body["template_version"],
                    observed_at=parse_datetime(body["payload"]["observed_at"]), payload_ciphertext=encrypt(body["payload"]),
                    content_digest=digest(body["payload"]), operation_id=body["operation_id"], request_hash=digest(body))
        revoke_device(self.owner, self.session["context"]["enrollment_id"])
        with self.assertRaises(DatabaseError), transaction.atomic():
            ReportRevision.objects.create(organization=self.org, report=report, submitted_by=self.owner,
                accepted_device_id=self.session["context"]["enrollment_id"], template_version=body["template_version"],
                observed_at=parse_datetime(body["payload"]["observed_at"]), payload_ciphertext=encrypt(body["payload"]),
                content_digest=digest(body["payload"]), operation_id=body["operation_id"], request_hash=digest(body))
        self.assertFalse(ReportRevision.objects.exists())
