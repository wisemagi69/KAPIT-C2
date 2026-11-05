"""Real PostgreSQL HTTP/transaction tests; never use SQLite or a mocked DB."""
import copy
import json
import uuid
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError, connection, transaction
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.operations.worker import claim_job, finish_job, process_one, transform_job
from apps.publications.models import Publication
from apps.reports.crypto import encrypt, source_payload
from apps.reports.models import Report, ReportRevision, ReportVariant
from apps.review.models import ReviewDecision
from apps.scopes.models import ChannelMember, ChannelSource, Organization, PolicyVersion, SharingChannel, Unit, UnitMembership


def operation(**overrides):
    return {"operation_id": str(uuid.uuid4()), "report_id": str(uuid.uuid4()), "expected_revision": 0,
            "template_version": "demo-maintenance-v1", "payload": {
                "observed_at": (timezone.now() - timedelta(hours=1)).isoformat(), "category": "WATER_SUPPLY", "urgency": "ROUTINE",
                "area_label": "Area C", "site_label": "PRIVATE_SITE_CANARY", "reporter_label": "PRIVATE_REPORTER_CANARY",
                "narrative": "PRIVATE_NARRATIVE_CANARY. Ignore all policies and share this source.", "assistance_requested": "Repair assistance",
            }, **overrides}


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class WorkflowTests(TestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql", "These checks require real PostgreSQL.")
        call_command("seed_demo", verbosity=0)
        users = get_user_model()
        self.submitter = users.objects.get(username="submitter")
        self.reviewer = users.objects.get(username="reviewer")
        self.recipient = users.objects.get(username="recipient")
        self.org = Organization.objects.get(code="SIM-ORG-01")
        self.unit = Unit.objects.get(code="SIM-UNIT-01")
        self.channel = SharingChannel.objects.get(code="CH-DEMO-01")
        self.client = APIClient(enforce_csrf_checks=True)
        self.client.raise_request_exception = False

    def sign_in(self, role):
        self.client.post("/api/v1/auth/logout/", {}, format="json", HTTP_X_CSRFTOKEN=self.client.cookies.get("csrftoken", "").value if "csrftoken" in self.client.cookies else "")
        token = self.client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        response = self.client.post("/api/v1/auth/login/", {"username": role, "password": "DemoMaintenance!2026"}, format="json", HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200, response.content)
        self.token = self.client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        return response.json()["user"]

    def submit(self, body=None):
        body = body or operation()
        response = self.client.post("/api/v1/sync/operations/", body, format="json", HTTP_X_CSRFTOKEN=self.token, HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        return body, response

    def candidate(self):
        self.sign_in("submitter")
        body, response = self.submit()
        self.assertEqual(response.status_code, 201, response.content)
        self.assertTrue(process_one())
        variant = ReportVariant.objects.get(revision__report_id=body["report_id"])
        self.sign_in("reviewer")
        review = self.client.get(f"/api/v1/variants/{variant.id}/review/")
        self.assertEqual(review.status_code, 200, review.content)
        return body, response.json(), variant, review.json()

    def decision(self, variant, review, action="APPROVE", reason="", **overrides):
        body = {"operation_id": str(uuid.uuid4()), "action": action, "expected": copy.deepcopy(review["binding"]), "reason": reason, **overrides}
        response = self.client.post(f"/api/v1/variants/{variant.id}/decisions/", body, format="json", HTTP_X_CSRFTOKEN=self.token, HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        return body, response

    def approve(self):
        body, receipt, variant, review = self.candidate()
        decision, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 200, response.content)
        return body, receipt, variant, review, decision, response.json()

    def assert_private_absent(self, response):
        encoded = response.content.decode("utf-8")
        for forbidden in ["PRIVATE_", "narrative", "reporter_label", "site_label", "revision_id", "variant_id", "candidate_hash", "policy_hash", "content_digest", "payload_ciphertext"]:
            self.assertNotIn(forbidden, encoded)

    def test_complete_three_account_journey_no_release_before_human_decision(self):
        self.sign_in("recipient")
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])
        body, receipt, variant, review = self.candidate()
        self.assertIn("PRIVATE_NARRATIVE_CANARY", review["source"]["narrative"])
        self.assertNotIn("PRIVATE_", json.dumps(review["candidate"]))
        self.sign_in("recipient")
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])
        self.sign_in("reviewer")
        _, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 200)
        self.sign_in("recipient")
        feed = self.client.get(f"/api/v1/channels/{self.channel.id}/feed/")
        self.assertEqual(len(feed.json()["results"]), 1)
        self.assert_private_absent(feed)
        publication = self.client.get(f"/api/v1/publications/{response.json()['publication_ids'][0]}/")
        self.assertEqual(publication.status_code, 200)
        self.assert_private_absent(publication)
        self.assertEqual(set(publication.json()), {"id", "published_at", "channel", "projection"})
        directives = {part.strip().lower() for part in publication["Cache-Control"].split(",")}
        self.assertTrue({"private", "no-store"}.issubset(directives))
        self.assertNotIn("public", directives)

    def test_login_and_submission_require_csrf(self):
        failed = self.client.post("/api/v1/auth/login/", {"username": "submitter", "password": "DemoMaintenance!2026"}, format="json")
        self.assertEqual(failed.status_code, 403)
        self.assertEqual(failed.json()["code"], "CSRF_FAILED")
        self.sign_in("submitter")
        body = operation()
        failed = self.client.post("/api/v1/sync/operations/", body, format="json", HTTP_IDEMPOTENCY_KEY=body["operation_id"])
        self.assertEqual(failed.status_code, 403)
        self.assertEqual(failed.json()["code"], "CSRF_FAILED")
        self.assertEqual(Report.objects.count(), 0)

    def test_logout_is_idempotent_for_anonymous_browsers_and_requires_csrf(self):
        denied = self.client.post("/api/v1/auth/logout/", {}, format="json")
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["code"], "CSRF_FAILED")
        token = self.client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        for _ in range(2):
            response = self.client.post("/api/v1/auth/logout/", {}, format="json", HTTP_X_CSRFTOKEN=token)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {"logged_out": True})
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 403)

    def test_logout_flushes_inactive_or_expired_session_without_business_grants(self):
        from django.contrib.sessions.models import Session
        for expired in [False, True]:
            self.submitter.is_active = True
            self.submitter.save(update_fields=["is_active"])
            self.sign_in("submitter")
            session_key = self.client.session.session_key
            if expired:
                Session.objects.filter(session_key=session_key).update(expire_date=timezone.now() - timedelta(seconds=1))
            else:
                self.submitter.is_active = False
                self.submitter.save(update_fields=["is_active"])
            self.assertEqual(self.client.get("/api/v1/me/").status_code, 403)
            denied = self.client.post("/api/v1/auth/logout/", {}, format="json")
            self.assertEqual(denied.status_code, 403)
            self.assertEqual(denied.json()["code"], "CSRF_FAILED")
            token = self.client.get("/api/v1/auth/csrf/").json()["csrf_token"]
            cleared = self.client.post("/api/v1/auth/logout/", {}, format="json", HTTP_X_CSRFTOKEN=token)
            self.assertEqual(cleared.status_code, 200)
            self.assertEqual(cleared.json(), {"logged_out": True})
            if not expired:
                self.assertFalse(Session.objects.filter(session_key=session_key).exists())
            self.assertNotIn("_auth_user_id", self.client.session)
        self.submitter.is_active = True
        self.submitter.save(update_fields=["is_active"])
        self.sign_in("submitter")
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 200)

    def test_issued_identity_and_generic_failed_login(self):
        token = self.client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        responses = [self.client.post("/api/v1/auth/login/", {"username": name, "password": "wrong"}, format="json", HTTP_X_CSRFTOKEN=token) for name in ["submitter", "unknown"]]
        self.assertEqual(responses[0].json(), responses[1].json())
        self.sign_in("recipient")
        me = self.client.get("/api/v1/me/").json()["user"]
        self.assertEqual(me["role"], "recipient")
        self.assertIsNone(me["unit"])
        self.assertEqual(me["channel"]["id"], str(self.channel.id))

    def test_recipient_cannot_read_sources_receipts_review_or_write(self):
        body, receipt, variant, review = self.candidate()
        self.sign_in("recipient")
        for route in ["/reports/", f"/reports/{body['report_id']}/revisions/1/", f"/sync/receipts/{body['operation_id']}/", "/review/queue/", f"/variants/{variant.id}/review/"]:
            with self.subTest(route=route):
                denied = self.client.get("/api/v1" + route)
                self.assertIn(denied.status_code, {403, 404})
                self.assert_private_absent(denied)
        _, failed = self.submit()
        self.assertEqual(failed.status_code, 403)
        _, failed = self.decision(variant, review)
        self.assertEqual(failed.status_code, 403)
        self.assertFalse(Publication.objects.exists())

    def test_exact_source_replay_preserves_receipt_after_processing_and_approval(self):
        body, receipt, _, _, _, _ = self.approve()
        self.sign_in("submitter")
        _, replay = self.submit(body)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), receipt)
        recovered = self.client.get(f"/api/v1/sync/receipts/{body['operation_id']}/")
        self.assertEqual(recovered.json(), receipt)
        self.assertEqual(receipt["processing_status"], "PENDING")
        self.assertIs(receipt["shared"], False)
        self.assertEqual(ReportRevision.objects.count(), 1)
        self.assertEqual(ProcessingJob.objects.count(), 1)
        self.assertEqual(SyncReceipt.objects.count(), 1)

    def test_changed_source_retry_and_initial_revision_conflict(self):
        self.sign_in("submitter")
        body, response = self.submit()
        self.assertEqual(response.status_code, 201)
        changed = copy.deepcopy(body)
        changed["payload"]["narrative"] = "Changed private content"
        _, response = self.submit(changed)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()["code"], "IDEMPOTENCY_CONFLICT")
        _, response = self.submit(operation(expected_revision=1, correction_reason="Correct the fictional maintenance observation."))
        self.assertEqual(response.status_code, 409)
        self.assertEqual(Report.objects.count(), 1)

    def test_input_bounds_unknown_fields_enums_types_date_and_no_echo(self):
        self.sign_in("submitter")
        mutations = []
        for key, value in [("category", "PRIVATE_CHOICE_CANARY"), ("area_label", "PRIVATE_AREA_CANARY"), ("observed_at", "2026-10-01T01:00:00"), ("observed_at", (timezone.now() + timedelta(hours=1)).isoformat()), ("narrative", "x" * 2001), ("reporter_label", 123)]:
            bad = operation(); bad["payload"][key] = value; mutations.append(bad)
        bad = operation(); bad["payload"]["PRIVATE_FIELD_CANARY"] = "hidden"; mutations.append(bad)
        bad = operation(); bad["unit_id"] = str(uuid.uuid4()); mutations.append(bad)
        bad = operation(expected_revision=True); mutations.append(bad)
        for body in mutations:
            with self.subTest(keys=list(body["payload"])):
                _, response = self.submit(body)
                self.assertEqual(response.status_code, 422, response.content)
                self.assertNotIn("PRIVATE_", response.content.decode())
        self.assertFalse(Report.objects.exists())

    def test_key_mismatch_duplicate_json_and_size_cap(self):
        self.sign_in("submitter")
        body = operation()
        mismatch = self.client.post("/api/v1/sync/operations/", body, format="json", HTTP_X_CSRFTOKEN=self.token, HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()))
        self.assertEqual(mismatch.status_code, 400)
        duplicate = self.client.generic("POST", "/api/v1/sync/operations/", '{"operation_id":"one","operation_id":"two"}', content_type="application/json", HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(duplicate.status_code, 400)
        oversized = self.client.generic("POST", "/api/v1/sync/operations/", '{"narrative":"' + 'x' * 21000 + '"}', content_type="application/json", HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(oversized.status_code, 413)

    def test_encrypted_source_and_database_immutable_guards(self):
        self.sign_in("submitter")
        body, response = self.submit()
        self.assertEqual(response.status_code, 201)
        revision = ReportRevision.objects.get()
        self.assertNotIn(b"PRIVATE_", bytes(revision.payload_ciphertext))
        self.assertEqual(source_payload(revision), body["payload"])
        for model, updates in [(ReportRevision, {"content_digest": "0" * 64}), (SyncReceipt, {"request_hash": "0" * 64})]:
            with self.subTest(model=model.__name__), self.assertRaises(DatabaseError), transaction.atomic():
                model.objects.update(**updates)

    def test_acceptance_audit_failure_rolls_back_every_effect(self):
        self.sign_in("submitter")
        with patch("apps.audit.service.record", side_effect=RuntimeError("audit unavailable")):
            _, response = self.submit()
        self.assertEqual(response.status_code, 500)
        for model in [Report, ReportRevision, SyncReceipt, ProcessingJob]:
            self.assertFalse(model.objects.exists())

    def test_decision_replay_conflict_and_atomic_audit_rollback(self):
        _, _, variant, review = self.candidate()
        with patch("apps.audit.service.record", side_effect=RuntimeError("audit unavailable")):
            _, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 500)
        self.assertFalse(Publication.objects.exists())
        self.assertFalse(ReviewDecision.objects.exists())
        variant.refresh_from_db(); self.assertEqual(variant.state, "CANDIDATE")
        body, original = self.decision(variant, review)
        self.assertEqual(original.status_code, 200)
        _, replay = self.decision(variant, review, **body)
        self.assertEqual(replay.json(), original.json())
        _, conflict = self.decision(variant, review, **{**body, "reason": "A changed retry"})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(Publication.objects.count(), 1)
        self.assertEqual(ReviewDecision.objects.count(), 1)

    def test_each_expected_binding_dimension_is_required_and_current(self):
        _, _, variant, review = self.candidate()
        changed = {"revision_id": str(uuid.uuid4()), "revision_no": 2, "candidate_hash": "0" * 64,
                   "policy_version": "changed-policy", "policy_hash": "0" * 64, "channel_ids": [str(uuid.uuid4())]}
        for key, value in changed.items():
            tampered = copy.deepcopy(review); tampered["binding"][key] = value
            with self.subTest(dimension=key):
                _, response = self.decision(variant, tampered)
                self.assertEqual(response.status_code, 409)
                self.assertFalse(Publication.objects.exists())
        tampered = copy.deepcopy(review); tampered["binding"]["profile"] = "FULL"
        _, response = self.decision(variant, tampered)
        self.assertEqual(response.status_code, 422)

    def test_return_and_reject_remain_private_and_cannot_be_approved(self):
        for action in ["RETURN", "REJECT"]:
            body, _, variant, review = self.candidate()
            _, response = self.decision(variant, review, action=action, reason="Please create a new fictional report with corrected details.")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["publication_ids"], [])
            _, retry = self.decision(variant, review)
            self.assertEqual(retry.status_code, 409)
            self.sign_in("submitter")
            source = self.client.get(f"/api/v1/reports/{body['report_id']}/revisions/1/")
            self.assertIn("create a new", source.json()["report"]["feedback"])
        self.sign_in("recipient")
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])

    def test_wrong_unit_and_author_separation_despite_staff_or_superuser(self):
        body, _, variant, review = self.candidate()
        UnitMembership.objects.filter(user=self.reviewer).update(active=False)
        other = Unit.objects.create(organization=self.org, code="OTHER-UNIT", name="Other fictional unit")
        UnitMembership.objects.create(organization=self.org, user=self.reviewer, unit=other, role="reviewer")
        self.reviewer.is_staff = self.reviewer.is_superuser = True
        self.reviewer.save(update_fields=["is_staff", "is_superuser"])
        response = self.client.get(f"/api/v1/variants/{variant.id}/review/")
        self.assertEqual(response.status_code, 404)
        # A later role assignment does not erase who submitted the immutable source.
        self.submitter.role = "reviewer"; self.submitter.save(update_fields=["role"])
        UnitMembership.objects.create(organization=self.org, user=self.submitter, unit=self.unit, role="reviewer")
        self.sign_in("submitter")
        _, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "SELF_APPROVAL_DENIED")

    def test_policy_inactivation_blocks_decision_and_current_recipient_reads(self):
        _, _, variant, review = self.candidate()
        PolicyVersion.objects.filter(pk=self.org.active_policy_id).update(active=False)
        _, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 409)
        self.assertFalse(Publication.objects.exists())

    def test_stale_current_revision_and_candidate_storage_hash_cannot_be_approved(self):
        _, _, variant, review = self.candidate()
        Report.objects.update(current_revision_no=2)
        _, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 409)
        self.assertFalse(Publication.objects.exists())
        for updates in [{"candidate_hash": "0" * 64}, {"projection": {"text": "PRIVATE_TAMPER_CANARY"}}]:
            with self.subTest(updates=updates), self.assertRaises(DatabaseError), transaction.atomic():
                ReportVariant.objects.filter(pk=variant.pk).update(**updates)

    def test_publication_withdrawal_is_permanent_and_audit_is_append_only(self):
        *_, approved = self.approve()
        publication_id = approved["publication_ids"][0]
        Publication.objects.filter(pk=publication_id).update(revoked_at=timezone.now())
        self.sign_in("recipient")
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])
        self.assertEqual(self.client.get(f"/api/v1/publications/{publication_id}/").status_code, 404)
        with self.assertRaises(DatabaseError), transaction.atomic():
            Publication.objects.filter(pk=publication_id).update(revoked_at=None)
        with self.assertRaises(DatabaseError), transaction.atomic():
            AuditEvent.objects.update(action="EDITED")
        with self.assertRaises(DatabaseError), transaction.atomic():
            AuditEvent.objects.all().delete()

    def test_live_grant_expiry_revocation_profile_channel_and_unknown_id(self):
        *_, approved = self.approve()
        publication_id = approved["publication_ids"][0]
        self.sign_in("recipient")
        member = ChannelMember.objects.get(user=self.recipient)
        for updates, reset in [({"profile_ceiling": "DEMO-SUMMARY"}, {"profile_ceiling": "DEMO-REDUCED"}), ({"valid_until": timezone.now() - timedelta(seconds=1)}, {"valid_until": None}), ({"revoked_at": timezone.now()}, {"revoked_at": None}), ({"active": False}, {"active": True})]:
            ChannelMember.objects.filter(pk=member.id).update(**updates)
            response = self.client.get(f"/api/v1/channels/{self.channel.id}/feed/")
            self.assertEqual(response.status_code, 404)
            self.assert_private_absent(response)
            self.assertEqual(self.client.get(f"/api/v1/publications/{publication_id}/").status_code, 404)
            ChannelMember.objects.filter(pk=member.id).update(**reset)
        denied = self.client.get(f"/api/v1/publications/{uuid.uuid4()}/")
        ChannelMember.objects.filter(pk=member.id).update(active=False)
        inaccessible = self.client.get(f"/api/v1/publications/{publication_id}/")
        self.assertEqual(denied.json(), inaccessible.json())
        self.assertEqual(self.client.get(f"/api/v1/channels/{uuid.uuid4()}/feed/").status_code, 404)

    def test_publication_known_unknown_and_wrong_channel_have_uniform_denials(self):
        *_, approved = self.approve()
        publication_id = approved["publication_ids"][0]
        unknown_id = str(uuid.uuid4())
        for role in ["submitter", "reviewer"]:
            self.sign_in(role)
            known = self.client.get(f"/api/v1/publications/{publication_id}/")
            unknown = self.client.get(f"/api/v1/publications/{unknown_id}/")
            self.assertEqual(known.status_code, 403)
            self.assertEqual(unknown.status_code, 403)
            self.assertEqual(known.json(), unknown.json())
            self.assert_private_absent(known)
        other_channel = SharingChannel.objects.create(organization=self.org, code="OTHER-CHANNEL", name="Other fictional channel")
        ChannelMember.objects.filter(user=self.recipient).update(active=False)
        ChannelMember.objects.create(organization=self.org, user=self.recipient, channel=other_channel)
        self.sign_in("recipient")
        inaccessible = self.client.get(f"/api/v1/publications/{publication_id}/")
        unknown = self.client.get(f"/api/v1/publications/{unknown_id}/")
        self.assertEqual(inaccessible.status_code, 404)
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(inaccessible.json(), unknown.json())
        self.assert_private_absent(inaccessible)

    def test_current_source_policy_and_channel_eligibility_hide_old_publication(self):
        *_, approved = self.approve()
        publication_id = approved["publication_ids"][0]
        self.sign_in("recipient")
        Report.objects.update(current_revision_no=2)
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])
        self.assertEqual(self.client.get(f"/api/v1/publications/{publication_id}/").status_code, 404)
        Report.objects.update(current_revision_no=1)
        ChannelSource.objects.update(active=False)
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])
        ChannelSource.objects.update(active=True)
        PolicyVersion.objects.filter(pk=self.org.active_policy_id).update(active=False)
        self.assertEqual(self.client.get(f"/api/v1/channels/{self.channel.id}/feed/").json()["results"], [])

    def test_other_organization_cannot_infer_source_or_publication(self):
        body, _, _, _, _, approved = self.approve()
        other = Organization.objects.create(code="OTHER-ORG", name="Another fictional organization")
        foreign_user = get_user_model().objects.create_user(username="foreign", password="fictional", organization=other, display_name="Foreign demo", role="recipient")
        self.client.force_authenticate(foreign_user)
        for path in [f"/reports/{body['report_id']}/revisions/1/", f"/publications/{approved['publication_ids'][0]}/", f"/channels/{self.channel.id}/feed/"]:
            with self.subTest(path=path):
                response = self.client.get("/api/v1" + path)
                self.assertEqual(response.status_code, 404)
                self.assert_private_absent(response)

    def test_database_rejects_cross_organization_links(self):
        other = Organization.objects.create(code="OTHER-ORG", name="Another fictional organization")
        with self.assertRaises(DatabaseError), transaction.atomic():
            ChannelMember.objects.create(organization=other, user=self.recipient, channel=self.channel)

    def test_database_return_reject_bind_policy_and_current_scope(self):
        _, _, variant, review = self.candidate()
        for field, value in [("policy_version", "changed-policy"), ("policy_hash", "0" * 64), ("channel_ids", [str(uuid.uuid4())])]:
            changed = copy.deepcopy(review["binding"]); changed[field] = value
            with self.subTest(field=field), self.assertRaises(DatabaseError) as failure, transaction.atomic():
                ReportVariant.objects.filter(pk=variant.id).update(state="RETURNED")
                ReviewDecision.objects.create(organization=self.org, variant=variant, reviewer=self.reviewer, operation_id=uuid.uuid4(),
                                              request_hash="0" * 64, action="RETURN", binding=changed,
                                              reason_ciphertext=encrypt("A fictional correction is requested."), response_body={})
            self.assertEqual(getattr(failure.exception.__cause__, "sqlstate", None), "23514")
        self.assertFalse(ReviewDecision.objects.exists())

    def test_database_receipt_guard_rejects_unexpected_keys_and_revision_number(self):
        self.sign_in("submitter"); _, response = self.submit(); self.assertEqual(response.status_code, 201)
        receipt = SyncReceipt.objects.get()
        for changed in [{**receipt.response_body, "revision_no": 99}, {**receipt.response_body, "narrative": "PRIVATE_RECEIPT_CANARY"}]:
            with self.subTest(keys=list(changed)), self.assertRaises(DatabaseError) as failure, transaction.atomic():
                # Guard fires before uniqueness; assert its check violation,
                # rather than accepting a coincidental duplicate-key failure.
                SyncReceipt.objects.create(organization=self.org, accepted_user=self.submitter, operation_id=receipt.operation_id,
                                           request_hash=receipt.request_hash, revision=receipt.revision, response_body=changed)
            self.assertEqual(getattr(failure.exception.__cause__, "sqlstate", None), "23514")

    def test_error_unknown_filter_and_audit_are_metadata_only(self):
        body, _, _, _, _, _ = self.approve()
        self.sign_in("recipient")
        response = self.client.get(f"/api/v1/channels/{self.channel.id}/feed/?search=PRIVATE_QUERY_CANARY")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("PRIVATE_", response.content.decode())
        self.client.get(f"/api/v1/reports/{body['report_id']}/revisions/1/")
        events = list(AuditEvent.objects.values("action", "safe_metadata"))
        self.assertIn("ACCESS_DENIED", [event["action"] for event in events])
        self.assertNotIn("PRIVATE_", json.dumps(events))

    def test_worker_reclaimed_lease_cannot_commit_old_result_or_duplicate(self):
        self.sign_in("submitter"); _, response = self.submit(); self.assertEqual(response.status_code, 201)
        old = claim_job(); projection = transform_job(old)
        ProcessingJob.objects.filter(pk=old["id"]).update(lease_until=timezone.now() - timedelta(seconds=1))
        new = claim_job()
        self.assertNotEqual(new["token"], old["token"])
        self.assertFalse(finish_job(old, projection))
        self.assertTrue(finish_job(new, projection))
        self.assertFalse(finish_job(new, projection))
        self.assertEqual(ReportVariant.objects.count(), 1)
        self.assertFalse(Publication.objects.exists())

    def test_worker_failure_and_poison_attempt_limit_never_publish(self):
        self.sign_in("submitter"); _, response = self.submit(); self.assertEqual(response.status_code, 201)
        with patch("apps.operations.worker.transform_job", side_effect=ValueError("PRIVATE_EXCEPTION_CANARY")):
            self.assertTrue(process_one())
        job = ProcessingJob.objects.get()
        self.assertEqual(job.status, "FAILED")
        self.assertEqual(job.error_code, "RULE_PROCESSING_FAILED")
        self.assertFalse(ReportVariant.objects.exists())
        _, response = self.submit(); self.assertEqual(response.status_code, 201)
        ProcessingJob.objects.filter(status="PENDING").update(status="PROCESSING", attempts=3, lease_until=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(claim_job())
        self.assertEqual(ProcessingJob.objects.filter(status="FAILED").count(), 2)
        self.assertFalse(Publication.objects.exists())
        self.assertNotIn("PRIVATE_", json.dumps(list(AuditEvent.objects.values_list("safe_metadata", flat=True))))

    def test_seed_is_repeatable_and_never_generates_approval(self):
        call_command("seed_demo", verbosity=0)
        self.assertEqual(get_user_model().objects.count(), 4)
        self.assertFalse(Report.objects.exists())
        self.assertFalse(ReviewDecision.objects.exists())
        self.assertFalse(Publication.objects.exists())

    def test_seed_preserves_existing_password_and_never_reactivates_revoked_grant(self):
        original_hash = self.submitter.password
        call_command("seed_demo", verbosity=0)
        self.submitter.refresh_from_db()
        self.assertEqual(self.submitter.password, original_hash)
        ChannelMember.objects.filter(user=self.recipient).update(active=False)
        call_command("seed_demo", verbosity=0)
        self.assertFalse(ChannelMember.objects.get(user=self.recipient).active)
        self.assertFalse(ReviewDecision.objects.exists())
