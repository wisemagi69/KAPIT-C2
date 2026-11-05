"""Real PostgreSQL integration tests for the approved website expansion."""
import copy
import uuid
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError, transaction
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.services import update_user
from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.operations.worker import process_one
from apps.publications.models import Publication
from apps.reports.crypto import source_payload
from apps.reports.models import Report, ReportRevision, ReportVariant
from apps.review.models import ReviewDecision
from apps.scopes.access import lock_identity
from apps.scopes.models import ChannelMember, ChannelSource, Organization, SharingChannel, Unit, UnitMembership

from . import test_workflow as workflow


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class WebsiteExtensionTests(TestCase):
    setUp = workflow.WorkflowTests.setUp
    sign_in = workflow.WorkflowTests.sign_in
    submit = workflow.WorkflowTests.submit
    candidate = workflow.WorkflowTests.candidate
    decision = workflow.WorkflowTests.decision
    assert_private_absent = workflow.WorkflowTests.assert_private_absent

    def returned(self):
        body, receipt, variant, review = self.candidate()
        _, response = self.decision(variant, review, "RETURN", "Correct this fictional source.")
        self.assertEqual(response.status_code, 200, response.content)
        self.sign_in("submitter")
        return body, receipt, variant

    def correction(self, original):
        body = copy.deepcopy(original)
        body.update(operation_id=str(uuid.uuid4()), expected_revision=1,
                    correction_reason="Correct the fictional maintenance category after review.")
        body["payload"]["category"] = "INFRASTRUCTURE"
        return body

    def admin_request(self, method, path, body):
        return getattr(self.client, method)("/api/v1/administration/" + path, body, format="json", HTTP_X_CSRFTOKEN=self.token)

    def new_user_body(self, **overrides):
        return {"username": "new-fictional-user", "display_name": "New Fictional User", "role": "submitter", "is_active": True,
                "unit_id": str(self.unit.id), "channel_id": str(self.channel.id), "password": "FictionalRiver!Access2026", **overrides}

    def test_correction_retains_original_receipt_and_requires_new_human_review(self):
        original, receipt, old_variant = self.returned()
        revision1 = ReportRevision.objects.get()
        encrypted_original = bytes(revision1.payload_ciphertext)
        detail_url = f"/api/v1/reports/{original['report_id']}/revisions/1/"
        self.assertTrue(self.client.get(detail_url).json()["can_correct"])
        corrected = self.correction(original)
        _, response = self.submit(corrected)
        self.assertEqual(response.status_code, 201, response.content)
        self.assertEqual(response.json()["revision_no"], 2)
        _, replay = self.submit(corrected)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), response.json())
        self.assertEqual(Report.objects.count(), 1)
        self.assertEqual(ReportRevision.objects.count(), 2)
        self.assertEqual(SyncReceipt.objects.count(), 2)
        self.assertEqual(ProcessingJob.objects.count(), 2)
        revision1.refresh_from_db()
        self.assertEqual(bytes(revision1.payload_ciphertext), encrypted_original)
        historical = self.client.get(detail_url).json()
        self.assertEqual(historical["payload"], original["payload"])
        self.assertEqual(historical["receipt"], receipt)
        self.assertFalse(historical["can_correct"])
        self.assertEqual([(x["revision_no"], x["status"]) for x in historical["history"]], [(2, "PENDING"), (1, "RETURNED")])
        self.assertEqual(self.client.get("/api/v1/reports/?status=RETURNED").json()["count"], 0)
        self.assertEqual(self.client.get("/api/v1/reports/?status=PENDING").json()["count"], 1)
        self.sign_in("reviewer")
        self.assertEqual(self.client.get("/api/v1/review/queue/").json()["count"], 0)
        self.assertTrue(process_one())
        queue = self.client.get("/api/v1/review/queue/").json()
        self.assertEqual(queue["results"][0]["revision_no"], 2)
        new_variant = ReportVariant.objects.get(revision__revision_no=2)
        review = self.client.get(f"/api/v1/variants/{new_variant.id}/review/").json()
        self.assertNotEqual(new_variant.candidate_hash, old_variant.candidate_hash)
        self.assertFalse(Publication.objects.exists())
        _, approved = self.decision(new_variant, review)
        self.assertEqual(approved.status_code, 200, approved.content)
        self.assertEqual(ReviewDecision.objects.count(), 2)
        self.sign_in("recipient")
        feed = self.client.get(f"/api/v1/channels/{self.channel.id}/feed/")
        self.assertEqual(len(feed.json()["results"]), 1)
        self.assert_private_absent(feed)
        self.assertEqual(self.client.get(detail_url).status_code, 404)

    def test_correction_rejects_changed_replay_stale_revision_and_unreturned_source(self):
        original, _, _ = self.returned()
        corrected = self.correction(original)
        _, accepted = self.submit(corrected)
        self.assertEqual(accepted.status_code, 201)
        changed = copy.deepcopy(corrected)
        changed["payload"]["category"] = "EQUIPMENT"
        _, conflict = self.submit(changed)
        self.assertEqual(conflict.json()["code"], "IDEMPOTENCY_CONFLICT")
        stale = copy.deepcopy(corrected); stale["operation_id"] = str(uuid.uuid4())
        _, conflict = self.submit(stale)
        self.assertEqual(conflict.json()["code"], "REVISION_CONFLICT")
        unreturned = copy.deepcopy(stale); unreturned["expected_revision"] = 2
        _, conflict = self.submit(unreturned)
        self.assertEqual(conflict.json()["code"], "CORRECTION_UNAVAILABLE")
        self.assertEqual(ReportRevision.objects.count(), 2)

    def test_correction_denies_another_author_and_revoked_authority_and_rolls_back_audit_failure(self):
        original, _, _ = self.returned()
        other = get_user_model().objects.create_user(username="another-author", password="unused", organization=self.org, display_name="Fictional", role="submitter")
        UnitMembership.objects.create(organization=self.org, user=other, unit=self.unit, role="submitter")
        self.client.force_authenticate(other)
        _, denied = self.submit(self.correction(original))
        self.assertEqual(denied.status_code, 404)
        self.client.force_authenticate(None)
        self.sign_in("submitter")
        with patch("apps.reports.services.audit.record", side_effect=RuntimeError("synthetic audit failure")):
            _, failed = self.submit(self.correction(original))
        self.assertEqual(failed.status_code, 500)
        self.assertEqual(Report.objects.get().current_revision_no, 1)
        self.assertEqual(ReportRevision.objects.count(), 1)
        UnitMembership.objects.filter(user=self.submitter).update(active=False)
        self.assertEqual(self.client.get(f"/api/v1/reports/{original['report_id']}/revisions/1/").status_code, 404)
        _, denied = self.submit(self.correction(original))
        self.assertEqual(denied.status_code, 403)

    def test_return_without_a_committed_decision_never_allows_correction(self):
        original, _, variant, _ = self.candidate()
        ReportVariant.objects.filter(pk=variant.pk).update(state="RETURNED")
        self.sign_in("submitter")
        detail = self.client.get(f"/api/v1/reports/{original['report_id']}/revisions/1/")
        self.assertFalse(detail.json()["can_correct"])
        _, denied = self.submit(self.correction(original))
        self.assertEqual(denied.json()["code"], "CORRECTION_UNAVAILABLE")

    def test_scoped_pagination_decrypts_only_requested_page_and_uses_current_states(self):
        self.sign_in("submitter")
        for _ in range(12):
            _, response = self.submit(); self.assertEqual(response.status_code, 201)
        other = get_user_model().objects.create_user(username="other-author", password="unused", organization=self.org, display_name="Fictional", role="submitter")
        UnitMembership.objects.create(organization=self.org, user=other, unit=self.unit, role="submitter")
        self.client.force_authenticate(other)
        _, response = self.submit(); self.assertEqual(response.status_code, 201)
        self.client.force_authenticate(None); self.sign_in("submitter")
        with patch("apps.reports.selectors.source_payload", wraps=source_payload) as decrypt:
            page = self.client.get("/api/v1/reports/?page=2&page_size=5&status=PENDING").json()
        self.assertEqual((page["count"], page["page"], page["page_size"], page["total_pages"]), (12, 2, 5, 3))
        self.assertEqual(decrypt.call_count, 5)
        ordered = list(Report.objects.filter(author=self.submitter).order_by("-created_at", "-id").values_list("id", flat=True))
        self.assertEqual([row["id"] for row in page["results"]], [str(value) for value in ordered[5:10]])
        self.assertEqual(self.client.get("/api/v1/reports/?page=4&page_size=5").json()["results"], [])
        self.sign_in("reviewer")
        self.assertEqual(self.client.get("/api/v1/review/queue/").json()["count"], 0)
        self.assertEqual(self.client.get("/api/v1/review/queue/?status=ALL").json()["count"], 13)
        UnitMembership.objects.filter(user=self.reviewer).update(active=False)
        self.assertEqual(self.client.get("/api/v1/review/queue/?status=ALL").json()["count"], 0)

    def test_report_creation_dates_include_utc_edges_and_reject_ambiguous_queries(self):
        self.sign_in("submitter")
        day = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=2)
        for stamp in [day - timedelta(microseconds=1), day, day + timedelta(days=1) - timedelta(microseconds=1), day + timedelta(days=1)]:
            body = workflow.operation(); body["payload"]["observed_at"] = (day - timedelta(days=1)).isoformat()
            with patch("django.utils.timezone.now", return_value=stamp):
                _, response = self.submit(body)
            self.assertEqual(response.status_code, 201, response.content)
        response = self.client.get(f"/api/v1/reports/?date_from={day.date()}&date_to={day.date()}")
        self.assertEqual(response.json()["count"], 2)
        for query in ["page=1&page=2", "page=0", "page=true", "page_size=51", "status=unknown", "status=ALL&status=PENDING",
                      "date_from=2026-02-30", "date_from=2026-2-01", "date_from=2026-02-02&date_to=2026-02-01", "q=PRIVATE_CANARY"]:
            with self.subTest(query=query):
                response = self.client.get("/api/v1/reports/?" + query)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn("PRIVATE_", response.content.decode())

    def test_admin_role_is_separate_from_staff_and_has_no_source_or_review_access(self):
        body, _, _, _ = self.candidate()
        for role in ["submitter", "reviewer", "recipient"]:
            user = get_user_model().objects.get(username=role)
            user.is_staff = user.is_superuser = True; user.save(update_fields=["is_staff", "is_superuser"])
            self.sign_in(role)
            for url in ["context/", "users/"]:
                self.assertEqual(self.client.get("/api/v1/administration/" + url).status_code, 403)
        session_user = self.sign_in("administrator")
        self.assertIsNone(session_user["unit"]); self.assertIsNone(session_user["channel"])
        self.assertEqual(self.client.get("/api/v1/reports/").status_code, 403)
        self.assertEqual(self.client.get("/api/v1/review/queue/").status_code, 403)
        self.assertEqual(self.client.get(f"/api/v1/reports/{body['report_id']}/revisions/1/").status_code, 404)

    def test_admin_create_search_context_and_safe_projection(self):
        self.sign_in("administrator")
        other_org = Organization.objects.create(code="FOREIGN", name="Other fictional organization")
        Unit.objects.create(organization=other_org, code="OTHER", name="Other unit")
        get_user_model().objects.create_user(username="foreign-account", password="unused", organization=other_org, display_name="Foreign", role="administrator")
        context = self.client.get("/api/v1/administration/context/").json()
        self.assertEqual([row["id"] for row in context["units"]], [str(self.unit.id)])
        for role in ["submitter", "reviewer", "recipient", "administrator"]:
            body = self.new_user_body(username="created-" + role, role=role,
                                     unit_id=str(self.unit.id) if role in {"submitter", "reviewer"} else None,
                                     channel_id=None if role == "administrator" else str(self.channel.id))
            created = self.admin_request("post", "users/", body)
            self.assertEqual(created.status_code, 201, created.content)
            self.assertEqual(set(created.json()), {"id", "username", "display_name", "role", "is_active", "permission_version", "unit_id", "channel_id"})
            self.assertNotIn(body["password"], created.content.decode())
        page = self.client.get("/api/v1/administration/users/?q=created-&page=2&page_size=2&active=true").json()
        self.assertEqual((page["count"], len(page["results"]), page["total_pages"]), (4, 2, 2))
        self.assertEqual(self.client.get("/api/v1/administration/users/?role=recipient").json()["count"], 2)
        self.assertEqual(self.client.get("/api/v1/administration/users/?q=foreign-account").json()["count"], 0)

    def test_admin_rejects_cross_org_targets_assignments_unknown_fields_and_weak_passwords(self):
        self.sign_in("administrator")
        other = Organization.objects.create(code="FOREIGN", name="Other fictional organization")
        foreign = get_user_model().objects.create_user(username="foreign", password="unused", organization=other, display_name="Foreign", role="administrator")
        foreign_channel = SharingChannel.objects.create(organization=other, code="FOREIGN", name="Other channel")
        for target in [foreign.id, uuid.uuid4()]:
            response = self.admin_request("patch", f"users/{target}/", {"display_name": "Changed", "expected_permission_version": 0})
            self.assertEqual(response.status_code, 404)
        for extra in [{"channel_id": str(foreign_channel.id)}, {"role": "administrator"}, {"is_staff": True}, {"is_active": "true"}, {"password": "123456789012"}, {"password": "short"}, {"password": "new-fictional-user"}]:
            with self.subTest(fields=list(extra)):
                response = self.admin_request("post", "users/", self.new_user_body(**extra))
                self.assertEqual(response.status_code, 422, response.content)
        self.assertFalse(get_user_model().objects.filter(username="new-fictional-user").exists())
        for query in ["page=1&page=2", "role=staff", "active=yes", "q=x&q=y", "unsupported=x"]:
            self.assertEqual(self.client.get("/api/v1/administration/users/?" + query).status_code, 400)

    def test_admin_scope_projection_respects_expiry_inactive_units_and_channels(self):
        self.sign_in("administrator")
        def account(name):
            return self.client.get("/api/v1/administration/users/?q=" + name).json()["results"][0]
        UnitMembership.objects.filter(user=self.submitter).update(valid_until=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(account("submitter")["unit_id"])
        self.assertIsNone(account("submitter")["channel_id"])
        ChannelMember.objects.filter(user=self.recipient).update(valid_until=timezone.now() - timedelta(seconds=1))
        self.assertIsNone(account("recipient")["channel_id"])
        ChannelMember.objects.filter(user=self.recipient).update(valid_until=None)
        SharingChannel.objects.filter(pk=self.channel.pk).update(active=False)
        self.assertIsNone(account("recipient")["channel_id"])
        Unit.objects.filter(pk=self.unit.pk).update(active=False)
        self.assertIsNone(account("reviewer")["unit_id"])

    def test_admin_scope_changes_preserve_history_invalidate_session_and_reject_stale_writes(self):
        self.sign_in("submitter")
        previous_client = self.client
        self.client = APIClient(enforce_csrf_checks=True); self.client.raise_request_exception = False
        self.sign_in("administrator")
        changed = self.admin_request("patch", f"users/{self.submitter.id}/", {
            "role": "recipient", "unit_id": None, "channel_id": str(self.channel.id), "expected_permission_version": 0})
        self.assertEqual(changed.status_code, 200, changed.content)
        self.assertEqual(changed.json()["permission_version"], 1)
        self.assertEqual(previous_client.get("/api/v1/me/").status_code, 403)
        self.assertFalse(UnitMembership.objects.get(user=self.submitter).active)
        self.assertTrue(ChannelMember.objects.get(user=self.submitter).active)
        stale = self.admin_request("patch", f"users/{self.submitter.id}/", {"display_name": "Wrong", "expected_permission_version": 0})
        self.assertEqual(stale.json()["code"], "STALE_PERMISSIONS")
        restored = self.admin_request("patch", f"users/{self.submitter.id}/", {"role": "submitter", "unit_id": str(self.unit.id), "channel_id": str(self.channel.id), "expected_permission_version": 1})
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(UnitMembership.objects.filter(user=self.submitter).count(), 2)
        self.assertEqual(UnitMembership.objects.filter(user=self.submitter, active=True).count(), 1)
        self.assertFalse(ChannelMember.objects.get(user=self.submitter).active)
        self.assertIsNotNone(ChannelMember.objects.get(user=self.submitter).revoked_at)
        # Authentication may have loaded the old version before the org lock.
        with self.assertRaises(ApiError), transaction.atomic():
            lock_identity(self.submitter)

    def test_admin_password_reset_revokes_sessions_and_does_not_disclose_password_or_hash(self):
        self.sign_in("reviewer"); old_client = self.client
        self.client = APIClient(enforce_csrf_checks=True); self.client.raise_request_exception = False
        self.sign_in("administrator")
        password = "FictionalReset!River2026"
        response = self.admin_request("post", f"users/{self.reviewer.id}/password/", {"password": password, "expected_permission_version": 0})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(old_client.get("/api/v1/me/").status_code, 403)
        self.reviewer.refresh_from_db()
        self.assertTrue(self.reviewer.check_password(password))
        self.assertNotIn(password, response.content.decode())
        self.assertNotIn(self.reviewer.password, response.content.decode())
        self.assertNotIn(password, str(list(AuditEvent.objects.values_list("safe_metadata", flat=True))))
        stale = self.admin_request("post", f"users/{self.reviewer.id}/password/", {"password": password, "expected_permission_version": 0})
        self.assertEqual(stale.status_code, 409)

    def test_self_changes_are_denied_and_administration_audit_failure_rolls_back(self):
        self.sign_in("administrator")
        administrator = get_user_model().objects.get(username="administrator")
        self.assertEqual(self.admin_request("patch", f"users/{administrator.id}/", {"is_active": False, "expected_permission_version": 0}).status_code, 403)
        self.assertEqual(self.admin_request("post", f"users/{administrator.id}/password/", {"password": "FictionalReset!River2026", "expected_permission_version": 0}).status_code, 403)
        with patch("apps.accounts.services.audit.record", side_effect=RuntimeError("synthetic audit failure")):
            response = self.admin_request("patch", f"users/{self.submitter.id}/", {"is_active": False, "expected_permission_version": 0})
        self.assertEqual(response.status_code, 500)
        self.submitter.refresh_from_db()
        self.assertTrue(self.submitter.is_active)
        self.assertEqual(self.submitter.permission_version, 0)
        self.assertEqual(UnitMembership.objects.filter(user=self.submitter).count(), 1)
        with patch("apps.accounts.services.audit.record", side_effect=RuntimeError("synthetic audit failure")):
            response = self.admin_request("post", "users/", self.new_user_body())
        self.assertEqual(response.status_code, 500)
        self.assertFalse(get_user_model().objects.filter(username="new-fictional-user").exists())

    def test_seed_preserves_administered_accounts_and_historical_grants(self):
        administrator = get_user_model().objects.get(username="administrator")
        update_user(administrator, self.submitter.id, {"role": "recipient", "unit_id": None, "channel_id": self.channel.id, "expected_permission_version": 0})
        update_user(administrator, self.submitter.id, {"role": "submitter", "unit_id": self.unit.id, "channel_id": self.channel.id, "expected_permission_version": 1})
        update_user(administrator, self.submitter.id, {"is_active": False, "expected_permission_version": 2})
        before = list(UnitMembership.objects.filter(user=self.submitter).values())
        call_command("seed_demo", verbosity=0)
        self.submitter.refresh_from_db()
        self.assertFalse(self.submitter.is_active)
        self.assertEqual(self.submitter.permission_version, 3)
        self.assertEqual(before, list(UnitMembership.objects.filter(user=self.submitter).values()))
