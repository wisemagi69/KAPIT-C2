"""Genuine Django/PostgreSQL coverage for the bounded M1 integration sprint."""
import copy
import json
import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.operations.models import ProcessingJob
from apps.operations.serializers import DecisionSerializer, OperationSerializer
from apps.operations.worker import binding_for, claim_job, finish_job, process_one, transform_job
from apps.publications.models import Publication
from apps.publications.selectors import candidate_digest
from apps.reports.models import Report, ReportRevision, ReportVariant
from apps.reports.services import accept_operation
from apps.review.services import decide
from apps.scopes.models import ChannelMember, ChannelSource, Organization, PolicyVersion, UnitMembership

from . import test_workflow as workflow


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class IntegrationSprintTests(TestCase):
    setUp = workflow.WorkflowTests.setUp
    sign_in = workflow.WorkflowTests.sign_in
    submit = workflow.WorkflowTests.submit
    candidate = workflow.WorkflowTests.candidate
    decision = workflow.WorkflowTests.decision
    approve = workflow.WorkflowTests.approve
    assert_private_absent = workflow.WorkflowTests.assert_private_absent

    def source(self, report_id, revision=1):
        return self.client.get(f"/api/v1/reports/{report_id}/revisions/{revision}/")

    def feed(self, query=""):
        return self.client.get(f"/api/v1/channels/{self.channel.id}/feed/" + query)

    def password(self, current="DemoMaintenance!2026", new="FictionalRiver!Changed2026", **extra):
        return self.client.post("/api/v1/auth/password/", {"current_password": current, "new_password": new, **extra},
                                format="json", HTTP_X_CSRFTOKEN=self.token)

    def login_client(self, client, username, password):
        token = client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        return client.post("/api/v1/auth/login/", {"username": username, "password": password},
                           format="json", HTTP_X_CSRFTOKEN=token)

    def publications(self, number):
        """Synthetic test-only transitions exercise real services and SQL guards."""
        fixed_time = timezone.now()
        for index in range(number):
            body = workflow.operation()
            body["payload"]["category"] = "WATER_SUPPLY" if index % 2 else "EQUIPMENT"
            body["payload"]["urgency"] = "PRIORITY" if index % 2 else "ROUTINE"
            serializer = OperationSerializer(data=body); serializer.is_valid(raise_exception=True)
            accept_operation(self.submitter, serializer.validated_data, body)
            self.assertTrue(process_one())
            variant = ReportVariant.objects.select_related("revision", "policy").get(revision__report_id=body["report_id"])
            request = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
            serializer = DecisionSerializer(data=request); serializer.is_valid(raise_exception=True)
            with patch("django.utils.timezone.now", return_value=fixed_time):
                decide(self.reviewer, variant.id, serializer.validated_data, request)

    def test_workflow_tracks_real_stages_without_rewriting_receipt(self):
        self.sign_in("submitter")
        body, accepted = self.submit()
        receipt = accepted.json()
        pending = self.source(body["report_id"]).json()
        progress = pending["workflow"]
        self.assertEqual(set(progress), {"revision_no", "is_current", "received_at", "processing", "review", "sharing"})
        self.assertEqual(progress["processing"], {"state": "PENDING", "attempts": 0})
        self.assertEqual(progress["review"], {"state": "NOT_READY", "prepared_at": None, "decided_at": None})
        self.assertEqual(progress["sharing"], {"state": "NOT_SHARED", "published_at": None})
        lease = claim_job()
        self.assertEqual(self.source(body["report_id"]).json()["workflow"]["processing"], {"state": "PROCESSING", "attempts": 1})
        self.assertTrue(finish_job(lease, transform_job(lease)))
        prepared = self.source(body["report_id"]).json()["workflow"]
        self.assertEqual(prepared["processing"]["state"], "DONE")
        self.assertEqual(prepared["review"]["state"], "AWAITING_REVIEW")
        self.assertIsNotNone(prepared["review"]["prepared_at"])
        self.assertIsNone(prepared["review"]["decided_at"])
        variant = ReportVariant.objects.get()
        self.sign_in("reviewer")
        review = self.client.get(f"/api/v1/variants/{variant.id}/review/").json()
        _, response = self.decision(variant, review)
        self.assertEqual(response.status_code, 200)
        complete = self.source(body["report_id"]).json()
        self.assertEqual(complete["receipt"], receipt)
        self.assertEqual(complete["workflow"]["review"]["state"], "APPROVED")
        self.assertIsNotNone(complete["workflow"]["review"]["decided_at"])
        self.assertEqual(complete["workflow"]["sharing"]["state"], "AVAILABLE")

    def test_workflow_availability_rechecks_policy_scope_revision_and_withdrawal(self):
        body, _, _, _, _, result = self.approve()
        initial = self.source(body["report_id"]).json()["workflow"]
        cases = [(Report.objects.filter(pk=body["report_id"]), {"current_revision_no": 2}, {"current_revision_no": 1}, "SUPERSEDED"),
                 (ChannelSource.objects.all(), {"active": False}, {"active": True}, "UNAVAILABLE"),
                 (PolicyVersion.objects.filter(pk=self.org.active_policy_id), {"active": False}, {"active": True}, "UNAVAILABLE")]
        for queryset, change, reset, expected in cases:
            queryset.update(**change)
            actual = self.source(body["report_id"]).json()["workflow"]
            self.assertEqual(actual["sharing"]["state"], expected)
            self.assertEqual(actual["sharing"]["published_at"], initial["sharing"]["published_at"])
            self.assertEqual(actual["review"], initial["review"])
            queryset.update(**reset)
        Publication.objects.filter(pk=result["publication_ids"][0]).update(revoked_at=timezone.now())
        self.assertEqual(self.source(body["report_id"]).json()["workflow"]["sharing"]["state"], "WITHDRAWN")

    def test_workflow_preserves_returned_revision_when_correction_is_pending(self):
        body, _, variant, review = self.candidate()
        _, result = self.decision(variant, review, "RETURN", "Please correct the fictional issue.")
        self.assertEqual(result.status_code, 200)
        self.sign_in("submitter")
        corrected = copy.deepcopy(body)
        corrected.update(operation_id=str(uuid.uuid4()), expected_revision=1,
                         correction_reason="Correct the fictional issue after reviewer feedback.")
        _, accepted = self.submit(corrected)
        self.assertEqual(accepted.status_code, 201)
        old = self.source(body["report_id"]).json()["workflow"]
        new = self.source(body["report_id"], 2).json()["workflow"]
        self.assertFalse(old["is_current"])
        self.assertEqual(old["review"]["state"], "RETURNED")
        self.assertEqual(old["sharing"]["state"], "NOT_SHARED")
        self.assertTrue(new["is_current"])
        self.assertEqual(new["processing"], {"state": "PENDING", "attempts": 0})
        self.assertEqual(new["review"]["state"], "NOT_READY")

    def test_inconsistent_processing_never_claims_approved_publication_available(self):
        body, _, variant, _, _, result = self.approve()
        initial = self.source(body["report_id"]).json()["workflow"]
        for queryset, change, reset in [
            (ProcessingJob.objects.filter(pk=variant.job_id), {"status": "FAILED"}, {"status": "DONE"}),
            (ReportRevision.objects.filter(pk=variant.revision_id), {"processing_state": "FAILED"}, {"processing_state": "AWAITING_REVIEW"}),
        ]:
            queryset.update(**change)
            actual = self.source(body["report_id"]).json()["workflow"]
            self.assertEqual(actual["review"], initial["review"])
            self.assertEqual(actual["sharing"]["state"], "UNAVAILABLE")
            self.sign_in("recipient")
            self.assertEqual(self.feed().json()["count"], 0)
            self.assertEqual(self.client.get(f"/api/v1/publications/{result['publication_ids'][0]}/").status_code, 404)
            self.sign_in("reviewer")
            queryset.update(**reset)

    def test_failed_workflow_has_only_safe_metadata_and_remains_private(self):
        self.sign_in("submitter")
        body, _ = self.submit()
        with patch("apps.operations.worker.transform_job", side_effect=ValueError("PRIVATE_FAILURE_CANARY")):
            self.assertTrue(process_one())
        progress = self.source(body["report_id"]).json()["workflow"]
        self.assertEqual(progress["processing"], {"state": "FAILED", "attempts": 1})
        self.assertEqual(progress["sharing"]["state"], "NOT_SHARED")
        for forbidden in ["PRIVATE_", "error_code", "lease", "actor", "reviewer", "operation_id"]:
            self.assertNotIn(forbidden, json.dumps(progress))
        for role in ["recipient", "administrator"]:
            self.sign_in(role)
            denied = self.source(body["report_id"])
            unknown = self.source(uuid.uuid4())
            self.assertEqual(denied.status_code, 404)
            self.assertEqual(denied.json(), unknown.json())
            self.assertNotIn("workflow", denied.json())

    def test_feed_reaches_record_101_with_stable_order_and_complete_count(self):
        self.publications(101)
        self.sign_in("recipient")
        response = self.feed("?page=11&page_size=10")
        self.assertEqual(response.status_code, 200, response.content)
        page = response.json()
        self.assertEqual((page["count"], page["page"], page["page_size"], page["total_pages"]), (101, 11, 10, 11))
        ordered = list(Publication.objects.order_by("-published_at", "-id").values_list("id", flat=True))
        self.assertEqual([row["id"] for row in page["results"]], [str(ordered[100])])
        self.assert_private_absent(response)

    def test_feed_filters_search_only_approved_projection_and_exclude_invalid_bindings_before_count(self):
        self.publications(5)
        invalid = Publication.objects.order_by("-published_at", "-id").first()
        def corrupt_hash(*args, **kwargs):
            if args[1] == invalid.variant.revision_id:
                return "0" * 64
            return candidate_digest(*args, **kwargs)
        self.sign_in("recipient")
        with patch("apps.publications.selectors.candidate_digest", side_effect=corrupt_hash):
            response = self.feed("?page_size=2")
            page = response.json()
            self.assertEqual((page["count"], len(page["results"]), page["total_pages"]), (4, 2, 2))
            self.assertNotIn(str(invalid.id), [row["id"] for row in page["results"]])
            self.assertEqual(self.client.get(f"/api/v1/publications/{invalid.id}/").status_code, 404)
        filtered = self.feed("?category=WATER_SUPPLY&urgency=PRIORITY&q=REPAIR").json()
        self.assertEqual(filtered["count"], 2)
        self.assertTrue(all(row["projection"]["category"] == "WATER_SUPPLY" for row in filtered["results"]))
        for query in ["PRIVATE_NARRATIVE_CANARY", "PRIVATE_SITE_CANARY", "PRIVATE_REPORTER_CANARY"]:
            response = self.feed("?q=" + query)
            self.assertEqual(response.json()["count"], 0)
            self.assertEqual(response.json()["total_pages"], 1)
            self.assert_private_absent(response)

    def test_feed_rejects_ambiguous_queries_and_rechecks_grant_on_later_pages(self):
        self.publications(2)
        self.sign_in("recipient")
        for query in ["page=0", "page_size=51", "page=1&page=2", "category=SECRET", "urgency=SECRET", "q=x&q=y", "q=" + "x" * 121, "source=PRIVATE_CANARY"]:
            response = self.feed("?" + query)
            self.assertEqual(response.status_code, 400, query)
            self.assert_private_absent(response)
        self.assertEqual(self.feed("?page_size=1").json()["count"], 2)
        ChannelMember.objects.filter(user=self.recipient).update(revoked_at=timezone.now())
        denied = self.feed("?page=2&page_size=1")
        unknown = self.client.get(f"/api/v1/channels/{uuid.uuid4()}/feed/?page=2&page_size=1")
        self.assertEqual(denied.status_code, 404)
        self.assertEqual(denied.json(), unknown.json())
        self.assertNotIn("count", denied.json())

    def test_all_roles_can_change_own_password_and_every_existing_session_ends(self):
        for role in ["submitter", "reviewer", "recipient", "administrator"]:
            with self.subTest(role=role):
                self.sign_in(role)
                user = get_user_model().objects.get(username=role)
                before = user.permission_version
                other = APIClient(enforce_csrf_checks=True)
                self.assertEqual(self.login_client(other, role, "DemoMaintenance!2026").status_code, 200)
                changed = self.password()
                self.assertEqual(changed.status_code, 200, changed.content)
                self.assertEqual(changed.json(), {"changed": True, "reauthenticate": True})
                self.assertEqual(self.client.get("/api/v1/me/").status_code, 403)
                self.assertEqual(other.get("/api/v1/me/").status_code, 403)
                user.refresh_from_db()
                self.assertEqual(user.permission_version, before + 1)
                self.assertEqual(self.login_client(other, role, "DemoMaintenance!2026").status_code, 401)
                self.assertEqual(self.login_client(other, role, "FictionalRiver!Changed2026").status_code, 200)
                self.assertEqual(AuditEvent.objects.filter(action="ACCOUNT_PASSWORD_CHANGED", actor=user).count(), 1)
        self.assertNotIn("FictionalRiver", json.dumps(list(AuditEvent.objects.values("safe_metadata"))))

    def test_password_change_requires_current_password_csrf_strict_fields_and_suitable_new_value(self):
        self.sign_in("administrator")
        actor = get_user_model().objects.get(username="administrator")
        before = actor.password
        self.assertEqual(self.password(current="WRONG_PRIVATE_PASSWORD").status_code, 400)
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 200)
        for new in ["DemoMaintenance!2026", "passwordpassword", "123456789012", "short"]:
            response = self.password(new=new)
            self.assertEqual(response.status_code, 422)
            self.assertNotIn(new, response.content.decode())
        for extra in [{"target_id": str(self.submitter.pk)}, {"role": "reviewer"}, {"session_id": "PRIVATE_CANARY"}]:
            self.assertEqual(self.password(**extra).status_code, 422)
        missing_csrf = self.client.post("/api/v1/auth/password/", {"current_password": "DemoMaintenance!2026", "new_password": "FictionalRiver!Changed2026"}, format="json")
        self.assertEqual(missing_csrf.status_code, 403)
        actor.refresh_from_db()
        self.assertEqual(actor.password, before)
        self.assertEqual(actor.permission_version, 0)
        self.assertFalse(AuditEvent.objects.filter(action="ACCOUNT_PASSWORD_CHANGED").exists())

    def test_password_audit_failure_rolls_back_and_revoked_context_cannot_change(self):
        self.sign_in("submitter")
        before = self.submitter.password
        with patch("apps.accounts.services.audit.record", side_effect=RuntimeError("PRIVATE_AUDIT_FAILURE")):
            response = self.password()
        self.assertEqual(response.status_code, 500)
        self.assertNotIn("PRIVATE_", response.content.decode())
        self.submitter.refresh_from_db()
        self.assertEqual(self.submitter.password, before)
        self.assertEqual(self.submitter.permission_version, 0)
        self.assertEqual(self.client.get("/api/v1/me/").status_code, 200)
        UnitMembership.objects.filter(user=self.submitter).update(active=False)
        self.assertEqual(self.password().status_code, 403)
        self.submitter.refresh_from_db()
        self.assertEqual(self.submitter.password, before)

    def test_self_password_route_preserves_whitespace_and_admin_self_edit_prohibition(self):
        self.sign_in("administrator")
        password = "  FictionalRiver!Changed2026  "
        actor = get_user_model().objects.get(username="administrator")
        self.assertEqual(self.password(new=password).status_code, 200)
        self.assertEqual(self.login_client(self.client, "administrator", password.strip()).status_code, 401)
        self.assertEqual(self.login_client(self.client, "administrator", password).status_code, 200)
        self.token = self.client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        denied = self.client.patch(f"/api/v1/administration/users/{actor.id}/", {"display_name": "Changed", "expected_permission_version": 1}, format="json", HTTP_X_CSRFTOKEN=self.token)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["code"], "SELF_ADMINISTRATION_DENIED")
