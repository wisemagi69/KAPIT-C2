"""Real PostgreSQL two-person policy service tests, including atomic invalidation."""
import uuid
from contextlib import nullcontext
from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob
from apps.operations.serializers import OperationSerializer
from apps.operations.worker import process_one
from apps.publications.models import Publication, PublicationRemoval
from apps.reports.models import ReportRevision, ReportVariant
from apps.reports.services import accept_operation
from apps.review.services import decide
from apps.operations.worker import binding_for
from apps.scopes.models import AdminAuthority, Organization, PolicyActivation, PolicyProposal, PolicyVersion
from apps.scopes import policy
from apps.scopes.policy_views import PolicyApplyView, ProposalSerializer
from tests.test_workflow import operation


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3PolicyTests(TestCase):
    def setUp(self):
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        users = get_user_model()
        self.first = users.objects.get(username="administrator")
        self.second = users.objects.get(username="administrator2")
        self.submitter = users.objects.get(username="submitter")
        self.reviewer = users.objects.get(username="reviewer")
        self.org = Organization.objects.get(code="SIM-ORG-01")
        self.v1 = PolicyVersion.objects.get(organization=self.org, version="demo-policy-v1")
        self.v2 = PolicyVersion.objects.get(organization=self.org, version="demo-policy-v2")

    def proposal(self, kind="ACTIVATE", target=None, **overrides):
        self.org.refresh_from_db()
        target = target or self.v2
        body = {"operation_id": str(uuid.uuid4()), "kind": kind, "target_policy_id": str(target.id),
                "target_rules_hash": target.rules_hash,
                "expected_active_policy_id": str(self.org.active_policy_id) if self.org.active_policy_id else None,
                **overrides}
        serializer = ProposalSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        return body, serializer.validated_data

    def make_proposal(self, **kwargs):
        body, data = self.proposal(**kwargs)
        result, created = policy.propose(self.first, data, body)
        self.assertTrue(created)
        return result, body, data

    def source(self, user=None):
        body = operation()
        serializer = OperationSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        accept_operation(user or self.submitter, serializer.validated_data, body)
        self.assertTrue(process_one())
        return ReportRevision.objects.get(report_id=body["report_id"])

    def approve_legacy(self):
        revision = self.source()
        variant = ReportVariant.objects.get(revision=revision)
        body = {"operation_id": uuid.uuid4(), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        decide(self.reviewer, variant.id, body, {**body, "operation_id": str(body["operation_id"])})
        return revision

    def test_different_authority_applies_and_replay_never_advances_again(self):
        result, body, data = self.make_proposal()
        replay, created = policy.propose(self.first, data, body)
        self.assertEqual(replay, result)
        self.assertFalse(created)
        with self.assertRaises(ApiError) as caught:
            policy.apply(self.first, result["id"])
        self.assertEqual(caught.exception.safe_body["code"], "SELF_APPROVAL_DENIED")
        applied, created = policy.apply(self.second, result["id"])
        self.assertTrue(created)
        self.org.refresh_from_db()
        self.assertEqual((self.org.active_policy_id, self.org.policy_epoch), (self.v2.id, 1))
        self.assertEqual(PolicyVersion.objects.filter(organization=self.org, active=True).count(), 1)
        replay, created = policy.apply(self.second, result["id"])
        self.assertEqual(replay, applied)
        self.assertFalse(created)
        self.org.refresh_from_db()
        self.assertEqual(self.org.policy_epoch, 1)

    def test_no_authority_role_and_revoked_authority_are_denied(self):
        result, body, data = self.make_proposal()
        for actor in (self.submitter, self.reviewer):
            with self.subTest(actor=actor.role), self.assertRaises(ApiError):
                policy.state(actor)
            with self.assertRaises(ApiError):
                policy.propose(actor, data, body)
            with self.assertRaises(ApiError):
                policy.apply(actor, result["id"])
        AdminAuthority.objects.filter(user=self.second, kind="POLICY").update(active=False)
        with self.assertRaises(ApiError):
            policy.apply(self.second, result["id"])
        self.assertFalse(PolicyActivation.objects.exists())

    def test_expiry_pointer_hash_and_proposer_version_are_rechecked(self):
        for fault in ("expired", "pointer", "hash", "permission", "authority"):
            with self.subTest(fault=fault):
                result, _, _ = self.make_proposal()
                row = PolicyProposal.objects.get(pk=result["id"])
                if fault == "permission":
                    get_user_model().objects.filter(pk=self.first.id).update(permission_version=1)
                elif fault == "authority":
                    AdminAuthority.objects.filter(user=self.first, kind="POLICY").update(active=False)
                clock = patch("apps.scopes.policy.timezone.now", return_value=row.expires_at + timedelta(seconds=1)) if fault == "expired" else patch("apps.scopes.policy.supported", return_value=False) if fault == "hash" else nullcontext()
                if fault == "pointer":
                    Organization.objects.filter(pk=self.org.pk).update(active_policy=None)
                with clock, self.assertRaises(ApiError) as caught:
                    policy.apply(self.second, row.id)
                self.assertEqual(caught.exception.safe_body["code"], "STALE_POLICY")
                self.assertFalse(PolicyActivation.objects.exists())
                # Direct test-only administrative faults are reset for the next case.
                Organization.objects.filter(pk=self.org.pk).update(active_policy=self.v1)
                get_user_model().objects.filter(pk=self.first.id).update(permission_version=0)
                AdminAuthority.objects.filter(user=self.first, kind="POLICY").update(active=True)

    def test_policy_removes_legacy_outputs_regenerates_and_never_revives(self):
        revision = self.approve_legacy()
        old = Publication.objects.get(report=revision.report)
        result, _, _ = self.make_proposal()
        policy.apply(self.second, result["id"])
        old.refresh_from_db()
        self.assertIsNotNone(old.revoked_at)
        self.assertTrue(PublicationRemoval.objects.filter(publication=old, cause="POLICY").exists())
        self.assertEqual(ProcessingJob.objects.filter(revision=revision, policy=self.v2, policy_epoch=1, status="PENDING").count(), 1)
        self.assertTrue(process_one())
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())
        result, _, _ = self.make_proposal(target=self.v1)
        policy.apply(self.second, result["id"])
        self.org.refresh_from_db()
        self.assertEqual(self.org.policy_epoch, 2)
        self.assertTrue(PublicationRemoval.objects.filter(publication=old).exists())
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())

    def test_deactivation_closes_sharing_skips_regeneration_and_seed_preserves_it(self):
        revision = self.approve_legacy()
        count = ProcessingJob.objects.count()
        result, _, _ = self.make_proposal(kind="DEACTIVATE", target=self.v1)
        policy.apply(self.second, result["id"])
        self.org.refresh_from_db()
        self.assertIsNone(self.org.active_policy_id)
        self.assertEqual(ProcessingJob.objects.count(), count)
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())
        call_command("seed_demo", verbosity=0)
        self.org.refresh_from_db()
        self.assertIsNone(self.org.active_policy_id)
        self.assertFalse(PolicyVersion.objects.filter(organization=self.org, active=True).exists())
        self.assertIsNotNone(ReportRevision.objects.get(pk=revision.pk))

    def test_audit_failure_rolls_back_proposal_and_all_apply_effects(self):
        body, data = self.proposal()
        with patch("apps.scopes.policy.audit.record", side_effect=RuntimeError("synthetic audit fault")), self.assertRaises(RuntimeError):
            policy.propose(self.first, data, body)
        self.assertFalse(PolicyProposal.objects.exists())
        revision = self.approve_legacy()
        result, _, _ = self.make_proposal()
        events = AuditEvent.objects.count()
        with patch("apps.scopes.policy.audit.record", side_effect=RuntimeError("synthetic audit fault")), self.assertRaises(RuntimeError):
            policy.apply(self.second, result["id"])
        self.org.refresh_from_db()
        self.assertEqual((self.org.active_policy_id, self.org.policy_epoch), (self.v1.id, 0))
        self.assertFalse(PolicyActivation.objects.exists())
        self.assertFalse(PublicationRemoval.objects.exists())
        self.assertEqual(AuditEvent.objects.count(), events)
        self.assertTrue(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())

    def test_operation_conflict_and_private_state(self):
        result, body, data = self.make_proposal()
        with self.assertRaises(ApiError) as caught:
            policy.propose(self.first, data, {**body, "kind": "DEACTIVATE"})
        self.assertEqual(caught.exception.safe_body["code"], "IDEMPOTENCY_CONFLICT")
        current = policy.state(self.second)
        self.assertEqual(current["proposals"][0]["id"], result["id"])
        self.assertFalse(current["proposals"][0]["applied"])
        self.assertEqual({p["version"] for p in current["policies"]}, {"demo-policy-v1", "demo-policy-v2"})

    def test_pending_proposal_cannot_revive_after_pointer_cycles_back(self):
        old, _, _ = self.make_proposal()
        change, _, _ = self.make_proposal()
        policy.apply(self.second, change["id"])
        back, _, _ = self.make_proposal(target=self.v1)
        policy.apply(self.second, back["id"])
        with self.assertRaises(ApiError) as caught:
            policy.apply(self.second, old["id"])
        self.assertEqual(caught.exception.safe_body["code"], "STALE_POLICY")
        self.org.refresh_from_db()
        self.assertEqual((self.org.active_policy_id, self.org.policy_epoch), (self.v1.id, 2))

    def test_denial_view_records_only_allowlisted_fixed_metadata(self):
        result, _, _ = self.make_proposal()
        request = APIRequestFactory().post("/administration/policy/proposals/apply/", {}, format="json")
        # Identity injection isolates business authority; session authentication has its own gates.
        force_authenticate(request, user=self.first)
        response = PolicyApplyView.as_view()(request, proposal_id=result["id"])
        self.assertEqual(response.status_code, 403)
        event = AuditEvent.objects.get(action="POLICY_DENIED")
        self.assertEqual(event.outcome, "DENIED")
        self.assertEqual(event.safe_metadata, {"error_code": "SELF_APPROVAL_DENIED"})
        self.assertIsNone(event.target_id)
        self.assertFalse(PolicyActivation.objects.exists())
