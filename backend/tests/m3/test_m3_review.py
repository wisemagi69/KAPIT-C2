"""PostgreSQL complete-set review tests; parent owns execution reservation."""
import copy
import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError, connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from apps.operations.errors import ApiError
from apps.operations.serializers import BatchDecisionSerializer
from apps.operations.worker import binding_for, process_one
from apps.publications.models import Publication, PublicationRemoval, RevisionWithdrawal
from apps.publications.services import withdraw_report
from apps.reports.models import ReportRevision
from apps.reports.services import accept_operation
from apps.review.models import DecisionBatch, ReviewDecision
from apps.review.services import candidate_set, decide, decide_batch
from apps.scopes.models import Organization, PolicyVersion, UnitMembership
from tests.test_workflow import operation


SETTINGS = {"KAPIT_SOURCE_KEY": Fernet.generate_key(), "PASSWORD_HASHERS": ["django.contrib.auth.hashers.MD5PasswordHasher"]}


class BatchSerializerTests(SimpleTestCase):
    def body(self):
        return {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "approve_profiles": ["DEMO-REDUCED"], "reason": None,
            "expected": {"revision_id": str(uuid.uuid4()), "revision_no": 1, "policy_version": "demo-policy-v1",
                "policy_hash": "a" * 64, "scope_context_hash": "b" * 64, "candidates": [{"variant_id": str(uuid.uuid4()),
                    "profile": "DEMO-REDUCED", "candidate_hash": "c" * 64, "channel_ids": [str(uuid.uuid4())]}]}}

    def test_binding_bool_duplicates_and_hostile_choices_fail_with_fixed_errors(self):
        self.assertTrue(BatchDecisionSerializer(data=self.body()).is_valid())
        body = self.body()
        body["expected"]["revision_no"] = True
        self.assertFalse(BatchDecisionSerializer(data=body).is_valid())
        for place in ("action", "approve_profiles", "profile"):
            body = self.body()
            if place == "action":
                body["action"] = "PRIVATE_INPUT_CANARY"
            elif place == "approve_profiles":
                body[place] = ["PRIVATE_INPUT_CANARY"]
            else:
                body["expected"]["candidates"][0]["profile"] = "PRIVATE_INPUT_CANARY"
            serializer = BatchDecisionSerializer(data=body)
            self.assertFalse(serializer.is_valid())
            self.assertNotIn("PRIVATE_INPUT_CANARY", str(serializer.errors))
        body = self.body()
        body["expected"]["candidates"][0]["channel_ids"] *= 2
        self.assertFalse(BatchDecisionSerializer(data=body).is_valid())

    def test_return_requires_reason_and_cannot_select_profiles(self):
        body = self.body()
        body.update(action="RETURN", approve_profiles=[], reason=" ")
        self.assertFalse(BatchDecisionSerializer(data=body).is_valid())
        body["reason"] = "Private synthetic reason"
        self.assertTrue(BatchDecisionSerializer(data=body).is_valid())


class ReviewFixture:
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        call_command("seed_m3_demo", verbosity=0)
        self.author = get_user_model().objects.get(username="submitter2")
        self.reviewer = get_user_model().objects.get(username="reviewer2")
        self.org = Organization.objects.get(pk=self.author.organization_id)
        self.client = APIClient()
        self.client.force_authenticate(user=self.reviewer)

    def submit_source(self, author=None):
        body = operation()
        receipt, _ = accept_operation(author or self.author, body, body)
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        for _ in range(20):
            if revision.variants.exists():
                break
            self.assertTrue(process_one())
        self.assertTrue(revision.variants.exists())
        return revision, body

    def batch_body(self, revision, action="APPROVE", profiles=None):
        binding = candidate_set(self.reviewer, revision.id)["binding"]
        return {"operation_id": str(uuid.uuid4()), "action": action,
            "approve_profiles": ([row["profile"] for row in binding["candidates"]] if profiles is None else profiles) if action == "APPROVE" else [],
            "expected": binding, "reason": None if action == "APPROVE" else "PRIVATE_DECISION_REASON_CANARY"}

    def batch(self, revision, body=None):
        body = body or self.batch_body(revision)
        serializer = BatchDecisionSerializer(data=body)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        return decide_batch(self.reviewer, revision.id, serializer.validated_data, body)

    def withdrawal_body(self, revision):
        return {"operation_id": str(uuid.uuid4()), "expected_revision_no": revision.revision_no, "reason": "PRIVATE_WITHDRAWAL_CANARY"}

    def activate_v2(self):
        from apps.reports.regeneration import invalidate_policy
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.id)
            PolicyVersion.objects.filter(organization=org, active=True).update(active=False)
            target = PolicyVersion.objects.get(organization=org, version="demo-policy-v2")
            target.active = True
            target.save(update_fields=["active"])
            org.active_policy = target
            org.save(update_fields=["active_policy"])
            invalidate_policy(org)


@override_settings(**SETTINGS)
class M3ReviewTests(ReviewFixture, TestCase):
    def test_complete_private_review_and_subset_atomic_withholding(self):
        revision, _ = self.submit_source()
        response = self.client.get(f"/api/v1/revisions/{revision.id}/candidates/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("PRIVATE_NARRATIVE_CANARY", response.json()["source"]["narrative"])
        self.assertEqual([row["profile"] for row in response.json()["binding"]["candidates"]], ["DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"])
        body = self.batch_body(revision, profiles=["DEMO-REDUCED"])
        result = self.batch(revision, body)
        self.assertEqual(result["approved_profiles"], ["DEMO-REDUCED"])
        self.assertEqual(set(result["withheld_profiles"]), {"DEMO-FULL", "DEMO-SUMMARY"})
        self.assertEqual(DecisionBatch.objects.count(), 1)
        self.assertEqual(ReviewDecision.objects.count(), 1)
        self.assertEqual(Publication.objects.filter(report=revision.report).count(), 1)
        for variant in revision.variants.all():
            if variant.profile == "DEMO-REDUCED":
                self.assertEqual(variant.state, "APPROVED")
                self.assertEqual(variant.decision.operation_id, uuid.uuid5(uuid.UUID(body["operation_id"]), str(variant.id)))
            else:
                self.assertEqual(variant.state, "REJECTED")
                self.assertFalse(ReviewDecision.objects.filter(variant=variant).exists())
        self.assertEqual(self.batch(revision, body), result)
        fresh = copy.deepcopy(body)
        fresh["operation_id"] = str(uuid.uuid4())
        with self.assertRaises(ApiError) as caught:
            self.batch(revision, fresh)
        self.assertEqual(caught.exception.safe_body["code"], "DECISION_CONFLICT")
        withheld = revision.variants.get(profile="DEMO-FULL")
        approved = ReviewDecision.objects.get()
        with self.assertRaises(DatabaseError), transaction.atomic():
            Publication.objects.create(organization=self.org, report=revision.report, variant=withheld, decision=approved,
                channel_id=withheld.channel_ids[0], profile=withheld.profile, projection=withheld.projection)

    def test_every_binding_dimension_and_incomplete_set_fail_without_partial_decision(self):
        revision, _ = self.submit_source()
        original = self.batch_body(revision)
        edits = [lambda b: b.update(revision_id=str(uuid.uuid4())), lambda b: b.update(revision_no=2),
            lambda b: b.update(policy_version="demo-policy-v2"), lambda b: b.update(policy_hash="0" * 64),
            lambda b: b.update(scope_context_hash="0" * 64), lambda b: b["candidates"].pop(),
            lambda b: b["candidates"][0].update(candidate_hash="0" * 64),
            lambda b: b["candidates"][0].update(variant_id=str(uuid.uuid4())),
            lambda b: b["candidates"][0].update(channel_ids=[str(uuid.uuid4())])]
        for edit in edits:
            body = copy.deepcopy(original)
            edit(body["expected"])
            with self.subTest(edit=edit), self.assertRaises(ApiError) as caught:
                self.batch(revision, body)
            self.assertEqual(caught.exception.safe_body["code"], "STALE_REVIEW")
        self.assertFalse(DecisionBatch.objects.exists())
        self.assertFalse(ReviewDecision.objects.exists())
        self.assertFalse(Publication.objects.exists())
        self.assertEqual(set(revision.variants.values_list("state", flat=True)), {"CANDIDATE"})

    def test_duplicate_subset_empty_approval_and_unknown_fields_rejected(self):
        revision, _ = self.submit_source()
        for profiles in ([], ["DEMO-FULL", "DEMO-FULL"]):
            body = self.batch_body(revision, profiles=profiles)
            self.assertFalse(BatchDecisionSerializer(data=body).is_valid())
        body = self.batch_body(revision)
        body["expected"]["candidates"].append(copy.deepcopy(body["expected"]["candidates"][0]))
        self.assertFalse(BatchDecisionSerializer(data=body).is_valid())
        body = self.batch_body(revision)
        body["PRIVATE_UNKNOWN_FIELD_CANARY"] = "ignored"
        serializer = BatchDecisionSerializer(data=body)
        self.assertFalse(serializer.is_valid())
        self.assertNotIn("PRIVATE_UNKNOWN", str(serializer.errors))

    def test_return_and_reject_cover_all_profiles_with_encrypted_reason(self):
        from apps.reports.crypto import decrypt
        for action in ("RETURN", "REJECT"):
            revision, _ = self.submit_source()
            result = self.batch(revision, self.batch_body(revision, action=action))
            batch = DecisionBatch.objects.get(pk=result["batch_id"])
            self.assertEqual(batch.decisions.count(), 3)
            self.assertEqual(decrypt(batch.reason_ciphertext), "PRIVATE_DECISION_REASON_CANARY")
            self.assertNotIn("PRIVATE_", str(result))
            self.assertFalse(Publication.objects.filter(report=revision.report).exists())

    def test_current_authority_and_self_review_refused_and_legacy_route_directed(self):
        revision, _ = self.submit_source()
        self.client.force_authenticate(user=get_user_model().objects.get(username="reviewer"))
        self.assertEqual(self.client.get(f"/api/v1/revisions/{revision.id}/candidates/").status_code, 404)
        self.client.force_authenticate(user=self.reviewer)
        variant = revision.variants.get(profile="DEMO-REDUCED")
        self.assertEqual(self.client.get(f"/api/v1/variants/{variant.id}/review/").json()["code"], "USE_CANDIDATE_SET")
        UnitMembership.objects.filter(user=self.reviewer).update(active=False)
        with self.assertRaises(ApiError):
            candidate_set(self.reviewer, revision.id)
        # A genuine author changed to reviewer still cannot self-review.
        user = get_user_model().objects.get(pk=self.author.id)
        user.role = "reviewer"
        user.save(update_fields=["role"])
        membership = UnitMembership.objects.get(user=user, active=True)
        membership.active = False
        membership.save(update_fields=["active"])
        UnitMembership.objects.create(organization=self.org, user=user, unit=membership.unit, role="reviewer")
        user.refresh_from_db()
        with self.assertRaises(ApiError) as caught:
            candidate_set(user, revision.id)
        self.assertEqual(caught.exception.safe_body["code"], "SELF_APPROVAL_DENIED")

    def test_batch_audit_failure_rolls_back_all_profiles_children_and_publications(self):
        revision, _ = self.submit_source()
        body = self.batch_body(revision)
        with patch("apps.review.services.audit.record", side_effect=RuntimeError("PRIVATE_AUDIT_CANARY")):
            with self.assertRaises(RuntimeError):
                self.batch(revision, body)
        self.assertFalse(DecisionBatch.objects.exists())
        self.assertFalse(ReviewDecision.objects.exists())
        self.assertFalse(Publication.objects.exists())
        self.assertEqual(set(revision.variants.values_list("state", flat=True)), {"CANDIDATE"})

    def test_legacy_v2_uses_current_rules_and_epoch_old_candidate_stays_denied(self):
        author = get_user_model().objects.get(username="submitter")
        reviewer = get_user_model().objects.get(username="reviewer")
        revision, _ = self.submit_source(author)
        old = revision.variants.get()
        self.activate_v2()
        from apps.review.services import verified_candidate
        self.org.refresh_from_db()
        with self.assertRaises(ApiError):
            verified_candidate(old, self.org)
        for _ in range(20):
            if revision.variants.filter(policy__version="demo-policy-v2").exists():
                break
            process_one()
        variant = revision.variants.get(policy__version="demo-policy-v2")
        self.assertIsNone(variant.scope_context_hash)
        verified_candidate(variant, self.org)
        data = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        result = decide(reviewer, variant.id, data, data)
        self.assertEqual(result["report_status"], "APPROVED")
