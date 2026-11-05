"""Durable withdrawal, historical replay and deterministic transaction ordering."""
from concurrent.futures import ThreadPoolExecutor
import copy
from threading import Event
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import close_old_connections, transaction
from django.test import TestCase, TransactionTestCase, override_settings

from apps.operations.errors import ApiError
from apps.publications.models import Publication, PublicationRemoval, RevisionWithdrawal
from apps.publications.services import withdraw_report
from apps.reports.models import ReportRevision
from apps.reports.regeneration import regenerate_units
from apps.reports.services import accept_operation
from apps.review.models import DecisionBatch
from apps.review.services import decide_batch
from apps.operations.serializers import BatchDecisionSerializer
from apps.scopes.models import Organization, UnitMembership
from .test_m3_review import ReviewFixture, SETTINGS


@override_settings(**SETTINGS)
class M3WithdrawalTests(ReviewFixture, TestCase):
    def test_withdrawal_removes_own_report_only_replay_never_revives(self):
        revision, _ = self.submit_source()
        original_body = self.batch_body(revision)
        approval = self.batch(revision, original_body)
        other, _ = self.submit_source()
        self.batch(other)
        body = self.withdrawal_body(revision)
        result = withdraw_report(self.reviewer, revision.report_id, body, body)
        self.assertEqual(withdraw_report(self.reviewer, revision.report_id, body, body), result)
        self.assertEqual(self.batch(revision, original_body), approval)
        self.assertEqual(RevisionWithdrawal.objects.filter(revision=revision).count(), 1)
        self.assertEqual(set(PublicationRemoval.objects.filter(publication__report=revision.report).values_list("cause", flat=True)), {"WITHDRAWAL"})
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())
        self.assertTrue(Publication.objects.filter(report=other.report, revoked_at__isnull=True).exists())
        changed = dict(body, reason="changed private request")
        with self.assertRaises(ApiError) as caught:
            withdraw_report(self.reviewer, revision.report_id, changed, changed)
        self.assertEqual(caught.exception.safe_body["code"], "IDEMPOTENCY_CONFLICT")
        original_body["operation_id"] = str(uuid.uuid4())
        with self.assertRaises(ApiError) as caught:
            self.batch(revision, original_body)
        self.assertEqual(caught.exception.safe_body["code"], "WITHDRAWAL_CONFLICT")
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.id)
            self.assertFalse(any(job.revision_id == revision.id for job in regenerate_units(org, [revision.report.unit_id])))
        UnitMembership.objects.filter(user=self.reviewer).update(active=False)
        with self.assertRaises(ApiError):
            withdraw_report(self.reviewer, revision.report_id, body, body)

    def test_pending_set_withdrawal_blocks_approval_and_audit_failure_rolls_back(self):
        revision, _ = self.submit_source()
        approve = self.batch_body(revision)
        body = self.withdrawal_body(revision)
        with patch("apps.publications.services.audit.record", side_effect=RuntimeError("PRIVATE_AUDIT_CANARY")):
            with self.assertRaises(RuntimeError):
                withdraw_report(self.reviewer, revision.report_id, body, body)
        self.assertFalse(RevisionWithdrawal.objects.exists())
        withdraw_report(self.reviewer, revision.report_id, body, body)
        with self.assertRaises(ApiError) as caught:
            self.batch(revision, approve)
        self.assertEqual(caught.exception.safe_body["code"], "WITHDRAWAL_CONFLICT")
        self.assertFalse(Publication.objects.exists())
        from apps.operations.worker import binding_for
        from apps.review.services import decide
        variant = revision.variants.get(profile="DEMO-REDUCED")
        legacy = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        legacy["expected"].pop("scope_context_hash")
        with self.assertRaises(ApiError) as caught:
            decide(self.reviewer, variant.id, legacy, legacy)
        self.assertEqual(caught.exception.safe_body["code"], "WITHDRAWAL_CONFLICT")


@override_settings(**SETTINGS)
class M3ReviewRaceTests(ReviewFixture, TransactionTestCase):
    def run_competitor(self, operation, started):
        close_old_connections()
        started.set()
        try:
            return "OK", operation()
        except ApiError as exc:
            return exc.safe_body["code"], None
        finally:
            close_old_connections()

    def force_order(self, first, second):
        started = Event()
        with ThreadPoolExecutor(max_workers=1) as pool:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.id)
                future = pool.submit(self.run_competitor, second, started)
                self.assertTrue(started.wait(10))
                result = first()
            return result, future.result(timeout=20)

    def batch_in_thread(self, revision_id, body, reviewer_id=None):
        actor = get_user_model().objects.get(pk=reviewer_id or self.reviewer.id)
        serializer = BatchDecisionSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        return decide_batch(actor, revision_id, serializer.validated_data, body)

    def test_two_reviewers_one_complete_set_only_one_commits(self):
        revision, _ = self.submit_source()
        other = get_user_model().objects.create(username="reviewer-race", organization=self.org, role="reviewer")
        UnitMembership.objects.create(organization=self.org, user=other, unit=revision.report.unit, role="reviewer")
        first, second = self.batch_body(revision), self.batch_body(revision)
        _, loser = self.force_order(lambda: self.batch(revision, first), lambda: self.batch_in_thread(revision.id, second, other.id))
        self.assertEqual(loser[0], "DECISION_CONFLICT")
        self.assertEqual(DecisionBatch.objects.count(), 1)

    def test_withdrawal_approval_both_serialized_branches(self):
        for withdraw_first in (True, False):
            revision, _ = self.submit_source()
            batch = self.batch_body(revision)
            withdrawal = self.withdrawal_body(revision)
            approve = lambda: self.batch(revision, batch)
            withdraw = lambda: withdraw_report(get_user_model().objects.get(pk=self.reviewer.id), revision.report_id, withdrawal, withdrawal)
            first, second = (withdraw, lambda: self.batch_in_thread(revision.id, batch)) if withdraw_first else (approve, withdraw)
            _, follower = self.force_order(first, second)
            self.assertEqual(follower[0], "WITHDRAWAL_CONFLICT" if withdraw_first else "OK")
            self.assertTrue(RevisionWithdrawal.objects.filter(revision=revision).exists())
            self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())

    def test_two_corrections_one_revision_and_original_operation_identity(self):
        revision, original = self.submit_source()
        self.batch(revision)
        first = dict(copy.deepcopy(original), operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason="first private correction")
        second = dict(copy.deepcopy(original), operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason="second private correction")
        apply = lambda body: accept_operation(get_user_model().objects.get(pk=self.author.id), body, body)
        _, follower = self.force_order(lambda: apply(first), lambda: apply(second))
        self.assertEqual(follower[0], "REVISION_CONFLICT")
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 2)

    def test_correction_versus_regenerated_approval_forces_both_branches(self):
        from apps.operations.worker import process_one
        from apps.reports.regeneration import invalidate_scope
        for correction_first in (True, False):
            revision, original = self.submit_source()
            self.batch(revision)
            with transaction.atomic():
                org = Organization.objects.select_for_update().get(pk=self.org.id)
                invalidate_scope(org, [revision.report.unit_id])
            for _ in range(20):
                if revision.jobs.order_by("-scope_epoch").first().status == "DONE":
                    break
                process_one()
            pending = self.batch_body(revision)
            correction = dict(copy.deepcopy(original), operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason="new private correction")
            correct = lambda: accept_operation(get_user_model().objects.get(pk=self.author.id), correction, correction)
            approve = lambda: self.batch_in_thread(revision.id, pending)
            first, second = (correct, approve) if correction_first else (approve, correct)
            _, follower = self.force_order(first, second)
            self.assertEqual(follower[0], "STALE_REVIEW" if correction_first else "OK")
            self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())
            self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 2)
