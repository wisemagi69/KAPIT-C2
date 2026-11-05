"""TASK-125 PostgreSQL processing/invalidation cases; executed only by serialized test-native."""
import json
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import IntegrityError, connection, transaction
from django.test import TestCase, override_settings

from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob
from apps.operations.worker import binding_for, candidate_digest, claim_job, finish_job, process_one, transform_job
from apps.publications.models import Publication, PublicationRemoval, RevisionWithdrawal
from apps.reports.canonical import digest
from apps.reports.models import ReportRevision, ReportVariant
from apps.reports.regeneration import (invalidate_policy, latest_job, queue_job, regenerate_units,
                                      processing_scope)
from apps.reports.selectors import filtered_reports, own_reports, revision_history, summary
from apps.reports.workflow import revision_workflow
from apps.scopes.models import ChannelSource, Organization, PolicyVersion, SharingChannel, Unit
from apps.scopes.services import update_channel, update_source, update_unit
from tests.test_workflow import WorkflowTests


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class M3ProcessingTests(TestCase):
    sign_in = WorkflowTests.sign_in
    submit = WorkflowTests.submit
    candidate = WorkflowTests.candidate
    decision = WorkflowTests.decision
    approve = WorkflowTests.approve

    def setUp(self):
        WorkflowTests.setUp(self)
        call_command("seed_m3_demo", verbosity=0)
        self.admin = get_user_model().objects.get(username="administrator")
        self.unit2 = Unit.objects.get(code="SIM-UNIT-02")
        self.channel2 = SharingChannel.objects.get(code="CH-DEMO-02")
        self.channel3 = SharingChannel.objects.get(code="CH-DEMO-03")

    def accept_m3(self):
        self.sign_in("submitter2")
        body, response = self.submit()
        self.assertEqual(response.status_code, 201, response.content)
        revision = ReportRevision.objects.get(report_id=body["report_id"])
        return body, response.json(), revision

    def apply_v2_fixture(self):
        """Test-only pointer mutation; production two-person service belongs to TASK-128."""
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.pk)
            PolicyVersion.objects.filter(organization=org, active=True).update(active=False)
            target = PolicyVersion.objects.get(organization=org, version="demo-policy-v2")
            target.active = True
            target.save(update_fields=["active"])
            org.active_policy = target
            org.save(update_fields=["active_policy"])
            jobs = invalidate_policy(org, actor=self.admin)
        self.org.refresh_from_db()
        return jobs

    def test_fresh_m3_submission_freezes_context_and_creates_complete_profile_set(self):
        _, receipt, revision = self.accept_m3()
        job = revision.jobs.get()
        self.assertIsNotNone(job.scope_context_hash)
        self.assertEqual(job.scope_context_hash, digest(job.scope_context))
        self.assertEqual((job.policy_epoch, job.scope_epoch), (0, 0))
        self.assertFalse(receipt["shared"])
        self.assertFalse(Publication.objects.exists())
        self.assertTrue(process_one())
        variants = {variant.profile: variant for variant in revision.variants.all()}
        self.assertEqual(set(variants), {"DEMO-FULL", "DEMO-REDUCED", "DEMO-SUMMARY"})
        self.assertEqual(variants["DEMO-FULL"].channel_ids, [str(self.channel2.id)])
        self.assertEqual(variants["DEMO-REDUCED"].channel_ids, [str(self.channel2.id)])
        self.assertEqual(variants["DEMO-SUMMARY"].channel_ids, sorted([str(self.channel2.id), str(self.channel3.id)]))
        for variant in variants.values():
            self.assertEqual(variant.state, "CANDIDATE")
            self.assertEqual(variant.scope_context_hash, job.scope_context_hash)
            self.assertEqual(binding_for(variant)["scope_context_hash"], job.scope_context_hash)
            self.assertNotIn("PRIVATE_", json.dumps(variant.projection))
            expected = candidate_digest(variant.projection, revision.id, revision.revision_no, revision.content_digest,
                job.policy_id, job.policy.rules_hash, variant.profile, variant.channel_ids,
                scope_context_hash=job.scope_context_hash, policy_epoch=job.policy_epoch, scope_epoch=job.scope_epoch)
            self.assertEqual(expected, variant.candidate_hash)
        self.assertNotIn("originating_unit", variants["DEMO-REDUCED"].projection)
        self.assertNotIn("area_label", variants["DEMO-SUMMARY"].projection)
        self.assertFalse(Publication.objects.exists())

    def test_historical_approval_with_stale_epoch_cannot_claim_current_availability(self):
        body, _, variant, _, _, _ = self.approve()
        revision = ReportRevision.objects.select_related("report").get(report_id=body["report_id"])
        before = revision_workflow(revision.report, revision, self.org)
        self.assertEqual(before["sharing"]["state"], "AVAILABLE")
        # Same policy, channels and projection; only the source epoch changed.
        # The pre-M3 recipient predicate is intentionally not an epoch proof.
        unit = Unit.objects.get(pk=revision.report.unit_id)
        unit.scope_epoch += 1
        unit.save(update_fields=["scope_epoch"])
        current = revision_workflow(revision.report, revision, self.org)
        self.assertEqual(current["sharing"]["state"], "UNAVAILABLE")
        self.assertEqual(current["sharing"]["published_at"], before["sharing"]["published_at"])
        self.assertEqual(current["review"], before["review"])

    def test_legacy_digest_binding_receipt_and_single_variant_remain_unchanged(self):
        _, receipt, variant, _ = self.candidate()
        job, revision = variant.job, variant.revision
        self.assertIsNone(job.scope_context)
        self.assertEqual(revision.variants.count(), 1)
        self.assertEqual(variant.profile, "DEMO-REDUCED")
        self.assertNotIn("scope_context_hash", binding_for(variant))
        self.assertEqual(variant.candidate_hash, digest({"projection": variant.projection, "revision_id": str(revision.id),
            "revision_no": revision.revision_no, "source_digest": revision.content_digest, "policy_id": str(job.policy_id),
            "policy_hash": job.policy.rules_hash, "profile": variant.profile, "channel_ids": variant.channel_ids}))
        self.assertEqual(set(receipt), {"operation_id", "report_id", "revision_id", "revision_no", "delivery_status", "processing_status", "shared"})

    def test_duplicate_regeneration_identity_does_not_add_jobs_or_reset_progress(self):
        _, _, revision = self.accept_m3()
        self.assertTrue(process_one())
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.pk)
            job, created = queue_job(org, self.unit2, revision)
            self.assertFalse(created)
            self.assertEqual(regenerate_units(org, [self.unit2.id]), [])
        self.assertEqual(revision.jobs.count(), 1)
        revision.refresh_from_db()
        self.assertEqual(revision.processing_state, "AWAITING_REVIEW")
        self.assertEqual(job.variants.count(), 3)

    def test_stale_lease_finish_after_topology_regeneration_cannot_create_or_overwrite(self):
        _, _, revision = self.accept_m3()
        old_lease = claim_job()
        output = transform_job(old_lease)
        update_source(self.admin, self.unit2.id, self.channel2.id, max_profile="DEMO-REDUCED")
        replacement = latest_job(revision)
        self.assertNotEqual(replacement.id, old_lease["id"])
        self.assertFalse(finish_job(old_lease, output))
        self.assertFalse(ReportVariant.objects.filter(job_id=old_lease["id"]).exists())
        revision.refresh_from_db()
        self.assertEqual(revision.processing_state, "PENDING")
        self.assertTrue(process_one())
        self.assertEqual(set(replacement.variants.values_list("profile", flat=True)), {"DEMO-REDUCED", "DEMO-SUMMARY"})

    def test_stale_context_is_not_claimed_and_replacement_is_processed(self):
        _, _, revision = self.accept_m3()
        old = latest_job(revision)
        update_channel(self.admin, self.channel2.id, max_profile="DEMO-REDUCED")
        lease = claim_job()
        self.assertNotEqual(lease["id"], old.id)
        old.refresh_from_db()
        self.assertEqual((old.status, old.error_code), ("FAILED", "STALE_CONTEXT"))
        self.assertTrue(finish_job(lease, transform_job(lease)))

    def test_profile_batch_rolls_back_completely_on_second_variant_insert_failure(self):
        _, _, revision = self.accept_m3()
        lease = claim_job()
        output = transform_job(lease)
        real_create = ReportVariant.objects.create
        calls = []
        def fail_second(**values):
            calls.append(values["profile"])
            if len(calls) == 2:
                raise IntegrityError("synthetic atomicity fault")
            return real_create(**values)
        with self.assertRaises(IntegrityError), transaction.atomic():
            with patch("apps.operations.worker.ReportVariant.objects.create", side_effect=fail_second):
                finish_job(lease, output)
        self.assertFalse(revision.variants.exists())
        job = latest_job(revision)
        self.assertEqual(job.status, "PROCESSING")
        self.assertTrue(finish_job(lease, output))
        self.assertEqual(revision.variants.count(), 3)

    def test_malformed_transformation_fails_private_without_partial_candidates(self):
        _, _, revision = self.accept_m3()
        lease = claim_job()
        self.assertTrue(finish_job(lease, {"DEMO-SUMMARY": {"text": "PRIVATE_INJECTION_CANARY"}}))
        self.assertFalse(revision.variants.exists())
        self.assertEqual(latest_job(revision).status, "FAILED")
        self.assertFalse(Publication.objects.exists())

    def test_current_summary_history_filter_and_workflow_select_replacement_not_old_decision(self):
        _, _, revision = self.accept_m3()
        self.assertTrue(process_one())
        old_ids = set(revision.variants.values_list("id", flat=True))
        update_source(self.admin, self.unit2.id, self.channel2.id, max_profile="DEMO-REDUCED")
        report = revision.report
        self.assertEqual(summary(report)["status"], "PENDING")
        self.assertIsNone(summary(report)["variant_id"])
        self.assertEqual(revision_history(report)[0]["status"], "PENDING")
        self.org.refresh_from_db()
        workflow = revision_workflow(report, ReportRevision.objects.get(pk=revision.pk), self.org)
        self.assertEqual(workflow["processing"]["state"], "PENDING")
        self.assertEqual(workflow["review"]["state"], "NOT_READY")
        submitter = get_user_model().objects.get(username="submitter2")
        self.assertEqual(filtered_reports(own_reports(submitter), {"status": "PENDING"}).count(), 1)
        self.assertEqual(filtered_reports(own_reports(submitter), {"status": "AWAITING_REVIEW"}).count(), 0)
        self.assertTrue(process_one())
        self.assertEqual(summary(report)["status"], "AWAITING_REVIEW")
        self.assertNotIn(summary(report)["variant_id"], {str(value) for value in old_ids})

    def test_policy_epoch_removes_legacy_publication_and_regenerates_all_eligible_units(self):
        _, _, legacy, _, _, _ = self.approve()
        _, _, m3 = self.accept_m3()
        self.assertTrue(process_one())
        old_publication = Publication.objects.get(variant=legacy)
        jobs = self.apply_v2_fixture()
        self.assertEqual({job.revision_id for job in jobs}, {legacy.revision_id, m3.id})
        old_publication.refresh_from_db()
        self.assertIsNotNone(old_publication.revoked_at)
        self.assertEqual(PublicationRemoval.objects.get(publication=old_publication).cause, "POLICY")
        legacy_job = latest_job(legacy.revision)
        self.assertIsNone(legacy_job.scope_context)
        self.assertEqual(legacy_job.policy_epoch, 1)
        self.assertTrue(process_one())
        self.assertTrue(process_one())
        self.assertEqual(legacy_job.variants.count(), 1)
        self.assertNotEqual(legacy_job.variants.get().candidate_hash, legacy.candidate_hash)
        self.assertEqual(Publication.objects.filter(revoked_at__isnull=True).count(), 0)

    def test_scope_a_b_a_increments_only_affected_units_and_old_context_never_revives(self):
        _, _, revision = self.accept_m3()
        self.assertTrue(process_one())
        initial = latest_job(revision)
        update_channel(self.admin, self.channel2.id, active=False)
        update_channel(self.admin, self.channel2.id, active=True)
        self.unit.refresh_from_db()
        self.unit2.refresh_from_db()
        self.assertEqual(self.unit.scope_epoch, 0)
        self.assertEqual(self.unit2.scope_epoch, 2)
        current = latest_job(revision)
        self.assertNotEqual(initial.scope_context_hash, current.scope_context_hash)
        self.assertEqual(current.scope_epoch, 2)
        self.assertEqual(revision.jobs.count(), 3)

    def test_returned_rejected_and_withdrawn_revisions_do_not_regenerate(self):
        _, _, variant, review = self.candidate()
        _, response = self.decision(variant, review, action="RETURN", reason="Synthetic correction requested.")
        self.assertEqual(response.status_code, 200, response.content)
        _, _, second, second_review = self.candidate()
        _, response = self.decision(second, second_review, action="REJECT", reason="Synthetic rejection.")
        self.assertEqual(response.status_code, 200, response.content)
        _, _, withdrawn, _, _, _ = self.approve()
        from django.utils import timezone
        import uuid
        RevisionWithdrawal.objects.create(organization=self.org, revision=withdrawn.revision, report=withdrawn.revision.report,
            reviewer=self.reviewer, operation_id=uuid.uuid4(), request_hash="f" * 64, expected_revision_no=1,
            reason_ciphertext=b"synthetic", publication_ids=[], response_body={}, withdrawn_at=timezone.now())
        self.assertEqual(self.apply_v2_fixture(), [])
        self.assertEqual(ProcessingJob.objects.count(), 3)

    def test_terminal_summary_history_and_status_counts_stay_consistent_after_policy_change(self):
        terminal = []
        for action, state in (("RETURN", "RETURNED"), ("REJECT", "REJECTED")):
            _, _, variant, review = self.candidate()
            _, response = self.decision(variant, review, action=action, reason="Synthetic terminal feedback.")
            self.assertEqual(response.status_code, 200, response.content)
            terminal.append((variant.revision.report, state))
        self.apply_v2_fixture()
        for report, state in terminal:
            self.assertEqual(summary(report)["status"], state)
            self.assertEqual(revision_history(report)[0]["status"], state)
            self.assertEqual(filtered_reports(own_reports(self.submitter), {"status": state}).count(), 1)
        self.assertEqual(filtered_reports(own_reports(self.submitter), {"status": "FAILED"}).count(), 0)

    def test_mixed_approved_and_withheld_set_regenerates(self):
        _, _, revision = self.accept_m3()
        self.assertTrue(process_one())
        revision.variants.filter(profile="DEMO-FULL").update(state="APPROVED")
        revision.variants.exclude(profile="DEMO-FULL").update(state="REJECTED")
        old = latest_job(revision)
        update_channel(self.admin, self.channel2.id, max_profile="DEMO-REDUCED")
        self.assertNotEqual(latest_job(revision).id, old.id)
        self.assertEqual(latest_job(revision).status, "PENDING")

    def test_missing_eligible_context_is_private_failed_not_stale_awaiting_review(self):
        _, _, revision = self.accept_m3()
        self.assertTrue(process_one())
        update_channel(self.admin, self.channel2.id, active=False)
        update_channel(self.admin, self.channel3.id, active=False)
        self.assertEqual(summary(revision.report)["status"], "FAILED")
        self.assertIsNone(summary(revision.report)["variant_id"])
        self.assertEqual(revision_history(revision.report)[0]["status"], "FAILED")
        self.org.refresh_from_db()
        self.assertEqual(revision_workflow(revision.report, revision, self.org)["review"]["state"], "NOT_READY")
        actor = get_user_model().objects.get(username="submitter2")
        self.assertEqual(filtered_reports(own_reports(actor), {"status": "AWAITING_REVIEW"}).count(), 0)
        self.assertEqual(filtered_reports(own_reports(actor), {"status": "FAILED"}).count(), 1)

    def test_deactivated_policy_has_no_current_candidate_queue(self):
        _, _, revision = self.accept_m3()
        self.assertTrue(process_one())
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.pk)
            PolicyVersion.objects.filter(organization=org, active=True).update(active=False)
            org.active_policy = None
            org.save(update_fields=["active_policy"])
            self.assertEqual(invalidate_policy(org), [])
        self.assertEqual(summary(revision.report)["status"], "FAILED")
        self.assertIsNone(summary(revision.report)["variant_id"])
        actor = get_user_model().objects.get(username="submitter2")
        self.assertEqual(filtered_reports(own_reports(actor), {"status": "FAILED"}).count(), 1)

    def test_topology_audit_failure_rolls_back_change_epoch_removal_and_job(self):
        _, _, revision = self.accept_m3()
        before_jobs = ProcessingJob.objects.count()
        with self.assertRaises(RuntimeError), transaction.atomic():
            with patch("apps.reports.regeneration.audit.record", side_effect=RuntimeError("synthetic audit fault")):
                update_source(self.admin, self.unit2.id, self.channel2.id, max_profile="DEMO-REDUCED")
        self.unit2.refresh_from_db()
        self.assertEqual(self.unit2.scope_epoch, 0)
        self.assertEqual(ChannelSource.objects.get(unit=self.unit2, channel=self.channel2).max_profile, "DEMO-FULL")
        self.assertEqual(ProcessingJob.objects.count(), before_jobs)

    def test_unit_deactivation_then_reactivation_queues_fresh_context(self):
        _, _, revision = self.accept_m3()
        update_unit(self.admin, self.unit2.id, active=False)
        self.assertEqual(revision.jobs.count(), 1)
        update_unit(self.admin, self.unit2.id, active=True)
        self.assertEqual(revision.jobs.count(), 2)
        self.assertEqual(latest_job(revision).scope_epoch, 2)

    def test_scope_change_requires_explicit_authority_and_preserves_mobile_topology(self):
        for actor in (self.submitter, self.reviewer):
            with self.assertRaises(ApiError):
                update_channel(actor, self.channel2.id, active=False)
        with self.assertRaises(ApiError):
            update_source(self.admin, self.unit.id, self.channel.id, max_profile="DEMO-SUMMARY")
        self.unit.refresh_from_db()
        self.assertEqual(self.unit.scope_epoch, 0)
        self.assertFalse(AuditEvent.objects.filter(action="SCOPE_CHANGED").exists())
