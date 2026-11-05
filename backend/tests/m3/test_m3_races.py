"""Independent R1-R15 PostgreSQL ordered interleavings; no runtime pass claim.

Two connections contend on the actual organization serialization lock. The first
thread owns it before the contender starts. Reversing actions forces both legal
linearizations; branches have explicit assertions, not permissive OR assertions.
"""
import copy
import threading
import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, transaction
from django.http import QueryDict
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.accounts.integration_services import request_client, approve_client, collect_client, revoke_client
from apps.accounts.models import IntegrationClient, IntegrationClientApproval, IntegrationClientRequest
from apps.accounts.services import reset_password
from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob
from apps.operations.worker import binding_for, claim_job, finish_job, process_one, transform_job
from apps.publications.models import Publication, PublicationRemoval, RevisionWithdrawal
from apps.publications.selectors import feed, map_counts
from apps.reports.models import ReportRevision
from apps.reports.regeneration import regenerate_units
from apps.reports.services import accept_operation
from apps.review.models import DecisionBatch, ReviewDecision
from apps.review.services import decide, decide_batch
from apps.scopes import policy
from apps.scopes.models import AdminAuthority, ChannelMember, Organization, PolicyActivation, PolicyProposal, UnitMembership
from apps.scopes.services import update_source, update_unit
from tests.test_workflow import operation
from .test_m3_isolation import QAMatrixFixture, WEB, INTEGRATION
from .test_m3_review import SETTINGS


@override_settings(**SETTINGS)
class IndependentRaceTests(QAMatrixFixture, TransactionTestCase):
    def ordered(self, first, second):
        ready, contender, release = threading.Event(), threading.Event(), threading.Event()
        result = [None, None]
        errors = []

        def run(index, action):
            close_old_connections()
            try:
                if index:
                    if not ready.wait(15):
                        raise AssertionError("QA first lock deadline")
                    contender.set()
                with transaction.atomic():
                    with connection.cursor() as cursor:
                        cursor.execute("SET LOCAL lock_timeout = '15s'")
                    Organization.objects.select_for_update().get(pk=self.org.pk)
                    if not index:
                        ready.set()
                        if not release.wait(15):
                            raise AssertionError("QA release deadline")
                    try:
                        with transaction.atomic():
                            result[index] = ("ok", action())
                    except ApiError as failure:
                        result[index] = ("denied", failure.safe_body["code"])
            except BaseException as failure:
                errors.append(type(failure).__name__)
            finally:
                close_old_connections()

        threads = [threading.Thread(target=run, args=(n, action), daemon=True) for n, action in enumerate((first, second))]
        threads[0].start()
        try:
            self.assertTrue(ready.wait(15), "First connection did not hold organization lock")
            threads[1].start()
            self.assertTrue(contender.wait(15), "Contending connection did not start")
        finally:
            release.set()
            for thread in threads:
                if thread.ident is not None:
                    thread.join(25)
        self.assertFalse(any(thread.is_alive() for thread in threads), "QA concurrency deadline")
        self.assertEqual(errors, [], "Unexpected worker exception types")
        self.assertTrue(all(value is not None for value in result))
        return result

    def old_set(self):
        revision, raw = self.prepared()
        data, body = self.decision_data(revision)
        return revision, raw, lambda: decide_batch(self.reviewer, revision.id, data, body)

    def assert_removed(self, revision):
        self.assertFalse(Publication.objects.filter(report=revision.report, revoked_at__isnull=True).exists())
        self.assertEqual(Publication.objects.filter(report=revision.report).count(), PublicationRemoval.objects.filter(publication__report=revision.report).count())

    def correction(self, body):
        result = copy.deepcopy(body)
        result.update(operation_id=str(uuid.uuid4()), expected_revision=1, correction_reason="QA_PRIVATE_CORRECTION")
        return result

    def test_r1_competing_reviewers_have_one_commit(self):
        revision, _, approve = self.old_set()
        peer = get_user_model().objects.create_user(username="qa-reviewer-peer", organization=self.org, role="reviewer", display_name="Synthetic peer")
        UnitMembership.objects.create(organization=self.org, user=peer, unit=self.units[2], role="reviewer")
        data, body = self.decision_data(revision, peer)
        results = self.ordered(approve, lambda: decide_batch(peer, revision.id, data, body))
        self.assertEqual([row[0] for row in results], ["ok", "denied"])
        self.assertEqual(results[1][1], "DECISION_CONFLICT")
        self.assertEqual(DecisionBatch.objects.filter(revision=revision).count(), 1)

    def approval_policy_branch(self, approval_first):
        revision, _, approve = self.old_set()
        proposal = self.proposal()
        apply = lambda: policy.apply(self.second, proposal)
        results = self.ordered(approve, apply) if approval_first else self.ordered(apply, approve)
        self.assertEqual(results[0][0], "ok")
        self.assertEqual(results[1][0], "ok" if approval_first else "denied")
        if not approval_first:
            self.assertEqual(results[1][1], "STALE_REVIEW")
        self.assert_removed(revision)

    def test_r2_approval_first_is_permanently_removed(self):
        self.approval_policy_branch(True)

    def test_r2_policy_first_denies_stale_approval(self):
        self.approval_policy_branch(False)

    def test_r3_approval_then_topology_and_back_never_revives(self):
        revision, _, approve = self.old_set()
        results = self.ordered(approve, lambda: update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED"))
        self.assertEqual([row[0] for row in results], ["ok", "ok"])
        update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-FULL")
        self.assert_removed(revision)
        approve()  # historical replay returns its receipt, without a publication revival
        self.assert_removed(revision)

    def test_r3_topology_first_denies_original_set(self):
        revision, _, approve = self.old_set()
        results = self.ordered(lambda: update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED"), approve)
        self.assertEqual(results[1], ("denied", "STALE_REVIEW"))
        update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-FULL")
        with self.assertRaises(ApiError):
            approve()
        self.assert_removed(revision)

    def withdrawal_branch(self, approval_first):
        revision, _, approve = self.old_set()
        withdraw = lambda: self.withdraw_revision(revision)
        results = self.ordered(approve, withdraw) if approval_first else self.ordered(withdraw, approve)
        self.assertEqual(results[0][0], "ok")
        self.assertEqual(results[1][0], "ok" if approval_first else "denied")
        if not approval_first:
            self.assertEqual(results[1][1], "WITHDRAWAL_CONFLICT")
        self.assert_removed(revision)
        proposal = self.proposal()
        policy.apply(self.second, proposal)
        while process_one():
            pass
        self.assert_removed(revision)
        self.assertTrue(RevisionWithdrawal.objects.filter(revision=revision).exists())

    def test_r4_approval_first_then_withdraw_policy_does_not_revive(self):
        self.withdrawal_branch(True)

    def test_r4_withdrawal_first_prevents_approval_after_policy(self):
        self.withdrawal_branch(False)

    def test_r4_withdrawal_of_pending_regeneration_and_topology_race(self):
        revision, _ = self.publish_unit()
        policy.apply(self.second, self.proposal())
        self.assertTrue(ProcessingJob.objects.filter(revision=revision, status="PENDING").exists())
        results = self.ordered(lambda: self.withdraw_revision(revision), lambda: update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED"))
        self.assertEqual([row[0] for row in results], ["ok", "ok"])
        while process_one():
            pass
        self.assert_removed(revision)

    def test_r4_topology_regeneration_first_then_withdrawal_stays_private(self):
        revision, _ = self.publish_unit()
        results = self.ordered(lambda: update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED"), lambda: self.withdraw_revision(revision))
        self.assertEqual([row[0] for row in results], ["ok", "ok"])
        while process_one():
            pass
        self.assert_removed(revision)
        from apps.review.services import candidate_set
        with self.assertRaises(ApiError) as caught:
            candidate_set(self.reviewer, revision.id)
        self.assertEqual(caught.exception.safe_body["code"], "WITHDRAWAL_CONFLICT")

    def read_withdrawal_branch(self, read_first):
        revision, _ = self.publish_unit()
        _, reader = self.issue_key()
        def read():
            response = reader.get(INTEGRATION + "publications/")
            self.assertEqual(response.status_code, 200)
            return response.json()
        results = self.ordered(read, lambda: self.withdraw_revision(revision)) if read_first else self.ordered(lambda: self.withdraw_revision(revision), read)
        observed = results[0 if read_first else 1][1]
        self.assertEqual(len(observed["results"]), 1 if read_first else 0)
        user = self.users["recipient-full"]
        with transaction.atomic():
            after = feed(user, self.org, self.channels[2].id, QueryDict())
            mapping = map_counts(user, self.org, self.channels[2].id, QueryDict())
        self.assertEqual(after["count"], 0)
        self.assertEqual(mapping, {"areas": [], "unmapped": 0})

    def test_r5_read_before_withdrawal_is_whole_before(self):
        self.read_withdrawal_branch(True)

    def test_r5_withdrawal_before_read_is_whole_after(self):
        self.read_withdrawal_branch(False)

    def recipient_read_branch(self, read_first):
        revision, _ = self.publish_unit()
        def read():
            # Both surfaces share the containing organization transaction.
            result = feed(self.users["recipient-full"], self.org, self.channels[2].id, QueryDict())
            mapping = map_counts(self.users["recipient-full"], self.org, self.channels[2].id, QueryDict())
            return result["count"], len(result["results"]), sum(row["count"] for row in mapping["areas"]) + mapping["unmapped"]
        results = self.ordered(read, lambda: self.withdraw_revision(revision)) if read_first else self.ordered(lambda: self.withdraw_revision(revision), read)
        self.assertEqual(results[0 if read_first else 1], ("ok", (1, 1, 1) if read_first else (0, 0, 0)))

    def test_r5_recipient_read_first_count_list_map_agree(self):
        self.recipient_read_branch(True)

    def test_r5_recipient_withdrawal_first_count_list_map_agree(self):
        self.recipient_read_branch(False)

    def test_r6_two_corrections_create_one_child_and_one_removal_per_publication(self):
        revision, raw = self.publish_unit()
        first, second = self.correction(raw), self.correction(raw)
        results = self.ordered(lambda: accept_operation(self.author, first, first), lambda: accept_operation(self.author, second, second))
        self.assertEqual(results[0][0], "ok")
        self.assertEqual(results[1], ("denied", "REVISION_CONFLICT"))
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 2)
        self.assert_removed(revision)

    def correction_approval_branch(self, approval_first):
        revision, raw = self.publish_unit()
        policy.apply(self.second, self.proposal())
        self.assertTrue(process_one())
        data, body = self.decision_data(revision)
        approve = lambda: decide_batch(self.reviewer, revision.id, data, body)
        correction = self.correction(raw)
        correct = lambda: accept_operation(self.author, correction, correction)
        results = self.ordered(approve, correct) if approval_first else self.ordered(correct, approve)
        self.assertEqual(results[0][0], "ok")
        self.assertEqual(results[1][0], "ok" if approval_first else "denied")
        if not approval_first:
            self.assertEqual(results[1][1], "STALE_REVIEW")
        self.assert_removed(revision)
        self.assertEqual(ReportRevision.objects.filter(report=revision.report).count(), 2)

    def test_r7_approval_before_correction_is_superseded(self):
        self.correction_approval_branch(True)

    def test_r7_correction_before_old_approval_is_stale(self):
        self.correction_approval_branch(False)

    def test_r8_competing_applies_and_policy_aba_never_restore_epoch_zero(self):
        revision, _ = self.publish_unit()
        one, two = self.proposal(), self.proposal()
        results = self.ordered(lambda: policy.apply(self.second, one), lambda: policy.apply(self.second, two))
        self.assertEqual(results[0][0], "ok")
        self.assertEqual(results[1], ("denied", "STALE_POLICY"))
        policy.apply(self.second, self.proposal("demo-policy-v1"))
        self.org.refresh_from_db()
        self.assertEqual(self.org.policy_epoch, 2)
        self.assertEqual(PolicyActivation.objects.count(), 2)
        self.assertEqual(self.org.policyversion_set.filter(active=True).count(), 1)
        self.assert_removed(revision)

    def test_r9_duplicate_regeneration_is_one_job_per_frozen_identity(self):
        revision, _ = self.publish_unit()
        update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED")
        results = self.ordered(lambda: regenerate_units(Organization.objects.get(pk=self.org.pk), [self.units[2].id]), lambda: regenerate_units(Organization.objects.get(pk=self.org.pk), [self.units[2].id]))
        self.assertEqual(results, [("ok", []), ("ok", [])])
        self.assertEqual(ProcessingJob.objects.filter(revision=revision, scope_epoch=1).count(), 1)

    def test_r10_client_and_grant_revocation_deny_next_page_and_do_not_reuse_cursor(self):
        for _ in range(2):
            self.publish_unit()
        client, reader = self.issue_key()
        first = reader.get(INTEGRATION + "publications/", {"limit": 1}).json()
        self.assertIsInstance(first["next_cursor"], str)
        results = self.ordered(lambda: revoke_client(self.admin, client.id), lambda: reader.get(INTEGRATION + "publications/", {"limit": 1, "cursor": first["next_cursor"]}).status_code)
        self.assertEqual(results[1], ("ok", 401))
        user = self.users["recipient-full"]
        self.read_as(user.username, f"channels/{self.channels[2].id}/feed/", {"page_size": 1})
        def revoke_grant():
            ChannelMember.objects.filter(user=user, channel=self.channels[2], active=True).update(active=False)
        results = self.ordered(revoke_grant, lambda: self.read_as(user.username, f"channels/{self.channels[2].id}/feed/", {"page": 2, "page_size": 1}).status_code)
        self.assertEqual(results[1], ("ok", 404))

    def test_r11_old_lease_finish_after_regeneration_cannot_write_candidates(self):
        raw = operation()
        receipt, _ = accept_operation(self.author, raw, raw)
        lease = claim_job()
        self.assertIsNotNone(lease)
        projected = transform_job(lease)
        results = self.ordered(lambda: update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED"), lambda: finish_job(lease, projected))
        self.assertEqual(results[1], ("ok", False))
        revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.assertFalse(revision.variants.exists())
        self.assertTrue(process_one())
        self.assertEqual(set(revision.variants.values_list("job__scope_epoch", flat=True)), {1})

    def test_r12_all_eight_audit_fault_boundaries_roll_back(self):
        revision, _, approve = self.old_set()
        published, _ = self.publish_unit()
        proposal = self.proposal()
        data = {"operation_id": uuid.uuid4(), "channel_id": self.channels[2].id, "profile_ceiling": "DEMO-FULL", "label": "Synthetic QA full reader", "expires_at": timezone.now() + timedelta(days=2)}
        request, _ = request_client(self.admin, data, {key: str(value) for key, value in data.items()})
        request_id = request["request"]["id"]
        client, _ = self.issue_key()
        models = (AuditEvent, DecisionBatch, ReviewDecision, Publication, PublicationRemoval, RevisionWithdrawal, PolicyProposal, PolicyActivation, ProcessingJob, IntegrationClientRequest, IntegrationClientApproval, IntegrationClient)
        def snapshot():
            self.org.refresh_from_db()
            return ([model.objects.count() for model in models], self.org.active_policy_id, self.org.policy_epoch,
                    list(Publication.objects.order_by("id").values_list("id", "revoked_at")),
                    list(revision.variants.order_by("id").values_list("id", "state")),
                    list(IntegrationClient.objects.order_by("id").values_list("id", "revoked_at")))
        target = self.org.policyversion_set.get(version="demo-policy-v2")
        proposal_data = {"operation_id": uuid.uuid4(), "kind": "ACTIVATE", "target_policy_id": target.id, "target_rules_hash": target.rules_hash, "expected_active_policy_id": self.org.active_policy_id}
        reduced = {**data, "operation_id": uuid.uuid4(), "profile_ceiling": "DEMO-REDUCED"}
        cases = [("approval", approve), ("withdrawal", lambda: self.withdraw_revision(published)),
                 ("policy-propose", lambda: policy.propose(self.admin, proposal_data, {key: str(value) for key, value in proposal_data.items()})),
                 ("policy-apply", lambda: policy.apply(self.second, proposal)),
                 ("key-request", lambda: request_client(self.admin, reduced, {key: str(value) for key, value in reduced.items()})),
                 ("key-approve", lambda: approve_client(self.second, request_id)),
                 ("key-revoke", lambda: revoke_client(self.admin, client.id))]
        for name, action in cases:
            with self.subTest(boundary=name):
                before = snapshot()
                with patch("apps.audit.service.record", side_effect=RuntimeError("synthetic audit fault")), self.assertRaises(RuntimeError):
                    action()
                self.assertEqual(snapshot(), before)
        approve_client(self.second, request_id)
        before = snapshot()
        with patch("apps.audit.service.record", side_effect=RuntimeError("synthetic audit fault")), self.assertRaises(RuntimeError):
            collect_client(self.admin, request_id)
        self.assertEqual(snapshot(), before)

    def test_r13_password_reset_is_protected_and_revoked_proposer_blocks_apply(self):
        proposal = self.proposal()
        reset = lambda: reset_password(self.second, self.admin.id, {"expected_permission_version": 0, "password": "SyntheticChanged!175"})
        results = self.ordered(reset, lambda: policy.apply(self.second, proposal))
        self.assertEqual(results[0], ("denied", "AUTHORITY_PROTECTED"))
        self.assertEqual(results[1][0], "ok")
        proposal = self.proposal("demo-policy-v1")
        def revoke():
            AdminAuthority.objects.filter(user=self.admin, kind="POLICY").update(active=False)
        results = self.ordered(revoke, lambda: policy.apply(self.second, proposal))
        self.assertEqual(results[1], ("denied", "STALE_POLICY"))

    def test_r14_unrelated_scope_does_not_invalidate_legacy_but_policy_does(self):
        revision, _ = self.prepared(1)
        variant = revision.variants.get()
        data = {"operation_id": uuid.uuid4(), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        approve = lambda: decide(self.users["reviewer"], variant.id, data, {**data, "operation_id": str(data["operation_id"])})
        results = self.ordered(lambda: update_source(self.admin, self.units[2].id, self.channels[2].id, max_profile="DEMO-REDUCED"), approve)
        self.assertEqual([row[0] for row in results], ["ok", "ok"])
        self.units[1].refresh_from_db()
        self.assertEqual(self.units[1].scope_epoch, 0)
        policy.apply(self.second, self.proposal())
        self.assert_removed(revision)
        self.assertTrue(ProcessingJob.objects.filter(revision=revision, policy_epoch=1, status="PENDING").exists())
        with self.assertRaises(ApiError) as caught:
            update_unit(self.admin, self.units[1].id, active=False)
        self.assertEqual(caught.exception.safe_body["code"], "SCOPE_UNAVAILABLE")

    def test_r14_policy_first_denies_legacy_decision_and_keeps_replacement_job(self):
        revision, _ = self.prepared(1)
        variant = revision.variants.get()
        data = {"operation_id": uuid.uuid4(), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        proposal = self.proposal()
        results = self.ordered(lambda: policy.apply(self.second, proposal), lambda: decide(self.users["reviewer"], variant.id, data, {**data, "operation_id": str(data["operation_id"])}))
        self.assertEqual(results[1], ("denied", "STALE_REVIEW"))
        self.assertTrue(ProcessingJob.objects.filter(revision=revision, policy_epoch=1, status="PENDING").exists())
        self.assert_removed(revision)

    def full_request(self):
        data = {"operation_id": uuid.uuid4(), "channel_id": self.channels[2].id, "profile_ceiling": "DEMO-FULL", "label": "Synthetic QA full reader", "expires_at": timezone.now() + timedelta(days=2)}
        result, _ = request_client(self.admin, data, {key: str(value) for key, value in data.items()})
        request_id = result["request"]["id"]
        approve_client(self.second, request_id)
        return request_id

    def test_r15_two_full_collects_expose_exactly_one_secret(self):
        request_id = self.full_request()
        results = self.ordered(lambda: collect_client(self.admin, request_id), lambda: collect_client(self.admin, request_id))
        self.assertEqual([row[0] for row in results], ["ok", "ok"])
        self.assertTrue(results[0][1][1])
        self.assertIn("key", results[0][1][0])
        self.assertFalse(results[1][1][1])
        self.assertNotIn("key", results[1][1][0])
        self.assertEqual(IntegrationClient.objects.count(), 1)

    def test_r15_authority_revocation_before_collect_denies_secret(self):
        request_id = self.full_request()
        def revoke():
            AdminAuthority.objects.filter(user=self.second, kind="INTEGRATION").update(active=False)
        results = self.ordered(revoke, lambda: collect_client(self.admin, request_id))
        self.assertEqual(results[1][0], "denied")
        if results[1][0] == "denied":
            self.assertEqual(results[1][1], "NOT_FOUND")
        self.assertFalse(IntegrationClient.objects.exists())

    def test_r15_collect_before_authority_revocation_does_not_reveal_a_second_secret(self):
        request_id = self.full_request()
        def revoke():
            AdminAuthority.objects.filter(user=self.second, kind="INTEGRATION").update(active=False)
        results = self.ordered(lambda: collect_client(self.admin, request_id), revoke)
        self.assertEqual([row[0] for row in results], ["ok", "ok"])
        self.assertIn("key", results[0][1][0])
        self.assertEqual(IntegrationClient.objects.count(), 1)
        self.assertIsNone(IntegrationClient.objects.get().revoked_at)
        replay, created = collect_client(self.admin, request_id)
        self.assertFalse(created)
        self.assertNotIn("key", replay)
