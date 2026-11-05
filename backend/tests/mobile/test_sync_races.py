"""Actual HTTP acceptance races use distinct PostgreSQL connections."""
from concurrent.futures import ThreadPoolExecutor
import copy
import threading
import uuid
from unittest.mock import patch

from django.db import close_old_connections
from django.test import TransactionTestCase, override_settings

from apps.audit.models import AuditEvent
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.publications.models import Publication
from apps.reports import mobile_services
from apps.reports.canonical import digest
from apps.reports.models import Report, ReportRevision
from apps.reports.projection import RULES
from apps.scopes.models import PolicyVersion
from tests.test_workflow import operation
from .helpers import MOBILE, MOBILE_SETTINGS
from .test_sync import SyncFixtures


@override_settings(**MOBILE_SETTINGS)
class MobileSyncRaceTests(SyncFixtures, TransactionTestCase):
    def parallel_submit(self, requests):
        barrier = threading.Barrier(len(requests))
        def send(item):
            close_old_connections()
            try:
                client = self.api()
                body, session = item
                barrier.wait(timeout=10)
                response = self.submit(body, session=session, client=client)[1]
                return response.status_code, response.json()
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=len(requests)) as executor:
            futures = [executor.submit(send, item) for item in requests]
            return [future.result(timeout=30) for future in futures]

    def test_simultaneous_exact_replays_commit_one_source_job_receipt_and_audit(self):
        body = operation()
        results = self.parallel_submit([(body, self.session)]*4)
        self.assertEqual(sorted(code for code, _ in results), [200,200,200,201])
        self.assertTrue(all(value == results[0][1] for _, value in results))
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="SOURCE_ACCEPTED").count(), 1)

    def test_concurrent_devices_with_same_operation_have_distinct_acceptance(self):
        first = operation()
        second = dict(first, report_id=str(uuid.uuid4()))
        other = self.new_session()
        results = self.parallel_submit([(first, self.session), (second, other)])
        self.assertEqual([code for code, _ in results], [201,201])
        self.assertNotEqual(results[0][1]["revision_id"], results[1][1]["revision_id"])
        self.assertEqual(ReportRevision.objects.count(), 2)
        self.assertEqual(SyncReceipt.objects.values("accepted_device").distinct().count(), 2)

    def test_concurrent_altered_payload_has_one_winner_without_overwrite(self):
        first = operation()
        second = copy.deepcopy(first)
        second["payload"]["narrative"] += " Conflicting synthetic update."
        results = self.parallel_submit([(first, self.session), (second, self.session)])
        self.assertEqual(sorted(code for code, _ in results), [201,409])
        self.assertEqual(next(body for code, body in results if code == 409)["code"], "IDEMPOTENCY_CONFLICT")
        winner = first if results[0][0] == 201 else second
        self.assertEqual(ReportRevision.objects.get().request_hash, digest({"body": winner, "route": "POST /sync/operations/"}))
        self.assertEqual(ProcessingJob.objects.count(), 1)
        self.assertEqual(SyncReceipt.objects.count(), 1)

    def test_revoke_after_authentication_before_actual_submit_blocks_commit(self):
        authenticated = threading.Event()
        resume = threading.Event()
        real_accept = mobile_services.accept_mobile_operation
        def wait_after_auth(claims, data, raw):
            authenticated.set()
            if not resume.wait(timeout=15):
                raise RuntimeError("Synthetic test rendezvous expired.")
            return real_accept(claims, data, raw)
        web, csrf = self.web()
        body = operation()
        def submit():
            close_old_connections()
            try:
                return self.submit(body, client=self.api())[1]
            finally:
                close_old_connections()
        with patch("apps.operations.mobile_views.accept_mobile_operation", side_effect=wait_after_auth), ThreadPoolExecutor(max_workers=1) as executor:
            pending = executor.submit(submit)
            try:
                self.assertTrue(authenticated.wait(timeout=10))
                response = web.post("/api/v1/account/devices/"+self.session["context"]["enrollment_id"]+"/revoke/",
                    {}, format="json", HTTP_X_CSRFTOKEN=csrf)
                self.assertEqual(response.status_code, 200)
            finally:
                resume.set()
            self.assert_auth_denied(pending.result(timeout=20))
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 0)

    def test_submit_holding_authority_lock_commits_before_waiting_revoke(self):
        accepted_uncommitted = threading.Event()
        release_acceptance = threading.Event()
        revoke_started = threading.Event()
        real_core = mobile_services._accept_locked
        def hold_before_commit(*args):
            result = real_core(*args)
            accepted_uncommitted.set()
            if not release_acceptance.wait(timeout=15):
                raise RuntimeError("Synthetic test rendezvous expired.")
            return result
        web, csrf = self.web()
        body = operation()
        def submit():
            close_old_connections()
            try:
                return self.submit(body, client=self.api())[1].status_code
            finally:
                close_old_connections()
        def revoke():
            close_old_connections()
            try:
                revoke_started.set()
                return web.post("/api/v1/account/devices/"+self.session["context"]["enrollment_id"]+"/revoke/",
                    {}, format="json", HTTP_X_CSRFTOKEN=csrf).status_code
            finally:
                close_old_connections()
        with patch("apps.reports.mobile_services._accept_locked", side_effect=hold_before_commit), ThreadPoolExecutor(max_workers=2) as executor:
            submission = executor.submit(submit)
            try:
                self.assertTrue(accepted_uncommitted.wait(timeout=10))
                revocation = executor.submit(revoke)
                self.assertTrue(revoke_started.wait(timeout=10))
            finally:
                release_acceptance.set()
            self.assertEqual(submission.result(timeout=20), 201)
            self.assertEqual(revocation.result(timeout=20), 200)
        self.assertEqual(ReportRevision.objects.count(), 1)
        self.assertEqual(SyncReceipt.objects.count(), 1)
        self.assert_auth_denied(self.submit(operation())[1])

    def test_commit_then_response_loss_recovers_by_receipt_and_exact_replay(self):
        body = operation()
        # Fail after the real service has committed, before a receipt reaches
        # the client. This simulates uncertain acknowledgement, not a rollback.
        with patch("apps.operations.mobile_views.MobileOperationsView.finalize_response", side_effect=RuntimeError("Synthetic acknowledgement unavailable.")):
            response = self.submit(body)[1]
        self.assertEqual(response.status_code, 500)
        recovered = self.read("sync/receipts/"+body["operation_id"]+"/")
        self.assertEqual(recovered.status_code, 200)
        replay = self.submit(body)[1]
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.json(), recovered.json())
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="SOURCE_ACCEPTED").count(), 1)

    def test_simultaneous_returned_corrections_preserve_original_and_one_successor(self):
        original, _ = self.submit()
        self.decision(original)
        ciphertext = bytes(ReportRevision.objects.get().payload_ciphertext)
        other = self.new_session()
        first = operation(report_id=original["report_id"], expected_revision=1)
        second = operation(report_id=original["report_id"], expected_revision=1)
        results = self.parallel_submit([(first, self.session), (second, other)])
        self.assertEqual(sorted(code for code, _ in results), [201,409])
        self.assertEqual(next(body for code, body in results if code == 409)["code"], "REVISION_CONFLICT")
        self.assertEqual(bytes(ReportRevision.objects.get(revision_no=1).payload_ciphertext), ciphertext)
        self.assertEqual(Report.objects.get().current_revision_no, 2)
        for model in [ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 2)
        self.assertFalse(Publication.objects.exists())

    def test_cross_org_initial_report_uuid_race_is_a_safe_revision_conflict(self):
        foreign = self.another_owner()
        policy = PolicyVersion.objects.create(organization=foreign.organization, version="demo-policy-v1", active=True, rules=RULES, rules_hash=digest(RULES))
        foreign.organization.active_policy = policy
        foreign.organization.save(update_fields=["active_policy"])
        other = self.new_session(owner=foreign)
        first = operation()
        second = operation(report_id=first["report_id"])
        barrier = threading.Barrier(2)
        real_create = Report.objects.create
        def simultaneous_create(**kwargs):
            barrier.wait(timeout=10)
            return real_create(**kwargs)
        with patch("apps.reports.services.Report.objects.create", side_effect=simultaneous_create):
            results = self.parallel_submit([(first, self.session), (second, other)])
        self.assertEqual(sorted(code for code, _ in results), [201,409])
        self.assertEqual(next(body for code, body in results if code == 409)["code"], "REVISION_CONFLICT")
        self.assertEqual(Report.objects.count(), 1)
        self.assertEqual(ReportRevision.objects.count(), 1)
