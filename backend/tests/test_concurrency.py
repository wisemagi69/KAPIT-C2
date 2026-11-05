"""Concurrency checks need distinct connections to a real PostgreSQL test DB."""
import copy
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.accounts.services import change_password, reset_password, update_user
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.operations.serializers import DecisionSerializer, OperationSerializer, WebOperationSerializer
from apps.operations.worker import binding_for, process_one
from apps.publications.models import Publication
from apps.publications.selectors import feed
from apps.reports.models import Report, ReportRevision, ReportVariant
from apps.reports.services import accept_operation
from apps.review.models import ReviewDecision
from apps.review.services import decide
from apps.scopes.access import lock_identity
from apps.scopes.models import ChannelMember, Organization, SharingChannel, UnitMembership

from .test_workflow import operation


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])
class PostgreSQLConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        self.org = Organization.objects.get(code="SIM-ORG-01")
        self.channel = SharingChannel.objects.get(code="CH-DEMO-01")
        self.submitter = get_user_model().objects.get(username="submitter")
        self.reviewer = get_user_model().objects.get(username="reviewer")
        self.recipient = get_user_model().objects.get(username="recipient")

    def validate_operation(self, body):
        serializer_type = WebOperationSerializer if body.get("expected_revision", 0) > 0 else OperationSerializer
        serializer = serializer_type(data=body); serializer.is_valid(raise_exception=True)
        return serializer.validated_data

    def candidate(self):
        body = operation()
        accept_operation(self.submitter, self.validate_operation(body), body)
        self.assertTrue(process_one())
        return ReportVariant.objects.select_related("revision", "policy").get()

    def test_simultaneous_source_replay_commits_one_revision_job_receipt_audit(self):
        body = operation()
        barrier = threading.Barrier(2)
        def send():
            close_old_connections()
            try:
                user = get_user_model().objects.get(pk=self.submitter.pk)
                validated = self.validate_operation(body)
                barrier.wait(timeout=10)
                return accept_operation(user, validated, body)
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: send(), range(2)))
        self.assertEqual(sorted(created for _, created in results), [False, True])
        self.assertEqual(results[0][0], results[1][0])
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="SOURCE_ACCEPTED").count(), 1)

    def test_two_distinct_decision_operations_have_one_winner(self):
        variant = self.candidate()
        binding = binding_for(variant)
        barrier = threading.Barrier(2)
        def approve():
            close_old_connections()
            try:
                user = get_user_model().objects.get(pk=self.reviewer.pk)
                body = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": copy.deepcopy(binding), "reason": ""}
                serializer = DecisionSerializer(data=body); serializer.is_valid(raise_exception=True)
                barrier.wait(timeout=10)
                try:
                    decide(user, variant.id, serializer.validated_data, body)
                    return "APPROVED"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: approve(), range(2)))
        self.assertEqual(sorted(results), ["APPROVED", "DECISION_CONFLICT"])
        self.assertEqual(Publication.objects.count(), 1)
        self.assertEqual(ReviewDecision.objects.count(), 1)
        self.assertEqual(AuditEvent.objects.filter(action="REVIEW_DECISION").count(), 1)

    def test_read_waiting_for_grant_revocation_never_returns_old_projection(self):
        variant = self.candidate()
        body = {"operation_id": str(uuid.uuid4()), "action": "APPROVE", "expected": binding_for(variant), "reason": ""}
        serializer = DecisionSerializer(data=body); serializer.is_valid(raise_exception=True)
        decide(self.reviewer, variant.id, serializer.validated_data, body)
        reader_started = threading.Event()
        def read():
            close_old_connections()
            try:
                user = get_user_model().objects.get(pk=self.recipient.pk)
                reader_started.set()
                try:
                    with transaction.atomic():
                        actor, org = lock_identity(user)
                        return feed(actor, org, self.channel.id)
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.id)
                pending = executor.submit(read)
                self.assertTrue(reader_started.wait(timeout=10))
                ChannelMember.objects.filter(user=self.recipient).update(revoked_at=timezone.now())
            result = pending.result(timeout=15)
        self.assertEqual(result, "NOT_FOUND")

    def test_two_returned_corrections_have_one_winner_and_retain_original(self):
        variant = self.candidate()
        decision = {"operation_id": str(uuid.uuid4()), "action": "RETURN", "expected": binding_for(variant), "reason": "Correct fictional details."}
        serializer = DecisionSerializer(data=decision); serializer.is_valid(raise_exception=True)
        decide(self.reviewer, variant.id, serializer.validated_data, decision)
        barrier = threading.Barrier(2)

        def correct():
            close_old_connections()
            try:
                user = get_user_model().objects.get(pk=self.submitter.pk)
                body = operation(report_id=str(variant.revision.report_id), expected_revision=1,
                                 correction_reason="Correct the fictional returned maintenance details.")
                data = self.validate_operation(body)
                barrier.wait(timeout=10)
                try:
                    result, created = accept_operation(user, data, body)
                    return result["revision_no"] if created else "REPLAY"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: correct(), range(2)))
        self.assertCountEqual(results, [2, "REVISION_CONFLICT"])
        self.assertEqual(Report.objects.get().current_revision_no, 2)
        for model in [ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 2)
        self.assertEqual(ReviewDecision.objects.count(), 1)
        self.assertFalse(Publication.objects.exists())

    def test_concurrent_account_updates_accept_only_one_expected_version(self):
        administrator_id = get_user_model().objects.get(username="administrator").id
        barrier = threading.Barrier(2)

        def change():
            close_old_connections()
            try:
                actor = get_user_model().objects.get(pk=administrator_id)
                barrier.wait(timeout=10)
                try:
                    update_user(actor, self.submitter.pk, {"display_name": "Edited fictional name", "expected_permission_version": 0})
                    return "UPDATED"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: change(), range(2)))
        self.assertCountEqual(results, ["UPDATED", "STALE_PERMISSIONS"])
        self.submitter.refresh_from_db()
        self.assertEqual(self.submitter.permission_version, 1)
        self.assertEqual(AuditEvent.objects.filter(action="ACCOUNT_ACCESS_CHANGED").count(), 1)

    def test_administrators_cannot_concurrently_disable_each_other(self):
        users = get_user_model()
        first = users.objects.get(username="administrator")
        second = users.objects.create_user(username="second-administrator", organization=self.org,
                                          role="administrator", display_name="Second fictional administrator", password="unused")
        barrier = threading.Barrier(2)

        def disable(pair):
            actor_id, target_id = pair
            close_old_connections()
            try:
                actor = users.objects.get(pk=actor_id)
                barrier.wait(timeout=10)
                try:
                    update_user(actor, target_id, {"is_active": False, "expected_permission_version": 0})
                    return "UPDATED"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(disable, [(first.id, second.id), (second.id, first.id)]))
        self.assertCountEqual(results, ["UPDATED", "ACCESS_DENIED"])
        self.assertEqual(users.objects.filter(organization=self.org, role="administrator", is_active=True).count(), 1)

    def test_self_password_change_and_administrator_reset_cannot_overwrite_each_other(self):
        administrator_id = get_user_model().objects.get(username="administrator").id
        barrier = threading.Barrier(2)

        def change(mode):
            close_old_connections()
            try:
                actor_id = self.submitter.pk if mode == "SELF" else administrator_id
                actor = get_user_model().objects.get(pk=actor_id)
                barrier.wait(timeout=10)
                try:
                    if mode == "SELF":
                        change_password(actor, {"current_password": "DemoMaintenance!2026", "new_password": "FictionalRiver!Changed2026"})
                        return "CHANGED"
                    reset_password(actor, self.submitter.pk, {"password": "FictionalRiver!Reset2026", "expected_permission_version": 0})
                    return "RESET"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(change, ["SELF", "ADMINISTRATOR"]))
        self.assertIn(results, [["CHANGED", "STALE_PERMISSIONS"], ["ACCESS_DENIED", "RESET"]])
        self.submitter.refresh_from_db()
        self.assertEqual(self.submitter.permission_version, 1)
        self.assertEqual(AuditEvent.objects.filter(action__in=["ACCOUNT_PASSWORD_CHANGED", "ACCOUNT_PASSWORD_RESET"]).count(), 1)
