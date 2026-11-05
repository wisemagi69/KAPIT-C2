"""Independent PostgreSQL connections prove commit ordering and linearization."""
from concurrent.futures import ThreadPoolExecutor
import threading
import secrets
import uuid

from django.db import close_old_connections, transaction
from django.test import TransactionTestCase, override_settings

from apps.accounts.models import DeviceEnrollment, DeviceFamily, MobileChallenge, RefreshCredential, User
from apps.accounts.mobile_protocol import decode_access, encode64
from apps.accounts.mobile_services import lock_mobile_identity, mobile_context, revoke_device
from apps.audit.models import AuditEvent
from apps.operations.errors import ApiError
from apps.operations.models import ProcessingJob, SyncReceipt
from apps.operations.serializers import OperationSerializer
from apps.reports.models import Report, ReportRevision
from apps.reports.services import accept_operation
from apps.scopes.models import Organization
from tests.test_workflow import operation
from .helpers import MOBILE, MOBILE_SETTINGS, MobileFixtures


@override_settings(**MOBILE_SETTINGS)
class MobileRaceTests(MobileFixtures, TransactionTestCase):
    def concurrent_posts(self, path, bodies):
        barrier = threading.Barrier(len(bodies))
        def send(body):
            close_old_connections()
            try:
                client = self.api()
                barrier.wait(timeout=10)
                response = client.post(MOBILE+path, body, format="json")
                return response.status_code, response.json()
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=len(bodies)) as executor:
            pending = [executor.submit(send, body) for body in bodies]
            return [future.result(timeout=25) for future in pending]

    def test_simultaneous_proof_commits_one_enrollment_family_and_credential(self):
        proof = self.proof_body(self.challenge())
        results = self.concurrent_posts("auth/token/", [proof, proof])
        self.assertEqual(sorted(code for code, _ in results), [200, 401])
        for model in [DeviceEnrollment, DeviceFamily, RefreshCredential]:
            self.assertEqual(model.objects.count(), 1)
        self.assertIsNotNone(MobileChallenge.objects.get().consumed_at)
        self.assertEqual(AuditEvent.objects.filter(action="MOBILE_AUTHENTICATED").count(), 1)

    def test_cross_organization_same_public_key_race_commits_only_one_binding(self):
        other = self.another_owner()
        first = self.proof_body(self.challenge())
        second = self.proof_body(self.challenge(owner=other, installation=str(uuid.uuid4())))
        results = self.concurrent_posts("auth/token/", [first, second])
        self.assertEqual(sorted(code for code, _ in results), [200, 403])
        for model in [DeviceEnrollment, DeviceFamily, RefreshCredential]:
            self.assertEqual(model.objects.count(), 1)
        self.assertEqual(MobileChallenge.objects.filter(consumed_at__isnull=False).count(), 2)
        denied = next(body for code, body in results if code == 403)
        self.assertEqual(set(denied), {"code", "message"})
        self.assertEqual(denied["code"], "ACCESS_DENIED")

    def test_concurrent_refresh_replay_commits_family_revocation(self):
        session = self.enroll()
        body = {"refresh_token": session["refresh_token"]}
        results = self.concurrent_posts("auth/refresh/", [body, body])
        self.assertEqual(sorted(code for code, _ in results), [200, 401])
        self.assertEqual(next(body for code, body in results if code == 401)["code"], "REFRESH_REUSED")
        self.assertIsNotNone(DeviceFamily.objects.get().revoked_at)
        self.assertEqual(RefreshCredential.objects.count(), 2)
        winner = next(body for code, body in results if code == 200)
        self.assert_auth_denied(self.me(winner))
        self.assertEqual(AuditEvent.objects.filter(action="MOBILE_REFRESH_REUSED").count(), 1)

    def test_revocation_wins_against_previously_authenticated_source_adapter(self):
        # TASK-058 proves the service boundary using existing acceptance. The
        # actual mobile-origin route/receipt race is a separate TASK-059 gate.
        session = self.enroll()
        claims = decode_access(session["access_token"])
        body = operation()
        serializer = OperationSerializer(data=body)
        serializer.is_valid(raise_exception=True)
        started = threading.Event()
        def submit_after_authentication():
            close_old_connections()
            try:
                started.set()
                try:
                    with transaction.atomic():
                        actor, _, _, _ = lock_mobile_identity(claims)
                        accept_operation(actor, serializer.validated_data, body)
                        return "ACCEPTED"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.id)
                pending = executor.submit(submit_after_authentication)
                self.assertTrue(started.wait(timeout=10))
                revoke_device(self.owner, session["context"]["enrollment_id"])
            result = pending.result(timeout=20)
        self.assertEqual(result, "AUTH_REQUIRED")
        for model in [Report, ReportRevision, ProcessingJob, SyncReceipt]:
            self.assertEqual(model.objects.count(), 0)

    def test_read_waiting_for_owner_revoke_cannot_return_stale_context(self):
        session = self.enroll()
        claims = decode_access(session["access_token"])
        started = threading.Event()
        def read():
            close_old_connections()
            try:
                started.set()
                try:
                    mobile_context(claims)
                    return "ACCEPTED"
                except ApiError as exc:
                    return exc.safe_body["code"]
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=1) as executor:
            with transaction.atomic():
                Organization.objects.select_for_update().get(pk=self.org.id)
                pending = executor.submit(read)
                self.assertTrue(started.wait(timeout=10))
                revoke_device(self.owner, session["context"]["enrollment_id"])
            result = pending.result(timeout=20)
        self.assertEqual(result, "AUTH_REQUIRED")

    def test_invalid_proof_consumption_survives_real_request_commit(self):
        challenge = self.challenge()
        body = dict(self.proof_body(challenge), signature="invalid")
        response = self.client.post(MOBILE+"auth/token/", body, format="json")
        self.assert_auth_denied(response)
        close_old_connections()
        self.assertIsNotNone(MobileChallenge.objects.get().consumed_at)
        self.assertEqual(DeviceFamily.objects.count(), 0)

    def _set_identity_active(self, kind, active):
        with transaction.atomic():
            org = Organization.objects.select_for_update().get(pk=self.org.id)
            owner = User.objects.select_for_update().get(pk=self.owner.id)
            if kind == "organization":
                org.active = active
                org.save(update_fields=["active"])
            else:
                owner.is_active = active
                owner.save(update_fields=["is_active"])

    def _assert_inactive_replay_stays_revoked_after_reactivation(self, kind):
        original = self.enroll()
        rotated = self.refresh(original)
        self.assertEqual(rotated.status_code, 200)
        successor = rotated.json()
        self._set_identity_active(kind, False)

        # A guessed secret for a real consumed handle must not revoke anything.
        guessed = dict(original, refresh_token=original["refresh_token"].split(".")[0]+"."+encode64(secrets.token_bytes(32)))
        self.assert_auth_denied(self.refresh(guessed))
        self.assertIsNone(DeviceFamily.objects.get().revoked_at)
        self.assertEqual(AuditEvent.objects.filter(action="MOBILE_REFRESH_REUSED").count(), 0)

        # Current authority is still required for unconsumed refresh/access.
        self.assert_auth_denied(self.refresh(successor))
        self.assert_auth_denied(self.me(successor))
        self.assertEqual(RefreshCredential.objects.count(), 2)
        self.assertIsNone(RefreshCredential.objects.get(generation=1).consumed_at)

        self.assert_auth_denied(self.refresh(original), "REFRESH_REUSED")
        # Observe the completed HTTP request's transition from an independent
        # PostgreSQL connection, not an enclosing test transaction/savepoint.
        def observe_commit():
            close_old_connections()
            try:
                return (DeviceFamily.objects.get().revoked_at,
                    AuditEvent.objects.filter(action="MOBILE_REFRESH_REUSED").count())
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=1) as executor:
            revoked_at, audit_count = executor.submit(observe_commit).result(timeout=15)
        self.assertIsNotNone(revoked_at)
        self.assertEqual(audit_count, 1)

        self._set_identity_active(kind, True)
        self.assert_auth_denied(self.me(successor))
        self.assert_auth_denied(self.refresh(successor))
        self.assert_auth_denied(self.refresh(original), "REFRESH_REUSED")
        self.assertEqual(DeviceFamily.objects.get().revoked_at, revoked_at)
        self.assertEqual(AuditEvent.objects.filter(action="MOBILE_REFRESH_REUSED").count(), 1)
        self.assertEqual(RefreshCredential.objects.count(), 2)

    def test_consumed_refresh_replay_during_inactive_org_survives_reactivation(self):
        self._assert_inactive_replay_stays_revoked_after_reactivation("organization")

    def test_consumed_refresh_replay_during_inactive_owner_survives_reactivation(self):
        self._assert_inactive_replay_stays_revoked_after_reactivation("owner")
