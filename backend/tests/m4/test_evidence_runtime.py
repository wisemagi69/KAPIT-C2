"""Real PostgreSQL/API quarantine tests; no retained DB or real photos.

Parent executes these in its exclusively reserved disposable runtime. Fixtures
are deliberately minimal image boundaries and never represent validated images.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
import struct
from threading import Barrier
import uuid
import zlib
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.urls import include, path
from rest_framework.test import APIClient

from apps.audit.models import AuditEvent
from apps.operations.evidence import LIMITS, accept_evidence, evidence_metadata
from apps.operations.evidence_views import BoundedEvidenceParser
from apps.operations.errors import ApiError
from apps.operations.models import PrivateEvidence, ProcessingJob, SyncReceipt
from apps.reports.crypto import decrypt
from apps.reports.models import Report, ReportRevision
from apps.reports.services import accept_operation
from apps.scopes.models import Organization, UnitMembership
from tests.test_workflow import operation
from tests.mobile import test_upgrade as upgrade
from tests.m3 import test_m3_migrations as m3_upgrade


urlpatterns = [
    path("api/v1/", include("apps.operations.urls")),
    path("api/v1/", include("apps.operations.evidence_urls")),
]
IMAGE = b"\xff\xd8PRIVATE_EVIDENCE_BYTES_CANARY\xff\xd9"
FILENAME = "PRIVATE_FILENAME_CANARY.jpg"
META_KEYS = {"id", "operation_id", "state", "validation_code", "created_at"}
TEST_SETTINGS = {"KAPIT_SOURCE_KEY": Fernet.generate_key(), "ROOT_URLCONF": __name__,
                 "PASSWORD_HASHERS": ["django.contrib.auth.hashers.MD5PasswordHasher"]}


class EvidenceParserTests(SimpleTestCase):
    def test_dedicated_parser_bounds_read_and_preserves_json_limit(self):
        from apps.operations.parsers import BoundedJSONParser
        self.assertEqual(BoundedEvidenceParser().parse(BytesIO(IMAGE)), IMAGE)
        with self.assertRaises(ApiError) as caught:
            BoundedEvidenceParser().parse(BytesIO(b"x" * (LIMITS.max_bytes + 1)))
        self.assertEqual(caught.exception.status_code, 413)
        with self.assertRaises(ApiError) as caught:
            BoundedJSONParser().parse(BytesIO(b" " * (20 * 1024 + 1)))
        self.assertEqual(caught.exception.status_code, 413)


@override_settings(**TEST_SETTINGS)
class EvidenceRuntimeTests(TestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        self.submitter = get_user_model().objects.get(username="submitter")
        self.reviewer = get_user_model().objects.get(username="reviewer")
        self.recipient = get_user_model().objects.get(username="recipient")
        self.administrator = get_user_model().objects.get(username="administrator")
        body = operation()
        receipt, _ = accept_operation(self.submitter, body, body)
        self.revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        self.client = APIClient()
        self.client.raise_request_exception = False
        self.client.force_authenticate(user=self.submitter)

    def upload(self, *, user=None, revision=None, operation_id=None, data=IMAGE, filename=FILENAME, media_type="image/jpeg"):
        return accept_evidence(user or self.submitter, (revision or self.revision).id,
            operation_id or uuid.uuid4(), data, media_type, filename)

    def post(self, *, revision_id=None, operation_id=None, data=IMAGE, filename=FILENAME, media_type="image/jpeg", client=None, **headers):
        return (client or self.client).generic("POST", f"/api/v1/revisions/{revision_id or self.revision.id}/evidence/",
            data=data, content_type=media_type, HTTP_IDEMPOTENCY_KEY=str(operation_id or uuid.uuid4()),
            HTTP_X_EVIDENCE_FILENAME=filename, **headers)

    def test_api_encrypts_bytes_and_filename_returns_private_allowlist_only(self):
        before = (ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count())
        response = self.post()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(set(response.json()), META_KEYS)
        self.assertEqual(response.json()["state"], "QUARANTINED")
        self.assertEqual(response.json()["validation_code"], "DECODER_REQUIRED")
        self.assertIn("no-store", response["Cache-Control"])
        item = PrivateEvidence.objects.get(pk=response.json()["id"])
        envelope = decrypt(item.payload_ciphertext)
        self.assertEqual(envelope["purpose"], "private-evidence-v1")
        self.assertEqual(envelope["filename"], FILENAME)
        self.assertEqual(base64.b64decode(envelope["bytes_base64"]), IMAGE)
        self.assertEqual(envelope["id"], str(item.id))
        self.assertEqual(envelope["revision_id"], str(self.revision.id))
        self.assertEqual(envelope["actor_id"], str(self.submitter.id))
        for value in (b"PRIVATE_EVIDENCE_BYTES_CANARY", FILENAME.encode()):
            self.assertNotIn(value, bytes(item.payload_ciphertext))
            self.assertNotIn(value, response.content)
        self.assertEqual((ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count()), before)
        self.assertEqual(AuditEvent.objects.filter(action="EVIDENCE_QUARANTINED").count(), 1)

    def test_retry_is_same_object_and_changed_bytes_name_or_type_conflicts(self):
        op = uuid.uuid4()
        first = self.post(operation_id=op)
        again = self.post(operation_id=op)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(again.status_code, 200)
        self.assertEqual(again.json(), first.json())
        for changes in ({"data": b"\xff\xd8different\xff\xd9"}, {"filename": "different.jpg"}, {"media_type": "image/png"}):
            with self.subTest(changes=changes):
                response = self.post(operation_id=op, **changes)
                self.assertEqual(response.status_code, 409)
                self.assertEqual(response.json()["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(PrivateEvidence.objects.count(), 1)

    def test_two_per_revision_and_retry_survives_capacity(self):
        first_op = uuid.uuid4()
        first, _ = self.upload(operation_id=first_op)
        self.upload()
        with self.assertRaises(ApiError) as caught:
            self.upload()
        self.assertEqual(caught.exception.safe_body["code"], "EVIDENCE_LIMIT")
        replay, created = self.upload(operation_id=first_op)
        self.assertFalse(created)
        self.assertEqual(first, replay)
        self.assertEqual(set(PrivateEvidence.objects.values_list("slot", flat=True)), {1, 2})

    def test_audit_and_encryption_failures_roll_back_only_evidence_not_text(self):
        before = (ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count())
        with patch("apps.operations.evidence.audit.record", side_effect=RuntimeError("private canary")):
            with self.assertRaises(RuntimeError):
                self.upload()
        self.assertEqual(PrivateEvidence.objects.count(), 0)
        with patch("apps.operations.evidence.encrypt", side_effect=RuntimeError("private canary")):
            response = self.post()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "EVIDENCE_UNAVAILABLE")
        self.assertNotIn(b"private canary", response.content)
        self.assertEqual(PrivateEvidence.objects.count(), 0)
        self.assertEqual((ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count()), before)
        self.upload()

    def test_author_reviewer_metadata_and_current_scope_denials_uniform(self):
        item, _ = self.upload()
        evidence_id = uuid.UUID(item["id"])
        for user in (self.submitter, self.reviewer):
            self.assertEqual(evidence_metadata(user, evidence_id), item)
        other_org = Organization.objects.create(code="EVIDENCE-OTHER", name="Synthetic other")
        outsider = get_user_model().objects.create(username="evidence-other", organization=other_org, role="submitter")
        same_org_other = get_user_model().objects.create(username="evidence-sibling", organization=self.submitter.organization, role="submitter")
        for user in (self.recipient, self.administrator, outsider, same_org_other):
            self.client.force_authenticate(user=user)
            for attempted_id in (evidence_id, uuid.uuid4()):
                response = self.client.get(f"/api/v1/evidence/{attempted_id}/")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json(), {"code": "NOT_FOUND", "message": "This item is unavailable."})
            for revision_id in (self.revision.id, uuid.uuid4()):
                response = self.post(revision_id=revision_id)
                self.assertEqual(response.status_code, 404)
        UnitMembership.objects.filter(user=self.reviewer).update(active=False)
        with self.assertRaises(ApiError) as caught:
            evidence_metadata(self.reviewer, evidence_id)
        self.assertEqual(caught.exception.status_code, 404)

    def test_no_download_for_any_role_or_unknown_object(self):
        item, _ = self.upload()
        for user in (self.submitter, self.reviewer, self.recipient, self.administrator):
            self.client.force_authenticate(user=user)
            for evidence_id in (item["id"], uuid.uuid4()):
                response = self.client.get(f"/api/v1/evidence/{evidence_id}/download/")
                self.assertEqual(response.status_code, 404)
                self.assertEqual(response.json(), {"code": "NOT_FOUND", "message": "This item is unavailable."})
                self.assertNotIn(b"PRIVATE_", response.content)

    def test_invalid_empty_type_filename_dimension_or_large_bytes_never_persist(self):
        for changes in ({"data": b""}, {"data": b"bad"}, {"media_type": "application/json"},
                        {"filename": "../private.jpg"}, {"filename": "CON.jpg"}):
            with self.subTest(changes=changes):
                response = self.post(**changes)
                self.assertEqual(response.status_code, 400)
                self.assertNotIn(b"PRIVATE_", response.content)
        ihdr = b"IHDR" + struct.pack(">IIBBBBB", 6001, 2, 8, 2, 0, 0, 0)
        png = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\r" + ihdr + struct.pack(">I", zlib.crc32(ihdr))
        self.assertEqual(self.post(data=png, filename="synthetic.png", media_type="image/png").status_code, 400)
        response = self.post(data=b"x" * (LIMITS.max_bytes + 1))
        self.assertEqual(response.status_code, 413)
        self.assertEqual(PrivateEvidence.objects.count(), 0)

    def test_binary_body_above_json_cap_accepted_without_weakening_json(self):
        from django.conf import settings
        self.assertEqual(settings.DATA_UPLOAD_MAX_MEMORY_SIZE, 20 * 1024)
        response = self.post(data=b"\xff\xd8" + b"synthetic" * 4000 + b"\xff\xd9")
        self.assertEqual(response.status_code, 201)
        json_response = self.client.generic("POST", "/api/v1/sync/operations/", data=b" " * (20 * 1024 + 1), content_type="application/json")
        self.assertEqual(json_response.status_code, 413)

    def test_exact_five_mib_binary_boundary_stays_quarantined(self):
        response = self.post(data=b"\xff\xd8" + b"x" * (LIMITS.max_bytes - 4) + b"\xff\xd9")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["state"], "QUARANTINED")
        self.assertEqual(PrivateEvidence.objects.get().byte_size, LIMITS.max_bytes)

    def test_real_session_requires_csrf_and_unauthenticated_request_fails(self):
        client = APIClient(enforce_csrf_checks=True)
        self.assertEqual(self.post(client=client).status_code, 403)
        client.force_login(self.submitter)
        self.assertEqual(self.post(client=client).status_code, 403)
        token = client.get("/api/v1/auth/csrf/").json()["csrf_token"]
        response = self.post(client=client, HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 201)

    def test_metadata_audit_failure_does_not_return_success(self):
        item, _ = self.upload()
        with patch("apps.operations.evidence.audit.record", side_effect=RuntimeError("private canary")):
            response = self.client.get(f"/api/v1/evidence/{item['id']}/")
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b"private canary", response.content)

    def test_current_revision_required_but_exact_old_replay_preserved(self):
        op = uuid.uuid4()
        before, _ = self.upload(operation_id=op)
        report = self.revision.report
        report.current_revision_no = 2
        report.save(update_fields=["current_revision_no"])
        replay, created = self.upload(operation_id=op)
        self.assertFalse(created)
        self.assertEqual(replay, before)
        with self.assertRaises(ApiError) as caught:
            self.upload()
        self.assertEqual(caught.exception.safe_body["code"], "REVISION_CONFLICT")

    def test_same_operation_cannot_be_rebound_to_another_author_owned_revision(self):
        op = uuid.uuid4()
        self.upload(operation_id=op)
        body = operation()
        receipt, _ = accept_operation(self.submitter, body, body)
        other_revision = ReportRevision.objects.get(pk=receipt["revision_id"])
        with self.assertRaises(ApiError) as caught:
            self.upload(operation_id=op, revision=other_revision)
        self.assertEqual(caught.exception.safe_body["code"], "IDEMPOTENCY_CONFLICT")
        self.assertEqual(PrivateEvidence.objects.count(), 1)

    def test_existing_source_and_recipient_surfaces_do_not_add_evidence_fields(self):
        item, _ = self.upload()
        source = self.client.get(f"/api/v1/reports/{self.revision.report_id}/revisions/1/")
        self.assertEqual(source.status_code, 200)
        self.assertNotIn(item["id"].encode(), source.content)
        self.assertNotIn(b"evidence", source.content)
        self.client.force_authenticate(user=self.recipient)
        from apps.scopes.models import SharingChannel
        channel_id = SharingChannel.objects.get(code="CH-DEMO-01").id
        feed = self.client.get(f"/api/v1/channels/{channel_id}/feed/")
        self.assertEqual(feed.status_code, 200)
        for forbidden in (item["id"].encode(), b"evidence", b"PRIVATE_EVIDENCE_BYTES_CANARY", FILENAME.encode()):
            self.assertNotIn(forbidden, feed.content)

    def test_database_immutable_constraints_owner_and_no_delete(self):
        result, _ = self.upload()
        item = PrivateEvidence.objects.get(pk=result["id"])
        for field, value in (("state", "VALIDATED_PRIVATE"), ("uploaded_by_id", self.reviewer.id),
                             ("request_hash", "a" * 64), ("payload_ciphertext", b"different")):
            with self.subTest(field=field), self.assertRaises(DatabaseError), transaction.atomic():
                PrivateEvidence.objects.filter(pk=item.id).update(**{field: value})
        with self.assertRaises(DatabaseError), transaction.atomic():
            PrivateEvidence.objects.filter(pk=item.id).delete()
        fields = {"organization_id": item.organization_id, "revision_id": item.revision_id,
            "uploaded_by_id": item.uploaded_by_id, "operation_id": uuid.uuid4(), "request_hash": "a" * 64,
            "payload_ciphertext": b"encrypted synthetic placeholder", "media_type": "image/jpeg", "byte_size": 10, "slot": 2}
        for overrides in ({"uploaded_by_id": self.reviewer.id}, {"slot": 3}, {"byte_size": 0}, {"byte_size": LIMITS.max_bytes + 1},
                          {"request_hash": "bad"}, {"payload_ciphertext": b""}, {"state": "VALIDATED_PRIVATE"},
                          {"validation_code": "SCANNER_POLICY_REQUIRED"}, {"media_type": "text/plain"}, {"key_id": "wrong"},
                          {"slot": 1}, {"operation_id": item.operation_id}):
            with self.subTest(overrides=overrides), self.assertRaises(DatabaseError), transaction.atomic():
                PrivateEvidence.objects.create(**(fields | overrides))
        other_org = Organization.objects.create(code="EVIDENCE-CROSS-LINK", name="Synthetic cross-link")
        with self.assertRaises(DatabaseError), transaction.atomic():
            PrivateEvidence.objects.create(**(fields | {"organization_id": other_org.id}))
        self.assertEqual(PrivateEvidence.objects.count(), 1)


@override_settings(**TEST_SETTINGS)
class EvidenceConcurrencyTests(TransactionTestCase):
    def setUp(self):
        self.assertEqual(connection.vendor, "postgresql")
        call_command("seed_demo", verbosity=0)
        self.actor = get_user_model().objects.get(username="submitter")
        body = operation()
        response, _ = accept_operation(self.actor, body, body)
        self.revision_id = uuid.UUID(response["revision_id"])

    def run_upload(self, operation_id):
        close_old_connections()
        try:
            user = get_user_model().objects.get(pk=self.actor.id)
            self.barrier.wait(timeout=10)
            result, created = accept_evidence(user, self.revision_id, operation_id, IMAGE, "image/jpeg", FILENAME)
            return result["id"], created
        except ApiError as exc:
            return exc.safe_body["code"], False
        finally:
            close_old_connections()

    def test_concurrent_identical_operation_has_one_committed_identity(self):
        op = uuid.uuid4()
        self.barrier = Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(self.run_upload, [op, op]))
        self.assertEqual(results[0][0], results[1][0])
        self.assertEqual(sum(created for _, created in results), 1)
        self.assertEqual(PrivateEvidence.objects.count(), 1)

    def test_concurrent_third_object_is_rejected_without_exceeding_cap(self):
        self.barrier = Barrier(3)
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(self.run_upload, [uuid.uuid4() for _ in range(3)]))
        self.assertEqual(sum(created for _, created in results), 2)
        self.assertEqual(sum(value == "EVIDENCE_LIMIT" for value, _ in results), 1)
        self.assertEqual(PrivateEvidence.objects.count(), 2)


@override_settings(**TEST_SETTINGS)
class EvidenceMigrationTests(TransactionTestCase):
    def test_m3_forward_preserves_rows_functions_and_installs_new_constraints(self):
        self.assertEqual(connection.vendor, "postgresql")
        with upgrade.owned_upgrade_schema() as (_, schema_oid):
            executor = MigrationExecutor(connection)
            # Freeze this exact evidence upgrade; later audit heads are tested separately.
            m4_targets = [(app, "0001_initial" if app == "audit" else "0006_private_evidence" if app == "operations" else name)
                          for app, name in executor.loader.graph.leaf_nodes()]
            m3_targets = [(app, "0005_m3_guards" if app == "operations" else name) for app, name in m4_targets]
            executor.migrate(m3_targets)
            m3_apps = executor.loader.project_state(m3_targets).apps
            user_id, _, receipt = upgrade.MobileAcceptedM1UpgradeTests.seed_historical_acceptance(m3_apps)
            before = upgrade.MobileAcceptedM1UpgradeTests.snapshot(m3_apps)
            functions_before = m3_upgrade.functions(schema_oid)
            triggers_before = m3_upgrade.triggers(schema_oid)
            executor = MigrationExecutor(connection)
            self.assertEqual({(m.app_label, m.name, backwards) for m, backwards in executor.migration_plan(m4_targets)},
                             {("operations", "0006_private_evidence", False)})
            executor.migrate(m4_targets)
            m4_apps = executor.loader.project_state(m4_targets).apps
            self.assertEqual(upgrade.MobileAcceptedM1UpgradeTests.snapshot(m4_apps), before)
            after_functions = m3_upgrade.functions(schema_oid)
            self.assertEqual({key: after_functions[key] for key in functions_before}, functions_before)
            self.assertIn("kapit_evidence_source_guard", after_functions)
            added = m3_upgrade.triggers(schema_oid) - triggers_before
            self.assertEqual(added, {("operations_privateevidence", name) for name in ("a_evidence_org", "b_evidence_frozen", "c_evidence_source")})
            model = m4_apps.get_model("operations", "PrivateEvidence")
            actor = m4_apps.get_model("accounts", "User").objects.get(pk=user_id)
            fields = dict(organization_id=actor.organization_id, revision_id=receipt["revision_id"], uploaded_by_id=user_id,
                operation_id=uuid.uuid4(), request_hash="a" * 64, payload_ciphertext=b"encrypted synthetic placeholder",
                media_type="image/jpeg", byte_size=10, slot=1)
            item = model.objects.create(**fields)
            with self.assertRaises(DatabaseError), transaction.atomic():
                model.objects.create(**(fields | {"operation_id": uuid.uuid4(), "slot": 3}))
            with self.assertRaises(DatabaseError), transaction.atomic():
                model.objects.filter(pk=item.pk).update(state="VALIDATED_PRIVATE")
            # Reversal cannot drop populated evidence history, even in a sandbox.
            with self.assertRaisesRegex(RuntimeError, "destructive reversal is refused"):
                MigrationExecutor(connection).migrate(m3_targets)
            self.assertEqual(model.objects.count(), 1)
            self.assertEqual(upgrade.MobileAcceptedM1UpgradeTests.snapshot(m4_apps), before)
