"""Forward-only accepted-M1 upgrade inside an exclusively owned test schema.

No retained database or existing schema is adopted, migrated backward or wiped.
The surrounding BrowserAcceptanceRunner already owns this disposable database.
"""
from contextlib import contextmanager
import uuid

from django.contrib.auth.hashers import make_password
from django.db import connection, DatabaseError, transaction
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from apps.accounts.models import User
from apps.operations.models import SyncReceipt
from apps.operations.serializers import OperationSerializer
from apps.reports.canonical import digest
from apps.reports.crypto import encrypt, source_payload
from apps.reports.models import ReportRevision
from apps.reports.projection import RULES
from apps.reports.selectors import authorized_receipt
from apps.reports.services import accept_operation
from tests.browser_runner import preserve_database
from tests.test_workflow import operation
from .helpers import MOBILE_SETTINGS, PASSWORD


@contextmanager
def owned_upgrade_schema():
    if connection.vendor != "postgresql":
        raise AssertionError("Upgrade verification requires PostgreSQL.")
    schema = "kapit_upgrade_"+uuid.uuid4().hex
    quoted = connection.ops.quote_name(schema)
    owned_oid = None
    created = False
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_setting('search_path')")
        database, previous_path = cursor.fetchone()
        if database != "test_kapit_m1":
            raise AssertionError("Upgrade database identity denied.")
        cursor.execute("SELECT oid FROM pg_namespace WHERE nspname = %s", [schema])
        if cursor.fetchone() is not None:
            raise AssertionError("Upgrade schema already exists; no adoption.")
    try:
        with connection.cursor() as cursor:
            # The random identifier is generated here, checked absent and quoted.
            cursor.execute("CREATE SCHEMA "+quoted)
            created = True
            cursor.execute("SELECT oid FROM pg_namespace WHERE nspname = %s", [schema])
            owned_oid = cursor.fetchone()[0]
            cursor.execute("SELECT set_config('search_path', %s, false)", [quoted])
            cursor.execute("SELECT current_schema(), current_schemas(false)")
            current, schemas = cursor.fetchone()
            if current != schema or schemas != [schema]:
                raise AssertionError("Upgrade search path isolation failed.")
        yield schema, owned_oid
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT set_config('search_path', %s, false)", [previous_path])
                cursor.execute("SELECT current_database()")
                if cursor.fetchone()[0] != "test_kapit_m1":
                    raise AssertionError("Upgrade cleanup database identity denied.")
                if created and owned_oid is None:
                    raise AssertionError("Upgrade cleanup ownership was not recorded.")
                if owned_oid is not None:
                    cursor.execute("SELECT oid FROM pg_namespace WHERE nspname = %s", [schema])
                    row = cursor.fetchone()
                    if row != (owned_oid,):
                        raise AssertionError("Upgrade cleanup schema identity denied.")
                    cursor.execute("DROP SCHEMA "+quoted+" CASCADE")
        except Exception:
            # Never let uncertainty trigger a broader runner cleanup instead.
            preserve_database()
            raise


@override_settings(**MOBILE_SETTINGS)
class MobileAcceptedM1UpgradeTests(TransactionTestCase):
    @staticmethod
    def seed_historical_acceptance(apps):
        Org = apps.get_model("scopes", "Organization")
        Unit = apps.get_model("scopes", "Unit")
        Channel = apps.get_model("scopes", "SharingChannel")
        Membership = apps.get_model("scopes", "UnitMembership")
        Source = apps.get_model("scopes", "ChannelSource")
        Policy = apps.get_model("scopes", "PolicyVersion")
        HistoricalUser = apps.get_model("accounts", "User")
        Report = apps.get_model("reports", "Report")
        Revision = apps.get_model("reports", "ReportRevision")
        Job = apps.get_model("operations", "ProcessingJob")
        Receipt = apps.get_model("operations", "SyncReceipt")
        Audit = apps.get_model("audit", "AuditEvent")
        org = Org.objects.create(code="UPGRADE-SYNTHETIC", name="Synthetic upgrade organization")
        unit = Unit.objects.create(organization=org, code="UPGRADE-UNIT", name="Synthetic upgrade unit")
        channel = Channel.objects.create(organization=org, code="UPGRADE-CHANNEL", name="Synthetic upgrade channel")
        user = HistoricalUser.objects.create(organization=org, username="upgrade-synthetic", display_name="Synthetic owner",
            role="submitter", password=make_password(PASSWORD), is_active=True)
        Membership.objects.create(organization=org, user=user, unit=unit, role="submitter")
        Source.objects.create(organization=org, unit=unit, channel=channel)
        policy = Policy.objects.create(organization=org, version="demo-policy-v1", active=True, rules=RULES, rules_hash=digest(RULES))
        org.active_policy = policy
        org.save(update_fields=["active_policy"])
        body = operation()
        report = Report.objects.create(id=body["report_id"], organization=org, author=user, unit=unit)
        revision = Revision.objects.create(organization=org, report=report, submitted_by=user, revision_no=1,
            template_version=body["template_version"], observed_at=parse_datetime(body["payload"]["observed_at"]),
            payload_ciphertext=encrypt(body["payload"]), content_digest=digest(body["payload"]), operation_id=body["operation_id"],
            request_hash=digest({"route": "POST /sync/operations/", "body": body}))
        Job.objects.create(organization=org, revision=revision, policy=policy, channel_ids=[str(channel.id)], available_at=timezone.now())
        response = {"operation_id": body["operation_id"], "report_id": body["report_id"], "revision_id": str(revision.id),
            "revision_no": 1, "delivery_status": "RECEIVED", "processing_status": "PENDING", "shared": False}
        Receipt.objects.create(organization=org, accepted_user=user, operation_id=body["operation_id"], request_hash=revision.request_hash,
            revision=revision, response_body=response)
        Audit.objects.create(organization=org, actor=user, action="SOURCE_ACCEPTED", target_id=report.id, outcome="ALLOWED",
            safe_metadata={"operation_id": body["operation_id"], "revision_no": 1})
        return user.id, body, response

    @staticmethod
    def snapshot(apps):
        result = {}
        for app, model in [("accounts", "User"), ("scopes", "Organization"), ("scopes", "Unit"),
            ("scopes", "SharingChannel"), ("scopes", "UnitMembership"), ("scopes", "ChannelSource"),
            ("scopes", "PolicyVersion"), ("reports", "Report"), ("reports", "ReportRevision"),
            ("operations", "ProcessingJob"), ("operations", "SyncReceipt"), ("audit", "AuditEvent")]:
            rows = []
            for row in apps.get_model(app, model).objects.order_by("id").values():
                row.pop("accepted_device_id", None)
                rows.append({key: bytes(value) if isinstance(value, memoryview) else value for key, value in row.items()})
            result[app+"."+model] = rows
        return result

    def test_forward_upgrade_preserves_m1_ciphertexts_hashes_receipts_and_guards(self):
        with owned_upgrade_schema() as (_, schema_oid):
            executor = MigrationExecutor(connection)
            # TASK-122: this test verifies the accepted M1 -> M2 upgrade; M3 is covered in tests/m3.
            m2_leaves = {"accounts": "0003_mobile_identity", "scopes": "0003_preserve_grant_history", "operations": "0003_device_origin",
                "reports": "0003_device_origin", "review": "0001_initial", "publications": "0001_initial",
                "audit": "0001_initial"}
            final_targets = [(app, m2_leaves.get(app, name)) for app, name in executor.loader.graph.leaf_nodes()]
            replacements = {"accounts": "0002_administrator_role", "reports": "0002_variants", "operations": "0002_integrity_guards"}
            m1_targets = [(app, replacements.get(app, name)) for app, name in final_targets]
            plan = executor.migration_plan(m1_targets)
            self.assertTrue(plan)
            self.assertFalse(any(backwards for _, backwards in plan))
            executor.migrate(m1_targets)
            historical_apps = executor.loader.project_state(m1_targets).apps
            user_id, body, original_receipt = self.seed_historical_acceptance(historical_apps)
            before = self.snapshot(historical_apps)
            with connection.cursor() as cursor:
                cursor.execute("SELECT proname, pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace = %s", [schema_oid])
                old_guards = dict(cursor.fetchall())
            self.assertIn("kapit_source_link_guard", old_guards)
            self.assertIn("kapit_frozen_guard", old_guards)

            executor = MigrationExecutor(connection)
            plan = executor.migration_plan(final_targets)
            self.assertFalse(any(backwards for _, backwards in plan))
            self.assertEqual({(migration.app_label, migration.name) for migration, _ in plan},
                {("accounts", "0003_mobile_identity"), ("reports", "0003_device_origin"), ("operations", "0003_device_origin")})
            executor.migrate(final_targets)
            current_apps = executor.loader.project_state(final_targets).apps
            self.assertEqual(self.snapshot(current_apps), before, "Historical row comparison failed.")
            with connection.cursor() as cursor:
                cursor.execute("SELECT proname, pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace = %s", [schema_oid])
                current_guards = dict(cursor.fetchall())
            self.assertTrue(all(current_guards.get(name) == definition for name, definition in old_guards.items()))
            self.assertIn("kapit_revision_device_guard", current_guards)
            self.assertIn("kapit_receipt_device_guard", current_guards)
            # The checks below use the current ORM, so finish at the real leaves (TASK-122); M3 itself is verified in tests/m3.
            MigrationExecutor(connection).migrate(executor.loader.graph.leaf_nodes())
            self.assertIsNone(ReportRevision.objects.get().accepted_device_id)
            self.assertIsNone(SyncReceipt.objects.get().accepted_device_id)
            self.assertEqual(source_payload(ReportRevision.objects.get()), body["payload"])

            # Real web-service replay of the pre-upgrade accepted request; HTTP
            # web compatibility is tested separately on the normal test schema.
            owner = User.objects.get(pk=user_id)
            serializer = OperationSerializer(data=body)
            serializer.is_valid(raise_exception=True)
            replay, created = accept_operation(owner, serializer.validated_data, body)
            self.assertFalse(created)
            self.assertEqual(replay, original_receipt)
            with transaction.atomic():
                self.assertEqual(authorized_receipt(owner, body["operation_id"]), original_receipt)
            self.assertEqual(self.snapshot(current_apps), before, "Web replay mutated historical acceptance.")
            with self.assertRaises(DatabaseError), transaction.atomic():
                ReportRevision.objects.all().update(request_hash="f"*64)
            self.assertEqual(self.snapshot(current_apps), before)
