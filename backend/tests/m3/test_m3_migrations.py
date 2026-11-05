"""TASK-122: M2 -> M3 forward preservation, exact reverse restore and the abort-only vocabulary pre-check.

Runs inside an exclusively owned random schema of the guarded test database (tests/mobile/test_upgrade.py);
no retained database is adopted, migrated backward or wiped.
"""
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

from tests.mobile.helpers import MOBILE_SETTINGS
from tests.mobile.test_upgrade import MobileAcceptedM1UpgradeTests, owned_upgrade_schema

M2_LEAVES = {"accounts": "0003_mobile_identity", "scopes": "0003_preserve_grant_history", "operations": "0003_device_origin",
             "reports": "0003_device_origin", "review": "0001_initial", "publications": "0001_initial", "audit": "0001_initial"}
M3_LEAVES = {"accounts": "0004_m3_integration_clients", "scopes": "0004_m3_scope_profiles",
             "operations": "0005_m3_guards", "reports": "0004_m3_variants_corrections",
             "review": "0002_m3_decision_batch", "publications": "0002_m3_lifecycle", "audit": "0001_initial"}
M3_MIGRATIONS = {("scopes", "0004_m3_scope_profiles"), ("accounts", "0004_m3_integration_clients"), ("operations", "0004_m3_scope_context"),
                 ("reports", "0004_m3_variants_corrections"), ("review", "0002_m3_decision_batch"), ("publications", "0002_m3_lifecycle"),
                 ("operations", "0005_m3_guards")}
REPLACED = {"kapit_source_link_guard", "kapit_decision_guard", "kapit_publication_guard"}
ADDED = {"kapit_profile_rank", "kapit_scope_context", "kapit_context_channels", "kapit_epoch_guard", "kapit_has_authority",
         "kapit_policy_activation_guard", "kapit_client_approval_guard", "kapit_client_issue_guard", "kapit_client_revocation_guard"}


def functions(schema_oid):
    with connection.cursor() as cursor:
        cursor.execute("SELECT proname, pg_get_functiondef(oid) FROM pg_proc WHERE pronamespace = %s", [schema_oid])
        return dict(cursor.fetchall())


def triggers(schema_oid):
    with connection.cursor() as cursor:
        cursor.execute("SELECT c.relname, t.tgname FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid "
                       "WHERE c.relnamespace = %s AND NOT t.tgisinternal", [schema_oid])
        return set(cursor.fetchall())


def common(snapshot, before):
    """Only the columns that existed before; new M3 columns are checked separately."""
    return {table: [{key: row[key] for key in (before[table][0] if before[table] else row)} for row in rows] for table, rows in snapshot.items()}


@override_settings(**MOBILE_SETTINGS)
class M3MigrationTests(TransactionTestCase):
    seed = staticmethod(MobileAcceptedM1UpgradeTests.seed_historical_acceptance)
    snapshot = staticmethod(MobileAcceptedM1UpgradeTests.snapshot)

    def targets(self, executor):
        leaves = executor.loader.graph.leaf_nodes()
        # Later additive M4 heads must not silently widen this exact M2->M3 test.
        return ([(app, M2_LEAVES.get(app, name)) for app, name in leaves],
                [(app, M3_LEAVES.get(app, name)) for app, name in leaves])

    def test_forward_preserves_m2_rows_and_reverse_restores_the_exact_m2_guards(self):
        with owned_upgrade_schema() as (_, schema_oid):
            executor = MigrationExecutor(connection)
            m2_targets, m3_targets = self.targets(executor)
            executor.migrate(m2_targets)
            m2_apps = executor.loader.project_state(m2_targets).apps
            self.seed(m2_apps)
            before = self.snapshot(m2_apps)
            m2_functions, m2_triggers = functions(schema_oid), triggers(schema_oid)
            self.assertTrue(REPLACED <= set(m2_functions))

            executor = MigrationExecutor(connection)
            plan = executor.migration_plan(m3_targets)
            self.assertFalse(any(backwards for _, backwards in plan))
            self.assertEqual({(migration.app_label, migration.name) for migration, _ in plan}, M3_MIGRATIONS)
            executor.migrate(m3_targets)
            m3_apps = executor.loader.project_state(m3_targets).apps
            after = self.snapshot(m3_apps)
            self.assertEqual(common(after, before), before, "M3 forward migration changed an existing row.")
            self.assertTrue(all(row["policy_epoch"] == 0 for row in after["scopes.Organization"]))
            self.assertTrue(all(row["scope_epoch"] == 0 for row in after["scopes.Unit"]))
            self.assertTrue(all(row["max_profile"] is None for row in after["scopes.SharingChannel"] + after["scopes.ChannelSource"]))
            self.assertTrue(all(row["scope_context"] is None and row["scope_context_hash"] is None and (row["policy_epoch"], row["scope_epoch"]) == (0, 0)
                                for row in after["operations.ProcessingJob"]))
            m3_functions = functions(schema_oid)
            self.assertTrue(ADDED <= set(m3_functions))
            for name, definition in m2_functions.items():
                if name in REPLACED:
                    self.assertNotEqual(m3_functions[name], definition, name)
                else:
                    self.assertEqual(m3_functions[name], definition, name)
            self.assertTrue(m2_triggers < triggers(schema_oid))

            executor = MigrationExecutor(connection)
            executor.migrate(m2_targets)
            self.assertEqual(functions(schema_oid), m2_functions, "Reverse migration did not restore the exact M2 guard set.")
            self.assertEqual(triggers(schema_oid), m2_triggers)
            self.assertEqual(self.snapshot(executor.loader.project_state(m2_targets).apps), before)

    def test_out_of_vocabulary_ceiling_aborts_without_rewriting(self):
        with owned_upgrade_schema():
            executor = MigrationExecutor(connection)
            m2_targets, m3_targets = self.targets(executor)
            executor.migrate(m2_targets)
            m2_apps = executor.loader.project_state(m2_targets).apps
            user_id, _, _ = self.seed(m2_apps)
            user = m2_apps.get_model("accounts", "User").objects.get(pk=user_id)
            channel = m2_apps.get_model("scopes", "SharingChannel").objects.get()
            member = m2_apps.get_model("scopes", "ChannelMember").objects.create(organization_id=user.organization_id, channel=channel, user=user,
                                                                                 profile_ceiling="SUMMARY")
            executor = MigrationExecutor(connection)
            with self.assertRaisesRegex(RuntimeError, "outside the profile vocabulary; no row was changed"):
                executor.migrate(m3_targets)
            with connection.cursor() as cursor:
                cursor.execute("SELECT profile_ceiling FROM scopes_channelmember WHERE id = %s", [member.id])
                self.assertEqual(cursor.fetchone(), ("SUMMARY",))
            recorded = MigrationExecutor(connection).loader.applied_migrations
            self.assertNotIn(("scopes", "0004_m3_scope_profiles"), recorded)
            self.assertNotIn(("operations", "0005_m3_guards"), recorded)
