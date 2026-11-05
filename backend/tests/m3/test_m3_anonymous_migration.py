"""Empty reverse and populated refusal, with preservation and loud latest restoration."""
import hashlib

from django.core.management import call_command
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

from apps.audit import service as audit
from apps.audit.models import AnonymousIntegrationFailure
from apps.reports.services import accept_operation
from django.contrib.auth import get_user_model
from tests.test_workflow import operation
from .test_m3_review import SETTINGS


def existing_table_hashes():
    result = {}
    with connection.cursor() as cursor:
        cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename NOT IN ('django_migrations','audit_anonymousintegrationfailure') ORDER BY tablename")
        for (name,) in cursor.fetchall():
            cursor.execute("SELECT row_to_json(t)::text FROM " + connection.ops.quote_name(name) + " t")
            values = sorted(row[0] for row in cursor.fetchall())
            result[name] = (len(values), hashlib.sha256("\n".join(values).encode()).hexdigest())
    return result


@override_settings(**SETTINGS)
class AnonymousIntegrationMigrationTests(TransactionTestCase):
    def test_empty_reverse_preserves_all_old_rows_populated_reverse_refuses_and_latest_restores(self):
        self.assertEqual(connection.vendor, "postgresql")
        latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        # This test reverses only the anonymous-audit migration. Future unrelated
        # heads (including validation history) must remain present and unchanged.
        previous = [(app, "0001_initial" if app == "audit" else name) for app, name in latest]
        try:
            call_command("seed_demo", verbosity=0)
            author = get_user_model().objects.get(username="submitter")
            body = operation()
            accept_operation(author, body, body)
            self.assertFalse(AnonymousIntegrationFailure.objects.exists())
            before = existing_table_hashes()
            executor = MigrationExecutor(connection)
            self.assertEqual({(m.app_label, m.name, backwards) for m, backwards in executor.migration_plan(previous)},
                             {("audit", "0002_anonymous_integration_failures", True)})
            executor.migrate(previous)
            self.assertNotIn("audit_anonymousintegrationfailure", connection.introspection.table_names())
            self.assertEqual(existing_table_hashes(), before)
            MigrationExecutor(connection).migrate(latest)
            self.assertEqual(existing_table_hashes(), before)
            row = audit.anonymous_integration_failure("abcd1234")
            with self.assertRaisesRegex(RuntimeError, "reversal refused"):
                MigrationExecutor(connection).migrate(previous)
            self.assertTrue(AnonymousIntegrationFailure.objects.filter(pk=row.pk).exists())
            self.assertEqual(existing_table_hashes(), before)
        finally:
            MigrationExecutor(connection).migrate(latest)
