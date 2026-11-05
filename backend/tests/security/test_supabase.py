"""Independent hosted-boundary probes; no credentials or remote connection.

Catalog probes use an explicitly permitted, existing PGlite package and fresh
in-memory fixtures. They do not run Django migrations or certify Supabase/TLS.
"""
import ast
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch

from infra.supabase import prepare
from config.runtime_boundary import boundary

ROOT = Path(__file__).resolve().parents[3]
LIBRARY = Path("C:/Users/Ken/ken/CurricuLogic-System/.cache/sql-tests/node_modules/@electric-sql/pglite")

# Deliberately incomplete synthetic table fixtures, not generated Django DDL.
# Only the original relational guard SQL and catalog verifier run here.
FIXTURE_DDL = """
CREATE TABLE scopes_organization(id uuid PRIMARY KEY, active_policy_id uuid, active boolean);
CREATE TABLE accounts_user(id uuid PRIMARY KEY, organization_id uuid, role text, is_active boolean);
CREATE TABLE scopes_unit(id uuid PRIMARY KEY, organization_id uuid, active boolean);
CREATE TABLE scopes_sharingchannel(id uuid PRIMARY KEY, organization_id uuid, active boolean);
CREATE TABLE scopes_policyversion(id uuid PRIMARY KEY, organization_id uuid, active boolean, version text, rules_hash text);
CREATE TABLE scopes_unitmembership(id uuid PRIMARY KEY, organization_id uuid, user_id uuid, unit_id uuid, role text, active boolean, valid_until timestamptz);
CREATE TABLE scopes_channelsource(id uuid PRIMARY KEY, organization_id uuid, channel_id uuid, unit_id uuid, active boolean);
CREATE TABLE scopes_channelmember(id uuid PRIMARY KEY, organization_id uuid, user_id uuid, channel_id uuid);
CREATE TABLE reports_report(id uuid PRIMARY KEY, organization_id uuid, author_id uuid, unit_id uuid, current_revision_no integer);
CREATE TABLE reports_reportrevision(id uuid PRIMARY KEY, organization_id uuid, report_id uuid, submitted_by_id uuid, revision_no integer, processing_state text, marker text);
CREATE TABLE operations_processingjob(id uuid PRIMARY KEY, organization_id uuid, revision_id uuid, policy_id uuid, channel_ids jsonb);
CREATE TABLE operations_syncreceipt(id uuid PRIMARY KEY, organization_id uuid, revision_id uuid, accepted_user_id uuid, operation_id uuid, request_hash text, response_body jsonb);
CREATE TABLE reports_reportvariant(id uuid PRIMARY KEY, organization_id uuid, revision_id uuid, policy_id uuid, job_id uuid, profile text, projection jsonb, channel_ids jsonb, candidate_hash text, state text);
CREATE TABLE review_reviewdecision(id uuid PRIMARY KEY, organization_id uuid, variant_id uuid, reviewer_id uuid, action text, binding jsonb);
CREATE TABLE publications_publication(id uuid PRIMARY KEY, organization_id uuid, variant_id uuid, decision_id uuid, report_id uuid, channel_id uuid, profile text, projection jsonb, revoked_at timestamptz);
CREATE TABLE audit_auditevent(id uuid PRIMARY KEY, organization_id uuid, actor_id uuid);
"""

HARDEN_FIXTURES = """
REVOKE ALL ON ALL TABLES IN SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role;
DO $$ DECLARE item record; BEGIN
  FOR item IN SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kapit_m1' AND relkind='r' LOOP
    EXECUTE format('ALTER TABLE kapit_m1.%I ENABLE ROW LEVEL SECURITY',item.relname);
  END LOOP;
  FOR item IN SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kapit_m1' LOOP
    EXECUTE format('ALTER FUNCTION kapit_m1.%I() SET search_path=pg_catalog,kapit_m1,pg_temp',item.proname);
  END LOOP;
  FOR item IN SELECT typname FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='kapit_m1' AND typelem=0 LOOP
    EXECUTE format('REVOKE ALL ON TYPE kapit_m1.%I FROM PUBLIC,anon,authenticated,service_role',item.typname);
  END LOOP;
END $$;
"""

BRIDGE = r"""
const readline = require('node:readline');
const fs = require('node:fs');
const { PGlite } = require(process.argv[1] + '/dist/index.cjs');
if (JSON.parse(fs.readFileSync(process.argv[1] + '/package.json')).version !== '0.3.14') throw new Error('Unexpected permitted package version');
let db;
(async()=>{
  for await (const line of readline.createInterface({input:process.stdin})) {
    const request=JSON.parse(line);
    try {
      if(request.init){db=new PGlite({database:'postgres'}); await db.exec(request.init); console.log(JSON.stringify({rows:[]}));}
      else if(request.exec){await db.exec(request.exec); console.log(JSON.stringify({rows:[]}));}
      else if(request.close){await db.close(); db=null; console.log(JSON.stringify({rows:[]})); break;}
      else {const result=await db.query(request.sql,request.params||[]); console.log(JSON.stringify({rows:result.rows.map(row=>Object.values(row).map(value=>value instanceof Uint8Array ? Array.from(value) : value))}));}
    }catch(error){console.log(JSON.stringify({error:error.message,code:error.code,where:error.where}));}
  }
  if(db) await db.close();
  process.stdin.destroy();
})().catch(()=>process.exitCode=1);
"""


class WasmCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        for index in range(len(params or [])):
            sql = sql.replace("%s", "$" + str(index + 1), 1)
        self.rows = self.connection.request({"sql": sql, "params": params or []})

    def fetchone(self):
        return tuple(self.rows.pop(0)) if self.rows else None

    def fetchall(self):
        return [tuple(row) for row in self.rows]


class WasmConnection:
    def __init__(self):
        module = ast.parse((ROOT / "backend/apps/operations/migrations/0002_integrity_guards.py").read_text(encoding="utf-8"))
        guards = next(ast.literal_eval(node.value) for node in module.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "SQL" for target in node.targets))
        self.process = subprocess.Popen([shutil.which("node"), "-e", BRIDGE, str(LIBRARY)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", cwd=ROOT)
        try:
            self.request({"init": "CREATE ROLE anon; CREATE ROLE authenticated; CREATE ROLE service_role; CREATE ROLE probe_unrelated;"})
            phases = [
                ("prerequisite", (ROOT / "infra/supabase/schema.sql").read_text(encoding="utf-8")),
                ("synthetic fixture DDL", "SET ROLE kapit_m1_app; SET search_path=kapit_m1,pg_catalog,pg_temp;\n" + FIXTURE_DDL),
                ("original migration guard SQL", guards),
                ("synthetic fixture hardening", HARDEN_FIXTURES),
            ]
            for name, sql in phases:
                try:
                    self.request({"exec": sql})
                except RuntimeError as error:
                    raise RuntimeError(name + ": " + str(error)) from None
        except BaseException:
            self.close()
            raise

    def request(self, data):
        self.process.stdin.write(json.dumps(data) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("The isolated PostgreSQL WASM probe stopped.")
        result = json.loads(line)
        if "error" in result:
            raise RuntimeError(result["error"] + ("; " + result["where"] if result.get("where") else ""))
        return result["rows"]

    def cursor(self):
        return WasmCursor(self)

    def sql(self, statement):
        with self.cursor() as cursor:
            cursor.execute(statement)
            return cursor.fetchall()

    def close(self):
        try:
            self.request({"close": True})
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=15)
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()


class HostedBoundaryTests(unittest.TestCase):
    def test_direct_entry_preflight_failure_stops_management_and_server(self):
        from config import hosted_preflight
        from infra import server

        spec = importlib.util.spec_from_file_location("_security_hosted_manage_probe", ROOT / "backend/manage.py")
        management = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(management)
        with patch.dict(prepare.os.environ, {"KAPIT_RUNTIME_CONTEXT": "supabase-m1"}, clear=True):
            with patch.object(prepare, "django_bootstrap", side_effect=RuntimeError("synthetic-catalog-denial")) as bootstrap:
                with patch.object(sys, "argv", ["manage.py", "seed_demo"]), self.assertRaisesRegex(RuntimeError, "synthetic-catalog-denial"):
                    management.main()
                bootstrap.assert_called_once_with(apply_migrations=False)
            with patch.object(prepare, "django_bootstrap") as bootstrap:
                with patch.object(sys, "argv", ["manage.py", "flush"]), self.assertRaisesRegex(RuntimeError, "not authorized"):
                    management.main()
                bootstrap.assert_not_called()
            wsgi = ModuleType("config.wsgi")
            wsgi.application = object()
            with patch.dict(sys.modules, {"config.wsgi": wsgi}), patch.object(server, "boundary", return_value=SimpleNamespace(bind_host="127.0.0.1")), patch.object(server, "make_server") as bind, patch.object(prepare, "django_bootstrap", side_effect=RuntimeError("synthetic-catalog-denial")) as bootstrap:
                with self.assertRaisesRegex(RuntimeError, "synthetic-catalog-denial"):
                    server.main()
                bootstrap.assert_called_once_with(apply_migrations=False)
                bind.assert_not_called()
        with patch.dict(prepare.os.environ, {"KAPIT_RUNTIME_CONTEXT": "native"}, clear=True), patch.object(prepare, "django_bootstrap") as bootstrap:
            hosted_preflight.enforce_hosted_preflight()
            bootstrap.assert_not_called()

    def test_direct_hosted_boundary_rejects_ambient_libpq_before_connection(self):
        for variable in ("PGHOSTADDR", "PGSERVICE", "PGSSLCERT", "PGOPTIONS", "DATABASE_URL"):
            with self.subTest(variable=variable), patch.object(prepare.profile, "load_config", return_value={"host": "db.vdemkykykybnxlixondr.supabase.co"}):
                with self.assertRaises(RuntimeError):
                    boundary({"KAPIT_RUNTIME_CONTEXT": "supabase-m1", variable: "synthetic-unreviewed-value"})

    def test_hosted_backend_hooks_deny_without_calling_driver_base(self):
        # The real Django/psycopg packages are unavailable. Stub only their base
        # classes to exercise the authored early rejection methods themselves.
        def forbidden_base(*args, **kwargs):
            raise AssertionError("A destructive driver base method was reached.")

        class BaseCreation:
            create_test_db = _create_test_db = destroy_test_db = _destroy_test_db = clone_test_db = _clone_test_db = forbidden_base

        class BaseOperations:
            sql_flush = forbidden_base

        names = ("django", "django.db", "django.db.backends", "django.db.backends.postgresql", "django.db.backends.postgresql.base", "django.db.backends.postgresql.creation", "django.db.backends.postgresql.operations")
        modules = {name: ModuleType(name) for name in names}
        modules[names[-3]].DatabaseWrapper = object
        modules[names[-2]].DatabaseCreation = BaseCreation
        modules[names[-1]].DatabaseOperations = BaseOperations
        spec = importlib.util.spec_from_file_location("_security_supabase_backend_probe", ROOT / "backend/config/supabase_backend/base.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, modules):
            spec.loader.exec_module(module)
        for method in ("create_test_db", "_create_test_db", "destroy_test_db", "_destroy_test_db", "clone_test_db", "_clone_test_db"):
            with self.subTest(method=method), self.assertRaisesRegex(RuntimeError, "not authorized"):
                getattr(module.Creation(), method)()
        with self.assertRaisesRegex(RuntimeError, "not authorized"):
            module.Operations().sql_flush()


@unittest.skipUnless(shutil.which("node") and (LIBRARY / "dist/index.cjs").is_file(), "Permitted local PGlite dependency unavailable")
class IsolatedCatalogTests(unittest.TestCase):
    def setUp(self):
        self.db = WasmConnection()

    def tearDown(self):
        self.db.close()

    def verify(self):
        # PGlite runs one connection in template1 and cannot authenticate the
        # managed target. Never fake current_database/current_user acceptance.
        prepare.verify_hardened_database(self.db)

    def test_actual_verifier_denies_acl_default_rls_path_and_trigger_drift(self):
        self.db.sql("CREATE SEQUENCE catalog_sequence_probe")
        self.verify()
        changes = [
            ("GRANT SELECT ON reports_reportrevision TO anon", "REVOKE SELECT ON reports_reportrevision FROM anon"),
            ("GRANT SELECT(marker) ON reports_reportrevision TO anon", "REVOKE SELECT(marker) ON reports_reportrevision FROM anon"),
            ("GRANT USAGE ON SEQUENCE catalog_sequence_probe TO authenticated", "REVOKE USAGE ON SEQUENCE catalog_sequence_probe FROM authenticated"),
            ("GRANT USAGE ON TYPE reports_reportrevision TO authenticated", "REVOKE USAGE ON TYPE reports_reportrevision FROM authenticated"),
            ("GRANT EXECUTE ON FUNCTION kapit_frozen_guard() TO PUBLIC", "REVOKE EXECUTE ON FUNCTION kapit_frozen_guard() FROM PUBLIC"),
            ("ALTER TABLE reports_reportrevision DISABLE ROW LEVEL SECURITY", "ALTER TABLE reports_reportrevision ENABLE ROW LEVEL SECURITY"),
            ("ALTER FUNCTION kapit_frozen_guard() SET search_path=public,pg_temp", "ALTER FUNCTION kapit_frozen_guard() SET search_path=pg_catalog,kapit_m1,pg_temp"),
            ("ALTER FUNCTION kapit_frozen_guard() SECURITY DEFINER", "ALTER FUNCTION kapit_frozen_guard() SECURITY INVOKER"),
            ("CREATE FUNCTION kapit_frozen_guard(integer) RETURNS integer LANGUAGE sql AS 'SELECT 1'", "DROP FUNCTION kapit_frozen_guard(integer)"),
            ("ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app GRANT EXECUTE ON FUNCTIONS TO PUBLIC,probe_unrelated", "ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC,probe_unrelated"),
            ("ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app GRANT EXECUTE ON FUNCTIONS TO probe_unrelated", "ALTER DEFAULT PRIVILEGES FOR ROLE kapit_m1_app REVOKE EXECUTE ON FUNCTIONS FROM probe_unrelated"),
            ("GRANT USAGE ON SCHEMA kapit_m1 TO probe_unrelated", "REVOKE USAGE ON SCHEMA kapit_m1 FROM probe_unrelated"),
            ("GRANT SELECT ON reports_reportrevision TO probe_unrelated", "REVOKE SELECT ON reports_reportrevision FROM probe_unrelated"),
            ("GRANT SELECT(marker) ON reports_reportrevision TO probe_unrelated", "REVOKE SELECT(marker) ON reports_reportrevision FROM probe_unrelated"),
            ("GRANT USAGE ON SEQUENCE catalog_sequence_probe TO probe_unrelated", "REVOKE USAGE ON SEQUENCE catalog_sequence_probe FROM probe_unrelated"),
            ("GRANT USAGE ON TYPE reports_reportrevision TO probe_unrelated", "REVOKE USAGE ON TYPE reports_reportrevision FROM probe_unrelated"),
            ("GRANT EXECUTE ON FUNCTION kapit_frozen_guard() TO probe_unrelated", "REVOKE EXECUTE ON FUNCTION kapit_frozen_guard() FROM probe_unrelated"),
            ("ALTER TABLE reports_reportrevision DISABLE TRIGGER b_frozen_guard", "ALTER TABLE reports_reportrevision ENABLE TRIGGER b_frozen_guard"),
        ]
        for change, restore in changes:
            with self.subTest(change=change):
                self.db.sql(change)
                try:
                    if "ALTER DEFAULT PRIVILEGES" in change:
                        self.assertEqual(self.db.sql("SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole WHERE r.rolname='kapit_m1_app' AND d.defaclnamespace=0 AND d.defaclobjtype IN ('f','T')"), [(2,)])
                    with self.assertRaises(RuntimeError):
                        self.verify()
                finally:
                    self.db.sql(restore)
                self.verify()

    def test_public_same_name_function_cannot_replace_private_guard_binding(self):
        self.verify()
        self.db.sql("RESET ROLE")
        self.db.sql("CREATE FUNCTION public.kapit_frozen_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$")
        self.db.sql("SET ROLE kapit_m1_app")
        self.db.sql("DROP TRIGGER b_frozen_guard ON reports_reportrevision")
        self.db.sql("CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON reports_reportrevision FOR EACH ROW EXECUTE FUNCTION public.kapit_frozen_guard('processing_state')")
        with self.assertRaisesRegex(RuntimeError, "trigger attachments"):
            self.verify()

    def test_original_guard_rejects_cross_org_under_public_and_temp_shadows(self):
        self.db.sql("INSERT INTO scopes_organization VALUES('00000000-0000-0000-0000-000000000001',NULL,true),('00000000-0000-0000-0000-000000000002',NULL,true)")
        self.db.sql("INSERT INTO accounts_user VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001','submitter',true)")
        self.db.sql("INSERT INTO scopes_unit VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000002',true)")
        # The dedicated owner cannot create in public on the live target. This
        # synthetic fixture uses its administrator only to create the shadow.
        self.db.sql("RESET ROLE")
        self.db.sql("CREATE TABLE public.scopes_unit(id uuid,organization_id uuid)")
        self.db.sql("INSERT INTO public.scopes_unit VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000001')")
        self.db.sql("SET ROLE kapit_m1_app")
        self.db.sql("CREATE TEMP TABLE scopes_unit(id uuid,organization_id uuid)")
        self.db.sql("INSERT INTO pg_temp.scopes_unit VALUES('00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000001')")
        self.db.sql("SET search_path=public,pg_temp,pg_catalog")
        with self.assertRaisesRegex(RuntimeError, "scope link is inconsistent"):
            self.db.sql("INSERT INTO kapit_m1.reports_report VALUES('00000000-0000-0000-0000-000000000005','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004',1)")
        self.assertEqual(self.db.sql("SELECT count(*) FROM kapit_m1.reports_report"), [(0,)])


if __name__ == "__main__":
    unittest.main()
