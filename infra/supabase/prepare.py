"""Prepare or run the authorized database profile; the website stays on loopback."""
import argparse
import ast
import getpass
import hashlib
import json
import os
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))
from config import supabase as profile
from infra import local


def environment():
    # Validation happens before local key preparation or any cloud operation.
    profile.load_config()
    env = dict(os.environ)
    for key in list(env):
        if key.startswith("PG") or key.startswith("KAPIT_") or key in {"DATABASE_URL", "DB_URL", "DJANGO_SETTINGS_MODULE"}:
            env.pop(key, None)
    env["DJANGO_SETTINGS_MODULE"] = "config.settings"
    env["KAPIT_RUNTIME_CONTEXT"] = "supabase-m1"
    env["KAPIT_SECRETS_FILE"] = str(local.SECRET_FILE)
    env["KAPIT_LOCAL_CONTAINER"] = "0"
    return env


def setup(args):
    if not sys.stdin.isatty():
        raise RuntimeError("Run setup in an interactive local terminal. Password input must remain hidden.")
    username = profile.ROLE if args.mode == "direct" else f"{profile.ROLE}.{profile.PROJECT_REF}"
    host = args.host or f"db.{profile.PROJECT_REF}.supabase.co"
    profile.validate_target(args.mode, host, username)
    profile.checked_private_paths()
    certificate = Path(args.ca_file).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" not in certificate:
        raise RuntimeError("Use the project's dashboard CA certificate in PEM format.")
    if profile.CONFIG_FILE.exists() or profile.CA_FILE.exists():
        raise RuntimeError("Existing private configuration was retained. Review it before any credential rotation.")
    password = getpass.getpass("Dedicated backend database password (hidden): ")
    if not password or "\x00" in password or len(password) > 1024:
        raise RuntimeError("Password input is unavailable or invalid.")
    profile.PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        profile.PRIVATE_DIR.chmod(0o700)
    descriptor = os.open(profile.CA_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(certificate)
    local.write_private(profile.CONFIG_FILE, json.dumps({
        "project_ref": profile.PROJECT_REF, "mode": args.mode, "host": host,
        "username": username, "port": "5432", "password": password,
        "certificate_sha256": hashlib.sha256(certificate).hexdigest(),
    }, indent=2) + "\n")
    print("Dedicated Supabase profile saved privately. No database connection or schema write was performed.")


def activate_login(args):
    if not sys.stdin.isatty() or not args.inventory_report:
        raise RuntimeError("Role activation requires an interactive private terminal and the orchestrator's authenticated prerequisite inventory report.")
    path = Path(args.inventory_report).resolve()
    if not path.is_relative_to(ROOT) or path.is_symlink():
        raise RuntimeError("Use a workspace inventory report for this exact project.")
    inventory = json.loads(path.read_text(encoding="utf-8"))
    if inventory.get("project_ref") != profile.PROJECT_REF or inventory.get("schema_owner") != profile.ROLE or inventory.get("prerequisite_applied") is not True or inventory.get("private_data_api") is not True:
        raise RuntimeError("The authenticated private-schema prerequisite inventory is incomplete.")
    data = profile.load_config()
    env = environment()
    os.environ.clear()
    os.environ.update(env)
    admin_password = getpass.getpass("Project database administrator password (hidden, not retained): ")
    if not admin_password:
        raise RuntimeError("Administrator credentials are unavailable.")
    import psycopg
    from psycopg import sql
    parameters = profile.database_settings()
    user = "postgres" if data["mode"] == "direct" else f"postgres.{profile.PROJECT_REF}"
    options = parameters["OPTIONS"]
    with psycopg.connect(host=data["host"], port=5432, dbname="postgres", user=user, password=admin_password, sslmode="verify-full", sslrootcert=str(profile.CA_FILE), connect_timeout=10, options=options["options"]) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_database(), current_user")
            if cursor.fetchone() != ("postgres", "postgres"):
                raise RuntimeError("The administrator connection differs from the exact project database identity.")
            cursor.execute("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname='kapit_m1'")
            if cursor.fetchone() != (profile.ROLE,):
                raise RuntimeError("The reviewed private schema prerequisite is unavailable.")
            cursor.execute("SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, rolreplication, rolbypassrls FROM pg_roles WHERE rolname='kapit_m1_app'")
            if cursor.fetchone() != (False, False, False, False, False, False, False):
                raise RuntimeError("Role activation is only for the new reviewed NOLOGIN role; existing credentials are never rotated automatically.")
            verifier = connection.pgconn.encrypt_password(data["password"].encode(connection.info.encoding), profile.ROLE.encode(connection.info.encoding), b"scram-sha-256")
            if not verifier.startswith(b"SCRAM-SHA-256$"):
                raise RuntimeError("The maintained password utility did not produce a SCRAM verifier.")
            cursor.execute(sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(profile.ROLE), sql.Literal(verifier.decode("ascii"))))
    print("The dedicated backend login was activated for the exact project. Passwords/verifier were not printed or retained in evidence.")


def verify_private_database(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), current_user")
        if cursor.fetchone() != ("postgres", profile.ROLE):
            raise RuntimeError("The connected database identity is not the dedicated M1 backend role.")
        cursor.execute("SELECT r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolinherit, r.rolreplication, r.rolbypassrls FROM pg_roles r WHERE r.rolname = %s", [profile.ROLE])
        if cursor.fetchone() != (False, False, False, False, False, False):
            raise RuntimeError("The dedicated backend role has unexpected elevated privileges.")
        cursor.execute("SELECT count(*) FROM pg_auth_members m WHERE m.member=(SELECT oid FROM pg_roles WHERE rolname='kapit_m1_app') OR (m.roleid=(SELECT oid FROM pg_roles WHERE rolname='kapit_m1_app') AND pg_get_userbyid(m.member)<>'postgres')")
        if cursor.fetchone() != (0,):
            raise RuntimeError("The dedicated role membership differs from the reviewed administrator-only setup.")
        cursor.execute("SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = %s", [profile.SCHEMA])
        if cursor.fetchone() != (profile.ROLE,):
            raise RuntimeError("The private schema prerequisite/ownership is unavailable.")
        for role in ("anon", "authenticated", "service_role", "public"):
            # PUBLIC is a privilege group, not a pg_roles row.
            if role != "public":
                cursor.execute("SELECT has_schema_privilege(%s, %s, 'USAGE,CREATE')", [role, profile.SCHEMA])
                if cursor.fetchone() != (False,):
                    raise RuntimeError("An API role unexpectedly has private schema access.")
        cursor.execute("SHOW search_path")
        if cursor.fetchone()[0].replace(" ", "") != profile.CREATE_SEARCH_PATH:
            raise RuntimeError("The connection search path differs from the private M1 schema.")


def harden_and_verify(connection):
    from psycopg import sql
    with connection.cursor() as cursor:
        cursor.execute("REVOKE ALL ON SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role")
        cursor.execute("REVOKE ALL ON ALL TABLES IN SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role")
        cursor.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role")
        cursor.execute("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA kapit_m1 FROM PUBLIC, anon, authenticated, service_role")
        cursor.execute("SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kapit_m1' AND c.relkind='r'")
        for (name,) in cursor.fetchall():
            cursor.execute(sql.SQL("ALTER TABLE {}.{} ENABLE ROW LEVEL SECURITY").format(sql.Identifier(profile.SCHEMA), sql.Identifier(name)))
        cursor.execute("SELECT p.proname, pg_get_function_identity_arguments(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kapit_m1'")
        for name, arguments in cursor.fetchall():
            if arguments != "" or not name.startswith("kapit_"):
                raise RuntimeError("An unexpected private function requires separate review.")
            cursor.execute(sql.SQL("ALTER FUNCTION {}.{}() SET search_path = pg_catalog, kapit_m1, pg_temp").format(sql.Identifier(profile.SCHEMA), sql.Identifier(name)))
        cursor.execute("SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='kapit_m1' AND t.typelem=0")
        for (name,) in cursor.fetchall():
            cursor.execute(sql.SQL("REVOKE ALL ON TYPE {}.{} FROM PUBLIC, anon, authenticated, service_role").format(sql.Identifier(profile.SCHEMA), sql.Identifier(name)))
    verify_private_database(connection)


def expected_trigger_specs():
    # Read canonical migration data without importing/executing it or Django.
    source = ROOT / "backend/apps/operations/migrations/0002_integrity_guards.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    sql = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "SQL" for target in node.targets))
    specs = set()
    for name, events, table, function, arguments in re.findall(r"CREATE TRIGGER (\w+) BEFORE ([A-Z ]+) ON (\w+) FOR EACH ROW EXECUTE FUNCTION (\w+)\(([^;]*)\);", sql):
        args = re.findall(r"'([^']*)'", arguments)
        mask = 1 | 2
        for event, bit in (("INSERT",4),("DELETE",8),("UPDATE",16)):
            if event in events.split():
                mask |= bit
        specs.add((table, name, function, "O", mask, len(args), b"".join(item.encode("ascii")+b"\x00" for item in args)))
    if not specs:
        raise RuntimeError("The canonical integrity trigger specification is unavailable.")
    return specs


def verify_hardened_database(connection):
    expected_functions = {"kapit_org_guard", "kapit_frozen_guard", "kapit_variant_state_guard", "kapit_source_link_guard", "kapit_revocation_guard", "kapit_decision_guard", "kapit_publication_guard"}
    with connection.cursor() as cursor:
        cursor.execute("SELECT c.relname, c.relrowsecurity, pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kapit_m1' AND c.relkind='r'")
        tables = cursor.fetchall()
        if not tables or any(not rls or owner != profile.ROLE for _, rls, owner in tables):
            raise RuntimeError("Private application table ownership/RLS differs from the reviewed setup.")
        cursor.execute("SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner), p.proconfig, p.pronargs FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kapit_m1'")
        functions = cursor.fetchall()
        if len(functions) != len(expected_functions) or {row[0] for row in functions} != expected_functions:
            raise RuntimeError("The exact private integrity function set is unavailable.")
        for name, definer, owner, options, nargs in functions:
            if nargs != 0 or definer or owner != profile.ROLE or "search_path=pg_catalog, kapit_m1, pg_temp" not in (options or []):
                raise RuntimeError("Private integrity function ownership/invoker/search path differs from the reviewed setup.")
        cursor.execute("SELECT c.relname,t.tgname,p.proname,t.tgenabled,t.tgtype,t.tgnargs,t.tgargs FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_proc p ON p.oid=t.tgfoid WHERE n.nspname='kapit_m1' AND p.pronamespace=n.oid AND NOT t.tgisinternal")
        triggers = {(table,name,function,enabled,kind,nargs,bytes(args)) for table,name,function,enabled,kind,nargs,args in cursor.fetchall()}
        if triggers != expected_trigger_specs():
            raise RuntimeError("The enabled private trigger attachments/events/arguments differ from the actual integrity migration.")
        # Actual object privileges are checked separately from schema visibility:
        # an accidental Data API schema exposure must not reveal object access.
        for role in ("anon", "authenticated", "service_role"):
            cursor.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kapit_m1' AND c.relkind='r' AND (has_table_privilege(%s,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(%s,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))", [role,role])
            if cursor.fetchone() != (0,):
                raise RuntimeError("An API role unexpectedly has private table privileges.")
            cursor.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kapit_m1' AND CASE WHEN c.relkind='S' THEN has_sequence_privilege(%s,c.oid,'USAGE,SELECT,UPDATE') ELSE false END", [role])
            if cursor.fetchone() != (0,):
                raise RuntimeError("An API role unexpectedly has private sequence privileges.")
            cursor.execute("SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kapit_m1' AND has_function_privilege(%s,p.oid,'EXECUTE')", [role])
            if cursor.fetchone() != (0,):
                raise RuntimeError("An API role unexpectedly has private function privileges.")
            cursor.execute("SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='kapit_m1' AND t.typelem=0 AND has_type_privilege(%s,t.oid,'USAGE')", [role])
            if cursor.fetchone() != (0,):
                raise RuntimeError("An API role unexpectedly has private type privileges.")
        cursor.execute("SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole WHERE r.rolname='kapit_m1_app' AND d.defaclnamespace=0 AND d.defaclobjtype IN ('f','T')")
        if cursor.fetchone() != (2,):
            raise RuntimeError("Global owner-scoped function/type PUBLIC defaults have not been revoked.")
        cursor.execute("SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole CROSS JOIN LATERAL aclexplode(d.defaclacl) a LEFT JOIN pg_roles grantee ON grantee.oid=a.grantee WHERE r.rolname='kapit_m1_app' AND (d.defaclnamespace=0 OR d.defaclnamespace=(SELECT oid FROM pg_namespace WHERE nspname='kapit_m1')) AND (a.grantee=0 OR grantee.rolname IN ('anon','authenticated','service_role'))")
        if cursor.fetchone() != (0,):
            raise RuntimeError("A private owner default privilege unexpectedly grants API/PUBLIC access.")
        # This project has not authorized any other database grantee either.
        # Unexpected grants fail for review rather than being silently revoked.
        owner_only_queries = [
            "SELECT count(*) FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a WHERE n.nspname='kapit_m1' AND a.grantee<>n.nspowner",
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(c.relacl) a WHERE n.nspname='kapit_m1' AND a.grantee<>c.relowner",
            "SELECT count(*) FROM pg_attribute column_acl JOIN pg_class c ON c.oid=column_acl.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(column_acl.attacl) a WHERE n.nspname='kapit_m1' AND a.grantee<>c.relowner",
            "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(p.proacl) a WHERE n.nspname='kapit_m1' AND a.grantee<>p.proowner",
            "SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace CROSS JOIN LATERAL aclexplode(t.typacl) a WHERE n.nspname='kapit_m1' AND a.grantee<>t.typowner",
            "SELECT count(*) FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE r.rolname='kapit_m1_app' AND (d.defaclnamespace=0 OR d.defaclnamespace=(SELECT oid FROM pg_namespace WHERE nspname='kapit_m1')) AND a.grantee<>d.defaclrole",
        ]
        for query in owner_only_queries:
            cursor.execute(query)
            if cursor.fetchone() != (0,):
                raise RuntimeError("A private object/default/column ACL grants an unrelated database role; human review is required.")


def django_bootstrap(apply_migrations=False):
    import django
    from django.core.management import call_command
    from django.db import connection, transaction
    from django.db.migrations.executor import MigrationExecutor
    from django.db.migrations.recorder import MigrationRecorder
    django.setup()
    verify_private_database(connection)
    if apply_migrations:
        # Serialize genuine migration/hardening writers; ordinary startup only
        # verifies existing private history and never applies schema changes.
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_lock(1262572116, 16)")
        try:
            call_command("migrate", interactive=False, verbosity=0)
            with transaction.atomic():
                harden_and_verify(connection)
        finally:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_unlock(1262572116, 16)")
    executor = MigrationExecutor(connection)
    if executor.migration_plan(executor.loader.graph.leaf_nodes()):
        raise RuntimeError("Real Django migrations remain unapplied.")
    applied = MigrationRecorder(connection).applied_migrations()
    if ("operations", "0002_integrity_guards") not in applied:
        raise RuntimeError("The real Django integrity migration is absent from private history.")
    verify_hardened_database(connection)
    print("Real Django migrations and private integrity history verified. No report has been approved.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["setup", "activate-login", "check", "migrate", "seed-demo", "backend", "worker"])
    parser.add_argument("--mode", choices=["direct", "session"], default="direct")
    parser.add_argument("--host", help="Exact direct target or dashboard-listed session pooler hostname.")
    parser.add_argument("--ca-file", help="Dashboard certificate file, for hidden setup only.")
    parser.add_argument("--inventory-report", help="Orchestrator's exact-project authenticated prerequisite inventory JSON, for role activation only.")
    args = parser.parse_args()
    if args.command == "setup":
        if not args.ca_file:
            raise RuntimeError("Hidden setup requires the dashboard CA certificate file.")
        setup(args)
        return
    if args.command == "activate-login":
        activate_login(args)
        return
    env = environment()
    if args.command == "check":
        print("Exact project, dedicated role, direct/session5432 and verify-full CA configuration validated offline. No connection was made.")
        return
    local.initialize()
    os.environ.clear()
    os.environ.update(env)
    django_bootstrap(apply_migrations=args.command == "migrate")
    if args.command == "backend":
        local.run([local.python_path(), str(ROOT / "infra/server.py")], environment=env)
    elif args.command == "seed-demo":
        local.run([local.python_path(), str(ROOT / "backend/manage.py"), "seed_demo"], environment=env)
    elif args.command == "worker":
        local.run([local.python_path(), str(ROOT / "backend/manage.py"), "process_jobs"], environment=env)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Driver exception objects can contain connection details; keep them
        # out of terminal logs and do not print config/credentials/SQL values.
        print("Supabase preparation could not complete. Check the guide, target access, private configuration and installed dependencies.", file=sys.stderr)
        raise SystemExit(1) from None
