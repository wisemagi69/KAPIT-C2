"""Dry private-profile tests; no Supabase or Django connection is made."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from infra.supabase import prepare
from config import supabase as profile
from config.hosted_preflight import validate_hosted_management


CERTIFICATE = b"-----BEGIN CERTIFICATE-----\nsynthetic-offline-fixture\n-----END CERTIFICATE-----\n"


class ProfileTests(unittest.TestCase):
    def setUp(self):
        base = profile.PROJECT_DIR / ".cache/m1-runtime/supabase-tests"
        base.mkdir(parents=True, exist_ok=True)
        self.folder = tempfile.TemporaryDirectory(dir=base)
        self.private = Path(self.folder.name)
        self.patches = [patch.object(profile, "PRIVATE_DIR", self.private), patch.object(profile, "CONFIG_FILE", self.private / "database.json"), patch.object(profile, "CA_FILE", self.private / "root.crt")]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.folder.cleanup()

    def configure(self):
        profile.CA_FILE.write_bytes(CERTIFICATE)
        profile.CONFIG_FILE.write_text(json.dumps({"project_ref":profile.PROJECT_REF,"mode":"direct","host":f"db.{profile.PROJECT_REF}.supabase.co","username":profile.ROLE,"port":"5432","password":"private-fixture-canary","certificate_sha256":hashlib.sha256(CERTIFICATE).hexdigest()}), encoding="utf-8")

    def test_exact_direct_and_project_scoped_session_targets(self):
        profile.validate_target("direct", f"db.{profile.PROJECT_REF}.supabase.co", profile.ROLE)
        profile.validate_target("session", "aws-0-ap-southeast-1.pooler.supabase.com", f"{profile.ROLE}.{profile.PROJECT_REF}")
        for mode, host, user, port in [("direct","db.otherproject.supabase.co",profile.ROLE,"5432"),("direct",f"db.{profile.PROJECT_REF}.supabase.co","postgres","5432"),("session","aws-0-ap-southeast-1.pooler.supabase.com",f"{profile.ROLE}.otherproject","5432"),("session","remote.example",f"{profile.ROLE}.{profile.PROJECT_REF}","5432"),("session","aws-0-ap-southeast-1.pooler.supabase.com",f"{profile.ROLE}.{profile.PROJECT_REF}","6543")]:
            with self.subTest(mode=mode,host=host,user=user,port=port), self.assertRaises(RuntimeError):
                profile.validate_target(mode,host,user,port=port)

    def test_tls_settings_are_fixed_and_certificate_tamper_is_denied(self):
        self.configure()
        settings = profile.database_settings()
        self.assertEqual(settings["ENGINE"], "config.supabase_backend")
        self.assertEqual(settings["OPTIONS"]["sslmode"], "verify-full")
        self.assertEqual(settings["OPTIONS"]["options"], "-c search_path=kapit_m1,pg_catalog,pg_temp")
        profile.CA_FILE.write_bytes(CERTIFICATE + b"changed")
        with self.assertRaisesRegex(RuntimeError, "fingerprint"):
            profile.load_config()

    def test_lf_setup_preserves_binary_certificate_and_loads_on_windows(self):
        source = self.private / "dashboard-certificate.pem"
        source.write_bytes(CERTIFICATE)
        output = io.StringIO()
        with patch.object(prepare.sys.stdin, "isatty", return_value=True), patch.object(prepare.getpass, "getpass", return_value="private-fixture-canary"), redirect_stdout(output):
            prepare.setup(SimpleNamespace(mode="direct",host=None,ca_file=str(source)))
        self.assertEqual(profile.CA_FILE.read_bytes(), CERTIFICATE)
        self.assertEqual(profile.load_config()["certificate_sha256"], hashlib.sha256(CERTIFICATE).hexdigest())
        self.assertNotIn("private-fixture-canary", output.getvalue())

    def test_inherited_database_libpq_and_settings_overrides_are_removed(self):
        self.configure()
        injected = {"PGHOST":"other-project.example","PGHOSTADDR":"192.0.2.10","PGPASSWORD":"private-fixture-canary","PGSERVICE":"production","PGOPTIONS":"-c search_path=public","DATABASE_URL":"private-fixture-url","DJANGO_SETTINGS_MODULE":"other.settings","KAPIT_DB_HOST":"other-project.example","KAPIT_LOCAL_CONTAINER":"1"}
        with patch.dict(prepare.os.environ, injected):
            env = prepare.environment()
            self.assertFalse(any(name.startswith("PG") for name in env))
            self.assertNotIn("DATABASE_URL", env)
            self.assertNotIn("KAPIT_DB_HOST", env)
            self.assertEqual(env["DJANGO_SETTINGS_MODULE"], "config.settings")
            self.assertEqual(env["KAPIT_LOCAL_CONTAINER"], "0")
            self.assertEqual(prepare.os.environ["PGHOST"], "other-project.example")

    def test_noninteractive_setup_refuses_before_password_capture(self):
        with patch.object(prepare.sys.stdin, "isatty", return_value=False), patch.object(prepare.getpass, "getpass") as secret:
            with self.assertRaisesRegex(RuntimeError, "interactive"):
                prepare.setup(SimpleNamespace(mode="direct",host=None,ca_file="unused"))
            secret.assert_not_called()

    def test_startup_does_not_apply_migrations_or_seed_and_command_has_no_hosted_test(self):
        self.configure()
        for command in ("backend", "worker"):
            with self.subTest(command=command), patch.dict(prepare.os.environ, {}, clear=True), patch.object(prepare.sys,"argv",["prepare.py",command]), patch.object(prepare.local,"initialize"), patch.object(prepare.local,"run") as run, patch.object(prepare,"django_bootstrap") as bootstrap:
                prepare.main()
                bootstrap.assert_called_once_with(apply_migrations=False)
                run.assert_called_once()
                self.assertNotIn("seed_demo", run.call_args.args[0])
        with patch.object(prepare.sys,"argv",["prepare.py","test"]), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                prepare.main()
            self.assertEqual(error.exception.code, 2)

    def test_explicit_seed_checks_real_existing_migrations_before_dispatch(self):
        self.configure()
        with patch.dict(prepare.os.environ, {}, clear=True), patch.object(prepare.sys, "argv", ["prepare.py", "seed-demo"]), patch.object(prepare.local, "initialize"), patch.object(prepare.local, "run") as run, patch.object(prepare, "django_bootstrap") as bootstrap:
            prepare.main()
            bootstrap.assert_called_once_with(apply_migrations=False)
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0][-1], "seed_demo")
        with patch.dict(prepare.os.environ, {}, clear=True), patch.object(prepare.sys, "argv", ["prepare.py", "seed-demo"]), patch.object(prepare.local, "initialize"), patch.object(prepare.local, "run") as run, patch.object(prepare, "django_bootstrap", side_effect=RuntimeError("Unapplied migration")):
            with self.assertRaisesRegex(RuntimeError, "Unapplied"):
                prepare.main()
            run.assert_not_called()

    def test_destructive_hosted_hooks_and_inherited_local_test_context_are_denied(self):
        with self.assertRaisesRegex(RuntimeError, "not authorized"):
            profile.refuse_destructive_operation()
        with self.assertRaisesRegex(RuntimeError, "hosted"):
            profile.require_local_test_context({"KAPIT_RUNTIME_CONTEXT":"supabase-m1"})
        profile.require_local_test_context({"KAPIT_RUNTIME_CONTEXT":"native"})

    def test_role_activation_requires_reviewed_inventory_before_secret_capture(self):
        with patch.object(prepare.sys.stdin, "isatty", return_value=True), patch.object(prepare.getpass,"getpass") as secret:
            with self.assertRaisesRegex(RuntimeError, "inventory report"):
                prepare.activate_login(SimpleNamespace(inventory_report=None))
            secret.assert_not_called()

    def test_direct_hosted_entry_rejects_ambient_libpq_and_private_key_redirects(self):
        for variables in ({"PGHOSTADDR":"192.0.2.10"},{"PGSERVICE":"unrelated"},{"PGSSLCERT":"unrelated-private-path"},{"KAPIT_DB_PASSWORD":"private-fixture-canary"},{"KAPIT_SECRETS_FILE":str(profile.PROJECT_DIR / "unrelated-key.json")}):
            with self.subTest(variables=list(variables)), self.assertRaises(RuntimeError):
                profile.validate_hosted_environment(variables)
        profile.validate_hosted_environment({"KAPIT_RUNTIME_CONTEXT":"supabase-m1"})

    def test_direct_hosted_management_only_accepts_reviewed_commands(self):
        env = {"KAPIT_RUNTIME_CONTEXT":"supabase-m1"}
        for args in (["test"],["flush"],["migrate"],["seed_demo","--settings=unrelated.settings"],["process_jobs","--pythonpath","unrelated"],["process_jobs","--interval","nan"]):
            with self.subTest(command=args), self.assertRaises(RuntimeError):
                validate_hosted_management(["manage.py",*args],env)
        for args in (["seed_demo"],["process_jobs"],["process_jobs","--once","--interval","2"]):
            validate_hosted_management(["manage.py",*args],env)
        validate_hosted_management(["manage.py","test","--settings=config.test_settings"],{"KAPIT_RUNTIME_CONTEXT":"native"})


if __name__ == "__main__":
    unittest.main()
