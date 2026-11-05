"""Pure tests for the hosted demonstration profile. No network, Django setup or cloud call."""
import base64
import contextlib
import hashlib
import hmac
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from config import hosted  # noqa: E402
from config.hosted_preflight import validate_hosted_management  # noqa: E402
from config.runtime_boundary import boundary  # noqa: E402
from infra.hosted import hosted as tool  # noqa: E402

CA = "-----BEGIN CERTIFICATE-----\nMIIBfakefixture\n-----END CERTIFICATE-----\n"
POOLER = "aws-0-ap-southeast-1.pooler.supabase.com"


def good_env(**changes):
    env = {
        "KAPIT_RUNTIME_CONTEXT": "hosted-demo",
        "KAPIT_HOSTED_DB_HOST": POOLER,
        "KAPIT_HOSTED_DB_PASSWORD": "x" * 32,
        "KAPIT_HOSTED_DB_CA": CA,
        "KAPIT_HOSTED_DB_CA_SHA256": hashlib.sha256(CA.encode()).hexdigest(),
        "KAPIT_SECRET_KEY": "k" * 64,
        "KAPIT_SOURCE_KEY": base64.urlsafe_b64encode(bytes(32)).decode(),
        "KAPIT_PUBLIC_ORIGIN": "https://kapit-demo.vercel.app",
        "KAPIT_BACKEND_HOST": "kapit-api.onrender.com",
    }
    env.update(changes)
    return {k: v for k, v in env.items() if v is not None}


class EnvironmentTests(unittest.TestCase):
    def test_accepts_complete_environment(self):
        self.assertEqual(hosted.validate_environment(good_env())["KAPIT_HOSTED_DB_HOST"], POOLER)

    def test_boundary_binds_all_interfaces_only_for_hosted(self):
        selected = boundary(good_env())
        self.assertEqual((selected.context, selected.bind_host, selected.db_port), ("hosted-demo", "0.0.0.0", "5432"))

    def test_rejects_missing_values(self):
        for name in hosted.REQUIRED:
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                hosted.validate_environment(good_env(**{name: None}))

    def test_rejects_libpq_and_local_overrides(self):
        for extra in ({"PGHOST": "evil"}, {"DATABASE_URL": "postgres://x"}, {"KAPIT_DB_PASSWORD": "x"}, {"KAPIT_SECRETS_FILE": "x"}):
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                hosted.validate_environment(good_env(**extra))

    def test_only_approved_project_session_pooler(self):
        for host in ("db.vdemkykykybnxlixondr.supabase.co", "evil.example.com", "aws-0-x.pooler.supabase.com.evil.com"):
            with self.subTest(host=host), self.assertRaises(RuntimeError):
                hosted.validate_environment(good_env(KAPIT_HOSTED_DB_HOST=host))

    def test_certificate_must_match_pin(self):
        with self.assertRaises(RuntimeError):
            hosted.validate_environment(good_env(KAPIT_HOSTED_DB_CA_SHA256="0" * 64))
        escaped = CA.replace("\n", "\\n")
        self.assertEqual(hosted.certificate_bytes(good_env(KAPIT_HOSTED_DB_CA=escaped)), CA.encode())

    def test_origin_and_host_shapes(self):
        for origin in ("http://kapit.vercel.app", "https://kapit.vercel.app/", "https://kapit.vercel.app:8443", "https://*.vercel.app"):
            with self.subTest(origin=origin), self.assertRaises(RuntimeError):
                hosted.validate_environment(good_env(KAPIT_PUBLIC_ORIGIN=origin))
        with self.assertRaises(RuntimeError):
            hosted.validate_environment(good_env(KAPIT_BACKEND_HOST="https://kapit-api.onrender.com"))

    def test_web_settings(self):
        settings = hosted.web_settings(good_env())
        self.assertEqual(settings["CSRF_TRUSTED_ORIGINS"], ["https://kapit-demo.vercel.app"])
        self.assertEqual(settings["ALLOWED_HOSTS"], ["kapit-api.onrender.com", "kapit-demo.vercel.app"])

    def test_database_settings_use_verified_tls_and_dedicated_role(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch("tempfile.gettempdir", return_value=directory):
            settings = hosted.database_settings(good_env())
            self.assertEqual(Path(settings["OPTIONS"]["sslrootcert"]).read_bytes(), CA.encode())
        self.assertEqual(settings["USER"], "kapit_m1_app.vdemkykykybnxlixondr")
        self.assertEqual(settings["OPTIONS"]["sslmode"], "verify-full")
        self.assertEqual(settings["ENGINE"], "config.supabase_backend")

    def test_management_allows_only_worker(self):
        env = {"KAPIT_RUNTIME_CONTEXT": "hosted-demo"}
        validate_hosted_management(["manage.py", "process_jobs"], env)
        for argv in (["manage.py", "migrate"], ["manage.py", "flush"], ["manage.py", "seed_demo"], ["manage.py", "process_jobs", "--settings=x"], ["manage.py"]):
            with self.subTest(argv=argv), self.assertRaises(RuntimeError):
                validate_hosted_management(argv, env)


class ToolTests(unittest.TestCase):
    def test_scram_verifier_matches_rfc5802_derivation(self):
        salt = b"0123456789abcdef"
        verifier = tool.scram_verifier("pencil-password", salt=salt)
        head, keys = verifier.split("$", 1)[1].split("$")
        self.assertEqual(head, "4096:" + base64.b64encode(salt).decode())
        salted = hashlib.pbkdf2_hmac("sha256", b"pencil-password", salt, 4096)
        stored = hashlib.sha256(hmac.new(salted, b"Client Key", hashlib.sha256).digest()).digest()
        server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
        self.assertEqual(keys, base64.b64encode(stored).decode() + ":" + base64.b64encode(server).decode())
        self.assertNotIn("pencil", verifier)

    def test_init_writes_private_files_and_prints_no_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            ca_file = base / "root.crt"
            ca_file.write_bytes(CA.replace("\n", "\r\n").encode())
            with mock.patch.object(tool, "PRIVATE", base / "private"), mock.patch.object(tool, "CONFIG", base / "private/config.json"), \
                    mock.patch.object(tool, "VERCEL", base / "vercel.json"):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    tool.main(["init", "--pooler-host", POOLER, "--ca-file", str(ca_file)])
                    first = json.loads((base / "private/config.json").read_text())
                    tool.main(["init", "--pooler-host", POOLER, "--ca-file", str(ca_file)])
                    tool.main(["set-urls", "--origin", "https://kapit-demo.vercel.app", "--backend-host", "kapit-api.onrender.com"])
                config = json.loads((base / "private/config.json").read_text())
                self.assertEqual(config["db_password"], first["db_password"])  # rerun keeps keys
                self.assertEqual(config["ca"], CA)
                for secret in [config["db_password"], config["secret_key"], config["source_key"], *config["accounts"].values()]:
                    self.assertNotIn(secret, out.getvalue())
                self.assertEqual(len(set(config["accounts"].values())), 4)
                self.assertNotIn(config["db_password"], (base / "private/activate-role.sql").read_text())
                env = dict(line.split("=", 1) for line in (base / "private/render.env").read_text().splitlines() if "=" in line and not line.startswith("#"))
                hosted.validate_environment(env)  # pasted values validate as-is
                vercel = json.loads((base / "vercel.json").read_text())
                self.assertEqual(vercel["rewrites"][0], {"source": "/api/(.*)", "destination": "https://kapit-api.onrender.com/api/$1"})

    def test_init_rejects_other_targets(self):
        with self.assertRaises(RuntimeError):
            tool.main(["init", "--pooler-host", "db.example.com", "--ca-file", "missing"])

    def test_serve_refuses_outside_container_context(self):
        with mock.patch.dict("os.environ", {"KAPIT_RUNTIME_CONTEXT": "native"}), self.assertRaises(RuntimeError):
            tool.serve()


if __name__ == "__main__":
    unittest.main()
