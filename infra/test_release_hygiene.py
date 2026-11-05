import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infra import release_hygiene as hygiene


class ReleaseHygieneTests(unittest.TestCase):
    def scan_text(self, text):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "backend").mkdir()
            (root / "backend/sample.py").write_text(text, encoding="utf-8")
            with patch.object(hygiene, "ROOT", root), patch.object(hygiene, "SHIPPED", ("backend",)):
                return hygiene.secret_scan()

    def test_planted_values_are_found_without_echoing_them(self):
        # Built at runtime so this test file does not itself contain a matching value.
        planted = {"aws_access_key": "AKIA" + "Q7XW2M4K9PLR3ZTB",
                   "private_key_block": "-----BEGIN " + "PRIVATE KEY-----",
                   "github_token": "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5",
                   "assigned_secret": "SECRET_KEY = '" + "Zk3P9qL2vX8mN4tR7wY1bC6dF0gH5jK" + "'"}
        secret = "Zk3P9qL2vX8mN4tR7wY1bC6dF0gH5jK"
        for shape in ("KAPIT_SECRET_KEY=" + secret, '  "KAPIT_DB_PASSWORD": "' + secret + '",', "KAPIT_SOURCE_KEY=" + secret,
                      '"password": "' + secret + '"'):
            with self.subTest(shape=shape[:12]):
                result = self.scan_text(shape + "\n")
                self.assertEqual([row["pattern"] for row in result["findings"]], ["assigned_secret"])
                self.assertNotIn(secret, json.dumps(result))
        for name, value in planted.items():
            with self.subTest(pattern=name):
                result = self.scan_text(f"line one\n{value}\n")
                self.assertEqual([(row["pattern"], row["line"]) for row in result["findings"]], [(name, 2)])
                self.assertNotIn(value, json.dumps(result))

    def test_known_public_fixtures_and_clean_text_are_not_findings(self):
        result = self.scan_text("password = 'DemoMaintenance!2026'\npassword: short\nkey = 'kapit_ic_abcd1234_" + "x" * 43 + "'\nplain text\n")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["files_scanned"], 1)

    def test_sbom_lists_locked_python_and_web_components_with_hashes(self):
        document = hygiene.sbom()
        self.assertEqual((document["bomFormat"], document["specVersion"]), ("CycloneDX", "1.5"))
        python = [row for row in document["components"] if row["purl"].startswith("pkg:pypi/")]
        self.assertIn("django", {row["name"].lower() for row in python})
        self.assertTrue(all(row["hashes"][0]["alg"] == "SHA-256" for row in python))
        self.assertTrue(any(row["purl"].startswith("pkg:npm/") for row in document["components"]))

    def test_findings_outside_tests_fail_the_gate_and_test_fixtures_are_listed_only(self):
        for in_test, code in ((True, 0), (False, 1)):
            finding = {"file": "x", "line": 1, "pattern": "assigned_secret", "in_test": in_test, "value_sha256_prefix": "0" * 12}
            with self.subTest(in_test=in_test), patch.object(hygiene, "secret_scan", return_value={"files_scanned": 1, "findings": [finding]}), \
                    patch("builtins.print"):
                self.assertEqual(hygiene.main([]), code)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for relative in ("backend/tests/sample.py", "backend/test_sample.py", "backend/app.py"):
                (root / relative).parent.mkdir(parents=True, exist_ok=True)
                (root / relative).write_text("KAPIT_SOURCE_KEY=" + "Zk3P9qL2vX8mN4tR7wY1bC6dF0gH5jK" + "\n", encoding="utf-8")
            with patch.object(hygiene, "ROOT", root), patch.object(hygiene, "SHIPPED", ("backend",)):
                rows = {row["file"]: row["in_test"] for row in hygiene.secret_scan()["findings"]}
        self.assertEqual(rows, {"backend/tests/sample.py": True, "backend/test_sample.py": True, "backend/app.py": False})

    def test_refuses_to_overwrite_an_existing_sbom(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "sbom.json"
            target.write_text("{}", encoding="utf-8")
            with patch.object(hygiene, "secret_scan", return_value={"files_scanned": 0, "findings": []}), \
                    self.assertRaises(SystemExit):
                hygiene.main(["--sbom", str(target)])
            self.assertEqual(target.read_text(encoding="utf-8"), "{}")


if __name__ == "__main__":
    unittest.main()
