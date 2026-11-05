import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from infra import package_source


class PackageSourceTest(unittest.TestCase):
    def tree(self, files):
        root = Path(tempfile.mkdtemp())
        for relative, data in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def test_ignore_rules_and_scanner_work_binaries_are_excluded(self):
        root = self.tree({"README.md": b"r", "backend/manage.py": b"m", ".env.example": b"e", "web/src/a.ts": b"a",
                          ".cache/m1-runtime/db.bin": b"x", "web/node_modules/p/i.js": b"x", "web/dist/i.js": b"x",
                          "android/app/build/o.apk": b"x", "android/.tooling/avd.img": b"x", "backend/x/__pycache__/m.pyc": b"x",
                          "ai/state/private-scanner-postflight-pcre-work-abc/docker.exe": b"x", "ai/state/source-snapshot.json": b"{}",
                          ".claude/settings.json": b"x", "web/debug.log": b"x"})
        self.assertEqual([".env.example", "README.md", "ai/state/source-snapshot.json", "backend/manage.py", "web/src/a.ts"],
                         package_source.collect(root))

    def test_secret_shaped_files_fail_instead_of_being_skipped(self):
        for name in ("infra/secrets.json", "android/release.jks", "config/.env.local", "x/pgpass", "keys/server.pem"):
            with self.subTest(name=name), self.assertRaises(package_source.PackageError):
                package_source.collect(self.tree({"README.md": b"r", name: b"s"}))

    def test_build_is_deterministic_and_verify_detects_tampering(self):
        root = self.tree({"README.md": b"readme", "infra/tool.py": b"print(1)\n"})
        first = package_source.build(root, Path(tempfile.mkdtemp()))
        output = Path(tempfile.mkdtemp())
        second = package_source.build(root, output)
        self.assertEqual(first["archive_sha256"], second["archive_sha256"])
        archive, manifest = output / "kapit-c2-source.zip", output / "kapit-c2-source.manifest.json"
        result = package_source.verify(archive, manifest, Path(tempfile.mkdtemp()) / "replay")
        self.assertEqual(2, result["verified_files"])
        with self.assertRaises(package_source.PackageError):
            package_source.verify(archive, manifest, root)  # non-empty destination
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"][0]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(package_source.PackageError):
            package_source.verify(archive, manifest, Path(tempfile.mkdtemp()) / "replay")

    def test_entries_use_fixed_time_and_never_escape(self):
        output = Path(tempfile.mkdtemp())
        package_source.build(self.tree({"a/b.txt": b"x"}), output)
        with zipfile.ZipFile(output / "kapit-c2-source.zip") as bundle:
            self.assertEqual([(1980, 1, 1, 0, 0, 0)], [info.date_time for info in bundle.infolist()])

    def test_only_pinned_evidence_exports_leave_the_runtime_area(self):
        import hashlib
        root = self.tree({"README.md": b"r", ".cache/m1-runtime/run/result.json": b'{"ok": true}', ".cache/m1-runtime/secrets.json": b"k"})
        listing = {"files": [{"path": ".cache/m1-runtime/run/result.json", "sha256": hashlib.sha256(b'{"ok": true}').hexdigest()}]}
        (root / "ai/reports").mkdir(parents=True)
        (root / package_source.EVIDENCE_EXPORTS).write_text(json.dumps(listing), encoding="utf-8")
        output = Path(tempfile.mkdtemp())
        manifest = package_source.build(root, output)
        paths = [item["path"] for item in manifest["files"]]
        self.assertIn(".cache/m1-runtime/run/result.json", paths)
        self.assertNotIn(".cache/m1-runtime/secrets.json", paths)
        (root / ".cache/m1-runtime/run/result.json").write_bytes(b'{"ok": false}')
        with self.assertRaises(package_source.PackageError):
            package_source.build(root, output)  # changed after review
        for bad in (".cache/m1-runtime/secrets.json", "backend/x.py", ".cache/../README.md", ".cache/..\..\README.md"):
            listing["files"] = [{"path": bad, "sha256": "0" * 64}]
            (root / package_source.EVIDENCE_EXPORTS).write_text(json.dumps(listing), encoding="utf-8")
            with self.subTest(bad=bad), self.assertRaises(package_source.PackageError):
                package_source.build(root, output)


if __name__ == "__main__":
    unittest.main()
