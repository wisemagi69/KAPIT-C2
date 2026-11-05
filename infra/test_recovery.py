from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infra import recovery


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cache = self.root / ".cache"
        self.cache.mkdir()
        self.archive = self.cache / "backup.dump"
        self.archive.write_bytes(b"synthetic dump")
        self.storage = self.cache / "storage.snapshot"
        self.storage.write_bytes(b"synthetic encrypted storage")
        self.key = self.cache / "private.key"
        self.key.write_bytes(b"PRIVATE_KEY_CANARY")
        digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        self.expected = recovery.ExpectedBackup(digest(self.archive), digest(self.storage), 16, "a" * 64, "b" * 64, frozenset({"key-1"}))
        self.manifest = {"schema": 1, "archive_sha256": self.expected.archive_sha256, "storage_sha256": self.expected.storage_sha256, "postgres_major": 16, "code_sha256": "a" * 64, "migrations_sha256": "b" * 64, "key_ids": ["key-1"]}
        self.args = dict(archive=self.archive, storage_snapshot=self.storage, key_inventory={"key-1": self.key}, target_id="1" * 32, port=56400, expected=self.expected)
        self.patcher = patch.object(recovery, "ROOT", self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.listener = patch.object(recovery, "_port_free")
        self.port = self.listener.start()
        self.addCleanup(self.listener.stop)

    def prepare(self, **overrides):
        return recovery.prepare(self.manifest, **(self.args | overrides))

    def test_valid_preparation_no_write_no_key_read_no_restore_claim(self):
        before = set(self.root.rglob("*"))
        original_open = Path.open
        def guarded_open(path, *args, **kwargs):
            if path == self.key:
                raise AssertionError("key material read")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", guarded_open):
            result = self.prepare()
        self.assertEqual(set(self.root.rglob("*")), before)
        self.assertEqual(result["status"], "PREPARED_NOT_RESTORED")
        self.assertEqual(result["application"], "CLOSED")
        self.assertIs(result["target_reserved"], False)
        self.assertIs(result["key_material_verified"], False)
        self.assertNotIn("PRIVATE_KEY_CANARY", json.dumps(result))
        self.assertNotIn(str(self.archive), json.dumps(result))

    def test_corrupt_archive_or_storage(self):
        for path in (self.archive, self.storage):
            data = path.read_bytes()
            path.write_bytes(b"corrupt")
            with self.assertRaisesRegex(recovery.RecoveryGuard, "^BACKUP_DIGEST_MISMATCH$"):
                self.prepare()
            path.write_bytes(data)

    def test_missing_key_and_manifest_or_version_mismatch(self):
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^KEY_INVENTORY_MISSING$"):
            self.prepare(key_inventory={})
        for field in ("postgres_major", "code_sha256", "migrations_sha256"):
            prior = self.manifest[field]
            self.manifest[field] = 17 if field == "postgres_major" else "c" * 64
            with self.assertRaisesRegex(recovery.RecoveryGuard, "^BACKUP_INCOMPATIBLE$"):
                self.prepare()
            self.manifest[field] = prior
        self.manifest["key_ids"] = ["wrong-key"]
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^KEY_INVENTORY_MISMATCH$"):
            self.prepare()

    def test_no_self_declared_or_empty_trusted_inventory(self):
        for expected in (None, replace(self.expected, key_ids=frozenset()), replace(self.expected, archive_sha256="bad")):
            with self.assertRaises(recovery.RecoveryGuard):
                self.prepare(expected=expected)

    def test_retained_ports_paths_and_traversal_refused(self):
        for port in (5432, 55436, 55435, 0, True, 57000):
            with self.subTest(port=port), self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_PORT_INVALID$"):
                self.prepare(port=port)
        for target in ("kapit_m1", "../retained", "", "A" * 32):
            with self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_INVALID$"):
                self.prepare(target_id=target)
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^INPUT_PATH_INVALID$"):
            self.prepare(archive=self.root / "retained.dump")

    def test_preexisting_target_wrong_owner_and_busy_listener(self):
        owned = self.cache / "m4-recovery"
        owned.mkdir()
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_OWNERSHIP_INVALID$"):
            self.prepare()
        marker = owned / "owner.json"
        marker.write_text(json.dumps({"schema": 1, "owner": recovery.OWNER, "workspace": str(self.root)}))
        self.prepare()
        target = owned / self.args["target_id"]
        target.mkdir()
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_PREEXISTS$"):
            self.prepare()
        # A different absent target still fails on a busy listener, without cleanup.
        self.port.side_effect = OSError("SECRET process/path")
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_PORT_UNAVAILABLE$"):
            self.prepare(target_id="2" * 32)
        self.assertTrue(target.is_dir())

    def test_generic_os_failure_is_safe_fixed_code(self):
        with patch.object(recovery, "_digest", side_effect=OSError("SECRET")):
            with self.assertRaisesRegex(recovery.RecoveryGuard, "^PREPARATION_UNAVAILABLE$"):
                self.prepare()

    def test_key_alias_not_hashed_as_archive(self):
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^INPUT_IDENTITY_CONFLICT$"):
            self.prepare(archive=self.key)

    def test_hardlinked_key_alias_refused(self):
        alias = self.cache / "key-alias.dump"
        alias.hardlink_to(self.key)
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^INPUT_IDENTITY_CONFLICT$"):
            self.prepare(archive=alias)

    def test_wrong_owner_marker_refused(self):
        owned = self.cache / "m4-recovery"
        owned.mkdir()
        (owned / "owner.json").write_text(json.dumps({"schema": 1, "owner": "different owner", "workspace": str(self.root)}))
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_OWNERSHIP_INVALID$"):
            self.prepare()

    def test_boolean_owner_schema_is_not_integer_version(self):
        owned = self.cache / "m4-recovery"
        owned.mkdir()
        (owned / "owner.json").write_text(json.dumps({"schema": True, "owner": recovery.OWNER, "workspace": str(self.root)}))
        with self.assertRaisesRegex(recovery.RecoveryGuard, "^TARGET_OWNERSHIP_INVALID$"):
            self.prepare()

    def test_symlink_redirect_refused_without_following_key(self):
        original_resolve = Path.resolve
        def redirected(path, *args, **kwargs):
            if path == self.archive:
                return self.key
            return original_resolve(path, *args, **kwargs)
        with patch.object(Path, "resolve", redirected):
            with self.assertRaisesRegex(recovery.RecoveryGuard, "^INPUT_PATH_INVALID$"):
                self.prepare()


if __name__ == "__main__":
    unittest.main()
