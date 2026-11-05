"""Benign fixtures only: no actual project bundle or native adapter loading."""
import dataclasses
import enum
import hashlib
import sys
import unittest
from types import ModuleType
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from infra import evidence_release_bundle_v2 as b

NOW = "2026-10-24T00:00:01Z"
NONCE = "1" * 32


class Owned:
    def __init__(self, payload, serial, directory=False):
        self.payload = payload
        self.closed = 0
        self.hook = None
        self.facts = dict(volume=2**63 + 13, file_id=f"{serial:032x}",
                          attributes=16 if directory else 0, links=1,
                          size=len(payload), disk=True, private=False, owner="fixture-owner")

    def identity(self):
        return dict(self.facts)

    def read(self, maximum):
        if self.hook:
            self.hook()
        return self.payload[:maximum]

    def close(self):
        self.closed += 1


class Backend:
    def __init__(self, payloads):
        self.parents = {"": Owned(b"", 1, True), "infra": Owned(b"", 2, True)}
        self.sources = {path: Owned(raw, n + 3) for n, ((_, path), raw) in enumerate(zip(b.BUNDLE, payloads))}
        self.opened = []

    def pin_parent(self, path):
        self.opened.append(self.parents[path])
        return self.parents[path]

    def open_source(self, path):
        self.opened.append(self.sources[path])
        return self.sources[path]


class BundleTests(unittest.TestCase):
    def setUp(self):
        # Only fixture isolation. Production loader itself never evicts aliases.
        saved = {n: v for n, v in tuple(sys.modules.items()) if b._target_alias(n)}
        for n in saved:
            del sys.modules[n]
        def restore():
            for n in tuple(sys.modules):
                if b._target_alias(n):
                    del sys.modules[n]
            sys.modules.update(saved)
        self.addCleanup(restore)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.trust = b.OfflineTrust("fixture-key", public, "fixture-policy", "fixture-authority", "fixture-owner")
        self.payloads = [
            b'from dataclasses import dataclass\n@dataclass(frozen=True, slots=True)\nclass Item:\n value: int = 7\n',
            b'from infra.evidence_release_schemas import Item\nALIAS = Item\n',
            b'from infra import evidence_release_bridge\nALIAS = evidence_release_bridge.ALIAS\ndef lazy():\n from infra.evidence_detection_controls import Choice\n return Choice\n',
            b'import infra.evidence_release_lifecycle\nALIAS = infra.evidence_release_lifecycle.ALIAS\n',
            b'from enum import Enum\nclass Choice(str, Enum):\n YES = "yes"\n']
        self.value = dict(scope="PUBLIC_LIBRARY_BUNDLE_V2", version=2,
            key_id=self.trust.key_id, policy=self.trust.policy, authority=self.trust.authority,
            nonce=NONCE, issued_utc="2026-10-24T00:00:00Z", expires_utc="2026-10-24T00:05:00Z", files=[])
        self.external = {"dataclasses": dataclasses, "enum": enum}
        self.refresh()

    def refresh(self):
        self.value["files"] = [dict(id=i, path=p, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for (i, p), raw in zip(b.BUNDLE, self.payloads)]
        self.backend = Backend(self.payloads)

    def signed(self):
        raw = b.canonical(self.value)
        return raw, self.key.sign(b.DOMAIN + raw)

    def load(self, **changes):
        kw = dict(trust=self.trust, now_utc=NOW, expected_nonce=NONCE, trusted_external=self.external)
        kw.update(changes)
        return b.load_synthetic_bundle(self.backend, *self.signed(), **kw)

    def assert_closed(self):
        self.assertTrue(all(o.closed == 1 for o in self.backend.opened))

    def test_dataclass_enum_and_absolute_import_identity(self):
        loaded = self.load()
        schemas, bridge, lifecycle, reservations, parser = [loaded.modules[n] for n in b.MODULES]
        self.assertIs(bridge.ALIAS, schemas.Item)
        self.assertIs(reservations.ALIAS, schemas.Item)
        self.assertIs(lifecycle.lazy(), parser.Choice)
        self.assertEqual(schemas.Item().value, 7)
        self.assertIs(sys.modules[schemas.Item.__module__], schemas)
        self.assertEqual(parser.Choice.YES.value, "yes")
        loaded.close()
        self.assertFalse(any(b._target_alias(n) for n in sys.modules))
        self.assert_closed()

    def test_all_five_hashes_checked_before_compile(self):
        for path in self.backend.sources:
            with self.subTest(path=path):
                self.refresh()
                self.backend.sources[path].payload += b"# altered"
                with patch.object(b, "_COMPILE") as compiler:
                    with self.assertRaises(b.Refused):
                        self.load()
                    compiler.assert_not_called()
                self.assert_closed()

    def test_all_compile_before_first_exec(self):
        self.payloads[-1] = b"syntax ! invalid\n"
        self.refresh()
        with patch.object(b, "_EXEC") as execution:
            with self.assertRaises(b.Refused):
                self.load()
            execution.assert_not_called()
        self.assert_closed()

    def test_signature_refuses_before_backend(self):
        raw, sig = self.signed()
        with self.assertRaises(b.Refused):
            b.load_synthetic_bundle(self.backend, raw, bytes(64), trust=self.trust,
                now_utc=NOW, expected_nonce=NONCE, trusted_external=self.external)
        self.assertEqual(self.backend.opened, [])

    def test_old_signature_domain_refused(self):
        raw, _ = self.signed()
        with self.assertRaises(b.Refused):
            b.verify_manifest(raw, self.key.sign(b"KAPIT-C2/EXECUTABLE-BUNDLE/V1\x00" + raw),
                              trust=self.trust, now_utc=NOW, expected_nonce=NONCE)

    def test_paths_order_and_extra_rows_refused(self):
        for mode in ("order", "path", "extra"):
            self.refresh()
            if mode == "order": self.value["files"].reverse()
            if mode == "path": self.value["files"][0]["path"] = "../other.py"
            if mode == "extra": self.value["files"].append(self.value["files"][0])
            with self.assertRaises(b.Refused): self.load()
            self.assertEqual(self.backend.opened, [])

    def test_nonce_policy_expiry_revocation(self):
        for change in (dict(expected_nonce="2"*32), dict(now_utc="2026-10-24T00:05:00Z"),
                       dict(trust=dataclasses.replace(self.trust, policy="other")),
                       dict(trust=dataclasses.replace(self.trust, revoked_key_ids=("fixture-key",)))):
            with self.assertRaises(b.Refused): self.load(**change)

    def test_cached_bare_dotted_case_and_private_prefix_refused(self):
        for name in (b.MODULES[0], b.MODULES[0].upper(), "evidence_release_schemas", b.NAMESPACE + ".extra"):
            sys.modules[name] = ModuleType(name)
            with self.assertRaises(b.Refused): self.load()
            self.assertEqual(self.backend.opened, [])
            del sys.modules[name]

    def test_duplicate_full_identity_refused(self):
        rows = list(self.backend.sources.values())
        rows[-1].facts["file_id"] = rows[0].facts["file_id"]
        with self.assertRaises(b.Refused): self.load()
        self.assert_closed()

    def test_handle_identity_mutation_refused(self):
        rows = list(self.backend.sources.values())
        rows[0].hook = lambda: rows[-1].facts.update(links=2)
        with self.assertRaises(b.Refused): self.load()
        self.assert_closed()

    def test_callback_substitution_does_not_change_owned_close(self):
        row = list(self.backend.sources.values())[0]
        row.hook = lambda: setattr(row, "close", lambda: self.fail("replacement called"))
        loaded = self.load()
        loaded.close()
        self.assertEqual(row.closed, 1)

    def test_namespace_replacement_not_deleted_and_sticky(self):
        loaded = self.load()
        replacement = ModuleType("replacement")
        sys.modules[b.OWNED_NAMES[-1]] = replacement
        with self.assertRaises(b.Refused): loaded.close()
        self.assertIs(sys.modules[b.OWNED_NAMES[-1]], replacement)
        with self.assertRaises(b.Refused): loaded.close()
        self.assert_closed()

    def test_extra_namespace_alias_refused_and_not_deleted(self):
        loaded = self.load()
        name = b.NAMESPACE + ".extra"
        sys.modules[name] = ModuleType(name)
        with self.assertRaises(b.Refused): loaded.close()
        self.assertIn(name, sys.modules)
        self.assert_closed()

    def test_package_child_substitution_refuses_lazy_import_and_cleanup(self):
        loaded = self.load()
        package = sys.modules[b.NAMESPACE]
        package.evidence_detection_controls = ModuleType("replacement")
        with self.assertRaises(b.Refused): loaded.recheck()
        with self.assertRaises(b.Refused): loaded.modules[b.MODULES[2]].lazy()
        with self.assertRaises(b.Refused): loaded.close()
        self.assert_closed()

    def test_lazy_import_after_close_refused(self):
        loaded = self.load()
        lazy = loaded.modules[b.MODULES[2]].lazy
        loaded.close()
        with self.assertRaises(b.Refused): lazy()

    def test_recheck_failure_stays_failed_after_namespace_restored(self):
        loaded = self.load()
        package = sys.modules[b.NAMESPACE]
        original = package.evidence_release_bridge
        package.evidence_release_bridge = ModuleType("replacement")
        with self.assertRaises(b.Refused): loaded.recheck()
        package.evidence_release_bridge = original
        with self.assertRaises(b.Refused): loaded.recheck()
        with self.assertRaises(b.Refused): loaded.close()
        self.assert_closed()

    def test_smoke_constructor_failure_closes_original_stream(self):
        class Stream:
            closed = 0
            def fileno(self): raise OSError("fixture stat failure")
            def close(self): self.closed += 1
        stream = Stream()
        class FakePath:
            def is_symlink(self): return False
            def open(self, mode):
                self.mode = mode
                return stream
        path = FakePath()
        with self.assertRaises(OSError): b._SmokeSource(path, False, 3, "fixture-owner")
        self.assertEqual(path.mode, "rb")
        self.assertEqual(stream.closed, 1)

    def test_unknown_relative_forward_imports_refused(self):
        for source in (b"import subprocess\n", b"from . import unknown\n",
                       b"from infra.evidence_detection_controls import Choice\n"):
            self.payloads[0] = source
            self.refresh()
            with self.assertRaises(b.Refused): self.load()
            self.assert_closed()
            self.assertFalse(any(b._target_alias(n) for n in sys.modules))

    def test_module_initializer_failure_cleans_all(self):
        self.payloads[-1] = b"raise RuntimeError('fixture')\n"
        self.refresh()
        with self.assertRaises(b.Refused): self.load()
        self.assert_closed()
        self.assertFalse(any(b._target_alias(n) for n in sys.modules))

    def test_close_failure_is_sticky_and_other_handles_closed(self):
        row = list(self.backend.sources.values())[-1]
        def fail():
            row.closed += 1
            raise RuntimeError()
        row.close = fail
        loaded = self.load()
        with self.assertRaises(b.Refused): loaded.close()
        with self.assertRaises(b.Refused): loaded.close()
        self.assert_closed()

    def test_production_unconditionally_closed(self):
        class Trap:
            def __getattribute__(self, name): raise AssertionError("input touched")
        with self.assertRaises(b.Refused): b.production_bootstrap(Trap())

    def test_cli_invalid_arguments_never_run_smoke(self):
        for args in ([], ["--public-library-smoke", "other"], ["--source", "private"]):
            with patch.object(b, "_public_library_smoke") as smoke, patch("builtins.print"):
                self.assertEqual(b.main(args), 1)
                smoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
