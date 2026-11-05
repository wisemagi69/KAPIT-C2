"""Actual Ed25519 and benign Python fixture loading; no real target execution."""
import hashlib
import dataclasses
import sys
import unittest
from dataclasses import replace
from types import ModuleType
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from infra import evidence_release_bootstrap as b

NOW = "2026-10-24T00:00:01Z"
NONCE = "1" * 32


class Owned:
    def __init__(self, payload, serial, directory=False):
        self.payload, self.offset = payload, 0
        self.closed, self.close_calls = False, 0
        self.facts = dict(volume=2**63 + 123, file_id=f"{serial:032x}",
            attributes=0x10 if directory else 0, links=1, size=len(payload),
            disk=True, private=False, owner="fixture-owner")
        self.read_hook = self.identity_hook = self.close_hook = None

    def identity(self):
        if self.identity_hook:
            self.identity_hook(self)
        return dict(self.facts)

    def read(self, maximum):
        if self.read_hook:
            self.read_hook(self)
        result = self.payload[self.offset:self.offset + maximum]
        self.offset += len(result)
        return result

    def close(self):
        self.close_calls += 1
        self.closed = True
        if self.close_hook:
            return self.close_hook(self)


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


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        # Test fixture isolation only: production still refuses cached targets.
        aliases = {name.casefold() for name in b.MODULES}
        aliases.update(name.rsplit(".", 1)[-1].casefold() for name in b.MODULES)
        saved = {name: module for name, module in tuple(sys.modules.items())
                 if type(name) is str and name.casefold() in aliases}
        for name in saved:
            del sys.modules[name]
        def restore():
            for name in tuple(sys.modules):
                if type(name) is str and name.casefold() in aliases:
                    del sys.modules[name]
            sys.modules.update(saved)
        self.addCleanup(restore)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.trust = b.OfflineTrust("fixture-key", public, "fixture-policy", "fixture-authority", "fixture-owner")
        self.payloads = [b"VALUE = 7\n", b"from infra.evidence_release_schemas import VALUE\nVALUE += 1\n",
            b"from infra import evidence_release_bridge\nVALUE = evidence_release_bridge.VALUE + 1\n",
            b"import infra.evidence_release_lifecycle\nVALUE = infra.evidence_release_lifecycle.VALUE + 1\n"]
        self.value = dict(scope="PUBLIC_EXECUTABLE_BUNDLE_V1", version=1, key_id=self.trust.key_id,
            policy=self.trust.policy, authority=self.trust.authority, nonce=NONCE,
            issued_utc="2026-10-24T00:00:00Z", expires_utc="2026-10-24T00:05:00Z", files=[])
        self.refresh()

    def refresh(self):
        self.value["files"] = [dict(id=i, path=p, size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            for (i, p), raw in zip(b.BUNDLE, self.payloads)]
        self.backend = Backend(self.payloads)

    def signed(self, value=None):
        raw = b.canonical(self.value if value is None else value)
        return raw, self.key.sign(b.DOMAIN + raw)

    def load(self, **kwargs):
        raw, sig = self.signed()
        args = dict(trust=self.trust, now_utc=NOW, expected_nonce=NONCE, trusted_external={})
        args.update(kwargs)
        return b.load_synthetic_bundle(self.backend, raw, sig, **args)

    def refuse(self, **kwargs):
        with self.assertRaises(b.Refused):
            self.load(**kwargs)
        self.assertTrue(all(o.closed for o in self.backend.opened))

    def test_complete_signed_benign_imports_and_original_closure(self):
        bundle = self.load()
        self.assertEqual(bundle.modules[b.MODULES[-1]].VALUE, 10)
        self.assertTrue(all(not o.closed for o in self.backend.opened))
        bundle.close()
        bundle.close()
        self.assertTrue(all(o.close_calls == 1 for o in self.backend.opened))
        self.assertTrue(all(name not in sys.modules for name in b.MODULES))

    def test_gate_before_argument_backend_access(self):
        class Poison:
            def __getattribute__(self, name):
                raise AssertionError(name)
        with self.assertRaises(b.Refused):
            b.production_bootstrap(Poison(), trust=Poison())

    def test_signature_tampering(self):
        raw, sig = self.signed()
        for altered_raw, altered_sig in ((raw+b" ", sig), (raw, bytes(64)), (raw, sig[:-1])):
            with self.subTest(case=len(altered_raw)), self.assertRaises(b.Refused):
                b.verify_manifest(altered_raw, altered_sig, trust=self.trust, now_utc=NOW, expected_nonce=NONCE)

    def test_wrong_domain(self):
        raw, _ = self.signed()
        with self.assertRaises(b.Refused):
            b.verify_manifest(raw, self.key.sign(raw), trust=self.trust, now_utc=NOW, expected_nonce=NONCE)

    def test_wrong_key_revocation_and_independent_policy(self):
        for trust in (replace(self.trust, public_key=bytes(32)), replace(self.trust, revoked_key_ids=(self.trust.key_id,)),
                      replace(self.trust, policy="other"), replace(self.trust, authority="other")):
            with self.subTest(trust=trust.policy):
                self.refuse(trust=trust)
                self.assertEqual(self.backend.opened, [])

    def test_nonce_and_expiry_freshness(self):
        for kwargs in (dict(expected_nonce="2"*32), dict(expected_nonce="1"*64), dict(now_utc="2026-10-23T23:59:59Z"),
                       dict(now_utc="2026-10-24T00:05:00Z"), dict(now_utc="２０２６-10-24T00:00:01Z")):
            with self.subTest(kwargs=kwargs):
                self.refuse(**kwargs)
                self.assertEqual(self.backend.opened, [])

    def test_closed_manifest_extra_fields_and_long_validity(self):
        for key, value in (("unknown", 1), ("version", True), ("expires_utc", "2026-10-24T00:05:01Z"),
                           ("scope", "OTHER")):
            original = self.value.copy()
            self.value[key] = value
            self.refuse()
            self.value = original

    def test_path_order_and_aliases(self):
        for change in ("Infra/evidence_release_schemas.py", "../infra/evidence_release_schemas.py", "schemas.py"):
            self.value["files"][0]["path"] = change
            self.refuse()
        self.refresh()
        self.value["files"].reverse()
        self.refuse()

    def test_canonical_ascii_and_duplicate_keys(self):
        raw, _ = self.signed()
        for changed in (raw+b"\n", raw.replace(b'"version":1', b'"version":1,"version":1')):
            with self.assertRaises(b.Refused):
                b.verify_manifest(changed, self.key.sign(b.DOMAIN+changed), trust=self.trust, now_utc=NOW, expected_nonce=NONCE)

    def test_all_verified_before_first_compile(self):
        self.backend.sources[b.BUNDLE[-1][1]].payload += b"# tamper"
        with patch.object(b, "_COMPILE", side_effect=AssertionError("compile must not run")) as compiler:
            self.refuse()
            compiler.assert_not_called()

    def test_missing_final_source_closes_originals(self):
        del self.backend.sources[b.BUNDLE[-1][1]]
        self.refuse()

    def test_full_width_identity_not_truncated(self):
        resource = self.backend.sources[b.BUNDLE[0][1]]
        calls = [0]
        def hook(obj):
            calls[0] += 1
            if calls[0] == 2:
                obj.facts["volume"] += 2**32
        resource.identity_hook = hook
        self.refuse()

    def test_same_byte_replacement_file_id(self):
        self.backend.sources[b.BUNDLE[0][1]].read_hook = lambda obj: obj.facts.update(file_id="f"*32)
        self.refuse()

    def test_reparse_hardlink_owner_disk_and_type_denials(self):
        changes = (dict(attributes=0x400), dict(attributes=0x40), dict(attributes=0x10), dict(links=2),
                   dict(owner="other"), dict(disk=False), dict(private=1), dict(volume=True), dict(file_id="0"*32))
        for change in changes:
            with self.subTest(change=change):
                self.refresh()
                self.backend.sources[b.BUNDLE[0][1]].facts.update(change)
                self.refuse()

    def test_parent_replacement_and_alias_identity(self):
        self.backend.parents["infra"].facts["file_id"] = self.backend.parents[""].facts["file_id"]
        self.refuse()

    def test_short_read_and_extra_sentinel(self):
        self.backend.sources[b.BUNDLE[0][1]].payload = b"x"
        self.refuse()
        self.refresh()
        resource = self.backend.sources[b.BUNDLE[0][1]]
        resource.read = lambda maximum: self.payloads[0] + b"x"
        self.refuse()

    def test_sys_modules_bare_dotted_and_case_aliases(self):
        for alias in (b.MODULES[0], b.MODULES[0].upper(), "evidence_release_schemas"):
            with self.subTest(alias=alias), patch.dict(sys.modules, {alias: ModuleType(alias)}):
                self.refuse()
                self.assertEqual(self.backend.opened, [])

    def test_dependency_escape_no_path_fallback(self):
        for source in (b"import sys\n", b"import infra.other_module\n", b"from infra import other_module\n",
                       b"from . import evidence_release_bridge\n", b"import os\n"):
            self.payloads[0] = source
            self.refresh()
            self.refuse()

    def test_forward_dependency_refused(self):
        self.payloads[0] = b"import infra.evidence_release_reservations\n"
        self.refresh()
        self.refuse()

    def test_explicit_external_dependency(self):
        self.payloads[0] = b"import math\nVALUE = math.VALUE\n"
        self.refresh()
        external = ModuleType("math")
        external.VALUE = 7
        bundle = self.load(trusted_external={"math": external})
        bundle.close()
        self.refresh()
        self.refuse(trusted_external={"sys": sys})

    def test_current_style_dataclass_without_registration(self):
        self.payloads[-1] = (b"from dataclasses import dataclass\n"
            b"@dataclass(frozen=True)\nclass Fixture:\n    value: int\n"
            b"VALUE = Fixture(10).value\n")
        self.refresh()
        bundle = self.load(trusted_external={"dataclasses": dataclasses})
        self.assertEqual(bundle.modules[b.MODULES[-1]].VALUE, 10)
        self.assertNotIn(b.MODULES[-1], sys.modules)
        bundle.close()

    def test_explicit_candidate_stdlib_imports_without_native_calls(self):
        self.payloads[-1] = (b"import ctypes\nfrom ctypes import wintypes\nimport ntpath\n"
            b"VALUE = ctypes.VALUE + wintypes.VALUE + ntpath.VALUE\n")
        self.refresh()
        ctypes_fixture = ModuleType("ctypes")
        wintypes_fixture = ModuleType("ctypes.wintypes")
        ntpath_fixture = ModuleType("ntpath")
        ctypes_fixture.VALUE = 3
        wintypes_fixture.VALUE = 3
        ntpath_fixture.VALUE = 4
        ctypes_fixture.wintypes = wintypes_fixture
        bundle = self.load(trusted_external={"ctypes": ctypes_fixture,
            "ctypes.wintypes": wintypes_fixture, "ntpath": ntpath_fixture})
        self.assertEqual(bundle.modules[b.MODULES[-1]].VALUE, 10)
        bundle.close()

    def test_compile_failure_closes_all(self):
        self.payloads[-1] = b"this is not valid Python !\n"
        self.refresh()
        self.refuse()

    def test_exec_failure_closes_all(self):
        self.payloads[-1] = b"raise RuntimeError('fixture')\n"
        self.refresh()
        self.refuse()

    def test_late_mutation_during_loading(self):
        external = ModuleType("math")
        external.mutate = lambda: self.backend.sources[b.BUNDLE[-1][1]].facts.update(file_id="f"*32)
        self.payloads[-1] = b"import math\nmath.mutate()\n"
        self.refresh()
        self.refuse(trusted_external={"math": external})

    def test_callbacks_captured_before_fixture_exec(self):
        external = ModuleType("math")
        def mutate():
            for obj in self.backend.opened:
                obj.close = lambda: (_ for _ in ()).throw(AssertionError("replacement"))
                obj.identity = lambda: {}
        external.mutate = mutate
        self.payloads[-1] = b"import math\nmath.mutate()\n"
        self.refresh()
        bundle = self.load(trusted_external={"math": external})
        bundle.close()
        self.assertTrue(all(o.closed for o in self.backend.opened))

    def test_close_uncertainty_sticky_and_all_resources_attempted(self):
        bundle = self.load()
        self.backend.sources[b.BUNDLE[0][1]].close_hook = lambda obj: (_ for _ in ()).throw(OSError("closed then error"))
        for _ in range(2):
            with self.assertRaises(b.Refused):
                bundle.close()
        self.assertTrue(all(o.closed for o in self.backend.opened))

    def test_close_non_none_refused(self):
        bundle = self.load()
        self.backend.parents[""].close_hook = lambda obj: False
        with self.assertRaises(b.Refused):
            bundle.close()


if __name__ == "__main__":
    unittest.main()
