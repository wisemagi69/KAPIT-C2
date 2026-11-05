"""Independent signed benign graph checks; no actual project bundle/native APIs."""
import dataclasses
import enum
import hashlib
import sys
import unittest
from types import ModuleType
from unittest.mock import patch

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from infra import evidence_release_bundle_v2 as loader
except ImportError:
    loader = None


class Handle:
    def __init__(self, raw, serial, directory=False):
        self.raw, self.closes, self.reads = raw, 0, []
        self.on_read = None
        self.facts = dict(volume=2**63+73, file_id=f"{serial:032x}",
            attributes=16 if directory else 0, links=1, size=len(raw),
            disk=True, private=False, owner="qa-owner")

    def identity(self):
        return dict(self.facts)

    def read(self, limit):
        self.reads.append(limit)
        if self.on_read:
            self.on_read()
        return self.raw[:limit]

    def close(self):
        self.closes += 1


class Provider:
    def __init__(self, raws):
        self.parents = {"": Handle(b"", 1, True), "infra": Handle(b"", 2, True)}
        self.files = {p: Handle(raw, i+3) for i, ((_, p), raw) in enumerate(zip(loader.BUNDLE, raws))}
        self.opened = []

    def pin_parent(self, path):
        self.opened.append(self.parents[path])
        return self.parents[path]

    def open_source(self, path):
        self.opened.append(self.files[path])
        return self.files[path]


@unittest.skipIf(loader is None, "project venv cryptography required")
class RuntimeBundleIndependentQA(unittest.TestCase):
    def setUp(self):
        saved = {k: v for k, v in tuple(sys.modules.items()) if loader._target_alias(k)}
        for k in saved:
            del sys.modules[k]
        registry = sys.modules
        def restore():
            sys.modules = registry
            for k in tuple(registry):
                if loader._target_alias(k):
                    del registry[k]
            registry.update(saved)
        self.addCleanup(restore)
        self.key = Ed25519PrivateKey.generate()
        self.trust = loader.OfflineTrust("qa-key", self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
            "qa-policy", "qa-authority", "qa-owner")
        self.raws = [
            b"from dataclasses import dataclass\n@dataclass(frozen=True, slots=True)\nclass Sample:\n value: int = 42\n",
            b"from infra.evidence_release_schemas import Sample\nITEM = Sample\n",
            b"def lazy():\n from infra import evidence_release_bridge\n return evidence_release_bridge.ITEM\ndef parser():\n from infra.evidence_detection_controls import Mode\n return Mode\n",
            b"from infra.evidence_release_bridge import ITEM\n",
            b"from enum import Enum\nclass Mode(str, Enum):\n SAFE = 'safe'\n"]
        self.external = {"dataclasses": dataclasses, "enum": enum}
        self.reset()

    def reset(self):
        self.provider = Provider(self.raws)
        self.manifest = dict(scope="PUBLIC_LIBRARY_BUNDLE_V2", version=2, key_id="qa-key", policy="qa-policy",
            authority="qa-authority", nonce="a"*32, issued_utc="2026-10-24T00:00:00Z",
            expires_utc="2026-10-24T00:05:00Z", files=[dict(id=i,path=p,size=len(raw),
            sha256=hashlib.sha256(raw).hexdigest()) for (i,p),raw in zip(loader.BUNDLE,self.raws)])

    def load(self, manifest=None, domain=None, **changes):
        raw = loader.canonical(self.manifest if manifest is None else manifest)
        kwargs = dict(trust=self.trust, now_utc="2026-10-24T00:00:01Z", expected_nonce="a"*32,
            trusted_external=self.external)
        kwargs.update(changes)
        return loader.load_synthetic_bundle(self.provider,raw,self.key.sign((loader.DOMAIN if domain is None else domain)+raw),**kwargs)

    def closed(self):
        self.assertTrue(all(h.closes == 1 for h in self.provider.opened))

    def test_real_decorators_and_lazy_identity(self):
        result = self.load()
        schemas,bridge,lifecycle,reservations,parser = [result.modules[n] for n in loader.MODULES]
        self.assertIs(lifecycle.lazy(),schemas.Sample)
        self.assertIs(lifecycle.parser(),parser.Mode)
        self.assertIs(bridge.ITEM,reservations.ITEM)
        self.assertEqual(schemas.Sample().value,42)
        self.assertIs(sys.modules[schemas.Sample.__module__],schemas)
        result.close(); self.closed()
        self.assertFalse(any(loader._target_alias(k) for k in sys.modules))

    def test_each_source_digest_before_any_compilation(self):
        for index in range(5):
            self.reset()
            list(self.provider.files.values())[index].raw = b"x"*len(self.raws[index])
            with patch.object(loader,"_COMPILE") as compile_spy:
                with self.assertRaises(loader.Refused): self.load()
                compile_spy.assert_not_called()
            self.closed()

    def test_last_syntax_error_executes_nothing(self):
        self.raws[-1]=b"syntax @ !\n"; self.reset()
        with patch.object(loader,"_EXEC") as execute:
            with self.assertRaises(loader.Refused): self.load()
            execute.assert_not_called()
        self.closed()

    def test_fixed_graph_mutations_refuse_before_provider(self):
        for mode in ("missing","order","path","id","oversized","boolsize"):
            self.reset(); rows=self.manifest["files"]
            if mode=="missing": rows.pop()
            elif mode=="order": rows.reverse()
            elif mode=="path": rows[0]["path"]="infra/../private.py"
            elif mode=="id": rows[0]["id"]="other"
            elif mode=="oversized": rows[0]["size"]=1048577
            else: rows[0]["size"]=True
            with self.assertRaises(loader.Refused): self.load()
            self.assertEqual(self.provider.opened,[])

    def test_old_domain_and_scope_refused(self):
        with self.assertRaises(loader.Refused): self.load(domain=b"KAPIT-C2/EXECUTABLE-BUNDLE/V1\x00")
        self.manifest["scope"]="PUBLIC_EXECUTABLE_BUNDLE_V1"
        with self.assertRaises(loader.Refused): self.load()
        self.assertEqual(self.provider.opened,[])

    def test_stale_future_nonce_revoked_and_wrong_key(self):
        for changes in (dict(now_utc="2026-10-24T00:05:00Z"),dict(now_utc="2026-10-23T23:59:59Z"),
            dict(expected_nonce="b"*32),dict(trust=dataclasses.replace(self.trust,revoked_key_ids=("qa-key",))),
            dict(trust=dataclasses.replace(self.trust,public_key=bytes(32)))):
            with self.assertRaises(loader.Refused): self.load(**changes)
        self.assertEqual(self.provider.opened,[])

    def test_all_alias_forms_refuse_without_eviction(self):
        for name in (loader.NAMESPACE.upper(),loader.NAMESPACE+".unknown",loader.MODULES[-1].upper(),"evidence_detection_controls"):
            marker=ModuleType(name); sys.modules[name]=marker
            with self.assertRaises(loader.Refused): self.load()
            self.assertIs(sys.modules[name],marker)
            del sys.modules[name]
        self.assertEqual(self.provider.opened,[])

    def test_late_private_alias_refuses_keeps_foreign(self):
        result=self.load(); name=loader.NAMESPACE+".alien"; marker=ModuleType(name); sys.modules[name]=marker
        with self.assertRaises(loader.Refused): result.close()
        self.assertIs(sys.modules[name],marker); self.closed()
        with self.assertRaises(loader.Refused): result.close()

    def test_replaced_module_refuses_preserves_foreign(self):
        result=self.load(); name=loader.OWNED_NAMES[2]; marker=ModuleType(name); sys.modules[name]=marker
        with self.assertRaises(loader.Refused): result.close()
        self.assertIs(sys.modules[name],marker); self.closed()

    def test_registry_dictionary_substitution_refuses_and_closes_originals(self):
        result=self.load(); original=sys.modules; replacement=dict(original); sys.modules=replacement
        try:
            with self.assertRaises(loader.Refused): result.close()
            self.assertFalse(any(loader._target_alias(k) for k in original))
            self.assertTrue(any(loader._target_alias(k) for k in replacement))
            self.closed()
        finally:
            sys.modules=original

    def test_package_child_substitution_is_detected(self):
        result=self.load(); package=sys.modules[loader.NAMESPACE]
        package.evidence_release_bridge=ModuleType("foreign")
        with self.assertRaises(loader.Refused): result.recheck()
        with self.assertRaises(loader.Refused): result.close()
        self.closed()

    def test_full_identity_high_bits_and_duplicate(self):
        values=list(self.provider.files.values()); values[-1].facts.update(volume=values[0].facts["volume"],file_id=values[0].facts["file_id"])
        with self.assertRaises(loader.Refused): self.load()
        self.closed()

    def test_last_handle_reparse_and_multilink_refused(self):
        for field,value in (("attributes",0x400),("links",2),("volume",True),("disk",1)):
            self.reset(); list(self.provider.files.values())[-1].facts[field]=value
            with self.assertRaises(loader.Refused): self.load()
            self.closed()

    def test_source_growth_sentinel_closes_all(self):
        list(self.provider.files.values())[-1].raw+=b"x"
        with self.assertRaises(loader.Refused): self.load()
        self.closed()

    def test_original_close_and_read_retained(self):
        row=list(self.provider.files.values())[0]
        def substitute():
            row.close=lambda: self.fail("foreign close")
            row.read=lambda limit: self.fail("foreign read")
        row.on_read=substitute
        result=self.load(); result.close(); self.closed()

    def test_constructor_identity_failure_still_closes_returned_object(self):
        row=list(self.provider.files.values())[0]
        row.identity=lambda: (_ for _ in ()).throw(ValueError())
        with self.assertRaises(loader.Refused): self.load()
        self.closed()

    def test_initializer_systemexit_closes_and_removes_namespace(self):
        self.raws[2]=b"raise SystemExit(7)\n"; self.reset()
        with self.assertRaises(loader.Refused): self.load()
        self.closed(); self.assertFalse(any(loader._target_alias(k) for k in sys.modules))

    def test_unknown_relative_forward_imports_no_fallback(self):
        for raw in (b"import subprocess\n",b"from . import other\n",b"from infra import evidence_detection_controls\n"):
            self.raws[0]=raw; self.reset()
            with self.assertRaises(loader.Refused): self.load()
            self.closed(); self.assertFalse(any(loader._target_alias(k) for k in sys.modules))

    def test_close_failure_sticky_all_originals_attempted_once(self):
        row=list(self.provider.files.values())[-1]
        def broken_close():
            row.closes+=1
            raise OSError()
        row.close=broken_close
        result=self.load()
        with self.assertRaises(loader.Refused): result.close()
        with self.assertRaises(loader.Refused): result.close()
        self.closed()

    def test_production_untouched_and_cli_other_arguments_closed(self):
        class Poison:
            def __getattribute__(self,name): raise AssertionError(name)
        with self.assertRaises(loader.Refused): loader.production_bootstrap(Poison())
        with patch.object(loader,"_public_library_smoke") as smoke, patch("builtins.print"):
            for args in ([],["--public-library-smoke","extra"],["--output","private"]):
                self.assertEqual(loader.main(args),1)
            smoke.assert_not_called()

    def test_lazy_import_after_close_refused(self):
        result=self.load(); lazy=result.modules[loader.MODULES[2]].lazy
        result.close()
        with self.assertRaises(loader.Refused): lazy()
        self.closed()

    def test_lazy_package_attribute_substitution_refused(self):
        result=self.load(); lazy=result.modules[loader.MODULES[2]].lazy
        sys.modules[loader.NAMESPACE].evidence_release_bridge=ModuleType("foreign")
        with self.assertRaises(loader.Refused): lazy()
        with self.assertRaises(loader.Refused): result.close()
        self.closed()

    def test_signed_noncanonical_manifest_refused_before_open(self):
        import json
        raw=json.dumps(self.manifest,indent=2).encode("ascii")
        with self.assertRaises(loader.Refused):
            loader.load_synthetic_bundle(self.provider,raw,self.key.sign(loader.DOMAIN+raw),trust=self.trust,
                now_utc="2026-10-24T00:00:01Z",expected_nonce="a"*32,trusted_external=self.external)
        self.assertEqual(self.provider.opened,[])

    def test_external_map_not_widened_or_dynamically_reused(self):
        self.external["subprocess"]=ModuleType("subprocess")
        with self.assertRaises(loader.Refused): self.load()
        self.assertEqual(self.provider.opened,[])

    def test_observed_namespace_failure_stays_refused_after_repair(self):
        result=self.load(); package=sys.modules[loader.NAMESPACE]; original=package.evidence_release_bridge
        package.evidence_release_bridge=ModuleType("foreign")
        with self.assertRaises(loader.Refused): result.recheck()
        package.evidence_release_bridge=original
        with self.assertRaises(loader.Refused): result.recheck()
        with self.assertRaises(loader.Refused): result.close()
        self.closed()
