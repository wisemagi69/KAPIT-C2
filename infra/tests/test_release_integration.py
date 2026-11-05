"""Benign signed wrappers delegate to explicitly admitted test interfaces only."""
import hashlib
import sys
import unittest
from types import ModuleType
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from infra import evidence_release_integration as i
from infra import evidence_release_bootstrap as b
from infra import evidence_release_schemas as s
from infra import evidence_release_bridge as bridge
from infra import evidence_release_lifecycle as lifecycle
from infra import evidence_release_reservations as reservations
from infra.tests.test_release_bridge import fixture
from infra.tests.test_release_bootstrap import Backend as SourceBackend
from infra.tests.test_release_reservations import Provider, OWNER
from infra.tests.test_release_lifecycle import Backend

NOW = "2026-10-23T15:00:00Z"
PAYLOADS = [b"from types import parse\n",
    b"from types import BridgeVerifier, ModelAdmission\n",
    b"from types import drive_model, ModelOutcome\n",
    b"from types import ProtectedReservationStore, ReservationRef\n"]


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.trust = b.OfflineTrust("test-key", self.key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw), "test-policy", "test-authority", OWNER)
        self.external = ModuleType("types")
        for module, names in ((s, ("parse",)), (bridge, ("BridgeVerifier", "ModelAdmission")),
                (lifecycle, ("drive_model", "ModelOutcome")),
                (reservations, ("ProtectedReservationStore", "ReservationRef"))):
            for name in names:
                setattr(self.external, name, getattr(module, name))
        original = s.digest
        def digest(raw):
            return original(PAYLOADS[1] if raw == b"verifier:synthetic-whole-file\n" else raw)
        with patch.object(s, "digest", digest):
            self.policy, self.proof, self.sources, self.sign = fixture()
        self.sources["verifier"] = PAYLOADS[1]
        self.records = {}
        self.op = "FRESH_PREFLIGHT"
        self.configure()

    def configure(self):
        self.nonce = "3"*32 if self.op == "FRESH_PREFLIGHT" else "4"*32
        self.manifest = dict(scope="PUBLIC_EXECUTABLE_BUNDLE_V1", version=1,
            key_id=self.trust.key_id, policy=self.trust.policy, authority=self.trust.authority,
            nonce=self.nonce, issued_utc="2026-10-23T14:59:59Z",
            expires_utc="2026-10-23T15:04:59Z", files=[dict(id=logical, path=path,
            sha256=s.digest(raw), size=len(raw)) for (logical,path),raw in zip(b.BUNDLE,PAYLOADS)])
        self.manifest_raw = b.canonical(self.manifest)
        self.manifest_signature = self.key.sign(b.DOMAIN+self.manifest_raw)
        self.binding = dict(scope="PUBLIC_RELEASE_INTEGRATION_V1",version=1,
            key_id=self.trust.key_id,policy=self.trust.policy,authority=self.trust.authority,
            manifest_sha256=s.digest(self.manifest_raw),policy_sha256=s.digest(self.policy),
            subject_sha256=s.digest(self.proof["S"]),envelope_sha256=s.digest(self.proof["E"][0]),
            authorization_sha256=s.digest(self.proof["AP" if self.op=="FRESH_PREFLIGHT" else "AD"][0]),
            operation=self.op,nonce=self.nonce,
            modules=[{key:row[key] for key in ("id","path","sha256")} for row in self.manifest["files"]])
        self.resign_binding()
        self.source = SourceBackend(PAYLOADS)
        for obj in (*self.source.parents.values(),*self.source.sources.values()):
            obj.facts["owner"] = OWNER
        self.provider = Provider(self.records)
        self.backend = Backend()

    def resign_binding(self):
        self.binding_raw=b.canonical(self.binding)
        self.binding_signature=self.key.sign(i.DOMAIN+self.binding_raw)

    def run_protocol(self, **changes):
        args=dict(trust=self.trust, source_backend=self.source,
            reservation_provider=self.provider,lifecycle_backend=self.backend,
            trusted_external={"types":self.external},clock=lambda:0)
        args.update(changes)
        # Test isolation only: ordinary production cache rejection is unchanged.
        aliases={name.casefold() for name in b.MODULES}
        aliases.update(name.rsplit(".",1)[-1].casefold() for name in b.MODULES)
        saved={name:mod for name,mod in tuple(sys.modules.items()) if name.casefold() in aliases}
        for name in saved: del sys.modules[name]
        try:
            return i.run_synthetic(self.manifest_raw,self.manifest_signature,
                self.binding_raw,self.binding_signature,self.policy,self.proof,self.sources,
                self.op,self.nonce,NOW,**args)
        finally:
            sys.modules.update(saved)

    def denied(self):
        with self.assertRaises(i.Refused) as caught: self.run_protocol()
        self.assertEqual(str(caught.exception),"RELEASE_INTEGRATION_REFUSED")
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(all(obj.close_calls==1 for obj in self.source.opened))

    def test_real_signed_preflight_and_reservation(self):
        result=self.run_protocol()
        self.assertTrue(result["synthetic"]); self.assertFalse(result["production_eligible"])
        self.assertEqual(result["outcome"].gates,s.GATES)
        self.assertEqual(len(self.records),1)
        self.assertTrue(all(obj.close_calls==1 for obj in self.source.opened))

    def test_real_signed_comparison_and_cleanup(self):
        self.op="ONE_COMPARISON"; self.configure()
        self.assertTrue(self.run_protocol()["outcome"].create_attempted)
        self.assertLess(self.backend.calls.index("record"),self.backend.calls.index("start"))
        self.assertIn("cleanup",self.backend.calls)

    def test_reservation_replay_fresh_store(self):
        self.run_protocol(); self.configure(); self.denied()
        self.assertEqual(self.backend.calls,[])

    def test_all_descriptor_fields_derived(self):
        for key in self.binding:
            with self.subTest(key=key):
                self.configure()
                self.binding[key] = [] if key=="modules" else 2 if key=="version" else "wrong"
                self.resign_binding(); self.denied()
                self.assertEqual(self.source.opened,[]); self.assertEqual(self.records,{})

    def test_descriptor_domain_signature(self):
        self.binding_signature=self.key.sign(b.DOMAIN+self.binding_raw); self.denied()
        self.assertEqual(self.source.opened,[])

    def test_descriptor_noncanonical(self):
        self.binding_raw+=b" "; self.binding_signature=self.key.sign(i.DOMAIN+self.binding_raw)
        self.denied()

    def test_tampered_release_no_reservation(self):
        self.proof["WH"]=(self.proof["WH"][0]+b" ",self.proof["WH"][1]); self.denied()
        self.assertFalse(self.records); self.assertEqual(self.backend.calls,[])

    def test_signed_nonce_mismatch(self):
        self.nonce="9"*32; self.denied(); self.assertFalse(self.records)

    def test_verifier_source_mapping(self):
        self.sources["verifier"]+=b"x"; self.denied(); self.assertEqual(self.source.opened,[])

    def test_reservation_faults_prevent_lifecycle(self):
        for fault in ("write_partial","flush_raise","close_raise"):
            with self.subTest(fault=fault):
                self.records={}; self.configure(); self.provider.fault=fault; self.denied()
                self.assertEqual(self.backend.calls,[]); self.assertEqual(len(self.records),1)

    def test_interruption_consumes_and_closes(self):
        self.backend.hold=lambda *a: (_ for _ in ()).throw(KeyboardInterrupt())
        self.denied(); self.assertEqual(len(self.records),1)

    def test_late_bundle_close_failure_sticky(self):
        first=next(iter(self.source.sources.values()))
        first.close_hook=lambda *a: (_ for _ in ()).throw(OSError("canary"))
        self.denied(); self.assertIn("finish",self.backend.calls)

    def test_lifecycle_fault_closes_and_keeps_consumed(self):
        self.backend.fault="postflight"; self.denied()
        self.assertEqual(len(self.records),1)
        self.assertTrue(self.backend.retained)

    def test_callbacks_captured_before_source_callback_mutation(self):
        original=self.source.pin_parent
        def pin(path):
            self.backend.hold=lambda *a: (_ for _ in ()).throw(AssertionError())
            self.provider.create_new=lambda *a: (_ for _ in ()).throw(AssertionError())
            return original(path)
        self.source.pin_parent=pin
        self.run_protocol(); self.assertIn("hold",self.backend.calls)

    def test_input_maps_copied_before_callbacks(self):
        original=self.source.pin_parent
        def pin(path):
            self.proof.clear(); self.sources.clear()
            return original(path)
        self.source.pin_parent=pin
        self.run_protocol()

    def test_gate_rejects_substitute_and_duplicate(self):
        original=object(); gate=i._ConsumeGate(original)
        with self.assertRaises(i.Refused): gate.consume(object())
        gate.consume(original)
        with self.assertRaises(i.Refused): gate.consume(original)

    def test_swallowed_duplicate_gate_refuses_success(self):
        original=self.external.drive_model
        def drive(admission,gate,*args,**kwargs):
            outcome=original(admission,gate,*args,**kwargs)
            try: gate.consume(admission)
            except i.Refused: pass
            return outcome
        self.external.drive_model=drive
        self.denied(); self.assertIn("finish",self.backend.calls)

    def test_missing_consume_refuses_outcome(self):
        self.external.drive_model=lambda admission,*a,**k: lifecycle.ModelOutcome(
            admission.operation,False,None,s.GATES,s.FINALIZERS)
        self.denied(); self.assertTrue(self.records)

    def test_wrong_reservation_result_never_runs_lifecycle(self):
        class Store:
            def __init__(self,*a,**k): pass
            def reserve(self,*a): return True
        self.external.ProtectedReservationStore=Store
        self.denied(); self.assertEqual(self.backend.calls,[])

    def test_closed_production_before_input_access(self):
        class Poison:
            def __getattribute__(self,name): raise AssertionError(name)
        with self.assertRaises(i.Refused): i.production_execute(Poison(),backend=Poison())


if __name__=="__main__": unittest.main()
