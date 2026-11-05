import copy
from datetime import datetime, timezone
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from infra import evidence_release_schemas as s
from infra.evidence_release_bridge import BridgeVerifier, signing_bytes, production_execute

NOW=datetime(2026,10,23,15,0,tzinfo=timezone.utc)
BEFORE="2026-10-23T14:59:00Z"; END="2026-10-23T14:59:10Z"; AFTER="2026-10-23T15:30:00Z"
D="1"*64; N="2"*32

def doc(kind, **values):
    result={"schema":2,"scope":s.SCOPES[kind]}
    if kind not in ("AUTH","SIGNATURE","POLICY"): result.update(native_eligible=False,private_input_allowed=False)
    result.update(values); return s.canonical(result)

def fixture():
    keys={role:Ed25519PrivateKey.generate() for role in ("AUTHORITY","REVIEWER","WITNESS","RELEASE")}
    rows=[]; ids={}
    for role,key in keys.items():
        raw=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw); kid=s.digest(raw); ids[role]=kid
        rows.append(dict(key_id=kid,public_key_hex=raw.hex(),roles=[role],not_before_utc=BEFORE,not_after_utc=AFTER))
    policy=doc("POLICY",policy_nonce=N,issued_utc=BEFORE,expires_utc=AFTER,keys=sorted(rows,key=lambda x:x["key_id"]),revoked_key_ids=[],baseline_manifest_sha256=s.digest(b"baseline:synthetic-whole-file\n"),contract_sha256=s.digest(b"contract:synthetic-whole-file\n"),protocol_sha256=D,runtime=dict(image_id="sha256:"+D,signature_generation=D,profile_sha256=D,preparation_sha256=D))
    def sign(kind,raw,role=None):
        role=role or {"AH":"AUTHORITY","A":"AUTHORITY","WH":"WITNESS","W":"WITNESS","C":"REVIEWER","E":"RELEASE"}[kind]
        signature=keys[role].sign(signing_bytes(kind,role,raw)).hex()
        if kind=="E": auth=doc("AUTH",envelope_sha256=s.digest(raw),signer_key_id=ids[role],signature_suite="ED25519_V1",signature_hex=signature)
        else: auth=doc("SIGNATURE",proof_kind=kind,proof_sha256=s.digest(raw),signer_key_id=ids[role],signature_suite="ED25519_V1",signature_hex=signature)
        return raw,auth
    sources={key:(key+":synthetic-whole-file\n").encode() for key in ("baseline","contract","controller","adapter","provenance","parser","probe","holder","verifier",*s.COMPONENTS)}
    H=lambda key:s.digest(sources[key]); h=s.digest
    subject=doc("S",subject_version=2,subject_nonce=N,baseline_manifest_sha256=H("baseline"),components=[dict(id=k,sha256=H(k)) for k in s.COMPONENTS],runtime=dict(image_id="sha256:"+D,signature_generation=D,profile_sha256=D,preparation_sha256=D),contract_sha256=H("contract"),measurand_ids=list(s.CASES))
    bundle={"S":subject}
    def record(name,typ,op,nonce,subject_hash,observation=None):
        raw=doc("RECORD",record_type=typ,operation_nonce=nonce,operation=op,subject_sha256=subject_hash,observation_sha256=observation,holder_sha256=H("holder"),trust_policy_sha256=h(policy),expires_utc=AFTER)
        bundle[name]=sign("RECORD",raw,"AUTHORITY" if typ=="AUTHORITY" else "REVIEWER"); return h(raw)
    ar=record("AH_authority","AUTHORITY","HOST_CALIBRATION",N,h(subject)); rr=record("AH_review","REVIEW","HOST_CALIBRATION",N,h(subject))
    budget=lambda op:dict(s.LIMITS,containers_created=1 if op=="ONE_COMPARISON" else 0,scanner_calls=3 if op=="ONE_COMPARISON" else 0,processes_created=4 if op=="HOST_CALIBRATION" else 0,files_created=2 if op=="HOST_CALIBRATION" else 0,directories_created=1 if op=="HOST_CALIBRATION" else 0)
    ah=doc("AH",operation_nonce=N,operation="HOST_CALIBRATION",subject_sha256=h(subject),runner_sha256=H("calibration-runner"),holder_sha256=H("holder"),verifier_sha256=H("verifier"),trust_policy_sha256=h(policy),expected_host_identity_sha256=D,expires_utc=AFTER,budgets=budget("HOST_CALIBRATION"),authority_record_sha256=ar,review_record_sha256=rr); bundle["AH"]=sign("AH",ah)
    finals=dict.fromkeys(s.FINALIZERS,"CONFIRMED")
    cases=[dict(id=i,expected=e,observed=e,ownership_closed=True,elapsed_ms=1) for i,e in zip(s.CASES,("NORMAL_RETURN","STDOUT_OVERFLOW_REFUSED","STDERR_OVERFLOW_REFUSED","OWNED_TIMEOUT_REFUSED","ABSENT_CONFIRMED","PRESENT_CONFIRMED"))]
    measured=dict(cases=cases,counts=dict(processes_created=4,containers_created=0,scanner_calls=0,files_created=2,directories_created=1),measured_scope="HOST_PIPE_AND_MARKER_ONLY",docker_attach_measured=False,native_workload_measured=False,finalizers=finals)
    o=doc("O",status="OBSERVED",subject_sha256=h(subject),runner_sha256=H("calibration-runner"),authorization_sha256=h(ah),host_identity_sha256=D,protocol_sha256=D,contract_sha256=H("contract"),started_utc=BEFORE,ended_utc=END,**measured); bundle["O"]=o
    wh=doc("WH",operation_nonce=N,authorization_sha256=h(ah),subject_sha256=h(subject),runner_sha256=H("calibration-runner"),holder_sha256=H("holder"),trust_policy_sha256=h(policy),actual_executed_sha256=H("calibration-runner"),actual_host_identity_sha256=D,observation_sha256=h(o),started_utc=BEFORE,ended_utc=END,process_result="NORMAL_RETURN",marker_states=dict(normal_marker="ABSENT_CONFIRMED",abort_marker="PRESENT_CONFIRMED"),**{k:v for k,v in measured.items() if k not in ("cases","counts")}); bundle["WH"]=sign("WH",wh)
    cr=record("C_review","REVIEW","HOST_CALIBRATION",N,h(subject),h(o))
    c=doc("C",status="MEASURED",subject_sha256=h(subject),runner_sha256=H("calibration-runner"),protocol_sha256=D,host_identity_sha256=D,contract_sha256=H("contract"),authorization_sha256=h(ah),observation_sha256=h(o),external_return_witness_sha256=h(wh),review_record_sha256=cr,created_utc=END,expires_utc=AFTER,**measured); bundle["C"]=sign("C",c)
    e=doc("E",status="SOURCE_FROZEN",release_nonce=N,subject_sha256=h(subject),calibration_sha256=h(c),**{k+"_sha256":H(k) for k in ("controller","adapter","provenance","parser","probe","holder","verifier","contract")},trust_policy_sha256=h(policy),baseline_manifest_sha256=H("baseline"),calibration_scope="HOST_PIPE_AND_MARKER_ONLY",issued_utc=END,expires_utc=AFTER); bundle["E"]=sign("E",e)
    def operation(prefix,op,nonce,preflight=None,witness=None):
        ar=record(prefix+"_authority","AUTHORITY",op,nonce,h(e)); rr=record(prefix+"_review","REVIEW",op,nonce,h(e))
        raw=doc("A",operation_nonce=nonce,release_envelope_sha256=h(e),authentication_sha256=h(bundle["E"][1]),operation=op,preflight_sha256=preflight,preflight_witness_sha256=witness,expires_utc=AFTER,budgets=budget(op),authority_record_sha256=ar,review_record_sha256=rr); bundle[prefix]=sign("A",raw); return raw
    ap=operation("AP","FRESH_PREFLIGHT","3"*32)
    p=doc("RECEIPT",operation_nonce="3"*32,operation="FRESH_PREFLIGHT",authorization_sha256=h(ap),release_envelope_sha256=h(e),subject_sha256=h(subject),calibration_sha256=h(c),controller_sha256=H("controller"),runtime_engine_sha256=D,started_utc=END,ended_utc=END,status="VERIFIED",gates=list(s.GATES),finalizers=finals,originals=28,canonical_records=112,create_attempted=False,original_cid=None,original_absent=True); bundle["P"]=p
    wp=doc("W",operation_nonce="3"*32,operation="FRESH_PREFLIGHT",authorization_sha256=h(ap),release_envelope_sha256=h(e),actual_executed_sha256=H("controller"),runtime_engine_sha256=D,receipt_sha256=h(p),started_utc=END,ended_utc=END,process_result="NORMAL_RETURN",finalizers=finals,guard_absent=True); bundle["WP"]=sign("W",wp)
    ad=operation("AD","ONE_COMPARISON","4"*32,h(p),h(wp))
    d=s.parse("RECEIPT",p).view(); d.update(operation_nonce="4"*32,operation="ONE_COMPARISON",authorization_sha256=h(ad),status="MEASURED",originals=29,canonical_records=116,create_attempted=True,original_cid="c"*64)
    bundle["D"]=s.canonical(d)
    wd=s.parse("W",wp).view(); wd.update(operation_nonce="4"*32,operation="ONE_COMPARISON",authorization_sha256=h(ad),receipt_sha256=h(bundle["D"]))
    bundle["WD"]=sign("W",s.canonical(wd))
    return policy,bundle,sources,sign

class BridgeTests(unittest.TestCase):
    def setUp(self): self.policy,self.bundle,self.sources,self.sign=fixture(); self.verifier=BridgeVerifier(self.policy,NOW)
    def test_signed_complete_chain(self):
        for op in ("FRESH_PREFLIGHT","ONE_COMPARISON"):
            result=self.verifier.admit(self.bundle,self.sources,op); self.assertFalse(result.production_eligible)
    def test_each_source_byte_tamper(self):
        for key in self.sources:
            with self.subTest(key=key):
                source=dict(self.sources); source[key]+=b"x"
                with self.assertRaises(s.Refused): self.verifier.admit(self.bundle,source,"ONE_COMPARISON")
    def test_every_signed_artifact_tamper(self):
        for key,value in self.bundle.items():
            if type(value) is tuple:
                with self.subTest(key=key):
                    bundle=dict(self.bundle); bundle[key]=(value[0]+b" ",value[1])
                    with self.assertRaises(s.Refused): self.verifier.verify_result(bundle,self.sources,"ONE_COMPARISON")
    def test_wrong_role_actual_signature(self):
        bundle=dict(self.bundle); bundle["WH"]=self.sign("WH",bundle["WH"][0],"AUTHORITY")
        with self.assertRaises(s.Refused): self.verifier.admit(bundle,self.sources,"ONE_COMPARISON")
    def test_revocation(self):
        policy=s.parse("POLICY",self.policy).view(); policy["revoked_key_ids"]=[s.parse("SIGNATURE",self.bundle["WH"][1]).view()["signer_key_id"]]
        with self.assertRaises(s.Refused): BridgeVerifier(s.canonical(policy),NOW).admit(self.bundle,self.sources,"ONE_COMPARISON")
    def test_expired_policy(self):
        with self.assertRaises(s.Refused): BridgeVerifier(self.policy,datetime(2027,1,1,tzinfo=timezone.utc))
    def test_future_policy(self):
        with self.assertRaises(s.Refused): BridgeVerifier(self.policy,datetime(2025,1,1,tzinfo=timezone.utc))
    def test_upstream_record_no_enclosing_reference(self):
        record=s.parse("RECORD",self.bundle["C_review"][0]).view(); record["calibration_sha256"]=s.digest(self.bundle["C"][0])
        with self.assertRaises(s.Refused): s.parse("RECORD",s.canonical(record))
    def test_signed_preflight_wrong_release_denied(self):
        for field,value in (("release_envelope_sha256","f"*64),("authentication_sha256","f"*64),("authority_record_sha256","f"*64),("review_record_sha256","f"*64)):
            bundle=dict(self.bundle); row=s.parse("A",bundle["AP"][0]).view(); row[field]=value; bundle["AP"]=self.sign("A",s.canonical(row))
            with self.assertRaises(s.Refused): self.verifier.admit(bundle,self.sources,"ONE_COMPARISON")
    def test_preflight_operation_substitution(self):
        bundle=dict(self.bundle); bundle["AP"]=bundle["AD"]
        with self.assertRaises(s.Refused): self.verifier.admit(bundle,self.sources,"ONE_COMPARISON")
    def test_preflight_witness_wrong_actual_execution(self):
        bundle=dict(self.bundle); row=s.parse("W",bundle["WP"][0]).view(); row["actual_executed_sha256"]="f"*64; bundle["WP"]=self.sign("W",s.canonical(row))
        with self.assertRaises(s.Refused): self.verifier.admit(bundle,self.sources,"ONE_COMPARISON")
    def test_future_observation(self):
        bundle=dict(self.bundle); row=s.parse("O",bundle["O"]).view(); row["ended_utc"]="2026-10-23T15:00:01Z"; bundle["O"]=s.canonical(row)
        with self.assertRaises(s.Refused): self.verifier.admit(bundle,self.sources,"ONE_COMPARISON")
    def test_policy_runtime_binding(self):
        policy=s.parse("POLICY",self.policy).view(); policy["runtime"]["profile_sha256"]="f"*64
        with self.assertRaises(s.Refused): BridgeVerifier(s.canonical(policy),NOW).admit(self.bundle,self.sources,"ONE_COMPARISON")
    def test_policy_protocol_binding(self):
        policy=s.parse("POLICY",self.policy).view(); policy["protocol_sha256"]="f"*64
        with self.assertRaises(s.Refused): BridgeVerifier(s.canonical(policy),NOW).admit(self.bundle,self.sources,"ONE_COMPARISON")
    def test_actual_independent_result_witness(self):
        for op in ("FRESH_PREFLIGHT","ONE_COMPARISON"): self.verifier.verify_result(self.bundle,self.sources,op)
    def test_domain_separation_actual_crypto(self):
        raw=self.bundle["WH"][0]
        wrong=self.sign("W",raw,"WITNESS")[1]
        signature=s.parse("SIGNATURE",wrong).view(); signature["proof_kind"]="WH"
        with self.assertRaises(s.Refused): self.verifier.authenticated("WH",raw,s.canonical(signature))
    def test_stale_preflight(self):
        verifier=BridgeVerifier(self.policy,datetime(2026,10,23,15,5,tzinfo=timezone.utc))
        with self.assertRaises(s.Refused): verifier.admit(self.bundle,self.sources,"ONE_COMPARISON")
    def test_signed_diagnostic_wrong_engine(self):
        bundle=dict(self.bundle); row=s.parse("W",bundle["WD"][0]).view(); row["runtime_engine_sha256"]="f"*64; bundle["WD"]=self.sign("W",s.canonical(row))
        with self.assertRaises(s.Refused): self.verifier.verify_result(bundle,self.sources,"ONE_COMPARISON")
    def test_result_without_independent_witness(self):
        bundle=dict(self.bundle); bundle.pop("WD")
        with self.assertRaises(s.Refused): self.verifier.verify_result(bundle,self.sources,"ONE_COMPARISON")
    def test_diagnostic_cannot_predate_preflight_completion(self):
        bundle=dict(self.bundle); p=s.parse("RECEIPT",bundle["P"]).view(); p["ended_utc"]="2026-10-23T14:59:40Z"; bundle["P"]=s.canonical(p)
        wp=s.parse("W",bundle["WP"][0]).view(); wp["ended_utc"]=p["ended_utc"]; wp["receipt_sha256"]=s.digest(bundle["P"]); bundle["WP"]=self.sign("W",s.canonical(wp))
        ad=s.parse("A",bundle["AD"][0]).view(); ad["preflight_sha256"]=s.digest(bundle["P"]); ad["preflight_witness_sha256"]=s.digest(bundle["WP"][0]); bundle["AD"]=self.sign("A",s.canonical(ad))
        d=s.parse("RECEIPT",bundle["D"]).view(); d["authorization_sha256"]=s.digest(bundle["AD"][0]); bundle["D"]=s.canonical(d)
        wd=s.parse("W",bundle["WD"][0]).view(); wd["authorization_sha256"]=d["authorization_sha256"]; wd["receipt_sha256"]=s.digest(bundle["D"]); bundle["WD"]=self.sign("W",s.canonical(wd))
        with self.assertRaises(s.Refused): self.verifier.verify_result(bundle,self.sources,"ONE_COMPARISON")
    def test_malformed_public_boundaries_fixed_privacy(self):
        for value in (None,{},[],object()):
            for method,args in ((self.verifier.verify_release,(value,self.sources)),(self.verifier.admit,(value,self.sources,"ONE_COMPARISON")),(self.verifier.verify_result,(value,self.sources,"ONE_COMPARISON")),(self.verifier.authenticated,(value,b"canary",b"canary"))):
                with self.subTest(method=method.__name__,value_type=type(value)):
                    with self.assertRaises(s.Refused) as caught: method(*args)
                    self.assertIsNone(caught.exception.__context__); self.assertIsNone(caught.exception.__cause__); self.assertEqual(str(caught.exception),"RELEASE_BRIDGE_REFUSED")
    def test_production_refuses_before_access(self):
        class Bomb:
            def __getattribute__(self,name): raise AssertionError("access")
        with self.assertRaises(s.Refused): production_execute(Bomb(),backend=Bomb())

if __name__ == "__main__": unittest.main()
