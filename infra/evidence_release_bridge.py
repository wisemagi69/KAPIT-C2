"""Authenticated noncircular proof admission; results are protocol facts only.

The policy supplied here is an explicit synthetic/offline verification input, not
an installed production trust anchor. No result can unlock production_execute.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import wraps
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from infra.evidence_release_schemas import parse, digest, require, Refused, utc

def _finite(method):
    @wraps(method)
    def wrapped(*args,**kwargs):
        failed=False; result=None
        try: result=method(*args,**kwargs)
        except BaseException: failed=True
        if failed: raise Refused()
        return result
    return wrapped

def signing_bytes(kind, role, raw):
    require(type(raw) is bytes and kind in ("AH", "WH", "C", "E", "A", "W", "RECORD") and role in ("AUTHORITY", "REVIEWER", "WITNESS", "RELEASE"))
    return b"KAPIT-C2:RELEASE-BRIDGE:V2\x00" + kind.encode("ascii") + b"\x00" + role.encode("ascii") + b"\x00" + raw

@dataclass(frozen=True)
class ModelAdmission:
    operation: str
    nonce: str
    authorization_sha256: str
    envelope_sha256: str
    controller_sha256: str
    engine_sha256: str
    expires_utc: str
    # Explicitly not an execution capability, even when constructed by callers.
    production_eligible: bool = False

class BridgeVerifier:
    def __init__(self, policy_raw, now):
        require(type(now) is datetime and now.tzinfo is not None)
        self.now = now.astimezone(timezone.utc)
        self.policy = parse("POLICY", policy_raw)
        policy = self.policy.view(); self._valid(policy, "issued_utc")
        self.keys = {key["key_id"]:key for key in policy["keys"]}
        self.revoked = frozenset(policy["revoked_key_ids"])

    def _valid(self, value, start=None):
        if start: require(utc(value[start]) <= self.now)
        if "expires_utc" in value:
            require(self.now < utc(value["expires_utc"]))
            require(utc(value["expires_utc"]) <= utc(self.policy.view()["expires_utc"]))
        if "ended_utc" in value: require(utc(value["ended_utc"]) <= self.now)

    @_finite
    def authenticated(self, kind, raw, signature_raw):
        document = parse(kind, raw); value = document.view()
        signature = parse("AUTH" if kind == "E" else "SIGNATURE", signature_raw).view()
        role = {"AH":"AUTHORITY", "A":"AUTHORITY", "WH":"WITNESS", "W":"WITNESS", "C":"REVIEWER", "E":"RELEASE"}.get(kind)
        if kind == "RECORD": role = "AUTHORITY" if value["record_type"] == "AUTHORITY" else "REVIEWER"
        if kind == "E": require(signature["envelope_sha256"] == document.sha256)
        else: require(signature["proof_kind"] == kind and signature["proof_sha256"] == document.sha256)
        key_id = signature["signer_key_id"]; require(key_id not in self.revoked and key_id in self.keys)
        key = self.keys[key_id]
        require(role in key["roles"] and utc(key["not_before_utc"]) <= self.now < utc(key["not_after_utc"]))
        failed = False
        try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key["public_key_hex"])).verify(bytes.fromhex(signature["signature_hex"]), signing_bytes(kind, role, raw))
        except Exception: failed = True
        if failed: raise Refused()
        self._valid(value)
        return document, key_id

    def _signed(self, bundle, name, kind):
        require(name in bundle and type(bundle[name]) is tuple and len(bundle[name]) == 2)
        return self.authenticated(kind, *bundle[name])

    def _record(self, bundle, name, record_type, authorization, subject, observation=None):
        doc, signer = self._signed(bundle, name, "RECORD"); row=doc.view()
        require(row["record_type"] == record_type and row["operation_nonce"] == authorization["operation_nonce"] and row["operation"] == authorization["operation"] and row["subject_sha256"] == subject and row["observation_sha256"] == observation and row["holder_sha256"] == bundle["subject_holder"] and row["trust_policy_sha256"] == self.policy.sha256)
        # A record contains only upstream subject/observation tuples. Closed schema
        # forbids enclosing authorization/calibration/release references.
        return doc, signer

    @_finite
    def verify_release(self, bundle, sources):
        """Check complete byte values, never caller digest claims or selected slices.

        sources is a fixed logical-ID -> exact bytes map; no paths are accepted.
        An external qualified holder still has to authenticate actual execution.
        """
        s=parse("S", bundle["S"]); subject=s.view()
        policy=self.policy.view()
        for key in ("baseline_manifest_sha256","contract_sha256","runtime"): require(subject[key] == policy[key])
        required = {"baseline", "contract", "controller", "adapter", "provenance", "parser", "probe", "holder", "verifier", *[row["id"] for row in subject["components"]]}
        require(type(sources) is dict and set(sources) == required and all(type(v) is bytes and 1 <= len(v) <= 4194304 for v in sources.values()))
        for row in subject["components"]: require(digest(sources[row["id"]]) == row["sha256"])
        require(digest(sources["baseline"]) == subject["baseline_manifest_sha256"] and digest(sources["contract"]) == subject["contract_sha256"])
        ah, authority=self._signed(bundle,"AH","AH"); a=ah.view()
        require(a["subject_sha256"] == s.sha256 and a["runner_sha256"] == digest(sources["calibration-runner"]) and a["holder_sha256"] == digest(sources["holder"]) and a["verifier_sha256"] == digest(sources["verifier"]) and a["trust_policy_sha256"] == self.policy.sha256)
        # Avoid a mutable trust field inside the supplied material dictionary.
        records=dict(bundle, subject_holder=digest(sources["holder"]))
        ar,ar_signer=self._record(records,"AH_authority","AUTHORITY",a,s.sha256)
        rr,rr_signer=self._record(records,"AH_review","REVIEW",a,s.sha256)
        require(ar_signer != rr_signer and authority != rr_signer)
        require(a["authority_record_sha256"] == ar.sha256 and a["review_record_sha256"] == rr.sha256)
        o=parse("O",bundle["O"]); obs=o.view(); self._valid(obs)
        require(obs["subject_sha256"] == s.sha256 and obs["runner_sha256"] == a["runner_sha256"] and obs["authorization_sha256"] == ah.sha256 and obs["host_identity_sha256"] == a["expected_host_identity_sha256"] and obs["contract_sha256"] == subject["contract_sha256"] and obs["protocol_sha256"] == policy["protocol_sha256"] and utc(obs["ended_utc"]) < utc(a["expires_utc"]))
        wh,witness=self._signed(bundle,"WH","WH"); w=wh.view(); require(witness != authority)
        for key in ("operation_nonce", "subject_sha256", "runner_sha256", "holder_sha256", "trust_policy_sha256"): require(w[key] == a[key])
        require(w["authorization_sha256"] == ah.sha256 and w["observation_sha256"] == o.sha256 and w["actual_executed_sha256"] == a["runner_sha256"] and w["actual_host_identity_sha256"] == obs["host_identity_sha256"])
        for key in ("started_utc","ended_utc","measured_scope","docker_attach_measured","native_workload_measured","finalizers"): require(w[key] == obs[key])
        c,reviewer=self._signed(bundle,"C","C"); cal=c.view(); self._valid(cal,"created_utc")
        cr,cr_signer=self._record(records,"C_review","REVIEW",a,s.sha256,o.sha256)
        require(cr_signer not in (authority,witness))
        require(cal["review_record_sha256"] == cr.sha256 and cal["subject_sha256"] == s.sha256 and cal["authorization_sha256"] == ah.sha256 and cal["observation_sha256"] == o.sha256 and cal["external_return_witness_sha256"] == wh.sha256 and utc(cal["created_utc"]) >= utc(obs["ended_utc"]))
        require(reviewer not in (authority,witness))
        for key in ("runner_sha256","protocol_sha256","host_identity_sha256","contract_sha256","cases","counts","measured_scope","docker_attach_measured","native_workload_measured","finalizers"): require(cal[key] == obs[key])
        e,_=self._signed(bundle,"E","E"); envelope=e.view(); self._valid(envelope,"issued_utc")
        require(envelope["subject_sha256"] == s.sha256 and envelope["calibration_sha256"] == c.sha256 and envelope["trust_policy_sha256"] == self.policy.sha256 and envelope["calibration_scope"] == cal["measured_scope"] and utc(envelope["issued_utc"]) >= utc(cal["created_utc"]) and utc(envelope["expires_utc"]) <= utc(cal["expires_utc"]))
        for key in ("controller","adapter","provenance","parser","probe","holder","verifier","contract"): require(envelope[key+"_sha256"] == digest(sources[key]))
        require(envelope["baseline_manifest_sha256"] == subject["baseline_manifest_sha256"])
        return s,c,e

    def _authorization(self,bundle,prefix,operation,e):
        env=e.view()
        auth, authority=self._signed(bundle,prefix,"A"); a=auth.view()
        require(a["operation"] == operation and a["release_envelope_sha256"] == e.sha256 and a["authentication_sha256"] == digest(bundle["E"][1]) and utc(a["expires_utc"]) <= utc(env["expires_utc"]))
        records=dict(bundle,subject_holder=env["holder_sha256"])
        record_signers=[]
        for suffix,typ,key in (("authority","AUTHORITY","authority_record_sha256"),("review","REVIEW","review_record_sha256")):
            record,signer=self._record(records,prefix+"_"+suffix,typ,a,e.sha256)
            record_signers.append(signer)
            require(a[key] == record.sha256)
        require(record_signers[0] != record_signers[1] and authority != record_signers[1])
        return auth,authority

    @_finite
    def admit(self, bundle, sources, operation):
        require(operation in ("FRESH_PREFLIGHT","ONE_COMPARISON"))
        s,c,e=self.verify_release(bundle,sources); env=e.view()
        prefix="AP" if operation == "FRESH_PREFLIGHT" else "AD"
        auth,authority=self._authorization(bundle,prefix,operation,e); a=auth.view()
        if operation == "ONE_COMPARISON":
            p,wp=self._receipt(bundle,"P","WP","AP",s,c,e)
            require(a["preflight_sha256"] == p.sha256 and a["preflight_witness_sha256"] == wp.sha256 and 0 <= (self.now-utc(p.view()["ended_utc"])).total_seconds() <= 300)
        # Engine is authenticated only by an already independently witnessed
        # preflight, never from a free caller argument.
        engine = parse("RECEIPT",bundle["P"]).view()["runtime_engine_sha256"] if operation == "ONE_COMPARISON" else "0"*64
        return ModelAdmission(operation,a["operation_nonce"],auth.sha256,e.sha256,env["controller_sha256"],engine,a["expires_utc"])

    @_finite
    def verify_result(self,bundle,sources,operation):
        admission=self.admit(bundle,sources,operation)
        s,c,e=self.verify_release(bundle,sources)
        name,witness,auth=("P","WP","AP") if operation=="FRESH_PREFLIGHT" else ("D","WD","AD")
        receipt,_=self._receipt(bundle,name,witness,auth,s,c,e,operation)
        if operation=="ONE_COMPARISON":
            require(receipt.view()["runtime_engine_sha256"] == admission.engine_sha256)
            preflight=parse("RECEIPT",bundle["P"]).view()
            require(utc(receipt.view()["started_utc"]) >= utc(preflight["ended_utc"]))
        return admission

    def _receipt(self,bundle,name,witness_name,auth_name,s,c,e,operation="FRESH_PREFLIGHT"):
        receipt=parse("RECEIPT",bundle[name]); r=receipt.view(); self._valid(r)
        authorization,author=self._authorization(bundle,auth_name,operation,e); a=authorization.view()
        witness,signer=self._signed(bundle,witness_name,"W"); w=witness.view(); require(author != signer)
        require(r["authorization_sha256"] == authorization.sha256 and r["operation_nonce"] == a["operation_nonce"] and r["operation"] == a["operation"] and r["release_envelope_sha256"] == e.sha256 and r["subject_sha256"] == s.sha256 and r["calibration_sha256"] == c.sha256 and r["controller_sha256"] == e.view()["controller_sha256"] and utc(r["ended_utc"]) < utc(a["expires_utc"]))
        for key in ("operation_nonce","operation","authorization_sha256","release_envelope_sha256","runtime_engine_sha256","started_utc","ended_utc","finalizers"): require(w[key] == r[key])
        require(w["actual_executed_sha256"] == r["controller_sha256"] and w["receipt_sha256"] == receipt.sha256)
        require(utc(r["started_utc"]) >= utc(e.view()["issued_utc"]))
        return receipt,witness

def production_execute(*args, **kwargs):
    """No qualified external bootstrap/trust/OS backend is installed by this batch."""
    raise Refused()
