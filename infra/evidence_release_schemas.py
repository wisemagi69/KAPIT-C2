"""Closed public release proofs. Parsing confers no execution authority."""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re

class Refused(ValueError):
    def __init__(self): super().__init__("RELEASE_BRIDGE_REFUSED")

FINALIZERS = ("context", "phase_pins", "dedicated_lock", "input_resources", "cli")
CASES = ("pipe_boundary_success", "stdout_4097_refusal", "stderr_16385_refusal", "owned_timeout_refusal", "marker_normal_commit", "marker_abort_retained")
COMPONENTS = ("transport", "marker", "bootstrap", "calibration-runner")
GATES = ("sources", "trust", "host", "engine", "package", "generation", "oci", "resources", "lineage", "absence")
LIMITS = {"runtime_floor_bytes": 2147483648, "build_floor_bytes": 6442450944, "scan_memory_bytes": 4294967296, "cpu_seconds": 120, "attach_seconds": 180, "whole_seconds": 300, "cli_seconds": 15, "reap_join_seconds": 5, "cleanup_commands": 8, "stdout_bytes": 4096, "stderr_bytes": 16384}
SCOPES = {"S":"PUBLIC_CALIBRATION_SUBJECT_V2", "AH":"PUBLIC_HOST_CALIBRATION_AUTHORIZATION_V2", "O":"PUBLIC_HOST_CALIBRATION_OBSERVATIONS_V2", "WH":"PUBLIC_HOST_RETURN_WITNESS_V2", "C":"PUBLIC_SCOPED_CALIBRATION_V2", "E":"PUBLIC_DETECTION_RELEASE_V2", "AUTH":"PUBLIC_RELEASE_AUTHENTICATION_V2", "A":"PUBLIC_RELEASE_OPERATION_AUTHORIZATION_V2", "W":"PUBLIC_RELEASE_RETURN_WITNESS_V2", "RECEIPT":"PUBLIC_RELEASE_RECEIPT_V2", "SIGNATURE":"PUBLIC_PROOF_AUTHENTICATION_V2", "POLICY":"PUBLIC_RELEASE_TRUST_POLICY_V2", "RECORD":"PUBLIC_UPSTREAM_RECORD_V2"}
FIELDS = {
"S":"subject_version subject_nonce baseline_manifest_sha256 components runtime contract_sha256 measurand_ids",
"AH":"operation_nonce operation subject_sha256 runner_sha256 holder_sha256 verifier_sha256 trust_policy_sha256 expected_host_identity_sha256 expires_utc budgets authority_record_sha256 review_record_sha256",
"O":"status subject_sha256 runner_sha256 authorization_sha256 host_identity_sha256 protocol_sha256 contract_sha256 started_utc ended_utc cases counts measured_scope docker_attach_measured native_workload_measured finalizers",
"WH":"operation_nonce authorization_sha256 subject_sha256 runner_sha256 holder_sha256 trust_policy_sha256 actual_executed_sha256 actual_host_identity_sha256 observation_sha256 started_utc ended_utc process_result measured_scope docker_attach_measured native_workload_measured finalizers marker_states",
"C":"status subject_sha256 runner_sha256 protocol_sha256 host_identity_sha256 contract_sha256 authorization_sha256 observation_sha256 external_return_witness_sha256 review_record_sha256 created_utc expires_utc cases counts measured_scope docker_attach_measured native_workload_measured finalizers",
"E":"status release_nonce subject_sha256 calibration_sha256 controller_sha256 adapter_sha256 provenance_sha256 parser_sha256 probe_sha256 holder_sha256 verifier_sha256 trust_policy_sha256 contract_sha256 baseline_manifest_sha256 calibration_scope issued_utc expires_utc",
"AUTH":"envelope_sha256 signer_key_id signature_suite signature_hex",
"A":"operation_nonce release_envelope_sha256 authentication_sha256 operation preflight_sha256 preflight_witness_sha256 expires_utc budgets authority_record_sha256 review_record_sha256",
"W":"operation_nonce operation authorization_sha256 release_envelope_sha256 actual_executed_sha256 runtime_engine_sha256 receipt_sha256 started_utc ended_utc process_result finalizers guard_absent",
"RECEIPT":"operation_nonce operation authorization_sha256 release_envelope_sha256 subject_sha256 calibration_sha256 controller_sha256 runtime_engine_sha256 started_utc ended_utc status gates finalizers originals canonical_records create_attempted original_cid original_absent",
"SIGNATURE":"proof_kind proof_sha256 signer_key_id signature_suite signature_hex",
"POLICY":"policy_nonce issued_utc expires_utc keys revoked_key_ids baseline_manifest_sha256 contract_sha256 protocol_sha256 runtime",
"RECORD":"record_type operation_nonce operation subject_sha256 observation_sha256 holder_sha256 trust_policy_sha256 expires_utc",
}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")

def digest(raw): return hashlib.sha256(raw).hexdigest()
def require(test):
    if not test: raise Refused()
def integer(v, low=0, high=300000): require(type(v) is int and low <= v <= high)
def hexadecimal(v, size=64): require(type(v) is str and re.fullmatch("[0-9a-f]{%d}" % size, v) is not None and v != "0"*size)
def closed(v, fields): require(type(v) is dict and set(v) == set(fields))
def utc(v):
    require(type(v) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", v) is not None)
    try: result = datetime.strptime(v, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError: result = None
    require(result is not None and result.strftime("%Y-%m-%dT%H:%M:%SZ") == v)
    return result

def _tree(v, depth=0):
    require(depth <= 20)
    if type(v) is dict:
        require(all(type(k) is str for k in v))
        for item in v.values(): _tree(item, depth+1)
    elif type(v) is list:
        require(len(v) <= 256)
        for item in v: _tree(item, depth+1)
    else: require(v is None or type(v) in (str, bool, int))

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result); result[key] = value
    return result

@dataclass(frozen=True)
class Document:
    kind: str
    raw: bytes
    @property
    def sha256(self): return digest(self.raw)
    def view(self): return json.loads(self.raw)

def parse(kind, raw):
    failed = False; value = None
    try:
        require(type(kind) is str and kind in FIELDS and type(raw) is bytes and 1 <= len(raw) <= 262144)
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(Refused()))
        _tree(value); require(canonical(value) == raw)
        _validate(kind, value)
    except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError): failed = True
    # Outside handler: raw decoder documents are not retained in public chains.
    if failed: raise Refused()
    return Document(kind, raw)

def _validate(kind, v):
    flags = () if kind in ("AUTH", "SIGNATURE", "POLICY") else ("native_eligible", "private_input_allowed")
    closed(v, ("schema", "scope", *FIELDS[kind].split(), *flags))
    require(type(v["schema"]) is int and v["schema"] == 2 and v["scope"] == SCOPES[kind])
    for key in flags: require(v[key] is False)
    for key, value in v.items():
        if key.endswith("_sha256") or key == "signer_key_id":
            if key in ("preflight_sha256", "preflight_witness_sha256", "observation_sha256") and value is None: continue
            hexadecimal(value)
        elif key.endswith("_nonce"): hexadecimal(value, 32)
        elif key.endswith("_utc"): utc(value)
    if "started_utc" in v: require(utc(v["started_utc"]) <= utc(v["ended_utc"]) and (utc(v["ended_utc"])-utc(v["started_utc"])).total_seconds() <= 300)
    if "finalizers" in v:
        closed(v["finalizers"], FINALIZERS)
        require(all(x == "CONFIRMED" for x in v["finalizers"].values()))
    if "process_result" in v: require(v["process_result"] == "NORMAL_RETURN")
    if "signature_suite" in v: require(v["signature_suite"] == "ED25519_V1"); hexadecimal(v["signature_hex"], 128)
    if "measured_scope" in v: require(v["measured_scope"] == "HOST_PIPE_AND_MARKER_ONLY" and v["docker_attach_measured"] is False and v["native_workload_measured"] is False)
    if "cases" in v:
        require(type(v["cases"]) is list and len(v["cases"]) == 6)
        for row, ident, expected in zip(v["cases"], CASES, ("NORMAL_RETURN", "STDOUT_OVERFLOW_REFUSED", "STDERR_OVERFLOW_REFUSED", "OWNED_TIMEOUT_REFUSED", "ABSENT_CONFIRMED", "PRESENT_CONFIRMED")):
            closed(row, ("id", "expected", "observed", "ownership_closed", "elapsed_ms"))
            require(row["id"] == ident and row["expected"] == expected and row["observed"] == expected and row["ownership_closed"] is True); integer(row["elapsed_ms"])
    if "counts" in v:
        require(v["counts"] == {"processes_created":4,"containers_created":0,"scanner_calls":0,"files_created":2,"directories_created":1})
        require(all(type(x) is int for x in v["counts"].values()))
    if "budgets" in v:
        expected = dict(LIMITS, containers_created=1 if v["operation"] == "ONE_COMPARISON" else 0, scanner_calls=3 if v["operation"] == "ONE_COMPARISON" else 0, processes_created=4 if kind == "AH" else 0, files_created=2 if kind == "AH" else 0, directories_created=1 if kind == "AH" else 0)
        require(v["budgets"] == expected and all(type(x) is int for x in v["budgets"].values()))
    if kind == "S":
        require(type(v["subject_version"]) is int and v["subject_version"] == 2 and v["measurand_ids"] == list(CASES))
        require(type(v["components"]) is list and len(v["components"]) == 4)
        for row, ident in zip(v["components"], COMPONENTS): closed(row, ("id", "sha256")); require(row["id"] == ident); hexadecimal(row["sha256"])
    if kind in ("S","POLICY"):
        closed(v["runtime"], ("image_id", "signature_generation", "profile_sha256", "preparation_sha256"))
        require(type(v["runtime"]["image_id"]) is str and v["runtime"]["image_id"].startswith("sha256:")); hexadecimal(v["runtime"]["image_id"][7:])
        for key in ("signature_generation", "profile_sha256", "preparation_sha256"): hexadecimal(v["runtime"][key])
    if kind == "AH": require(v["operation"] == "HOST_CALIBRATION")
    if kind in ("A", "W", "RECEIPT"): require(v["operation"] in ("FRESH_PREFLIGHT", "ONE_COMPARISON"))
    if kind == "A":
        if v["operation"] == "FRESH_PREFLIGHT": require(v["preflight_sha256"] is None and v["preflight_witness_sha256"] is None)
        else: hexadecimal(v["preflight_sha256"]); hexadecimal(v["preflight_witness_sha256"])
    if kind == "O": require(v["status"] == "OBSERVED")
    if kind == "C": require(v["status"] == "MEASURED" and 0 < (utc(v["expires_utc"])-utc(v["created_utc"])).total_seconds() <= 3600)
    if kind == "E": require(v["status"] == "SOURCE_FROZEN" and v["calibration_scope"] == "HOST_PIPE_AND_MARKER_ONLY")
    if kind == "WH": require(v["marker_states"] == {"normal_marker":"ABSENT_CONFIRMED", "abort_marker":"PRESENT_CONFIRMED"})
    if kind == "W": require(v["guard_absent"] is True)
    if kind == "SIGNATURE": require(v["proof_kind"] in ("AH", "WH", "C", "A", "W", "RECORD"))
    if kind == "RECORD":
        require(v["record_type"] in ("AUTHORITY", "REVIEW") and v["operation"] in ("HOST_CALIBRATION", "FRESH_PREFLIGHT", "ONE_COMPARISON"))
        if v["record_type"] == "REVIEW" and v["observation_sha256"] is not None: hexadecimal(v["observation_sha256"])
        if v["record_type"] == "AUTHORITY": require(v["observation_sha256"] is None)
    if kind == "RECEIPT":
        require(v["gates"] == list(GATES) and v["original_absent"] is True and v["status"] == ("VERIFIED" if v["operation"] == "FRESH_PREFLIGHT" else "MEASURED"))
        comparison = v["operation"] == "ONE_COMPARISON"
        require(type(v["originals"]) is int and v["originals"] == (29 if comparison else 28) and type(v["canonical_records"]) is int and v["canonical_records"] == (116 if comparison else 112) and v["create_attempted"] is comparison)
        if comparison: hexadecimal(v["original_cid"])
        else: require(v["original_cid"] is None)
    if kind == "POLICY":
        require(type(v["keys"]) is list and 1 <= len(v["keys"]) <= 16 and type(v["revoked_key_ids"]) is list)
        ids=[]
        for key in v["keys"]:
            closed(key, ("key_id", "public_key_hex", "roles", "not_before_utc", "not_after_utc")); hexadecimal(key["key_id"]); hexadecimal(key["public_key_hex"])
            require(digest(bytes.fromhex(key["public_key_hex"])) == key["key_id"])
            require(type(key["roles"]) is list and len(key["roles"]) >= 1 and key["roles"] == sorted(set(key["roles"])) and set(key["roles"]) <= {"AUTHORITY", "REVIEWER", "WITNESS", "RELEASE"})
            require(utc(key["not_before_utc"]) < utc(key["not_after_utc"])); ids.append(key["key_id"])
        require(ids == sorted(set(ids)) and v["revoked_key_ids"] == sorted(set(v["revoked_key_ids"])) and set(v["revoked_key_ids"]) <= set(ids))
