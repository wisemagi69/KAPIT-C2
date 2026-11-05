"""Externally admitted synthetic orchestration; never a production launcher.

Only the bootstrap is imported from the project before authenticated fixture
initialization. This module, interpreter and admitted dependencies remain TCB.
"""
import hashlib
import json
from types import SimpleNamespace
from infra import evidence_release_bootstrap as bootstrap

DOMAIN = b"KAPIT-C2/RELEASE-INTEGRATION/V1\x00"
CALLBACKS = ("hold", "observe", "reserve_guard", "repeat_live_gates",
    "mark_create_attempted", "create_original", "record_original", "start_original",
    "attach_original", "postflight", "save_candidate", "cleanup_original", "finalize",
    "close_candidate", "commit_original_guard", "confirm_guard_absent", "finish_model",
    "retain_refusal_guard")


class Refused(ValueError):
    def __init__(self):
        super().__init__("RELEASE_INTEGRATION_REFUSED")


def _need(value):
    if value is not True:
        raise Refused()


def _bytes(value, maximum):
    _need(type(value) is bytes and 1 <= len(value) <= maximum)
    return value


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _freeze_map(value, proofs=False):
    _need(type(value) is dict and 1 <= len(value) <= 64)
    result = {}
    for key, item in value.items():
        _need(type(key) is str and 1 <= len(key) <= 128 and key.isascii())
        if proofs and type(item) is tuple:
            _need(len(item) == 2)
            result[key] = tuple(_bytes(raw, 262144) for raw in item)
        else:
            result[key] = _bytes(item, 262144 if proofs else 4194304)
    return result


def _snapshot(obj, names):
    result = {name: getattr(obj, name) for name in names}
    _need(all(callable(value) for value in result.values()))
    return SimpleNamespace(**result)


class _ConsumeGate:
    """One invocation-owned admission, already reserved; never a second store."""
    def __init__(self, admission):
        self.admission = admission
        self.used = False
        self.failed = False

    def consume(self, admission):
        if self.used or admission is not self.admission:
            self.failed = True
            raise Refused()
        self.used = True


def production_execute(*args, **kwargs):
    raise Refused()


def run_synthetic(manifest_raw, manifest_signature, binding_raw, binding_signature,
                  policy_raw, proof_bundle, sources, operation, nonce, now_utc, *,
                  trust, source_backend, reservation_provider, lifecycle_backend,
                  trusted_external, clock):
    """Synthetic combined protocol, with authenticated initialization before reserve.

    Supplied providers and loaded code are not sandboxed or OS-qualified. No
    caller-provided admission, ledger or digest assertion is accepted as authority.
    """
    failed = False
    result = None
    close = None
    try:
        # Freeze values before the first supplied callback or fixture initializer.
        manifest_raw = _bytes(manifest_raw, 8192)
        manifest_signature = _bytes(manifest_signature, 64)
        binding_raw = _bytes(binding_raw, 8192)
        binding_signature = _bytes(binding_signature, 64)
        _need(len(manifest_signature) == len(binding_signature) == 64)
        policy_raw = _bytes(policy_raw, 262144)
        proof_bundle = _freeze_map(proof_bundle, True)
        sources = _freeze_map(sources)
        _need(type(operation) is str and operation in ("FRESH_PREFLIGHT", "ONE_COMPARISON"))
        bootstrap._hex(nonce, 32)
        now = bootstrap._utc(now_utc)
        _need(type(trusted_external) is dict)
        external = dict(trusted_external)
        _need(type(trust) is bootstrap.OfflineTrust)
        trust = bootstrap.OfflineTrust(trust.key_id, trust.public_key, trust.policy,
            trust.authority, trust.owner, trust.revoked_key_ids)
        load = bootstrap.load_synthetic_bundle
        module_names = bootstrap.MODULES
        verify_manifest = bootstrap.verify_manifest
        canonical = bootstrap.canonical
        public_key = bootstrap.Ed25519PublicKey
        manifest = verify_manifest(manifest_raw, manifest_signature, trust=trust,
                                  now_utc=now_utc, expected_nonce=nonce)
        # Descriptor verification precedes backend callbacks and all compilation.
        public_key.from_public_bytes(trust.public_key).verify(binding_signature, DOMAIN + binding_raw)
        binding = json.loads(binding_raw.decode("ascii"))
        prefix = "AP" if operation == "FRESH_PREFLIGHT" else "AD"
        expected = dict(scope="PUBLIC_RELEASE_INTEGRATION_V1", version=1,
            key_id=trust.key_id, policy=trust.policy, authority=trust.authority,
            manifest_sha256=_sha(manifest_raw), policy_sha256=_sha(policy_raw),
            subject_sha256=_sha(proof_bundle["S"]),
            envelope_sha256=_sha(proof_bundle["E"][0]),
            authorization_sha256=_sha(proof_bundle[prefix][0]), operation=operation,
            nonce=nonce, modules=[{key: row[key] for key in ("id", "path", "sha256")}
                                    for row in manifest["files"]])
        _need(type(binding) is dict and canonical(binding) == binding_raw
              and binding == expected and type(binding["version"]) is int)
        bridge_row = manifest["files"][1]
        _need(_sha(sources["verifier"]) == bridge_row["sha256"]
              and len(sources["verifier"]) == bridge_row["size"])
        source_owned = _snapshot(source_backend, ("pin_parent", "open_source"))
        provider_owned = _snapshot(reservation_provider, ("pin_parent", "create_new"))
        backend_owned = _snapshot(lifecycle_backend, CALLBACKS)
        _need(callable(clock))
        owned_clock = clock
        loaded = load(source_owned, manifest_raw, manifest_signature, trust=trust,
            now_utc=now_utc, expected_nonce=nonce, trusted_external=external)
        close = loaded.close  # Original callback retained before loaded interfaces.
        modules = loaded.modules
        schemas, bridge, lifecycle, reservations = (modules[name] for name in module_names)
        parse = schemas.parse
        verifier_type, admission_type = bridge.BridgeVerifier, bridge.ModelAdmission
        drive, outcome_type = lifecycle.drive_model, lifecycle.ModelOutcome
        store_type = reservations.ProtectedReservationStore
        reservation_type = reservations.ReservationRef
        verifier = verifier_type(policy_raw, now)
        admission = verifier.admit(dict(proof_bundle), dict(sources), operation)
        authorization = parse("A", proof_bundle[prefix][0])
        _need(type(admission) is admission_type and admission.production_eligible is False
              and admission.operation == operation and admission.nonce == nonce
              and admission.authorization_sha256 == _sha(authorization.raw)
              and admission.authorization_sha256 == expected["authorization_sha256"]
              and authorization.raw == proof_bundle[prefix][0]
              and authorization.view()["operation_nonce"] == nonce
              and authorization.view()["operation"] == operation
              and admission.envelope_sha256 == expected["envelope_sha256"])
        store = store_type(provider_owned, owner=trust.owner)
        reservation = store.reserve(operation, nonce, dict(authorization_sha256=admission.authorization_sha256,
                      source_bundle_sha256=expected["manifest_sha256"]))
        _need(type(reservation) is reservation_type and reservation.production_eligible is False
              and (reservation.operation, reservation.nonce, reservation.authorization_sha256,
                   reservation.source_bundle_sha256) == (operation, nonce,
                   expected["authorization_sha256"], expected["manifest_sha256"]))
        gate = _ConsumeGate(admission)
        outcome = drive(admission, gate, backend_owned, clock=owned_clock)
        _need(gate.used and not gate.failed and type(outcome) is outcome_type
              and outcome.production_eligible is False and outcome.operation == operation)
        result = dict(synthetic=True, production_eligible=False, operation=operation,
                      outcome=outcome)
    except BaseException:
        failed = True
    finally:
        if close is not None:
            try:
                _need(close() is None)
            except BaseException:
                failed = True
    if failed:
        raise Refused()
    return result
