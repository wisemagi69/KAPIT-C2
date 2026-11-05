"""Pure Linux declaration/authentication prerequisites, never native eligibility.

No file, key-bootstrap, signing, process, Docker or activation API. Expectations
must come from the future protected loader, not from the supplied proof itself.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
from types import MappingProxyType

from backend.apps.operations.evidence_policy import parse_manifest

CONTRACT_SHA256 = 'd0fab21054c4efc4e0c725773c0d158767a4e7cdc821fb4bf8dc3666a0e0de1d'
PLATFORM = 'linux-amd64-landlock3-seccomp-v1'
PURPOSE = 'private-evidence-linux-native-proof-v1'
DOMAIN = b'KAPIT-C2:private-evidence-linux-native-proof-v1\x00'
DESCRIPTOR_FIELDS = frozenset({'schema', 'execution_platform', 'image_id', 'oci_manifest_sha256',
    'closure_inventory_sha256', 'build_provenance_sha256', 'worker_sha256', 'confinement_sha256',
    'seccomp_sha256', 'protocol_sha256', 'scanner_options_sha256', 'decoder_options_sha256',
    'strict_scan_patch_sha256', 'strict_scan_abi', 'limits_sha256', 'signature_generation',
    'signature_verification_receipt_sha256', 'proof_binding_sha256'})
CONTEXT_FIELDS = frozenset({'schema', 'execution_platform', 'kernel_release', 'daemon_engine_version',
    'probe_source_sha256', 'required_suite_sha256', 'verification_key_sha256'})
PROOF_FIELDS = frozenset({'schema', 'purpose', 'execution_platform', 'contract_sha256', 'descriptor_sha256',
    'manifest_sha256', 'proof_context_sha256', 'required_suite_sha256', 'observed_suite_sha256',
    'observed_at', 'valid_until', 'verification_key_sha256', 'signature'})
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_LABEL = re.compile(r'[A-Za-z0-9._+-]{1,128}\Z')
_STAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z')
_SIGNATURE = re.compile(r'[A-Za-z0-9_-]{86}\Z')


class BindingUnavailable(RuntimeError):
    def __init__(self):
        self.code = 'LINUX_BINDING_UNAVAILABLE'
        super().__init__(self.code)


def _require(value):
    if not value: raise BindingUnavailable()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def _hash(value):
    _require(type(value) is str and _HEX.fullmatch(value) is not None)
    return value


def _pairs(items):
    value = {}
    for key, item in items:
        _require(key not in value)
        value[key] = item
    return value


def _closed(raw, fields):
    _require(type(raw) is bytes and 0 < len(raw) <= 16384)
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _require(False))
        stack, nodes = [(value, 1)], 0
        while stack:
            item, depth = stack.pop()
            nodes += 1
            _require(nodes <= 2048 and depth <= 8)
            if type(item) is dict:
                nodes += len(item)
                _require(nodes <= 2048)
                stack.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                stack.extend((child, depth + 1) for child in item)
        _require(type(value) is dict and set(value) == fields
                 and type(value['schema']) is int and value['schema'] == 1
                 and value['execution_platform'] == PLATFORM)
        # These three declarations are deliberately flat. No scalar coercion.
        _require(all(type(item) is str for key, item in value.items() if key != 'schema'))
        return value
    except Exception:
        raise BindingUnavailable() from None


@dataclass(frozen=True)
class ParsedDeclaration:
    """Immutable canonical declaration; parsing conveys no authority."""
    canonical_bytes: bytes
    sha256: str

    @property
    def document(self):
        return MappingProxyType(json.loads(self.canonical_bytes))

    def as_dict(self):
        return json.loads(self.canonical_bytes)


def parse_descriptor(raw):
    value = _closed(raw, DESCRIPTOR_FIELDS)
    _require(re.fullmatch(r'sha256:[0-9a-f]{64}', value['image_id']) is not None
             and value['strict_scan_abi'] == 'cl_kapit_scanmap_strict_v1')
    for key in DESCRIPTOR_FIELDS - {'schema', 'execution_platform', 'image_id', 'strict_scan_abi'}:
        _hash(value[key])
    encoded = _canonical(value)
    return ParsedDeclaration(encoded, _digest(encoded))


def parse_context(raw):
    value = _closed(raw, CONTEXT_FIELDS)
    for key in ('kernel_release', 'daemon_engine_version'):
        _require(_LABEL.fullmatch(value[key]) is not None)
    for key in CONTEXT_FIELDS - {'schema', 'execution_platform', 'kernel_release', 'daemon_engine_version'}:
        _hash(value[key])
    encoded = _canonical(value)
    return ParsedDeclaration(encoded, _digest(encoded))


def _utc(value):
    _require(type(value) is datetime and value.tzinfo is not None
             and value.utcoffset() == timedelta(0))
    return value


def _timestamp(value):
    _require(type(value) is str and _STAMP.fullmatch(value) is not None)
    try: return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError: raise BindingUnavailable() from None


def _signature(value):
    _require(type(value) is str and _SIGNATURE.fullmatch(value) is not None)
    try:
        raw = base64.b64decode(value + '==', altchars=b'-_', validate=True)
        _require(len(raw) == 64 and base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') == value)
        return raw
    except Exception:
        raise BindingUnavailable() from None


@dataclass(frozen=True)
class VerifiedBinding:
    """Authenticated bindings only: no ready/eligible/scan or issuer capability."""
    descriptor_sha256: str
    context_sha256: str
    manifest_sha256: str
    proof_sha256: str
    verification_key_sha256: str
    required_suite_sha256: str
    observed_suite_sha256: str
    observed_at: datetime
    expires_at: datetime


def verify_binding(descriptor_raw, context_raw, proof_raw, manifest_raw, *,
                   trusted_public_key, expected_key_sha256, expected_context_sha256,
                   required_suite_sha256, expected_manifest_sha256,
                   verified_manifest_expires_at, verified_signature_expires_at, now):
    """Expectations/UTC clock must be independently protected loader inputs.

    This authenticates declarations. It does not verify artifacts, actual suite
    completion, host controls, highwater/revocation or any activation gate.
    """
    try:
        _utc(now); _utc(verified_manifest_expires_at); _utc(verified_signature_expires_at)
        for expected in (expected_key_sha256, expected_context_sha256, required_suite_sha256, expected_manifest_sha256):
            _hash(expected)
        _require(type(trusted_public_key) is bytes and len(trusted_public_key) == 32
                 and _digest(trusted_public_key) == expected_key_sha256)
        descriptor = parse_descriptor(descriptor_raw)
        context = parse_context(context_raw)
        desc, ctx = descriptor.document, context.document
        proof = _closed(proof_raw, PROOF_FIELDS)
        for key in PROOF_FIELDS:
            if key.endswith('_sha256'): _hash(proof[key])
        _require(proof['purpose'] == PURPOSE and proof['contract_sha256'] == CONTRACT_SHA256)
        _require(context.sha256 == expected_context_sha256 == desc['proof_binding_sha256'] == proof['proof_context_sha256']
                 and proof['descriptor_sha256'] == descriptor.sha256
                 and ctx['verification_key_sha256'] == proof['verification_key_sha256'] == expected_key_sha256
                 and ctx['required_suite_sha256'] == proof['required_suite_sha256'] == required_suite_sha256)
        manifest = parse_manifest(manifest_raw, now=now)
        declared = manifest.document
        _require(manifest.manifest_hash == expected_manifest_sha256 == proof['manifest_sha256']
                 and declared['contract_sha256'] == CONTRACT_SHA256
                 and declared['isolation_profile_sha256'] == descriptor.sha256
                 and declared['signature_generation'] == desc['signature_generation']
                 and declared['signature_verification_receipt_sha256'] == desc['signature_verification_receipt_sha256']
                 and declared['limits_sha256'] == desc['limits_sha256'])
        observed, expires = _timestamp(proof['observed_at']), _timestamp(proof['valid_until'])
        _require(observed <= now < expires and observed < expires <= observed + timedelta(seconds=86400)
                 and expires <= manifest.expires_at and expires <= verified_manifest_expires_at
                 and expires <= verified_signature_expires_at)
        signature = _signature(proof['signature'])
        unsigned = {key: value for key, value in proof.items() if key != 'signature'}
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(trusted_public_key).verify(signature, DOMAIN + _canonical(unsigned))
        return VerifiedBinding(descriptor.sha256, context.sha256, manifest.manifest_hash,
            _digest(_canonical(proof)), expected_key_sha256, required_suite_sha256,
            proof['observed_suite_sha256'], observed, expires)
    except Exception:
        raise BindingUnavailable() from None
