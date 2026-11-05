"""Actual test-key Ed25519 verification; no operator issuer/runtime/IO proof."""
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import base64
from copy import deepcopy
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from infra import evidence_linux_trust as trust
from backend.apps.operations import evidence_policy as policy

NOW = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def sha(value):
    return hashlib.sha256(value).hexdigest()


def stamp(value):
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')


class LinuxBindingTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.from_private_bytes(b'A' * 32)  # Test fixture only.
        public = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.context = {key:sha(key.encode()) for key in trust.CONTEXT_FIELDS}
        self.context.update(schema=1, execution_platform=trust.PLATFORM, kernel_release='6.6.87.2-microsoft-standard-WSL2',
                            daemon_engine_version='28.5.1', verification_key_sha256=sha(public))
        self.descriptor = {key:sha(key.encode()) for key in trust.DESCRIPTOR_FIELDS}
        self.descriptor.update(schema=1, execution_platform=trust.PLATFORM, image_id='sha256:'+'a'*64,
            strict_scan_abi='cl_kapit_scanmap_strict_v1', proof_binding_sha256=sha(canonical(self.context)))
        files = [{'name':name+'.cvd','sha256':sha(name.encode()),'version':1,
                  'signed_at':stamp(NOW-timedelta(hours=1)), 'verification_receipt_sha256':sha((name+'receipt').encode())}
                 for name in ('bytecode','daily','main')]
        self.manifest = {key:sha(key.encode()) for key in policy.MANIFEST_FIELDS}
        self.manifest.update(schema_version=1, purpose='private-evidence-validation-v1', policy_generation=1,
            created_at=stamp(NOW-timedelta(minutes=1)),valid_until=stamp(NOW+timedelta(hours=2)),
            contract_sha256=trust.CONTRACT_SHA256,python_version='3.14.0',pillow_version='13.0.0',clamav_version='1.4.6',
            codec_versions={'jpeg':'9f','zlib':'1.3.1'},signature_files=files,
            signature_generation=sha(canonical(files)),daily_signed_at=files[1]['signed_at'],
            last_successful_update_check_at=stamp(NOW-timedelta(minutes=5)))
        for key in ('signature_generation','signature_verification_receipt_sha256','limits_sha256'):
            self.descriptor[key]=self.manifest[key]
        self.manifest['isolation_profile_sha256']=sha(canonical(self.descriptor))
        self.proof = dict(schema=1,purpose=trust.PURPOSE,execution_platform=trust.PLATFORM,
            contract_sha256=trust.CONTRACT_SHA256, descriptor_sha256=sha(canonical(self.descriptor)),
            manifest_sha256=sha(canonical(self.manifest)),proof_context_sha256=sha(canonical(self.context)),
            required_suite_sha256=self.context['required_suite_sha256'],observed_suite_sha256=sha(b'closed native test fixture'),
            observed_at=stamp(NOW-timedelta(minutes=1)),valid_until=stamp(NOW+timedelta(hours=1)),
            verification_key_sha256=sha(public))
        self.sign()
        self.options=dict(trusted_public_key=public,expected_key_sha256=sha(public),
            expected_context_sha256=sha(canonical(self.context)),required_suite_sha256=self.context['required_suite_sha256'],
            expected_manifest_sha256=sha(canonical(self.manifest)),verified_manifest_expires_at=NOW+timedelta(hours=2),
            verified_signature_expires_at=NOW+timedelta(hours=2),now=NOW)

    def sign(self, *, key=None, domain=None):
        unsigned={k:v for k,v in self.proof.items() if k!='signature'}
        self.proof['signature']=base64.urlsafe_b64encode((key or self.key).sign(
            (trust.DOMAIN if domain is None else domain)+canonical(unsigned))).rstrip(b'=').decode('ascii')

    def verify(self, **overrides):
        return trust.verify_binding(canonical(self.descriptor),canonical(self.context),canonical(self.proof),
                                    canonical(self.manifest),**(self.options|overrides))

    def denied(self, action):
        with self.assertRaises(trust.BindingUnavailable) as caught: action()
        self.assertEqual(str(caught.exception),'LINUX_BINDING_UNAVAILABLE')
        self.assertEqual(caught.exception.code,'LINUX_BINDING_UNAVAILABLE')

    def test_actual_signature_returns_only_frozen_binding_not_runtime_authority(self):
        result=self.verify()
        self.assertIs(type(result),trust.VerifiedBinding)
        self.assertEqual(result.manifest_sha256,self.options['expected_manifest_sha256'])
        self.assertEqual(result.descriptor_sha256,sha(canonical(self.descriptor)))
        self.assertFalse(hasattr(result,'ready'));self.assertFalse(hasattr(result,'native_eligible'))
        with self.assertRaises(FrozenInstanceError):result.manifest_sha256='x'
        # Common helper remains the host policy parser; it is not the native worker.
        self.assertNotEqual(self.manifest['helper_sha256'],self.descriptor['worker_sha256'])

    def test_declarations_canonicalize_and_are_detached_immutable(self):
        raw=json.dumps(self.descriptor,indent=2).encode()
        parsed=trust.parse_descriptor(raw)
        self.assertEqual(parsed.canonical_bytes,canonical(self.descriptor))
        with self.assertRaises(TypeError):parsed.document['schema']=2
        detached=parsed.as_dict();detached['schema']=99
        self.assertEqual(parsed.document['schema'],1)
        self.assertEqual(len(trust.CONTEXT_FIELDS),7);self.assertEqual(len(trust.PROOF_FIELDS),13)

    def test_wrong_domain_missing_nul_and_noncanonical_signed_bytes_refuse(self):
        for domain in (b'',trust.DOMAIN[:-1],b'KAPIT-C2:PUBLIC_ABI3_ONLY\x00'):
            self.sign(domain=domain);self.denied(self.verify)
        unsigned={k:v for k,v in self.proof.items() if k!='signature'}
        self.proof['signature']=base64.urlsafe_b64encode(self.key.sign(
            trust.DOMAIN+json.dumps(unsigned,indent=2).encode())).rstrip(b'=').decode()
        self.denied(self.verify)

    def test_canonical_signature_encoding_length_and_padding_are_mandatory(self):
        original=self.proof['signature'];alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
        altered=original[:-1]+alphabet[alphabet.index(original[-1])+1]
        self.assertEqual(base64.urlsafe_b64decode(original+'=='),base64.urlsafe_b64decode(altered+'=='))
        for value in (original+'==',original[:-1],altered,'+'+original[1:],'A'*86,True):
            self.proof['signature']=value;self.denied(self.verify)

    def test_tampered_signature_and_valid_signature_by_other_key_refuse(self):
        raw=bytearray(base64.urlsafe_b64decode(self.proof['signature']+'=='));raw[0]^=1
        self.proof['signature']=base64.urlsafe_b64encode(raw).rstrip(b'=').decode();self.denied(self.verify)
        self.sign(key=Ed25519PrivateKey.from_private_bytes(b'B'*32));self.denied(self.verify)

    def test_attacker_self_declared_key_cannot_replace_protected_key_or_context(self):
        attacker=Ed25519PrivateKey.from_private_bytes(b'B'*32)
        public=attacker.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.context['verification_key_sha256']=sha(public)
        self.descriptor['proof_binding_sha256']=sha(canonical(self.context))
        self.manifest['isolation_profile_sha256']=sha(canonical(self.descriptor))
        self.proof.update(verification_key_sha256=sha(public),proof_context_sha256=sha(canonical(self.context)),
            descriptor_sha256=sha(canonical(self.descriptor)),manifest_sha256=sha(canonical(self.manifest)))
        self.sign(key=attacker);self.denied(self.verify)
        self.denied(lambda:self.verify(trusted_public_key=public))

    def test_each_protected_expectation_is_required_independently(self):
        for name in ('expected_key_sha256','expected_context_sha256','required_suite_sha256','expected_manifest_sha256'):
            self.denied(lambda name=name:self.verify(**{name:'f'*64}))
        for value in (b'A'*31,b'A'*33,bytearray(self.options['trusted_public_key']),None):
            self.denied(lambda value=value:self.verify(trusted_public_key=value))

    def test_each_signed_hash_cross_binding_refuses_even_with_valid_signature(self):
        original=deepcopy(self.proof)
        for name in ('contract_sha256','descriptor_sha256','manifest_sha256','proof_context_sha256',
                     'required_suite_sha256','verification_key_sha256'):
            self.proof=original|{name:'e'*64};self.sign();self.denied(self.verify)
        self.proof=original
        for purpose in ('PUBLIC_ABI3_ONLY','PUBLIC_ABI3_CONFINEMENT','private-evidence-validation-v1'):
            self.proof=original|{'purpose':purpose};self.sign();self.denied(self.verify)

    def test_only_final_contract_is_allowed_in_proof_and_generic_manifest(self):
        final=trust.CONTRACT_SHA256
        for contract in ('0dd9c68967c643f97f8a7dc722d3167231f543ce9e9be7c70be8aa3c88b98ace','a'*64):
            self.proof['contract_sha256']=contract;self.sign();self.denied(self.verify)
        self.proof['contract_sha256']=final
        self.manifest['contract_sha256']='a'*64
        self.proof['manifest_sha256']=sha(canonical(self.manifest));self.sign()
        self.denied(lambda:self.verify(expected_manifest_sha256=sha(canonical(self.manifest))))

    def test_context_substitution_and_cross_platform_are_rejected(self):
        original=deepcopy(self.context)
        for field in ('kernel_release','daemon_engine_version','probe_source_sha256','required_suite_sha256'):
            self.context=original|{field:('other' if field in ('kernel_release','daemon_engine_version') else 'f'*64)}
            self.denied(self.verify)
        self.context=original
        for target in (self.context,self.descriptor,self.proof):
            target['execution_platform']='windows-lpac-v1';self.denied(self.verify);target['execution_platform']=trust.PLATFORM

    def test_manifest_descriptor_shared_fields_and_full_manifest_binding_refuse(self):
        original=deepcopy(self.manifest)
        for field in ('helper_sha256','isolation_profile_sha256','limits_sha256','signature_verification_receipt_sha256'):
            self.manifest=original|{field:'f'*64};self.denied(self.verify)
        # A valid newly signed proof cannot override descriptor-manifest mismatch.
        self.manifest=original|{'limits_sha256':'e'*64}
        self.proof['manifest_sha256']=sha(canonical(self.manifest));self.sign()
        self.denied(lambda:self.verify(expected_manifest_sha256=sha(canonical(self.manifest))))

    def test_future_expired_invalid_calendar_precision_and_overlong_proofs_refuse(self):
        original=deepcopy(self.proof)
        cases=[{'observed_at':stamp(NOW+timedelta(seconds=1))}, {'valid_until':stamp(NOW)},
            {'valid_until':stamp(NOW-timedelta(seconds=1))}, {'valid_until':stamp(NOW+timedelta(days=1))},
            {'observed_at':'2026-02-30T00:00:00Z'}, {'observed_at':'2026-10-22T11:59:00.000Z'},
            {'observed_at':'2026-10-22T11:59:00+00:00'}, {'valid_until':'2026-10-23T12:00:01Z'}]
        for changes in cases:
            self.proof=original|changes;self.sign();self.denied(self.verify)

    def test_verified_expiry_bounds_and_aware_utc_clock_are_mandatory(self):
        for field in ('verified_manifest_expires_at','verified_signature_expires_at'):
            for value in (NOW,NOW+timedelta(minutes=30),NOW.replace(tzinfo=None),True):
                self.denied(lambda field=field,value=value:self.verify(**{field:value}))
        for now in (NOW.replace(tzinfo=None),NOW.astimezone(timezone(timedelta(hours=1))),True):
            self.denied(lambda now=now:self.verify(now=now))

    def test_descriptor_context_strict_flat_schemas_and_ascii_bounds(self):
        for document,parser in ((self.descriptor,trust.parse_descriptor),(self.context,trust.parse_context)):
            for value in (document|{'schema':True},document|{'extra':'PRIVATE_CANARY'},
                          {k:v for k,v in document.items() if k!='schema'},document|{'schema':1.0}):
                self.denied(lambda value=value,parser=parser:parser(canonical(value)))
        for value in ('','a'*129,'kernel name','kernel\nname','é'):
            self.denied(lambda value=value:trust.parse_context(canonical(self.context|{'kernel_release':value})))
        for field,value in (('image_id','sha256:'+'A'*64),('worker_sha256','A'*64),('strict_scan_abi','cl_scanmap_callback')):
            self.denied(lambda field=field,value=value:trust.parse_descriptor(canonical(self.descriptor|{field:value})))

    def test_malformed_utf8_duplicates_trailing_depth_nodes_and_size_refuse(self):
        for document,parser in ((self.context,trust.parse_context),(self.descriptor,trust.parse_descriptor)):
            raw=canonical(document)
            for invalid in (raw.decode().encode('utf-16'),b'\xff',raw+b'{}',b'{"schema":1,"schema":1}',b' '*16385,
                            b'['*10+b'0'+b']'*10,canonical([0]*2100),None):
                self.denied(lambda invalid=invalid,parser=parser:parser(invalid))
        raw=canonical(self.proof)
        for invalid in (raw+b'{}',raw.replace(b'"schema":1',b'"schema":true'),
                        raw[:-1]+b',"unknown":"PRIVATE_CANARY"}',raw.decode().encode('utf-16'),b' '*16385):
            self.denied(lambda invalid=invalid:trust.verify_binding(canonical(self.descriptor),canonical(self.context),invalid,
                        canonical(self.manifest),**self.options))

    def test_common_manifest_parser_is_used_without_django(self):
        self.assertEqual(policy.parse_manifest(canonical(self.manifest),now=NOW).manifest_hash,self.verify().manifest_sha256)
        original=deepcopy(self.manifest)
        for changes in ({'extra':'PRIVATE_CANARY'},{'policy_generation':True},
                        {'pillow_version':'0'},{'last_successful_update_check_at':stamp(NOW-timedelta(days=2))}):
            self.manifest=original|changes;self.denied(self.verify)


if __name__ == '__main__':
    unittest.main()
