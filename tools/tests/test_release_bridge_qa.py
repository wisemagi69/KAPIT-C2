"""Independent public release-proof challenges; never invoke runtime backends."""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
from datetime import timedelta
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from infra import evidence_release_schemas as schemas

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    HAVE_CRYPTO = False
else:
    HAVE_CRYPTO = True
    from infra import evidence_release_bridge as bridge
    from infra import evidence_release_lifecycle as lifecycle
    from infra.tests.test_release_bridge import fixture as signed_fixture, NOW as FIXTURE_NOW


def host_authorization():
    return {
        'schema': 2, 'scope': 'PUBLIC_HOST_CALIBRATION_AUTHORIZATION_V2',
        'operation_nonce': 'a' * 32, 'operation': 'HOST_CALIBRATION',
        'subject_sha256': '1' * 64, 'runner_sha256': '2' * 64,
        'holder_sha256': '3' * 64, 'verifier_sha256': '4' * 64,
        'trust_policy_sha256': '5' * 64, 'expected_host_identity_sha256': '6' * 64,
        'expires_utc': '2026-10-23T16:00:00Z',
        'budgets': {
            'runtime_floor_bytes': 2147483648, 'build_floor_bytes': 6442450944,
            'scan_memory_bytes': 4294967296, 'cpu_seconds': 120,
            'attach_seconds': 180, 'whole_seconds': 300, 'cli_seconds': 15,
            'reap_join_seconds': 5, 'cleanup_commands': 8,
            'stdout_bytes': 4096, 'stderr_bytes': 16384,
            'containers_created': 0, 'scanner_calls': 0,
            'processes_created': 4, 'files_created': 2, 'directories_created': 1,
        },
        'authority_record_sha256': '7' * 64, 'review_record_sha256': '8' * 64,
        'native_eligible': False, 'private_input_allowed': False,
    }


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


class IndependentReleaseSchemaTests(unittest.TestCase):
    def refuse(self, kind, raw):
        try:
            schemas.parse(kind, raw)
        except schemas.Refused as error:
            self.assertEqual(error.args, ('RELEASE_BRIDGE_REFUSED',))
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
        else:
            self.fail('Invalid public proof accepted')

    def test_golden_host_authorization_and_fresh_view(self):
        raw = encoded(host_authorization())
        document = schemas.parse('AH', raw)
        self.assertEqual(document.raw, raw)
        self.assertEqual(document.sha256, hashlib.sha256(raw).hexdigest())
        view = document.view()
        view['budgets']['scanner_calls'] = 1
        self.assertEqual(document.view()['budgets']['scanner_calls'], 0)
        with self.assertRaises(FrozenInstanceError):
            document.raw = b'PRIVATE_QA_CANARY'

    def test_each_budget_exact_integer_and_fixed_value(self):
        for field, good in host_authorization()['budgets'].items():
            for bad in (False, True, float(good), str(good), None, good + 1):
                with self.subTest(field=field, bad_type=type(bad).__name__):
                    value = host_authorization()
                    value['budgets'][field] = bad
                    self.refuse('AH', encoded(value))

    def test_closed_root_and_nested_budget_fields(self):
        for field in host_authorization():
            value = host_authorization()
            del value[field]
            self.refuse('AH', encoded(value))
        for place in ('root', 'budgets'):
            value = host_authorization()
            (value if place == 'root' else value['budgets'])['approved'] = True
            self.refuse('AH', encoded(value))

    def test_noncanonical_whitespace_order_and_second_document(self):
        value = host_authorization()
        raw = encoded(value)
        for bad in (b' ' + raw, raw + b'\n', raw + b'{}',
                    json.dumps(value).encode('ascii')):
            self.refuse('AH', bad)

    def test_duplicate_and_escaped_duplicate_keys(self):
        raw = encoded(host_authorization())
        for bad in (
            raw[:-1] + b',"schema":2}',
            raw[:-1] + b',"\\u0073chema":2}',
            raw.replace(b'"scanner_calls":0', b'"scanner_calls":0,"scanner_calls":0'),
        ):
            self.refuse('AH', bad)

    def test_exact_ascii_utc_and_invalid_calendar_dates(self):
        for bad in ('\u0662\u0660\u0662\u0666-10-23T16:00:00Z',
                    '2026-1\u0660-23T16:00:00Z',
                    '2026-10-23T1\u0666:00:00Z',
                    '2026-02-30T16:00:00Z', '2026-10-23T16:00:00+00:00',
                    '2026-10-23T16:00:00.000Z'):
            with self.subTest(timestamp=ascii(bad)):
                value = host_authorization()
                value['expires_utc'] = bad
                self.refuse('AH', encoded(value))

    def test_nested_policy_dates_cannot_use_unicode_numerals(self):
        public = bytes([1]) * 32
        key_id = hashlib.sha256(public).hexdigest()
        policy = {
            'schema': 2, 'scope': 'PUBLIC_RELEASE_TRUST_POLICY_V2',
            'policy_nonce': '1' * 32, 'issued_utc': '2026-10-23T15:00:00Z',
            'expires_utc': '2026-10-23T16:00:00Z', 'revoked_key_ids': [],
            'baseline_manifest_sha256': '2' * 64, 'contract_sha256': '3' * 64,
            'protocol_sha256': '4' * 64,
            'runtime': {'image_id': 'sha256:' + '5' * 64,
                        'signature_generation': '6' * 64,
                        'profile_sha256': '7' * 64, 'preparation_sha256': '8' * 64},
            'keys': [{'key_id': key_id, 'public_key_hex': public.hex(),
                      'roles': ['AUTHORITY'], 'not_before_utc': '2026-10-23T14:00:00Z',
                      'not_after_utc': '2026-10-23T17:00:00Z'}],
        }
        schemas.parse('POLICY', encoded(policy))
        for field in ('not_before_utc', 'not_after_utc'):
            changed = deepcopy(policy)
            changed['keys'][0][field] = '\u0662\u0660\u0662\u0666-10-23T15:00:00Z'
            self.refuse('POLICY', encoded(changed))

    def test_raw_types_sizes_and_unsupported_kind(self):
        raw = encoded(host_authorization())
        for bad in ('', None, bytearray(raw), memoryview(raw), b'', b' ' * 262145):
            self.refuse('AH', bad)
        for kind in (None, 'APPROVED', [], {}):
            self.refuse(kind, raw)

    def test_decoder_privacy_and_nonfinite_values(self):
        for raw in (b'{"PRIVATE_QA_CANARY":', b'\xffPRIVATE_QA_CANARY',
                    b'[' * 2000 + b']' * 2000, b'\xef\xbb\xbf{}'):
            self.refuse('AH', raw)
        raw = encoded(host_authorization())
        for bad in (b'NaN', b'Infinity', b'-Infinity', b'1e999'):
            self.refuse('AH', raw.replace(b'"schema":2', b'"schema":' + bad))

    def test_no_enclosing_or_downstream_hash_in_host_authorization(self):
        for field in ('release_envelope_sha256', 'calibration_sha256',
                      'controller_sha256', 'authorization_sha256'):
            value = host_authorization()
            value[field] = '9' * 64
            self.refuse('AH', encoded(value))

    def test_schema_flags_cannot_be_approval_or_integer_aliases(self):
        for field in ('native_eligible', 'private_input_allowed'):
            for bad in (0, 1, True, None, 'false'):
                value = host_authorization()
                value[field] = bad
                self.refuse('AH', encoded(value))
        value = host_authorization()
        value['schema'] = True
        self.refuse('AH', encoded(value))


@unittest.skipUnless(HAVE_CRYPTO, 'Existing project venv required for Ed25519 challenges')
class IndependentReleaseCryptoTests(unittest.TestCase):
    def setUp(self):
        self.policy, self.bundle, self.sources, self.sign = signed_fixture()
        self.verifier = bridge.BridgeVerifier(self.policy, FIXTURE_NOW)

    def refuse(self, action):
        try:
            action()
        except schemas.Refused as error:
            self.assertEqual(error.args, ('RELEASE_BRIDGE_REFUSED',))
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
        else:
            self.fail('Invalid signed proof accepted')

    def change(self, name, kind, **changes):
        value = schemas.parse(kind, self.bundle[name][0]).view()
        value.update(changes)
        self.bundle[name] = self.sign(kind, encoded(value))

    def refresh_preflight_links(self):
        receipt = schemas.parse('RECEIPT', self.bundle['P']).view()
        receipt['authorization_sha256'] = schemas.digest(self.bundle['AP'][0])
        self.bundle['P'] = encoded(receipt)
        self.change('WP', 'W', authorization_sha256=receipt['authorization_sha256'],
                    receipt_sha256=schemas.digest(self.bundle['P']),
                    started_utc=receipt['started_utc'], ended_utc=receipt['ended_utc'])
        self.change('AD', 'A', preflight_sha256=schemas.digest(self.bundle['P']),
                    preflight_witness_sha256=schemas.digest(self.bundle['WP'][0]))

    def test_real_signed_positive_chains_and_external_results(self):
        for operation in ('FRESH_PREFLIGHT', 'ONE_COMPARISON'):
            facts = self.verifier.admit(self.bundle, self.sources, operation)
            verified = self.verifier.verify_result(self.bundle, self.sources, operation)
            self.assertEqual(facts, verified)
            self.assertFalse(facts.production_eligible)

    def test_full_source_bytes_not_prefixes_or_digest_assertions(self):
        for name, raw in self.sources.items():
            changed = dict(self.sources)
            changed[name] = raw + b'\n'
            self.refuse(lambda: self.verifier.admit(self.bundle, changed, 'ONE_COMPARISON'))
        changed = dict(self.sources)
        changed['controller'] = schemas.digest(self.sources['controller']).encode()
        self.refuse(lambda: self.verifier.admit(self.bundle, changed, 'ONE_COMPARISON'))

    def test_valid_signature_wrong_role_is_denied(self):
        self.bundle['WH'] = self.sign('WH', self.bundle['WH'][0], 'AUTHORITY')
        self.refuse(lambda: self.verifier.admit(self.bundle, self.sources, 'ONE_COMPARISON'))

    def test_ed25519_domain_is_verified_not_just_key_and_digest(self):
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id = hashlib.sha256(public).hexdigest()
        policy = schemas.parse('POLICY', self.policy).view()
        policy['keys'].append({'key_id': key_id, 'public_key_hex': public.hex(),
                               'roles': ['WITNESS'], 'not_before_utc': '2026-10-23T14:59:00Z',
                               'not_after_utc': '2026-10-23T15:30:00Z'})
        policy['keys'].sort(key=lambda row: row['key_id'])
        verifier = bridge.BridgeVerifier(encoded(policy), FIXTURE_NOW)
        raw = self.bundle['WH'][0]
        signature = {'schema': 2, 'scope': 'PUBLIC_PROOF_AUTHENTICATION_V2',
                     'proof_kind': 'WH', 'proof_sha256': hashlib.sha256(raw).hexdigest(),
                     'signer_key_id': key_id, 'signature_suite': 'ED25519_V1',
                     'signature_hex': key.sign(bridge.signing_bytes('WH', 'WITNESS', raw)).hex()}
        verifier.authenticated('WH', raw, encoded(signature))
        signature['signature_hex'] = key.sign(b'WRONG_DOMAIN\x00' + raw).hex()
        self.refuse(lambda: verifier.authenticated('WH', raw, encoded(signature)))

    def test_revoked_key_and_key_time_window_are_enforced(self):
        key_id = schemas.parse('SIGNATURE', self.bundle['WH'][1]).view()['signer_key_id']
        policy = schemas.parse('POLICY', self.policy).view()
        policy['revoked_key_ids'] = [key_id]
        verifier = bridge.BridgeVerifier(encoded(policy), FIXTURE_NOW)
        self.refuse(lambda: verifier.authenticated('WH', *self.bundle['WH']))
        for key in policy['keys']:
            if key['key_id'] == key_id:
                key['not_before_utc'] = '2026-10-23T15:01:00Z'
        policy['revoked_key_ids'] = []
        verifier = bridge.BridgeVerifier(encoded(policy), FIXTURE_NOW)
        self.refuse(lambda: verifier.authenticated('WH', *self.bundle['WH']))

    def test_stale_preflight_is_not_hidden_by_unexpired_release(self):
        verifier = bridge.BridgeVerifier(self.policy, FIXTURE_NOW + timedelta(seconds=251))
        verifier.admit(self.bundle, self.sources, 'FRESH_PREFLIGHT')
        self.refuse(lambda: verifier.admit(self.bundle, self.sources, 'ONE_COMPARISON'))

    def test_preflight_authorization_is_fully_verified_for_comparison(self):
        self.change('AP', 'A', release_envelope_sha256='f' * 64)
        self.refresh_preflight_links()
        self.refuse(lambda: self.verifier.admit(self.bundle, self.sources, 'ONE_COMPARISON'))

    def test_missing_preflight_upstream_records_cannot_bypass_via_ad(self):
        for name in ('AP_authority', 'AP_review'):
            changed = dict(self.bundle)
            del changed[name]
            self.refuse(lambda: self.verifier.admit(changed, self.sources, 'ONE_COMPARISON'))

    def test_comparison_cannot_use_another_signed_engine(self):
        receipt = schemas.parse('RECEIPT', self.bundle['D']).view()
        receipt['runtime_engine_sha256'] = 'f' * 64
        self.bundle['D'] = encoded(receipt)
        self.change('WD', 'W', runtime_engine_sha256='f' * 64,
                    receipt_sha256=schemas.digest(self.bundle['D']))
        self.refuse(lambda: self.verifier.verify_result(self.bundle, self.sources, 'ONE_COMPARISON'))

    def test_validly_resigned_comparison_must_follow_its_preflight(self):
        receipt = schemas.parse('RECEIPT', self.bundle['P']).view()
        receipt.update(started_utc='2026-10-23T14:59:40Z', ended_utc='2026-10-23T14:59:40Z')
        self.bundle['P'] = encoded(receipt)
        self.refresh_preflight_links()
        comparison = schemas.parse('RECEIPT', self.bundle['D']).view()
        comparison.update(authorization_sha256=schemas.digest(self.bundle['AD'][0]),
                          started_utc='2026-10-23T14:59:50Z', ended_utc='2026-10-23T14:59:50Z')
        self.bundle['D'] = encoded(comparison)
        self.change('WD', 'W', authorization_sha256=comparison['authorization_sha256'],
                    started_utc=comparison['started_utc'], ended_utc=comparison['ended_utc'],
                    receipt_sha256=schemas.digest(self.bundle['D']))
        self.verifier.verify_result(self.bundle, self.sources, 'ONE_COMPARISON')
        comparison.update(started_utc='2026-10-23T14:59:20Z', ended_utc='2026-10-23T14:59:20Z')
        self.bundle['D'] = encoded(comparison)
        self.change('WD', 'W', started_utc=comparison['started_utc'], ended_utc=comparison['ended_utc'],
                    receipt_sha256=schemas.digest(self.bundle['D']))
        self.refuse(lambda: self.verifier.verify_result(self.bundle, self.sources, 'ONE_COMPARISON'))

    def test_constructed_document_is_reparsed_not_trusted_as_raw_proof(self):
        changed = dict(self.bundle)
        changed['S'] = schemas.Document('S', self.bundle['S'])
        self.refuse(lambda: self.verifier.admit(changed, self.sources, 'ONE_COMPARISON'))

    def test_upstream_record_cannot_include_enclosing_authorization_hash(self):
        record = schemas.parse('RECORD', self.bundle['AH_review'][0]).view()
        record['authorization_sha256'] = schemas.digest(self.bundle['AH'][0])
        self.bundle['AH_review'] = self.sign('RECORD', encoded(record), 'REVIEWER')
        self.refuse(lambda: self.verifier.admit(self.bundle, self.sources, 'ONE_COMPARISON'))

    def test_malformed_bundle_shapes_have_fixed_private_refusal(self):
        for value in (None, {}, [], {'S': None}):
            self.refuse(lambda: self.verifier.admit(value, self.sources, 'ONE_COMPARISON'))

    def test_model_facts_cannot_open_public_production_entry(self):
        facts = self.verifier.admit(self.bundle, self.sources, 'ONE_COMPARISON')
        class Bomb:
            def __getattribute__(self, name):
                raise AssertionError('Backend accessed before production refusal')
        self.refuse(lambda: bridge.production_execute(facts, backend=Bomb(), approved=True))


class IndependentModelBackend:
    """Records protocol sequencing; never creates a process or container."""
    def __init__(self, fail=None):
        self.events, self.finalized, self.cleaned = [], [], []
        self.fail, self.retained = fail, False

    def step(self, name):
        self.events.append(name)
        if name == self.fail:
            raise RuntimeError('PRIVATE_QA_CANARY')

    def hold(self, *args): self.step('hold')
    def observe(self, gate, *args):
        self.step(gate)
        return {'gate': gate, 'confirmed': True}
    def reserve_guard(self, *args): self.step('guard')
    def repeat_live_gates(self, *args): self.step('repeat')
    def mark_create_attempted(self, *args): self.step('attempt')
    def create_original(self, *args):
        self.step('create')
        return {'cid': 'c' * 64, 'returncode': 0}
    def record_original(self, *args): self.step('record')
    def start_original(self, *args): self.step('start')
    def attach_original(self, *args):
        self.step('attach')
        value = {'schema_version': 1, 'scope': 'PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY',
                 'completed': 3, 'controls': [
                     {'id': 'raw_upstream', 'category': 'NOT_CLEAN'},
                     {'id': 'png_strict', 'category': 'CLEAN'},
                     {'id': 'png_upstream', 'category': 'CLEAN'}]}
        return {'returncode': 0, 'stdout': encoded(value), 'stderr_bytes': 0, 'closed': True}
    def cleanup_original(self, cid, *args):
        self.step('cleanup')
        self.cleaned.append(cid)
    def postflight(self, cid, originals, records, *args):
        self.step('postflight')
        if cid is not None:
            if self.cleaned != [cid]:
                raise AssertionError('Positive postflight preceded original cleanup')
            if (originals, records) != (29, 116):
                raise AssertionError('Wrong combined original/journal count')
    def save_candidate(self, *args): self.step('save')
    def finalize(self, name, *args):
        self.finalized.append(name)
        self.step('finalize:' + name)
    def close_candidate(self, *args): self.step('close')
    def commit_original_guard(self, *args): self.step('commit')
    def confirm_guard_absent(self, *args):
        self.step('absent')
        return True
    def finish_model(self, *args): self.step('finish')
    def retain_refusal_guard(self):
        self.retained = True
        self.step('retain')


@unittest.skipUnless(HAVE_CRYPTO, 'Existing project venv required for lifecycle challenges')
class IndependentReleaseLifecycleTests(unittest.TestCase):
    def setUp(self):
        policy, bundle, sources, _ = signed_fixture()
        self.admission = bridge.BridgeVerifier(policy, FIXTURE_NOW).admit(bundle, sources, 'ONE_COMPARISON')

    def refuse(self, action):
        try:
            action()
        except schemas.Refused as error:
            self.assertEqual(error.args, ('RELEASE_BRIDGE_REFUSED',))
            self.assertIsNone(error.__context__)
            self.assertIsNone(error.__cause__)
        else:
            self.fail('Failed protocol accepted')

    def test_positive_order_ownership_cleanup_postflight_then_five_finalizers(self):
        backend = IndependentModelBackend()
        with tempfile.TemporaryDirectory() as directory:
            facts = lifecycle.drive_model(self.admission, lifecycle.ModelFileLedger(directory), backend, clock=lambda: 0)
            self.assertFalse(facts.production_eligible)
            for earlier, later in (('attempt', 'create'), ('record', 'start'),
                                   ('cleanup', 'postflight'), ('postflight', 'save'),
                                   ('save', 'finalize:context'), ('close', 'commit')):
                self.assertLess(backend.events.index(earlier), backend.events.index(later))
            self.assertEqual(tuple(backend.finalized), schemas.FINALIZERS)
            self.refuse(lambda: lifecycle.ModelFileLedger(directory).consume(self.admission))

    def test_timeout_still_attempts_all_owned_finalizer_callbacks(self):
        ticks = [0]
        backend = IndependentModelBackend()
        original = backend.observe
        def late(*args):
            ticks[0] = 301
            return original(*args)
        backend.observe = late
        with tempfile.TemporaryDirectory() as directory:
            self.refuse(lambda: lifecycle.drive_model(self.admission, lifecycle.ModelFileLedger(directory),
                                                     backend, clock=lambda: ticks[0]))
            self.assertEqual(tuple(backend.finalized), schemas.FINALIZERS)
            self.assertTrue(backend.retained)
            self.refuse(lambda: lifecycle.ModelFileLedger(directory).consume(self.admission))

    def test_parseable_original_id_survives_failed_closed_create_frame(self):
        backend = IndependentModelBackend()
        backend.create_original = lambda *args: {'cid': 'c' * 64, 'returncode': 0, 'extra': 'PRIVATE_QA_CANARY'}
        with tempfile.TemporaryDirectory() as directory:
            self.refuse(lambda: lifecycle.drive_model(self.admission, lifecycle.ModelFileLedger(directory), backend, clock=lambda: 0))
        self.assertEqual(backend.cleaned, ['c' * 64])
        self.assertNotIn('start', backend.events)
        self.assertTrue(backend.retained)

    def test_original_callbacks_are_held_before_backend_attribute_mutation(self):
        backend = IndependentModelBackend()
        original = backend.hold
        def hold(*args):
            original(*args)
            backend.cleanup_original = lambda *args: self.fail('Replacement cleanup adopted')
            backend.finalize = lambda *args: self.fail('Replacement finalizer adopted')
        backend.hold = hold
        with tempfile.TemporaryDirectory() as directory:
            lifecycle.drive_model(self.admission, lifecycle.ModelFileLedger(directory), backend, clock=lambda: 0)
        self.assertEqual(backend.cleaned, ['c' * 64])
        self.assertEqual(tuple(backend.finalized), schemas.FINALIZERS)

    def test_each_finalizer_and_late_close_fault_keeps_refusal(self):
        for fault in (*['finalize:' + name for name in schemas.FINALIZERS], 'close', 'commit', 'finish'):
            backend = IndependentModelBackend(fail=fault)
            with tempfile.TemporaryDirectory() as directory:
                self.refuse(lambda: lifecycle.drive_model(self.admission, lifecycle.ModelFileLedger(directory), backend, clock=lambda: 0))
            self.assertTrue(backend.retained)
            self.assertEqual(tuple(backend.finalized), schemas.FINALIZERS)

    def test_interruption_after_create_cleans_original_without_recycling_nonce(self):
        backend = IndependentModelBackend()
        def interrupt(*args): raise KeyboardInterrupt()
        backend.attach_original = interrupt
        with tempfile.TemporaryDirectory() as directory:
            self.refuse(lambda: lifecycle.drive_model(self.admission, lifecycle.ModelFileLedger(directory), backend, clock=lambda: 0))
            self.assertEqual(backend.cleaned, ['c' * 64])
            self.refuse(lambda: lifecycle.ModelFileLedger(directory).consume(self.admission))

    def test_partial_write_fsync_and_closed_then_raised_reservations_stay_consumed(self):
        real_close = os.close
        def closed_then_raised(fd):
            real_close(fd)
            raise OSError('PRIVATE_QA_CLOSE_CANARY')
        faults = (('write', {'return_value': 1}),
                  ('fsync', {'side_effect': OSError('PRIVATE_QA_FSYNC_CANARY')}),
                  ('close', {'side_effect': closed_then_raised}))
        for name, kwargs in faults:
            with self.subTest(stage=name), tempfile.TemporaryDirectory() as directory:
                with patch.object(lifecycle.os, name, **kwargs):
                    self.refuse(lambda: lifecycle.ModelFileLedger(directory).consume(self.admission))
                self.refuse(lambda: lifecycle.ModelFileLedger(directory).consume(self.admission))
                self.assertEqual(len(list(Path(directory).iterdir())), 1)


if __name__ == '__main__':
    unittest.main()
