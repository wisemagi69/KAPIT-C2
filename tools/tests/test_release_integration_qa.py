"""Independent synthetic integration checks; no native or project-bundle loading."""
import hashlib
import json
import sys
import unittest
from types import ModuleType
from unittest.mock import patch

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    HAS_CRYPTO = False
else:
    HAS_CRYPTO = True
    from infra import evidence_release_bootstrap as boot
    from infra import evidence_release_bridge as bridge
    from infra import evidence_release_schemas as schemas
    from infra import evidence_release_reservations as reservations
    from infra import evidence_release_lifecycle as lifecycle
    from infra.tests import test_release_bridge as inherited_fixture

OWNER = 'qa-synthetic-owner'
NOW = '2026-10-23T15:00:00Z'
PATHS = ('infra/evidence_release_schemas.py', 'infra/evidence_release_bridge.py',
         'infra/evidence_release_lifecycle.py', 'infra/evidence_release_reservations.py')
IDS = ('schemas', 'bridge', 'lifecycle', 'reservations')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Original:
    def __init__(self, serial, raw=b'', directory=False, private=False):
        self.raw, self.closed = raw, 0
        self.facts = dict(volume=2**63+113, file_id=f'{serial:032x}',
                          attributes=16 if directory else 0, links=1, size=len(raw),
                          disk=True, private=private, owner=OWNER)
        self.close_hook = self.flush_hook = self.write_hook = None

    def identity(self):
        return dict(self.facts)

    def read(self, maximum):
        return self.raw[:maximum]

    def write(self, raw):
        self.raw = raw
        self.facts['size'] = len(raw)
        return self.write_hook(raw) if self.write_hook else len(raw)

    def flush(self):
        if self.flush_hook:
            return self.flush_hook()

    def close(self):
        self.closed += 1
        if self.close_hook:
            return self.close_hook()


class Sources:
    def __init__(self, raws):
        self.parents = {p: Original(i+1, directory=True) for i, p in enumerate(('', 'infra'))}
        self.files = {p: Original(i+3, raw) for i, (p, raw) in enumerate(zip(PATHS, raws))}
        self.opened = []
        self.hook = None

    def pin_parent(self, path):
        if self.hook:
            self.hook()
        obj = self.parents[path]
        self.opened.append(obj)
        return obj

    def open_source(self, path):
        obj = self.files[path]
        self.opened.append(obj)
        return obj


class StoreProvider:
    def __init__(self):
        self.records = {}
        self.opened = []
        self.hook = None

    def pin_parent(self, path):
        paths = ('', 'ai', 'ai/state', 'ai/state/release-reservations-v1')
        obj = Original(20+paths.index(path), directory=True, private=path.endswith('-v1'))
        self.opened.append(obj)
        return obj

    def create_new(self, path, intent):
        if path in self.records:
            raise FileExistsError('private duplicate canary')
        obj = Original(40+len(self.records), private=True)
        self.records[path] = obj
        self.opened.append(obj)
        if self.hook:
            self.hook(obj)
        return obj


class LifecycleBackend:
    def __init__(self):
        self.calls = []
        self.fault = None
        self.hold_hook = None

    def step(self, name):
        self.calls.append(name)
        if name == self.fault:
            raise RuntimeError('private lifecycle canary')

    def hold(self, *args):
        self.step('hold')
        if self.hold_hook:
            self.hold_hook()
    def observe(self, name, *args):
        self.step(name)
        return dict(gate=name, confirmed=True)
    def reserve_guard(self, *args): self.step('guard')
    def repeat_live_gates(self, *args): self.step('repeat')
    def mark_create_attempted(self, *args): self.step('attempt')
    def create_original(self, *args):
        self.step('create')
        return dict(cid='c'*64, returncode=0)
    def record_original(self, *args): self.step('record')
    def start_original(self, *args): self.step('start')
    def attach_original(self, *args):
        self.step('attach')
        return dict(returncode=0, stdout=canonical(dict(schema_version=1,
            scope='PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY', completed=3,
            controls=[dict(id=i, category='CLEAN') for i in ('raw_upstream', 'png_strict', 'png_upstream')])),
            stderr_bytes=0, closed=True)
    def cleanup_original(self, *args): self.step('cleanup')
    def postflight(self, *args): self.step('postflight')
    def save_candidate(self, *args): self.step('save')
    def finalize(self, name, *args): self.step('finalize_'+name)
    def close_candidate(self, *args): self.step('close')
    def commit_original_guard(self, *args): self.step('commit')
    def confirm_guard_absent(self, *args):
        self.step('absence')
        return True
    def finish_model(self, *args): self.step('finish')
    def retain_refusal_guard(self): self.step('retain')


@unittest.skipUnless(HAS_CRYPTO, 'Existing project venv required for real Ed25519 tests')
class ReleaseIntegrationIndependentTests(unittest.TestCase):
    def setUp(self):
        from infra import evidence_release_integration as integration
        self.integration = integration
        self.operation, self.nonce = 'FRESH_PREFLIGHT', '3'*32
        self.saved = {name: value for name, value in tuple(sys.modules.items())
                      if name.casefold() in self.target_aliases()}
        for name in self.saved:
            sys.modules.pop(name)
        self.addCleanup(self.restore_modules)
        # These are short BENIGN FIXTURE sources, not current project file bytes.
        self.raws = [b'from types import schema_api\nparse=schema_api.parse\ndigest=schema_api.digest\n',
                     b'from types import bridge_api\nBridgeVerifier=bridge_api.BridgeVerifier\nModelAdmission=bridge_api.ModelAdmission\n',
                     b'from types import lifecycle_api\ndrive_model=lifecycle_api.drive_model\nModelOutcome=lifecycle_api.ModelOutcome\n',
                     b'from types import store_api\nProtectedReservationStore=store_api.ProtectedReservationStore\nReservationRef=store_api.ReservationRef\n']
        self.external = ModuleType('types')
        self.external.schema_api, self.external.bridge_api = schemas, bridge
        self.external.lifecycle_api, self.external.store_api = lifecycle, reservations
        self.source_backend, self.provider, self.backend = Sources(self.raws), StoreProvider(), LifecycleBackend()
        self.key = Ed25519PrivateKey.generate()
        self.trust = boot.OfflineTrust('qa-key', self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                                       'qa-policy', 'qa-authority', OWNER)
        # Reuse the independently reviewed signed-chain constructor, changing
        # ONLY its synthetic verifier source to these benign wrapper bytes.
        original_digest = schemas.digest
        def fixture_digest(raw):
            return digest(self.raws[1]) if raw == b'verifier:synthetic-whole-file\n' else original_digest(raw)
        with patch.object(schemas, 'digest', fixture_digest):
            self.policy, self.proofs, self.sources, self.sign = inherited_fixture.fixture()
        self.sources['verifier'] = self.raws[1]
        self.manifest = dict(scope='PUBLIC_EXECUTABLE_BUNDLE_V1', version=1,
            key_id='qa-key', policy='qa-policy', authority='qa-authority', nonce=self.nonce,
            issued_utc='2026-10-23T14:59:00Z', expires_utc='2026-10-23T15:02:00Z',
            files=[dict(id=i, path=p, sha256=digest(raw), size=len(raw))
                   for i, p, raw in zip(IDS, PATHS, self.raws)])
        self.refresh()

    @staticmethod
    def target_aliases():
        return {name.casefold() for path in PATHS for name in (path[:-3].replace('/', '.'), path[6:-3])}

    def restore_modules(self):
        for name in tuple(sys.modules):
            if name.casefold() in self.target_aliases():
                sys.modules.pop(name)
        sys.modules.update(self.saved)

    def refresh(self):
        self.manifest_raw = canonical(self.manifest)
        self.manifest_signature = self.key.sign(boot.DOMAIN+self.manifest_raw)
        selected = 'AP' if self.operation == 'FRESH_PREFLIGHT' else 'AD'
        self.binding = dict(scope='PUBLIC_RELEASE_INTEGRATION_V1', version=1,
            key_id='qa-key', policy='qa-policy', authority='qa-authority',
            manifest_sha256=digest(self.manifest_raw), policy_sha256=digest(self.policy),
            subject_sha256=digest(self.proofs['S']), envelope_sha256=digest(self.proofs['E'][0]),
            authorization_sha256=digest(self.proofs[selected][0]), operation=self.operation, nonce=self.nonce,
            modules=[{k: row[k] for k in ('id', 'path', 'sha256')} for row in self.manifest['files']])
        self.resign_binding()

    def resign_binding(self):
        self.binding_raw = canonical(self.binding)
        self.binding_signature = self.key.sign(b'KAPIT-C2/RELEASE-INTEGRATION/V1\0'+self.binding_raw)

    def run_protocol(self, **changes):
        values = dict(manifest_raw=self.manifest_raw, manifest_signature=self.manifest_signature,
            binding_raw=self.binding_raw, binding_signature=self.binding_signature,
            policy_raw=self.policy, proof_bundle=self.proofs, sources=self.sources,
            operation=self.operation, nonce=self.nonce, now_utc=NOW, trust=self.trust,
            source_backend=self.source_backend, reservation_provider=self.provider,
            lifecycle_backend=self.backend, trusted_external={'types': self.external}, clock=lambda: 0)
        values.update(changes)
        return self.integration.run_synthetic(**values)

    def denied(self, **changes):
        with self.assertRaises(self.integration.Refused) as caught:
            self.run_protocol(**changes)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn('canary', str(caught.exception))

    def test_valid_preflight_reserves_exact_signed_tuple_before_operation(self):
        self.backend.hold_hook = lambda: self.assertEqual(len(self.provider.records), 1)
        result = self.run_protocol()
        self.assertTrue(result['synthetic'])
        self.assertIs(result['production_eligible'], False)
        record = json.loads(next(iter(self.provider.records.values())).raw)
        self.assertEqual(record['nonce'], self.nonce)
        self.assertEqual(record['authorization_sha256'], self.binding['authorization_sha256'])
        self.assertEqual(record['source_bundle_sha256'], digest(self.manifest_raw))
        self.assertTrue(all(obj.closed == 1 for obj in self.source_backend.opened+self.provider.opened))

    def test_valid_comparison_retains_full_model_order(self):
        self.operation, self.nonce = 'ONE_COMPARISON', '4'*32
        self.manifest['nonce'] = self.nonce
        self.refresh()
        self.run_protocol()
        for first, second in (('attempt', 'create'), ('record', 'start'), ('attach', 'cleanup'), ('cleanup', 'postflight')):
            self.assertLess(self.backend.calls.index(first), self.backend.calls.index(second))

    def test_bad_manifest_signature_prevents_file_or_store_access(self):
        self.denied(manifest_signature=b'x'*64)
        self.assertEqual(self.source_backend.opened, [])
        self.assertEqual(self.provider.records, {})

    def test_bad_descriptor_signature_never_reserves_or_runs(self):
        self.denied(binding_signature=b'x'*64)
        self.assertEqual(self.provider.records, {})
        self.assertEqual(self.backend.calls, [])

    def test_signed_descriptor_each_digest_mismatch_refuses(self):
        for field in ('manifest_sha256', 'policy_sha256', 'subject_sha256', 'envelope_sha256', 'authorization_sha256'):
            with self.subTest(field=field):
                self.setUp()
                self.binding[field] = 'f'*64
                self.resign_binding()
                self.denied()
                self.assertEqual(self.provider.records, {})

    def test_signed_descriptor_nonce_operation_and_authority_mismatch(self):
        for field, value in (('nonce', 'a'*32), ('operation', 'ONE_COMPARISON'),
                             ('key_id', 'different'), ('policy', 'different'), ('authority', 'different')):
            with self.subTest(field=field):
                self.setUp()
                self.binding[field] = value
                self.resign_binding()
                self.denied()
                self.assertEqual(self.provider.records, {})

    def test_signed_manifest_nonce_cannot_replace_authorization_nonce(self):
        self.nonce = 'a'*32
        self.manifest['nonce'] = self.nonce
        self.refresh()
        self.denied()
        self.assertEqual(self.provider.records, {})

    def test_signed_descriptor_module_order_path_and_digest_mismatch(self):
        for mutation in ('order', 'path', 'digest', 'missing'):
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == 'order': self.binding['modules'].reverse()
                if mutation == 'path': self.binding['modules'][0]['path'] = 'infra/other.py'
                if mutation == 'digest': self.binding['modules'][2]['sha256'] = 'f'*64
                if mutation == 'missing': self.binding['modules'].pop()
                self.resign_binding()
                self.denied()
                self.assertEqual(self.provider.records, {})

    def test_release_signature_rejection_precedes_store(self):
        raw, auth = self.proofs['E']
        self.proofs['E'] = (raw+b' ', auth)
        self.denied()
        self.assertEqual(self.provider.records, {})
        self.assertEqual(self.backend.calls, [])

    def test_source_full_byte_tamper_precedes_reservation(self):
        self.sources['controller'] += b'x'
        self.denied()
        self.assertEqual(self.provider.records, {})

    def test_bridge_manifest_cross_binding(self):
        self.raws[1] += b'\n'
        self.source_backend = Sources(self.raws)
        self.manifest['files'][1].update(size=len(self.raws[1]), sha256=digest(self.raws[1]))
        self.refresh()
        self.denied()
        self.assertEqual(self.provider.records, {})

    def test_reservation_partial_write_no_lifecycle_and_consumed(self):
        self.provider.hook = lambda obj: setattr(obj, 'write_hook', lambda raw: 1)
        self.denied()
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.backend.calls, [])
        self.assertTrue(all(obj.closed == 1 for obj in self.source_backend.opened+self.provider.opened))

    def test_reservation_flush_failure_no_lifecycle_and_consumed(self):
        def failed(): raise KeyboardInterrupt('private flush canary')
        self.provider.hook = lambda obj: setattr(obj, 'flush_hook', failed)
        self.denied()
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.backend.calls, [])

    def test_reservation_close_failure_no_lifecycle_and_consumed(self):
        def failed(): raise OSError('private close canary')
        self.provider.hook = lambda obj: setattr(obj, 'close_hook', failed)
        self.denied()
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.backend.calls, [])

    def test_loader_close_after_success_sticky(self):
        def failed(): raise RuntimeError('private final close canary')
        self.source_backend.files[PATHS[0]].close_hook = failed
        self.denied()
        self.assertIn('finish', self.backend.calls)
        self.assertEqual(len(self.provider.records), 1)
        self.assertTrue(all(obj.closed == 1 for obj in self.source_backend.opened))

    def test_interruption_runs_five_finalizers_and_closes_originals(self):
        def interrupted(): raise KeyboardInterrupt('private interrupted canary')
        self.backend.hold_hook = interrupted
        self.denied()
        self.assertTrue(all('finalize_'+name in self.backend.calls for name in schemas.FINALIZERS))
        self.assertTrue(all(obj.closed == 1 for obj in self.source_backend.opened))
        self.assertEqual(len(self.provider.records), 1)

    def test_replay_fresh_store_instance_same_provider_remains_consumed(self):
        self.run_protocol()
        self.source_backend = Sources(self.raws)
        self.backend = LifecycleBackend()
        self.denied()
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.backend.calls, [])

    def test_input_source_map_mutation_in_first_provider_callback_uses_frozen_copy(self):
        self.source_backend.hook = lambda: self.sources.__setitem__('controller', b'changed-private-canary')
        self.run_protocol()
        self.assertEqual(len(self.provider.records), 1)

    def test_input_proof_map_mutation_in_first_provider_callback_uses_frozen_copy(self):
        self.source_backend.hook = lambda: self.proofs.clear()
        self.run_protocol()
        self.assertEqual(len(self.provider.records), 1)

    def test_lifecycle_callbacks_captured_before_reservation(self):
        original = self.provider.create_new
        def create(*args):
            self.backend.hold = lambda *a: (_ for _ in ()).throw(AssertionError('replacement'))
            return original(*args)
        self.provider.create_new = create
        self.run_protocol()
        self.assertIn('hold', self.backend.calls)

    def test_original_bundle_close_callback_held_after_lifecycle_mutation(self):
        def mutate():
            for obj in self.source_backend.opened:
                obj.close = lambda: (_ for _ in ()).throw(AssertionError('replacement'))
        self.backend.hold_hook = mutate
        self.run_protocol()
        self.assertTrue(all(obj.closed == 1 for obj in self.source_backend.opened))

    def test_production_entry_does_not_inspect_inputs(self):
        class Bomb:
            def __getattribute__(self, name): raise AssertionError('input touched')
        with self.assertRaises(self.integration.Refused):
            self.integration.production_execute(Bomb(), backend=Bomb())

    def test_duplicate_gate_consumption_denied(self):
        admission = object()
        gate = self.integration._ConsumeGate(admission)
        gate.consume(admission)
        with self.assertRaises(self.integration.Refused):
            gate.consume(admission)

    def test_substituted_gate_consumption_denied(self):
        gate = self.integration._ConsumeGate(object())
        with self.assertRaises(self.integration.Refused):
            gate.consume(object())
        self.assertFalse(gate.used)

    def test_signed_descriptor_bool_version_rejected(self):
        self.binding['version'] = True
        self.resign_binding()
        self.denied()
        self.assertEqual(self.source_backend.opened, [])

    def test_descriptor_signature_domain_separation(self):
        self.binding_signature = self.key.sign(boot.DOMAIN+self.binding_raw)
        self.denied()
        self.assertEqual(self.source_backend.opened, [])

    def test_expired_and_future_manifest_no_provider_access(self):
        for now in ('2026-10-23T14:58:59Z', '2026-10-23T15:02:00Z'):
            with self.subTest(now=now):
                self.denied(now_utc=now)
                self.assertEqual(self.source_backend.opened, [])

    def test_signed_authorization_nonce_replacement_not_admission(self):
        row = schemas.parse('A', self.proofs['AP'][0]).view()
        row['operation_nonce'] = self.nonce = 'b'*32
        self.proofs['AP'] = self.sign('A', canonical(row))
        self.manifest['nonce'] = self.nonce
        self.refresh()
        self.denied()
        self.assertEqual(self.provider.records, {})

    def test_all_lifecycle_faults_preserve_consumed_reservation_and_close_bundle(self):
        for fault in ('hold', 'sources', 'postflight', 'save', 'finalize_context', 'finish'):
            with self.subTest(fault=fault):
                self.setUp()
                self.backend.fault = fault
                self.denied()
                self.assertEqual(len(self.provider.records), 1)
                self.assertTrue(all(obj.closed == 1 for obj in self.source_backend.opened))
                self.assertTrue(all('finalize_'+name in self.backend.calls for name in schemas.FINALIZERS))

    def test_operation_execution_requires_gate_consumption(self):
        original = self.external.lifecycle_api
        replacement = ModuleType('qa_nonconsuming_lifecycle')
        replacement.ModelOutcome = original.ModelOutcome
        replacement.drive_model = lambda admission, gate, backend, **kw: original.ModelOutcome(
            admission.operation, False, None, (), ())
        self.external.lifecycle_api = replacement
        self.denied()
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.backend.calls, [])

    def test_malformed_byte_boundaries_refuse_before_callbacks(self):
        for field, value in (('manifest_raw', bytearray(self.manifest_raw)),
                             ('binding_raw', b'x'*8193), ('binding_signature', b'x'*63),
                             ('policy_raw', b'x'*262145), ('proof_bundle', []),
                             ('sources', {'verifier': bytearray(b'private')})):
            with self.subTest(field=field):
                self.denied(**{field: value})
                self.assertEqual(self.source_backend.opened, [])

    def test_swallowed_duplicate_gate_stays_failed(self):
        replacement = ModuleType('qa_repeated_lifecycle')
        replacement.ModelOutcome = lifecycle.ModelOutcome
        def repeated(admission, gate, backend, **kwargs):
            gate.consume(admission)
            try: gate.consume(admission)
            except self.integration.Refused: pass
            return lifecycle.ModelOutcome(admission.operation, False, None, (), ())
        replacement.drive_model = repeated
        self.external.lifecycle_api = replacement
        self.denied()
        self.assertEqual(len(self.provider.records), 1)

    def test_swallowed_substituted_gate_stays_failed(self):
        replacement = ModuleType('qa_substituted_lifecycle')
        replacement.ModelOutcome = lifecycle.ModelOutcome
        def substituted(admission, gate, backend, **kwargs):
            try: gate.consume(object())
            except self.integration.Refused: pass
            gate.consume(admission)
            return lifecycle.ModelOutcome(admission.operation, False, None, (), ())
        replacement.drive_model = substituted
        self.external.lifecycle_api = replacement
        self.denied()
        self.assertEqual(len(self.provider.records), 1)

    def test_store_returned_wrong_binding_never_reaches_lifecycle(self):
        replacement = ModuleType('qa_wrong_reservation')
        replacement.ReservationRef = reservations.ReservationRef
        original_type = reservations.ProtectedReservationStore
        class WrongBindingStore:
            def __init__(self, provider, *, owner):
                self.store = original_type(provider, owner=owner)
            def reserve(self, operation, nonce, payload):
                value = self.store.reserve(operation, nonce, payload)
                return reservations.ReservationRef(operation, nonce, 'f'*64,
                    value.source_bundle_sha256, value.identity)
        replacement.ProtectedReservationStore = WrongBindingStore
        self.external.store_api = replacement
        self.denied()
        self.assertEqual(len(self.provider.records), 1)
        self.assertEqual(self.backend.calls, [])

    def test_original_trust_mutation_during_provider_callback_cannot_change_owner(self):
        self.source_backend.hook = lambda: object.__setattr__(self.trust, 'owner', 'changed-owner')
        self.run_protocol()
        self.assertEqual(len(self.provider.records), 1)


if __name__ == '__main__':
    unittest.main()
