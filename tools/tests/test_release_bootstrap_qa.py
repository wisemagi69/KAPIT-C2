"""Independent benign-byte/fake-handle checks, never real project loading or WinAPI."""
import hashlib
import json
import sys
import unittest
from dataclasses import replace
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from infra import evidence_release_reservations as r
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    HAS_CRYPTO = False
else:
    HAS_CRYPTO = True
    from infra import evidence_release_bootstrap as b

OWNER = 'fixture-owner'
PATHS = ('infra/evidence_release_schemas.py', 'infra/evidence_release_bridge.py',
         'infra/evidence_release_lifecycle.py', 'infra/evidence_release_reservations.py')
IDS = ('schemas', 'bridge', 'lifecycle', 'reservations')
NONCE = 'a' * 32
NOW = '2026-10-24T00:00:01Z'


class FakeOriginal:
    def __init__(self, serial, raw=b'', directory=False, private=False):
        self.raw = raw
        self.facts = dict(volume=2**63+81, file_id=f'{serial:032x}', attributes=16 if directory else 0,
                          links=1, size=len(raw), disk=True, private=private, owner=OWNER)
        self.closed = 0
        self.identities = 0
        self.hook = None
        self.write_hook = self.flush_hook = self.close_hook = None

    def identity(self):
        self.identities += 1
        if self.hook:
            self.hook(self)
        return dict(self.facts)

    def read(self, bound):
        # Accepted shared provider contract starts at zero on EVERY read.
        return self.raw[:bound]

    def write(self, raw):
        self.raw = raw
        self.facts['size'] = len(raw)
        if self.write_hook:
            return self.write_hook(self, raw)
        return len(raw)

    def flush(self):
        if self.flush_hook:
            return self.flush_hook(self)

    def close(self):
        self.closed += 1
        if self.close_hook:
            return self.close_hook(self)


class SourceProvider:
    def __init__(self, raws):
        self.parents = {'': FakeOriginal(1, directory=True), 'infra': FakeOriginal(2, directory=True)}
        self.sources = {p: FakeOriginal(i+3, raw) for i, (p, raw) in enumerate(zip(PATHS, raws))}
        self.opened = []

    def pin_parent(self, path):
        obj = self.parents[path]
        self.opened.append(obj)
        return obj

    def open_source(self, path):
        obj = self.sources[path]
        self.opened.append(obj)
        return obj


class ReservationProvider:
    def __init__(self):
        self.parents = {p: FakeOriginal(i+1, directory=True, private=p.endswith('-v1'))
                        for i, p in enumerate(('', 'ai', 'ai/state', 'ai/state/release-reservations-v1'))}
        self.records = {}
        self.opened = []
        self.new_hook = None

    def pin_parent(self, path):
        old = self.parents[path]
        obj = FakeOriginal(int(old.facts['file_id'], 16), directory=True)
        obj.facts = dict(old.facts)
        obj.hook = old.hook
        self.opened.append(obj)
        return obj

    def create_new(self, path, intent):
        if path in self.records:
            raise FileExistsError('private path canary')
        obj = FakeOriginal(30+len(self.records), private=True)
        self.records[path] = obj
        self.opened.append(obj)
        if self.new_hook:
            self.new_hook(obj)
        return obj


class ReservationIndependentTests(unittest.TestCase):
    def setUp(self):
        self.provider = ReservationProvider()
        self.payload = dict(authorization_sha256='1'*64, source_bundle_sha256='2'*64)

    def reserve(self, operation='FRESH_PREFLIGHT', nonce='b'*32):
        return r.ProtectedReservationStore(self.provider, owner=OWNER).reserve(operation, nonce, self.payload)

    def denied(self):
        with self.assertRaises(r.ReservationRefused):
            self.reserve()

    def test_success_full_identity_exact_content_and_reopened_cross_operation_consumption(self):
        result = self.reserve()
        self.assertFalse(result.production_eligible)
        self.assertEqual(result.identity, (2**63+81, f'{30:032x}'))
        self.assertTrue(all(o.closed == 1 for o in self.provider.opened))
        record = next(iter(self.provider.records.values()))
        value = json.loads(record.raw)
        self.assertEqual(value['operation'], 'FRESH_PREFLIGHT')
        self.assertEqual(value['authorization_sha256'], self.payload['authorization_sha256'])
        with self.assertRaises(r.ReservationRefused):
            self.reserve('ONE_COMPARISON')
        self.assertEqual(len(self.provider.records), 1)

    def test_private_namespace_only_ordinary_parents_may_be_private_or_not(self):
        for flag in (False, True):
            self.setUp()
            self.provider.parents['ai'].facts['private'] = flag
            self.reserve()
        self.setUp()
        self.provider.parents['ai/state/release-reservations-v1'].facts['private'] = False
        self.denied()
        self.assertFalse(self.provider.records)

    def test_partial_write_flush_and_closed_then_raised_remain_consumed(self):
        def error(*args):
            raise OSError('private reservation canary')
        for fault in ('write', 'flush', 'close'):
            with self.subTest(fault=fault):
                self.setUp()
                def configure(obj):
                    if fault == 'write': obj.write_hook = lambda obj, raw: len(raw)-1
                    if fault == 'flush': obj.flush_hook = error
                    if fault == 'close': obj.close_hook = error
                self.provider.new_hook = configure
                self.denied()
                first = next(iter(self.provider.records.values()))
                self.assertEqual(first.closed, 1)
                self.provider.new_hook = None
                self.denied()
                self.assertIs(first, next(iter(self.provider.records.values())))

    def test_late_identity_failure_still_closes_every_original(self):
        def configure(obj):
            def on_flush(current):
                # Recheck fails before close; original close remains owed.
                current.facts['file_id'] = 'f'*32
            obj.flush_hook = on_flush
        self.provider.new_hook = configure
        self.denied()
        self.assertTrue(all(obj.closed == 1 for obj in self.provider.opened))

    def test_parent_changes_on_final_unwind_still_close(self):
        def configure(obj):
            parent = self.provider.opened[0]
            old = parent.facts['file_id']
            def mutate(current):
                if current.identities >= 5:
                    current.facts['file_id'] = 'f'*32
            parent.hook = mutate
            self.assertNotEqual(old, 'f'*32)
        self.provider.new_hook = configure
        self.denied()
        self.assertTrue(all(obj.closed == 1 for obj in self.provider.opened))

    def test_callback_substitution_cannot_redirect_original_operations(self):
        def configure(obj):
            def mutate(current, raw):
                current.close = lambda: (_ for _ in ()).throw(AssertionError('replacement close'))
                current.identity = lambda: {}
                current.read = lambda n: b'changed'
                return len(raw)
            obj.write_hook = mutate
        self.provider.new_hook = configure
        self.reserve()
        self.assertTrue(all(obj.closed == 1 for obj in self.provider.opened))

    def test_exact_identity_metadata_denials_and_full_width_change(self):
        for change in (dict(volume=True), dict(volume=2**64), dict(file_id='0'*32), dict(links=2),
                       dict(attributes=0x400), dict(attributes=0x40), dict(disk=1), dict(private=1),
                       dict(owner='foreign'), dict(size=True)):
            with self.subTest(change=change):
                self.setUp()
                self.provider.new_hook = lambda obj: obj.facts.update(change)
                self.denied()
                self.assertTrue(all(obj.closed == 1 for obj in self.provider.opened))

    def test_no_backend_access_from_closed_production_entry(self):
        class Bomb:
            def __getattribute__(self, key):
                raise AssertionError(key)
        with self.assertRaises(r.ReservationRefused):
            r.production_open(Bomb(), approved=True)

    def test_identity_alias_parent_and_new_original_refuse_without_adoption(self):
        self.provider.parents['ai'].facts['file_id'] = self.provider.parents[''].facts['file_id']
        self.denied()
        self.assertFalse(self.provider.records)
        self.setUp()
        self.provider.new_hook = lambda obj: obj.facts.update(file_id=self.provider.parents[''].facts['file_id'])
        self.denied()
        self.assertTrue(all(o.closed == 1 for o in self.provider.opened))

    def test_invalid_payload_nonce_and_operation_do_not_create(self):
        for operation, nonce, payload in (('DELETE','b'*32,self.payload),
                ('FRESH_PREFLIGHT','../'+'b'*32,self.payload),
                ('ONE_COMPARISON','B'*32,self.payload),
                ('FRESH_PREFLIGHT','b'*32,dict(self.payload,override=True)),
                ('FRESH_PREFLIGHT','b'*32,dict(self.payload,authorization_sha256=True))):
            with self.assertRaises(r.ReservationRefused):
                r.ProtectedReservationStore(self.provider,owner=OWNER).reserve(operation,nonce,payload)
        self.assertFalse(self.provider.opened)
        self.assertFalse(self.provider.records)

    def test_exact_write_and_flush_return_types_refuse(self):
        for kind in ('write_bool','flush_bool','close_bool'):
            self.setUp()
            def configure(obj):
                if kind == 'write_bool': obj.write_hook = lambda obj, raw: True
                if kind == 'flush_bool': obj.flush_hook = lambda obj: False
                if kind == 'close_bool': obj.close_hook = lambda obj: False
            self.provider.new_hook = configure
            self.denied()
            self.assertTrue(all(o.closed == 1 for o in self.provider.opened))

    def test_exported_snapshot_error_never_retains_private_exception(self):
        obj = FakeOriginal(80)
        def fail(current):
            raise OSError('private snapshot canary')
        obj.hook = fail
        with self.assertRaises(r.ReservationRefused) as caught:
            r.capture_owned(obj,owner=OWNER)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(obj.closed,1)

    def test_candidate_owned_close_captures_underlying_fake_function(self):
        # No candidate provider construction, ctypes/WinDLL or OS call.
        calls = []
        fake = SimpleNamespace(c=object(),w=object(),owner=OWNER)
        names = ('_basic','_info','_kind','_read','_write','_seek','_flush','_close',
                 '_security','_control','_sidtext','_acl','_ace','_free')
        for name in names:
            setattr(fake,name,lambda *args: True)
        fake._close = lambda handle: calls.append(handle) or True
        owned = r._Win32Owned(fake,12345)
        fake._close = lambda handle: (_ for _ in ()).throw(AssertionError('replaced native callback'))
        owned.close()
        owned.close()
        self.assertEqual(calls,[12345])

    def test_successful_handle_transfer_retains_passed_original_close(self):
        calls = []
        fake = SimpleNamespace(c=object(),w=object(),owner=OWNER)
        for name in ('_basic','_info','_kind','_read','_write','_seek','_flush','_close',
                     '_security','_control','_sidtext','_acl','_ace','_free'):
            setattr(fake,name,lambda *args: True)
        original = lambda handle: calls.append(handle) or True
        fake._close = lambda handle: (_ for _ in ()).throw(AssertionError('replacement after create'))
        owned = r._transfer_win32(fake,456,original)
        owned.close()
        owned.close()
        self.assertEqual(calls,[456])

    def test_reservation_write_bound_4096_and_no_4097_mutation(self):
        obj = FakeOriginal(81,private=True)
        snapshot = r.capture_owned(obj,owner=OWNER,writable=True,require_private=True)
        snapshot.write_exact(b'x'*4096)
        snapshot.flush()
        self.assertEqual(snapshot.read_exact(4096),b'x'*4096)
        snapshot.close()
        obj = FakeOriginal(82,private=True)
        snapshot = r.capture_owned(obj,owner=OWNER,writable=True,require_private=True)
        with self.assertRaises(r.ReservationRefused):
            snapshot.write_exact(b'x'*4097)
        self.assertEqual(obj.raw,b'')
        with self.assertRaises(r.ReservationRefused):
            snapshot.close()
        self.assertEqual(obj.closed,1)


@unittest.skipUnless(HAS_CRYPTO, 'existing project venv required for actual Ed25519')
class BootstrapIndependentTests(unittest.TestCase):
    def setUp(self):
        # Explicit fixture isolation only: preserve/restore real cached modules.
        # The loader itself never evicts or bypasses target caches.
        aliases = {p[:-3].replace('/', '.').casefold() for p in PATHS}
        aliases.update(p.rsplit('/', 1)[-1][:-3].casefold() for p in PATHS)
        saved = {name: module for name, module in tuple(sys.modules.items())
                 if type(name) is str and name.casefold() in aliases}
        for name in saved:
            del sys.modules[name]
        def restore():
            sys.modules.update(saved)
        self.addCleanup(restore)
        self.key = Ed25519PrivateKey.generate()
        pub = self.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.trust = b.OfflineTrust('key-fixture', pub, 'policy-fixture', 'authority-fixture', OWNER)
        self.raws = [b'VALUE=11\n', b'from infra.evidence_release_schemas import VALUE\nVALUE+=1\n',
                     b'from infra import evidence_release_bridge\nVALUE=evidence_release_bridge.VALUE+1\n',
                     b'from infra.evidence_release_lifecycle import VALUE\nVALUE+=1\n']
        self.provider = SourceProvider(self.raws)
        self.external = {}
        self.value = dict(scope='PUBLIC_EXECUTABLE_BUNDLE_V1', version=1, key_id='key-fixture',
                          policy='policy-fixture', authority='authority-fixture', nonce=NONCE,
                          issued_utc='2026-10-24T00:00:00Z', expires_utc='2026-10-24T00:05:00Z')
        self.refresh()

    def refresh(self):
        self.value['files'] = [dict(id=i, path=p, sha256=hashlib.sha256(raw).hexdigest(), size=len(raw))
                               for i, p, raw in zip(IDS, PATHS, self.raws)]
        self.provider = SourceProvider(self.raws)

    def signed(self):
        raw = json.dumps(self.value, sort_keys=True, separators=(',', ':')).encode('ascii')
        return raw, self.key.sign(b'KAPIT-C2/EXECUTABLE-BUNDLE/V1\0'+raw)

    def load(self, **kwargs):
        raw, sig = self.signed()
        args = dict(trust=self.trust, now_utc=NOW, expected_nonce=NONCE, trusted_external=self.external)
        args.update(kwargs)
        return b.load_synthetic_bundle(self.provider, raw, sig, **args)

    def deny(self, **kwargs):
        with self.assertRaises(b.Refused) as caught:
            self.load(**kwargs)
        self.assertIsNone(caught.exception.__context__)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(all(o.closed == 1 for o in self.provider.opened))

    def test_offset_zero_read_success_held_exact_bytes_no_module_registration(self):
        loaded = self.load()
        self.assertEqual(loaded.modules['infra.evidence_release_reservations'].VALUE, 14)
        self.assertTrue(all(o.closed == 0 for o in self.provider.opened))
        self.assertTrue(all(p[:-3].replace('/', '.') not in sys.modules for p in PATHS))
        loaded.close()
        self.assertTrue(all(o.closed == 1 for o in self.provider.opened))

    def test_each_last_source_failure_prevents_any_compile_or_execute(self):
        for index in range(4):
            self.setUp()
            self.provider.sources[PATHS[index]].raw += b'#extra'
            with patch.object(b, '_COMPILE', side_effect=AssertionError('must not compile')) as compiler:
                self.deny()
                compiler.assert_not_called()

    def test_validly_resigned_policy_authority_nonce_and_dates_refuse_before_io(self):
        for field, value in (('policy','foreign'), ('authority','foreign'), ('nonce','b'*64),
                             ('issued_utc','2026-10-24T00:00:02Z'), ('expires_utc',NOW),
                             ('expires_utc','2026-10-24T00:05:01Z'),
                             ('issued_utc','2026-02-30T00:00:00Z')):
            self.setUp()
            self.value[field] = value
            self.deny()
            self.assertEqual(self.provider.opened, [])

    def test_valid_signature_wrong_domain_revoked_and_wrong_key(self):
        raw, _ = self.signed()
        for signature, trust in ((self.key.sign(raw), self.trust),
                                (self.key.sign(b.DOMAIN+raw), replace(self.trust, revoked_key_ids=('key-fixture',))),
                                (self.key.sign(b.DOMAIN+raw), replace(self.trust,public_key=bytes(32)))):
            with self.assertRaises(b.Refused) as caught:
                b.verify_manifest(raw, signature, trust=trust, now_utc=NOW, expected_nonce=NONCE)
            self.assertIsNone(caught.exception.__context__)
            self.assertIsNone(caught.exception.__cause__)

    def test_same_bytes_identity_swap_during_read_full128_and64_widths(self):
        for field, value in (('file_id',f'{2**96+3:032x}'), ('volume',2**63+81+2**32)):
            self.setUp()
            obj = self.provider.sources[PATHS[0]]
            original_read = obj.read
            def read(n):
                obj.facts[field] = value
                return original_read(n)
            obj.read = read
            self.deny()

    def test_mutation_between_compile_and_execution_refuses_no_execution(self):
        original = b._COMPILE
        def compiler(*args, **kwargs):
            result = original(*args, **kwargs)
            self.provider.parents['infra'].facts['file_id'] = 'f'*32
            return result
        with patch.object(b, '_COMPILE', side_effect=compiler), patch.object(b, '_EXEC') as executor:
            self.deny()
            executor.assert_not_called()

    def test_retained_original_callbacks_survive_benign_fixture_substitution(self):
        external = ModuleType('math')
        def mutate():
            for obj in self.provider.opened:
                obj.identity = lambda: {}
                obj.close = lambda: (_ for _ in ()).throw(AssertionError('replacement'))
        external.change = mutate
        self.raws[3] = b'import math\nmath.change()\n'
        self.refresh()
        self.external = {'math': external}
        loaded = self.load()
        loaded.close()
        self.assertTrue(all(o.closed == 1 for o in self.provider.opened))

    def test_namespace_cache_and_bare_case_aliases_denied_without_access(self):
        for name in ('infra.evidence_release_schemas','INFRA.EVIDENCE_RELEASE_BRIDGE',
                     'evidence_release_lifecycle','EVIDENCE_RELEASE_RESERVATIONS'):
            with patch.dict(sys.modules,{name:ModuleType(name)}):
                self.deny()
                self.assertFalse(self.provider.opened)

    def test_dependency_escapes_even_if_cached_never_imported(self):
        for source in (b'import sys\n',b'import pathlib\n',b'import infra.evidence_release_other\n',
                       b'from . import evidence_release_schemas\n'):
            self.raws[0] = source
            self.refresh()
            self.deny()

    def test_close_uncertainty_sticky_all_originals_attempted(self):
        loaded = self.load()
        def fail(obj):
            raise OSError('private close canary')
        self.provider.sources[PATHS[0]].close_hook = fail
        for _ in range(2):
            with self.assertRaises(b.Refused) as caught:
                loaded.close()
            self.assertIsNone(caught.exception.__context__)
        self.assertTrue(all(o.closed == 1 for o in self.provider.opened))

    def test_invalid_initial_owned_identity_still_closes_original_and_private_error(self):
        obj = self.provider.sources[PATHS[0]]
        def fail(current):
            raise OSError('private source canary')
        obj.hook = fail
        self.deny()

    def test_source_and_parent_closed_metadata_types(self):
        for field, value in (('private',1),('disk',1),('owner',True),('size',True),
                             ('links',2),('attributes',0x400),('file_id','0'*32)):
            self.setUp()
            self.provider.sources[PATHS[1]].facts[field] = value
            self.deny()

    def test_resigned_closed_file_list_and_numeric_aliases(self):
        for alteration in ('missing','extra','duplicate','case','bool_size'):
            self.setUp()
            rows = self.value['files']
            if alteration == 'missing': rows.pop()
            if alteration == 'extra': rows.append(dict(rows[0]))
            if alteration == 'duplicate': rows[1] = dict(rows[0])
            if alteration == 'case': rows[0]['path'] = rows[0]['path'].upper()
            if alteration == 'bool_size': rows[0]['size'] = True
            self.deny()
            self.assertFalse(self.provider.opened)

    def test_partial_or_extra_bytes_refuse_before_compile(self):
        for changed in (self.raws[0][:-1],self.raws[0]+b'\n'):
            self.setUp()
            self.provider.sources[PATHS[0]].raw = changed
            with patch.object(b,'_COMPILE') as compiler:
                self.deny()
                compiler.assert_not_called()

    def test_post_execution_identity_change_closes_all_and_refuses(self):
        external = ModuleType('math')
        external.change = lambda: self.provider.sources[PATHS[0]].facts.update(file_id='f'*32)
        self.raws[3] = b'import math\nmath.change()\n'
        self.refresh()
        self.external = {'math':external}
        self.deny()

    def test_lazy_candidate_dependencies_require_explicit_benign_external_modules(self):
        # Synthetic ModuleTypes only: no real ctypes/WinDLL/native API usage.
        fake_c = ModuleType('ctypes')
        fake_w = ModuleType('ctypes.wintypes')
        fake_n = ModuleType('ntpath')
        fake_c.MARK, fake_w.MARK, fake_n.MARK = 1,2,3
        fake_c.wintypes = fake_w
        self.raws[0] = (b'import ctypes\nfrom ctypes import wintypes\nimport ntpath\n'
                        b'VALUE=ctypes.MARK+wintypes.MARK+ntpath.MARK\n')
        self.refresh()
        self.deny()
        self.refresh()
        self.external = {'ctypes':fake_c,'ctypes.wintypes':fake_w,'ntpath':fake_n}
        loaded = self.load()
        self.assertEqual(loaded.modules['infra.evidence_release_reservations'].VALUE,9)
        loaded.close()

    def test_production_entry_does_not_touch_arguments(self):
        class Bomb:
            def __getattribute__(self, key):
                raise AssertionError(key)
        with self.assertRaises(b.Refused):
            b.production_bootstrap(Bomb(), trust=Bomb(), approved=True)


if __name__ == '__main__':
    unittest.main()
