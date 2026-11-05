"""Pure guards plus real Windows control-ACL/two-process fence tests; no DB."""
from contextlib import contextmanager, ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from infra import evidence_tools as tools


class ContainerTests(unittest.TestCase):
    def test_error_vocabulary_never_reflects_unknown_values(self):
        for value in ('PRIVATE_ERROR_CANARY', None, {}, True):
            error = tools.ToolUnavailable(value)
            self.assertEqual(str(error), 'PROVENANCE_UNAVAILABLE')
            self.assertEqual(error.code, 'PROVENANCE_UNAVAILABLE')

    def test_closed_json_rejects_duplicates_nonfinite_float_invalid_utf8(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}',
                    b'{"x":1.2}', b'"\xff"', b'{} trailing', b'[' * 12 + b']' * 12):
            with self.subTest(raw_kind=len(raw)), self.assertRaises(tools.ToolUnavailable):
                tools.closed_json(raw)

    def test_json_byte_depth_node_budgets(self):
        for raw in (b' ' * 65537, json.dumps([0] * 2049).encode(), json.dumps({'x': [[[[[[[[[0]]]]]]]]]}).encode()):
            with self.assertRaises(tools.ToolUnavailable):
                tools.closed_json(raw)
        self.assertEqual(tools.closed_json(b'{"schema":1}'), {'schema': 1})

    def test_fixed_contract_identity_is_unchanged(self):
        self.assertEqual(hashlib.sha256(tools.CONTRACT.read_bytes()).hexdigest(), tools.CONTRACT_SHA256)
        self.assertEqual(len(json.loads(tools.CONTRACT.read_bytes())['manifest']['fields']), 23)

    def test_actual_companion_parser_future_and_stale_manifest_inputs(self):
        now = datetime.now(timezone.utc)
        iso = lambda seconds: (now + timedelta(seconds=seconds)).isoformat()
        signatures = [{'name': name + '.cvd', 'sha256': 'a' * 64, 'version': 1,
                       'signed_at': iso(-30), 'verification_receipt_sha256': 'b' * 64}
                      for name in ('bytecode', 'daily', 'main')]
        fields = json.loads(tools.CONTRACT.read_bytes())['manifest']['fields']
        document = {name: 'a' * 64 for name in fields}
        document.update(schema_version=1, purpose='private-evidence-validation-v1', policy_generation=1,
                        created_at=iso(-10), valid_until=iso(600), python_version='3.14.4',
                        pillow_version='13.0.0', clamav_version='1.4.6', codec_versions={'jpeg': '8.0', 'zlib': '1.3.1'},
                        signature_files=signatures, signature_generation=hashlib.sha256(tools.canonical(signatures)).hexdigest(),
                        daily_signed_at=iso(-30), last_successful_update_check_at=iso(-20))
        parsed = tools._parser(tools.canonical(document))
        self.assertEqual(parsed.as_provenance(), document)
        self.assertGreater(parsed.expires_at, now)
        for changes in ({'created_at': iso(60)}, {'valid_until': iso(-1)},
                        {'valid_until': iso(700000)}, {'last_successful_update_check_at': iso(-90000)}):
            with self.assertRaises(tools.ToolUnavailable):
                tools._parser(tools.canonical({**document, **changes}))

    def test_no_native_receipt_or_caller_verdict_can_enable(self):
        for supplied in ({}, {'PASS': True, 'disk_quota': 'VERIFIED'}, {'validation': 'OPEN'}):
            with self.assertRaisesRegex(tools.ToolUnavailable, '^ISOLATION_UNAVAILABLE$'):
                tools._verify_native_trust(supplied)
        with self.assertRaisesRegex(tools.ToolUnavailable, '^ISOLATION_UNAVAILABLE$'):
            tools.run_scan(b'private-canary', manifest={'approved': True})
        with self.assertRaisesRegex(tools.ToolUnavailable, '^ISOLATION_UNAVAILABLE$'):
            tools.decode(b'private-canary', manifest={'approved': True}, media_type='image/png')

    def test_provenance_is_fresh_copy_and_manifest_is_frozen(self):
        document = {'purpose': 'private-evidence-validation-v1', 'nested': {'x': [1]}}
        manifest = tools.ToolManifest('a' * 64, 'b' * 64, datetime.now(timezone.utc), 1, tools.CONTRACT_SHA256, tools.canonical(document))
        one = manifest.as_provenance()
        one['nested']['x'].append(2)
        self.assertEqual(manifest.as_provenance(), document)
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):
            manifest.policy_generation = 2
        with self.assertRaises(tools.ToolUnavailable):
            tools.assert_current(manifest)

    def test_assert_requires_exact_live_context_identity(self):
        manifest = tools.ToolManifest('a' * 64, 'b' * 64, datetime.now(timezone.utc), 1, tools.CONTRACT_SHA256, b'{}')
        equal_copy = tools.ToolManifest(**vars(manifest))
        token = tools._LEASE.set((manifest, object(), object(), object()))
        try:
            with self.assertRaises(tools.ToolUnavailable):
                tools.assert_current(equal_copy)
            with patch.object(tools, '_refresh_state'), patch.object(tools, '_load', return_value=equal_copy) as load:
                tools.assert_current(manifest)
                self.assertEqual(load.call_count, 1)
            changed = tools.ToolManifest('c' * 64, manifest.signature_generation, manifest.expires_at, 2, tools.CONTRACT_SHA256, b'{}')
            with patch.object(tools, '_refresh_state'), patch.object(tools, '_load', return_value=changed), self.assertRaises(tools.ToolUnavailable):
                tools.assert_current(manifest)
        finally:
            tools._LEASE.reset(token)

    def test_context_holds_fence_for_body_and_revalidates_before_release(self):
        manifest = tools.ToolManifest('a' * 64, 'b' * 64, datetime.now(timezone.utc) + timedelta(hours=1), 1, tools.CONTRACT_SHA256, b'{}')
        events = []
        @contextmanager
        def fence():
            events.append('acquire')
            with ExitStack() as stack:
                try:
                    yield object(), stack, object()
                finally:
                    events.append('release')
        def load(*args):
            self.assertEqual(events[0], 'acquire')
            self.assertNotIn('release', events)
            events.append('verify')
            return manifest
        with patch.object(tools, '_fence', fence), patch.object(tools, '_refresh_state'), patch.object(tools, '_load', side_effect=load):
            with tools.current_tools() as current:
                self.assertIs(current, manifest)
                events.append('transaction-enter')
                tools.assert_current(current)
                events.extend(('audit', 'commit', 'response-prepared'))
        self.assertEqual(events, ['acquire', 'verify', 'transaction-enter', 'verify', 'audit', 'commit', 'response-prepared', 'verify', 'release'])
        self.assertIsNone(tools._LEASE.get())

    def test_context_failure_restores_lease_and_redacts_exception(self):
        @contextmanager
        def fence():
            with ExitStack() as stack:
                yield object(), stack, object()
        with patch.object(tools, '_fence', fence), patch.object(tools, '_load', side_effect=ValueError('PRIVATE_CANARY')):
            with self.assertRaisesRegex(tools.ToolUnavailable, '^PROVENANCE_UNAVAILABLE$'):
                with tools.current_tools():
                    self.fail('unreachable')
        self.assertIsNone(tools._LEASE.get())


@unittest.skipUnless(os.name == 'nt', 'WINDOWS_CONTROL_UNAVAILABLE')
class WindowsControlTests(unittest.TestCase):
    def setUp(self):
        self.windows = tools.Windows()
        # Actual operator preparation is separate. These exclusive fixture roots
        # remain within the sole task-owned control subtree.
        if not tools.CONTROL.exists():
            self.fail('OPERATOR_PREPARE_CONTROL_REQUIRED')
        self.temporary = TemporaryDirectory(dir=tools.CONTROL)
        self.addCleanup(self.temporary.cleanup)
        self.control = Path(self.temporary.name)
        self.windows.protect(self.control, directory=True)
        self.patcher = patch.object(tools, 'CONTROL', self.control)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        owner = {'schema': 1, 'owner': tools.OWNER, 'workspace': hashlib.sha256(str(tools.ROOT).encode()).hexdigest(), 'sid': self.windows.user}
        state = {'schema': 1, 'generation': 0, 'manifest_sha256': '', 'observed_at': tools._utc_now().isoformat()}
        for name, raw in (('owner.json', tools.canonical(owner)), ('fence.lock', b'C'), ('state.json', tools.canonical(state))):
            path = self.control / name
            path.write_bytes(raw)
            self.windows.protect(path)

    def test_real_acl_owner_and_os_lock_entry(self):
        with tools._fence() as (_, _, stream):
            self.assertEqual(stream.read(), b'')

    def test_prepare_refuses_adoption(self):
        with self.assertRaisesRegex(tools.ToolUnavailable, '^PROVENANCE_UNAVAILABLE$'):
            tools.prepare_control()
        self.assertEqual((self.control / 'fence.lock').read_bytes(), b'C')

    def test_absent_pointer_fails_without_native_or_creation(self):
        baseline = sorted(p.name for p in self.control.iterdir())
        with patch.object(tools, '_verify_native_trust', side_effect=AssertionError('NO_NATIVE')):
            with self.assertRaisesRegex(tools.ToolUnavailable, '^PROVENANCE_UNAVAILABLE$'):
                with tools.current_tools():
                    self.fail('no pointer')
        self.assertEqual(sorted(p.name for p in self.control.iterdir()), baseline)

    def test_owner_marker_drift_fails(self):
        (self.control / 'owner.json').write_bytes(b'{"owner":"PRIVATE_CANARY"}')
        with self.assertRaisesRegex(tools.ToolUnavailable, '^PROVENANCE_UNAVAILABLE$'):
            with tools._fence():
                self.fail('owner mismatch')

    def test_boolean_owner_schema_is_not_integer_one(self):
        path = self.control / 'owner.json'
        owner = json.loads(path.read_bytes())
        path.write_bytes(tools.canonical({**owner, 'schema': True}))
        with self.assertRaises(tools.ToolUnavailable):
            with tools._fence():
                self.fail('boolean schema')

    def test_interrupted_or_unknown_marker_never_adopted(self):
        for marker in (b'B', b'X', b'', b'CC'):
            (self.control / 'fence.lock').write_bytes(marker)
            with self.assertRaisesRegex(tools.ToolUnavailable, '^FENCE_UNAVAILABLE$'):
                with tools._fence():
                    self.fail('bad marker')

    def test_hardlink_directory_and_outside_inputs_refused(self):
        with self.assertRaises(tools.ToolUnavailable):
            tools.checked(tools.ROOT.parent / 'outside')
        with self.assertRaises(tools.ToolUnavailable):
            with self.windows.pin(self.control, private=True):
                pass
        alias = self.control / 'alias'
        os.link(self.control / 'owner.json', alias)
        with self.assertRaises(tools.ToolUnavailable):
            with self.windows.pin(alias, private=True):
                pass

    def test_bad_dacl_refused_then_fixture_repaired(self):
        path = self.control / 'owner.json'
        descriptor = tools.c.c_void_p()
        self.windows.require(self.windows.a.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;FA;;;WD)', 1, tools.c.byref(descriptor), None))
        try:
            self.windows.require(self.windows.a.SetFileSecurityW(str(path), 0x80000004, descriptor))
        finally:
            self.windows.k.LocalFree(descriptor)
        try:
            with self.assertRaises(tools.ToolUnavailable):
                with tools._fence():
                    self.fail('untrusted ACL')
        finally:
            self.windows.protect(path)

    def test_pinned_file_refuses_replacement(self):
        source = self.control / 'owner.json'
        replacement = self.control / 'replacement'
        replacement.write_bytes(b'public replacement')
        with self.windows.pin(source, private=True):
            with self.assertRaises(OSError):
                os.replace(replacement, source)

    def test_actual_two_process_lock_excludes_then_releases(self):
        # This is real cross-process exclusion, not a mocked Python lock. Child
        # uses only the fixed helper and this exclusive control fixture.
        program = """import sys
sys.path.insert(0,sys.argv[1])
from pathlib import Path
from infra import evidence_tools as t
t.CONTROL=Path(sys.argv[2])
try:
 with t._fence(wait=0.15): pass
 print('ACQUIRED')
except t.ToolUnavailable as e:
 print(e.code)
"""
        env = {name: os.environ[name] for name in ('SystemRoot', 'WINDIR') if name in os.environ}
        command = [sys.executable, '-B', '-I', '-c', program, str(tools.ROOT), str(self.control)]
        def run():
            try:
                return subprocess.run(command, env=env, cwd=tools.ROOT, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10,
                                      creationflags=subprocess.CREATE_NO_WINDOW, check=True).stdout.strip()
            except OSError:
                self.skipTest('CHILD_PROCESS_UNAVAILABLE')
        with tools._fence():
            self.assertEqual(run(), b'FENCE_UNAVAILABLE')
        self.assertEqual(run(), b'ACQUIRED')

    def artifact_fixture(self):
        root = self.control
        generation = root / 'generation'
        generation.mkdir()
        self.windows.protect(generation, directory=True)
        rows = []
        def add(role, path, content):
            target = root / path
            target.parent.mkdir(exist_ok=True)
            self.windows.protect(target.parent, directory=True)
            target.write_bytes(content)
            self.windows.protect(target)
            row = {'role': role, 'path': path, 'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
            rows.append(row)
            return row
        document = {}
        for role, key in (('python_archive', 'python_artifact_sha256'), ('pillow_wheel', 'pillow_wheel_sha256'), ('clamav_archive', 'clamav_archive_sha256')):
            document[key] = add(role, role + '.bin', b'fixture-' + role.encode())['sha256']
        for role, key in (('decoder', 'decoder_tree_sha256'), ('scanner', 'scanner_tree_sha256')):
            add(role, role + '/binary.bin', b'fixture-' + role.encode())
            document[key] = hashlib.sha256(tools.canonical(sorted((row for row in rows if row['role'] == role), key=lambda row: row['path']))).hexdigest()
        receipt = add('signature_receipt', 'receipt.json', b'{"fixture":"not-authenticity-proof"}')
        document['signature_verification_receipt_sha256'] = receipt['sha256']
        document['signature_files'] = []
        for name in ('bytecode.cvd', 'daily.cvd', 'main.cvd'):
            row = add('signature', name, b'fixture-' + name.encode())
            document['signature_files'].append({'name': name, 'sha256': row['sha256'], 'verification_receipt_sha256': receipt['sha256']})
        document['isolation_profile_sha256'] = add('isolation_receipt', 'isolation.json', b'{"fixture":"not-isolation-proof"}')['sha256']
        inventory = generation / 'artifacts.json'
        inventory.write_bytes(tools.canonical({'schema': 1, 'files': rows}))
        self.windows.protect(inventory)
        return generation, rows, document

    def verify_fixture(self, generation, document):
        with patch.object(tools, 'TOOLS', self.control), ExitStack() as stack:
            tools._verify_artifacts(self.windows, stack, generation, document)

    def test_real_pinned_inventory_hash_closure_not_native_authenticity(self):
        generation, rows, document = self.artifact_fixture()
        self.verify_fixture(generation, document)
        with self.assertRaisesRegex(tools.ToolUnavailable, '^ISOLATION_UNAVAILABLE$'):
            tools._verify_native_trust(document)
        (self.control / rows[0]['path']).write_bytes(b'PRIVATE_ARTIFACT_CANARY')
        with self.assertRaisesRegex(tools.ToolUnavailable, '^PROVENANCE_UNAVAILABLE$'):
            self.verify_fixture(generation, document)

    def test_undeclared_runtime_tree_member_refused(self):
        generation, _, document = self.artifact_fixture()
        path = self.control / 'decoder' / 'extra.dll'
        path.write_bytes(b'fixture')
        self.windows.protect(path)
        with self.assertRaises(tools.ToolUnavailable):
            self.verify_fixture(generation, document)

    def test_artifact_inventory_escape_duplicates_extra_fields_and_bools_refused(self):
        generation, rows, document = self.artifact_fixture()
        inventory = generation / 'artifacts.json'
        for changed in ([{**rows[0], 'path': '../outside'}, *rows[1:]],
                        [*rows, rows[0]],
                        [{**rows[0], 'PASS': True}, *rows[1:]],
                        [{**rows[0], 'bytes': True}, *rows[1:]]):
            inventory.write_bytes(tools.canonical({'schema': 1, 'files': changed}))
            with self.assertRaises(tools.ToolUnavailable):
                self.verify_fixture(generation, document)

    def test_pointer_closed_schema_and_generation_refuse_before_parser(self):
        for value in ({'schema': 1, 'generation': True, 'manifest_sha256': 'a' * 64},
                      {'schema': 1, 'generation': 1, 'manifest_sha256': 'a' * 64, 'path': 'outside'},
                      {'schema': 1, 'generation': -1, 'manifest_sha256': 'a' * 64}):
            path = self.control / 'current.json'
            path.write_bytes(tools.canonical(value))
            self.windows.protect(path)
            with self.assertRaises(tools.ToolUnavailable), tools._fence() as (windows, stack, _), patch.object(tools, '_parser', side_effect=AssertionError('NO_PARSE')):
                    tools._load(windows, stack)

    def activation_manifest(self, generation=2):
        return tools.ToolManifest('a' * 64, 'b' * 64, datetime.now(timezone.utc) + timedelta(hours=1), generation, tools.CONTRACT_SHA256, b'{}')

    def test_activation_protocol_atomic_pointer_and_clean_marker_after_recheck(self):
        # Simulates future verified capability at the private loader boundary;
        # the production native trust gate remains unconditional refusal.
        manifest = self.activation_manifest()
        with patch.object(tools, '_load', return_value=manifest) as load:
            self.assertEqual(tools.activate(), 'GENERATION_ACTIVATED')
        self.assertEqual(load.call_count, 2)
        self.assertEqual(json.loads((self.control / 'current.json').read_bytes()),
                         {'schema': 1, 'generation': 2, 'manifest_sha256': 'a' * 64})
        self.assertEqual((self.control / 'fence.lock').read_bytes(), b'C')

    def test_activation_failure_leaves_dirty_marker_and_refuses_adoption(self):
        original = tools.Windows.replace
        def replace(api, source, target):
            if Path(target).name == 'current.json':
                raise PermissionError('PRIVATE_ERROR_CANARY')
            return original(api, source, target)
        with patch.object(tools, '_load', return_value=self.activation_manifest()), patch.object(tools.Windows, 'replace', replace):
            with self.assertRaisesRegex(tools.ToolUnavailable, '^PROVENANCE_UNAVAILABLE$'):
                tools.activate()
        self.assertEqual((self.control / 'fence.lock').read_bytes(), b'B')
        self.assertFalse((self.control / 'current.json').exists())
        self.assertEqual(json.loads((self.control / 'state.json').read_bytes())['generation'], 2)
        with self.assertRaisesRegex(tools.ToolUnavailable, '^FENCE_UNAVAILABLE$'):
            with tools._fence():
                self.fail('dirty control must be closed')

    def test_activation_generation_rollback_refused_before_mutation(self):
        pointer = self.control / 'current.json'
        raw = tools.canonical({'schema': 1, 'generation': 2, 'manifest_sha256': 'c' * 64})
        pointer.write_bytes(raw)
        self.windows.protect(pointer)
        self.set_state(generation=2, manifest_sha256='c' * 64)
        with patch.object(tools, '_load', return_value=self.activation_manifest(1)):
            with self.assertRaises(tools.ToolUnavailable):
                tools.activate()
        self.assertEqual(pointer.read_bytes(), raw)
        self.assertEqual((self.control / 'fence.lock').read_bytes(), b'C')

    def set_state(self, **changes):
        path = self.control / 'state.json'
        value = json.loads(path.read_bytes())
        path.write_bytes(tools.canonical({**value, **changes}))

    def test_missing_state_on_existing_control_never_reinitialized(self):
        path = self.control / 'state.json'
        path.unlink()
        with self.assertRaises(tools.ToolUnavailable):
            with tools.current_tools():
                self.fail('state is required')
        self.assertFalse(path.exists())
        with self.assertRaises(tools.ToolUnavailable):
            tools.prepare_control()

    def test_deleted_pointer_after_activation_cannot_reset_generation(self):
        with patch.object(tools, '_load', return_value=self.activation_manifest()):
            tools.activate()
        (self.control / 'current.json').unlink()
        state = (self.control / 'state.json').read_bytes()
        with patch.object(tools, '_load', side_effect=AssertionError('NO_RESET')):
            with self.assertRaises(tools.ToolUnavailable):
                tools.activate()
        self.assertEqual((self.control / 'state.json').read_bytes(), state)
        self.assertFalse((self.control / 'current.json').exists())

    def test_persistent_clock_rollback_refused_before_manifest_can_revive(self):
        now = tools._utc_now()
        self.set_state(observed_at=(now + timedelta(hours=1)).isoformat())
        before = (self.control / 'state.json').read_bytes()
        with patch.object(tools, '_load', side_effect=AssertionError('NO_REVIVED_MANIFEST')):
            with self.assertRaises(tools.ToolUnavailable):
                with tools.current_tools():
                    self.fail('wall clock reversed')
        self.assertEqual((self.control / 'state.json').read_bytes(), before)
        self.assertEqual((self.control / 'fence.lock').read_bytes(), b'C')

    def test_clock_observation_advances_under_fence_and_is_durable(self):
        before = json.loads((self.control / 'state.json').read_bytes())['observed_at']
        with tools._fence():
            pass
        after = json.loads((self.control / 'state.json').read_bytes())['observed_at']
        self.assertGreaterEqual(datetime.fromisoformat(after), datetime.fromisoformat(before))
        with patch.object(tools, '_utc_now', return_value=datetime.fromisoformat(before) - timedelta(seconds=1)):
            with self.assertRaises(tools.ToolUnavailable):
                with tools._fence():
                    self.fail('rollback across operations')

    def test_state_pointer_hash_mismatch_and_reused_generation_refused(self):
        with patch.object(tools, '_load', return_value=self.activation_manifest()):
            tools.activate()
        with patch.object(tools, '_load', return_value=self.activation_manifest()):
            with self.assertRaises(tools.ToolUnavailable):
                tools.activate()
        pointer = self.control / 'current.json'
        pointer.write_bytes(tools.canonical({'schema': 1, 'generation': 2, 'manifest_sha256': 'c' * 64}))
        with self.assertRaises(tools.ToolUnavailable):
            with tools.current_tools():
                self.fail('mismatched pointer')

    def test_assert_current_rechecks_clock_before_commit(self):
        committed = False
        with patch.object(tools, '_load', return_value=self.activation_manifest()):
            with tools.current_tools() as manifest:
                state = json.loads((self.control / 'state.json').read_bytes())
                earlier = datetime.fromisoformat(state['observed_at']) - timedelta(seconds=1)
                with patch.object(tools, '_utc_now', return_value=earlier):
                    with self.assertRaises(tools.ToolUnavailable):
                        tools.assert_current(manifest)
                        committed = True
        self.assertFalse(committed)

    def test_invalid_persistent_state_never_becomes_first_activation(self):
        path = self.control / 'state.json'
        original = json.loads(path.read_bytes())
        for changes in ({'generation': True}, {'manifest_sha256': 'a' * 64},
                        {'observed_at': '2026-10-21T00:00:00'}, {'schema': True},
                        {'generation': 1, 'manifest_sha256': ''}, {'unknown': 'PASS'}):
            path.write_bytes(tools.canonical({**original, **changes}))
            with self.assertRaises(tools.ToolUnavailable):
                with tools.current_tools():
                    self.fail('unknown state')


if __name__ == '__main__':
    unittest.main()
