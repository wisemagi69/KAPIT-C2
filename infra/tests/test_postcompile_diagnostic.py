"""Pure finite-controller tests; no Docker/native/protected-file operations."""
from contextlib import ExitStack, contextmanager
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from infra import evidence_postcompile_diagnostic as diagnostic
from infra import evidence_native_runtime as runtime
from infra import evidence_native_attestation as attestation
from infra import evidence_native_refresh_runtime as refresh
from infra import evidence_native_ownership as ownership
from infra.native import postcompile_probe as program
from infra import live_recovery_drill
from infra import evidence_tools
from infra import evidence_container as base
from infra import evidence_container_native as public
from backend.apps.operations import evidence_scan_protocol as protocol


TOKEN = 'a' * 32
CID = 'b' * 64
MEASUREMENT = {'schema': 1, 'scope': program.SCOPE, 'completed': True,
    'observation': 'FIRST_MISMATCH', 'field': '17', 'category': 'AUTO',
    'native_eligible': False, 'private_input_allowed': False}


def probe():
    phase = runtime._Phase(runtime.Candidate(diagnostic.IMAGE, diagnostic.GENERATION),
        protocol.Binding('scan', 'c' * 64, diagnostic.OLD_POLICY, diagnostic.GENERATION), TOKEN)
    return diagnostic.Probe(phase, diagnostic.metadata(TOKEN), 'fixed program')


class BindingTests(unittest.TestCase):
    def test_fixed_metadata_rejects_every_invalid_token(self):
        for value in (True, None, 'x', diagnostic.OLD_TOKEN, '../' + TOKEN, 'A' * 32):
            with self.subTest(value=value), self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.metadata(value)
        value = diagnostic.metadata(TOKEN)
        self.assertEqual(value['image_id'], diagnostic.IMAGE)
        self.assertEqual(value['expected_name'], 'kapit-postcompile-public-' + TOKEN)
        self.assertEqual(value['source_sha256'], diagnostic.PROGRAM_SHA256)
        self.assertFalse(value['native_eligible'])
        self.assertFalse(value['private_input_allowed'])
        self.assertEqual(value['expected_labels']['org.kapit.generation'], diagnostic.GENERATION)

    def test_transport_requires_actual_fixed_program(self):
        raw = Path(diagnostic.ROOT / diagnostic.PROGRAM).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), diagnostic.PROGRAM_SHA256)
        self.assertIn(diagnostic.PROGRAM_SHA256, diagnostic.transport(raw))
        for value in (raw + b'\n', b'', True, b'x' * 16385):
            with self.subTest(value=type(value)), self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.transport(value)

    def test_no_caller_labels_image_or_generation_api(self):
        with self.assertRaises(TypeError): diagnostic.metadata(TOKEN, image_id='wrong')
        with self.assertRaises(TypeError): diagnostic.execute(image_id='wrong')

    def test_scan_resource_create_args_retained_and_exact_command(self):
        candidate = probe(); args = diagnostic.create_args(candidate, Path('fixed-profile'))
        for pair in (['--read-only', '--network'], ['--network', 'none'], ['--pids-limit', '1'],
                     ['--memory', '4294967296'], ['--memory-swap', '4294967296'], ['--ipc', 'none'],
                     ['--cap-drop', 'ALL'], ['--user', '65532:65532'], ['--cpus', '1']):
            self.assertTrue(any(args[i:i+2] == pair for i in range(len(args)-1)), pair)
        self.assertEqual(args[-5:], [diagnostic.IMAGE, '-I', '-B', '-c', candidate.program])
        changed = deepcopy(candidate.fixed); changed['image_id'] = 'sha256:' + '0' * 64
        with self.assertRaises(diagnostic.DiagnosticUnavailable):
            diagnostic.create_args(diagnostic.Probe(candidate.phase, changed, candidate.program), Path('profile'))

    def test_effective_properties_checked_before_normalization(self):
        candidate = probe()
        value = {'Id': CID, 'Name': '/' + candidate.name, 'Image': diagnostic.IMAGE,
            'Config': {'Labels': candidate.labels, 'Cmd': candidate.command,
                'Env': [key + '=' + item for key, item in runtime.EFFECTIVE_ENV.items()]}}
        with patch.object(runtime, 'verify_inspection') as verify:
            diagnostic.inspection(value, candidate, CID)
            normalized = verify.call_args.args[0]
            self.assertEqual(normalized['Config']['Labels'], candidate.phase.labels)
            self.assertEqual(value['Config']['Labels'], candidate.labels)
        for key, replacement in (('Id', 'd'*64), ('Name', '/wrong'), ('Image', 'sha256:' + 'e'*64)):
            with self.subTest(key=key), self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.inspection(dict(value, **{key: replacement}), candidate, CID)
        changed = deepcopy(value); changed['Config']['Labels']['extra'] = 'x'
        with self.assertRaises(diagnostic.DiagnosticUnavailable):
            diagnostic.inspection(changed, candidate, CID)

    def test_injected_missing_duplicate_or_modified_effective_env_refuses(self):
        candidate = probe()
        expected = [key + '=' + item for key, item in runtime.EFFECTIVE_ENV.items()]
        for env in (None, expected[:-1], expected + ['INJECTED=x'], expected + [expected[0]],
                    ['HOME=/other' if item.startswith('HOME=') else item for item in expected]):
            value = {'Id': CID, 'Name': '/' + candidate.name, 'Image': diagnostic.IMAGE,
                'Config': {'Labels': candidate.labels, 'Cmd': candidate.command, 'Env': env}}
            with self.subTest(env=env), patch.object(runtime, 'verify_inspection') as verify:
                with self.assertRaises(Exception): diagnostic.inspection(value, candidate, CID)
                verify.assert_not_called()


class LiveTests(unittest.TestCase):
    def test_fixed_profile_contract_ordinary_identity_pin_hash_and_canonical_bytes(self):
        raw = base.canonical(public.startup_profile())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), diagnostic.PROFILE_SHA256)
        api = object(); pins = ExitStack()
        with patch.object(refresh, 'pin_bytes', return_value=raw) as pin:
            self.assertEqual(diagnostic.profile_source(Path('root'), pins, api), raw)
        pin.assert_called_once_with(Path('root'), pins, api, diagnostic.PROFILE,
            expected='389b9d083fc90982a51f999c9cfc1858cb660654d8d01dd5bc28da0a4e0523a7')
        self.assertNotIn('private', pin.call_args.kwargs)
        self.assertEqual(pin.call_args.args[3], '.cache/m1-runtime/private-scanner-build/abi3-startup-profile.json')

    def test_profile_changed_hash_and_canonical_bytes_refuse_without_private_acl(self):
        raw = base.canonical(public.startup_profile())
        calls = []
        @contextmanager
        def pin(path, **kwargs):
            calls.append((path, kwargs)); yield io.BytesIO(raw + b' ')
        with self.assertRaises(Exception), ExitStack() as pins:
            diagnostic.profile_source(Path('root'), pins, SimpleNamespace(pin=pin))
        self.assertEqual(calls, [(Path('root') / diagnostic.PROFILE, {'private': False})])
        # Canonical equality remains an independent predicate after hashing.
        with patch.object(refresh, 'pin_bytes', return_value=b'{}'):
            with self.assertRaises(diagnostic.DiagnosticUnavailable) as error:
                diagnostic.profile_source(Path('root'), ExitStack(), object())
        self.assertEqual(error.exception.code, 'PROFILE_BYTES_CHANGED')

    def test_preserved_precreate_refusal_exact_bytes_hash_and_closed_schema(self):
        raw = (diagnostic.ROOT / diagnostic.PRIOR_RECEIPT).read_bytes()
        self.assertEqual(len(raw), 503)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), diagnostic.PRIOR_RECEIPT_SHA256)
        def api_for(data):
            @contextmanager
            def pin(*a, **k): yield io.BytesIO(data)
            return SimpleNamespace(pin=pin)
        with ExitStack() as stack:
            diagnostic.preserved_refusal(Path('root'), stack, api_for(raw))
        for changed in (raw + b' ', raw.replace(b'REFUSED', b'OBSERVED'), raw.replace(b'0.022', b'0.023')):
            with self.subTest(changed=changed[:20]), ExitStack() as stack, self.assertRaises(Exception):
                diagnostic.preserved_refusal(Path('root'), stack, api_for(changed))
        # Independently exercise the closed schema even behind the byte gate.
        wrong = raw.replace(b'0.022', b'0.023')
        with patch.object(refresh, 'pin_bytes', return_value=wrong):
            with self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.preserved_refusal(Path('root'), ExitStack(), object())
        with patch.object(refresh, 'pin_bytes', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                diagnostic.preserved_refusal(Path('root'), ExitStack(), object())

    def test_legacy_lock_exact_fixed_existing_identity_pin_no_acl_or_creation(self):
        for size, data in ((1, b'0'), (0, b''), (2, b'00'), (1, b'1')):
            api = MagicMock(); stream = MagicMock(); stream.fileno.return_value = 7; stream.read.return_value = data
            @contextmanager
            def pin(*a, **k): yield stream
            api.pin.side_effect = pin
            msvcrt = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=MagicMock())
            with patch.dict(sys.modules, msvcrt=msvcrt), \
                 patch.object(diagnostic.os, 'fstat', return_value=SimpleNamespace(st_size=size)), \
                 patch.object(diagnostic.os, 'open') as create:
                if (size, data) == (1, b'0'):
                    with diagnostic.legacy_lock(api): pass
                    self.assertEqual(msvcrt.locking.call_count, 2)
                else:
                    with self.assertRaises(diagnostic.DiagnosticUnavailable):
                        with diagnostic.legacy_lock(api): self.fail('Changed legacy lock used')
                    msvcrt.locking.assert_not_called()
            api.pin.assert_called_once_with(diagnostic.ROOT / diagnostic.STAGE / 'resume-pcre.lock', writable=True)
            create.assert_not_called(); api.protect.assert_not_called()
        api = MagicMock(); api.pin.side_effect = FileNotFoundError
        with patch.object(diagnostic.os, 'open') as create:
            with self.assertRaises(FileNotFoundError):
                with diagnostic.legacy_lock(api): self.fail('Missing legacy lock created')
        create.assert_not_called(); api.protect.assert_not_called()

    def test_fresh_observation_single_use_and_stale_age(self):
        for age in (-1, 5.001):
            item = diagnostic.Observation(diagnostic._LIVE_SEAL, 10, clock=lambda: 10 + age)
            with self.assertRaises(diagnostic.DiagnosticUnavailable): item.consume()
        item = diagnostic.Observation(diagnostic._LIVE_SEAL, 10, clock=lambda: 15)
        item.consume()
        with self.assertRaises(diagnostic.DiagnosticUnavailable): item.consume()
        with self.assertRaises(diagnostic.DiagnosticUnavailable): diagnostic.Observation(object(), 10)

    def test_original_absence_exact_response_only(self):
        expected = ('Error response from daemon: No such container: ' + diagnostic.OLD_CID + '\n').encode()
        good = (1, b'[]\n', expected, 'EXIT')
        diagnostic.absent(lambda *args: good, diagnostic.OLD_CID)
        for bad in ((0, b'[]\n', expected, 'EXIT'), (1, b'', expected, 'EXIT'),
                    (1, b'[]\n', b'permission denied', 'EXIT'), (1, b'[]\n', expected, 'WALL_LIMIT'),
                    (True, b'[]\n', expected, 'EXIT'), (1, b'[]\n', expected + b'extra', 'EXIT')):
            with self.subTest(bad=bad), self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.absent(lambda *args: bad, diagnostic.OLD_CID)

    def test_live_engine_changes_or_unknown_output_refuse(self):
        for out in (b'', b'wrong\n', b'wrong\nsecond', b'x'*257):
            with self.subTest(out=out), self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.engine(lambda *args: (0, out, b'', 'EXIT'))

    def test_live_postflight_requires_same_engine_twice_and_exact_old_targets(self):
        call = SimpleNamespace(count=0, uncertain=False)
        def mark(*args): call.count += 1
        with patch.object(diagnostic, 'engine', side_effect=mark) as engine, \
             patch.object(diagnostic, 'absent', side_effect=mark) as absent:
            item = diagnostic.observe_original(call)
        self.assertEqual(engine.call_count, 2)
        self.assertEqual(absent.call_args_list[0].args[1], diagnostic.OLD_CID)
        self.assertEqual(absent.call_args_list[1].args[1], diagnostic.OLD_NAME)
        item.consume()

    def test_commands_fixed_endpoint_no_authless_override_and_sticky_uncertainty(self):
        call = diagnostic.Commands('docker', 'empty-config')
        with patch('infra.evidence_container._bounded_command', return_value=(0, b'2\n', b'', 'EXIT')) as bounded:
            call('info', '--format', '{{.CgroupVersion}}')
        self.assertEqual(bounded.call_args.args[0][:5], ['docker', '--host', refresh.HOST, '--config', 'empty-config'])
        self.assertEqual(bounded.call_args.kwargs, {'timeout': 15, 'maximum': 65536})
        with patch('infra.evidence_container._bounded_command', return_value=(0, b'', b'', 'OUTPUT_LIMIT')):
            with self.assertRaises(diagnostic.DiagnosticUnavailable): call('info')
        self.assertTrue(call.uncertain)

    def test_changed_original_bytes_missing_file_duplicate_json_refuse(self):
        for raw in (b'{}', b'{"x":1,"x":2}'):
            with patch.object(refresh, 'pin_bytes', return_value=raw), \
                 patch.object(live_recovery_drill, 'PrivateDirectory', return_value=SimpleNamespace(pin=lambda *a, **k: ExitStack())):
                with self.assertRaises(diagnostic.DiagnosticUnavailable):
                    diagnostic.original_documents(Path('root'), ExitStack(), SimpleNamespace(pin=lambda *a, **k: ExitStack()))
        with patch.object(refresh, 'pin_bytes', side_effect=FileNotFoundError), \
             patch.object(live_recovery_drill, 'PrivateDirectory', return_value=SimpleNamespace(pin=lambda *a, **k: ExitStack())):
            with self.assertRaises(FileNotFoundError):
                diagnostic.original_documents(Path('root'), ExitStack(), SimpleNamespace(pin=lambda *a, **k: ExitStack()))

    def test_unknown_prior_diagnostic_refuses(self):
        path = Path('root') / diagnostic.STAGE / ('native-run-' + TOKEN)
        api = SimpleNamespace(pin=lambda *args, **kwargs: ExitStack())
        with patch.object(Path, 'glob', return_value=[path]), \
             patch.object(live_recovery_drill, 'PrivateDirectory', return_value=api), \
             patch.object(refresh, 'pin_bytes', return_value=json.dumps({'purpose': diagnostic.PURPOSE}).encode()):
            with self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.unknown_diagnostics(Path('root'), ExitStack(), api)

    def test_existing_native_directories_use_exact_private_directory_acl_helper(self):
        api = MagicMock(); private = MagicMock()
        private.pin.side_effect = lambda *a, **k: ExitStack()
        native = Path('root') / diagnostic.STAGE / ('native-run-' + TOKEN)
        with patch.object(live_recovery_drill, 'PrivateDirectory', return_value=private), \
             patch.object(Path, 'glob', return_value=[native]), \
             patch.object(refresh, 'pin_bytes', return_value=b'{"purpose":"same-image-probe"}'):
            with ExitStack() as stack:
                diagnostic.unknown_diagnostics(Path('root'), stack, api)
        private.pin.assert_called_once_with(native, private=True, directory=True)
        api.pin.assert_not_called()
        with patch.object(live_recovery_drill, 'PrivateDirectory', return_value=private), \
             patch.object(refresh, 'pin_bytes', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                diagnostic.original_documents(Path('root'), ExitStack(), api)
        self.assertEqual(private.pin.call_args.args[0], Path('root') / diagnostic.STAGE / ('native-run-' + diagnostic.OLD_TOKEN))

    def test_only_new_lock_is_protected_before_writing_never_existing_lock(self):
        for fresh in (True, False):
            events = []; api = MagicMock()
            @contextmanager
            def pinned(*a, **k):
                events.append('pin'); yield MagicMock(fileno=lambda: 7)
            api.pin.side_effect = pinned
            api.protect.side_effect = lambda *a: events.append('protect')
            msvcrt = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=MagicMock())
            with patch.dict(sys.modules, msvcrt=msvcrt), \
                 patch.object(diagnostic.os, 'open', return_value=7, side_effect=None if fresh else FileExistsError), \
                 patch.object(diagnostic.os, 'write', side_effect=lambda *a: events.append('write')), \
                 patch.object(diagnostic.os, 'fsync'), patch.object(diagnostic.os, 'close'), \
                 patch.object(diagnostic.os, 'fstat', return_value=SimpleNamespace(st_size=1)):
                with diagnostic.exclusive_lock(Path('fixed-lock'), api): pass
            self.assertEqual(api.protect.call_count, int(fresh))
            if fresh:
                self.assertLess(events.index('protect'), events.index('write'))
                self.assertLess(events.index('write'), events.index('pin'))
            self.assertEqual(msvcrt.locking.call_count, 2)

    def test_new_lock_protection_failure_closes_descriptor_without_write_pin_or_use(self):
        api = MagicMock(); api.protect.side_effect = OSError()
        msvcrt = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=MagicMock())
        with patch.dict(sys.modules, msvcrt=msvcrt), \
             patch.object(diagnostic.os, 'open', return_value=7), \
             patch.object(diagnostic.os, 'write') as write, \
             patch.object(diagnostic.os, 'fsync') as fsync, \
             patch.object(diagnostic.os, 'close') as close:
            with self.assertRaises(OSError):
                with diagnostic.exclusive_lock(Path('new-lock'), api):
                    self.fail('Unprotected lock was used')
        api.protect.assert_called_once_with(Path('new-lock'))
        close.assert_called_once_with(7)
        write.assert_not_called(); fsync.assert_not_called(); api.pin.assert_not_called()
        msvcrt.locking.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def exercise(self, *, record_failure=False, finish_failure=False, attach_failure=False, cleanup_failure=False,
                 malformed=False, stale=False, final_late=False):
        events = []; result = {}; candidate = probe()
        journal = SimpleNamespace(failed=False, closed=False)
        def mark(): events.append('durable-attempt')
        def record(cid):
            events.append('durable-cid')
            if record_failure: raise OSError()
        def finish(status):
            events.append('finish-' + status); journal.closed = True
            if finish_failure: raise OSError()
        journal.mark_create_attempted, journal.record_original, journal.finish = mark, record, finish
        @contextmanager
        def reserved(token): yield journal
        class Call:
            docker = 'docker'; config = 'empty'; uncertain = False
            def __call__(self, *args, **kwargs):
                events.append(args[0])
                if args[0] == 'create': return 0, (CID + '\n').encode(), b'', 'EXIT'
                return 0, b'2\n', b'', 'EXIT'
        def observed():
            events.append('consume')
            if stale: raise diagnostic.DiagnosticUnavailable('LIVE_POSTFLIGHT_STALE')
        def inspected(*args):
            events.append('inspect')
            return {'State': {'OOMKilled': False, 'ExitCode': 0, 'Pid': 0}}
        def attached(*args, **kwargs):
            events.append('attach')
            if attach_failure: raise RuntimeError()
            return 0, b'bad' if malformed else json.dumps(MEASUREMENT).encode()
        def cleaned(*args):
            events.append('cleanup')
            if cleanup_failure: raise OSError()
            return 'NOT_CREATED' if not args[-1] else 'ORIGINAL_ID_ABSENT_VERIFIED'
        with ExitStack() as stack:
            stack.enter_context(patch.object(diagnostic, 'reserve', side_effect=reserved))
            stack.enter_context(patch.object(diagnostic, 'transport', return_value='fixed'))
            stack.enter_context(patch.object(diagnostic, 'create_args', return_value=['create']))
            stack.enter_context(patch.object(diagnostic, 'inspection'))
            stack.enter_context(patch.object(diagnostic, 'inspect', side_effect=inspected))
            stack.enter_context(patch.object(diagnostic, 'cleanup', side_effect=cleaned))
            stack.enter_context(patch.object(attestation, '_attach', side_effect=attached))
            stack.enter_context(patch.object(diagnostic.shutil, 'disk_usage', return_value=SimpleNamespace(free=diagnostic.FLOOR)))
            if final_late:
                stack.enter_context(patch.object(diagnostic.time, 'monotonic', side_effect=[0, 0, 181, 181]))
            try:
                measured = diagnostic.run_probe(Path('root'), Call(), Path('profile'), b'fixed',
                    SimpleNamespace(consume=observed), result)
                return measured, events, result, None
            except BaseException as error:
                return None, events, result, error

    def test_durable_original_cid_precedes_inspection_and_start(self):
        measured, events, result, error = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(measured, MEASUREMENT)
        self.assertLess(events.index('durable-attempt'), events.index('create'))
        self.assertLess(events.index('consume'), events.index('create'))
        self.assertLess(events.index('durable-cid'), events.index('inspect'))
        self.assertLess(events.index('durable-cid'), events.index('attach'))
        self.assertEqual(result['cleanup'], 'ORIGINAL_ID_ABSENT_VERIFIED')

    def test_journal_record_failure_blocks_start_retains_guarded_cleanup(self):
        measured, events, result, error = self.exercise(record_failure=True)
        self.assertIsNone(measured)
        self.assertNotIn('inspect', events); self.assertNotIn('attach', events)
        self.assertIn('cleanup', events)
        self.assertEqual(error.code, 'DIAGNOSTIC_CLEANUP_UNCONFIRMED')

    def test_cleanup_finish_and_attach_failures_never_complete(self):
        for option in ('finish_failure', 'cleanup_failure', 'attach_failure', 'malformed', 'stale', 'final_late'):
            with self.subTest(option=option):
                measured, events, result, error = self.exercise(**{option: True})
                self.assertIsNone(measured); self.assertIsNotNone(error)
                self.assertIn('cleanup', events)
                if option == 'stale': self.assertNotIn('create', events)
                if option == 'final_late': self.assertEqual(error.code, 'ATTACH_FINAL_DEADLINE')

    def test_cleanup_refuses_changed_owner_without_removing(self):
        call = MagicMock()
        value = {'Id': CID, 'Image': diagnostic.IMAGE, 'Name': '/wrong', 'Config': {'Labels': {}}}
        with patch.object(diagnostic, 'inspect', return_value=value):
            with self.assertRaises(diagnostic.DiagnosticUnavailable):
                diagnostic.cleanup(call, probe(), CID, True)
        call.assert_not_called()

    def test_fixed_parent_receipt_cannot_be_reused(self):
        with patch.object(Path, 'open', side_effect=FileExistsError):
            with self.assertRaises(FileExistsError): refresh.Receipt(Path('fixed'), {})


class FinalizationTests(unittest.TestCase):
    def execute_fake(self, mode):
        saved = []; times = iter([0, 601 if mode == 'late' else 1, 602 if mode == 'late' else 2])
        api = MagicMock(); api.pin.side_effect = lambda *a, **k: ExitStack()
        pins = SimpleNamespace(enter_context=lambda cm: cm.__enter__(), close=MagicMock())
        if mode == 'pins': pins.close.side_effect = OSError()
        receipt = MagicMock(); receipt.stream.closed = False
        def save(value):
            if mode == 'save' and not saved:
                saved.append({'write_failed': True}); raise OSError()
            saved.append(deepcopy(value))
        receipt.save.side_effect = save
        if mode == 'close': receipt.close.side_effect = [OSError(), None]
        private = SimpleNamespace(pin=lambda *a, **k: ExitStack())
        with ExitStack() as patches:
            patches.enter_context(patch.object(diagnostic.os, 'name', 'nt'))
            patches.enter_context(patch.object(refresh, 'Receipt', return_value=receipt))
            patches.enter_context(patch.object(diagnostic, 'ExitStack', return_value=pins))
            patches.enter_context(patch.object(evidence_tools, 'Windows', return_value=api))
            patches.enter_context(patch.object(live_recovery_drill, 'PrivateDirectory', return_value=private))
            patches.enter_context(patch.object(refresh, 'pin_bytes', return_value=b'profile'))
            patches.enter_context(patch.object(base, 'canonical', return_value=b'profile'))
            tools = patches.enter_context(patch.object(refresh, 'tools', return_value=('docker', None, 'empty', {})))
            patches.enter_context(patch.object(diagnostic, 'exclusive_lock', side_effect=lambda *a: ExitStack()))
            patches.enter_context(patch.object(diagnostic, 'legacy_lock', side_effect=lambda *a: ExitStack()))
            prior = patches.enter_context(patch.object(diagnostic, 'preserved_refusal'))
            if mode == 'prior': prior.side_effect = diagnostic.DiagnosticUnavailable('PRIOR_REFUSAL_CHANGED')
            if mode == 'profile':
                patches.enter_context(patch.object(diagnostic, 'profile_source', side_effect=OSError('not-for-reports')))
            patches.enter_context(patch.object(refresh, 'verified_image', return_value={'image_id': diagnostic.IMAGE,
                'signature_generation': diagnostic.GENERATION}))
            for name in ('original_documents', 'unknown_diagnostics', 'engine'):
                patches.enter_context(patch.object(diagnostic, name))
            patches.enter_context(patch.object(diagnostic, 'observe_original', return_value=object()))
            patches.enter_context(patch.object(runtime, '_require_cgroup_v2'))
            patches.enter_context(patch.object(diagnostic, 'run_probe', return_value=MEASUREMENT))
            patches.enter_context(patch.object(diagnostic.shutil, 'disk_usage', return_value=SimpleNamespace(free=diagnostic.FLOOR)))
            patches.enter_context(patch.object(diagnostic.time, 'monotonic', side_effect=lambda: next(times)))
            try: return diagnostic.execute(), saved, None
            except BaseException as error: return None, saved, error
            finally:
                if mode == 'prior': tools.assert_not_called()

    def test_preserved_refusal_mismatch_stops_before_tools_or_daemon(self):
        result, saved, error = self.execute_fake('prior')
        self.assertIsNone(result); self.assertIsNotNone(error)
        self.assertEqual(saved[-1]['failure_code'], 'PRIOR_REFUSAL_CHANGED')
        self.assertFalse(saved[-1]['completed'])

    def test_profile_failure_has_finite_stage_without_exception_text(self):
        result, saved, error = self.execute_fake('profile')
        self.assertIsNone(result); self.assertIsNotNone(error)
        self.assertEqual(saved[-1]['failed_stage'], 'PROFILE_PIN')
        self.assertEqual(saved[-1]['status'], 'REFUSED')
        self.assertFalse(saved[-1]['completed'])
        self.assertNotIn('not-for-reports', json.dumps(saved[-1]))

    def test_final_pin_close_or_deadline_refuses_measurement(self):
        for mode, expected in (('pins', 'PIN_CLOSE_UNCONFIRMED'), ('late', 'FINAL_DEADLINE')):
            result, saved, error = self.execute_fake(mode)
            with self.subTest(mode=mode):
                self.assertIsNone(result); self.assertIsNotNone(error)
                self.assertEqual(saved[-1]['failure_code'], expected)
                self.assertFalse(saved[-1]['completed'])
                self.assertEqual(saved[-1]['status'], 'REFUSED')
                self.assertNotIn('measurement', saved[-1])

    def test_final_receipt_save_or_close_failure_overrides_measurement(self):
        for mode in ('save', 'close'):
            result, saved, error = self.execute_fake(mode)
            with self.subTest(mode=mode):
                self.assertIsNone(result)
                self.assertEqual(error.code, 'RECEIPT_CLOSE_UNCONFIRMED')
                self.assertEqual(saved[-1]['status'], 'REFUSED')
                self.assertFalse(saved[-1]['completed'])
                self.assertNotIn('measurement', saved[-1])

    def test_success_only_after_all_finalizers_complete(self):
        result, saved, error = self.execute_fake('ok')
        self.assertIsNone(error)
        self.assertEqual(result['status'], 'OBSERVED')
        self.assertTrue(result['completed']); self.assertTrue(result['pins_closed'])
        self.assertEqual(result['measurement'], MEASUREMENT)
        self.assertFalse(result['native_eligible']); self.assertFalse(result['private_input_allowed'])

    def test_existing_parent_receipt_refuses_before_any_daemon_access(self):
        with patch.object(diagnostic.os, 'name', 'nt'), \
             patch.object(refresh, 'Receipt', side_effect=FileExistsError) as reserve, \
             patch.object(refresh, 'tools') as tools, patch.object(refresh, 'verified_image') as verified:
            with self.assertRaises(FileExistsError): diagnostic.execute()
        tools.assert_not_called(); verified.assert_not_called()
        self.assertEqual(reserve.call_args.args[0], diagnostic.ROOT / 'ai/state/private-scanner-postcompile-diagnostic-v2-pcre.json')


if __name__ == '__main__': unittest.main()
