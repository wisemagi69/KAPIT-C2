"""Pure continuation checks. Every host and runtime boundary is replaced."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from infra import evidence_postcompile_continuation as continuation
from infra import evidence_postcompile_diagnostic as diagnostic
from infra import evidence_native_refresh_runtime as refresh


MEASUREMENT = {'schema': 1, 'scope': 'PUBLIC_POSTCOMPILE_READBACK_ONLY',
    'completed': True, 'observation': 'FIRST_MISMATCH', 'field': '17',
    'category': 'AUTO', 'native_eligible': False, 'private_input_allowed': False}


class SourceTests(unittest.TestCase):
    def test_import_is_inert(self):
        with patch.object(os, 'open') as opened, patch.object(Path, 'open') as path_open, \
             patch.object(subprocess, 'Popen') as popen, \
             patch.object(refresh, 'Receipt') as receipt:
            importlib.reload(continuation)
        opened.assert_not_called(); path_open.assert_not_called()
        popen.assert_not_called(); receipt.assert_not_called()

    def test_frozen_source_and_program_are_unchanged(self):
        self.assertEqual(hashlib.sha256((continuation.ROOT / continuation.PREFLIGHT).read_bytes()).hexdigest(),
                         continuation.PREFLIGHT_SHA256)
        self.assertEqual(hashlib.sha256((continuation.ROOT / continuation.FROZEN_CONTROLLER).read_bytes()).hexdigest(),
                         continuation.FROZEN_CONTROLLER_SHA256)
        self.assertEqual(hashlib.sha256((continuation.ROOT / diagnostic.PROGRAM).read_bytes()).hexdigest(),
                         diagnostic.PROGRAM_SHA256)

    def test_fixed_no_override_api_and_receipt(self):
        self.assertEqual(continuation.RECEIPT,
            'ai/state/private-scanner-continuation-diagnostic-pcre.json')
        for kwargs in ({'image_id': 'wrong'}, {'receipt': 'other'}, {'resume': True}):
            with self.assertRaises(TypeError):
                continuation.execute(**kwargs)

    def test_provenance_pins_exact_sources_and_bounded_fixed_receipt(self):
        preflight = SimpleNamespace(PREFLIGHT_RECEIPT='fixed-preflight', validate_receipt=MagicMock())
        ctx = SimpleNamespace(pins=object(), api=object())
        with patch.object(continuation, 'modules', return_value=(preflight, diagnostic, refresh)), \
             patch.object(continuation, 'PREFLIGHT_SHA256', 'a' * 64), \
             patch.object(refresh, 'pin_bytes', return_value=b'{}') as pin:
            continuation.provenance(ctx)
        self.assertEqual(pin.call_args_list[0].kwargs, {'expected': 'a' * 64})
        self.assertEqual(pin.call_args_list[0].args[3], continuation.PREFLIGHT)
        self.assertEqual(pin.call_args_list[1].kwargs,
                         {'expected': continuation.FROZEN_CONTROLLER_SHA256})
        self.assertEqual(pin.call_args_list[2].args[3], 'fixed-preflight')
        self.assertEqual(pin.call_args_list[2].kwargs, {'maximum': 8192})
        preflight.validate_receipt.assert_called_once_with({}, 'a' * 64)

    def test_unreviewed_source_stops_before_receipt_or_live_checks(self):
        with patch.object(continuation, 'modules', return_value=(object(), diagnostic, refresh)), \
             patch.object(continuation, 'PREFLIGHT_SHA256', None), \
             patch.object(refresh, 'pin_bytes') as pin:
            with self.assertRaises(diagnostic.DiagnosticUnavailable):
                continuation.provenance(SimpleNamespace(pins=object(), api=object()))
        pin.assert_not_called()

    def test_changed_source_or_malformed_receipt_never_validates(self):
        preflight = SimpleNamespace(PREFLIGHT_RECEIPT='fixed', validate_receipt=MagicMock())
        ctx = SimpleNamespace(pins=object(), api=object())
        for effects in ([OSError('private canary')],
                        [b'fixed-source', b'fixed-controller', b'{"schema":1,"schema":1}']):
            with self.subTest(effects=len(effects)), \
                 patch.object(continuation, 'modules', return_value=(preflight, diagnostic, refresh)), \
                 patch.object(continuation, 'PREFLIGHT_SHA256', 'a' * 64), \
                 patch.object(refresh, 'pin_bytes', side_effect=effects):
                with self.assertRaises(Exception): continuation.provenance(ctx)
        preflight.validate_receipt.assert_not_called()


class LifecycleTests(unittest.TestCase):
    def exercise(self, mode='ok'):
        events = []; saved = []
        ctx = SimpleNamespace(api=object(), pins=object(), raw=b'fixed',
                              call=SimpleNamespace(uncertain=False))
        receipt = MagicMock(); receipt.stream.closed = False
        def save(value):
            if mode == 'save' and not saved:
                saved.append({'write_failed': True})
                raise OSError('private canary')
            saved.append(deepcopy(value))
        receipt.save.side_effect = save
        if mode == 'close': receipt.close.side_effect = [OSError('private canary'), None]
        @contextmanager
        def checked(mark):
            events.append('inputs-enter'); mark('ROOT_PINS')
            if mode == 'inputs': raise OSError('private canary')
            try:
                yield ctx
            finally:
                events.append('inputs-close')
                if mode == 'pins': raise OSError('private canary')
        @contextmanager
        def locked(path, api):
            events.append('lock-enter')
            self.assertEqual(path, continuation.ROOT / diagnostic.STAGE / 'postcompile-diagnostic.lock')
            self.assertIs(api, ctx.api)
            if mode == 'lock': raise OSError('private canary')
            try: yield
            finally:
                events.append('lock-close')
                if mode == 'unlock': raise OSError('private canary')
        observation = object()
        def verify(context, mark):
            self.assertIs(context, ctx); events.append('live'); mark('FRESH_IMAGE')
            if mode == 'live': raise OSError('private canary')
            return observation
        def provenance(context):
            events.append('provenance')
            if mode == 'provenance': raise OSError('private canary')
        def run(root, call, profile, raw, observed, result):
            self.assertIs(call, ctx.call); self.assertIs(observed, observation)
            self.assertEqual(profile, continuation.ROOT / diagnostic.PROFILE)
            self.assertEqual(raw, b'fixed'); events.append('probe')
            if mode == 'probe': raise OSError('private canary')
            if mode == 'uncertain': ctx.call.uncertain = True
            result.update(original_id='b' * 64, reservation='a' * 32,
                          cleanup='ORIGINAL_ID_ABSENT_VERIFIED')
            return MEASUREMENT
        def engine(call):
            events.append('engine')
            if mode == 'engine': raise OSError('private canary')
        preflight = SimpleNamespace(checked_inputs=checked, verify_live=verify,
                                   SUCCESS_STAGES=('ROOT_PINS', 'FRESH_IMAGE'))
        elapsed = 601 if mode == 'late' else 1
        with patch.object(continuation.os, 'name', 'nt'), \
             patch.object(continuation, 'modules', return_value=(preflight, diagnostic, refresh)), \
             patch.object(refresh, 'Receipt', return_value=receipt), \
             patch.object(continuation, 'provenance', side_effect=provenance), \
             patch.object(continuation, 'atomic_private_lock', side_effect=locked), \
             patch.object(diagnostic, 'run_probe', side_effect=run), \
             patch.object(diagnostic, 'engine', side_effect=engine), \
             patch.object(continuation.shutil, 'disk_usage', return_value=SimpleNamespace(
                 free=0 if mode == 'disk' else diagnostic.FLOOR)), \
             patch.object(continuation.time, 'monotonic', side_effect=[0, elapsed]):
            try: return continuation.execute(), saved, events, None
            except BaseException as error: return None, saved, events, error

    def test_repeat_live_checks_under_both_locks_before_probe(self):
        result, saved, events, error = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(events, ['inputs-enter', 'provenance', 'lock-enter', 'live',
            'probe', 'engine', 'lock-close', 'inputs-close'])
        self.assertEqual(result['status'], 'OBSERVED'); self.assertTrue(result['completed'])
        self.assertTrue(result['pins_closed']); self.assertTrue(result['cli_cleanup_confirmed'])
        self.assertEqual(result['measurement'], MEASUREMENT)
        self.assertFalse(result['native_eligible']); self.assertFalse(result['private_input_allowed'])
        self.assertFalse(result['control_state_modified'])

    def test_missing_provenance_cannot_be_saved_clearance(self):
        result, saved, events, error = self.exercise('provenance')
        self.assertIsNotNone(error); self.assertIsNone(result)
        self.assertNotIn('live', events); self.assertNotIn('probe', events)
        self.assertEqual(saved[-1]['failed_stage'], 'PREFLIGHT_PROVENANCE')

    def test_input_lock_and_live_failure_do_not_create(self):
        for mode in ('inputs', 'lock', 'live'):
            with self.subTest(mode=mode):
                result, saved, events, error = self.exercise(mode)
                self.assertIsNotNone(error); self.assertIsNone(result)
                self.assertNotIn('probe', events)
                self.assertFalse(saved[-1]['completed'])

    def test_failed_probe_still_rechecks_engine_and_preserves_failure(self):
        result, saved, events, error = self.exercise('probe')
        self.assertIsNotNone(error); self.assertIn('engine', events)
        self.assertEqual(saved[-1]['failed_stage'], 'PUBLIC_PROBE')
        self.assertNotIn('PUBLIC_PROBE', saved[-1]['completed_stages'])
        self.assertNotIn('measurement', saved[-1])

    def test_final_engine_limits_unlock_and_pin_close_dominate_measurement(self):
        for mode in ('engine', 'uncertain', 'disk', 'unlock', 'pins', 'late'):
            with self.subTest(mode=mode):
                result, saved, events, error = self.exercise(mode)
                self.assertIsNotNone(error); self.assertIsNone(result)
                self.assertEqual(saved[-1]['status'], 'REFUSED')
                self.assertFalse(saved[-1]['completed'])
                self.assertNotIn('measurement', saved[-1])
                self.assertNotIn('private canary', json.dumps(saved[-1]))

    def test_final_receipt_failure_never_returns_or_prints_success(self):
        for mode in ('save', 'close'):
            with self.subTest(mode=mode):
                result, saved, events, error = self.exercise(mode)
                self.assertIsNone(result)
                self.assertEqual(error.code, 'RECEIPT_CLOSE_UNCONFIRMED')
                self.assertFalse(saved[-1]['completed'])
                self.assertNotIn('measurement', saved[-1])

    def test_existing_fixed_receipt_refuses_before_inputs(self):
        preflight = SimpleNamespace(checked_inputs=MagicMock())
        with patch.object(continuation.os, 'name', 'nt'), \
             patch.object(continuation, 'modules', return_value=(preflight, diagnostic, refresh)), \
             patch.object(refresh, 'Receipt', side_effect=FileExistsError):
            with self.assertRaises(FileExistsError): continuation.execute()
        preflight.checked_inputs.assert_not_called()


class AtomicLockTests(unittest.TestCase):
    def exercise(self, mode='new'):
        events = []; attrs = []; descriptor_text = []
        class Stream(io.BytesIO):
            def fileno(self): return 7
            def write(self, value):
                if mode == 'write': raise OSError()
                if mode == 'short-write': return 0
                return super().write(value)
            def read(self, size=-1):
                if mode == 'byte': return b'1'
                return super().read(size)
            def close(self):
                events.append('stream-close')
                super().close()
                if mode == 'stream-close': raise OSError()
        stream = Stream(b'0' if mode.startswith('existing') else b'')
        api = SimpleNamespace(user='S-1-5-21-123', a=SimpleNamespace(), k=SimpleNamespace(),
                              pin=MagicMock(), protect=MagicMock())
        def convert(text, revision, pointer, unused):
            descriptor_text.append(text)
            if mode == 'convert': return 0
            pointer._obj.value = 123
            return 1
        def create(*args):
            events.append('create'); attrs.append(args)
            security = args[3]._obj
            self.assertFalse(security.bInheritHandle)
            self.assertEqual(security.lpSecurityDescriptor, 123)
            return continuation.c.c_void_p(-1).value if mode.startswith('existing') or mode == 'create-denied' else 42
        def verify(handle):
            events.append('acl'); self.assertEqual(handle, 42)
            if mode == 'acl': raise OSError()
        def localfree(descriptor):
            events.append('descriptor-free')
            return 1 if mode == 'free' else None
        def closehandle(handle):
            events.append('handle-close'); self.assertEqual(handle, 42)
            return False if mode == 'handle-close' else True
        def transfer(handle, flags):
            events.append('transfer'); self.assertEqual(handle, 42)
            if mode in ('transfer', 'handle-close'): raise OSError()
            return 7
        @contextmanager
        def pinned(path, **kwargs):
            events.append('existing-pin')
            self.assertEqual(kwargs, {'private': True, 'writable': True})
            if mode == 'existing-invalid': raise OSError()
            yield stream
        api.a.ConvertStringSecurityDescriptorToSecurityDescriptorW = convert
        api.k.CreateFileW, api.k.LocalFree, api.k.CloseHandle = create, localfree, closehandle
        api.verify_acl = verify; api.pin.side_effect = pinned
        crt = SimpleNamespace(open_osfhandle=transfer, LK_NBLCK=1, LK_UNLCK=2)
        def locking(fd, kind, length):
            events.append('lock' if kind == 1 else 'unlock')
            if mode == ('lock' if kind == 1 else 'unlock'): raise OSError()
        crt.locking = locking
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1,
                               st_dev=1, st_ino=2, st_size=1, st_mtime_ns=3)
        if mode == 'link': info.st_nlink = 2
        if mode == 'size': info.st_size = 2
        if mode == 'nonregular': info.st_mode = stat.S_IFDIR | 0o700
        path_info = deepcopy(info)
        if mode == 'identity': path_info.st_ino += 1
        def fsync(fd):
            events.append('fsync')
            if mode == 'fsync': raise OSError()
        def fdopen(fd, *args, **kwargs):
            if mode == 'fdopen': raise OSError()
            return stream
        def checked(path):
            if mode == 'reparse': raise OSError()
            return path
        from infra import evidence_tools
        with patch.object(evidence_tools, 'checked', side_effect=checked), \
             patch.object(continuation, 'lock_runtime', return_value=crt), \
             patch.object(continuation.c, 'get_last_error', return_value=5 if mode == 'create-denied' else 183,
                          create=True), \
             patch.object(continuation.os, 'fdopen', side_effect=fdopen), \
             patch.object(continuation.os, 'close') as close_fd, \
             patch.object(continuation.os, 'fstat', return_value=info), \
             patch.object(Path, 'stat', return_value=path_info), \
             patch.object(continuation.os, 'fsync', side_effect=fsync):
            try:
                with continuation.atomic_private_lock(Path('fixed'), api) as created:
                    self.assertIs(created, not mode.startswith('existing'))
                    events.append('body')
                error = None
            except BaseException as caught: error = caught
        api.protect.assert_not_called()
        if mode == 'fdopen': close_fd.assert_called_once_with(7)
        return events, attrs, descriptor_text, error

    def test_new_lock_atomic_acl_original_handle_and_retained_lock(self):
        events, calls, descriptors, error = self.exercise()
        self.assertIsNone(error)
        self.assertEqual(descriptors, ['O:S-1-5-21-123D:P(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-21-123)'])
        self.assertEqual(calls[0][1:3], (0x20000 | 0x80000000 | 0x40000000, 3))
        self.assertEqual(calls[0][4:], (1, 0x00200000, None))
        self.assertEqual(events, ['create', 'acl', 'descriptor-free', 'transfer', 'fsync',
                                 'lock', 'body', 'unlock', 'stream-close'])

    def test_existing_lock_is_only_private_pinned_and_never_written(self):
        events, calls, descriptors, error = self.exercise('existing')
        self.assertIsNone(error)
        self.assertEqual(events, ['create', 'descriptor-free', 'existing-pin', 'lock', 'body', 'unlock'])
        self.assertNotIn('acl', events); self.assertNotIn('fsync', events)

    def test_creation_and_security_failures_prevent_body_and_close_owned_handles(self):
        for mode in ('convert', 'create-denied', 'acl', 'free', 'transfer', 'handle-close',
                     'fdopen', 'write', 'short-write', 'fsync', 'link', 'size', 'nonregular',
                     'identity', 'byte', 'reparse', 'lock', 'existing-invalid'):
            with self.subTest(mode=mode):
                events, calls, descriptors, error = self.exercise(mode)
                self.assertIsNotNone(error); self.assertNotIn('body', events)
                if mode in ('acl', 'free', 'transfer', 'handle-close'):
                    self.assertIn('handle-close', events)
                if mode in ('write', 'short-write', 'fsync', 'link', 'size', 'nonregular',
                            'identity', 'byte', 'lock'):
                    self.assertIn('stream-close', events)

    def test_unlock_and_stream_close_failures_propagate_after_body(self):
        for mode in ('unlock', 'stream-close'):
            with self.subTest(mode=mode):
                events, calls, descriptors, error = self.exercise(mode)
                self.assertIn('body', events); self.assertIsNotNone(error)
                self.assertIn('stream-close', events)


if __name__ == '__main__':
    unittest.main()
