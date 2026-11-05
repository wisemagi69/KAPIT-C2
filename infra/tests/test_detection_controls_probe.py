"""Fake C API only. No installed worker, native load or live services."""
from contextlib import redirect_stderr, redirect_stdout
import ctypes as c
import importlib
from io import StringIO
from itertools import product
import json
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch
import weakref

from infra.evidence_detection_controls import parse_detection_controls
from infra.native import detection_controls_probe as probe
from infra.native import strict_probe


def images():
    png = b'\x89PNG\r\n\x1a\n' + strict_probe._chunk(b'IHDR', b'\x00'*13)
    png += strict_probe._chunk(b'IDAT', b'') + strict_probe._chunk(b'IEND', b'')
    jpeg = b'\xff\xd8' + b'P'*20 + b'\xff\xda' + b'P'*10 + b'\xff\xd9'
    return (('image/png', png), ('image/jpeg', jpeg))


class Function:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = []
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


class FakeWorker:
    def __init__(self, codes=(1, 0, 0), fault=None, hook=None):
        self.codes, self.fault, self.hook = codes, fault, hook
        self.events, self.calls, self.buffers, self.maps = [], [], [], {}
        self.opens = self.closes = self.frees = self.scratches = self.options_created = 0
        self.scanner = None
        self.c = SimpleNamespace(**{name: getattr(c, name) for name in (
            'cast', 'c_void_p', 'c_char_p', 'c_ulong', 'byref')})
        self.c.create_string_buffer = self.buffer
        self.ScanOptions = self.options
        self.library = SimpleNamespace(
            cl_fmap_open_memory=Function(self.open_map), cl_fmap_close=Function(self.close_map),
            cl_engine_free=Function(self.free_engine),
            cl_kapit_scanmap_strict_v1=Function(lambda *a: self.scan('strict', *a)),
            cl_scanmap_callback=Function(lambda *a: self.scan('upstream', *a)))
        strict = self.library.cl_kapit_scanmap_strict_v1
        strict.argtypes = [c.c_void_p, c.c_char_p, c.POINTER(c.c_char_p), c.POINTER(c.c_ulong),
                           c.c_void_p, c.c_void_p, c.c_void_p]
        strict.restype = c.c_int

    def stage(self, name):
        self.events.append(name)
        if self.hook:
            self.hook(name, self)
        if self.fault == name:
            raise RuntimeError('PRIVATE_EXCEPTION_CANARY')

    def load_configuration(self):
        self.stage('configuration')

    def _public_images(self):
        self.stage('images')
        return images()

    def NativeScanner(self):
        self.stage('initialize')
        worker = self

        class Scanner:
            def __init__(self):
                self.library = worker.library
                self.engine = 17

            def _check_limits(self):
                worker.stage('limits')

            def close(self):
                worker.stage('engine_close')
                engine, self.engine = self.engine, None
                if self.library.cl_engine_free(engine) != 0:
                    raise RuntimeError('PRIVATE_CLOSE_CANARY')

        self.scanner = Scanner()
        return self.scanner

    def options(self, *values):
        self.stage('options')
        self.options_created += 1

        class Options(c.Structure):
            _fields_ = [(name, c.c_uint32) for name in ('general', 'parse', 'heuristic', 'mail', 'dev')]
        self.option_object = Options(*values)
        return self.option_object

    def buffer(self, data):
        self.stage('buffer')
        self.current_data = data
        result = c.create_string_buffer(data)
        self.buffers.append(weakref.ref(result))
        return result

    def open_map(self, pointer, length):
        self.stage('allocate')
        self.opens += 1
        self.maps[self.opens] = (self.current_data, self.buffers[-1])
        return self.opens

    def scan(self, entry, fmap, filename, name, scanned, engine, options, context):
        self.stage('scan')
        data, buffer = self.maps[fmap]
        if buffer() is None:
            raise AssertionError('Buffer expired during scan')
        self.calls.append((entry, data, engine, options._obj))
        result = self.codes[len(self.calls)-1]
        if isinstance(result, BaseException):
            raise result
        return result

    def close_map(self, fmap):
        self.closes += 1
        if self.maps[fmap][1]() is None:
            raise AssertionError('Buffer expired before map closure')
        self.stage('map_close')

    def free_engine(self, engine):
        self.frees += 1
        self.freed_engine = engine
        self.stage('engine_free')
        return 0

    def _scratch_empty(self):
        self.scratches += 1
        self.stage('scratch')


class DetectionControlProbeTests(unittest.TestCase):
    def invoke_main(self, worker, arguments=None):
        package = ModuleType('kapit_evidence')
        package.evidence_native_worker = worker
        output, errors = StringIO(), StringIO()
        with patch.dict(sys.modules, {'kapit_evidence': package}), \
                patch.object(sys, 'argv', ['fixed'] + (arguments or [])), \
                redirect_stdout(output), redirect_stderr(errors):
            code = probe.main()
        return code, output.getvalue(), errors.getvalue()

    def test_all_27_category_combinations(self):
        for codes in product((0, 1, 2), repeat=3):
            with self.subTest(codes=codes):
                worker = FakeWorker(codes)
                code, output, errors = self.invoke_main(worker)
                self.assertEqual(errors, '')
                if 2 in codes:
                    self.assertEqual((code, output), (2, ''))
                    self.assertEqual(len(worker.calls), codes.index(2)+1)
                else:
                    self.assertEqual(code, 0)
                    value = parse_detection_controls(output.encode(), code)
                    self.assertEqual((value.raw_upstream, value.png_strict, value.png_upstream),
                                     tuple('CLEAN' if n == 0 else 'NOT_CLEAN' for n in codes))
                self.assertEqual(worker.closes, len(worker.calls))
                self.assertEqual((worker.frees, worker.scratches), (1, 1))

    def test_fixed_vectors_match_frozen_source(self):
        worker = FakeWorker()
        probe._run(worker)
        expected = strict_probe._vectors(images()[0][1], images()[1][1])[2][1]
        # Boolean assertions avoid outputting vector bytes or digests on failure.
        self.assertTrue(worker.calls[0][1] == strict_probe.EICAR)
        self.assertEqual(len(worker.calls[0][1]), 68)
        self.assertTrue(worker.calls[1][1] == expected)
        self.assertIs(worker.calls[1][1], worker.calls[2][1])

    def test_one_engine_options_order_abi_and_readbacks(self):
        worker = FakeWorker()
        probe._run(worker)
        self.assertEqual([row[0] for row in worker.calls], ['upstream', 'strict', 'upstream'])
        self.assertEqual([row[2] for row in worker.calls], [17]*3)
        self.assertEqual(worker.options_created, 1)
        self.assertTrue(all(row[3] is worker.option_object for row in worker.calls))
        self.assertEqual(tuple(getattr(worker.option_object, n) for n in probe._FIELDS), (4, 2048, 8196, 0, 0))
        self.assertEqual(worker.events.count('limits'), 6)
        self.assertEqual(worker.library.cl_scanmap_callback.argtypes,
                         worker.library.cl_kapit_scanmap_strict_v1.argtypes)
        self.assertIs(worker.library.cl_scanmap_callback.restype, c.c_int)

    def test_every_stage_exception_refuses_and_attempts_scratch(self):
        for stage in ('configuration', 'images', 'initialize', 'options', 'limits', 'buffer',
                      'allocate', 'scan', 'map_close', 'engine_close', 'engine_free', 'scratch'):
            with self.subTest(stage=stage):
                worker = FakeWorker(fault=stage)
                self.assertEqual(self.invoke_main(worker), (2, '', ''))
                self.assertEqual(worker.scratches, 1)
                self.assertLessEqual(len(worker.calls), 3)
                if stage not in ('configuration', 'images', 'initialize'):
                    self.assertEqual(worker.events.count('engine_close'), 1)

    def test_scan_exceptions_close_map_once_and_stop(self):
        for exception in (RuntimeError('PRIVATE_CANARY'), KeyboardInterrupt(), SystemExit('PRIVATE_CANARY')):
            worker = FakeWorker((exception, 0, 0))
            self.assertEqual(self.invoke_main(worker), (2, '', ''))
            self.assertEqual((worker.opens, worker.closes, len(worker.calls)), (1, 1, 1))

    def test_exact_native_return_types(self):
        for result in (False, True, 0.0, '0', None, c.c_int(0), -1, 256):
            with self.subTest(type=type(result).__name__):
                worker = FakeWorker((result, 0, 0))
                self.assertEqual(self.invoke_main(worker), (2, '', ''))
                self.assertEqual((worker.closes, len(worker.calls)), (1, 1))

    def test_null_map_never_scans_or_closes_unallocated_map(self):
        worker = FakeWorker()
        worker.library.cl_fmap_open_memory.callback = lambda *_: None
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual((len(worker.calls), worker.closes), (0, 0))
        self.assertEqual((worker.frees, worker.scratches), (1, 1))

    def test_map_close_failure_stops_dependent_calls(self):
        worker = FakeWorker(fault='map_close')
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual((len(worker.calls), worker.closes), (1, 1))

    def test_both_finalizers_are_attempted_with_sticky_failure(self):
        worker = FakeWorker(fault='engine_close')
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual(worker.events[-2:], ['engine_close', 'scratch'])
        worker = FakeWorker(fault='scratch')
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual(worker.frees, 1)

    def test_partial_second_and_third_call_failures_no_output(self):
        for codes in ((0, 2, 0), (0, 0, 2)):
            worker = FakeWorker(codes)
            self.assertEqual(self.invoke_main(worker), (2, '', ''))
            self.assertEqual(len(worker.calls), codes.index(2)+1)
            self.assertEqual(worker.closes, len(worker.calls))

    def test_identity_tampering_cleans_original_handles(self):
        for field in ('engine', 'library', 'close'):
            replacement = SimpleNamespace(cl_engine_free=lambda *_: self.fail('Replacement used'))

            def hook(stage, worker):
                if stage == 'scan':
                    setattr(worker.scanner, field, {'engine': 999, 'library': replacement,
                            'close': lambda: self.fail('Replacement close used')}[field])
            worker = FakeWorker(hook=hook)
            result = self.invoke_main(worker)
            # Mutating only close cannot redirect the already-held callback.
            self.assertEqual(result, (0, result[1], '') if field == 'close' else (2, '', ''))
            self.assertEqual(worker.freed_engine, 17)
            self.assertEqual(worker.frees, 1)
            if field != 'close':
                self.assertEqual(len(worker.calls), 1)

    def test_options_tampering_stops_after_call(self):
        def hook(stage, worker):
            if stage == 'scan':
                worker.option_object.parse = 0
        worker = FakeWorker(hook=hook)
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual((len(worker.calls), worker.closes), (1, 1))

    def test_readback_mutation_is_checked_before_input(self):
        def hook(stage, worker):
            if stage == 'limits':
                worker.scanner.engine = 999
        worker = FakeWorker(hook=hook)
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual(len(worker.calls), 0)
        self.assertEqual(worker.freed_engine, 17)

    def test_upstream_abi_tampering_refuses(self):
        def hook(stage, worker):
            if stage == 'scan':
                worker.library.cl_scanmap_callback.restype = c.c_void_p
        worker = FakeWorker(hook=hook)
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual(len(worker.calls), 1)

    def test_image_schema_and_framing_refusal(self):
        for value in (None, [], (), (('image/png', b'bad'), ('image/jpeg', b'bad')),
                      tuple(reversed(images()))):
            with self.subTest(type=type(value).__name__):
                worker = FakeWorker()
                worker._public_images = lambda: value
                self.assertEqual(self.invoke_main(worker), (2, '', ''))
                self.assertIsNone(worker.scanner)

    def test_python_diagnostic_output_discarded(self):
        def hook(stage, worker):
            print('PRIVATE_STDOUT_CANARY')
            print('PRIVATE_STDERR_CANARY', file=sys.stderr)
        worker = FakeWorker(hook=hook)
        code, output, errors = self.invoke_main(worker)
        self.assertEqual((code, errors), (0, ''))
        self.assertNotIn('PRIVATE', output)
        parse_detection_controls(output.encode(), code)

    def test_zero_argument_main_rejects_before_import(self):
        worker = FakeWorker()
        self.assertEqual(self.invoke_main(worker, ['--path=PRIVATE_CANARY']), (2, '', ''))
        self.assertEqual(worker.events, [])

    def test_initial_options_and_engine_types_refuse(self):
        for kind in ('options', 'engine'):
            def hook(stage, worker):
                if kind == 'engine' and stage == 'options':
                    worker.scanner.engine = True
                if kind == 'options' and stage == 'limits':
                    worker.option_object.general = 0
            worker = FakeWorker(hook=hook)
            self.assertEqual(self.invoke_main(worker), (2, '', ''))
            self.assertEqual(len(worker.calls), 0)
            self.assertEqual(worker.freed_engine, 17)

    def test_invalid_cleanup_results_refuse(self):
        worker = FakeWorker()
        worker.library.cl_engine_free.callback = lambda *_: 1
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual(worker.scratches, 1)
        worker = FakeWorker()
        original = worker.close_map
        worker.library.cl_fmap_close.callback = lambda fmap: (original(fmap), 0)[1]
        self.assertEqual(self.invoke_main(worker), (2, '', ''))
        self.assertEqual(worker.closes, 1)
        for stage in ('engine_close', 'scratch', 'limits'):
            with self.subTest(stage=stage):
                worker = FakeWorker()
                if stage == 'scratch':
                    worker._scratch_empty = lambda: False
                else:
                    original_init = worker.NativeScanner

                    def initialize():
                        scanner = original_init()
                        if stage == 'engine_close':
                            original_close = scanner.close
                            scanner.close = lambda: (original_close(), False)[1]
                        else:
                            scanner._check_limits = lambda: False
                        return scanner
                    worker.NativeScanner = initialize
                self.assertEqual(self.invoke_main(worker), (2, '', ''))

    def test_import_exception_is_silent(self):
        original_import = __import__

        def guarded_import(name, *args, **kwargs):
            if name == 'kapit_evidence':
                raise RuntimeError('PRIVATE_IMPORT_CANARY')
            return original_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=guarded_import):
            self.assertEqual(self.invoke_main(FakeWorker()), (2, '', ''))

    def test_output_failure_never_returns_success(self):
        for result in (None, False, 0, 1):
            package = ModuleType('kapit_evidence')
            package.evidence_native_worker = FakeWorker()
            output = SimpleNamespace(write=lambda text: result, flush=lambda: None)
            with patch.dict(sys.modules, {'kapit_evidence': package}), \
                    patch.object(sys, 'argv', ['fixed']), patch.object(sys, 'stdout', output):
                self.assertEqual(probe.main(), 2)
        package.evidence_native_worker = FakeWorker()

        def fail_flush():
            raise RuntimeError('PRIVATE_FLUSH_CANARY')
        output = SimpleNamespace(write=lambda text: len(text), flush=fail_flush)
        with patch.dict(sys.modules, {'kapit_evidence': package}), \
                patch.object(sys, 'argv', ['fixed']), patch.object(sys, 'stdout', output):
            self.assertEqual(probe.main(), 2)

    def test_import_is_inert(self):
        original_import = __import__

        def guarded_import(name, *args, **kwargs):
            if name.startswith(('kapit_evidence', 'PIL')):
                self.fail('Runtime package imported')
            return original_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=guarded_import), \
                patch.object(c, 'CDLL', side_effect=AssertionError('Native load')):
            importlib.reload(probe)

    def test_no_stdin_read_or_early_output(self):
        worker = FakeWorker()
        with patch.object(sys, 'stdin', SimpleNamespace(read=lambda: self.fail('stdin read'))):
            code, output, _ = self.invoke_main(worker)
        self.assertEqual(code, 0)
        self.assertTrue(output.endswith('\n'))
        self.assertEqual(worker.events[-1], 'scratch')
        self.assertEqual(set(json.loads(output)), {'schema_version', 'scope', 'controls', 'completed'})


if __name__ == '__main__':
    unittest.main()
