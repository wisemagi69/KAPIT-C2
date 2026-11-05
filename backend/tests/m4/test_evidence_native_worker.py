"""Worker sequencing/FFI-adapter doubles only. No actual native/kernel calls."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from apps.operations import evidence_native_worker as w
from apps.operations import evidence_scan_protocol as p
from apps.operations.evidence_policy import EvidenceError
from tests.m4.test_evidence_scan_protocol import png, binding


def configuration():
    return {'schema': 1, 'policy_sha256': w.POLICY_SHA256,
            'signature_generation': 'c'*64, 'files': {name: 'd'*64 for name in w.FILES}}


class Function:
    def __init__(self, implementation): self.implementation = implementation; self.calls = []
    def __call__(self, *args): self.calls.append(args); return self.implementation(*args)


class FakeLibrary:
    def __init__(self):
        self.fields = {}; self.closed = []; self.code = 0
        implementations = {
            'cl_kapit_strict_abi_v1': lambda: 1, 'cl_init': lambda _: 0,
            'cl_engine_new': lambda: 123, 'cl_engine_set_num': self.set_num,
            'cl_engine_get_num': self.get_num, 'cl_engine_set_str': lambda *_: 0,
            'cl_load': self.load, 'cl_engine_compile': lambda _: 0,
            'cl_engine_free': lambda engine: self.closed.append(engine) or 0,
            'cl_fmap_open_memory': lambda *_: 456, 'cl_fmap_close': lambda _: None,
            'cl_kapit_scanmap_strict_v1': lambda *_: self.code,
            'cl_set_clcb_msg': lambda _: None,
        }
        for name, impl in implementations.items(): setattr(self, name, Function(impl))
    def set_num(self, _, field, value): self.fields[field] = value; return 0
    def get_num(self, _, field, error):
        error._obj.value = 0
        return 4 if field == 26 and self.fields[field] == 1 else self.fields[field]
    def load(self, path, engine, count, options): count._obj.value = 10; return 0


class FakeRuntime:
    def __init__(self, events): self.events = events; self.fail_close = False
    def scan(self, data, media): self.events.append('scan'); return 'SCAN_CLEAN'
    def decode(self, data, media):
        self.events.append('decode'); return SimpleNamespace(data=png(), width=1, height=1)
    def close(self):
        self.events.append('close')
        if self.fail_close: raise RuntimeError('synthetic private diagnostic')


class NativeWorkerTests(unittest.TestCase):
    def setUp(self):
        # The host is Windows; emulate numeric Linux constants only, never OS calls.
        for name, value in {'RTLD_NOW': 2, 'RTLD_LOCAL': 0, 'O_PATH': 0x200000,
                            'O_DIRECTORY': 0x10000, 'O_NOFOLLOW': 0x20000,
                            'O_CLOEXEC': 0x80000}.items():
            handle = patch.object(w.os, name, value, create=True)
            handle.start(); self.addCleanup(handle.stop)

    def test_configuration_closed_bound_and_no_paths_or_pass_flags(self):
        self.assertEqual(w.parse_configuration(json.dumps(configuration()).encode())['policy_sha256'], w.POLICY_SHA256)
        for key, value in [('schema', True), ('policy_sha256', 'a'*64), ('signature_generation', '0'*64),
                           ('files', {}), ('caller_pass', True)]:
            doc = configuration(); doc[key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError): w.parse_configuration(json.dumps(doc).encode())
        for raw in [b'{"schema":1,"schema":1}', b'{"schema":NaN}', b'\xff', b' '*16385]:
            with self.assertRaises(EvidenceError): w.parse_configuration(raw)

    def test_exact_source_fixed_readback_policy_and_hash_preserved(self):
        self.assertEqual(w.POLICY_SHA256, '1e2b71ab05a6905a3c9edfe056cf83ddb4df0170560f1f04a0e7978741358105')
        self.assertEqual(w.POLICY['engine']['26'], 1)
        for field, configured in w.POLICY['engine'].items():
            self.assertEqual(w.expected_engine_readback(int(field), configured), 4 if field == '26' else configured)
        for field in (32, 33): self.assertEqual(w.expected_engine_readback(field, 1), 1)
        for field, value in [(26, 0), (26, 4), (26, True), (True, 1), ('26', 1),
                             (999, 1), (0, 16), (32, 2), (33, '1')]:
            with self.assertRaises(EvidenceError): w.expected_engine_readback(field, value)

    def test_pe_stats_exact_mask_error_and_type_checks_at_init_and_before_scan(self):
        for observed, error_code in [(-1, 3), (0, 0), (1, 0), (5, 0), (8, 0),
                                     (True, 0), ('4', 0), (4.0, 0), (4, 3)]:
            for after_init in (False, True):
                lib = FakeLibrary()
                scanner = self.scanner(lib) if after_init else None
                original = lib.get_num
                def getter(engine, field, error):
                    if field == 26:
                        error._obj.value = error_code
                        return observed
                    return original(engine, field, error)
                lib.cl_engine_get_num.implementation = getter
                with self.assertRaises(EvidenceError):
                    if after_init: scanner.scan(png(), 'image/png')
                    else: self.scanner(lib)
                self.assertEqual(lib.cl_kapit_scanmap_strict_v1.calls, [])
                if scanner is not None: scanner.close()
                self.assertEqual(lib.closed, [123])

    def test_other_numeric_getters_remain_exact_and_typed(self):
        for field in [int(name) for name in w.POLICY['engine'] if name != '26']:
            for replacement in (w.POLICY['engine'][str(field)]+1, True):
                lib=FakeLibrary(); original=lib.get_num
                def getter(engine, queried, error):
                    if queried==field:
                        error._obj.value=0
                        return replacement
                    return original(engine,queried,error)
                lib.cl_engine_get_num.implementation=getter
                with self.assertRaises(EvidenceError):self.scanner(lib)
                self.assertEqual(lib.closed,[123])

    def test_bad_arguments_do_not_load_files_libraries_or_read_stdin(self):
        for argv in [['worker'], ['worker', 'scan', 'bad'], ['worker', 'unknown', 'a'*64]]:
            with patch.object(w.sys, 'argv', argv), patch.object(w, 'load_configuration', side_effect=AssertionError), \
                 patch.object(w.c, 'CDLL', side_effect=AssertionError):
                self.assertEqual(w.main(), 2)

    def test_real_main_order_with_doubles_install_precedes_ready_and_all_reads(self):
        events = []; runtime = FakeRuntime(events); out = io.BytesIO()
        expected = p.Binding('scan', 'a'*64, w.POLICY_SHA256, 'c'*64)
        request = io.BytesIO(); p.write_request(request, expected, png(), 'image/png')
        class GuardedInput(io.BytesIO):
            def read(self, size=-1):
                if 'installed' not in events or 'ready' not in events: raise AssertionError('early input')
                events.append('read'); return super().read(size)
        original_ready = p.write_ready
        def ready(stream, item): events.append('ready'); original_ready(stream, item)
        with patch.object(w.sys, 'argv', ['worker', 'scan', 'a'*64]), \
             patch.object(w.sys, 'stdin', SimpleNamespace(buffer=GuardedInput(request.getvalue()))), \
             patch.object(w.sys, 'stdout', SimpleNamespace(buffer=out)), \
             patch.object(w, 'load_configuration', return_value=configuration()), \
             patch.object(w, '_public_images', return_value=(('image/png', png()),)), \
             patch.object(w, 'NativeScanner', return_value=runtime), \
             patch.object(w, '_scratch_empty', side_effect=lambda: events.append('empty')), \
             patch.object(w.os, 'open', return_value=9), patch.object(w.os, 'close'), \
             patch.object(w, 'install_abi3_confinement', side_effect=lambda _: events.append('installed')), \
             patch.object(p, 'write_ready', side_effect=ready):
            self.assertEqual(w.main(), 0)
        self.assertLess(events.index('installed'), events.index('ready'))
        self.assertLess(events.index('ready'), events.index('read'))
        stream = io.BytesIO(out.getvalue()); p.read_ready(stream, expected)
        self.assertEqual(p.read_result(stream, expected)[0]['code'], 'SCAN_CLEAN')
        self.assertEqual(events.count('close'), 1)

    def test_failed_install_never_emits_ready_or_reads_input(self):
        events = []; runtime = FakeRuntime(events); out = io.BytesIO()
        with patch.object(w.sys, 'argv', ['worker', 'scan', 'a'*64]), \
             patch.object(w.sys, 'stdin', SimpleNamespace(buffer=None)), \
             patch.object(w.sys, 'stdout', SimpleNamespace(buffer=out)), \
             patch.object(w, 'load_configuration', return_value=configuration()), \
             patch.object(w, '_public_images', return_value=()), patch.object(w, 'NativeScanner', return_value=runtime), \
             patch.object(w, '_scratch_empty'), patch.object(w.os, 'open', return_value=9), patch.object(w.os, 'close'), \
             patch.object(w, 'install_abi3_confinement', side_effect=RuntimeError('private text')):
            self.assertEqual(w.main(), 2)
        self.assertEqual(out.getvalue(), b''); self.assertEqual(events, ['close'])

    def test_each_pre_ready_stage_failure_never_touches_stdin_or_emits_any_header(self):
        for stage in ['configuration', 'public_plugins', 'engine_init', 'warmup', 'scratch']:
            with self.subTest(stage=stage):
                out = io.BytesIO(); events = []; runtime = FakeRuntime(events)
                if stage == 'warmup': runtime.scan = lambda *_: 'SCANNER_UNAVAILABLE'
                failure = RuntimeError('synthetic diagnostic must never be reflected')
                with patch.object(w.sys, 'argv', ['worker', 'scan', 'a'*64]), \
                     patch.object(w.sys, 'stdin', SimpleNamespace(buffer=None)), \
                     patch.object(w.sys, 'stdout', SimpleNamespace(buffer=out)), \
                     patch.object(w, 'load_configuration', side_effect=failure if stage == 'configuration' else None, return_value=configuration()), \
                     patch.object(w, '_public_images', side_effect=failure if stage == 'public_plugins' else None, return_value=(('image/png', png()),)), \
                     patch.object(w, 'NativeScanner', side_effect=failure if stage == 'engine_init' else None, return_value=runtime), \
                     patch.object(w, '_scratch_empty', side_effect=failure if stage == 'scratch' else None), \
                     patch.object(w, 'install_abi3_confinement', side_effect=AssertionError('must not install')):
                    self.assertEqual(w.main(), 2)
                self.assertEqual(out.getvalue(), b'')

    def test_image_module_or_native_artifact_hash_mismatch_refuses_configuration(self):
        raw = json.dumps(configuration()).encode()
        for bad_name in ['evidence_native_worker.py', 'clamav', 'daily.cvd']:
            def reader(path, maximum, *, digest_only=False):
                if path == w.CONFIG: return raw
                return 'e'*64 if path == w.FILES[bad_name] else 'd'*64
            with self.subTest(name=bad_name), \
                 patch.object(w, '__file__', str(w.PACKAGE_ROOT/'evidence_native_worker.py')), \
                 patch.object(w, '_read_regular', side_effect=reader), \
                 self.assertRaises(EvidenceError):
                w.load_configuration()

    def test_cleanup_failure_overrides_scan_or_decode_success(self):
        for mode in ['scan', 'decode']:
            events = []; runtime = FakeRuntime(events); runtime.fail_close = True
            request = io.BytesIO(); p.write_request(request, binding(mode), png(), 'image/png')
            out = io.BytesIO()
            with patch.object(w, '_scratch_empty'):
                self.assertEqual(w._serve(io.BytesIO(request.getvalue()), out, binding(mode), runtime), 2)
            header, data = p.read_result(io.BytesIO(out.getvalue()), binding(mode))
            self.assertEqual(header['code'], 'SCANNER_UNAVAILABLE' if mode == 'scan' else 'DECODE_UNAVAILABLE')
            self.assertEqual(data, b''); self.assertNotIn(b'private diagnostic', out.getvalue())

    def test_leftover_scratch_and_bad_request_close_runtime_and_never_clean(self):
        for raw in [b'bad', None]:
            out = io.BytesIO(); runtime = FakeRuntime([])
            if raw is None:
                request = io.BytesIO(); p.write_request(request, binding(), png(), 'image/png'); raw = request.getvalue()
            with patch.object(w, '_scratch_empty', side_effect=EvidenceError('SCRATCH_CLEANUP_REQUIRED')):
                self.assertEqual(w._serve(io.BytesIO(raw), out, binding(), runtime), 2)
            self.assertEqual(p.read_result(io.BytesIO(out.getvalue()), binding())[0]['code'], 'SCANNER_UNAVAILABLE')
            self.assertIn('close', runtime.events)

    def scanner(self, lib):
        # No CDLL/foreign function/kernel call; callback construction also mocked.
        with patch.object(w.c, 'CDLL', return_value=lib), \
             patch.object(w.c, 'CFUNCTYPE', side_effect=lambda *_: lambda fn: fn):
            return w.NativeScanner()

    def test_strict_ffi_only_fixed_options_limits_and_no_fallback(self):
        lib = FakeLibrary(); scanner = self.scanner(lib)
        self.assertEqual(scanner.scan(png(), 'image/png'), 'SCAN_CLEAN')
        args = lib.cl_kapit_scanmap_strict_v1.calls[-1]
        self.assertIsNone(args[1]); self.assertIsNone(args[6])
        self.assertEqual(tuple(getattr(args[5]._obj, key) for key in ('general', 'parse', 'heuristic', 'mail', 'dev')), (4, 2048, 8196, 0, 0))
        self.assertEqual(lib.fields, {int(k): v for k, v in w.POLICY['engine'].items()})
        self.assertEqual(lib.cl_load.calls[0][0], b'/opt/signatures')
        self.assertEqual(lib.cl_load.calls[0][3], 0x300a)
        for code, expected in [(1, 'SCAN_NOT_CLEAN'), (27, 'SCANNER_UNAVAILABLE'), (-1, 'SCANNER_UNAVAILABLE')]:
            lib.code = code; self.assertEqual(scanner.scan(png(), 'image/png'), expected)
        scanner.close(); scanner.close(); self.assertEqual(lib.closed, [123])
        self.assertEqual(len(lib.cl_fmap_close.calls), 4)

    def test_missing_strict_export_or_wrong_abi_refuses_before_engine(self):
        for kind in ['missing', 'wrong']:
            lib = FakeLibrary()
            if kind == 'missing': del lib.cl_kapit_scanmap_strict_v1
            else: lib.cl_kapit_strict_abi_v1.implementation = lambda: 0
            with self.assertRaises((EvidenceError, AttributeError)): self.scanner(lib)
            self.assertEqual(lib.cl_engine_new.calls, [])

    def test_engine_setting_signature_or_compile_failure_frees_exact_engine(self):
        for function in ['cl_engine_set_num', 'cl_load', 'cl_engine_compile']:
            lib = FakeLibrary(); getattr(lib, function).implementation = lambda *_: 5
            with self.assertRaises(EvidenceError): self.scanner(lib)
            self.assertEqual(lib.closed, [123])

    def test_limit_readback_signature_count_and_native_free_uncertainty_refuse(self):
        lib = FakeLibrary(); lib.cl_engine_get_num.implementation = lambda *_: -1
        with self.assertRaises(EvidenceError): self.scanner(lib)
        self.assertEqual(lib.closed, [123])
        lib = FakeLibrary(); lib.cl_load.implementation = lambda *_: 0  # no signatures actually loaded
        with self.assertRaises(EvidenceError): self.scanner(lib)
        self.assertEqual(lib.closed, [123])
        lib = FakeLibrary(); scanner = self.scanner(lib)
        lib.cl_engine_free.implementation = lambda _: 5
        with self.assertRaises(EvidenceError): scanner.close()

    def test_supported_logger_callback_suppresses_synthetic_native_messages(self):
        import contextlib
        lib = FakeLibrary(); scanner = self.scanner(lib)
        callback = lib.cl_set_clcb_msg.calls[0][0]
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            callback(2, b'synthetic native filename', b'synthetic signature name', None)
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
        scanner.close()


if __name__ == '__main__':
    unittest.main()
