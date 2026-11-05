"""Pure mocked-C-API tests. Never load libclamav/Pillow or execute a kernel call."""
import ctypes as c
import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib

from infra.native import strict_probe as probe


class Options(c.Structure):
    _fields_ = [(name, c.c_uint32) for name in ('general', 'parse', 'heuristic', 'mail', 'dev')]


class Function:
    argtypes = []; restype = c.c_int

    def __init__(self, fn): self.fn = fn
    def __call__(self, *args): return self.fn(*args)


def images():
    png = (b'\x89PNG\r\n\x1a\n' + probe._chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) +
           probe._chunk(b'IDAT', zlib.compress(b'\x00\x01\x02\x03')) + probe._chunk(b'IEND', b''))
    # Synthetic framing for harness control-flow only, not a decoded JPEG.
    jpeg = b'\xff\xd8\xff\xe0\x00\x10JFIF\x00' + b'P'*21 + b'\xff\xda\x00\x02\xff\xd9'
    return png, jpeg


def fake_worker():
    png, jpeg = images(); maps = {}; limits = {0: 33554432, 1: 5242880}; calls = []
    def open_map(ptr, size):
        ident = len(calls)+100
        calls.append(('open', ident)); maps[ident] = c.string_at(ptr, size)
        return ident
    def close_map(ident): calls.append(('close', ident)); maps.pop(ident)
    def strict(ident, filename, name, scanned, engine, opts, context):
        calls.append(('strict', ident))
        data = maps.get(ident); options = opts._obj
        if data is None or not 5 < len(data) <= 5242880 or options.parse != 2048: return 2
        if 16 in limits.values(): return 2
        if probe.EICAR in data: return 1
        return 0 if data in (png, jpeg) else 2
    def upstream(*args):
        calls.append(('upstream', args[0])); return 0
    def set_num(engine, field, value): limits[field] = value; return 0
    def get_num(engine, field, error): error._obj.value = 0; return limits[field]
    lib = SimpleNamespace(cl_fmap_open_memory=Function(open_map), cl_fmap_close=Function(close_map),
                          cl_kapit_scanmap_strict_v1=Function(strict), cl_scanmap_callback=Function(upstream),
                          cl_engine_set_num=Function(set_num), cl_engine_get_num=Function(get_num))
    scanner = SimpleNamespace(engine=123, library=lib, close=Mock(), _check_limits=Mock())
    worker = SimpleNamespace(c=c, ScanOptions=Options, POLICY={'engine': {'0': 33554432, '1': 5242880}},
                             load_configuration=Mock(), _public_images=Mock(return_value=(('image/png', png), ('image/jpeg', jpeg))),
                             NativeScanner=Mock(return_value=scanner), _scratch_empty=Mock())
    return worker, scanner, maps, calls, limits


class StrictProbeTests(unittest.TestCase):
    def test_import_is_inert_without_native_package_or_library_loading(self):
        path = Path(probe.__file__)
        spec = importlib.util.spec_from_file_location('inert_probe', path)
        module = importlib.util.module_from_spec(spec)
        with patch('ctypes.CDLL', side_effect=AssertionError('native load forbidden')), patch.dict(sys.modules, {'kapit_evidence': None}):
            spec.loader.exec_module(module)

    def test_fixed_vectors_crc_framing_and_exact_public_bounds(self):
        png, jpeg = images(); rows = probe._vectors(png, jpeg)
        self.assertEqual(tuple(row[0] for row in rows), probe.CASE_IDS)
        by_id = {row[0]: row for row in rows}
        data = by_id['png_zero_width'][1]
        self.assertEqual(data[16:20], b'\x00'*4)
        self.assertEqual(data[29:33], struct.pack('>I', zlib.crc32(data[12:29])))
        eicar = by_id['eicar_png'][1]
        self.assertEqual(len(probe.EICAR), 68)
        offset = eicar.index(b'tEXt')
        length = struct.unpack('>I', eicar[offset-4:offset])[0]
        self.assertEqual(eicar[offset+4:offset+4+length], b'Comment\x00'+probe.EICAR)
        self.assertEqual(eicar[offset+4+length:offset+8+length], struct.pack('>I', zlib.crc32(eicar[offset:offset+4+length])))
        self.assertEqual(len(by_id['fmap_overlimit'][1]), 5242881)
        self.assertEqual(by_id['engine_max_scan'][3], 'ENGINE_LIMIT')
        for bad_png, bad_jpeg in [(b'x', jpeg), (png[:-1], jpeg), (png, jpeg[:-1]), (png, b'\xff\xd8'+b'P'*40+b'\xff\xd9')]:
            with self.assertRaises(probe.ProbeUnavailable): probe._vectors(bad_png, bad_jpeg)

    def test_all_fixed_cases_direct_c_calls_restore_limits_and_close_every_map(self):
        worker, scanner, maps, calls, limits = fake_worker()
        result = probe._run(worker)
        self.assertTrue(result['completed']); self.assertTrue(result['passed'])
        self.assertFalse(result['native_eligible'])
        self.assertEqual(len(result['cases']), 14)
        self.assertEqual(maps, {})
        self.assertEqual(limits, {0: 33554432, 1: 5242880})
        scanner.close.assert_called_once(); worker._scratch_empty.assert_called_once()
        self.assertEqual(sum(row[0] == 'open' for row in calls), sum(row[0] == 'close' for row in calls))
        for row in result['cases']:
            self.assertEqual(set(row), {'case', 'kind', 'strict', 'upstream', 'passed', 'normalization_observed'})
            if row['kind'] == 'PRECONDITION': self.assertEqual(row['upstream'], 'NOT_RUN')

    def test_missing_configuration_or_initialization_does_not_scan(self):
        for stage in ('load_configuration', 'NativeScanner'):
            worker, scanner, maps, calls, _ = fake_worker()
            getattr(worker, stage).side_effect = RuntimeError('not emitted')
            result = probe._run(worker)
            self.assertFalse(result['passed']); self.assertFalse(result['completed'])
            self.assertEqual(calls, [])
            self.assertNotIn('not emitted', json.dumps(result))

    def test_engine_or_scratch_cleanup_failure_overrides_all_case_passes(self):
        for stage in ('engine', 'scratch'):
            worker, scanner, _, _, _ = fake_worker()
            (scanner.close if stage == 'engine' else worker._scratch_empty).side_effect = RuntimeError('secret diagnostic')
            result = probe._run(worker)
            self.assertFalse(result['passed']); self.assertFalse(result['completed'])
            self.assertNotIn('secret diagnostic', json.dumps(result))
            worker._scratch_empty.assert_called_once()

    def test_unexpected_clean_adverse_or_failed_positive_never_passes(self):
        for force in (0, 2, True):
            worker, scanner, maps, _, _ = fake_worker()
            scanner.library.cl_kapit_scanmap_strict_v1.fn = lambda *args: force
            result = probe._run(worker)
            self.assertFalse(result['passed']); self.assertEqual(maps, {})
            scanner.close.assert_called_once()

    def test_scan_exception_still_closes_map_and_engine(self):
        worker, scanner, maps, _, _ = fake_worker()
        scanner.library.cl_kapit_scanmap_strict_v1.fn = Mock(side_effect=RuntimeError('raw exception'))
        self.assertFalse(probe._run(worker)['passed'])
        self.assertEqual(maps, {}); scanner.close.assert_called_once()

    def test_fmap_open_and_close_failures_are_unavailable(self):
        for name, replacement in [('cl_fmap_open_memory', lambda *args: 0),
                                  ('cl_fmap_close', Mock(side_effect=RuntimeError('no output')))]:
            worker, scanner, _, _, _ = fake_worker()
            getattr(scanner.library, name).fn = replacement
            self.assertFalse(probe._run(worker)['passed'])
            scanner.close.assert_called_once()

    def test_actual_limit_set_and_readback_and_restore_are_required(self):
        for name in ('cl_engine_set_num', 'cl_engine_get_num'):
            worker, scanner, maps, _, _ = fake_worker()
            getattr(scanner.library, name).fn = lambda *args: -1
            result = probe._run(worker)
            self.assertFalse(result['passed']); self.assertFalse(result['completed'])
            self.assertEqual(maps, {})

    def test_final_limit_policy_check_cannot_be_skipped(self):
        worker, scanner, _, _, _ = fake_worker()
        scanner._check_limits.side_effect = RuntimeError('policy drift')
        result = probe._run(worker)
        self.assertFalse(result['passed']); self.assertFalse(result['completed'])

    def test_main_forbids_arguments_without_import_or_stdin(self):
        with patch.object(sys, 'argv', ['probe', '/caller/path']), patch.dict(sys.modules, {'kapit_evidence': None}), patch('sys.stdin', None), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(probe.main(), 2)
            self.assertEqual(output.getvalue(), '')

    def test_main_emits_closed_failure_without_raw_import_error(self):
        with patch.object(sys, 'argv', ['probe']), patch.dict(sys.modules, {'kapit_evidence': None}), patch('sys.stdin', None), patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(probe.main(), 2)
            result = json.loads(output.getvalue())
            self.assertEqual(set(result), {'schema', 'scope', 'completed', 'passed', 'cases', 'native_eligible', 'diagnostic'})
            self.assertFalse(result['passed']); self.assertFalse(result['native_eligible'])

    def test_closed_initialization_diagnostic_and_cleanup_override(self):
        worker, scanner, _, _, _ = fake_worker()
        namespace = {}
        exec(compile("def load_configuration():\n    raise OSError('CANARY_SECRET_PATH_AND_DATA')\n", probe.WORKER_FILE, 'exec'), namespace)
        worker.load_configuration = namespace['load_configuration']
        result = probe._run(worker)
        summary = probe.parse_failure(json.dumps(result).encode())
        self.assertEqual(summary['diagnostic'], {'stage':'CONFIGURATION','kind':'OS_ERROR',
            'location':{'source':'WORKER','function':'load_configuration','line':2}})
        self.assertNotIn('CANARY', json.dumps(result)); self.assertNotIn('cases', summary)
        worker._scratch_empty.side_effect = RuntimeError('SECOND_CANARY')
        result = probe._run(worker)
        self.assertEqual(probe.parse_failure(json.dumps(result).encode())['diagnostic']['stage'], 'SCRATCH_CLEANUP')
        self.assertFalse(result['passed'])

    def test_failure_parser_validates_full_rows_and_never_accepts_success(self):
        worker, scanner, _, _, _ = fake_worker()
        good = probe._run(worker)
        with self.assertRaises(probe.ProbeUnavailable): probe.parse_failure(json.dumps(good).encode())
        bad = copy.deepcopy(good); bad['completed'] = False; bad['passed'] = False
        bad['diagnostic'] = probe._diagnostic(None, 'ENGINE_CLEANUP')
        self.assertEqual(probe.parse_failure(json.dumps(bad).encode())['case_count'], 14)
        changes = [lambda d:d.update(schema=True), lambda d:d.update(passed=0),
                   lambda d:d.update(extra='CANARY'), lambda d:d['cases'][0].update(passed=False),
                   lambda d:d['cases'][0].update(strict='CANARY'), lambda d:d['cases'].reverse(),
                   lambda d:d['diagnostic']['location'].update(line=True),
                   lambda d:d['diagnostic'].update(kind='CANARY'),
                   lambda d:d['diagnostic']['location'].update(function='CANARY')]
        for change in changes:
            value=copy.deepcopy(bad); change(value)
            with self.assertRaises(probe.ProbeUnavailable): probe.parse_failure(json.dumps(value).encode())
        for raw in [b'\xff', b'x'*16385, b'{"schema":1,"schema":1}',
                    json.dumps(bad).encode('utf-16'), json.dumps(bad).encode()+b'{}']:
            with self.assertRaises(probe.ProbeUnavailable): probe.parse_failure(raw)

    def test_traceback_filters_exact_source_and_bounds_context_cycles(self):
        for filename, function, known in [(probe.WORKER_FILE,'_read_regular',True),
                ('/other/evidence_native_worker.py','_read_regular',False),
                ('','_read_regular',False),
                (probe.WORKER_FILE,'UNTRUSTED_CANARY',False)]:
            namespace={}
            exec(compile('def '+function+"():\n    raise ValueError('CANARY')\n", filename, 'exec'),namespace)
            try: namespace[function]()
            except Exception as error:
                error.__context__ = error
                diagnostic=probe._diagnostic(error,'CONFIGURATION')
            self.assertEqual(diagnostic['location']['source'], 'WORKER' if known else 'UNKNOWN')
            self.assertNotIn('CANARY',json.dumps(diagnostic))
        namespace={}
        exec(compile("def _read_regular():\n    raise OSError('CANARY')\ndef load_configuration():\n    try: _read_regular()\n    except Exception: raise RuntimeError() from None\n",probe.WORKER_FILE,'exec'),namespace)
        try: namespace['load_configuration']()
        except Exception as error: diagnostic=probe._diagnostic(error,'CONFIGURATION')
        self.assertEqual(diagnostic['location'],{'source':'WORKER','function':'_read_regular','line':2})


if __name__ == '__main__':
    unittest.main()
