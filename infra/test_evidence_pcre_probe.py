"""Fake-FFI ownership/control-flow tests; no native library or child is loaded."""
import contextlib
import copy
import ctypes as c
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import zlib

from infra.native import pcre_probe as probe
from backend.apps.operations.evidence_policy import inspect_container
from backend.apps.operations.evidence_native_worker import expected_engine_readback


class Function:
    def __init__(self, fn):
        self.fn = fn
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        if self.argtypes is None:
            raise AssertionError('FFI function called without signature')
        return self.fn(*args)


class Fake:
    def __init__(self):
        self.events = []
        self.engines = {}
        self.codes = {}
        self.contexts = {}
        self.data = set()
        self.maps = {}
        self.sequence = 100
        self.raw_codes = []
        self.override_scan = None
        self.provider_bytes = b'P'*probe.PROVIDER_BYTES
        self.lib = SimpleNamespace()
        def add(name, fn): setattr(self.lib, name, Function(fn))
        add('cl_kapit_strict_abi_v1', lambda: 1)
        add('cl_init', lambda options: 0)
        add('cl_set_clcb_msg', lambda callback: None)
        add('dladdr', self.dladdr)
        add('cl_engine_new', self.new_engine)
        add('cl_engine_free', self.free_engine)
        add('cl_engine_set_num', self.set_num)
        add('cl_engine_get_num', self.get_num)
        add('cl_engine_set_str', lambda *args: 0)
        add('cl_load', self.load)
        add('cl_engine_compile', self.compile_engine)
        add('cl_fmap_open_memory', self.open_map)
        add('cl_fmap_close', self.close_map)
        add('cl_scanmap_callback', lambda *args: self.scan(False, *args))
        add('cl_kapit_scanmap_strict_v1', lambda *args: self.scan(True, *args))
        add('pcre2_compile_8', self.compile_pattern)
        add('pcre2_code_free_8', lambda pointer: self.codes.pop(pointer))
        add('pcre2_match_context_create_8', self.new_context)
        add('pcre2_match_context_free_8', lambda pointer: self.contexts.pop(pointer))
        add('pcre2_set_match_limit_8', lambda pointer, value: self.set_context(pointer, 32, value))
        add('pcre2_set_depth_limit_8', lambda pointer, value: self.set_context(pointer, 33, value))
        add('pcre2_match_data_create_from_pattern_8', self.new_data)
        add('pcre2_match_data_free_8', lambda pointer: self.data.remove(pointer))
        add('pcre2_match_8', self.match)
        add('pcre2_pattern_info_8', self.pattern_info)
        add('pcre2_config_8', self.config)
        self.provider = SimpleNamespace(**{name: value for name, value in vars(self.lib).items() if name.startswith('pcre2_')})
        self.worker = SimpleNamespace(LIBRARY=probe.LIBRARY, load_configuration=Mock(),
            _read_regular=Mock(return_value=self.provider_bytes), _scratch_empty=Mock(),
            inspect_container=inspect_container,
            expected_engine_readback=expected_engine_readback,
            POLICY={'engine': {'0': 33554432, '1': 5242880, '2': 4, '3': 32, '14': 0,
                              '15': 1, '17': 2, '23': 0, '25': 1, '26': 1, '31': 60000,
                              '32': 100000, '33': 1000, '34': 5242880}})

    def ident(self):
        self.sequence += 1
        return self.sequence

    def dladdr(self, address, info):
        info._obj.dli_fname = probe.PROVIDER.encode('ascii')
        return 1

    def config(self, field, buffer):
        assert field == probe.PCRE2_CONFIG_VERSION
        buffer.value = probe.PROVIDER_VERSION
        return len(probe.PROVIDER_VERSION)+1

    def new_engine(self):
        pointer = self.ident()
        self.engines[pointer] = {'limits': {}, 'compiled': False}
        self.events.append(('new', pointer))
        return pointer

    def free_engine(self, pointer):
        self.events.append(('free', pointer))
        self.engines.pop(pointer)
        return 0

    def set_num(self, pointer, field, value):
        assert not self.engines[pointer]['compiled']
        self.events.append(('set', pointer, field, value))
        self.engines[pointer]['limits'][field] = value
        return 0

    def get_num(self, pointer, field, error):
        error._obj.value = 0
        value = self.engines[pointer]['limits'][field]
        return 4 if field == 26 and value == 1 else value

    def signature(self, library, pointer, raw):
        self.events.append(('load', pointer, raw))
        suffix = raw.split(b';')[-1]
        self.engines[pointer]['offset'] = int(suffix.split(b':')[0])
        self.engines[pointer]['pattern'] = suffix.split(b'/', 2)[1]

    def load(self, path, pointer, count, options):
        self.events.append(('real_load', pointer))
        count._obj.value = 1
        assert options == 0
        return 0

    def compile_engine(self, pointer):
        assert 'pattern' in self.engines[pointer]
        self.events.append(('compile', pointer))
        self.engines[pointer]['compiled'] = True
        return 0

    def compile_pattern(self, pattern, length, options, error, offset, context):
        assert options == 0 and context is None
        pointer = self.ident()
        self.codes[pointer] = c.string_at(pattern, length)
        return pointer

    def new_context(self, context):
        assert context is None
        pointer = self.ident()
        self.contexts[pointer] = {}
        return pointer

    def set_context(self, pointer, field, value):
        self.contexts[pointer][field] = value
        return 0

    def new_data(self, code, context):
        assert code in self.codes and context is None
        pointer = self.ident()
        self.data.add(pointer)
        return pointer

    def pattern_info(self, code, field, result):
        assert code in self.codes and field == probe.PCRE2_INFO_JITSIZE
        result._obj.value = 0
        return 0

    @staticmethod
    def raw(pattern, subject, limits):
        # Deliberate fake oracle for API wiring, never native proof.
        if limits[32] == 1: return probe.PCRE2_ERROR_MATCHLIMIT
        if limits[33] == 1: return probe.PCRE2_ERROR_DEPTHLIMIT
        if pattern == probe.N: return probe.PCRE2_ERROR_NOMATCH
        return probe.PCRE2_ERROR_NOMATCH if subject.startswith(b'a'*12+b'c') else 2

    def match(self, code, subject, length, start, options, data, context):
        assert start == 0 and options == probe.PCRE2_ANCHORED and data in self.data
        actual = c.string_at(subject, length)
        self.events.append(('direct', actual, self.codes[code], dict(self.contexts[context])))
        return self.raw_codes.pop(0) if self.raw_codes else self.raw(self.codes[code], actual, self.contexts[context])

    def open_map(self, pointer, size):
        ident = self.ident()
        self.maps[ident] = c.string_at(pointer, size)
        return ident

    def close_map(self, pointer):
        self.maps.pop(pointer)

    def scan(self, strict, fmap, filename, name, scanned, engine, options, context):
        record = self.engines[engine]
        assert record['compiled'] and filename is None and context is None
        assert tuple(getattr(options._obj, key) for key, _ in probe.Options._fields_) == (4, 2048, 8196, 0, 0)
        self.events.append(('scan', engine, strict))
        if self.override_scan is not None: return self.override_scan
        value = self.raw(record['pattern'], self.maps[fmap][record['offset']:], record['limits'])
        if value in (probe.PCRE2_ERROR_MATCHLIMIT, probe.PCRE2_ERROR_DEPTHLIMIT):
            return probe.CL_ERROR if strict else 0
        return 1 if value > 0 else 0

    @contextlib.contextmanager
    def installed(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(probe.os, 'RTLD_NOW', 2, create=True))
            stack.enter_context(patch.object(probe.os, 'RTLD_LOCAL', 0, create=True))
            stack.enter_context(patch.object(probe, 'PROVIDER_SHA256', hashlib.sha256(self.provider_bytes).hexdigest()))
            stack.enter_context(patch.object(probe.c, 'CDLL', side_effect=lambda path, **kwargs: self.lib if path == probe.LIBRARY else self.provider))
            stack.enter_context(patch.object(probe.c, 'CFUNCTYPE', return_value=lambda callback=None: callback))
            stack.enter_context(patch.object(probe, '_address', side_effect=id))
            stack.enter_context(patch.object(probe.os, 'lstat', return_value=SimpleNamespace(
                st_dev=1, st_ino=2, st_mode=0o120777, st_uid=0, st_gid=0, st_nlink=1,
                st_size=len(probe.PROVIDER_LINK), st_mtime_ns=3, st_ctime_ns=4)))
            stack.enter_context(patch.object(probe.os, 'readlink', return_value=probe.PROVIDER_LINK))
            stack.enter_context(patch.object(probe, '_load_signature', side_effect=self.signature))
            yield


class PcreProbeTests(unittest.TestCase):
    def test_import_inert_and_main_rejects_arguments_before_import_or_input(self):
        spec = importlib.util.spec_from_file_location('inert_pcre_probe', probe.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch('ctypes.CDLL', side_effect=AssertionError('native forbidden')):
            spec.loader.exec_module(module)
        with patch.object(sys, 'argv', ['probe', 'input']), patch.dict(sys.modules, {'kapit_evidence': None}), patch('sys.stdin', None):
            self.assertEqual(probe.main(), 2)

    def test_png_crc_framing_subject_offset_signature_trigger_are_real(self):
        for row in probe._cases():
            data, offset = probe._image(row[2])
            inspect_container(data, 'image/png')
            position = 8
            while position < len(data):
                length = struct.unpack('>I', data[position:position+4])[0]
                contents = data[position+4:position+8+length]
                self.assertEqual(struct.unpack('>I', data[position+8+length:position+12+length])[0], zlib.crc32(contents))
                position += length+12
            self.assertEqual(position, len(data))
            self.assertEqual(data[offset:offset+len(row[2])], row[2])
            signature = probe._signature(row[1], offset)
            self.assertTrue(signature.startswith(b'Kapit.PcreProbe;Engine:81-255,Target:0;0&1;0:89504e470d0a1a0a;'))
            self.assertIn(str(offset).encode()+b':0/'+row[1]+b'/\n', signature)

    def test_full_fixed_matrix_two_orders_fresh_engines_and_owned_lifetimes(self):
        fake = Fake()
        with fake.installed(): result = probe._run(fake.worker)
        self.assertTrue(result['passed']); self.assertTrue(result['harness_cleanup'])
        self.assertFalse(result['native_eligible'])
        self.assertEqual(tuple(row['case'] for row in result['cases']), probe.CASE_IDS)
        self.assertEqual(len([event for event in fake.events if event[0] == 'new']), 16)
        for pointer in [event[1] for event in fake.events if event[0] == 'new']:
            events = [event for event in fake.events if len(event) > 1 and event[1] == pointer]
            self.assertEqual([event[0] for event in events][-1], 'free')
            kinds = [event[0] for event in events]
            self.assertLess(kinds.index('set'), kinds.index('load'))
            self.assertLess(kinds.index('load'), kinds.index('compile'))
            self.assertLess(kinds.index('compile'), kinds.index('scan'))
        scans = [event[2] for event in fake.events if event[0] == 'scan']
        self.assertEqual(scans, [False, True, True, False]*8)
        self.assertEqual((fake.engines, fake.codes, fake.contexts, fake.data, fake.maps), ({}, {}, {}, set(), {}))
        for row in result['cases']:
            self.assertEqual(row['orders_completed'], 2)
            self.assertEqual(set(row), {'case','direct','upstream','strict','orders_completed','passed','normalization_observed'})

    def test_direct_call_receives_entire_root_tail_and_exact_limits(self):
        fake = Fake()
        with fake.installed(): probe._run(fake.worker)
        events = [event for event in fake.events if event[0] == 'direct']
        self.assertEqual(len(events), 16)
        for index, row in enumerate(probe._cases()):
            data, offset = probe._image(row[2])
            for event in events[index*2:index*2+2]:
                self.assertEqual(event[1:], (data[offset:], row[1], {32: row[3], 33: row[4]}))

    def test_full_ctypes_signatures_and_exact_generic_error(self):
        self.assertEqual(probe.CL_ERROR, 34)
        fake = Fake()
        with fake.installed(): bindings = probe.Bindings(fake.worker)
        self.assertEqual(bindings.lib.cl_engine_set_num.argtypes, [c.c_void_p, c.c_int, c.c_longlong])
        self.assertEqual(bindings.lib.pcre2_match_8.argtypes,
                         [c.c_void_p,c.c_void_p,c.c_size_t,c.c_size_t,c.c_uint32,c.c_void_p,c.c_void_p])
        self.assertIs(bindings.lib.pcre2_compile_8.restype, c.c_void_p)
        fake.worker._read_regular.assert_called_once_with(Path(probe.PROVIDER_REGULAR), probe.PROVIDER_BYTES)

    def test_shared_exact_pe_stats_readback_rejects_old_getter_and_other_masks(self):
        fake=Fake()
        self.assertIs(fake.worker.expected_engine_readback, expected_engine_readback)
        with fake.installed(): result=probe._run(fake.worker)
        self.assertTrue(result['passed'])
        self.assertTrue(all(event[3]==1 for event in fake.events if event[0]=='set' and event[2]==26))
        for value,error_code in [(-1,3),(0,0),(1,0),(5,0),(8,0),(True,0),('4',0),(4.0,0),(4,3)]:
            fake=Fake(); original=fake.get_num
            def getter(pointer,field,error):
                if field==26:
                    error._obj.value=error_code
                    return value
                return original(pointer,field,error)
            fake.lib.cl_engine_get_num.fn=getter
            with fake.installed(): result=probe._run(fake.worker)
            self.assertFalse(result['passed']); self.assertEqual(result['failure_stage'],'ENGINE')
            self.assertEqual(fake.engines,{})
            self.assertFalse(any(event[0] in ('load','scan','direct') for event in fake.events))

    def test_other_fields_cannot_use_mask_or_type_normalization(self):
        for field in (0,23,25,32,33):
            for value in (True,4.0,'4',5):
                fake=Fake(); original=fake.get_num
                def getter(pointer,queried,error):
                    if queried==field:
                        error._obj.value=0
                        return value
                    return original(pointer,queried,error)
                fake.lib.cl_engine_get_num.fn=getter
                with fake.installed(): result=probe._run(fake.worker)
                self.assertFalse(result['passed']); self.assertEqual(fake.engines,{})

    def test_exact_symlink_kind_literal_and_identity_are_mandatory(self):
        fake = Fake()
        for target in ('/lib/x86_64-linux-gnu/'+probe.PROVIDER_LINK, '../'+probe.PROVIDER_LINK,
                       'libpcre2-8.so.0.11.3', '', b'libpcre2-8.so.0.11.2'):
            with fake.installed(), patch.object(probe.os, 'readlink', return_value=target):
                with self.assertRaises(probe.ProbeUnavailable): probe.Bindings(fake.worker)
        for mode in (0o100644, 0o040755):
            info = SimpleNamespace(st_mode=mode, st_size=len(probe.PROVIDER_LINK))
            with fake.installed(), patch.object(probe.os, 'lstat', return_value=info):
                with self.assertRaises(probe.ProbeUnavailable): probe.Bindings(fake.worker)
        old = SimpleNamespace(st_dev=1, st_ino=2, st_mode=0o120777, st_uid=0, st_gid=0, st_nlink=1,
                              st_size=len(probe.PROVIDER_LINK), st_mtime_ns=3, st_ctime_ns=4)
        changed = copy.copy(old); changed.st_ino = 9
        for sequence in ([old, changed], [old, old, changed, changed]):
            with fake.installed(), patch.object(probe.os, 'lstat', side_effect=sequence):
                with self.assertRaises(probe.ProbeUnavailable): probe.Bindings(fake.worker)
        with fake.installed(), patch.object(probe.os, 'readlink', side_effect=[probe.PROVIDER_LINK, 'other']):
            with self.assertRaises(probe.ProbeUnavailable): probe.Bindings(fake.worker)
        fake.worker._read_regular.side_effect = OSError('no-follow regular target refused')
        with fake.installed(): result = probe._run(fake.worker)
        self.assertFalse(result['passed']); self.assertEqual(fake.engines, {})

    def test_actual_exported_header_hash_version_date_and_constants_match(self):
        raw = (Path(__file__).resolve().parents[1]/'ai/state/private-scanner-pcre2-header.source.h').read_bytes()
        self.assertEqual(len(raw), 47257)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), 'c684acf79df1d782309e2fccb05e41ea25d7a059d8a1e7d61226b73dcc23e12f')
        text = raw.decode('ascii')
        for name in ('PCRE2_ANCHORED','PCRE2_ERROR_NOMATCH','PCRE2_ERROR_MATCHLIMIT',
                     'PCRE2_ERROR_DEPTHLIMIT','PCRE2_INFO_JITSIZE','PCRE2_CONFIG_VERSION'):
            match = re.search(r'^#define\s+'+name+r'\s+\(?(-?(?:0x[0-9a-fA-F]+|[0-9]+))u?\)?(?:\s|$)', text, re.M)
            self.assertIsNotNone(match)
            self.assertEqual(getattr(probe, name), int(match.group(1), 0))
        for name, value in [('PCRE2_MAJOR','10'), ('PCRE2_MINOR','42'),
                            ('PCRE2_DATE','2022-12-11'), ('PCRE2_CONFIG_JIT','1')]:
            self.assertRegex(text, r'(?m)^#define\s+'+name+r'\s+'+re.escape(value)+r'\s*$')
        self.assertEqual(probe.PROVIDER_VERSION, b'10.42 2022-12-11')

    def test_provider_bytes_path_version_address_and_abi_fail_closed(self):
        alterations = [lambda f: setattr(f.worker._read_regular, 'return_value', b'x'),
                       lambda f: setattr(f.worker._read_regular, 'return_value', b'Q'*probe.PROVIDER_BYTES),
                       lambda f: setattr(f.lib.dladdr, 'fn', lambda address, info: 0),
                       lambda f: setattr(f.lib.dladdr, 'fn', lambda address, info: setattr(info._obj, 'dli_fname', b'/other') or 1),
                       lambda f: setattr(f.provider, 'pcre2_match_8', Function(lambda *args: -1)),
                       lambda f: setattr(f.lib.pcre2_config_8, 'fn', lambda field, buf: setattr(buf, 'value', b'other') or 6),
                       lambda f: setattr(f.lib.cl_kapit_strict_abi_v1, 'fn', lambda: True)]
        for change in alterations:
            fake = Fake(); change(fake)
            with fake.installed(): result = probe._run(fake.worker)
            self.assertFalse(result['passed']); self.assertEqual(fake.engines, {})
            self.assertEqual(result['failure_stage'], 'PROVIDER')

    def test_wrong_raw_zero_unknown_and_normalization_never_pass(self):
        for value in (0, -1, -999, True):
            fake = Fake(); fake.raw_codes = [value]*16
            with fake.installed(): result = probe._run(fake.worker)
            self.assertFalse(result['passed'])
            self.assertEqual((fake.codes, fake.contexts, fake.data), ({}, {}, set()))
        for value in (0, 1, 19, True):
            fake = Fake(); fake.override_scan = value
            with fake.installed(): result = probe._run(fake.worker)
            self.assertFalse(result['passed']); self.assertEqual(fake.maps, {})

    def test_every_direct_allocation_and_failure_frees_earlier_resources(self):
        for name in ('pcre2_compile_8','pcre2_match_context_create_8','pcre2_match_data_create_from_pattern_8'):
            fake = Fake(); getattr(fake.lib, name).fn = lambda *args: None
            with fake.installed(): result = probe._run(fake.worker)
            self.assertFalse(result['passed'])
            self.assertEqual((fake.engines, fake.codes, fake.contexts, fake.data), ({}, {}, {}, set()))
        fake = Fake(); fake.lib.pcre2_match_8.fn = Mock(side_effect=RuntimeError('not emitted'))
        with fake.installed(): result = probe._run(fake.worker)
        self.assertFalse(result['passed']); self.assertNotIn('not emitted', json.dumps(result))
        self.assertEqual((fake.engines, fake.codes, fake.contexts, fake.data), ({}, {}, {}, set()))

    def test_limit_readback_compile_load_and_scan_failures_close_engine(self):
        for name in ('cl_engine_set_num','cl_engine_get_num','cl_engine_compile','cl_fmap_open_memory'):
            fake = Fake(); getattr(fake.lib, name).fn = lambda *args: 0 if name == 'cl_fmap_open_memory' else -1
            with fake.installed(): result = probe._run(fake.worker)
            self.assertFalse(result['passed']); self.assertEqual(fake.engines, {})
        fake = Fake()
        with fake.installed(), patch.object(probe, '_load_signature', side_effect=RuntimeError('private')):
            result = probe._run(fake.worker)
        self.assertFalse(result['passed']); self.assertEqual(fake.engines, {})

    def test_each_cleanup_failure_dominates_and_remaining_cleanup_attempted(self):
        for name in ('pcre2_match_data_free_8','pcre2_match_context_free_8','pcre2_code_free_8',
                     'cl_fmap_close','cl_engine_free'):
            fake = Fake(); original = getattr(fake.lib, name).fn
            def failing(*args):
                original(*args)
                raise RuntimeError('cleanup contents never printed')
            getattr(fake.lib, name).fn = failing
            with fake.installed(): result = probe._run(fake.worker)
            self.assertFalse(result['passed']); self.assertFalse(result['harness_cleanup'])
            self.assertEqual(result['failure_stage'], 'CLEANUP')
            self.assertEqual((fake.engines, fake.codes, fake.contexts, fake.data, fake.maps), ({}, {}, {}, set(), {}))
        fake = Fake(); fake.worker._scratch_empty.side_effect = [None, RuntimeError('leftovers')]
        with fake.installed(): result = probe._run(fake.worker)
        self.assertFalse(result['passed']); self.assertFalse(result['harness_cleanup'])

    def test_only_exclusive_owned_signature_is_removed_and_load_failure_still_unlinks(self):
        fake = Fake(); fake.lib.cl_load.argtypes = []
        for failed in (False, True):
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(probe.os, 'O_NOFOLLOW', 0x20000, create=True))
                stack.enter_context(patch.object(probe.os, 'O_CLOEXEC', 0x80000, create=True))
                opened = stack.enter_context(patch.object(probe.os, 'open', return_value=77))
                stack.enter_context(patch.object(probe.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600,st_uid=123)))
                stack.enter_context(patch.object(probe.os, 'getuid', return_value=123, create=True))
                stack.enter_context(patch.object(probe.os, 'write', side_effect=lambda fd, raw: min(3,len(raw))))
                closed = stack.enter_context(patch.object(probe.os, 'close'))
                unlinked = stack.enter_context(patch.object(probe.os, 'unlink'))
                fake.lib.cl_load.fn = (lambda *args: -1) if failed else fake.load
                if failed:
                    with self.assertRaises(probe.ProbeUnavailable): probe._load_signature(fake.lib, 1, b'synthetic')
                else: probe._load_signature(fake.lib, 1, b'synthetic')
                self.assertTrue(opened.call_args.args[1] & probe.os.O_EXCL)
                closed.assert_called_once_with(77); unlinked.assert_called_once_with(probe.SIGNATURE)
        with patch.object(probe.os, 'O_NOFOLLOW', 0, create=True), patch.object(probe.os, 'O_CLOEXEC', 0, create=True), \
             patch.object(probe.os, 'open', side_effect=FileExistsError()), patch.object(probe.os, 'unlink') as unlinked:
            with self.assertRaises(FileExistsError): probe._load_signature(fake.lib, 1, b'synthetic')
            unlinked.assert_not_called()

    def test_main_closed_import_failure_contains_no_raw_diagnostics(self):
        with patch.object(sys, 'argv', ['probe']), patch.dict(sys.modules, {'kapit_evidence': None}), \
             patch('sys.stdout', new_callable=io.StringIO) as output, patch('sys.stdin', None):
            self.assertEqual(probe.main(), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(set(result), {'schema','scope','completed','passed','cases','harness_cleanup','failure_stage','native_eligible','diagnostic'})
        self.assertFalse(result['native_eligible']); self.assertEqual(result['cases'], [])

    def test_callback_unregister_and_postcompile_readback_failures_dominate(self):
        fake = Fake()
        def callback(value):
            if value is None:
                raise RuntimeError('not logged')
        fake.lib.cl_set_clcb_msg.fn = callback
        with fake.installed(): result = probe._run(fake.worker)
        self.assertFalse(result['passed']); self.assertFalse(result['harness_cleanup'])
        self.assertEqual(result['failure_stage'], 'CLEANUP'); self.assertEqual(fake.engines, {})
        fake = Fake()
        original = fake.lib.cl_engine_compile.fn
        def compile_changed(pointer):
            original(pointer)
            fake.engines[pointer]['limits'][32] += 1
            return 0
        fake.lib.cl_engine_compile.fn = compile_changed
        with fake.installed(): result = probe._run(fake.worker)
        self.assertFalse(result['passed']); self.assertEqual(fake.engines, {})

    def test_signature_close_or_unlink_failures_remain_cleanup_errors(self):
        fake = Fake(); fake.lib.cl_load.argtypes = []
        for name in ('close', 'unlink'):
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(probe.os, 'O_NOFOLLOW', 0, create=True))
                stack.enter_context(patch.object(probe.os, 'O_CLOEXEC', 0, create=True))
                stack.enter_context(patch.object(probe.os, 'open', return_value=77))
                stack.enter_context(patch.object(probe.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600,st_uid=123)))
                stack.enter_context(patch.object(probe.os, 'getuid', return_value=123, create=True))
                stack.enter_context(patch.object(probe.os, 'write', side_effect=lambda fd, raw: len(raw)))
                closed = stack.enter_context(patch.object(probe.os, 'close'))
                unlinked = stack.enter_context(patch.object(probe.os, 'unlink'))
                (closed if name == 'close' else unlinked).side_effect = RuntimeError('private')
                with self.assertRaises(probe.CleanupUnavailable): probe._load_signature(fake.lib, 1, b'synthetic')
                closed.assert_called_once_with(77); unlinked.assert_called_once_with(probe.SIGNATURE)

    def test_strict_public_parser_recomputes_every_case_and_rejects_type_shape_tampering(self):
        fake = Fake()
        with fake.installed(): good = probe._run(fake.worker)
        encode = lambda value: json.dumps(value, separators=(',', ':')).encode('ascii')
        self.assertEqual(probe.parse_success(encode(good)), good)
        changes = [lambda d: d.update(schema=True), lambda d: d.update(completed=1),
                   lambda d: d.update(native_eligible=0), lambda d: d.update(harness_cleanup=False),
                   lambda d: d.update(failure_stage='RESULT'), lambda d: d.update(extra=True),
                   lambda d: d['cases'].pop(), lambda d: d['cases'].reverse(),
                   lambda d: d['cases'][0].update(orders_completed=True),
                   lambda d: d['cases'][0].update(orders_completed=2.0),
                   lambda d: d['cases'][0].update(direct='NOMATCH'),
                   lambda d: d['cases'][0].update(strict='OTHER_ERROR'),
                   lambda d: d['cases'][0].update(normalization_observed=1),
                   lambda d: d['cases'][0].update(normalization_observed=False),
                   lambda d: d['cases'][0].update(passed=1),
                   lambda d: d['cases'][0].update(caller_safe=True)]
        for change in changes:
            altered = copy.deepcopy(good); change(altered)
            with self.assertRaises(probe.ProbeUnavailable): probe.parse_success(encode(altered))
        for raw in [encode(good)+b'{}', b'\xff', encode(good).decode().encode('utf-16'), b'x'*8193,
                    b'{"schema":1,"schema":1}', b'{"schema":NaN}', bytearray(encode(good))]:
            with self.assertRaises(probe.ProbeUnavailable): probe.parse_success(raw)

    def test_failure_parser_keeps_only_closed_diagnostic_and_count(self):
        fake=Fake(); namespace={}
        exec(compile("def load_configuration():\n    raise OSError('CANARY_PRIVATE')\n",probe.WORKER_FILE,'exec'),namespace)
        fake.worker.load_configuration=namespace['load_configuration']
        with fake.installed(): value=probe._run(fake.worker)
        summary=probe.parse_failure(json.dumps(value).encode())
        self.assertEqual(summary['diagnostic'],{'stage':'PROVIDER','kind':'OS_ERROR',
            'location':{'source':'WORKER','function':'load_configuration','line':2}})
        self.assertEqual(summary['case_count'],0); self.assertNotIn('cases',summary)
        self.assertNotIn('CANARY',json.dumps(value)); self.assertFalse(summary['passed'])
        with self.assertRaises(probe.ProbeUnavailable): probe.parse_success(json.dumps(value).encode())
        fake.worker._scratch_empty.side_effect=[None,RuntimeError('SECOND_CANARY')]
        with fake.installed(): result=probe._run(fake.worker)
        self.assertEqual(probe.parse_failure(json.dumps(result).encode())['diagnostic']['stage'],'CLEANUP')

    def test_failure_parser_recomputes_every_partial_row_and_types(self):
        fake=Fake()
        with fake.installed(): good=probe._run(fake.worker)
        with self.assertRaises(probe.ProbeUnavailable): probe.parse_failure(json.dumps(good).encode())
        bad=copy.deepcopy(good); bad.update(completed=False,passed=False,failure_stage='DIRECT')
        bad['cases']=bad['cases'][:1]; bad['diagnostic']=probe._diagnostic(None,'DIRECT')
        self.assertEqual(probe.parse_failure(json.dumps(bad).encode())['case_count'],1)
        changes=[lambda d:d.update(schema=True),lambda d:d.update(passed=0),
                 lambda d:d.update(extra='CANARY'),lambda d:d.update(failure_stage='SCANNER'),
                 lambda d:d['cases'][0].update(orders_completed=True),
                 lambda d:d['cases'][0].update(passed=False),
                 lambda d:d['cases'][0].update(direct='CANARY'),
                 lambda d:d['cases'][0].update(case='depth_limit'),
                 lambda d:d['diagnostic']['location'].update(line=True),
                 lambda d:d['diagnostic']['location'].update(source='WORKER',function='CANARY',line=1),
                 lambda d:d['diagnostic'].update(kind='CANARY')]
        for change in changes:
            value=copy.deepcopy(bad);change(value)
            with self.assertRaises(probe.ProbeUnavailable):probe.parse_failure(json.dumps(value).encode())
        for raw in [b'\xff',b'x'*16385,b'{"schema":1,"schema":1}',
                    json.dumps(bad).encode('utf-16'),json.dumps(bad).encode()+b'{}']:
            with self.assertRaises(probe.ProbeUnavailable):probe.parse_failure(raw)

    def test_diagnostic_trusts_exact_qualnames_and_bounds_context_cycles(self):
        for filename,function,known in [(probe.WORKER_FILE,'_read_regular',True),
            ('/other/evidence_native_worker.py','_read_regular',False),
            ('','_read_regular',False),
            (probe.WORKER_FILE,'CANARY_FUNCTION',False)]:
            namespace={}
            exec(compile('def '+function+"():\n    raise ValueError('CANARY_VALUE')\n",filename,'exec'),namespace)
            try:namespace[function]()
            except Exception as error:
                error.__context__=error
                value=probe._diagnostic(error,'PROVIDER')
            self.assertEqual(value['location']['source'],'WORKER' if known else 'UNKNOWN')
            self.assertNotIn('CANARY',json.dumps(value))
        namespace={}
        exec(compile("def _read_regular():\n    raise OSError('CANARY')\n",probe.WORKER_FILE,'exec'),namespace)
        try:namespace['_read_regular']()
        except Exception as error: cause=error
        for _ in range(4):
            wrapper=RuntimeError('CANARY');wrapper.__cause__=cause;cause=wrapper
        self.assertEqual(probe._diagnostic(cause,'PROVIDER')['location']['source'],'UNKNOWN')


if __name__ == '__main__':
    unittest.main()
