"""Fixed PUBLIC PCRE regression harness. Import performs no native/file access.

Direct PCRE results are independent provider evidence, not scanner telemetry.
Synthetic test engines never authenticate production signatures or eligibility.
"""
from __future__ import annotations

import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zlib

LIBRARY = '/opt/clamav/lib/libclamav.so.12.0.3'
PROVIDER = '/lib/x86_64-linux-gnu/libpcre2-8.so.0'
PROVIDER_LINK = 'libpcre2-8.so.0.11.2'
PROVIDER_REGULAR = '/lib/x86_64-linux-gnu/libpcre2-8.so.0.11.2'
PROVIDER_BYTES = 629384
PROVIDER_SHA256 = '19c626251526131ac9340826c8f7bcb693c6ceb9d5da55919c3aa45d972b704f'
SIGNATURE = '/scratch/pcre-probe.ldb'
# Matched actual Debian compiler header SHA256 c684acf79df1d782309e2fccb05e41ea25d7a059d8a1e7d61226b73dcc23e12f.
PCRE2_ANCHORED = 0x80000000
PCRE2_ERROR_NOMATCH = -1
PCRE2_ERROR_MATCHLIMIT = -47
PCRE2_ERROR_DEPTHLIMIT = -53
PCRE2_INFO_JITSIZE = 10
PCRE2_CONFIG_VERSION = 11
PROVIDER_VERSION = b'10.42 2022-12-11'
CL_ERROR = 34  # Exact pinned ClamAV 1.4.6 cl_error_t enum, not a generic error.
M = b'(*NO_START_OPT)(*NO_AUTO_POSSESS)(a+)+b'
D = b'(*NO_START_OPT)(*NO_AUTO_POSSESS)(a(?1)?b)'
N = b'(*NO_START_OPT)z'
CASE_IDS = ('match_limit', 'depth_limit', 'match_nomatch', 'depth_nomatch',
            'match_positive', 'depth_positive', 'ordinary_nomatch', 'restored_control')
SCOPE = 'PUBLIC_PCRE_NATIVE_REGRESSION_ONLY'


class ProbeUnavailable(Exception):
    def __str__(self):
        return 'PUBLIC_PCRE_PROBE_UNAVAILABLE'


class CleanupUnavailable(ProbeUnavailable):
    pass


HARNESS_FILES = frozenset(name for name in ('<fixed-public-pcre>', globals().get('__file__', '')) if name)
HARNESS_FUNCTIONS = frozenset(('Bindings.__init__', 'Bindings.close', 'Engine.__init__', 'Engine.readback', 'Engine.close', '_provider_link', '_load_signature', '_direct', '_scan', '_release', '_run', 'main'))
DIAGNOSTIC_STAGES = frozenset(('WORKER_IMPORT', 'PROVIDER', 'ENGINE', 'DIRECT', 'SCANNER', 'RESULT', 'CLEANUP'))

WORKER_FILE = '/usr/local/lib/python3.14/site-packages/kapit_evidence/evidence_native_worker.py'
WORKER_FUNCTIONS = frozenset(('load_configuration', 'parse_configuration', '_read_regular',
    '_public_images', 'NativeScanner.__init__', 'NativeScanner._check_limits',
    'NativeScanner.close', '_scratch_empty'))
DIAGNOSTIC_KINDS = frozenset(('IMPORT_ERROR', 'OS_ERROR', 'TYPE_ERROR', 'MISSING_ATTRIBUTE',
                             'VALUE_ERROR', 'REFUSED', 'OTHER_ERROR'))


def _diagnostic(error, stage):
    kind = 'REFUSED' if error is None or isinstance(error, ProbeUnavailable) else 'OTHER_ERROR'
    for cls, value in ((ImportError, 'IMPORT_ERROR'), (OSError, 'OS_ERROR'),
                       (TypeError, 'TYPE_ERROR'), (AttributeError, 'MISSING_ATTRIBUTE'),
                       (ValueError, 'VALUE_ERROR')):
        if isinstance(error, cls):
            kind = value
            break
    location = {'source': 'UNKNOWN', 'function': 'UNKNOWN', 'line': 0}
    seen = set()
    for _ in range(4):
        if not isinstance(error, BaseException) or id(error) in seen:
            break
        seen.add(id(error))
        frame = error.__traceback__
        for _ in range(32):
            if frame is None:
                break
            code = frame.tb_frame.f_code
            source = None
            if code.co_filename == WORKER_FILE and code.co_qualname in WORKER_FUNCTIONS:
                source = 'WORKER'
            elif code.co_filename in HARNESS_FILES and code.co_qualname in HARNESS_FUNCTIONS:
                source = 'HARNESS'
            if source and type(frame.tb_lineno) is int and 1 <= frame.tb_lineno <= 2048:
                location = {'source': source, 'function': code.co_qualname, 'line': frame.tb_lineno}
            frame = frame.tb_next
        error = error.__cause__ if error.__cause__ is not None else error.__context__
    return {'stage': stage, 'kind': kind, 'location': location}


def _validate_diagnostic(value):
    if type(value) is not dict or set(value) != {'stage', 'kind', 'location'}:
        raise ProbeUnavailable()
    if value['stage'] not in DIAGNOSTIC_STAGES or value['kind'] not in DIAGNOSTIC_KINDS:
        raise ProbeUnavailable()
    location = value['location']
    if type(location) is not dict or set(location) != {'source', 'function', 'line'}:
        raise ProbeUnavailable()
    source, function, line = location['source'], location['function'], location['line']
    if type(line) is not int:
        raise ProbeUnavailable()
    if source == 'UNKNOWN':
        if function != 'UNKNOWN' or line != 0:
            raise ProbeUnavailable()
    elif not (source in ('WORKER', 'HARNESS') and 1 <= line <= 2048 and
              function in (WORKER_FUNCTIONS if source == 'WORKER' else HARNESS_FUNCTIONS)):
        raise ProbeUnavailable()
    return value


def _failure_document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProbeUnavailable()
            result[key] = value
        return result
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
            raise ProbeUnavailable()
        return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ProbeUnavailable()))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ProbeUnavailable() from None



def _require(value):
    if not value:
        raise ProbeUnavailable()


def _zero(value):
    _require(type(value) is int and value == 0)


def _release(actions):
    failed = False
    for function, args, checked in actions:
        try:
            result = function(*args)
            if checked:
                _zero(result)
        except BaseException:
            failed = True
    if failed:
        raise CleanupUnavailable()


class Options(c.Structure):
    _fields_ = [(name, c.c_uint32) for name in ('general', 'parse', 'heuristic', 'mail', 'dev')]


class DlInfo(c.Structure):
    _fields_ = [('dli_fname', c.c_char_p), ('dli_fbase', c.c_void_p),
                ('dli_sname', c.c_char_p), ('dli_saddr', c.c_void_p)]


def _address(function):
    return c.cast(function, c.c_void_p).value


def _declare(library, definitions):
    for name, (arguments, result) in definitions.items():
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = result


def _provider_link():
    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    before = os.lstat(PROVIDER)
    _require(stat.S_ISLNK(before.st_mode) and before.st_size == len(PROVIDER_LINK))
    _require(os.readlink(PROVIDER) == PROVIDER_LINK)
    _require(identity(before) == identity(os.lstat(PROVIDER)))
    return identity(before)


class Bindings:
    def __init__(self, worker):
        # The installed worker verifies the actual immutable library/config pins.
        _require(str(worker.LIBRARY) == LIBRARY)
        worker.load_configuration()
        link = _provider_link()
        raw = worker._read_regular(Path(PROVIDER_REGULAR), PROVIDER_BYTES)
        _require(type(raw) is bytes and len(raw) == PROVIDER_BYTES and
                 hashlib.sha256(raw).hexdigest() == PROVIDER_SHA256)
        self.lib = c.CDLL(LIBRARY, mode=os.RTLD_NOW | os.RTLD_LOCAL)
        self.provider = c.CDLL(PROVIDER, mode=os.RTLD_NOW | os.RTLD_LOCAL)
        _declare(self.lib, {
            'cl_kapit_strict_abi_v1': ([], c.c_uint),
            'cl_init': ([c.c_uint], c.c_int), 'cl_engine_new': ([], c.c_void_p),
            'cl_engine_set_num': ([c.c_void_p, c.c_int, c.c_longlong], c.c_int),
            'cl_engine_get_num': ([c.c_void_p, c.c_int, c.POINTER(c.c_int)], c.c_longlong),
            'cl_engine_set_str': ([c.c_void_p, c.c_int, c.c_char_p], c.c_int),
            'cl_load': ([c.c_char_p, c.c_void_p, c.POINTER(c.c_uint), c.c_uint], c.c_int),
            'cl_engine_compile': ([c.c_void_p], c.c_int),
            'cl_engine_free': ([c.c_void_p], c.c_int),
            'cl_fmap_open_memory': ([c.c_void_p, c.c_size_t], c.c_void_p),
            'cl_fmap_close': ([c.c_void_p], None),
            'dladdr': ([c.c_void_p, c.POINTER(DlInfo)], c.c_int),
        })
        scan = ([c.c_void_p, c.c_char_p, c.POINTER(c.c_char_p), c.POINTER(c.c_ulong),
                 c.c_void_p, c.POINTER(Options), c.c_void_p], c.c_int)
        _declare(self.lib, {'cl_scanmap_callback': scan, 'cl_kapit_scanmap_strict_v1': scan})
        definitions = {
            'pcre2_compile_8': ([c.c_void_p, c.c_size_t, c.c_uint32, c.POINTER(c.c_int),
                                  c.POINTER(c.c_size_t), c.c_void_p], c.c_void_p),
            'pcre2_code_free_8': ([c.c_void_p], None),
            'pcre2_match_context_create_8': ([c.c_void_p], c.c_void_p),
            'pcre2_match_context_free_8': ([c.c_void_p], None),
            'pcre2_set_match_limit_8': ([c.c_void_p, c.c_uint32], c.c_int),
            'pcre2_set_depth_limit_8': ([c.c_void_p, c.c_uint32], c.c_int),
            'pcre2_match_data_create_from_pattern_8': ([c.c_void_p, c.c_void_p], c.c_void_p),
            'pcre2_match_data_free_8': ([c.c_void_p], None),
            'pcre2_match_8': ([c.c_void_p, c.c_void_p, c.c_size_t, c.c_size_t, c.c_uint32,
                                c.c_void_p, c.c_void_p], c.c_int),
            'pcre2_pattern_info_8': ([c.c_void_p, c.c_uint32, c.c_void_p], c.c_int),
            'pcre2_config_8': ([c.c_uint32, c.c_void_p], c.c_int),
        }
        _declare(self.lib, definitions)
        _declare(self.provider, definitions)
        for name in definitions:
            function = getattr(self.lib, name)
            address = _address(function)
            _require(address and address == _address(getattr(self.provider, name)))
            info = DlInfo()
            observed = self.lib.dladdr(c.c_void_p(address), c.byref(info))
            _require(type(observed) is int and observed != 0 and info.dli_fname == PROVIDER.encode('ascii'))
        version = c.create_string_buffer(64)
        count = self.lib.pcre2_config_8(PCRE2_CONFIG_VERSION, version)
        _require(type(count) is int and 0 < count <= 64 and version.value == PROVIDER_VERSION)
        abi = self.lib.cl_kapit_strict_abi_v1()
        _require(type(abi) is int and abi == 1)
        _require(_provider_link() == link)
        self.logger_type = c.CFUNCTYPE(None, c.c_int, c.c_char_p, c.c_char_p, c.c_void_p)
        self.logger = self.logger_type(lambda *_: None)
        _declare(self.lib, {'cl_set_clcb_msg': ([self.logger_type], None)})
        try:
            self.lib.cl_set_clcb_msg(self.logger)
            _zero(self.lib.cl_init(0))
        except BaseException:
            self.close()
            raise

    def close(self):
        # Release the global C callback before its Python owner disappears.
        if self.logger is not None:
            _release([(self.lib.cl_set_clcb_msg, (self.logger_type(),), False)])
            self.logger = None


def _chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind+data))


def _image(subject):
    base = (b'\x89PNG\r\n\x1a\n' + _chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) +
            _chunk(b'IDAT', zlib.compress(b'\0\1\2\3')) + _chunk(b'IEND', b''))
    keyword = b'KAPITPCRE\0'
    offset = len(base)-12+8+len(keyword)
    data = base[:-12] + _chunk(b'tEXt', keyword+subject) + base[-12:]
    _require(len(data) < 4096 and data[offset:offset+len(subject)] == subject)
    return data, offset


def _cases():
    miss = b'a'*12+b'c'
    return (
        ('match_limit', M, miss, 1, 1000, 'MATCHLIMIT', 'CLEAN', 'ERROR'),
        ('depth_limit', D, miss, 100000, 1, 'DEPTHLIMIT', 'CLEAN', 'ERROR'),
        ('match_nomatch', M, miss, 100000, 1000, 'NOMATCH', 'CLEAN', 'CLEAN'),
        ('depth_nomatch', D, miss, 100000, 1000, 'NOMATCH', 'CLEAN', 'CLEAN'),
        ('match_positive', M, b'a'*12+b'b', 100000, 1000, 'POSITIVE', 'VIRUS', 'VIRUS'),
        ('depth_positive', D, b'a'*8+b'b'*8, 100000, 1000, 'POSITIVE', 'VIRUS', 'VIRUS'),
        ('ordinary_nomatch', N, miss, 100000, 1000, 'NOMATCH', 'CLEAN', 'CLEAN'),
        ('restored_control', M, miss, 100000, 1000, 'NOMATCH', 'CLEAN', 'CLEAN'),
    )


def _signature(pattern, offset):
    _require(pattern in (M, D, N) and type(offset) is int and 0 < offset < 4096)
    return (b'Kapit.PcreProbe;Engine:81-255,Target:0;0&1;0:89504e470d0a1a0a;' +
            str(offset).encode('ascii') + b':0/' + pattern + b'/\n')


def _load_signature(lib, engine, raw):
    # One fresh container, one exact harness-owned tmpfs file. Never unlink a
    # pre-existing target after exclusive creation fails.
    fd = None
    owned = False
    try:
        fd = os.open(SIGNATURE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        owned = True
        info = os.fstat(fd)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid())
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            _require(type(count) is int and 0 < count <= len(view))
            view = view[count:]
        closing, fd = fd, None
        _release([(os.close, (closing,), False)])
        count = c.c_uint(0)
        _zero(lib.cl_load(SIGNATURE.encode('ascii'), engine, c.byref(count), 0))
        _require(count.value == 1)
    finally:
        actions = []
        if fd is not None:
            actions.append((os.close, (fd,), False))
        if owned:
            actions.append((os.unlink, (SIGNATURE,), False))
        _release(actions)


class Engine:
    def __init__(self, bindings, worker, pattern, offset, match_limit, depth_limit):
        self.lib = bindings.lib
        self.expected_readback = worker.expected_engine_readback
        self.engine = None
        try:
            self.engine = self.lib.cl_engine_new()
            _require(self.engine)
            self.limits = {int(key): value for key, value in worker.POLICY['engine'].items()}
            self.limits.update({32: match_limit, 33: depth_limit})
            for field, value in self.limits.items():
                _zero(self.lib.cl_engine_set_num(self.engine, field, value))
            _zero(self.lib.cl_engine_set_str(self.engine, 13, b'/scratch'))
            self.readback()
            _load_signature(self.lib, self.engine, _signature(pattern, offset))
            _zero(self.lib.cl_engine_compile(self.engine))
            self.readback()
        except BaseException:
            self.close()
            raise

    def readback(self):
        for field, expected in self.limits.items():
            error = c.c_int(-1)
            value = self.lib.cl_engine_get_num(self.engine, field, c.byref(error))
            _require(error.value == 0 and type(value) is int and
                     value == self.expected_readback(field, expected))

    def close(self):
        if self.engine:
            engine, self.engine = self.engine, None
            _release([(self.lib.cl_engine_free, (engine,), True)])


def _direct(bindings, pattern, data, offset, match_limit, depth_limit):
    lib = bindings.lib
    code = context = match_data = None
    try:
        pattern_buffer = c.create_string_buffer(pattern)
        error = c.c_int(0)
        error_offset = c.c_size_t(0)
        code = lib.pcre2_compile_8(pattern_buffer, len(pattern), 0, c.byref(error), c.byref(error_offset), None)
        _require(code)
        jit_bytes = c.c_size_t(1)
        _zero(lib.pcre2_pattern_info_8(code, PCRE2_INFO_JITSIZE, c.byref(jit_bytes)))
        _require(jit_bytes.value == 0)
        context = lib.pcre2_match_context_create_8(None)
        _require(context)
        _zero(lib.pcre2_set_match_limit_8(context, match_limit))
        _zero(lib.pcre2_set_depth_limit_8(context, depth_limit))
        match_data = lib.pcre2_match_data_create_from_pattern_8(code, None)
        _require(match_data)
        subject = data[offset:]
        subject_buffer = c.create_string_buffer(subject)
        value = lib.pcre2_match_8(code, subject_buffer, len(subject), 0, PCRE2_ANCHORED, match_data, context)
        _require(type(value) is int)
        if value > 0:
            return 'POSITIVE'
        return {PCRE2_ERROR_NOMATCH: 'NOMATCH', PCRE2_ERROR_MATCHLIMIT: 'MATCHLIMIT',
                PCRE2_ERROR_DEPTHLIMIT: 'DEPTHLIMIT', 0: 'ZERO'}.get(value, 'OTHER_ERROR')
    finally:
        actions = []
        for value, function in [(match_data, lib.pcre2_match_data_free_8),
                                (context, lib.pcre2_match_context_free_8), (code, lib.pcre2_code_free_8)]:
            if value:
                actions.append((function, (value,), False))
        _release(actions)


def _scan(engine, data, strict):
    engine.readback()
    buffer = c.create_string_buffer(data)
    fmap = engine.lib.cl_fmap_open_memory(c.cast(buffer, c.c_void_p), len(data))
    _require(fmap)
    try:
        function = engine.lib.cl_kapit_scanmap_strict_v1 if strict else engine.lib.cl_scanmap_callback
        name = c.c_char_p()
        scanned = c.c_ulong(0)
        options = Options(4, 2048, 8196, 0, 0)
        value = function(fmap, None, c.byref(name), c.byref(scanned), engine.engine, c.byref(options), None)
        _require(type(value) is int)
        # Exact CL_ERROR, not a generic nonclean result, is required for low limits.
        return {0: 'CLEAN', 1: 'VIRUS', CL_ERROR: 'ERROR'}.get(value, 'OTHER_ERROR')
    finally:
        _release([(engine.lib.cl_fmap_close, (fmap,), False)])


def _run(worker):
    rows = []
    completed = False
    cleanup = False
    cleanup_failed = False
    bindings = None
    stage = 'PROVIDER'
    diagnostic = None
    try:
        worker._scratch_empty()
        bindings = Bindings(worker)
        for case_id, pattern, subject, match_limit, depth_limit, raw_expected, up_expected, strict_expected in _cases():
            data, offset = _image(subject)
            worker.inspect_container(data, 'image/png')
            observed = []
            for order in ((False, True), (True, False)):
                stage = 'ENGINE'
                engine = Engine(bindings, worker, pattern, offset, match_limit, depth_limit)
                try:
                    stage = 'DIRECT'
                    raw = _direct(bindings, pattern, data, offset, match_limit, depth_limit)
                    stage = 'SCANNER'
                    outcomes = {strict: _scan(engine, data, strict) for strict in order}
                    observed.append((raw, outcomes[False], outcomes[True]))
                finally:
                    engine.close()
            stage = 'RESULT'
            _require(len(observed) == 2 and observed[0] == observed[1])
            raw, upstream, strict = observed[0]
            passed = observed[0] == (raw_expected, up_expected, strict_expected)
            rows.append({'case': case_id, 'direct': raw, 'upstream': upstream, 'strict': strict,
                         'orders_completed': 2, 'passed': passed,
                         'normalization_observed': upstream == 'CLEAN' and strict == 'ERROR'})
        completed = tuple(row['case'] for row in rows) == CASE_IDS
        stage = 'NONE' if all(row['passed'] for row in rows) else 'RESULT'
    except CleanupUnavailable as error:
        cleanup_failed = True
        completed = False
        stage = 'CLEANUP'
        diagnostic = _diagnostic(error, stage)
    except Exception as error:
        completed = False
        diagnostic = _diagnostic(error, stage)
    finally:
        try:
            if bindings is not None:
                bindings.close()
        except BaseException as error:
            cleanup_failed = True
            completed = False
            stage = 'CLEANUP'
            diagnostic = _diagnostic(error, stage)
        try:
            worker._scratch_empty()
            cleanup = not cleanup_failed
        except BaseException as error:
            completed = False
            stage = 'CLEANUP'
            diagnostic = _diagnostic(error, stage)
    result = {'schema': 1, 'scope': SCOPE, 'completed': completed,
            'passed': completed and cleanup and all(row['passed'] for row in rows),
            'cases': rows, 'harness_cleanup': cleanup, 'failure_stage': stage, 'native_eligible': False}
    if not result['passed']:
        result['diagnostic'] = diagnostic or _diagnostic(None, stage)
    return result


def parse_success(raw):
    """Validate public observations only; never authenticates image or eligibility."""
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result)
            result[key] = value
        return result
    try:
        _require(type(raw) is bytes and 1 <= len(raw) <= 8192)
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: _require(False))
        _require(type(value) is dict and set(value) == {'schema', 'scope', 'completed', 'passed',
                  'cases', 'harness_cleanup', 'failure_stage', 'native_eligible'})
        _require(type(value['schema']) is int and value['schema'] == 1 and value['scope'] == SCOPE)
        _require(value['completed'] is True and value['passed'] is True and
                 value['harness_cleanup'] is True and value['native_eligible'] is False and
                 value['failure_stage'] == 'NONE')
        _require(type(value['cases']) is list and len(value['cases']) == len(CASE_IDS))
        for row, case in zip(value['cases'], _cases()):
            _require(type(row) is dict and set(row) == {'case', 'direct', 'upstream', 'strict',
                     'orders_completed', 'passed', 'normalization_observed'})
            _require(row['case'] == case[0] and row['direct'] == case[5] and
                     row['upstream'] == case[6] and row['strict'] == case[7])
            _require(type(row['orders_completed']) is int and row['orders_completed'] == 2)
            _require(row['passed'] is True and row['normalization_observed'] is
                     (case[6] == 'CLEAN' and case[7] == 'ERROR'))
        return value
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError):
        raise ProbeUnavailable() from None


def parse_failure(raw):
    """Return only closed diagnostic metadata; never accept success or eligibility."""
    try:
        value = _failure_document(raw)
        _require(type(value) is dict and set(value) == {'schema', 'scope', 'completed', 'passed',
                  'cases', 'harness_cleanup', 'failure_stage', 'native_eligible', 'diagnostic'})
        _require(type(value['schema']) is int and value['schema'] == 1 and value['scope'] == SCOPE)
        _require(value['passed'] is False and value['native_eligible'] is False and
                 type(value['completed']) is bool and type(value['harness_cleanup']) is bool)
        diagnostic = _validate_diagnostic(value['diagnostic'])
        _require(value['failure_stage'] == diagnostic['stage'])
        _require(type(value['cases']) is list and len(value['cases']) <= len(CASE_IDS))
        for row, case in zip(value['cases'], _cases()):
            _require(type(row) is dict and set(row) == {'case', 'direct', 'upstream', 'strict',
                     'orders_completed', 'passed', 'normalization_observed'})
            _require(row['case'] == case[0] and type(row['orders_completed']) is int and row['orders_completed'] == 2)
            _require(row['direct'] in ('POSITIVE', 'NOMATCH', 'MATCHLIMIT', 'DEPTHLIMIT', 'ZERO', 'OTHER_ERROR'))
            _require(row['upstream'] in ('CLEAN', 'VIRUS', 'ERROR', 'OTHER_ERROR') and
                     row['strict'] in ('CLEAN', 'VIRUS', 'ERROR', 'OTHER_ERROR'))
            expected = (row['direct'], row['upstream'], row['strict']) == (case[5], case[6], case[7])
            _require(row['passed'] is expected and row['normalization_observed'] is
                     (row['upstream'] == 'CLEAN' and row['strict'] == 'ERROR'))
        _require(not value['completed'] or len(value['cases']) == len(CASE_IDS))
        _require(not (value['completed'] and value['harness_cleanup'] and all(row['passed'] for row in value['cases'])))
        return {'diagnostic': diagnostic, 'completed': value['completed'], 'passed': False,
                'case_count': len(value['cases']), 'harness_cleanup': value['harness_cleanup'], 'native_eligible': False}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ProbeUnavailable() from None


def main():
    if len(sys.argv) != 1:
        return 2
    try:
        from kapit_evidence import evidence_native_worker as worker
        result = _run(worker)
    except Exception as error:
        result = {'schema': 1, 'scope': SCOPE, 'completed': False, 'passed': False, 'cases': [],
                  'harness_cleanup': False, 'failure_stage': 'WORKER_IMPORT', 'native_eligible': False,
                  'diagnostic': _diagnostic(error, 'WORKER_IMPORT')}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
