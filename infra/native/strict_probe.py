"""Fixed PUBLIC native test vectors, never a production scan or readiness issuer.

Import is inert. Only main loads the fixed installed package and its verified
configuration. The harness alone bypasses inspect_container so real C error
paths can run; the production scanner remains strict-only and unchanged.
"""
from __future__ import annotations

import json
import struct
import sys
import zlib


class ProbeUnavailable(Exception):
    def __str__(self):
        return 'PUBLIC_NATIVE_PROBE_UNAVAILABLE'


HARNESS_FILES = frozenset(name for name in ('<fixed-public-strict>', globals().get('__file__', '')) if name)
HARNESS_FUNCTIONS = frozenset(('_run', '_exercise', '_call', '_limit', '_vectors', 'main'))
DIAGNOSTIC_STAGES = frozenset(('WORKER_IMPORT', 'CONFIGURATION', 'PUBLIC_IMAGES', 'SCANNER_INITIALIZATION', 'CASES', 'ENGINE_CLEANUP', 'SCRATCH_CLEANUP'))

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



EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
CASE_IDS = ('png_positive', 'jpeg_positive', 'eicar_png', 'png_zero_width',
            'png_truncated_chunk', 'jpeg_before_sos', 'jpeg_jpg7', 'raw_no_image',
            'fmap_null', 'fmap_short', 'fmap_overlimit', 'options_parse_off',
            'engine_max_file', 'engine_max_scan')


def _chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def _vectors(png, jpeg):
    if (type(png) is not bytes or type(jpeg) is not bytes or
            not 45 <= len(png) <= 65536 or not 32 <= len(jpeg) <= 65536 or
            png[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR' or
            png[-12:] != _chunk(b'IEND', b'') or jpeg[:2] != b'\xff\xd8' or jpeg[-2:] != b'\xff\xd9'):
        raise ProbeUnavailable()
    sos = jpeg.find(b'\xff\xda')
    if sos < 20:
        raise ProbeUnavailable()
    # CRC-correct malformed IHDR reaches the actual PNG dimension parser rather
    # than failing a Python wrapper or an unrelated CRC check.
    bad_ihdr = b'\x00'*4 + png[20:29]
    return (
        ('png_positive', png, 'CLEAN', 'COMPLETION', None, False),
        ('jpeg_positive', jpeg, 'CLEAN', 'COMPLETION', None, False),
        ('eicar_png', png[:-12] + _chunk(b'tEXt', b'Comment\x00' + EICAR) + png[-12:], 'NOT_CLEAN', 'DETECTION', None, False),
        ('png_zero_width', png[:8] + _chunk(b'IHDR', bad_ihdr) + png[33:], 'NONCLEAN', 'PARSER', None, False),
        ('png_truncated_chunk', png[:41], 'NONCLEAN', 'PARSER', None, False),
        ('jpeg_before_sos', jpeg[:sos], 'NONCLEAN', 'PARSER', None, False),
        ('jpeg_jpg7', jpeg[:sos] + b'\xff\xf7\x00\x02', 'NONCLEAN', 'PARSER', None, False),
        ('raw_no_image', b'fixed public raw bytes without image framing', 'NONCLEAN', 'COMPLETION', None, False),
        ('fmap_null', None, 'NONCLEAN', 'PRECONDITION', None, False),
        ('fmap_short', b'short', 'NONCLEAN', 'PRECONDITION', None, False),
        ('fmap_overlimit', b'P' * (5242880 + 1), 'NONCLEAN', 'PRECONDITION', None, False),
        ('options_parse_off', png, 'NONCLEAN', 'PRECONDITION', None, True),
        ('engine_max_file', png, 'NONCLEAN', 'ENGINE_LIMIT', 1, False),
        ('engine_max_scan', png, 'NONCLEAN', 'ENGINE_LIMIT', 0, False),
    )


def _category(code):
    if type(code) is not int:
        raise ProbeUnavailable()
    return 'CLEAN' if code == 0 else 'NOT_CLEAN' if code == 1 else 'ERROR'


def _call(worker, scanner, data, *, upstream=False, parse_off=False):
    c = worker.c
    buf = None; fmap = None
    if data is not None:
        buf = c.create_string_buffer(data)
        fmap = scanner.library.cl_fmap_open_memory(c.cast(buf, c.c_void_p), len(data))
        if not fmap:
            raise ProbeUnavailable()
    try:
        name = c.c_char_p(); scanned = c.c_ulong(0)
        options = worker.ScanOptions(4, 0 if parse_off else 2048, 8196, 0, 0)
        fn = scanner.library.cl_scanmap_callback if upstream else scanner.library.cl_kapit_scanmap_strict_v1
        # Never access name.value or diagnostic/error text. NULL is permitted
        # only on the derived strict entry point's explicit argument guard.
        if upstream and fmap is None:
            raise ProbeUnavailable()
        return _category(fn(fmap, None, c.byref(name), c.byref(scanned), scanner.engine, c.byref(options), None))
    finally:
        if fmap:
            scanner.library.cl_fmap_close(fmap)


def _limit(worker, scanner, field, value):
    c = worker.c
    if scanner.library.cl_engine_set_num(scanner.engine, field, value) != 0:
        raise ProbeUnavailable()
    error = c.c_int(-1)
    if scanner.library.cl_engine_get_num(scanner.engine, field, c.byref(error)) != value or error.value != 0:
        raise ProbeUnavailable()


def _exercise(worker, scanner, png, jpeg):
    results = []
    lib = scanner.library
    strict = lib.cl_kapit_scanmap_strict_v1
    lib.cl_scanmap_callback.argtypes = strict.argtypes
    lib.cl_scanmap_callback.restype = strict.restype
    for case_id, data, expected, kind, field, parse_off in _vectors(png, jpeg):
        try:
            if field is not None:
                _limit(worker, scanner, field, 16)
            observed = _call(worker, scanner, data, parse_off=parse_off)
            # Compare genuine parser/completion/limit cases on the SAME built
            # library. ABI-precondition refusals have no safe upstream analogue.
            upstream = _call(worker, scanner, data, upstream=True) if kind != 'PRECONDITION' else 'NOT_RUN'
        finally:
            if field is not None:
                _limit(worker, scanner, field, worker.POLICY['engine'][str(field)])
        passed = observed != 'CLEAN' if expected == 'NONCLEAN' else observed == expected
        results.append({'case': case_id, 'kind': kind, 'strict': observed, 'upstream': upstream,
                        'passed': passed, 'normalization_observed': observed != 'CLEAN' and upstream == 'CLEAN'})
    scanner._check_limits()
    # Also prove restoring changed limits did not leave a disabled/broken engine.
    if _call(worker, scanner, png) != 'CLEAN':
        raise ProbeUnavailable()
    return results


def _run(worker):
    scanner = None; results = []; completed = False
    stage = 'CONFIGURATION'; diagnostic = None
    try:
        worker.load_configuration()
        stage = 'PUBLIC_IMAGES'
        images = dict(worker._public_images())
        stage = 'SCANNER_INITIALIZATION'
        scanner = worker.NativeScanner()
        stage = 'CASES'
        results = _exercise(worker, scanner, images['image/png'], images['image/jpeg'])
        completed = tuple(row['case'] for row in results) == CASE_IDS
    except Exception as error:
        completed = False
        diagnostic = _diagnostic(error, stage)
    finally:
        try:
            if scanner is not None:
                scanner.close()
        except Exception as error:
            completed = False
            diagnostic = _diagnostic(error, 'ENGINE_CLEANUP')
        try:
            worker._scratch_empty()
        except Exception as error:
            completed = False
            diagnostic = _diagnostic(error, 'SCRATCH_CLEANUP')
    passed = completed and all(row['passed'] for row in results)
    result = {'schema': 1, 'scope': 'PUBLIC_STRICT_NATIVE_PROBE_ONLY', 'completed': completed,
            'passed': passed, 'cases': results, 'native_eligible': False}
    if not passed:
        result['diagnostic'] = diagnostic or _diagnostic(None, 'CASES')
    return result


FAILURE_CASES = (
    ('png_positive','COMPLETION','CLEAN'), ('jpeg_positive','COMPLETION','CLEAN'),
    ('eicar_png','DETECTION','NOT_CLEAN'), ('png_zero_width','PARSER','NONCLEAN'),
    ('png_truncated_chunk','PARSER','NONCLEAN'), ('jpeg_before_sos','PARSER','NONCLEAN'),
    ('jpeg_jpg7','PARSER','NONCLEAN'), ('raw_no_image','COMPLETION','NONCLEAN'),
    ('fmap_null','PRECONDITION','NONCLEAN'), ('fmap_short','PRECONDITION','NONCLEAN'),
    ('fmap_overlimit','PRECONDITION','NONCLEAN'), ('options_parse_off','PRECONDITION','NONCLEAN'),
    ('engine_max_file','ENGINE_LIMIT','NONCLEAN'), ('engine_max_scan','ENGINE_LIMIT','NONCLEAN'))


def parse_failure(raw):
    """Validate the failure frame, return no untrusted partial case rows."""
    try:
        value = _failure_document(raw)
        if (type(value) is not dict or set(value) != {'schema', 'scope', 'completed', 'passed', 'cases', 'native_eligible', 'diagnostic'} or
                type(value['schema']) is not int or value['schema'] != 1 or value['scope'] != 'PUBLIC_STRICT_NATIVE_PROBE_ONLY' or
                type(value['completed']) is not bool or value['passed'] is not False or value['native_eligible'] is not False):
            raise ProbeUnavailable()
        diagnostic = _validate_diagnostic(value['diagnostic'])
        if type(value['cases']) is not list or len(value['cases']) > len(CASE_IDS):
            raise ProbeUnavailable()
        for row, (name, kind, expected) in zip(value['cases'], FAILURE_CASES):
            if (type(row) is not dict or set(row) != {'case', 'kind', 'strict', 'upstream', 'passed', 'normalization_observed'} or
                    row['case'] != name or row['kind'] != kind or row['strict'] not in ('CLEAN','NOT_CLEAN','ERROR') or
                    row['upstream'] not in ('CLEAN','NOT_CLEAN','ERROR','NOT_RUN') or
                    (row['upstream'] == 'NOT_RUN') != (kind == 'PRECONDITION')):
                raise ProbeUnavailable()
            passed = row['strict'] != 'CLEAN' if expected == 'NONCLEAN' else row['strict'] == expected
            if (row['passed'] is not passed or row['normalization_observed'] is not
                    (row['strict'] != 'CLEAN' and row['upstream'] == 'CLEAN')):
                raise ProbeUnavailable()
        if value['completed'] and (len(value['cases']) != len(CASE_IDS) or all(row['passed'] for row in value['cases'])):
            raise ProbeUnavailable()
        return {'diagnostic': diagnostic, 'completed': value['completed'], 'passed': False,
                'case_count': len(value['cases']), 'native_eligible': False}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ProbeUnavailable() from None


def main():
    # No paths, fixture bytes, callbacks, mode options or stdin from a caller.
    if len(sys.argv) != 1:
        return 2
    try:
        from kapit_evidence import evidence_native_worker as worker
        result = _run(worker)
    except Exception as error:
        result = {'schema': 1, 'scope': 'PUBLIC_STRICT_NATIVE_PROBE_ONLY', 'completed': False,
                  'passed': False, 'cases': [], 'native_eligible': False,
                  'diagnostic': _diagnostic(error, 'WORKER_IMPORT')}
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
