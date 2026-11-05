"""Fixed public scratch measurements; import is inert and stdin is never read."""
from __future__ import annotations

import ctypes
import errno
import json
import os
import stat
import sys

SCOPE = 'PUBLIC_SCRATCH_DIAGNOSTIC_ONLY'
SCRATCH = '/scratch'
DIRECTORY = '/scratch/kapit-public-rmdir-probe'
MAX_RESULT = 4096
MAX_ENTRIES = 64
STAGES = ('fresh_start', 'scanner_initialization', 'strict_png', 'upstream_png', 'engine_close')
TYPES = ('regular', 'directory', 'symlink', 'other')
SCAN = frozenset(('CLEAN', 'NOT_CLEAN', 'ERROR'))
RMDIR = frozenset(('REMOVED', 'EPERM', 'OTHER_ERRNO'))


class ProbeUnavailable(ValueError):
    def __str__(self): return 'PUBLIC_SCRATCH_DIAGNOSTIC_UNAVAILABLE'


def _require(value):
    if value is not True: raise ProbeUnavailable()


def _base(operation):
    return {'schema': 1, 'scope': SCOPE, 'operation': operation, 'completed': False,
            'failed_stage': 'fresh_start', 'observation': 'NONE', 'snapshots': [],
            'native_eligible': False, 'private_input_allowed': False}


def _snapshot():
    """At most 65 entries are queried; never recurse or follow links."""
    _require(sys.platform == 'linux')
    counts = {name: 0 for name in TYPES}
    with os.scandir(SCRATCH) as entries:
        for index, entry in enumerate(entries):
            _require(index < MAX_ENTRIES)
            mode = entry.stat(follow_symlinks=False).st_mode
            _require(type(mode) is int)
            kind = ('regular' if stat.S_ISREG(mode) else 'directory' if stat.S_ISDIR(mode)
                    else 'symlink' if stat.S_ISLNK(mode) else 'other')
            counts[kind] += 1
    return counts


def _worker():
    from kapit_evidence import evidence_native_worker
    return evidence_native_worker


def _rmdir():
    result = _base('rmdir')
    try:
        _require(sys.platform == 'linux')
        _require(sum(_snapshot().values()) == 0)
        result['failed_stage'] = 'create_directory'
        os.mkdir(DIRECTORY, 0o700)
        _require(stat.S_ISDIR(os.lstat(DIRECTORY).st_mode))
        with os.scandir(DIRECTORY) as entries:
            _require(next(entries, None) is None)
        result['failed_stage'] = 'native_abi'
        library = ctypes.CDLL(None, use_errno=True)
        remove = library.rmdir
        remove.argtypes = [ctypes.c_char_p]
        remove.restype = ctypes.c_int
        result['failed_stage'] = 'remove_directory'
        ctypes.set_errno(0)
        code = remove(b'/scratch/kapit-public-rmdir-probe')
        error = ctypes.get_errno()
        _require(type(code) is int and type(error) is int)
        if code == 0:
            observation = 'REMOVED'
        else:
            _require(code == -1 and 1 <= error <= 4095)
            observation = 'EPERM' if error == errno.EPERM else 'OTHER_ERRNO'
        result.update(completed=True, failed_stage='NONE', observation=observation)
    except BaseException:
        # No exception text, raw errno, name or fallback removal is emitted.
        if result['failed_stage'] == 'NONE':
            result['failed_stage'] = 'remove_directory'
        result.update(completed=False, observation='NONE')
    return result


def _upstream(worker, scanner, png):
    """Exact reviewed strict-probe fmap/ctypes lifetime, same scanner library."""
    scanner._check_limits()
    c = worker.c
    buffer = c.create_string_buffer(png)
    fmap = scanner.library.cl_fmap_open_memory(c.cast(buffer, c.c_void_p), len(png))
    _require(bool(fmap))
    try:
        strict = scanner.library.cl_kapit_scanmap_strict_v1
        scan = scanner.library.cl_scanmap_callback
        scan.argtypes = strict.argtypes
        scan.restype = strict.restype
        name = c.c_char_p()
        scanned = c.c_ulong(0)
        options = worker.ScanOptions(4, 2048, 8196, 0, 0)
        code = scan(fmap, None, c.byref(name), c.byref(scanned), scanner.engine, c.byref(options), None)
        _require(type(code) is int)
        scanner._check_limits()
        return 'CLEAN' if code == 0 else 'NOT_CLEAN' if code == 1 else 'ERROR'
    finally:
        scanner.library.cl_fmap_close(fmap)


def _lifecycle():
    result = _base('lifecycle')
    scanner = None
    body_complete = False
    try:
        _require(sys.platform == 'linux')
        result['snapshots'].append({'stage': 'fresh_start', 'counts': _snapshot(), 'scan': 'NONE'})
        result['failed_stage'] = 'worker_import'
        worker = _worker()
        result['failed_stage'] = 'configuration'
        worker.load_configuration()
        result['failed_stage'] = 'public_images'
        images = dict(worker._public_images())
        png = images['image/png']
        _require(type(png) is bytes and 45 <= len(png) <= 65536)
        result['failed_stage'] = 'scanner_initialization'
        scanner = worker.NativeScanner()
        result['snapshots'].append({'stage': 'scanner_initialization', 'counts': _snapshot(), 'scan': 'NONE'})
        result['failed_stage'] = 'strict_png'
        code = scanner.scan(png, 'image/png')
        _require(type(code) is str and code in ('SCAN_CLEAN', 'SCAN_NOT_CLEAN', 'SCANNER_UNAVAILABLE'))
        category = {'SCAN_CLEAN': 'CLEAN', 'SCAN_NOT_CLEAN': 'NOT_CLEAN', 'SCANNER_UNAVAILABLE': 'ERROR'}[code]
        result['snapshots'].append({'stage': 'strict_png', 'counts': _snapshot(), 'scan': category})
        result['failed_stage'] = 'upstream_png'
        category = _upstream(worker, scanner, png)
        result['snapshots'].append({'stage': 'upstream_png', 'counts': _snapshot(), 'scan': category})
        body_complete = True
    except BaseException:
        body_complete = False
        if len(result['snapshots']) == 4:
            result['failed_stage'] = 'lifecycle_finalization'
    finally:
        try:
            if scanner is not None:
                scanner.close()
            if body_complete and len(result['snapshots']) == 4:
                result['failed_stage'] = 'engine_close'
                result['snapshots'].append({'stage': 'engine_close', 'counts': _snapshot(), 'scan': 'NONE'})
                result.update(completed=True, failed_stage='NONE')
        except BaseException:
            result.update(completed=False, failed_stage='engine_close')
    return result


def parse_result(raw, operation):
    """Reject partial or contradictory frames as success; return nameless data."""
    def pairs(items):
        doc = {}
        for key, value in items:
            _require(key not in doc)
            doc[key] = value
        return doc
    try:
        _require(type(operation) is str and operation in ('rmdir', 'lifecycle'))
        _require(type(raw) is bytes and 1 <= len(raw) <= MAX_RESULT)
        doc = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                         parse_constant=lambda _: _require(False))
        _require(type(doc) is dict and set(doc) == {'schema', 'scope', 'operation', 'completed',
                 'failed_stage', 'observation', 'snapshots', 'native_eligible', 'private_input_allowed'})
        _require(type(doc['schema']) is int and doc['schema'] == 1 and doc['scope'] == SCOPE and
                 doc['operation'] == operation and type(doc['completed']) is bool and
                 doc['native_eligible'] is False and doc['private_input_allowed'] is False and
                 type(doc['failed_stage']) is str and type(doc['observation']) is str and type(doc['snapshots']) is list)
        if operation == 'rmdir':
            _require(doc['snapshots'] == [])
            if doc['completed']:
                _require(doc['failed_stage'] == 'NONE' and doc['observation'] in RMDIR)
            else:
                _require(doc['observation'] == 'NONE' and doc['failed_stage'] in
                         ('fresh_start', 'create_directory', 'native_abi', 'remove_directory'))
        else:
            rows = doc['snapshots']
            _require(doc['observation'] == 'NONE' and len(rows) <= 5)
            for row, stage in zip(rows, STAGES):
                _require(type(row) is dict and set(row) == {'stage', 'counts', 'scan'} and
                         row['stage'] == stage and type(row['scan']) is str)
                counts = row['counts']
                _require(type(counts) is dict and set(counts) == set(TYPES) and
                         all(type(value) is int and 0 <= value <= MAX_ENTRIES for value in counts.values()) and
                         sum(counts.values()) <= MAX_ENTRIES)
                _require(row['scan'] in SCAN if stage in ('strict_png', 'upstream_png') else row['scan'] == 'NONE')
            if doc['completed']:
                _require(len(rows) == 5 and doc['failed_stage'] == 'NONE')
            else:
                expected = {'fresh_start': 0, 'worker_import': 1, 'configuration': 1, 'public_images': 1,
                            'scanner_initialization': 1, 'strict_png': 2, 'upstream_png': 3, 'lifecycle_finalization': 4}
                _require(len(rows) <= 4 and ((doc['failed_stage'] == 'engine_close' and len(rows) >= 1) or
                         (doc['failed_stage'] in expected and len(rows) == expected[doc['failed_stage']])))
        return doc
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ProbeUnavailable() from None


def run(operation):
    _require(type(operation) is str and operation in ('rmdir', 'lifecycle'))
    result = _rmdir() if operation == 'rmdir' else _lifecycle()
    return parse_result(json.dumps(result, separators=(',', ':')).encode('ascii'), operation)


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in ('rmdir', 'lifecycle'):
            return 2
        result = run(sys.argv[1])
        print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        return 0 if result['completed'] else 2
    except BaseException:
        # Transport/parser uncertainty produces no raw native exception frame.
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
