"""Fixed public diagnostic child source; import is inert, never a runtime gate.

Local consistency and cleanup do not authenticate provenance, generation,
currentness or the protected parent's five finalizers. No private input API.
"""
from contextlib import redirect_stderr, redirect_stdout
import json
import struct
import sys
import zlib


class ProbeUnavailable(Exception):
    def __str__(self):
        return 'PUBLIC_DETECTION_CONTROLS_UNAVAILABLE'


_RAW = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
_FIELDS = ('general', 'parse', 'heuristic', 'mail', 'dev')
_OPTIONS = (4, 2048, 8196, 0, 0)


def _chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def _png(images):
    if (type(images) is not tuple or len(images) != 2
            or any(type(row) is not tuple or len(row) != 2 for row in images)
            or images[0][0] != 'image/png' or images[1][0] != 'image/jpeg'):
        raise ProbeUnavailable()
    png, jpeg = images[0][1], images[1][1]
    if (type(png) is not bytes or type(jpeg) is not bytes
            or not 45 <= len(png) <= 65536 or not 32 <= len(jpeg) <= 65536
            or png[:16] != b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
            or png[-12:] != _chunk(b'IEND', b'')
            or jpeg[:2] != b'\xff\xd8' or jpeg[-2:] != b'\xff\xd9'
            or jpeg.find(b'\xff\xda') < 20):
        raise ProbeUnavailable()
    return png[:-12] + _chunk(b'tEXt', b'Comment\x00' + _RAW) + png[-12:]


def _check(scanner, library, engine, options, limits, strict, upstream, abi):
    def consistent():
        return (scanner.library is library and type(scanner.engine) is int
                and scanner.engine == engine
                and library.cl_kapit_scanmap_strict_v1 is strict
                and library.cl_scanmap_callback is upstream
                and tuple(strict.argtypes) == abi[0] and strict.restype is abi[1]
                and tuple(upstream.argtypes) == abi[0] and upstream.restype is abi[1]
                and all(type(getattr(options, field)) is int
                        and getattr(options, field) == value
                        for field, value in zip(_FIELDS, _OPTIONS)))
    if not consistent():
        raise ProbeUnavailable()
    if limits() is not None:
        raise ProbeUnavailable()
    if not consistent():
        raise ProbeUnavailable()


def _call(c, library, engine, options, data, function):
    # Keep buffer/data/options/library/engine strongly referenced through close.
    buffer = c.create_string_buffer(data)
    close_map = library.cl_fmap_close
    fmap = library.cl_fmap_open_memory(c.cast(buffer, c.c_void_p), len(data))
    if not fmap:
        raise ProbeUnavailable()
    failed = False
    result = None
    try:
        name = c.c_char_p()
        scanned = c.c_ulong(0)
        # Native names and diagnostic text are deliberately never dereferenced.
        code = function(fmap, None, c.byref(name), c.byref(scanned), engine,
                        c.byref(options), None)
        if type(code) is not int or code not in (0, 1):
            failed = True
        else:
            result = 'CLEAN' if code == 0 else 'NOT_CLEAN'
    except BaseException:
        failed = True
    finally:
        try:
            if close_map(fmap) is not None:
                failed = True
        except BaseException:
            failed = True
    if failed:
        raise ProbeUnavailable()
    return result


def _run(worker):
    """Private fake-worker seam for tests; main supplies only the fixed worker."""
    scanner = None
    close = None
    library = engine = None
    failed = False
    rows = []
    try:
        worker.load_configuration()
        png = _png(worker._public_images())
        scanner = worker.NativeScanner()
        close = scanner.close
        library, engine = scanner.library, scanner.engine
        if type(engine) is not int or engine <= 0:
            raise ProbeUnavailable()
        limits = scanner._check_limits
        strict = library.cl_kapit_scanmap_strict_v1
        upstream = library.cl_scanmap_callback
        abi = (tuple(strict.argtypes), strict.restype)
        upstream.argtypes = list(abi[0])
        upstream.restype = abi[1]
        options = worker.ScanOptions(*_OPTIONS)
        for name, data, function in (
                ('raw_upstream', _RAW, upstream),
                ('png_strict', png, strict),
                ('png_upstream', png, upstream)):
            _check(scanner, library, engine, options, limits, strict, upstream, abi)
            result = _call(worker.c, library, engine, options, data, function)
            _check(scanner, library, engine, options, limits, strict, upstream, abi)
            rows.append({'id': name, 'category': result})
    except BaseException:
        failed = True
    finally:
        if scanner is not None and close is not None:
            try:
                # close is the original bound method. Restore only held handles
                # so identity tampering cannot redirect cleanup to a replacement.
                scanner.library, scanner.engine = library, engine
                if close() is not None:
                    failed = True
            except BaseException:
                failed = True
        try:
            if worker._scratch_empty() is not None:
                failed = True
        except BaseException:
            failed = True
    if failed or len(rows) != 3:
        raise ProbeUnavailable()
    return {'schema_version': 1, 'scope': 'PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY',
            'controls': rows, 'completed': 3}


class _Discard:
    """Discard Python-level worker output without retaining arbitrary content."""

    def write(self, text):
        return len(text)

    def flush(self):
        pass


def main():
    if len(sys.argv) != 1:
        return 2
    failed = False
    encoded = None
    # Native fd/transport output bounding is a future parent obligation.
    with redirect_stdout(_Discard()), redirect_stderr(_Discard()):
        try:
            from kapit_evidence import evidence_native_worker as worker
            encoded = json.dumps(_run(worker), separators=(',', ':'), sort_keys=True)
            if not 1 <= len(encoded.encode('utf-8')) <= 4096:
                failed = True
        except BaseException:
            failed = True
    if failed:
        return 2
    try:
        output = encoded + '\n'
        count = sys.stdout.write(output)
        if type(count) is not int or count != len(output):
            return 2
        sys.stdout.flush()
    except BaseException:
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
