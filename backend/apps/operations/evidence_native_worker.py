"""Fixed image-only Linux worker. Imports are inert; no Django or host settings.

Packaged as kapit_evidence and invoked with -I -B -m, exactly one mode/nonce.
Only the real main installs controls and emits READY; tests of internal adapters
are not isolation evidence. The parent must separately prove the immutable image.
"""
from __future__ import annotations

import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from . import evidence_scan_protocol as protocol
from .evidence_policy import EvidenceError, inspect_container
from .evidence_decoder import decode_image, PILLOW_VERSION
from .evidence_linux import install_abi3_confinement

PACKAGE_ROOT = Path('/usr/local/lib/python3.14/site-packages/kapit_evidence')
CONFIG = Path('/opt/evidence/runtime.json')
LIBRARY = Path('/opt/clamav/lib/libclamav.so.12.0.3')
SIGNATURE_ROOT = Path('/opt/signatures')
SCRATCH = '/scratch'
MODULES = ('evidence_native_worker.py', 'evidence_scan_protocol.py', 'evidence_protocol.py',
           'evidence_policy.py', 'evidence_decoder.py', 'evidence_linux.py', '__init__.py')
FILES = {name: PACKAGE_ROOT / name for name in MODULES}
FILES.update({'clamav': LIBRARY, **{name: SIGNATURE_ROOT/name for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd')}})
POLICY = {
    'schema': 1, 'execution_platform': 'linux-amd64-landlock3-seccomp-v1',
    'strict_abi': 'cl_kapit_scanmap_strict_v1', 'input_bytes': 5242880,
    'general': 4, 'parse': 2048, 'heuristic': 8196, 'mail': 0, 'dev': 0,
    'engine': {'0': 33554432, '1': 5242880, '2': 4, '3': 32, '14': 0,
               '15': 1, '17': 2, '23': 0, '25': 1, '26': 1, '31': 60000,
               '32': 100000, '33': 1000, '34': 5242880},
}
POLICY_SHA256 = hashlib.sha256(json.dumps(POLICY, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def expected_engine_readback(field, configured):
    """Exact source-fixed getter semantics; never normalize arbitrary masks."""
    if type(field) is not int or type(configured) is not int or str(field) not in POLICY['engine']:
        _unavailable()
    baseline = POLICY['engine'][str(field)]
    if configured != baseline and not (field in (32, 33) and configured == 1):
        _unavailable()
    # Derived ClamAV exposes the native ENGINE_OPTIONS_DISABLE_PE_STATS bit.
    return 4 if field == 26 else configured


def _unavailable():
    raise EvidenceError('SCANNER_UNAVAILABLE')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _unavailable()
        result[key] = value
    return result


def parse_configuration(raw):
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
            _unavailable()
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                         parse_constant=lambda _: _unavailable())
        if type(doc) is not dict or set(doc) != {'schema', 'policy_sha256', 'signature_generation', 'files'}:
            _unavailable()
        if type(doc['schema']) is not int or doc['schema'] != 1 or doc['policy_sha256'] != POLICY_SHA256:
            _unavailable()
        if type(doc['signature_generation']) is not str or not protocol.HEX.fullmatch(doc['signature_generation']):
            _unavailable()
        if doc['signature_generation'] == '0'*64 or type(doc['files']) is not dict or set(doc['files']) != set(FILES):
            _unavailable()
        for value in doc['files'].values():
            if type(value) is not str or not protocol.HEX.fullmatch(value) or value == '0'*64:
                _unavailable()
        return doc
    except (ValueError, UnicodeError, TypeError, RecursionError):
        _unavailable()


def _read_regular(path, maximum, *, digest_only=False):
    # Fixed immutable-image paths only. No path from the request/config is used.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= maximum:
            _unavailable()
        result = bytearray(); digest = hashlib.sha256(); count = 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - count))
            if not block:
                break
            count += len(block)
            if count > maximum:
                _unavailable()
            digest.update(block)
            if not digest_only:
                result.extend(block)
        after = os.fstat(fd)
        stable = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                               item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if count != info.st_size or stable(after) != stable(info):
            _unavailable()
        return digest.hexdigest() if digest_only else bytes(result)
    finally:
        os.close(fd)


def load_configuration():
    if Path(__file__).parent != PACKAGE_ROOT:
        _unavailable()
    doc = parse_configuration(_read_regular(CONFIG, 16384))
    for name, path in FILES.items():
        if _read_regular(path, 256*1024*1024, digest_only=True) != doc['files'][name]:
            _unavailable()
    return doc


def _scratch_empty():
    # No broad recursive cleanup. Leftovers close this request; parent destroys
    # the exact owned container and tmpfs rather than claiming secure erasure.
    with os.scandir(SCRATCH) as entries:
        if next(entries, None) is not None:
            raise EvidenceError('SCRATCH_CLEANUP_REQUIRED')


def _public_images():
    import io
    import PIL
    from PIL import Image, JpegImagePlugin, PngImagePlugin, ImageOps, ImageFile
    if PIL.__version__ != PILLOW_VERSION:
        _unavailable()
    result = []
    with Image.new('RGB', (1, 1), (1, 2, 3)) as image:
        for format_name, media in [('PNG', 'image/png'), ('JPEG', 'image/jpeg')]:
            sink = io.BytesIO(); image.save(sink, format=format_name)
            result.append((media, sink.getvalue()))
    return tuple(result)


class ScanOptions(c.Structure):
    _fields_ = [(name, c.c_uint32) for name in ('general', 'parse', 'heuristic', 'mail', 'dev')]


class NativeScanner:
    """Only fixed strict exports; diagnostic names are never dereferenced."""
    def __init__(self):
        self.engine = None
        self.library = c.CDLL(str(LIBRARY), mode=os.RTLD_NOW | os.RTLD_LOCAL)
        lib = self.library
        # Missing any exact export raises: no upstream fallback or fake ABI.
        lib.cl_kapit_strict_abi_v1.argtypes = []; lib.cl_kapit_strict_abi_v1.restype = c.c_uint
        if lib.cl_kapit_strict_abi_v1() != 1:
            _unavailable()
        definitions = {
            'cl_init': ([c.c_uint], c.c_int), 'cl_engine_new': ([], c.c_void_p),
            'cl_engine_set_num': ([c.c_void_p, c.c_int, c.c_longlong], c.c_int),
            'cl_engine_get_num': ([c.c_void_p, c.c_int, c.POINTER(c.c_int)], c.c_longlong),
            'cl_engine_set_str': ([c.c_void_p, c.c_int, c.c_char_p], c.c_int),
            'cl_load': ([c.c_char_p, c.c_void_p, c.POINTER(c.c_uint), c.c_uint], c.c_int),
            'cl_engine_compile': ([c.c_void_p], c.c_int),
            'cl_engine_free': ([c.c_void_p], c.c_int),
            'cl_fmap_open_memory': ([c.c_void_p, c.c_size_t], c.c_void_p),
            'cl_fmap_close': ([c.c_void_p], None),
            'cl_kapit_scanmap_strict_v1': ([c.c_void_p, c.c_char_p, c.POINTER(c.c_char_p),
                c.POINTER(c.c_ulong), c.c_void_p, c.POINTER(ScanOptions), c.c_void_p], c.c_int),
        }
        for name, (args, result) in definitions.items():
            fn = getattr(lib, name); fn.argtypes = args; fn.restype = result
        # libclamav's supported message callback suppresses native diagnostics;
        # parent still bounds/discards stderr in case an underlying library writes.
        self._logger_type = c.CFUNCTYPE(None, c.c_int, c.c_char_p, c.c_char_p, c.c_void_p)
        self._logger = self._logger_type(lambda *_: None)
        lib.cl_set_clcb_msg.argtypes = [self._logger_type]; lib.cl_set_clcb_msg.restype = None
        lib.cl_set_clcb_msg(self._logger)
        try:
            if lib.cl_init(0) != 0:
                _unavailable()
            self.engine = lib.cl_engine_new()
            if not self.engine:
                _unavailable()
            for field, value in POLICY['engine'].items():
                error = c.c_int(-1)
                if lib.cl_engine_set_num(self.engine, int(field), value) != 0:
                    _unavailable()
                observed = lib.cl_engine_get_num(self.engine, int(field), c.byref(error))
                if (type(observed) is not int or observed != expected_engine_readback(int(field), value) or
                        error.value != 0):
                    _unavailable()
            if lib.cl_engine_set_str(self.engine, 13, b'/scratch') != 0:
                _unavailable()
            count = c.c_uint(0)
            # OFFICIAL_ONLY + STDOPT, never unsigned bytecode/signature options.
            if lib.cl_load(b'/opt/signatures', self.engine, c.byref(count), 0x300a) != 0 or count.value == 0:
                _unavailable()
            if lib.cl_engine_compile(self.engine) != 0:
                _unavailable()
            self._check_limits()
        except BaseException:
            self.close()
            raise

    def _check_limits(self):
        for field, value in POLICY['engine'].items():
            error = c.c_int(-1)
            observed = self.library.cl_engine_get_num(self.engine, int(field), c.byref(error))
            if (error.value != 0 or type(observed) is not int or
                    observed != expected_engine_readback(int(field), value)):
                _unavailable()

    def scan(self, data, media_type):
        self._check_limits()
        inspect_container(data, media_type)
        buf = c.create_string_buffer(data)
        fmap = self.library.cl_fmap_open_memory(c.cast(buf, c.c_void_p), len(data))
        if not fmap:
            _unavailable()
        try:
            name = c.c_char_p(); scanned = c.c_ulong(0)
            options = ScanOptions(4, 2048, 8196, 0, 0)
            code = self.library.cl_kapit_scanmap_strict_v1(fmap, None, c.byref(name), c.byref(scanned),
                                                        self.engine, c.byref(options), None)
            # Never read name.value, log exceptions, or infer completion from count.
            if type(code) is not int:
                _unavailable()
            if code == 0:
                return 'SCAN_CLEAN'
            if code == 1:
                return 'SCAN_NOT_CLEAN'
            return 'SCANNER_UNAVAILABLE'
        finally:
            self.library.cl_fmap_close(fmap)

    def close(self):
        engine, self.engine = self.engine, None
        if engine and self.library.cl_engine_free(engine) != 0:
            _unavailable()


class Decoder:
    def decode(self, data, media_type):
        return decode_image(data, media_type)

    def close(self):
        return None


def _serve(stdin, stdout, binding, runtime):
    code = 'SCANNER_UNAVAILABLE' if binding.mode == 'scan' else 'DECODE_UNAVAILABLE'
    data = b''; width = height = None
    try:
        media, original = protocol.read_request(stdin, binding)
        if binding.mode == 'scan':
            code = runtime.scan(original, media)
        else:
            result = runtime.decode(original, media)
            code, data, width, height = 'DECODE_COMPLETE', result.data, result.width, result.height
    except Exception:
        pass
    finally:
        try:
            runtime.close()
            _scratch_empty()
        except Exception:
            code = 'SCANNER_UNAVAILABLE' if binding.mode == 'scan' else 'DECODE_UNAVAILABLE'
            data = b''; width = height = None
    protocol.write_result(stdout, binding, code, data=data, width=width, height=height)
    return 0 if code in ('SCAN_CLEAN', 'DECODE_COMPLETE') else 2


def main():
    runtime = None; scratch_fd = None
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ('scan', 'decode') or not protocol.HEX.fullmatch(sys.argv[2]):
            return 2
        config = load_configuration()
        binding = protocol.Binding(sys.argv[1], sys.argv[2], config['policy_sha256'], config['signature_generation'])
        public = _public_images()
        runtime = NativeScanner() if binding.mode == 'scan' else Decoder()
        for media, data in public:
            if binding.mode == 'scan':
                if runtime.scan(data, media) != 'SCAN_CLEAN':
                    _unavailable()
            else:
                runtime.decode(data, media)
        _scratch_empty()
        scratch_fd = os.open(SCRATCH, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        install_abi3_confinement(scratch_fd)
        os.close(scratch_fd); scratch_fd = None
        # Real installation must return before any stdin/header/image access.
        protocol.write_ready(sys.stdout.buffer, binding)
        active, runtime = runtime, None
        return _serve(sys.stdin.buffer, sys.stdout.buffer, binding, active)
    except Exception:
        return 2
    finally:
        if runtime is not None:
            try: runtime.close()
            except Exception: pass
        if scratch_fd is not None:
            try: os.close(scratch_fd)
            except OSError: pass


if __name__ == '__main__':
    raise SystemExit(main())
