"""Trusted evidence-tool control. Native validation remains fail-closed.

Enter current_tools BEFORE opening the business transaction. Call assert_current
inside that transaction immediately before its required audit/COMMIT. Keep the
context until COMMIT and bounded response preparation complete. Exit checks are
defence in depth, not a substitute for the pre-COMMIT assertion.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
import ctypes as c
from ctypes import wintypes as w
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.cache/m1-runtime/evidence-tools'
CONTROL = TOOLS / 'control'
CONTRACT = ROOT / 'contracts/m4/private-evidence-validation.json'
CONTRACT_SHA256 = '0dd9c68967c643f97f8a7dc722d3167231f543ce9e9be7c70be8aa3c88b98ace'
OWNER = 'KAPIT-C2 evidence tool control v1'
WAIT_SECONDS = 5
_LEASE = ContextVar('evidence_tool_lease', default=None)
FAILURE_CODES = frozenset({'PROVENANCE_UNAVAILABLE', 'ISOLATION_UNAVAILABLE',
                           'FENCE_UNAVAILABLE', 'SIGNATURES_STALE', 'SCANNER_UNAVAILABLE',
                           'RESOURCE_LIMIT', 'SCRATCH_CLEANUP_REQUIRED'})


class ToolUnavailable(RuntimeError):
    def __init__(self, code='PROVENANCE_UNAVAILABLE'):
        self.code = code if type(code) is str and code in FAILURE_CODES else 'PROVENANCE_UNAVAILABLE'
        super().__init__(self.code)


def fail(code='PROVENANCE_UNAVAILABLE'):
    raise ToolUnavailable(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def closed_json(raw, limit=65536):
    if type(raw) is not bytes or len(raw) > limit:
        fail()
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail()
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                           parse_constant=lambda _: fail())
        remaining = 2048
        def walk(item, depth=0):
            nonlocal remaining
            remaining -= 1
            if remaining < 0 or depth > 8:
                fail()
            if type(item) is dict:
                for key, child in item.items():
                    walk(key, depth + 1)
                    walk(child, depth + 1)
            elif type(item) is list:
                for child in item:
                    walk(child, depth + 1)
            elif type(item) not in (str, int, bool, type(None)):
                fail()
        walk(value)
        return value
    except ToolUnavailable:
        raise
    except Exception:
        fail()


def checked(path):
    path = Path(path)
    try:
        parts = path.relative_to(ROOT).parts
    except ValueError:
        fail()
    current = ROOT
    for part in ('', *parts):
        if part in ('.', '..'):
            fail()
        if part:
            current /= part
        if current.exists() or current.is_symlink():
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                fail()
    if path.resolve() != path:
        fail()
    return path


class Windows:
    """Owner/DACL checked handle pins and a mandatory Windows byte-range lock."""
    def __init__(self):
        if os.name != 'nt':
            fail('ISOLATION_UNAVAILABLE')
        self.k = c.WinDLL('kernel32', use_last_error=True)
        self.a = c.WinDLL('advapi32', use_last_error=True)
        def bind(dll, name, args, result):
            f = getattr(dll, name)
            f.argtypes, f.restype = args, result
        bind(self.k, 'GetCurrentProcess', [], w.HANDLE)
        bind(self.k, 'CloseHandle', [w.HANDLE], w.BOOL)
        bind(self.k, 'LocalFree', [c.c_void_p], c.c_void_p)
        bind(self.k, 'CreateFileW', [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
        bind(self.k, 'MoveFileExW', [w.LPCWSTR, w.LPCWSTR, w.DWORD], w.BOOL)
        bind(self.a, 'OpenProcessToken', [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL)
        bind(self.a, 'GetTokenInformation', [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
        bind(self.a, 'ConvertSidToStringSidW', [c.c_void_p, c.POINTER(w.LPWSTR)], w.BOOL)
        bind(self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p], w.BOOL)
        bind(self.a, 'SetFileSecurityW', [w.LPCWSTR, w.DWORD, c.c_void_p], w.BOOL)
        bind(self.a, 'GetSecurityInfo', [w.HANDLE, c.c_int, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p), c.c_void_p, c.POINTER(c.c_void_p)], w.DWORD)
        bind(self.a, 'GetSecurityDescriptorControl', [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)], w.BOOL)
        bind(self.a, 'GetAce', [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)], w.BOOL)
        self.user = self.current_user()

    def require(self, value):
        if not value:
            fail()

    def sid(self, value):
        text = w.LPWSTR()
        self.require(self.a.ConvertSidToStringSidW(value, c.byref(text)))
        try:
            return text.value
        finally:
            self.k.LocalFree(c.cast(text, c.c_void_p))

    def current_user(self):
        token = w.HANDLE()
        self.require(self.a.OpenProcessToken(self.k.GetCurrentProcess(), 8, c.byref(token)))
        try:
            size = w.DWORD()
            self.a.GetTokenInformation(token, 1, None, 0, c.byref(size))
            if not 0 < size.value <= 65536:
                fail()
            data = c.create_string_buffer(size.value)
            self.require(self.a.GetTokenInformation(token, 1, data, size, c.byref(size)))
            return self.sid(c.c_void_p.from_buffer(data).value)
        finally:
            self.k.CloseHandle(token)

    def protect(self, path, directory=False):
        flags = 'OICI' if directory else ''
        sids = list(dict.fromkeys(('S-1-5-18', self.user)))
        text = 'D:P' + ''.join(f'(A;{flags};FA;;;{sid})' for sid in sids)
        descriptor = c.c_void_p()
        self.require(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(text, 1, c.byref(descriptor), None))
        try:
            self.require(self.a.SetFileSecurityW(str(checked(path)), 0x80000004, descriptor))
        finally:
            self.k.LocalFree(descriptor)
        with self.pin(path, private=True, directory=directory):
            pass

    def replace(self, source, target):
        # Same-volume atomic replacement with write-through request. This is not
        # a claim of resilience against arbitrary host/storage hardware failure.
        self.require(self.k.MoveFileExW(str(checked(source)), str(checked(target)), 1 | 8))

    def verify_acl(self, handle, directory=False):
        owner, dacl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        if self.a.GetSecurityInfo(handle, 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(descriptor)) != 0:
            fail()
        try:
            control, revision = w.WORD(), w.DWORD()
            self.require(self.a.GetSecurityDescriptorControl(descriptor, c.byref(control), c.byref(revision)))
            if not control.value & 0x1000 or not dacl.value or self.sid(owner) != self.user:
                fail()
            count = c.c_ushort.from_address(dacl.value + 4).value
            expected = list(dict.fromkeys(('S-1-5-18', self.user)))
            if count != len(expected):
                fail()
            actual = []
            for index in range(count):
                ace = c.c_void_p()
                self.require(self.a.GetAce(dacl, index, c.byref(ace)))
                if (c.c_ubyte.from_address(ace.value).value != 0
                        or c.c_ubyte.from_address(ace.value + 1).value != (3 if directory else 0)
                        or w.DWORD.from_address(ace.value + 4).value != 0x1f01ff):
                    fail()
                actual.append(self.sid(ace.value + 8))
            if actual != expected:
                fail()
        finally:
            self.k.LocalFree(descriptor)

    @contextmanager
    def pin(self, path, *, private=False, directory=False, writable=False):
        import msvcrt
        path = checked(path)
        before = path.stat()
        if ((directory and not stat.S_ISDIR(before.st_mode))
                or (not directory and (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1))):
            fail()
        access = 0x20000 | (0x80 if directory else 0x80000000) | (0x40000000 if writable else 0)
        # No FILE_SHARE_DELETE; readers additionally prohibit concurrent writers.
        handle = self.k.CreateFileW(str(path), access, 3 if writable or directory else 1,
                                    None, 3, 0x00200000 | (0x02000000 if directory else 0), None)
        if handle in (None, c.c_void_p(-1).value):
            fail()
        fd = None
        try:
            checked(path)
            if private:
                self.verify_acl(handle, directory)
            if directory:
                yield None
            else:
                fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY))
                handle = None  # CRT now owns the handle.
                observed = os.fstat(fd)
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
                if identity(before) != identity(observed):
                    fail()
                with os.fdopen(fd, 'r+b' if writable else 'rb', buffering=0) as stream:
                    fd = None
                    yield stream
            checked(path)
        finally:
            if fd is not None:
                os.close(fd)
            if handle:
                self.k.CloseHandle(handle)


def _read(stream, limit):
    raw = stream.read(limit + 1)
    if len(raw) > limit:
        fail()
    return raw


def _owner(windows, stack):
    # Pin ancestors against rename/reparse replacement during the critical section.
    path = ROOT
    for part in ('', *CONTROL.relative_to(ROOT).parts):
        if part:
            path /= part
        stack.enter_context(windows.pin(path, directory=True, private=path == CONTROL))
    stream = stack.enter_context(windows.pin(CONTROL / 'owner.json', private=True))
    data = closed_json(_read(stream, 1024), 1024)
    if (type(data) is not dict or type(data.get('schema')) is not int
            or data != {'schema': 1, 'owner': OWNER, 'workspace': hashlib.sha256(str(ROOT).encode()).hexdigest(), 'sid': windows.user}):
        fail()


def _utc_now():
    return datetime.now(timezone.utc)


def _pointer(value):
    if (type(value) is not dict or set(value) != {'schema', 'generation', 'manifest_sha256'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['generation']) is not int or not 1 <= value['generation'] <= 2147483647
            or type(value['manifest_sha256']) is not str
            or not re.fullmatch('[a-f0-9]{64}', value['manifest_sha256'])):
        fail()
    return value


def _state(windows, *, now=None, coherent=True):
    """Missing/unknown state on existing control is NEVER initial activation."""
    now = _utc_now() if now is None else now
    with ExitStack() as stack:
        value = closed_json(_read_pinned(windows, stack, CONTROL / 'state.json', 1024), 1024)
    if (type(value) is not dict or set(value) != {'schema', 'generation', 'manifest_sha256', 'observed_at'}
            or type(value['schema']) is not int or value['schema'] != 1
            or type(value['generation']) is not int or not 0 <= value['generation'] <= 2147483647
            or type(value['manifest_sha256']) is not str
            or (value['generation'] == 0 and value['manifest_sha256'] != '')
            or (value['generation'] > 0 and not re.fullmatch('[a-f0-9]{64}', value['manifest_sha256']))
            or type(value['observed_at']) is not str
            or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?\+00:00', value['observed_at'])):
        fail()
    try:
        observed = datetime.fromisoformat(value['observed_at'])
    except ValueError:
        fail()
    if now < observed:
        fail()  # Persistent UTC high-water rejects resurrection after rollback.
    if coherent:
        path = CONTROL / 'current.json'
        if value['generation'] == 0:
            if path.exists() or path.is_symlink():
                fail()
        else:
            with ExitStack() as stack:
                pointer = _pointer(closed_json(_read_pinned(windows, stack, path, 1024), 1024))
            if pointer['generation'] != value['generation'] or pointer['manifest_sha256'] != value['manifest_sha256']:
                fail()
    return value


def _marker_write(marker, value):
    marker.seek(0)
    marker.write(value)
    marker.flush()
    os.fsync(marker.fileno())


def _atomic_private(windows, name, raw):
    staged = checked(CONTROL / ('staged-' + uuid.uuid4().hex + '.json'))
    with staged.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    windows.protect(staged)
    windows.replace(staged, CONTROL / name)


def _refresh_state(windows, marker):
    now = _utc_now()
    previous = _state(windows, now=now)
    updated = {**previous, 'observed_at': now.isoformat()}
    _marker_write(marker, b'B')
    _atomic_private(windows, 'state.json', canonical(updated))
    if _state(windows) != updated:
        fail()
    _marker_write(marker, b'C')
    return updated


@contextmanager
def _fence(*, wait=WAIT_SECONDS):
    if _LEASE.get() is not None:
        fail('FENCE_UNAVAILABLE')
    import msvcrt
    windows = Windows()
    with ExitStack() as stack:
        _owner(windows, stack)
        stream = stack.enter_context(windows.pin(CONTROL / 'fence.lock', private=True, writable=True))
        started = time.monotonic()
        while True:
            try:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() - started >= min(max(wait, 0), WAIT_SECONDS):
                    fail('FENCE_UNAVAILABLE')
                time.sleep(0.01)
        try:
            stream.seek(0)
            marker = stream.read(2)
            if marker != b'C':
                fail('FENCE_UNAVAILABLE')
            _refresh_state(windows, stream)
            yield windows, stack, stream
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def prepare_control():
    """Explicit operator preparation only; never adopts an existing control root."""
    try:
        windows = Windows()
        checked(CONTROL.parent)
        checked(CONTROL).mkdir()  # Exclusive, no exist_ok/adoption.
        windows.protect(CONTROL, directory=True)
        owner = {'schema': 1, 'owner': OWNER, 'workspace': hashlib.sha256(str(ROOT).encode()).hexdigest(), 'sid': windows.user}
        state = {'schema': 1, 'generation': 0, 'manifest_sha256': '', 'observed_at': _utc_now().isoformat()}
        # Initial dirty marker is cleared only after all three files are private.
        for name, raw in (('owner.json', canonical(owner)), ('fence.lock', b'B'), ('state.json', canonical(state))):
            with (CONTROL / name).open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            windows.protect(CONTROL / name)
        with windows.pin(CONTROL / 'fence.lock', private=True, writable=True) as stream:
            _marker_write(stream, b'C')
        with _fence():
            pass
        return 'CONTROL_PREPARED'
    except ToolUnavailable:
        raise
    except Exception:
        fail()


@dataclass(frozen=True)
class ToolManifest:
    manifest_hash: str
    signature_generation: str
    expires_at: datetime
    policy_generation: int
    contract_sha256: str
    _raw: bytes = field(repr=False)

    def as_provenance(self):
        return closed_json(self._raw)


def _parser(raw):
    try:
        try:
            module = importlib.import_module('apps.operations.evidence_policy')
        except ModuleNotFoundError:
            module = importlib.import_module('backend.apps.operations.evidence_policy')
        return module.parse_manifest(raw, now=datetime.now(timezone.utc))
    except Exception as error:
        fail('SIGNATURES_STALE' if getattr(error, 'code', None) == 'SIGNATURES_STALE' else 'PROVENANCE_UNAVAILABLE')


def _read_pinned(windows, stack, path, limit=65536, private=True):
    stream = stack.enter_context(windows.pin(path, private=private))
    return _read(stream, limit)


def _verify_artifacts(windows, stack, generation, document):
    inventory = closed_json(_read_pinned(windows, stack, generation / 'artifacts.json'))
    if (type(inventory) is not dict or set(inventory) != {'schema', 'files'}
            or type(inventory['schema']) is not int or inventory['schema'] != 1
            or type(inventory['files']) is not list or not 1 <= len(inventory['files']) <= 256):
        fail()
    rows, seen, total = [], set(), 0
    roles = {'decoder', 'scanner', 'python_archive', 'pillow_wheel', 'clamav_archive', 'signature', 'signature_receipt', 'isolation_receipt'}
    for row in inventory['files']:
        if type(row) is not dict or set(row) != {'role', 'path', 'sha256', 'bytes'}:
            fail()
        relative = row['path']
        if (type(row['role']) is not str or row['role'] not in roles or type(relative) is not str or len(relative) > 240
                or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', relative)
                or any(part in ('.', '..') for part in relative.split('/'))
                or relative in seen or type(row['sha256']) is not str or not re.fullmatch(r'[a-f0-9]{64}', row['sha256'])
                or type(row['bytes']) is not int or not 0 < row['bytes'] <= 536870912):
            fail()
        seen.add(relative)
        total += row['bytes']
        if total > 2147483648:
            fail()
        stream = stack.enter_context(windows.pin(TOOLS / relative, private=True))
        digest, size = hashlib.sha256(), 0
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            if size > row['bytes']:
                fail()
            digest.update(chunk)
        if size != row['bytes'] or digest.hexdigest() != row['sha256']:
            fail()
        rows.append(row)
    for role, key in (('python_archive', 'python_artifact_sha256'), ('pillow_wheel', 'pillow_wheel_sha256'), ('clamav_archive', 'clamav_archive_sha256')):
        selected = [row for row in rows if row['role'] == role]
        if len(selected) != 1 or selected[0]['sha256'] != document[key]:
            fail()
    for role, key in (('decoder', 'decoder_tree_sha256'), ('scanner', 'scanner_tree_sha256')):
        selected = sorted((row for row in rows if row['role'] == role), key=lambda row: row['path'])
        if not selected or hashlib.sha256(canonical(selected)).hexdigest() != document[key]:
            fail()
        # Every file in every declared runtime's top-level root must be listed.
        roots = {row['path'].split('/')[0] for row in selected}
        expected = {row['path'] for row in selected}
        actual, count = set(), 0
        for root in roots:
            for parent, dirs, files in os.walk(checked(TOOLS / root), followlinks=False):
                count += 1
                if count > 512:
                    fail()
                stack.enter_context(windows.pin(Path(parent), directory=True, private=True))
                for name in dirs:
                    checked(Path(parent) / name)
                for name in files:
                    actual.add((Path(parent) / name).relative_to(TOOLS).as_posix())
        if actual != expected:
            fail()
    signatures = [row for row in rows if row['role'] == 'signature']
    if len(signatures) != 3 or {Path(row['path']).name: row['sha256'] for row in signatures} != {row['name']: row['sha256'] for row in document['signature_files']}:
        fail()
    receipt_hashes = {row['sha256'] for row in rows if row['role'] == 'signature_receipt'}
    if document['signature_verification_receipt_sha256'] not in receipt_hashes or any(row['verification_receipt_sha256'] not in receipt_hashes for row in document['signature_files']):
        fail()
    if document['isolation_profile_sha256'] not in {row['sha256'] for row in rows if row['role'] == 'isolation_receipt'}:
        fail()


def _verify_native_trust(document):
    # Intentionally no JSON PASS flag/caller callback unlocks this branch. Actual
    # official signature receipt verification and reviewed quota-capable runtime
    # binding require a separately reviewed integration, not artifact existence.
    fail('ISOLATION_UNAVAILABLE')


def _load(windows, stack, pointer_name='current.json'):
    state = _state(windows)
    pointer = _pointer(closed_json(_read_pinned(windows, stack, CONTROL / pointer_name, 1024), 1024))
    if ((pointer_name == 'current.json' and (pointer['generation'] != state['generation'] or pointer['manifest_sha256'] != state['manifest_sha256']))
            or (pointer_name == 'candidate.json' and pointer['generation'] <= state['generation'])):
        fail()
    generation = CONTROL / 'generations' / str(pointer['generation'])
    stack.enter_context(windows.pin(generation, directory=True, private=True))
    raw = _read_pinned(windows, stack, generation / 'manifest.json')
    parsed = _parser(raw)
    document = parsed.as_provenance()
    if (parsed.manifest_hash != pointer['manifest_sha256'] or parsed.policy_generation != pointer['generation']
            or document['contract_sha256'] != CONTRACT_SHA256
            or hashlib.sha256(_read_pinned(windows, stack, CONTRACT, private=False)).hexdigest() != CONTRACT_SHA256):
        fail()
    # Bind the reviewed pure policy helper and exact limits as well as trees.
    helper = ROOT / 'backend/apps/operations/evidence_policy.py'
    if hashlib.sha256(_read_pinned(windows, stack, helper, 262144, private=False)).hexdigest() != document['helper_sha256']:
        fail()
    contract = closed_json(_read_pinned(windows, stack, CONTRACT, private=False))
    if hashlib.sha256(canonical(contract['bounds'])).hexdigest() != document['limits_sha256']:
        fail()
    _verify_artifacts(windows, stack, generation, document)
    _verify_native_trust(document)
    return ToolManifest(parsed.manifest_hash, parsed.signature_generation, parsed.expires_at,
                        parsed.policy_generation, document['contract_sha256'], canonical(document))


@contextmanager
def current_tools():
    """Fixed trusted pointer only; no activation, native execution or network."""
    try:
        with _fence() as (windows, stack, marker):
            manifest = _load(windows, stack)
            token = _LEASE.set((manifest, windows, stack, marker))
            try:
                yield manifest
                assert_current(manifest)
            finally:
                _LEASE.reset(token)
    except ToolUnavailable:
        raise
    except Exception:
        fail()


def assert_current(manifest):
    lease = _LEASE.get()
    if lease is None or manifest is not lease[0]:
        fail()
    try:
        # Existing handles stay pinned; new reads recheck bytes, current pointer,
        # ACL, contract, freshness and artifact identity while the fence is held.
        _refresh_state(lease[1], lease[3])
        with ExitStack() as checks:
            observed = _load(lease[1], checks)
            if observed != manifest:
                fail()
    except ToolUnavailable:
        raise
    except Exception:
        fail()


def activate():
    """Explicit fixed candidate only. Remains unavailable until native proof."""
    try:
        with _fence() as (windows, stack, marker):
            manifest = _load(windows, stack, 'candidate.json')
            # _verify_native_trust currently always refuses before this point;
            # adding a real verifier requires separate source review. Tests can
            # exercise this compensation path without enabling native helpers.
            state = _state(windows)
            if manifest.policy_generation <= state['generation']:
                fail()
            # Durable dirty marker BEFORE mutation. Crash/failure leaves it B;
            # subsequent entry refuses rather than adopting an uncertain switch.
            _marker_write(marker, b'B')
            now = _utc_now()
            if now < datetime.fromisoformat(state['observed_at']):
                fail()
            updated = {'schema': 1, 'generation': manifest.policy_generation,
                       'manifest_sha256': manifest.manifest_hash, 'observed_at': now.isoformat()}
            # High-water first: a lost/interrupted pointer can never turn an
            # already-used control back into a first activation.
            _atomic_private(windows, 'state.json', canonical(updated))
            _atomic_private(windows, 'current.json', canonical({'schema': 1, 'generation': manifest.policy_generation,
                                                               'manifest_sha256': manifest.manifest_hash}))
            with ExitStack() as verification:
                if _state(windows) != updated or _load(windows, verification) != manifest:
                    fail()
            _marker_write(marker, b'C')
            return 'GENERATION_ACTIVATED'
    except ToolUnavailable:
        raise
    except Exception:
        fail()


def run_scan(data, *, manifest, media_type=None):
    fail('ISOLATION_UNAVAILABLE')


def decode(data, *, manifest, media_type):
    fail('ISOLATION_UNAVAILABLE')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare-control', 'activate', 'status'))
    args = parser.parse_args(argv)
    try:
        if args.action == 'prepare-control':
            status = prepare_control()
        elif args.action == 'activate':
            status = activate()
        else:
            with current_tools():
                status = 'CURRENT_VERIFIED'
        print(json.dumps({'status': status}))
        return 0
    except Exception as error:
        code = error.code if isinstance(error, ToolUnavailable) else 'PROVENANCE_UNAVAILABLE'
        print(json.dumps({'status': 'UNAVAILABLE', 'code': code}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
