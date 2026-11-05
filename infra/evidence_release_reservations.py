"""Original-handle reservation protocol and unqualified lazy Win32 source adapter.

Injected facts are synthetic protocol evidence, never production authority.
No old reservation is opened, repaired, renamed or erased. Production stays shut.
"""
from dataclasses import dataclass
import json
import re
from functools import wraps
from types import SimpleNamespace


class ReservationRefused(RuntimeError):
    pass


def _opaque(callback):
    """Discard private exception objects before exposing a fixed public error."""
    @wraps(callback)
    def wrapped(*args, **kwargs):
        failed = False
        try:
            result = callback(*args, **kwargs)
        except BaseException:
            failed = True
        if failed:
            raise ReservationRefused()
        return result
    return wrapped


def _need(value):
    if value is not True:
        raise ReservationRefused()


def validate_identity(value, *, owner, directory=False, require_private=False):
    _need(type(directory) is bool and type(require_private) is bool)
    _need(type(owner) is str and 1 <= len(owner) <= 184 and owner.isascii()
          and all(33 <= ord(c) <= 126 for c in owner))
    _need(type(value) is dict and set(value) == {
        'volume', 'file_id', 'attributes', 'links', 'size', 'disk', 'private', 'owner'})
    _need(type(value['volume']) is int and 1 <= value['volume'] < 2**64)
    _need(type(value['file_id']) is str and re.fullmatch('[0-9a-f]{32}', value['file_id']) is not None
          and value['file_id'] != '0'*32)
    _need(type(value['attributes']) is int and 0 <= value['attributes'] < 2**32)
    _need(not value['attributes'] & (0x400 | 0x40)
          and bool(value['attributes'] & 0x10) is directory)
    _need(type(value['links']) is int and value['links'] == 1)
    _need(type(value['size']) is int and 0 <= value['size'] <= (2**63-1 if directory else 1048576))
    _need(value['disk'] is True and type(value['private']) is bool
          and (not require_private or value['private'] is True)
          and type(value['owner']) is str and value['owner'] == owner)
    return dict(value)


class OwnedSnapshot:
    """Capture original bound callbacks before the first observation.

    This object does not attest the OS or its own final close. Close is attempted
    once; failure is sticky and is never converted to success by retry.
    """
    @_opaque
    def __init__(self, obj, *, owner, directory=False, writable=False, require_private=False):
        self.owner, self.directory, self.require_private = owner, directory, require_private
        self.closed = self.failed = False
        self._close = getattr(obj, 'close')
        try:
            self._identity = getattr(obj, 'identity')
            self._read = None if directory else getattr(obj, 'read')
            self._write = getattr(obj, 'write') if writable else None
            self._flush = getattr(obj, 'flush') if writable else None
            _need(all(callable(x) for x in (self._close, self._identity)))
            _need(directory or callable(self._read))
            _need(not writable or (callable(self._write) and callable(self._flush)))
            self.original_identity = validate_identity(self._identity(), owner=owner, directory=directory, require_private=require_private)
        except BaseException:
            self.failed = True
            try:
                self.close()
            except BaseException:
                pass
            raise ReservationRefused() from None

    @_opaque
    def recheck(self):
        _need(not self.closed and not self.failed)
        try:
            current = validate_identity(self._identity(), owner=self.owner, directory=self.directory, require_private=self.require_private)
            _need(current == self.original_identity)
            return dict(current)
        except BaseException:
            self.failed = True
            raise ReservationRefused() from None

    @_opaque
    def read_exact(self, maximum):
        _need(type(maximum) is int and 0 <= maximum <= 1048576 and not self.directory)
        before = self.recheck()
        try:
            _need(before['size'] <= maximum)
            raw = self._read(maximum + 1)
            _need(type(raw) is bytes and len(raw) == before['size'] and len(raw) <= maximum)
            self.recheck()
            return raw
        except BaseException:
            self.failed = True
            raise ReservationRefused() from None

    @_opaque
    def write_exact(self, payload):
        before = self.recheck()
        try:
            _need(type(payload) is bytes and 1 <= len(payload) <= 4096
                  and before['size'] == 0 and self._write is not None)
            count = self._write(payload)
            _need(type(count) is int and count == len(payload))
            after = validate_identity(self._identity(), owner=self.owner, require_private=self.require_private)
            expected = dict(before, size=len(payload))
            _need(after == expected)
            self.original_identity = expected
        except BaseException:
            self.failed = True
            raise ReservationRefused() from None

    @_opaque
    def flush(self):
        self.recheck()
        try:
            _need(self._flush is not None and self._flush() is None)
            self.recheck()
        except BaseException:
            self.failed = True
            raise ReservationRefused() from None

    @_opaque
    def close(self):
        if not self.closed:
            self.closed = True
            try:
                _need(self._close() is None)
            except BaseException:
                self.failed = True
        if self.failed:
            raise ReservationRefused()


def capture_owned(obj, *, owner, directory=False, writable=False, require_private=False):
    return OwnedSnapshot(obj, owner=owner, directory=directory, writable=writable, require_private=require_private)


@_opaque
def _capture_ancestor(obj, *, owner, repository_root):
    """Transfer once: initial metadata failure and capture failure own cleanup."""
    close = obj.close
    failed = False
    try:
        actual = obj.identity()
        expected_owner = owner if repository_root else actual.get('owner')
    except BaseException:
        failed = True
    if failed:
        try: close()
        except BaseException: pass
        raise ReservationRefused()
    # capture_owned owns cleanup on its own failure. Do not close it twice.
    return capture_owned(obj, owner=expected_owner, directory=True)


@dataclass(frozen=True)
class ReservationRef:
    operation: str
    nonce: str
    authorization_sha256: str
    source_bundle_sha256: str
    identity: tuple
    production_eligible: bool = False


class ProtectedReservationStore:
    """Provider-backed source protocol; fresh stores cannot reuse existing names."""
    @_opaque
    def __init__(self, provider, *, owner):
        # Capture before callbacks can replace provider attributes.
        self._pin = provider.pin_parent
        self._create = provider.create_new
        self.owner = owner

    @_opaque
    def reserve(self, operation, nonce, payload):
        _need(type(operation) is str and operation in ('FRESH_PREFLIGHT', 'ONE_COMPARISON'))
        _need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}', nonce) is not None)
        _need(type(payload) is dict and set(payload) == {'authorization_sha256','source_bundle_sha256'})
        authorization = payload['authorization_sha256']
        source_bundle = payload['source_bundle_sha256']
        _need(type(authorization) is str and re.fullmatch('[0-9a-f]{64}', authorization) is not None)
        _need(type(source_bundle) is str and re.fullmatch('[0-9a-f]{64}', source_bundle) is not None)
        raw = json.dumps({'schema': 1, 'operation': operation, 'nonce': nonce,
                          'authorization_sha256': authorization, 'source_bundle_sha256': source_bundle}, sort_keys=True,
                         separators=(',', ':'), ensure_ascii=True).encode('ascii')
        held, failed, result = [], False, None
        try:
            for relative in ('', 'ai', 'ai/state', 'ai/state/release-reservations-v1'):
                held.append(capture_owned(self._pin(relative), owner=self.owner, directory=True,
                                          require_private=relative == 'ai/state/release-reservations-v1'))
            for parent in held:
                parent.recheck()
            identities = {(item.original_identity['volume'], item.original_identity['file_id']) for item in held}
            _need(len(identities) == len(held))
            # Nonce alone names the reservation: different operations collide.
            obj = self._create('ai/state/release-reservations-v1/'+nonce+'.reservation', raw)
            original = capture_owned(obj, owner=self.owner, writable=True, require_private=True)
            held.append(original)
            _need((original.original_identity['volume'], original.original_identity['file_id']) not in identities)
            _need(original.original_identity['size'] == 0)
            for parent in held[:-1]:
                parent.recheck()
            original.write_exact(raw)
            original.flush()
            _need(original.read_exact(4096) == raw)
            for resource in held:
                resource.recheck()
            facts = original.original_identity
            result = ReservationRef(operation, nonce, authorization, source_bundle, (facts['volume'], facts['file_id']))
        except BaseException:
            failed = True
        finally:
            # Always unwind every original even if another close fails.
            for resource in reversed(held):
                try:
                    if not resource.failed:
                        resource.recheck()
                except BaseException:
                    failed = True
                try:
                    resource.close()
                except BaseException:
                    failed = True
        if failed:
            raise ReservationRefused() from None
        return result


def production_open(*args, **kwargs):
    """Unconditional boundary, before inspecting caller inputs or a backend."""
    raise ReservationRefused('External qualification and trust admission required')


class CandidateWin32Provider:
    """Unqualified source adapter. Explicit construction alone binds WinDLLs.

    The outside authority must authenticate this backend and its root/owner.
    Construction never creates a directory or changes an existing ACL. No
    production admission is provided; callers must close the held root chain.
    """
    @_opaque
    def __init__(self, root, owner):
        import ctypes as c
        from ctypes import wintypes as w
        import ntpath
        _need(type(root) is str and ntpath.isabs(root) and not root.startswith('\\\\')
              and not any(x in root for x in ('/', '..', '\x00')))
        _need(type(owner) is str and re.fullmatch(r'S-1-(?:[0-9]+-)*[0-9]+', owner) is not None
              and len(owner) <= 184)
        self.c, self.w, self.root, self.owner = c, w, ntpath.normpath(root), owner
        self.k = c.WinDLL('kernel32', use_last_error=True)
        self.a = c.WinDLL('advapi32', use_last_error=True)
        def bind(dll, name, args, restype):
            fn = getattr(dll, name); fn.argtypes, fn.restype = args, restype
            return fn
        self._create = bind(self.k, 'CreateFileW', [w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE], w.HANDLE)
        self._close = bind(self.k, 'CloseHandle', [w.HANDLE], w.BOOL)
        self._kind = bind(self.k, 'GetFileType', [w.HANDLE], w.DWORD)
        self._info = bind(self.k, 'GetFileInformationByHandleEx', [w.HANDLE,c.c_int,c.c_void_p,w.DWORD], w.BOOL)
        self._basic = bind(self.k, 'GetFileInformationByHandle', [w.HANDLE,c.c_void_p], w.BOOL)
        self._read = bind(self.k, 'ReadFile', [w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p], w.BOOL)
        self._write = bind(self.k, 'WriteFile', [w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p], w.BOOL)
        self._seek = bind(self.k, 'SetFilePointerEx', [w.HANDLE,c.c_longlong,c.c_void_p,w.DWORD], w.BOOL)
        self._flush = bind(self.k, 'FlushFileBuffers', [w.HANDLE], w.BOOL)
        self._free = bind(self.k, 'LocalFree', [c.c_void_p], c.c_void_p)
        self._sddl = bind(self.a, 'ConvertStringSecurityDescriptorToSecurityDescriptorW', [w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p], w.BOOL)
        self._security = bind(self.a, 'GetSecurityInfo', [w.HANDLE,c.c_int,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p,c.POINTER(c.c_void_p),c.c_void_p,c.POINTER(c.c_void_p)], w.DWORD)
        self._control = bind(self.a, 'GetSecurityDescriptorControl', [c.c_void_p,c.POINTER(w.WORD),c.POINTER(w.DWORD)], w.BOOL)
        self._sidtext = bind(self.a, 'ConvertSidToStringSidW', [c.c_void_p,c.POINTER(c.c_void_p)], w.BOOL)
        self._acl = bind(self.a, 'GetAclInformation', [c.c_void_p,c.c_void_p,w.DWORD,c.c_int], w.BOOL)
        self._ace = bind(self.a, 'GetAce', [c.c_void_p,w.DWORD,c.POINTER(c.c_void_p)], w.BOOL)
        self._roots = []; self._close_failed = False
        try:
            drive, tail = ntpath.splitdrive(self.root)
            _need(re.fullmatch('[A-Za-z]:', drive) is not None)
            paths = [drive+'\\']
            for part in tail.strip('\\').split('\\'):
                if part:
                    _need(part not in ('.','..') and not part.endswith((' ','.')) and ':' not in part)
                    paths.append(ntpath.join(paths[-1], part))
            for path in paths:
                obj = self._open(path, directory=True)
                snapshot = _capture_ancestor(obj, owner=owner,
                                             repository_root=path.casefold() == self.root.casefold())
                self._roots.append(snapshot)
        except BaseException:
            try: self.close()
            except BaseException: pass
            raise ReservationRefused() from None

    def _path(self, relative):
        import ntpath
        _need(type(relative) is str and relative.isascii() and len(relative) <= 240)
        parts = relative.split('/') if relative else []
        _need(all(re.fullmatch('[a-z0-9_][a-z0-9_.-]*', p) is not None
                  and p not in ('.','..') and not p.endswith('.') for p in parts))
        for root in self._roots:
            root.recheck()
        return ntpath.join(self.root, *parts)

    def _open(self, path, *, directory=False, create=False):
        c, w = self.c, self.w
        original_close = self._close
        class Attributes(c.Structure):
            _fields_ = [('length',w.DWORD),('descriptor',c.c_void_p),('inherit',w.BOOL)]
        descriptor = c.c_void_p(); handle = None; failed = False
        try:
            attrs = None
            if create:
                sids = sorted(set((self.owner, 'S-1-5-18')))
                sddl = 'O:'+self.owner+'D:P'+''.join('(A;;FA;;;'+sid+')' for sid in sids)
                _need(bool(self._sddl(sddl,1,c.byref(descriptor),None)))
                attrs = Attributes(c.sizeof(Attributes),descriptor,False)
            handle = self._create(path, 0xc0020000 if create else 0x80020000, 0 if create else 1,
                                  c.byref(attrs) if attrs else None, 1 if create else 3,
                                  0x00200000 | (0x02000000 if directory else 0x80), None)
            _need(type(handle) is int and handle not in (0,c.c_void_p(-1).value))
        except BaseException:
            failed = True
        finally:
            if descriptor.value:
                try: _need(not self._free(descriptor))
                except BaseException: failed = True
        if failed:
            if type(handle) is int and handle not in (0,c.c_void_p(-1).value):
                try: original_close(handle)
                except BaseException: pass
            raise ReservationRefused()
        return _transfer_win32(self, handle, original_close)

    @_opaque
    def pin_parent(self, relative):
        return self._open(self._path(relative), directory=True)

    @_opaque
    def open_source(self, relative):
        return self._open(self._path(relative))

    @_opaque
    def create_new(self, relative, payload):
        _need(type(payload) is bytes and 1 <= len(payload) <= 4096
              and type(relative) is str and re.fullmatch(r'ai/state/release-reservations-v1/[0-9a-f]{32}\.reservation', relative) is not None)
        return self._open(self._path(relative), create=True)

    @_opaque
    def close(self):
        failed = self._close_failed
        for obj in reversed(self._roots):
            try: obj.close()
            except BaseException: failed = True
        self._roots = []
        self._close_failed = failed
        if failed: raise ReservationRefused()

    def _sid(self, pointer):
        c = self.c; text = c.c_void_p()
        _need(bool(self._sidtext(pointer,c.byref(text))))
        try: return c.wstring_at(text)
        finally: _need(not self._free(text))

    def _private(self, handle):
        c, w = self.c, self.w
        owner, acl, descriptor = c.c_void_p(), c.c_void_p(), c.c_void_p()
        _need(self._security(handle,1,5,c.byref(owner),None,c.byref(acl),None,c.byref(descriptor)) == 0)
        try:
            control, revision = w.WORD(), w.DWORD()
            _need(bool(self._control(descriptor,c.byref(control),c.byref(revision))))
            actual_owner = self._sid(owner)
            if not (control.value & 0x1000 and acl.value and actual_owner == self.owner):
                return actual_owner, False
            class AclSize(c.Structure):
                _fields_ = [('count',w.DWORD),('used',w.DWORD),('free',w.DWORD)]
            info = AclSize()
            _need(bool(self._acl(acl,c.byref(info),c.sizeof(info),2)))
            expected = set((self.owner,'S-1-5-18')); seen = set()
            if info.count != len(expected): return actual_owner, False
            for index in range(info.count):
                ace = c.c_void_p()
                _need(bool(self._ace(acl,index,c.byref(ace))))
                header = c.string_at(ace,8)
                if not (header[0] == 0 and header[1] == 0 and int.from_bytes(header[2:4],'little') >= 12
                        and int.from_bytes(header[4:8],'little') == 0x1f01ff):
                    return actual_owner, False
                sid = self._sid(c.c_void_p(ace.value+8))
                if sid not in expected or sid in seen: return actual_owner, False
                seen.add(sid)
            return actual_owner, seen == expected
        finally: _need(not self._free(descriptor))


@_opaque
def _transfer_win32(provider, handle, original_close):
    failed = False
    try:
        owned = _Win32Owned(provider, handle, original_close=original_close)
    except BaseException:
        failed = True
    if failed:
        try: _need(bool(original_close(handle)))
        except BaseException: pass
        raise ReservationRefused()
    return owned


class _Win32Owned:
    def __init__(self, provider, handle, *, original_close=None):
        # Own exact original callbacks, not a mutable provider lookup at cleanup.
        self.p = SimpleNamespace(**{name:getattr(provider,name) for name in (
            'c','w','owner','_basic','_info','_kind','_read','_write','_seek','_flush',
            '_security','_control','_sidtext','_acl','_ace','_free')})
        self.p._close = provider._close if original_close is None else original_close
        snapshot = self.p
        sid_function, private_function = CandidateWin32Provider._sid, CandidateWin32Provider._private
        snapshot._sid = lambda pointer: sid_function(snapshot,pointer)
        snapshot._private = lambda original: private_function(snapshot,original)
        self.handle, self.failed = handle, False

    def identity(self):
        p = self.p; c, w = p.c, p.w
        _need(self.handle is not None and not self.failed)
        class Basic(c.Structure):
            _fields_ = [('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),('write',w.FILETIME),
                        ('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),
                        ('index_high',w.DWORD),('index_low',w.DWORD)]
        class Full(c.Structure):
            _fields_ = [('volume',c.c_uint64),('file_id',c.c_ubyte*16)]
        basic, full = Basic(), Full()
        _need(c.sizeof(Full) == 24 and Full.file_id.offset == 8
              and bool(p._basic(self.handle,c.byref(basic)))
              and bool(p._info(self.handle,18,c.byref(full),c.sizeof(full))))
        owner, private = p._private(self.handle)
        return {'volume':full.volume,'file_id':bytes(full.file_id).hex(),
                'attributes':basic.attributes,'links':basic.links,
                'size':basic.size_high << 32 | basic.size_low,
                'disk':p._kind(self.handle) == 1,'private':private,'owner':owner}

    def read(self, maximum):
        p=self.p; c,w=p.c,p.w
        _need(self.handle is not None and type(maximum) is int and 0 <= maximum <= 1048577)
        _need(bool(p._seek(self.handle,0,None,0)))
        buf, count = c.create_string_buffer(maximum), w.DWORD()
        _need(bool(p._read(self.handle,buf,maximum,c.byref(count),None)))
        _need(count.value <= maximum)
        return bytes(buf.raw[:count.value])

    def write(self, payload):
        p=self.p; c,w=p.c,p.w
        _need(self.handle is not None and type(payload) is bytes and len(payload) <= 4096)
        _need(bool(p._seek(self.handle,0,None,0)))
        buf,count=c.create_string_buffer(payload),w.DWORD()
        _need(bool(p._write(self.handle,buf,len(payload),c.byref(count),None)))
        return count.value

    def flush(self):
        _need(self.handle is not None and bool(self.p._flush(self.handle)))

    def close(self):
        if self.handle is not None:
            handle,self.handle=self.handle,None
            try: _need(bool(self.p._close(handle)))
            except BaseException: self.failed=True
        if self.failed: raise ReservationRefused()
