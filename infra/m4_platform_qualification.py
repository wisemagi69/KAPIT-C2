"""Finite synthetic Windows backend measurement. Production always closed.

Initial loader/interpreter/dependencies/backend are an externally reviewed trusted
base. Source pins and model outcomes never create trust or activation authority.
Workers test injected fakes only. Native APIs are bound lazily by the opt-in CLI.
"""
import hashlib
import json
import math
import re
import sys
import time
from types import SimpleNamespace

BACKEND_SHA256 = "55192b75a67d0dd54fdd3fd08a8b617d4e4f4739173a30bc51597775f6b9cec8"
ROOT = "C:\\Users\\Ken\\KAPIT-C2"
RECEIPT = "ai/reports/devops-m4-platform-qualification-actual.json"
CASES = ("identity_owner_private", "offset_zero_read", "create_write_flush_readback",
         "fresh_child_replay", "different_operation_same_nonce", "held_sharing_denials",
         "hardlink_duplicate_refusal", "reparse_refusal", "injected_fault_protocol")
METHODS = ("prepare",) + CASES + ("observation", "close")
MAX_REPORT = 16384
MAX_OUTPUT = 4096
MAX_SOURCE = 1048576
EXECUTION_SECONDS = 60
CLEANUP_SECONDS = 5
CHILD_SECONDS = 10


class Refused(ValueError):
    def __init__(self):
        super().__init__("M4_PLATFORM_QUALIFICATION_REFUSED")


class Unavailable(Exception):
    pass


def _need(value):
    if value is not True:
        raise Refused()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def production_qualify(*args, **kwargs):
    raise Refused()


def validate_child_request(nonce, parent_pid, actual_parent_pid):
    _need(type(nonce) is str and re.fullmatch("[0-9a-f]{32}", nonce) is not None)
    _need(type(parent_pid) is str and re.fullmatch("[1-9][0-9]{0,9}", parent_pid) is not None)
    _need(type(actual_parent_pid) is int and int(parent_pid) == actual_parent_pid)
    return nonce


def _case_result(value, expected_kind):
    _need(type(value) is dict and set(value) == {"status", "kind", "code"})
    _need(type(value["status"]) is str and type(value["kind"]) is str)
    _need(value["status"] in ("PASSED", "FAILED", "UNAVAILABLE"))
    _need(value["kind"] == expected_kind)
    _need(type(value["code"]) is str and re.fullmatch("[A-Z][A-Z0-9_]{0,63}", value["code"]) is not None)
    return dict(value)


def run_protocol(lab, *, clock=time.monotonic):
    """Injected protocol seam. Fake results are not native/OS evidence."""
    callbacks = {name: getattr(lab, name) for name in METHODS}
    _need(all(callable(fn) for fn in callbacks.values()) and callable(clock))
    now = clock
    start = last = None
    rows = {name: {"status": "UNAVAILABLE", "kind": "MODEL" if name == CASES[-1] else "ACTUAL",
                   "code": "NOT_REACHED"} for name in CASES}
    result = dict(status="NOT_COMPLETE", qualification_authority=False, production_enabled=False,
                  cases=rows, error_stage="PREPARE", cleanup="NOT_CONFIRMED", elapsed_seconds=0)

    def deadline():
        nonlocal last
        current = now()
        _need(type(current) in (int, float) and math.isfinite(current) and current >= last)
        last = current
        _need(current - start <= EXECUTION_SECONDS)

    failed = False
    try:
        start = now()
        _need(type(start) in (int, float) and math.isfinite(start))
        last = start
        deadline()
        metadata = callbacks["prepare"]()
        _need(type(metadata) is dict and set(metadata) == {"namespace_nonce", "owner_sha256", "restricting_sids_observed"})
        _need(type(metadata["namespace_nonce"]) is str and re.fullmatch("[0-9a-f]{32}", metadata["namespace_nonce"]) is not None)
        _need(type(metadata["owner_sha256"]) is str and re.fullmatch("[0-9a-f]{64}", metadata["owner_sha256"]) is not None)
        _need(type(metadata["restricting_sids_observed"]) is bool)
        result["host_observation"] = dict(metadata)
        deadline()
        for name in CASES:
            result["error_stage"] = name.upper()
            deadline()
            rows[name] = _case_result(callbacks[name](), "MODEL" if name == CASES[-1] else "ACTUAL")
            deadline()
            if rows[name]["status"] == "FAILED":
                failed = True
                break
    except BaseException:
        failed = True
    finally:
        if failed:
            try:
                observation = callbacks["observation"]()
                _need(type(observation) is dict and set(observation) == {"stage", "last_error_observed", "attribution"})
                _need(type(observation["stage"]) is str and re.fullmatch("[A-Z][A-Z0-9_]{0,63}",observation["stage"]) is not None)
                _need(type(observation["last_error_observed"]) is int and 0 <= observation["last_error_observed"] <= 65535)
                _need(observation["attribution"] == "UNCONFIRMED")
                result["failure_observation"] = dict(observation)
            except BaseException:
                pass
        close_started = None
        try:
            close_started = now()
            _need(type(close_started) in (int,float) and math.isfinite(close_started)
                  and (last is None or close_started >= last))
        except BaseException:
            failed = True
            close_started = None
        try:
            _need(callbacks["close"]() is None)
            closed = now()
            _need(close_started is not None and type(closed) in (int, float) and math.isfinite(closed)
                  and closed >= close_started and closed - close_started <= CLEANUP_SECONDS)
            result["cleanup"] = "CONFIRMED_ORIGINAL_CALLBACKS"
        except BaseException:
            result["cleanup"] = "UNCONFIRMED"
            failed = True
        if type(start) in (int,float) and type(last) in (int,float) and math.isfinite(start) and math.isfinite(last):
            result["elapsed_seconds"] = max(0, int(last - start))
    if failed:
        result["status"] = "FAILED_OR_UNCONFIRMED"
    elif any(row["status"] != "PASSED" for row in rows.values()):
        result["status"] = "INCOMPLETE_UNAVAILABLE_REQUIRED_CASES"
    else:
        result["status"] = "MEASURED_MATRIX_ONLY_NOT_PRODUCTION_AUTHORITY"
        result["error_stage"] = "NONE"
    return result


def _passed(kind="ACTUAL", code="OBSERVED_EXPECTATION"):
    return dict(status="PASSED", kind=kind, code=code)


class WinApi:
    """Lazy concrete Windows API bindings; construction forbidden in worker tests."""
    def __init__(self):
        import ctypes as c
        from ctypes import wintypes as w
        _need(sys.platform == "win32")
        self.c, self.w = c, w
        k, a = c.WinDLL("kernel32", use_last_error=True), c.WinDLL("advapi32", use_last_error=True)
        def bind(dll, name, args, returns):
            fn = getattr(dll, name)
            fn.argtypes, fn.restype = args, returns
            return fn
        self.raw = SimpleNamespace(
            current=bind(k,"GetCurrentProcess",[],w.HANDLE),
            token=bind(a,"OpenProcessToken",[w.HANDLE,w.DWORD,c.POINTER(w.HANDLE)],w.BOOL),
            tokeninfo=bind(a,"GetTokenInformation",[w.HANDLE,c.c_int,c.c_void_p,w.DWORD,c.POINTER(w.DWORD)],w.BOOL),
            restricted=bind(a,"IsTokenRestricted",[w.HANDLE],w.BOOL),
            sidtext=bind(a,"ConvertSidToStringSidW",[c.c_void_p,c.POINTER(c.c_void_p)],w.BOOL),
            close=bind(k,"CloseHandle",[w.HANDLE],w.BOOL),
            free=bind(k,"LocalFree",[c.c_void_p],c.c_void_p),
            sddl=bind(a,"ConvertStringSecurityDescriptorToSecurityDescriptorW",[w.LPCWSTR,w.DWORD,c.POINTER(c.c_void_p),c.c_void_p],w.BOOL),
            mkdir=bind(k,"CreateDirectoryW",[w.LPCWSTR,c.c_void_p],w.BOOL),
            create=bind(k,"CreateFileW",[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,w.HANDLE],w.HANDLE),
            write=bind(k,"WriteFile",[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p],w.BOOL),
            flush=bind(k,"FlushFileBuffers",[w.HANDLE],w.BOOL),
            final=bind(k,"GetFinalPathNameByHandleW",[w.HANDLE,w.LPWSTR,w.DWORD,w.DWORD],w.DWORD),
            delete=bind(k,"DeleteFileW",[w.LPCWSTR],w.BOOL),
            move=bind(k,"MoveFileExW",[w.LPCWSTR,w.LPCWSTR,w.DWORD],w.BOOL),
            hardlink=bind(k,"CreateHardLinkW",[w.LPCWSTR,w.LPCWSTR,c.c_void_p],w.BOOL),
            symlink=bind(k,"CreateSymbolicLinkW",[w.LPCWSTR,w.LPCWSTR,w.DWORD],c.c_ubyte))
        self.last_error = c.get_last_error
        self.clear_error = c.set_last_error

    def owner(self):
        c, w, raw = self.c, self.w, self.raw
        close, free = raw.close, raw.free
        clear_error, get_error = self.clear_error, self.last_error
        handle, text = w.HANDLE(), c.c_void_p()
        acquired = False
        try:
            _need(bool(raw.token(raw.current(), 8, c.byref(handle))))
            acquired = True
            needed = w.DWORD()
            _need(not raw.tokeninfo(handle, 1, None, 0, c.byref(needed)))
            _need(1 <= needed.value <= 4096)
            buffer = c.create_string_buffer(needed.value)
            _need(bool(raw.tokeninfo(handle, 1, buffer, needed.value, c.byref(needed))))
            pointer = c.cast(buffer, c.POINTER(c.c_void_p))[0]
            _need(bool(raw.sidtext(pointer, c.byref(text))))
            sid = c.wstring_at(text)
            _need(re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", sid) is not None and len(sid) <= 184)
            clear_error(0)
            restricted = bool(raw.restricted(handle))
            _need(restricted or get_error() == 0)
            # This observes restricting SIDs only, not every token restriction.
            return sid, restricted
        finally:
            failed = False
            if text.value:
                try: _need(not free(text))
                except BaseException: failed = True
            if acquired:
                try: _need(bool(close(handle)))
                except BaseException: failed = True
            _need(not failed)

    def descriptor(self, owner, action):
        c, w, raw = self.c, self.w, self.raw
        free = raw.free
        class Attributes(c.Structure):
            _fields_ = [("length",w.DWORD),("descriptor",c.c_void_p),("inherit",w.BOOL)]
        descriptor = c.c_void_p()
        try:
            sids = sorted(set((owner,"S-1-5-18")))
            _need(bool(raw.sddl("O:"+owner+"D:P"+"".join("(A;;FA;;;"+sid+")" for sid in sids),
                                1,c.byref(descriptor),None)))
            attrs = Attributes(c.sizeof(Attributes),descriptor,False)
            return action(c.byref(attrs))
        finally:
            if descriptor.value:
                _need(not free(descriptor))

    def mkdir(self, path, owner):
        _need(self.descriptor(owner,lambda attrs: bool(self.raw.mkdir(path,attrs))))

    def final_path(self, handle, expected):
        buffer = self.c.create_unicode_buffer(1024)
        size = self.raw.final(handle,buffer,1024,0)
        _need(1 <= size < 1024 and buffer.value.removeprefix("\\\\?\\").casefold() == expected.casefold())

    def create(self, path, owner, payload):
        _need(type(payload) is bytes and len(payload) <= 4096)
        raw, c, w = self.raw, self.c, self.w
        close = raw.close
        handle = None
        try:
            def acquire(attrs):
                nonlocal handle
                handle = raw.create(path,0xc0020000,0,attrs,1,0x00200080,None)
                return None
            self.descriptor(owner,acquire)
            _need(type(handle) is int and handle not in (0,c.c_void_p(-1).value))
            self.final_path(handle,path)
            count = w.DWORD()
            data = c.create_string_buffer(payload)
            _need(bool(raw.write(handle,data,len(payload),c.byref(count),None)) and count.value == len(payload))
            _need(bool(raw.flush(handle)))
        finally:
            if type(handle) is int and handle not in (0,c.c_void_p(-1).value):
                _need(bool(close(handle)))

    def sharing(self, source, moved):
        raw, c = self.raw, self.c
        original_close = raw.close
        handle = raw.create(source,0x40000000,7,None,3,0x00200080,None)
        if type(handle) is int and handle not in (0,c.c_void_p(-1).value):
            _need(bool(original_close(handle)))
            raise Refused()
        _need(self.last_error() == 32)
        _need(not raw.delete(source) and self.last_error() == 32)
        _need(not raw.move(source,moved,0) and self.last_error() == 32)

    def hardlink(self, alias, source):
        if not self.raw.hardlink(alias,source,None):
            raise Unavailable()

    def reparse(self, alias, source):
        if not self.raw.symlink(alias,source,2):
            raise Unavailable()


def _source_file_facts(st):
    import stat
    _need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and
          not getattr(st,"st_file_attributes",0) & 0x400 and 1 <= st.st_size <= MAX_SOURCE)
    fields = (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,
              st.st_mtime_ns,st.st_ctime_ns,getattr(st,"st_file_attributes",0),
              getattr(st,"st_birthtime_ns",None))
    _need(all(type(value) is int for value in fields) and fields[0] >= 0 and fields[1] > 0 and fields[8] >= 0)
    return fields


def _source_parent_facts(st):
    import stat
    _need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
          not getattr(st,"st_file_attributes",0) & 0x400)
    return st.st_dev,st.st_ino,st.st_mode,getattr(st,"st_file_attributes",0)


def _source_identity(path, stream):
    import os
    pathname = _source_file_facts(path.lstat())
    descriptor = _source_file_facts(os.fstat(stream.fileno()))
    # Cross-API ctime meanings differ on Windows. Preserve and recheck BOTH
    # complete API snapshots; common identity/content/birth fields must agree.
    _need(pathname[:6]+pathname[7:] == descriptor[:6]+descriptor[7:])
    parents = tuple((p,_source_parent_facts(p.lstat())) for p in reversed(path.parents))
    return pathname,descriptor,parents


def _recheck_source_identity(path,stream,expected):
    _need(_source_identity(path,stream) == expected)


def _release_backend_module(registry, name, module):
    failed = sys.modules is not registry
    if registry.get(name) is module:
        del registry[name]
    else:
        failed = True
    if any(type(n) is str and n.casefold() == name.casefold() for n in tuple(registry)):
        failed = True
    _need(not failed)


def _load_backend():
    """One exact public initial dependency, externally reviewed; no self-trust."""
    from pathlib import Path
    from types import ModuleType
    import os
    path = Path(ROOT) / "infra/evidence_release_reservations.py"
    name = "_m4_qualification_reviewed_reservations"
    registry = sys.modules
    _need(type(registry) is dict and not any(type(n) is str and n.casefold() == name.casefold() for n in tuple(registry)))
    module = None
    before = _source_file_facts(path.lstat())
    parents = tuple((p,_source_parent_facts(p.lstat())) for p in reversed(path.parents))
    stream = path.open("rb")
    try:
        identity = _source_identity(path,stream)
        _need(identity[0] == before and identity[2] == parents)
        payload = stream.read(MAX_SOURCE+1)
        _need(1 <= len(payload) <= MAX_SOURCE and _sha(payload) == BACKEND_SHA256)
        _recheck_source_identity(path,stream,identity)
        module = ModuleType(name)
        registry[name] = module
        exec(compile(payload,str(path),"exec",dont_inherit=True),module.__dict__)
        _need(sys.modules is registry and registry.get(name) is module)
        _recheck_source_identity(path,stream,identity)
        return module, stream, identity, path, registry
    except BaseException:
        if module is not None and registry.get(name) is module:
            del registry[name]
        stream.close()
        raise


class NativeLab:
    """Root-only native laboratory, fresh synthetic namespace and fixed paths."""
    def __init__(self, *, api=None, backend=None, nonce=None, child_runner=None):
        # Test injections never construct WinApi or import the actual backend.
        self.api = api
        self.backend = backend
        self.nonce = nonce
        self.child_runner = child_runner
        self.cleanups = []
        self.parents = []
        self.closed = self.failed = False
        self.provider = self.store = None
        self.owner = None
        self.stage = "NOT_STARTED"
        self._last_error = lambda: 0
        self.created_directories = self.created_files = self.created_aliases = 0

    def _close_later(self, callback):
        self.cleanups.append(callback)

    def _guard(self):
        _need(not self.failed and not self.closed)
        for original in self.parents:
            original.recheck()
        _need(self.created_directories <= 5 and self.created_files <= 6 and self.created_aliases <= 2)

    def _mkdir(self, path):
        self._guard()
        _need(self.created_directories < 5)
        self.created_directories += 1
        self._api.mkdir(path,self.owner)

    def _create(self, path, payload):
        self._guard()
        _need(self.created_files < 6)
        self.created_files += 1
        self._api.create(path,self.owner,payload)

    def _pin(self, provider, relative, expected, *, private=False):
        obj = provider.pin_parent(relative)
        snap = self.backend.capture_owned(obj,owner=self.owner,directory=True,require_private=private)
        self._close_later(snap.close)
        self.parents.append(snap)
        self._api.final_path(obj.handle,expected)
        return snap

    def prepare(self):
        import secrets
        import ntpath
        if self.api is None:
            self.api = WinApi()
        # Snapshot all lower-level operations before provider constructor callbacks.
        self._api = SimpleNamespace(**{n:getattr(self.api,n) for n in
            ("owner","mkdir","create","final_path","sharing","hardlink","reparse")})
        self._last_error = getattr(self.api,"last_error",lambda:0)
        self.stage = "CURRENT_TOKEN_OWNER"
        self.owner, restricted = self._api.owner()
        _need(type(self.owner) is str and re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+",self.owner) is not None)
        _need(type(restricted) is bool)
        if self.backend is None:
            self.stage = "ADMITTED_BACKEND_SOURCE"
            self.backend, stream, self.backend_identity, self.backend_path, backend_registry = _load_backend()
            self.backend_stream = stream
            self._close_later(stream.close)
            original_module = self.backend
            original_name = original_module.__name__
            def unregister():
                _release_backend_module(backend_registry,original_name,original_module)
            self._close_later(unregister)
        factory = self.backend.CandidateWin32Provider
        parent_root = ntpath.join(ROOT,".cache","m1-runtime")
        self.stage = "EXISTING_PARENT_IDENTITY"
        parent = factory(parent_root,self.owner)
        self._close_later(parent.close)
        self._pin(parent,"",parent_root)
        self.nonce = self.nonce or secrets.token_hex(16)
        _need(re.fullmatch("[0-9a-f]{32}",self.nonce) is not None)
        base = ntpath.join(parent_root,"m4-platform-qualification")
        self.stage = "FRESH_PRIVATE_BASE_CREATION"
        # Base is deliberately fresh too. Existing earlier runs consume this scope.
        self._mkdir(base)
        self._pin(parent,"m4-platform-qualification",base,private=True)
        self.root = ntpath.join(base,self.nonce)
        self.stage = "FRESH_PRIVATE_NAMESPACE_CREATION"
        self._mkdir(self.root)
        self._pin(parent,"m4-platform-qualification/"+self.nonce,self.root,private=True)
        self.provider = factory(self.root,self.owner)
        self._close_later(self.provider.close)
        self._pin(self.provider,"",self.root,private=True)
        for relative in ("ai","ai/state","ai/state/release-reservations-v1"):
            self.stage = "FRESH_PRIVATE_COMPONENT_DIRECTORIES"
            target = ntpath.join(self.root,*relative.split("/"))
            self._mkdir(target)
            self._pin(self.provider,relative,target,private=True)
        self.store = self.backend.ProtectedReservationStore(self.provider,owner=self.owner)
        self.source = ntpath.join(self.root,"public-source.bin")
        self.stage = "FRESH_SYNTHETIC_SOURCE_CREATION"
        self._create(self.source,b"KAPIT-C2-C03-SYNTHETIC\n")
        self.payload = {"authorization_sha256":"a"*64,"source_bundle_sha256":"b"*64}
        self.reservation_nonce = "1"*32
        self._guard()
        return dict(namespace_nonce=self.nonce,owner_sha256=_sha(self.owner.encode("ascii")),restricting_sids_observed=restricted)

    def identity_owner_private(self):
        self._guard()
        identities = []
        for row in self.parents:
            value = row.recheck()
            _need(type(value["volume"]) is int and 1 <= value["volume"] < 2**64)
            _need(re.fullmatch("[0-9a-f]{32}",value["file_id"]) is not None)
            identities.append((value["volume"],value["file_id"]))
        # The root is intentionally pinned through both provider instances.
        _need(len(set(identities)) >= 6)
        return _passed()

    def offset_zero_read(self):
        self._guard()
        obj = self.provider.open_source("public-source.bin")
        snap = self.backend.capture_owned(obj,owner=self.owner,require_private=True)
        self.source_snapshot = snap
        self._close_later(snap.close)
        _need(snap.read_exact(4096) == b"KAPIT-C2-C03-SYNTHETIC\n")
        _need(snap.read_exact(4096) == b"KAPIT-C2-C03-SYNTHETIC\n")
        return _passed()

    def create_write_flush_readback(self):
        self._guard()
        self.reference = self.store.reserve("FRESH_PREFLIGHT",self.reservation_nonce,self.payload)
        self.created_files += 1
        self._guard()
        return _passed()

    def fresh_child_replay(self):
        self._guard()
        import ntpath
        import os
        self.challenge = _canonical(dict(scope="C03_FRESH_REPLAY_ONLY",namespace=self.nonce,
            parent_pid=os.getpid(),reservation_nonce=self.reservation_nonce))
        self._create(ntpath.join(self.root,"child-challenge.json"),self.challenge)
        runner = self.child_runner or _run_child
        _need(runner(self.nonce,os.getpid()) is True)
        return _passed(code="FRESH_PROCESS_EXISTING_ORIGINAL_REFUSED")

    def different_operation_same_nonce(self):
        self._guard()
        refused = False
        try:
            self.store.reserve("ONE_COMPARISON",self.reservation_nonce,self.payload)
        except self.backend.ReservationRefused:
            refused = True
        _need(refused)
        return _passed()

    def held_sharing_denials(self):
        self._guard()
        import ntpath
        self.source_snapshot.recheck()
        self._api.sharing(self.source,ntpath.join(self.root,"unexpected-moved.bin"))
        self.source_snapshot.recheck()
        self.source_snapshot.close()
        return _passed()

    def hardlink_duplicate_refusal(self):
        self._guard()
        import ntpath
        try:
            self._api.hardlink(ntpath.join(self.root,"public-hardlink.bin"),self.source)
        except Unavailable:
            return dict(status="UNAVAILABLE",kind="ACTUAL",code="HARDLINK_FIXTURE_CREATION_DENIED")
        self.created_aliases += 1
        refused = False
        unexpected = None
        try:
            unexpected = self.backend.capture_owned(self.provider.open_source("public-hardlink.bin"),owner=self.owner)
        except self.backend.ReservationRefused:
            refused = True
        finally:
            if unexpected is not None:
                original_close = unexpected.close
                original_close()
        _need(refused)
        return _passed()

    def reparse_refusal(self):
        self._guard()
        import ntpath
        try:
            self._api.reparse(ntpath.join(self.root,"public-reparse.bin"),self.source)
        except Unavailable:
            return dict(status="UNAVAILABLE",kind="ACTUAL",code="REPARSE_FIXTURE_PRIVILEGE_UNAVAILABLE")
        self.created_aliases += 1
        refused = False
        unexpected = None
        try:
            unexpected = self.backend.capture_owned(self.provider.open_source("public-reparse.bin"),owner=self.owner)
        except self.backend.ReservationRefused:
            refused = True
        finally:
            if unexpected is not None:
                original_close = unexpected.close
                original_close()
        _need(refused)
        return _passed()

    def injected_fault_protocol(self):
        # Pure fake-provider regression belongs in source tests, not native facts.
        return dict(status="UNAVAILABLE",kind="MODEL",code="SOURCE_FAULT_TESTS_SEPARATE_NOT_RUNTIME_MEASUREMENT")

    def observation(self):
        code = self._last_error()
        if type(code) is not int or not 0 <= code <= 65535:
            code = 0
        return dict(stage=self.stage,last_error_observed=code,attribution="UNCONFIRMED")

    def close(self):
        if self.closed:
            _need(not self.failed)
            return
        self.closed = True
        for parent in self.parents:
            try: parent.recheck()
            except BaseException: self.failed = True
        if hasattr(self,"backend_stream"):
            try:
                _recheck_source_identity(self.backend_path,self.backend_stream,self.backend_identity)
                self.backend_stream.seek(0)
                _need(_sha(self.backend_stream.read(MAX_SOURCE+1)) == BACKEND_SHA256)
                _recheck_source_identity(self.backend_path,self.backend_stream,self.backend_identity)
            except BaseException:
                self.failed = True
        for callback in reversed(self.cleanups):
            try: _need(callback() is None)
            except BaseException: self.failed = True
        _need(not self.failed)


def _collect_child(process, *, thread_factory=None, clock=time.monotonic):
    """At most4097 bytes per pipe including sentinel; own callbacks captured first."""
    import threading
    factory = thread_factory or threading.Thread
    streams = (process.stdout,process.stderr)
    reads = tuple(stream.read for stream in streams)
    closes = tuple(stream.close for stream in streams)
    wait, poll, kill = process.wait, process.poll, process.kill
    close_process = process._handle.Close
    buffers, errors, workers = [None,None], [False,False], []
    failed = False
    started = None
    def read_one(index):
        try:
            data = reads[index](MAX_OUTPUT+1)
            _need(type(data) is bytes and len(data) <= MAX_OUTPUT)
            buffers[index] = data
        except BaseException:
            errors[index] = True
    try:
        started = clock()
        _need(type(started) in (int,float) and math.isfinite(started))
        for index in range(2):
            worker = factory(target=read_one,args=(index,),daemon=True)
            workers.append(worker)
            worker.start()
        _need(wait(timeout=CHILD_SECONDS) == 0)
    except BaseException:
        failed = True
    finally:
        cleanup_start = None
        try:
            cleanup_start = clock()
            _need(type(cleanup_start) in (int,float) and math.isfinite(cleanup_start)
                  and (started is None or cleanup_start >= started))
        except BaseException:
            failed = True
            cleanup_start = None
        last_cleanup = cleanup_start
        running = True
        try:
            running = poll() is None
        except BaseException:
            failed = True
        if running:
            try: kill()
            except BaseException: failed = True
            try: wait(timeout=CLEANUP_SECONDS)
            except BaseException: failed = True
        for worker in workers:
            try:
                current = clock()
                _need(last_cleanup is not None and type(current) in (int,float) and math.isfinite(current)
                      and current >= last_cleanup)
                last_cleanup = current
                remaining = max(0,CLEANUP_SECONDS-(current-cleanup_start))
                worker.join(timeout=remaining)
                _need(not worker.is_alive())
            except BaseException: failed = True
        for close in closes:
            try: close()
            except BaseException: failed = True
        try: close_process()
        except BaseException: failed = True
        try:
            current = clock()
            _need(last_cleanup is not None and type(current) in (int,float) and math.isfinite(current)
                  and current >= last_cleanup and current-cleanup_start <= CLEANUP_SECONDS)
        except BaseException: failed = True
    _need(not any(errors) and all(type(data) is bytes for data in buffers))
    _need(not failed)
    return tuple(buffers)


def _run_child(nonce, parent_pid):
    """One fixed trusted child; fixed output grammar and original process cleanup."""
    import subprocess
    from pathlib import Path
    command = [sys.executable,"-I","-B",str(Path(ROOT)/"infra/m4_platform_qualification.py"),
               "--internal-replay-only",nonce,str(parent_pid)]
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    process = subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               cwd=ROOT,startupinfo=startup,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    stdout, stderr = _collect_child(process)
    _need(stdout == b"C03_EXISTING_ORIGINAL_REPLAY_REFUSED\n" and stderr == b"")
    return True


def _child(nonce, parent_pid):
    import os
    import ntpath
    nonce = validate_child_request(nonce,parent_pid,os.getppid())
    module, stream, identity, path, registry = _load_backend()
    api, provider, held = None, None, []
    failed = False
    try:
        api = WinApi()
        owner, restricted = api.owner()
        root = ntpath.join(ROOT,".cache","m1-runtime","m4-platform-qualification",nonce)
        provider = module.CandidateWin32Provider(root,owner)
        challenge = module.capture_owned(provider.open_source("child-challenge.json"),owner=owner,require_private=True)
        held.append(challenge)
        expected = _canonical(dict(scope="C03_FRESH_REPLAY_ONLY",namespace=nonce,parent_pid=int(parent_pid),reservation_nonce="1"*32))
        _need(challenge.read_exact(4096) == expected)
        original = module.capture_owned(provider.open_source("ai/state/release-reservations-v1/"+"1"*32+".reservation"),owner=owner,require_private=True)
        held.append(original)
        # Holding the existing original blocks deletion/replacement before CREATE_NEW.
        _need(original.read_exact(4096) == _canonical(dict(schema=1,operation="FRESH_PREFLIGHT",nonce="1"*32,
            authorization_sha256="a"*64,source_bundle_sha256="b"*64)))
        refused = False
        try:
            module.ProtectedReservationStore(provider,owner=owner).reserve("FRESH_PREFLIGHT","1"*32,
                {"authorization_sha256":"a"*64,"source_bundle_sha256":"b"*64})
        except module.ReservationRefused:
            refused = True
        _need(refused)
        original.recheck()
    except BaseException:
        failed = True
    finally:
        for obj in reversed(held):
            try: obj.close()
            except BaseException: failed = True
        if provider is not None:
            try: provider.close()
            except BaseException: failed = True
        try:
            _recheck_source_identity(path,stream,identity)
            stream.seek(0)
            _need(_sha(stream.read(MAX_SOURCE+1)) == BACKEND_SHA256)
            _recheck_source_identity(path,stream,identity)
        except BaseException: failed = True
        try: stream.close()
        except BaseException: failed = True
        try: _release_backend_module(registry,module.__name__,module)
        except BaseException: failed = True
    _need(not failed)
    sys.stdout.buffer.write(b"C03_EXISTING_ORIGINAL_REPLAY_REFUSED\n")
    sys.stdout.buffer.flush()
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if type(args) is not list:
        return 1
    if len(args) == 3 and args[0] == "--internal-replay-only":
        try:
            return _child(args[1],args[2])
        except BaseException:
            print("C03_REPLAY_CHILD_REFUSED")
            return 1
    if args != ["--qualify-new-synthetic-namespace"]:
        print("M4_PLATFORM_OPT_IN_REQUIRED")
        return 1
    report = None
    failed = False
    try:
        from pathlib import Path
        import os
        import stat
        _need(sys.platform == "win32")
        _need(Path(__file__).absolute() == Path(ROOT)/"infra/m4_platform_qualification.py")
        target = Path(ROOT)/RECEIPT
        for ancestor in reversed(target.parents):
            st = ancestor.lstat()
            _need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
                  not getattr(st,"st_file_attributes",0) & 0x400)
        # Mandatory one-use receipt reservation BEFORE any NativeLab/WinApi call.
        report = target.open("xb+")
        report_identity = os.fstat(report.fileno())
        reserved = _canonical(dict(status="RESERVED_NOT_COMPLETE",qualification_authority=False))
        _need(report.write(reserved) == len(reserved))
        report.flush(); os.fsync(report.fileno())
        result = run_protocol(NativeLab())
        result.update(task="TASK-605",backend_sha256=BACKEND_SHA256,
                      crash_power_loss_qualified=False,scanner_workload_measured=False)
        raw = _canonical(result)
        _need(len(raw) <= MAX_REPORT)
        current = target.lstat()
        _need((current.st_dev,current.st_ino) == (report_identity.st_dev,report_identity.st_ino))
        report.seek(0)
        _need(report.write(raw) == len(raw))
        report.truncate(); report.flush(); os.fsync(report.fileno())
        failed = result["status"] == "FAILED_OR_UNCONFIRMED"
    except BaseException:
        failed = True
    finally:
        if report is not None:
            try: report.close()
            except BaseException: failed = True
    print("M4_PLATFORM_MEASUREMENT_FAILED_NO_RETRY" if failed else "M4_PLATFORM_MEASUREMENT_RECORDED_NO_AUTHORITY")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
