"""Source-only private-job watchdog candidate; production authority always false.

Native bindings/target execution require a later distinct reviewed operation.
Interpreter, stdlib and this module are initial externally admitted trusted base.
"""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import time

ROOT = Path("C:/Users/Ken/KAPIT-C2")
TARGET = ROOT / "infra/m4_platform_qualification.py"
BACKEND = ROOT / "infra/evidence_release_reservations.py"
# Direct base interpreter: a venv redirector would consume another process slot.
INTERPRETER = Path("C:/Users/Ken/AppData/Local/Programs/Python/Python314/python.exe")
SOURCE_PINS = ((TARGET,"e2f5414b13bbfe8bff49d93ac5280a8e8f70e549e775930acab4d83c70b113d8"),
               (BACKEND,"55192b75a67d0dd54fdd3fd08a8b617d4e4f4739173a30bc51597775f6b9cec8"),
               (INTERPRETER,"7ca24f26d6e3f463419ee4f537ddd3acd312c38fe45e678cce08572f26a8bd1a",106328))
WATCHDOG_RECEIPT = ROOT / "ai/reports/devops-m4-platform-watchdog-actual.json"
TARGET_RECEIPT = ROOT / "ai/reports/devops-m4-platform-qualification-actual.json"
MAX_SOURCE = 1048576
MAX_OUTPUT = 4096
MAX_RECEIPT = 16384
RUN_SECONDS = 60
CLEANUP_SECONDS = 5
MAX_RUN_POLLS = 6000
MAX_CLEANUP_POLLS = 500
JOB_FLAGS = 0x2208
JOB_MEMORY = 256 * 1024 * 1024
SUCCESS_LINES = (b"M4_PLATFORM_MEASUREMENT_RECORDED_NO_AUTHORITY\n",
                 b"M4_PLATFORM_MEASUREMENT_RECORDED_NO_AUTHORITY\r\n")
PROVIDER_METHODS = ("create_job","configure","limits","create_pipes","inheritable",
    "create_suspended_atomic","member","resume","peek","read","poll_exit","active","terminate")


class Refused(ValueError):
    def __init__(self,code="API_FAILURE"):
        super().__init__("M4_WATCHDOG_REFUSED")
        allowed={"API_FAILURE","CLOCK_INVALID","TIMEOUT","OUTPUT_LIMIT","NONZERO_EXIT","BAD_OUTPUT",
                 "CONTAINMENT_MISMATCH","CLEANUP_UNCONFIRMED","SOURCE_OR_RECEIPT_FAILURE"}
        self.code=code if type(code) is str and code in allowed else "API_FAILURE"


def need(condition,code="API_FAILURE"):
    if condition is not True:
        raise Refused(code)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")


def production_execute(*args, **kwargs):
    raise Refused()


@dataclass(frozen=True)
class Token:
    value: int
    close: object


class Owners:
    def __init__(self):
        self.tokens=[];self.attempted=set();self.failed=False

    def adopt_many(self,objects,count):
        need(type(objects) is tuple)
        result=[];bad=len(objects)!=count
        for obj in objects:
            close=None;already_owned=False
            try:
                close=obj.close
                value=obj.value
                need(callable(close) and type(value) is int and value > 0)
                already_owned=value in {token.value for token in self.tokens if id(token) not in self.attempted}
                need(not already_owned)
                token=Token(value,close)
                self.tokens.append(token);result.append(token)
            except BaseException:
                bad=True
                if callable(close) and not already_owned:
                    try: need(close() is None)
                    except BaseException: self.failed=True
        need(not bad)
        return tuple(result)

    def close_one(self,token):
        if id(token) not in self.attempted:
            self.attempted.add(id(token))
            try: need(token.close() is None)
            except BaseException: self.failed=True
        need(not self.failed)

    def close_all(self):
        for token in reversed(self.tokens):
            try:self.close_one(token)
            except BaseException:self.failed=True
        need(not self.failed)


def _limits(value):
    need(type(value) is dict and set(value)=={"flags","active","memory"})
    need(all(type(v) is int for v in value.values()))
    need(value==dict(flags=JOB_FLAGS,active=2,memory=JOB_MEMORY))


def _counts(value,last_total):
    need(type(value) is dict and set(value)=={"active","total"})
    need(all(type(v) is int for v in value.values()))
    need(0<=value["active"]<=value["total"]<=2 and value["total"]>=last_total)
    return value["active"],value["total"]


def _main_state(value):
    need(type(value) is dict and set(value)=={"stopped","exit"} and type(value["stopped"]) is bool)
    if value["stopped"]:
        need(type(value["exit"]) is int and 0<=value["exit"]<=2**32-1)
    else:
        need(value["exit"] is None)
    return value["stopped"],value["exit"]


def supervise(provider, *, clock=time.monotonic, pause=time.sleep, source_recheck=lambda:None):
    """Injected protocol; fake providers remain MODEL evidence, never OS proof."""
    callbacks={name:getattr(provider,name) for name in PROVIDER_METHODS}
    need(all(callable(fn) for fn in callbacks.values()) and callable(clock) and callable(pause) and callable(source_recheck))
    now,rest,recheck_source=clock,pause,source_recheck
    owners=Owners();job=main=thread=None
    launched=False;failed=False;normal=False;last_clock=None;start=None;last_total=0
    acquisition_pending=False
    out,err=bytearray(),bytearray()
    result=dict(status="FAILED",qualification_authority=False,production_authority=False,
        supervision_only=True,main_stopped=False,job_empty=False,cleanup="UNCONFIRMED",
        stdout_bytes=0,stderr_bytes=0,stage="START",resume_attempts=0)
    result["failure_reason"]="API_FAILURE"

    def stamp():
        nonlocal last_clock
        value=now()
        need(type(value) in (int,float) and math.isfinite(value),"CLOCK_INVALID")
        need(last_clock is None or value>=last_clock,"CLOCK_INVALID")
        last_clock=value
        return value

    def check():
        value=stamp()
        need(start is not None and value-start<=RUN_SECONDS,"TIMEOUT")

    def invoke(name,*args):
        check();result["stage"]=name.upper()
        value=callbacks[name](*args)
        check()
        return value

    def guard_source(stage):
        result["stage"]=stage
        check();refused=False
        try:need(recheck_source() is None)
        except BaseException:refused=True
        if refused:raise Refused("SOURCE_OR_RECEIPT_FAILURE")
        check()

    def drain(pipe,buffer):
        observation=invoke("peek",pipe)
        need(type(observation) is dict and set(observation)=={"available","closed"})
        available,closed=observation["available"],observation["closed"]
        need(type(available) is int and 0<=available<=2**32-1 and type(closed) is bool)
        need(not closed or available==0)
        need(available<=MAX_OUTPUT-len(buffer),"OUTPUT_LIMIT")
        if available:
            payload=invoke("read",pipe,available)
            need(type(payload) is bytes and len(payload)==available)
            buffer.extend(payload)
        return closed

    try:
        start=stamp()
        check();result["stage"]="CREATE_JOB"
        acquisition_pending=True
        job=owners.adopt_many((callbacks["create_job"](),),1)[0]
        acquisition_pending=False;check()
        need(invoke("inheritable",job) is False)
        invoke("configure",job);_limits(invoke("limits",job))
        check();result["stage"]="CREATE_PIPES"
        acquisition_pending=True
        pipes=owners.adopt_many(callbacks["create_pipes"](),6)
        acquisition_pending=False;check()
        stdin_read,stdin_write,stdout_read,stdout_write,stderr_read,stderr_write=pipes
        for token,expected in zip(pipes,(True,False,False,True,False,True)):
            need(invoke("inheritable",token) is expected)
        owners.close_one(stdin_write)  # child receives EOF, never caller input
        guard_source("SOURCE_RECHECK_PRECREATE")
        launched=True
        check();result["stage"]="CREATE_SUSPENDED_ATOMIC"
        acquisition_pending=True
        main,thread=owners.adopt_many(callbacks["create_suspended_atomic"](job,(stdin_read,stdout_write,stderr_write)),2)
        acquisition_pending=False;check()
        need(invoke("inheritable",main) is False and invoke("inheritable",thread) is False)
        need(invoke("member",main,job) is True)
        _limits(invoke("limits",job))
        count,last_total=_counts(invoke("active",job),last_total)
        need(count==1 and last_total==1)
        for token in (stdin_read,stdout_write,stderr_write):owners.close_one(token)
        guard_source("SOURCE_RECHECK_PRE_RESUME")
        result["resume_attempts"]+=1
        previous=invoke("resume",thread)
        need(type(previous) is int and previous==1)
        for _ in range(MAX_RUN_POLLS):
            stdout_closed=drain(stdout_read,out)
            stderr_closed=drain(stderr_read,err)
            stopped,code=_main_state(invoke("poll_exit",main))
            count,last_total=_counts(invoke("active",job),last_total)
            if stopped and code!=0:raise Refused("NONZERO_EXIT")
            if stopped and count==0 and stdout_closed and stderr_closed:
                need(bytes(out) in SUCCESS_LINES and bytes(err)==b"","BAD_OUTPUT")
                result.update(main_stopped=True,job_empty=True,stage="NORMAL_MAIN_AND_JOB_EMPTY")
                normal=True
                break
            check();rest(0.01);check()
        else:raise Refused("TIMEOUT")
    except Refused as error:
        if type(error) is Refused:result["failure_reason"]=error.code
        failed=True
    except BaseException:
        failed=True
    finally:
        cleanup_failed=acquisition_pending
        cleanup_start=None
        terminated=False
        stopped=not launched;empty=job is None
        try:cleanup_start=stamp()
        except BaseException:cleanup_failed=True

        def cleanup_tick():
            value=stamp()
            need(cleanup_start is not None and value-cleanup_start<=CLEANUP_SECONDS,"CLEANUP_UNCONFIRMED")

        def terminate_once():
            nonlocal terminated,cleanup_failed
            if job is None or terminated:return
            terminated=True
            try:cleanup_tick()
            except BaseException:cleanup_failed=True
            # Termination is still owed when clock observation itself failed.
            try:need(callbacks["terminate"](job) is None)
            except BaseException:cleanup_failed=True
            try:cleanup_tick()
            except BaseException:cleanup_failed=True

        def observe_cleanup():
            nonlocal stopped,empty,last_total,cleanup_failed
            try:
                for _ in range(MAX_CLEANUP_POLLS):
                    if job is None:return
                    cleanup_tick()
                    if main is not None:
                        candidate=_main_state(callbacks["poll_exit"](main))
                        cleanup_tick();stopped=candidate[0]
                    cleanup_tick()
                    count,total=_counts(callbacks["active"](job),last_total)
                    cleanup_tick();last_total=total;empty=count==0
                    if stopped and empty:return
                    cleanup_tick();rest(0.01);cleanup_tick()
                raise Refused("CLEANUP_UNCONFIRMED")
            except BaseException:cleanup_failed=True

        def close_original(token):
            nonlocal cleanup_failed
            try:cleanup_tick()
            except BaseException:cleanup_failed=True
            try:owners.close_one(token)
            except BaseException:cleanup_failed=True
            try:cleanup_tick()
            except BaseException:cleanup_failed=True

        if not normal:terminate_once()
        observe_cleanup()
        # Keep main/job handles valid for independent post-termination queries.
        for token in reversed(owners.tokens):
            if token is not job and token is not main:close_original(token)
        # Even a normally observed empty job is terminated before its final close;
        # this covers later close faults without ever reusing a closed handle.
        terminate_once()
        observe_cleanup()
        if main is not None:close_original(main)
        if job is not None:close_original(job)
        # Also close any partially transferred handles not represented by roles.
        for token in reversed(owners.tokens):
            if id(token) not in owners.attempted:close_original(token)
        try:cleanup_tick()
        except BaseException:cleanup_failed=True
        result["termination_attempted"]=terminated
        result["acquisition_uncertain"]=acquisition_pending
        result["normal_empty_job_termination"]=bool(normal and terminated)
        result["main_stopped"],result["job_empty"]=bool(stopped and not cleanup_failed),bool(empty and not cleanup_failed)
        if stopped and empty and not owners.failed and not cleanup_failed:
            result["cleanup"]="CONFIRMED_ORIGINALS_CLOSED"
        else:
            failed=True;result["failure_reason"]="CLEANUP_UNCONFIRMED"
        result["stdout_bytes"],result["stderr_bytes"]=len(out),len(err)
    if normal and not failed:
        result["status"]="SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE"
        result["failure_reason"]="NONE"
    return result


def _file_facts(st):
    import stat
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not getattr(st,"st_file_attributes",0)&0x400)
    fields=(st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns,
            getattr(st,"st_file_attributes",0),getattr(st,"st_birthtime_ns",None))
    need(all(type(v) is int for v in fields) and fields[0]>=0 and fields[1]>0 and fields[8]>=0)
    need(1<=fields[4]<=MAX_SOURCE)
    return fields


def _directory_facts(st):
    import stat
    need(stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode) and not getattr(st,"st_file_attributes",0)&0x400)
    return st.st_dev,st.st_ino,st.st_mode,getattr(st,"st_file_attributes",0)


class HeldSource:
    """Ordinary source-path/descriptor pairs, not protected initial trust proof."""
    def __init__(self,path,expected,exact_size=None):
        import os
        self.path,self.expected=path,expected
        self.parents=tuple((p,_directory_facts(p.lstat())) for p in reversed(path.parents))
        named=_file_facts(path.lstat())
        self.stream=path.open("rb");self.closed=self.failed=False
        self._close=self.stream.close
        failed=False
        try:
            self._read,self._seek=self.stream.read,self.stream.seek
            fileno=self.stream.fileno;fstat=os.fstat
            self._descriptor=lambda:fstat(fileno())
            self._named=path.lstat
            self.pair=self._pair()
            need(self.pair[0]==named)
            need(all(_directory_facts(p.lstat())==facts for p,facts in self.parents))
            self.payload=self._read(MAX_SOURCE+1)
            need(type(self.payload) is bytes and len(self.payload)==named[4] and
                 hashlib.sha256(self.payload).hexdigest()==expected)
            need(exact_size is None or type(exact_size) is int and len(self.payload)==exact_size)
            self.recheck()
        except BaseException:
            self.failed=True
            failed=True
            try:self.close()
            except BaseException:pass
        if failed:raise Refused()

    def _pair(self):
        named,descriptor=_file_facts(self._named()),_file_facts(self._descriptor())
        need(named[:6]+named[7:]==descriptor[:6]+descriptor[7:])
        return named,descriptor

    def recheck(self):
        try:
            need(not self.closed and not self.failed and self._pair()==self.pair)
            need(all(_directory_facts(p.lstat())==facts for p,facts in self.parents))
            self._seek(0);need(self._read(MAX_SOURCE+1)==self.payload)
            need(self._pair()==self.pair)
            need(all(_directory_facts(p.lstat())==facts for p,facts in self.parents))
        except BaseException:
            self.failed=True
        else:return
        raise Refused()

    def close(self):
        if not self.closed:
            self.closed=True
            try:need(self._close() is None)
            except BaseException:self.failed=True
        need(not self.failed)


class FixedSources:
    def __init__(self,pins=SOURCE_PINS):self.pins=tuple(pins);self.held=[];self.failed=False
    def verify(self):
        for pin in self.pins:self.held.append(HeldSource(*pin))
        self.recheck()
    def recheck(self):
        for source in self.held:source.recheck()
    def close(self):
        for source in reversed(self.held):
            try:source.recheck()
            except BaseException:self.failed=True
            try:source.close()
            except BaseException:self.failed=True
        need(not self.failed)


def _receipt_facts(st):
    import stat
    need(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and not getattr(st,"st_file_attributes",0)&0x400)
    fields=(st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns,
            getattr(st,"st_file_attributes",0),getattr(st,"st_birthtime_ns",None))
    need(all(type(v) is int for v in fields) and fields[0]>=0 and fields[1]>0 and fields[8]>=0)
    need(0<=fields[4]<=MAX_RECEIPT)
    return fields


def _stable_receipt_identity(facts):
    return facts[:4]+facts[7:]


class Receipt:
    def __init__(self,path=WATCHDOG_RECEIPT,forbidden=TARGET_RECEIPT):
        self.path,self.forbidden=path,forbidden;self.stream=None;self.closed=False;self.failed=False
        self.parents={}
    def _parents(self):
        need(all(_directory_facts(p.lstat())==facts for p,facts in self.parents.items()))
    def _pair(self):
        named,descriptor=_receipt_facts(self._named()),_receipt_facts(self._descriptor())
        need(named[:6]+named[7:]==descriptor[:6]+descriptor[7:])
        return named,descriptor
    def reserve(self,raw):
        import os
        for path in (self.path,self.forbidden):
            for parent in reversed(path.parents):
                facts=_directory_facts(parent.lstat())
                if parent in self.parents:need(self.parents[parent]==facts)
                self.parents[parent]=facts
        try:self.forbidden.lstat()
        except FileNotFoundError:pass
        else:raise Refused()
        self._parents()
        self.stream=self.path.open("xb+")
        self._close=self.stream.close
        self._write=self.stream.write;self._flush=self.stream.flush
        self._seek=self.stream.seek;self._read=self.stream.read;self._truncate=self.stream.truncate
        fileno=self.stream.fileno;self._fileno=fileno;self._fsync=os.fsync
        fstat=os.fstat
        self._descriptor=lambda:fstat(fileno())
        self._named=self.path.lstat
        self.pair=self._pair();need(self.pair[0][4]==0)
        self._parents()
        self.finish(raw)
    def finish(self,raw):
        failed=False
        try:
            need(type(raw) is bytes and len(raw)<=MAX_RECEIPT and not self.closed and not self.failed)
            self._parents();need(self._pair()==self.pair)
            self._seek(0);need(self._write(raw)==len(raw));self._truncate();self._flush();self._fsync(self._fileno())
            after=self._pair()
            need(all(_stable_receipt_identity(a)==_stable_receipt_identity(b) for a,b in zip(after,self.pair)))
            need(after[0][4]==len(raw));self._parents()
            self._seek(0);need(self._read(len(raw)+1)==raw)
            need(self._pair()==after);self._parents()
            self.pair=after
        except BaseException:failed=True;self.failed=True
        if failed:raise Refused("SOURCE_OR_RECEIPT_FAILURE")
    def close(self):
        if self.stream is not None and not self.closed:
            self.closed=True
            try:need(self._close() is None)
            except BaseException:self.failed=True
        need(not self.failed)


def execute_model(factory,sources,receipt,*,clock=time.monotonic,pause=time.sleep):
    """Source/receipt seam; only injected providers/fixtures in this batch."""
    reserve,finish,close_receipt=receipt.reserve,receipt.finish,receipt.close
    verify,recheck,close_sources=sources.verify,sources.recheck,sources.close
    result=dict(status="FAILED",qualification_authority=False,production_authority=False,
                failure_reason="SOURCE_OR_RECEIPT_FAILURE",stage="PREPARATION")
    failed=False;reserved=False
    try:
        reserve(canonical(dict(status="RESERVED_NOT_COMPLETE",qualification_authority=False)))
        reserved=True
        verify()
        result=supervise(factory(),clock=clock,pause=pause,source_recheck=recheck)
        failed=result["status"]!="SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE"
        recheck()
    except BaseException:
        failed=True
        result["failure_reason"]="SOURCE_OR_RECEIPT_FAILURE"
    finally:
        try:close_sources()
        except BaseException:failed=True;result["failure_reason"]="SOURCE_OR_RECEIPT_FAILURE"
        if failed:result["status"]="FAILED"
        if reserved:
            try:finish(canonical(result))
            except BaseException:failed=True;result["failure_reason"]="SOURCE_OR_RECEIPT_FAILURE"
        try:close_receipt()
        except BaseException:failed=True;result["failure_reason"]="SOURCE_OR_RECEIPT_FAILURE"
    if failed:result["status"]="FAILED"
    return (1 if failed else 0),result


def native_types(c):
    """ABI definitions only; safe with ctypes and fake functions, no DLL load."""
    D=c.c_uint32;W=c.c_uint16;H=c.c_void_p;S=c.c_size_t;Q=c.c_uint64
    class Basic(c.Structure):
        _fields_=[("ProcessTime",c.c_int64),("JobTime",c.c_int64),("LimitFlags",D),
            ("MinimumWorkingSetSize",S),("MaximumWorkingSetSize",S),("ActiveProcessLimit",D),
            ("Affinity",S),("PriorityClass",D),("SchedulingClass",D)]
    class IO(c.Structure):
        _fields_=[(name,Q) for name in ("ReadOperationCount","WriteOperationCount","OtherOperationCount",
                                       "ReadTransferCount","WriteTransferCount","OtherTransferCount")]
    class Extended(c.Structure):
        _fields_=[("BasicLimitInformation",Basic),("IoInfo",IO),("ProcessMemoryLimit",S),
            ("JobMemoryLimit",S),("PeakProcessMemoryUsed",S),("PeakJobMemoryUsed",S)]
    class Accounting(c.Structure):
        _fields_=[("TotalUserTime",c.c_int64),("TotalKernelTime",c.c_int64),
            ("ThisPeriodTotalUserTime",c.c_int64),("ThisPeriodTotalKernelTime",c.c_int64),
            ("TotalPageFaultCount",D),("TotalProcesses",D),("ActiveProcesses",D),("TotalTerminatedProcesses",D)]
    class Security(c.Structure):
        _fields_=[("nLength",D),("lpSecurityDescriptor",H),("bInheritHandle",c.c_int32)]
    class Startup(c.Structure):
        _fields_=[("cb",D),("lpReserved",c.c_wchar_p),("lpDesktop",c.c_wchar_p),("lpTitle",c.c_wchar_p),
            ("dwX",D),("dwY",D),("dwXSize",D),("dwYSize",D),("dwXCountChars",D),
            ("dwYCountChars",D),("dwFillAttribute",D),("dwFlags",D),("wShowWindow",W),
            ("cbReserved2",W),("lpReserved2",H),("hStdInput",H),("hStdOutput",H),("hStdError",H)]
    class StartupEx(c.Structure):
        _fields_=[("StartupInfo",Startup),("lpAttributeList",H)]
    class Process(c.Structure):
        _fields_=[("hProcess",H),("hThread",H),("dwProcessId",D),("dwThreadId",D)]
    return dict(Basic=Basic,Extended=Extended,Accounting=Accounting,Security=Security,
                Startup=Startup,StartupEx=StartupEx,Process=Process)


class NativeOwner:
    def __init__(self,value,close_native):
        need(type(value) is int and value>0)
        self.value=value
        closed=failed=False
        def close():
            nonlocal closed,failed
            if not closed:
                closed=True
                try:need(bool(close_native(value)))
                except BaseException:failed=True
            need(not failed)
        self.close=close


def _raw_cleanup(values,close):
    failed=False
    for value in reversed(tuple(dict.fromkeys(values))):
        try:need(bool(close(value)))
        except BaseException:failed=True
    need(not failed)


def _bind_native():
    import ctypes as c
    need(sys.platform=="win32")
    k=c.WinDLL("kernel32",use_last_error=True)
    H=c.c_void_p;D=c.c_uint32;B=c.c_int32;S=c.c_size_t;V=c.c_void_p;P=c.c_wchar_p
    signatures={
        "CloseHandle":([H],B),"CreateJobObjectW":([V,P],H),
        "SetInformationJobObject":([H,c.c_int,V,D],B),"QueryInformationJobObject":([H,c.c_int,V,D,c.POINTER(D)],B),
        "GetHandleInformation":([H,c.POINTER(D)],B),"SetHandleInformation":([H,D,D],B),
        "CreatePipe":([c.POINTER(H),c.POINTER(H),V,D],B),
        "InitializeProcThreadAttributeList":([V,D,D,c.POINTER(S)],B),
        "UpdateProcThreadAttribute":([V,D,S,V,S,V,V],B),"DeleteProcThreadAttributeList":([V],None),
        "CreateProcessW":([P,V,V,V,B,D,V,P,V,V],B),"IsProcessInJob":([H,H,c.POINTER(B)],B),
        "ResumeThread":([H],D),"PeekNamedPipe":([H,V,D,V,c.POINTER(D),V],B),
        "ReadFile":([H,V,D,c.POINTER(D),V],B),"WaitForSingleObject":([H,D],D),
        "GetExitCodeProcess":([H,c.POINTER(D)],B),"TerminateJobObject":([H,D],B)}
    functions={}
    for name,(args,returns) in signatures.items():
        fn=getattr(k,name);fn.argtypes=args;fn.restype=returns;functions[name]=fn
    return c,functions,c.get_last_error


class NativeAdapter:
    """Opt-in-only lazy native provider. Inject fake API tuple in source tests."""
    def __init__(self,api=None):
        from types import MappingProxyType
        c,raw,last_error=_bind_native() if api is None else api
        self.c,self.types=c,native_types(c)
        self.raw=MappingProxyType(dict(raw));self.last_error=last_error
        self._owner_factory=NativeOwner

    def _valid(self,value):
        return type(value) is int and value>0 and value!=self.c.c_void_p(-1).value

    def _wrap_group(self,values,close,owner_factory):
        # Caller retains raw ownership until all wrapper construction succeeds.
        result=[]
        for value in values:
            owner=owner_factory(value,close)
            need(type(owner.value) is int and owner.value==value and callable(owner.close))
            result.append(owner)
        return tuple(result)

    def create_job(self):
        create,close=self.raw["CreateJobObjectW"],self.raw["CloseHandle"]
        factory=self._owner_factory;value=create(None,None)
        need(self._valid(value))
        failed=False
        try:return self._wrap_group((value,),close,factory)[0]
        except BaseException:failed=True
        if failed:
            _raw_cleanup((value,),close)
            raise Refused()

    def configure(self,job):
        c=self.c;info=self.types["Extended"]()
        info.BasicLimitInformation.LimitFlags=JOB_FLAGS
        info.BasicLimitInformation.ActiveProcessLimit=2
        info.JobMemoryLimit=JOB_MEMORY
        need(bool(self.raw["SetInformationJobObject"](job.value,9,c.byref(info),c.sizeof(info))))

    def limits(self,job):
        c=self.c;info=self.types["Extended"]()
        need(bool(self.raw["QueryInformationJobObject"](job.value,9,c.byref(info),c.sizeof(info),None)))
        return dict(flags=int(info.BasicLimitInformation.LimitFlags),active=int(info.BasicLimitInformation.ActiveProcessLimit),
                    memory=int(info.JobMemoryLimit))

    def create_pipes(self):
        c=self.c;create=self.raw["CreatePipe"];change=self.raw["SetHandleInformation"]
        close=self.raw["CloseHandle"];factory=self._owner_factory
        attrs=self.types["Security"](c.sizeof(self.types["Security"]),None,True)
        values=[];failed=False;result=None
        try:
            for _ in range(3):
                read,write=c.c_void_p(),c.c_void_p()
                try:success=create(c.byref(read),c.byref(write),c.byref(attrs),0)
                finally:
                    for value in (read.value,write.value):
                        if self._valid(value):values.append(value)
                need(bool(success) and self._valid(read.value) and self._valid(write.value))
            need(len(set(values))==6)
            for index in (1,2,4):need(bool(change(values[index],1,0)))
            result=self._wrap_group(values,close,factory)
        except BaseException:failed=True
        if failed:
            _raw_cleanup(values,close)
            raise Refused()
        return result

    def inheritable(self,handle):
        flags=self.c.c_uint32()
        need(bool(self.raw["GetHandleInformation"](handle.value,self.c.byref(flags))))
        return bool(flags.value&1)

    def create_suspended_atomic(self,job,stdio):
        c=self.c;raw=self.raw;close=raw["CloseHandle"];factory=self._owner_factory
        need(type(stdio) is tuple and len(stdio)==3)
        size=c.c_size_t();initialized=False;values=[];failed=False;result=None
        process=self.types["Process"]()
        try:
            need(not raw["InitializeProcThreadAttributeList"](None,2,0,c.byref(size)))
            need(1<=size.value<=65536)
            attributes=c.create_string_buffer(size.value)
            need(bool(raw["InitializeProcThreadAttributeList"](attributes,2,0,c.byref(size))))
            initialized=True
            jobs=(c.c_void_p*1)(job.value)
            handles=(c.c_void_p*3)(*(h.value for h in stdio))
            need(bool(raw["UpdateProcThreadAttribute"](attributes,0,0x2000D,jobs,c.sizeof(jobs),None,None)))
            need(bool(raw["UpdateProcThreadAttribute"](attributes,0,0x20002,handles,c.sizeof(handles),None,None)))
            startup=self.types["StartupEx"]()
            startup.StartupInfo.cb=c.sizeof(startup);startup.StartupInfo.dwFlags=0x100
            startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError=(h.value for h in stdio)
            startup.lpAttributeList=c.addressof(attributes)
            command=c.create_unicode_buffer('"'+str(INTERPRETER)+'" -I -B "'+str(TARGET)+'" --qualify-new-synthetic-namespace')
            success=raw["CreateProcessW"](str(INTERPRETER),command,None,None,True,0x08080004,None,str(ROOT),
                                           c.byref(startup),c.byref(process))
            for value in (process.hProcess,process.hThread):
                if self._valid(value):values.append(value)
            need(bool(success) and len(values)==2 and len(set(values))==2)
        except BaseException:failed=True
        finally:
            for value in (process.hProcess,process.hThread):
                if self._valid(value) and value not in values:values.append(value)
            if initialized:
                try:raw["DeleteProcThreadAttributeList"](attributes)
                except BaseException:failed=True
        if not failed:
            try:result=self._wrap_group(values,close,factory)
            except BaseException:failed=True
        if failed:
            _raw_cleanup(values,close)
            raise Refused()
        return result

    def member(self,process,job):
        value=self.c.c_int32()
        need(bool(self.raw["IsProcessInJob"](process.value,job.value,self.c.byref(value))))
        return bool(value.value)

    def resume(self,thread):return int(self.raw["ResumeThread"](thread.value))

    def peek(self,pipe):
        available=self.c.c_uint32()
        get_error=self.last_error
        if not self.raw["PeekNamedPipe"](pipe.value,None,0,None,self.c.byref(available),None):
            need(get_error()==109)
            return dict(available=0,closed=True)
        return dict(available=int(available.value),closed=False)

    def read(self,pipe,count):
        need(type(count) is int and 1<=count<=MAX_OUTPUT)
        buffer=self.c.create_string_buffer(count);actual=self.c.c_uint32()
        need(bool(self.raw["ReadFile"](pipe.value,buffer,count,self.c.byref(actual),None)))
        need(actual.value==count)
        return buffer.raw

    def poll_exit(self,process):
        state=int(self.raw["WaitForSingleObject"](process.value,0))
        if state==258:return dict(stopped=False,exit=None)
        need(state==0)
        code=self.c.c_uint32()
        need(bool(self.raw["GetExitCodeProcess"](process.value,self.c.byref(code))))
        return dict(stopped=True,exit=int(code.value))

    def active(self,job):
        c=self.c;info=self.types["Accounting"]()
        need(bool(self.raw["QueryInformationJobObject"](job.value,1,c.byref(info),c.sizeof(info),None)))
        return dict(active=int(info.ActiveProcesses),total=int(info.TotalProcesses))

    def terminate(self,job):need(bool(self.raw["TerminateJobObject"](job.value,1)))


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if type(args) is not list or args!=["--guard-fixed-qualification"]:
        print("M4_WATCHDOG_OPT_IN_REQUIRED")
        return 1
    code=1
    try:
        need(sys.platform=="win32" and Path(__file__).absolute()==ROOT/"infra/m4_platform_watchdog.py")
        code,result=execute_model(NativeAdapter,FixedSources(),Receipt())
    except BaseException:code=1
    print("M4_WATCHDOG_SUPERVISION_RECORDED_NO_AUTHORITY" if code==0 else "M4_WATCHDOG_FAILED_NO_RETRY")
    return code


if __name__=="__main__":raise SystemExit(main())
