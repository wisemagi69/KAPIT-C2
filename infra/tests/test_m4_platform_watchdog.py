"""Fake lifecycle/Win32/stream tests only: no DLL, process or actual source load."""
import ctypes as c
import hashlib
import io
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from infra import m4_platform_watchdog as w


class Handle:
    def __init__(self,value,events):self.value=value;self.events=events;self.calls=0;self.fail=False
    def close(self):
        self.calls+=1;self.events.append(("close",self.value))
        if self.fail:raise RuntimeError("fake close")


class Clock:
    def __init__(self):self.value=0
    def now(self):return self.value
    def pause(self,seconds):self.value+=seconds


class Provider:
    def __init__(self,clock):
        self.clock=clock;self.events=[];self.handles=[];self.started=False;self.terminated=0
        self.failure=None;self.descendant=False;self.hang=False;self.exit=0;self.total=2
        self.output=w.SUCCESS_LINES[0];self.error=b"";self.pending={4:self.output,6:self.error}
        self.resume_value=1;self.reuse=False;self.hook=None
    def make(self,value):
        handle=Handle(value,self.events);self.handles.append(handle);return handle
    def call(self,name):
        self.events.append((name,))
        if self.hook:self.hook(name)
        if self.failure==name:raise RuntimeError("fake private canary")
    def create_job(self):self.call("create_job");return self.make(1)
    def configure(self,job):self.call("configure")
    def limits(self,job):self.call("limits");return dict(flags=w.JOB_FLAGS,active=2,memory=w.JOB_MEMORY)
    def create_pipes(self):self.call("create_pipes");return tuple(self.make(n) for n in range(2,8))
    def inheritable(self,handle):self.call("inheritable");return handle.value in (2,5,7)
    def create_suspended_atomic(self,job,stdio):
        self.call("create_suspended_atomic")
        assert tuple(h.value for h in stdio)==(2,5,7)
        return self.make(3 if self.reuse else 8),self.make(9)
    def member(self,process,job):self.call("member");return True
    def resume(self,thread):self.call("resume");self.started=True;return self.resume_value
    def peek(self,pipe):
        self.call("peek");data=self.pending[pipe.value]
        return dict(available=len(data),closed=not data)
    def read(self,pipe,count):
        self.call("read");data=self.pending[pipe.value]
        assert 0<count<=len(data)
        self.pending[pipe.value]=data[count:];return data[:count]
    def poll_exit(self,process):
        self.call("poll_exit")
        return dict(stopped=not self.hang or bool(self.terminated),exit=self.exit if not self.hang or self.terminated else None)
    def active(self,job):
        self.call("active")
        if self.terminated:return dict(active=0,total=self.total)
        return dict(active=1 if not self.started or self.hang or self.descendant else 0,total=self.total if self.started else 1)
    def terminate(self,job):self.call("terminate");self.terminated+=1


class ProtocolTests(unittest.TestCase):
    def run_provider(self,provider,clock,**kw):
        return w.supervise(provider,clock=clock.now,pause=clock.pause,**kw)
    def test_normal_empty_job_exit_and_exact_lines_no_authority(self):
        for line in w.SUCCESS_LINES:
            clock=Clock();provider=Provider(clock);provider.pending[4]=line
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE")
            self.assertTrue(result["main_stopped"] and result["job_empty"])
            self.assertFalse(result["qualification_authority"] or result["production_authority"])
            self.assertEqual(provider.terminated,1)
            self.assertTrue(all(h.calls==1 for h in provider.handles))
            self.assertEqual(provider.events[-1],("close",1))
    def test_numeric_handle_reuse_new_generation_closes_both_originals(self):
        clock=Clock();provider=Provider(clock);provider.reuse=True
        result=self.run_provider(provider,clock)
        self.assertEqual(result["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE")
        self.assertEqual([h.calls for h in provider.handles if h.value==3],[1,1])
    def test_duplicate_live_handle_not_adopted_or_double_closed(self):
        owners=w.Owners();events=[];original=Handle(1,events);duplicate=Handle(1,events)
        owners.adopt_many((original,),1)
        with self.assertRaises(w.Refused):owners.adopt_many((duplicate,),1)
        owners.close_all();self.assertEqual((original.calls,duplicate.calls),(1,0))
    def test_every_callback_failure_stops_and_attempts_owned_closes(self):
        for name in ("configure","limits","create_pipes","inheritable","member","resume","peek","read","poll_exit","active"):
            clock=Clock();provider=Provider(clock);provider.failure=name
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"FAILED")
            self.assertTrue(all(h.calls==1 for h in provider.handles))
            self.assertNotIn("canary",str(result))
    def test_launch_post_transfer_clock_failure_keeps_original_handles(self):
        clock=Clock();provider=Provider(clock)
        original=provider.create_suspended_atomic
        def create(*args):
            value=original(*args);clock.value=61;return value
        provider.create_suspended_atomic=create
        result=self.run_provider(provider,clock)
        self.assertEqual(result["status"],"FAILED")
        self.assertTrue(all(h.calls==1 for h in provider.handles))
        self.assertEqual(provider.terminated,1)
    def test_exact_resume_integer_one_required(self):
        for value in (True,1.0,0,2,0xffffffff):
            clock=Clock();provider=Provider(clock);provider.resume_value=value
            self.assertEqual(self.run_provider(provider,clock)["status"],"FAILED")
    def test_limit_and_membership_fail_before_resume(self):
        for mode in ("limit","member"):
            clock=Clock();provider=Provider(clock)
            if mode=="limit":provider.limits=lambda job:dict(flags=0x3208,active=2,memory=w.JOB_MEMORY)
            else:provider.member=lambda *args:False
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"FAILED");self.assertFalse(provider.started)
    def test_nonzero_exit_including_legitimate_259_refuses(self):
        for code in (1,259):
            clock=Clock();provider=Provider(clock);provider.exit=code
            self.assertEqual(self.run_provider(provider,clock)["failure_reason"],"NONZERO_EXIT")
    def test_unknown_stdout_and_stderr_never_persist_raw_content(self):
        for pipe in (4,6):
            clock=Clock();provider=Provider(clock);provider.pending[pipe]=b"private-canary"
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"FAILED");self.assertNotIn("canary",str(result))
    def test_flood_detected_before_read_and_exact_4096_bounded(self):
        for size in (4096,4097):
            clock=Clock();provider=Provider(clock);provider.pending[4]=b"x"*size
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"FAILED")
            self.assertLessEqual(result["stdout_bytes"],4096)
            if size==4097:self.assertNotIn(("read",),provider.events)
    def test_main_exit_with_live_descendant_not_completion(self):
        clock=Clock();provider=Provider(clock);provider.descendant=True
        result=self.run_provider(provider,clock)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(provider.terminated,1)
    def test_total_process_count_above_two_or_decreasing_refuses(self):
        clock=Clock();provider=Provider(clock);provider.total=3
        self.assertEqual(self.run_provider(provider,clock)["status"],"FAILED")
        with self.assertRaises(w.Refused):w._counts(dict(active=0,total=1),2)
    def test_stalled_clock_and_pause_have_finite_iteration_stop(self):
        provider=Provider(Clock());provider.hang=True
        result=w.supervise(provider,clock=lambda:0,pause=lambda _:None)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(provider.terminated,1)
    def test_clock_error_or_rollback_does_not_skip_termination_or_closes(self):
        for value in (-1,float("nan"),float("inf")):
            clock=Clock();provider=Provider(clock)
            provider.hook=lambda name: setattr(clock,"value",value) if name=="resume" else None
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"FAILED");self.assertEqual(provider.terminated,1)
            self.assertTrue(all(h.calls==1 for h in provider.handles))
    def test_cleanup_query_termination_and_close_failures_remain_unconfirmed(self):
        for mode in ("terminate","close","query"):
            clock=Clock();provider=Provider(clock)
            if mode=="terminate":provider.failure="terminate"
            if mode=="close":
                old=provider.create_job
                def create():
                    handle=old();handle.fail=True;return handle
                provider.create_job=create
            if mode=="query":
                old=provider.terminate
                def terminate(job):old(job);provider.failure="active"
                provider.terminate=terminate
            result=self.run_provider(provider,clock)
            self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED")
            self.assertTrue(all(h.calls==1 for h in provider.handles))
    def test_original_callbacks_captured_before_provider_substitution(self):
        clock=Clock();provider=Provider(clock)
        old=provider.create_job
        def create():
            handle=old();provider.resume=lambda *args:self.fail("replacement used")
            provider.terminate=lambda *args:self.fail("replacement terminate used")
            return handle
        provider.create_job=create
        self.assertEqual(self.run_provider(provider,clock)["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE")
    def test_source_changes_after_factory_deny_create_or_resume(self):
        for fail_at in (1,2):
            clock=Clock();provider=Provider(clock);calls=[0]
            def recheck():
                calls[0]+=1
                if calls[0]==fail_at:raise w.Refused()
            result=self.run_provider(provider,clock,source_recheck=recheck)
            self.assertEqual(result["status"],"FAILED");self.assertFalse(provider.started)
            self.assertEqual(result["failure_reason"],"SOURCE_OR_RECEIPT_FAILURE")
            self.assertEqual(result["stage"],"SOURCE_RECHECK_PRECREATE" if fail_at==1 else "SOURCE_RECHECK_PRE_RESUME")
            self.assertEqual(("create_suspended_atomic",) in provider.events,fail_at==2)


class NativeTests(unittest.TestCase):
    def native(self):
        types=w.native_types(c);self.types=types;self.closed=[];self.deleted=0;self.attrs=[]
        def initialize(buffer,count,flags,size):
            c.cast(size,c.POINTER(c.c_size_t))[0]=1024
            return buffer is not None
        def update(buffer,flags,key,value,size,previous,result):
            values=tuple(c.cast(value,c.POINTER(c.c_void_p))[n] for n in range(size//c.sizeof(c.c_void_p)))
            self.attrs.append((key,values));return 1
        def create(app,command,ps,ts,inherit,flags,env,cwd,startup,out):
            self.assertEqual((inherit,flags),(True,0x08080004))
            self.assertEqual(app,str(w.INTERPRETER));self.assertIsNone(env)
            pi=c.cast(out,c.POINTER(types["Process"])).contents;pi.hProcess=101;pi.hThread=102
            return 1
        def delete(buffer):self.deleted+=1
        raw={"CloseHandle":lambda handle:self.closed.append(handle) or 1,
             "CreateJobObjectW":lambda attrs,name:11,"InitializeProcThreadAttributeList":initialize,
             "UpdateProcThreadAttribute":update,"CreateProcessW":create,"DeleteProcThreadAttributeList":delete}
        return w.NativeAdapter(api=(c,raw,lambda:109)),raw
    def test_atomic_job_and_exact_stdio_attributes_and_flags(self):
        adapter,raw=self.native()
        handles=adapter.create_suspended_atomic(w.Token(11,lambda:None),tuple(w.Token(n,lambda:None) for n in (21,22,23)))
        self.assertEqual(self.attrs,[(0x2000D,(11,)),(0x20002,(21,22,23))])
        self.assertEqual(self.deleted,1);self.assertEqual(self.closed,[])
        for owner in handles:owner.close()
        self.assertEqual(self.closed,[101,102])
    def test_partial_process_api_and_attribute_cleanup_failures_close_originals(self):
        for mode in ("raise","false","delete"):
            adapter,raw=self.native();copy=dict(adapter.raw);original=copy["CreateProcessW"]
            def create(*args):
                original(*args)
                if mode=="raise":raise RuntimeError("fake ffi fault")
                return 0 if mode=="false" else 1
            copy["CreateProcessW"]=create
            if mode=="delete":copy["DeleteProcThreadAttributeList"]=lambda p:(_ for _ in ()).throw(RuntimeError())
            adapter.raw=copy
            with self.assertRaises(w.Refused):adapter.create_suspended_atomic(w.Token(11,lambda:None),tuple(w.Token(n,lambda:None) for n in (21,22,23)))
            self.assertEqual(sorted(self.closed),[101,102])
    def test_process_wrapper_construction_failure_closes_both_raw_handles(self):
        adapter,raw=self.native();adapter._owner_factory=lambda *args:(_ for _ in ()).throw(RuntimeError())
        with self.assertRaises(w.Refused):adapter.create_suspended_atomic(w.Token(11,lambda:None),tuple(w.Token(n,lambda:None) for n in (21,22,23)))
        self.assertEqual(sorted(self.closed),[101,102])
    def test_job_wrapper_failure_and_failed_original_native_close_is_unconfirmed(self):
        adapter,raw=self.native();functions=dict(adapter.raw);closes=[]
        functions["CloseHandle"]=lambda handle:closes.append(handle) or 0
        adapter.raw=functions;adapter._owner_factory=lambda *args:(_ for _ in ()).throw(RuntimeError())
        result=w.supervise(adapter,clock=lambda:0,pause=lambda seconds:None)
        self.assertEqual(result["status"],"FAILED")
        self.assertEqual(result["cleanup"],"UNCONFIRMED")
        self.assertTrue(result["acquisition_uncertain"])
        self.assertFalse(result["job_empty"] or result["main_stopped"])
        self.assertEqual(closes,[11])
    def test_partial_pipe_factory_and_failed_original_close_is_unconfirmed(self):
        adapter,raw=self.native();functions=dict(adapter.raw);closes=[]
        def pipe(read,write,attrs,size):
            c.cast(read,c.POINTER(c.c_void_p))[0]=201;c.cast(write,c.POINTER(c.c_void_p))[0]=202
            return 0
        functions["CreatePipe"]=pipe;functions["SetHandleInformation"]=lambda *args:1
        functions["CloseHandle"]=lambda handle:closes.append(handle) or 0
        adapter.raw=functions
        clock=Clock();provider=Provider(clock);provider.create_pipes=adapter.create_pipes
        result=w.supervise(provider,clock=clock.now,pause=clock.pause)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED")
        self.assertTrue(result["acquisition_uncertain"])
        self.assertFalse(result["job_empty"] or result["main_stopped"])
        self.assertEqual(sorted(closes),[201,202]);self.assertEqual(provider.terminated,1)
        self.assertTrue(all(handle.calls==1 for handle in provider.handles))
    def test_process_wrapper_cleanup_failure_remains_unknown_despite_empty_job(self):
        adapter,raw=self.native();functions=dict(adapter.raw);closes=[]
        functions["CloseHandle"]=lambda handle:closes.append(handle) or 0
        adapter.raw=functions;adapter._owner_factory=lambda *args:(_ for _ in ()).throw(RuntimeError())
        clock=Clock();provider=Provider(clock);provider.create_suspended_atomic=adapter.create_suspended_atomic
        result=w.supervise(provider,clock=clock.now,pause=clock.pause)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED")
        self.assertTrue(result["acquisition_uncertain"])
        self.assertFalse(result["job_empty"] or result["main_stopped"])
        self.assertEqual(sorted(closes),[101,102]);self.assertEqual(provider.terminated,1)
        self.assertTrue(all(handle.calls==1 for handle in provider.handles))
    def test_pipe_api_throw_after_both_handles_filled_closes_both(self):
        adapter,raw=self.native();functions=dict(adapter.raw)
        def pipe(read,write,attrs,size):
            c.cast(read,c.POINTER(c.c_void_p))[0]=201;c.cast(write,c.POINTER(c.c_void_p))[0]=202
            raise RuntimeError("fake pipe ffi fault")
        functions["CreatePipe"]=pipe;functions["SetHandleInformation"]=lambda *args:1;adapter.raw=functions
        with self.assertRaises(w.Refused):adapter.create_pipes()
        self.assertEqual(sorted(self.closed),[201,202])
    def test_native_owner_retains_original_close_callback_and_value(self):
        adapter,raw=self.native();owner=adapter.create_job();raw["CloseHandle"]=lambda h:self.fail("replacement")
        owner.value=99;owner.close();owner.close()
        self.assertEqual(self.closed,[11])
    def test_wait_state_separate_from_legitimate_exit_259(self):
        adapter,raw=self.native();functions=dict(adapter.raw)
        functions["WaitForSingleObject"]=lambda handle,timeout:0
        def code(handle,out):c.cast(out,c.POINTER(c.c_uint32))[0]=259;return 1
        functions["GetExitCodeProcess"]=code;adapter.raw=functions
        self.assertEqual(adapter.poll_exit(w.Token(11,lambda:None)),dict(stopped=True,exit=259))
    def test_pipe_error_getter_captured_before_query_callback_mutation(self):
        adapter,raw=self.native();functions=dict(adapter.raw);adapter.last_error=lambda:5
        def peek(*args):adapter.last_error=lambda:109;return 0
        functions["PeekNamedPipe"]=peek;adapter.raw=functions
        with self.assertRaises(w.Refused):adapter.peek(w.Token(11,lambda:None))
    def test_job_limits_abi_fields_and_query_accounting(self):
        adapter,raw=self.native();functions=dict(adapter.raw)
        def configure(handle,kind,pointer,size):
            value=c.cast(pointer,c.POINTER(self.types["Extended"])).contents
            self.assertEqual((kind,value.BasicLimitInformation.LimitFlags,value.BasicLimitInformation.ActiveProcessLimit,value.JobMemoryLimit),
                             (9,0x2208,2,268435456));return 1
        functions["SetInformationJobObject"]=configure;adapter.raw=functions;adapter.configure(w.Token(11,lambda:None))
        self.assertEqual(c.sizeof(self.types["Extended"]),144 if c.sizeof(c.c_void_p)==8 else 112)


class Metadata:
    def __init__(self,*,directory=False,size=0,ctime=20):
        self.st_dev=2**63+3;self.st_ino=2**127+7;self.st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|0o600
        self.st_nlink=1;self.st_size=size;self.st_mtime_ns=10;self.st_ctime_ns=ctime
        self.st_file_attributes=0;self.st_birthtime_ns=5


class FakeFile(io.BytesIO):
    def __init__(self,payload,named,descriptor):
        super().__init__(payload);self.named=named;self.descriptor=descriptor;self.close_calls=0;self.partial=False
    def fileno(self):return 17
    def update(self):
        for item in (self.named,self.descriptor):item.st_size=len(self.getvalue());item.st_mtime_ns+=1;item.st_ctime_ns+=1
    def write(self,raw):
        if self.partial:raw=raw[:-1]
        result=super().write(raw);self.update();return result
    def truncate(self,*args):result=super().truncate(*args);self.update();return result
    def close(self):self.close_calls+=1;super().close()


class FakePath:
    def __init__(self,metadata,stream=None,parents=(),missing=False):
        self.metadata=metadata;self.stream=stream;self.parents=parents;self.missing=missing;self.created=False
    def lstat(self):
        if self.missing:raise FileNotFoundError()
        return self.metadata
    def open(self,mode):
        if mode=="xb+":
            if self.created:raise FileExistsError()
            self.created=True
        return self.stream


class GuardsTests(unittest.TestCase):
    def fixture(self,payload=b"fixture"):
        named=Metadata(size=len(payload),ctime=20);descriptor=Metadata(size=len(payload),ctime=30)
        parent=FakePath(Metadata(directory=True))
        stream=FakeFile(payload,named,descriptor);path=FakePath(named,stream,[parent])
        return path,stream,named,descriptor,parent
    def test_paired_source_ctimes_positive_and_each_clock_mutation_refused(self):
        for field in ("st_ctime_ns","st_birthtime_ns","st_ino"):
            path,stream,named,descriptor,parent=self.fixture()
            with patch("os.fstat",return_value=descriptor):source=w.HeldSource(path,hashlib.sha256(b"fixture").hexdigest())
            self.assertEqual((source.pair[0][6],source.pair[1][6]),(20,30))
            setattr(descriptor,field,getattr(descriptor,field)+1)
            with self.assertRaises(w.Refused):source.recheck()
            with self.assertRaises(w.Refused):source.close()
            self.assertEqual(stream.close_calls,1)
    def test_source_parent_mutation_during_read_refuses_and_closes(self):
        path,stream,named,descriptor,parent=self.fixture()
        with patch("os.fstat",return_value=descriptor):source=w.HeldSource(path,hashlib.sha256(b"fixture").hexdigest())
        original=source._read
        def read(count):parent.metadata.st_ino+=1;return original(count)
        source._read=read
        with self.assertRaises(w.Refused):source.recheck()
        with self.assertRaises(w.Refused):source.close()
        self.assertEqual(stream.close_calls,1)
    def test_receipt_pair_valid_own_writes_then_parent_or_reparse_change_refuses(self):
        for mode in ("parent","reparse"):
            path,stream,named,descriptor,parent=self.fixture(b"")
            forbidden=FakePath(None,parents=[parent],missing=True);receipt=w.Receipt(path,forbidden)
            with patch("os.fstat",return_value=descriptor),patch("os.fsync"):
                receipt.reserve(b"RESERVED")
                if mode=="parent":parent.metadata.st_ino+=1
                else:named.st_file_attributes=0x400
                with self.assertRaises(w.Refused):receipt.finish(b"SUCCESS")
            with self.assertRaises(w.Refused):receipt.close()
            self.assertEqual(stream.close_calls,1)
    def test_receipt_partial_initial_write_closes_and_denies_factory(self):
        path,stream,named,descriptor,parent=self.fixture(b"");stream.partial=True
        receipt=w.Receipt(path,FakePath(None,parents=[parent],missing=True))
        sources=SimpleNamespace(verify=lambda:None,recheck=lambda:None,close=lambda:None)
        factory_calls=[]
        with patch("os.fstat",return_value=descriptor),patch("os.fsync"):
            code,result=w.execute_model(lambda:factory_calls.append(1),sources,receipt)
        self.assertEqual(code,1);self.assertEqual(factory_calls,[]);self.assertEqual(stream.close_calls,1)
    def test_wrapper_late_receipt_and_source_failures_remain_nonzero(self):
        for mode in ("finish","close","source"):
            clock=Clock();provider=Provider(clock)
            def fail():raise RuntimeError("private-canary")
            receipt=SimpleNamespace(reserve=lambda raw:None,finish=(lambda raw:fail()) if mode=="finish" else lambda raw:None,
                                    close=fail if mode=="close" else lambda:None)
            sources=SimpleNamespace(verify=lambda:None,recheck=lambda:None,close=fail if mode=="source" else lambda:None)
            code,result=w.execute_model(lambda:provider,sources,receipt,clock=clock.now,pause=clock.pause)
            self.assertEqual(code,1);self.assertEqual(result["status"],"FAILED");self.assertNotIn("canary",str(result))
    def test_consumed_receipt_and_wrong_cli_or_production_refuse(self):
        path,stream,named,descriptor,parent=self.fixture(b"")
        receipt=w.Receipt(path,FakePath(None,parents=[parent],missing=True));path.created=True
        with self.assertRaises(FileExistsError):receipt.reserve(b"RESERVED")
        with patch.object(w,"NativeAdapter") as factory,patch("builtins.print"):
            self.assertEqual(w.main([]),1);self.assertEqual(w.main(["--guard-fixed-qualification","other"]),1)
            factory.assert_not_called()
        class Trap:
            def __getattribute__(self,name):raise AssertionError("touched")
        with self.assertRaises(w.Refused):w.production_execute(Trap())


if __name__=="__main__":unittest.main()
