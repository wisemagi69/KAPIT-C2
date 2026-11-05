"""Independent watchdog protocol/fake Win32 tests; never actual native work."""
import math
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from infra import m4_platform_watchdog as w


class Owned:
    def __init__(self,value,events):self.value=value;self.events=events;self.close_calls=0;self.fail=False
    def close(self):
        self.close_calls+=1;self.events.append(("close",self.value))
        if self.fail:raise OSError("synthetic-private-canary")


class Provider:
    def __init__(self):
        self.events=[];self.objects={n:Owned(n,self.events) for n in range(1,10)};self.resumed=False;self.terminated=False
        self.output=w.SUCCESS_LINES[0];self.error=b"";self.reads={4:0,6:0};self.hang=False;self.orphan=False;self.fail_stage=None
        self.resume_result=1;self.limits_value=dict(flags=w.JOB_FLAGS,active=2,memory=w.JOB_MEMORY)
    def note(self,name):
        self.events.append(name)
        if name==self.fail_stage:raise OSError("synthetic-private-canary")
    def create_job(self):self.note("create_job");return self.objects[1]
    def configure(self,job):self.note("configure")
    def limits(self,job):self.note("limits");return dict(self.limits_value)
    def create_pipes(self):self.note("create_pipes");return tuple(self.objects[n] for n in range(2,8))
    def inheritable(self,token):self.note("inheritable");return token.value in (2,5,7)
    def create_suspended_atomic(self,job,stdio):
        self.note("create_suspended_atomic");assert job.value==1 and tuple(x.value for x in stdio)==(2,5,7)
        return self.objects[8],self.objects[9]
    def member(self,process,job):self.note("member");return True
    def resume(self,thread):self.note("resume");self.resumed=True;return self.resume_result
    def peek(self,pipe):
        self.note("peek");payload=self.output if pipe.value==4 else self.error
        n=len(payload) if not self.reads[pipe.value] else 0
        return dict(available=n,closed=n==0 and not self.hang)
    def read(self,pipe,maximum):
        self.note("read");self.reads[pipe.value]+=1
        return (self.output if pipe.value==4 else self.error)[:maximum]
    def poll_exit(self,process):
        self.note("poll_exit");return dict(stopped=not self.hang or self.terminated,exit=None if self.hang and not self.terminated else 0)
    def active(self,job):
        self.note("active")
        if not self.resumed:return dict(active=1,total=1)
        return dict(active=0 if self.terminated or not(self.hang or self.orphan) else 1,total=2 if self.orphan else 1)
    def terminate(self,job):self.note("terminate");self.terminated=True


class WatchdogIndependentQA(unittest.TestCase):
    def run_fake(self,provider,**changes):
        args=dict(clock=lambda:0,pause=lambda amount:None);args.update(changes)
        with patch.object(w,"MAX_RUN_POLLS",4),patch.object(w,"MAX_CLEANUP_POLLS",3):return w.supervise(provider,**args)

    def assert_closed_once(self,p):
        acquired={1}
        if "create_pipes" in p.events:acquired.update(range(2,8))
        if "create_suspended_atomic" in p.events and p.fail_stage!="create_suspended_atomic":acquired.update((8,9))
        for n in acquired:self.assertEqual(p.objects[n].close_calls,1)
        self.assertEqual([x for x in p.events if isinstance(x,tuple)][-1],("close",1))

    def test_complete_requires_main_job_and_pipe_eof_never_authority(self):
        p=Provider();result=self.run_fake(p)
        self.assertEqual(result["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE")
        self.assertTrue(result["main_stopped"] and result["job_empty"])
        self.assertFalse(result["qualification_authority"] or result["production_authority"])
        self.assertEqual(result["resume_attempts"],1);self.assert_closed_once(p)

    def test_crlf_fixed_line_supported_without_arbitrary_output(self):
        p=Provider();p.output=w.SUCCESS_LINES[1]
        self.assertEqual(self.run_fake(p)["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE")
        for raw in (b"",b"PASS\n",w.SUCCESS_LINES[0]+b"private-canary"):
            p=Provider();p.output=raw;result=self.run_fake(p)
            self.assertEqual(result["status"],"FAILED");self.assertNotIn("private-canary",str(result));self.assert_closed_once(p)

    def test_main_exit_with_live_descendant_is_failure_then_exact_job_termination(self):
        p=Provider();p.orphan=True;result=self.run_fake(p)
        self.assertEqual(result["status"],"FAILED");self.assertTrue(p.terminated)
        self.assertTrue(result["main_stopped"] and result["job_empty"]);self.assert_closed_once(p)

    def test_hang_stalled_clock_poll_limit_still_terminates_and_closes(self):
        p=Provider();p.hang=True;result=self.run_fake(p)
        self.assertEqual(result["status"],"FAILED");self.assertTrue(p.terminated);self.assert_closed_once(p)

    def test_unknown_job_count_or_membership_refuses_before_resume(self):
        for mode in ("count","member","limits"):
            p=Provider()
            if mode=="count":p.active=lambda job:dict(active=3,total=3)
            elif mode=="member":p.member=lambda *args:False
            else:p.limits_value["memory"]+=1
            result=self.run_fake(p);self.assertEqual(result["status"],"FAILED");self.assertFalse(p.resumed);self.assert_closed_once(p)

    def test_resume_previous_count_requires_exact_integer_one(self):
        for value in (0,2,True,1.0):
            p=Provider();p.resume_result=value
            self.assertEqual(self.run_fake(p)["status"],"FAILED");self.assert_closed_once(p)

    def test_each_api_fault_never_reports_success_and_closes_every_acquired(self):
        for stage in ("configure","limits","create_pipes","inheritable","create_suspended_atomic","member","resume","peek","read","poll_exit","active"):
            p=Provider();p.fail_stage=stage;result=self.run_fake(p)
            self.assertEqual(result["status"],"FAILED");self.assertNotIn("private-canary",str(result))
            # A create_pipes callback that raises never transfers its fake objects.
            if stage!="create_pipes":self.assert_closed_once(p)

    def test_underlying_close_callbacks_captured_before_later_substitution(self):
        p=Provider();old=p.configure
        def substitute(job):
            p.objects[1].close=lambda:self.fail("replacement close")
            p.resume=lambda token:self.fail("replacement provider callback")
            old(job)
        p.configure=substitute
        self.assertEqual(self.run_fake(p)["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE");self.assertEqual(p.objects[1].close_calls,1)

    def test_late_original_close_fault_latches_and_attempts_all_others(self):
        p=Provider();p.objects[9].fail=True;result=self.run_fake(p)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED");self.assert_closed_once(p)

    def test_stdout_and_stderr_overflow_refuse_before_any_unbounded_read(self):
        for stream in ("output","error"):
            p=Provider();setattr(p,stream,b"x"*4097);result=self.run_fake(p)
            self.assertEqual(result["status"],"FAILED");self.assertLessEqual(result["stdout_bytes"],4096);self.assertLessEqual(result["stderr_bytes"],4096);self.assert_closed_once(p)

    def test_nonempty_stderr_and_short_read_are_failure(self):
        p=Provider();p.error=b"synthetic-private-canary"
        result=self.run_fake(p);self.assertEqual(result["status"],"FAILED");self.assertNotIn("canary",str(result))
        p=Provider();p.read=lambda pipe,n:b""
        self.assertEqual(self.run_fake(p)["status"],"FAILED")

    def test_job_query_failure_cannot_become_absence(self):
        p=Provider();p.orphan=True
        def broken(job):raise OSError()
        p.active=broken;result=self.run_fake(p)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED");self.assertFalse(result["job_empty"])

    def test_nonfinite_or_backward_execution_clock_closes_owned_resources(self):
        for second in (math.nan,math.inf,True,-1,61):
            p=Provider();ticks=iter([0,second]);result=self.run_fake(p,clock=lambda:next(ticks,0))
            self.assertEqual(result["status"],"FAILED")

    def test_adoption_before_postcallback_deadline_keeps_owned_job(self):
        p=Provider();expired=False;old=p.create_job
        def create():
            nonlocal expired
            value=old();expired=True;return value
        p.create_job=create
        result=self.run_fake(p,clock=lambda:61 if expired else 0)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(p.objects[1].close_calls,1)

    def test_partial_handle_wrapper_failure_closes_originals(self):
        p=Provider();bad=SimpleNamespace(close=lambda:p.events.append("badclose"),value=False)
        p.create_pipes=lambda:(p.objects[2],bad,p.objects[4],p.objects[5],p.objects[6],p.objects[7])
        result=self.run_fake(p);self.assertEqual(result["status"],"FAILED");self.assertIn("badclose",p.events)
        for n in (1,2,4,5,6,7):self.assertEqual(p.objects[n].close_calls,1)

    def test_termination_fault_retains_cleanup_uncertainty(self):
        p=Provider();p.hang=True;p.terminate=lambda job:(_ for _ in ()).throw(OSError())
        result=self.run_fake(p);self.assertEqual(result["status"],"FAILED");self.assertFalse(result["main_stopped"] or result["job_empty"]);self.assertEqual(result["cleanup"],"UNCONFIRMED");self.assert_closed_once(p)

    def test_impossible_pipe_schema_refuses_not_content_echo(self):
        for value in (dict(available=1,closed=True),dict(available=True,closed=False),dict(available=0,closed=False,raw="canary")):
            p=Provider();p.peek=lambda pipe,value=value:value
            result=self.run_fake(p);self.assertEqual(result["status"],"FAILED");self.assertNotIn("canary",str(result))

    def test_count_total_cannot_decrease_or_exceed_lifetime_budget(self):
        for total in (0,3):
            p=Provider();old=p.active
            p.active=lambda job,old=old,total=total:dict(active=0,total=total) if p.resumed else old(job)
            self.assertEqual(self.run_fake(p)["status"],"FAILED")

    def test_execute_receipt_reservation_failure_never_constructs_provider(self):
        receipt=SimpleNamespace(reserve=lambda raw:(_ for _ in ()).throw(OSError()),finish=lambda raw:self.fail("finish"),close=lambda:None)
        sources=SimpleNamespace(verify=lambda:self.fail("verify"),recheck=lambda:self.fail("recheck"),close=lambda:None)
        code,result=w.execute_model(lambda:self.fail("provider"),sources,receipt)
        self.assertEqual(code,1);self.assertEqual(result["status"],"FAILED")

    def test_late_source_or_receipt_failure_cannot_keep_success(self):
        for fault in ("recheck","sourceclose","finish","receiptclose"):
            def maybe(name):
                if name==fault:raise OSError()
            sources=SimpleNamespace(verify=lambda:None,recheck=lambda:maybe("recheck"),close=lambda:maybe("sourceclose"))
            receipt=SimpleNamespace(reserve=lambda raw:None,finish=lambda raw:maybe("finish"),close=lambda:maybe("receiptclose"))
            with patch.object(w,"MAX_RUN_POLLS",4),patch.object(w,"MAX_CLEANUP_POLLS",3):code,result=w.execute_model(Provider,sources,receipt,clock=lambda:0,pause=lambda t:None)
            self.assertEqual(code,1);self.assertEqual(result["status"],"FAILED")

    def test_fixed_interpreter_target_backend_and_no_production_authority(self):
        self.assertEqual(str(w.INTERPRETER).replace("\\","/"),"C:/Users/Ken/AppData/Local/Programs/Python/Python314/python.exe")
        self.assertEqual(w.SOURCE_PINS[-1][1:],("7ca24f26d6e3f463419ee4f537ddd3acd312c38fe45e678cce08572f26a8bd1a",106328))
        class Poison:
            def __getattribute__(self,name):raise AssertionError(name)
        with self.assertRaises(w.Refused):w.production_execute(Poison())

    def test_cleanup_transition_rollback_never_preserves_success(self):
        baseline=[]
        self.run_fake(Provider(),clock=lambda:baseline.append(10) or 10)
        cutoff=len(baseline)-3;calls=0
        def clock():
            nonlocal calls
            calls+=1
            return 10 if calls<=cutoff else 1
        p=Provider();result=self.run_fake(p,clock=clock)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED");self.assert_closed_once(p)

    def test_atomic_attributes_and_only_fixed_command_are_passed_to_fake_api(self):
        import ctypes as c
        calls=[];closed=[];deleted=[]
        def initialize(buffer,count,flags,size):
            self.assertEqual((count,flags),(2,0));size._obj.value=256
            return bool(buffer)
        def update(buffer,flags,attribute,value,size,previous,result):
            calls.append((attribute,tuple(value),size));self.assertEqual(flags,0);return 1
        def create(application,command,pa,ta,inherit,flags,environment,cwd,startup,process):
            self.assertEqual(application,str(w.INTERPRETER));self.assertIn(' -I -B ',command.value)
            self.assertIn(str(w.TARGET),command.value);self.assertTrue(command.value.endswith('--qualify-new-synthetic-namespace'))
            self.assertTrue(inherit);self.assertEqual(flags,0x08080004);self.assertEqual(cwd,str(w.ROOT));self.assertIsNone(environment)
            self.assertEqual((startup._obj.StartupInfo.hStdInput,startup._obj.StartupInfo.hStdOutput,startup._obj.StartupInfo.hStdError),(2,5,7))
            process._obj.hProcess=88;process._obj.hThread=99;return 1
        raw=dict(InitializeProcThreadAttributeList=initialize,UpdateProcThreadAttribute=update,DeleteProcThreadAttributeList=lambda ptr:deleted.append(1),CreateProcessW=create,CloseHandle=lambda handle:closed.append(handle) or 1)
        provider=w.NativeAdapter((c,raw,lambda:0))
        tokens=provider.create_suspended_atomic(w.Token(1,lambda:None),tuple(w.Token(n,lambda:None) for n in (2,5,7)))
        self.assertEqual([row[0] for row in calls],[0x2000D,0x20002]);self.assertEqual(calls[0][1],(1,));self.assertEqual(calls[1][1],(2,5,7));self.assertEqual(deleted,[1])
        for token in tokens:token.close()
        self.assertEqual(closed,[88,99])

    def test_atomic_postcreate_attribute_failure_closes_original_process_and_thread(self):
        import ctypes as c
        closed=[]
        def initialize(buffer,count,flags,size):size._obj.value=256;return bool(buffer)
        def create(*args):args[-1]._obj.hProcess=88;args[-1]._obj.hThread=99;return 1
        raw=dict(InitializeProcThreadAttributeList=initialize,UpdateProcThreadAttribute=lambda *args:1,
            DeleteProcThreadAttributeList=lambda ptr:(_ for _ in ()).throw(OSError()),CreateProcessW=create,CloseHandle=lambda h:closed.append(h) or 1)
        provider=w.NativeAdapter((c,raw,lambda:0))
        with self.assertRaises(w.Refused):provider.create_suspended_atomic(w.Token(1,lambda:None),tuple(w.Token(n,lambda:None) for n in (2,5,7)))
        self.assertEqual(sorted(closed),[88,99])

    def test_pipe_constructor_partial_failure_closes_every_returned_original(self):
        import ctypes as c
        closed=[];calls=0
        def create(read,write,attrs,size):
            nonlocal calls
            calls+=1;read._obj.value=calls*2;write._obj.value=calls*2+1
            return calls<2
        raw=dict(CreatePipe=create,SetHandleInformation=lambda *args:1,CloseHandle=lambda h:closed.append(h) or 1)
        provider=w.NativeAdapter((c,raw,lambda:0))
        with self.assertRaises(w.Refused):provider.create_pipes()
        self.assertEqual(sorted(closed),[2,3,4,5])

    def test_native_owner_uses_original_close_and_latches_failure(self):
        calls=[]
        def close(value):calls.append(value);return 0
        owner=w.NativeOwner(12,close)
        with self.assertRaises(w.Refused):owner.close()
        with self.assertRaises(w.Refused):owner.close()
        self.assertEqual(calls,[12])

    @staticmethod
    def facts(raw=b"synthetic",**changes):
        import stat
        values=dict(st_dev=2**63+1,st_ino=2**120+3,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=len(raw),st_mtime_ns=77,st_ctime_ns=88,st_file_attributes=0,st_birthtime_ns=5)
        values.update(changes);return SimpleNamespace(**values)

    def test_source_guard_keeps_both_api_clocks_and_latches_mutation(self):
        import hashlib,stat
        raw=b"synthetic";named=self.facts(raw);descriptor=self.facts(raw,st_ctime_ns=99)
        parentfacts=self.facts(raw,st_mode=stat.S_IFDIR|0o700);parent=SimpleNamespace(lstat=lambda:parentfacts)
        stream=io.BytesIO(raw);stream.fileno=lambda:37
        path=SimpleNamespace(parents=[parent],lstat=lambda:named,open=lambda mode:stream)
        with patch("os.fstat",return_value=descriptor):
            source=w.HeldSource(path,hashlib.sha256(raw).hexdigest(),len(raw));source.recheck()
            self.assertEqual((source.pair[0][6],source.pair[1][6]),(88,99))
            descriptor.st_ctime_ns=100
            with self.assertRaises(w.Refused):source.recheck()
            descriptor.st_ctime_ns=99
            with self.assertRaises(w.Refused):source.recheck()
            with self.assertRaises(w.Refused):source.close()
            self.assertTrue(stream.closed)

    def test_source_guard_missing_birth_or_changed_parent_refuses(self):
        import hashlib,stat
        raw=b"synthetic";named=self.facts(raw);descriptor=self.facts(raw)
        parentfacts=self.facts(raw,st_mode=stat.S_IFDIR|0o700);parent=SimpleNamespace(lstat=lambda:parentfacts)
        stream=io.BytesIO(raw);stream.fileno=lambda:37
        path=SimpleNamespace(parents=[parent],lstat=lambda:named,open=lambda mode:stream)
        with patch("os.fstat",return_value=descriptor):
            source=w.HeldSource(path,hashlib.sha256(raw).hexdigest());parentfacts.st_ino+=1
            with self.assertRaises(w.Refused):source.recheck()
            with self.assertRaises(w.Refused):source.close()
        invalid=self.facts(raw,st_birthtime_ns=None)
        with self.assertRaises(w.Refused):w._file_facts(invalid)

    def test_receipt_parent_replacement_and_same_id_reparse_refuse(self):
        import stat
        class Stream(io.BytesIO):
            def fileno(self):return 37
        class Parent:
            def __init__(self,facts):self.facts=facts
            def lstat(self):return self.facts
        for mode in ("parent","reparse"):
            parentfacts=self.facts(st_mode=stat.S_IFDIR|0o700);parent=Parent(parentfacts)
            stream=Stream();attributes=[0]
            def facts(ctime_offset):
                length=len(stream.getvalue())
                return self.facts(st_size=length,st_mtime_ns=100+length,st_ctime_ns=200+length+ctime_offset,st_file_attributes=attributes[0])
            path=SimpleNamespace(parents=[parent],lstat=lambda:facts(0),open=lambda mode:stream)
            def absent():raise FileNotFoundError()
            forbidden=SimpleNamespace(parents=[parent],lstat=absent)
            with patch("os.fstat",side_effect=lambda fd:facts(77)),patch("os.fsync",lambda fd:None):
                receipt=w.Receipt(path,forbidden);receipt.reserve(b"reserved")
                if mode=="parent":parentfacts.st_ino+=1
                else:attributes[0]=0x400
                with self.assertRaises(w.Refused):receipt.finish(b"finished")
                with self.assertRaises(w.Refused):receipt.close()
                self.assertTrue(stream.closed)

    def test_closed_numeric_handle_reuse_has_new_owned_generation(self):
        p=Provider();p.objects[8].value=3  # new process reuses already-closed stdin writer value
        result=self.run_fake(p)
        self.assertEqual(result["status"],"SUPERVISION_COMPLETE_NOT_PLATFORM_ACCEPTANCE")
        self.assertEqual(p.objects[3].close_calls,1);self.assertEqual(p.objects[8].close_calls,1)
        self.assertEqual(p.objects[9].close_calls,1)

    def test_source_recheck_failure_before_resume_prevents_target_execution(self):
        p=Provider();calls=0
        def guard():
            nonlocal calls
            calls+=1
            if "create_suspended_atomic" in p.events:raise OSError()
        with patch.object(w,"MAX_RUN_POLLS",4),patch.object(w,"MAX_CLEANUP_POLLS",3):result=w.supervise(p,clock=lambda:0,pause=lambda t:None,source_recheck=guard)
        self.assertGreaterEqual(calls,2);self.assertFalse(p.resumed);self.assertEqual(result["status"],"FAILED");self.assert_closed_once(p)

    def test_output_exact_ceiling_is_retained_but_not_accepted_as_status(self):
        p=Provider();p.output=b"x"*4096;out=self.run_fake(p)
        self.assertEqual(out["stdout_bytes"],4096);self.assertEqual(out["status"],"FAILED");self.assert_closed_once(p)

    def test_partial_initial_receipt_write_stays_consumed_without_native_factory(self):
        import stat
        class Parent:
            def lstat(inner):return self.facts(st_mode=stat.S_IFDIR|0o700)
        class Stream(io.BytesIO):
            def fileno(self):return 37
            def write(self,raw):return super().write(raw[:-1])
        parent=Parent();stream=Stream()
        def facts(offset):return self.facts(st_size=len(stream.getvalue()),st_mtime_ns=10+len(stream.getvalue()),st_ctime_ns=20+offset+len(stream.getvalue()))
        path=SimpleNamespace(parents=[parent],lstat=lambda:facts(0),open=lambda mode:stream)
        def absent():raise FileNotFoundError()
        forbidden=SimpleNamespace(parents=[parent],lstat=absent)
        receipt=w.Receipt(path,forbidden);sources=SimpleNamespace(verify=lambda:self.fail("sources"),recheck=lambda:self.fail("recheck"),close=lambda:None)
        with patch("os.fstat",side_effect=lambda fd:facts(9)),patch("os.fsync",lambda fd:None):
            code,result=w.execute_model(lambda:self.fail("native factory"),sources,receipt)
        self.assertEqual(code,1);self.assertEqual(result["status"],"FAILED");self.assertTrue(stream.closed)

    def test_wrong_cli_cannot_construct_adapter_or_touch_fixed_receipt(self):
        with patch.object(w,"NativeAdapter",side_effect=AssertionError()),patch.object(w,"Receipt",side_effect=AssertionError()),patch("builtins.print"):
            for args in ([],["--guard-fixed-qualification","extra"],["--command","private"],("--guard-fixed-qualification",)):
                self.assertEqual(w.main(args),1)

    def test_createpipe_outparams_filled_then_exception_closes_both_originals(self):
        import ctypes as c
        closed=[]
        def create(read,write,attrs,size):
            read._obj.value=72;write._obj.value=73
            raise KeyboardInterrupt()
        provider=w.NativeAdapter((c,dict(CreatePipe=create,SetHandleInformation=lambda *args:1,CloseHandle=lambda h:closed.append(h) or 1),lambda:0))
        with self.assertRaises(w.Refused):provider.create_pipes()
        self.assertEqual(sorted(closed),[72,73])

    def test_createprocess_outparams_filled_then_exception_close_process_thread(self):
        import ctypes as c
        closed=[];deleted=[]
        def initialize(buffer,count,flags,size):size._obj.value=256;return bool(buffer)
        def create(*args):
            args[-1]._obj.hProcess=82;args[-1]._obj.hThread=83
            raise KeyboardInterrupt()
        raw=dict(InitializeProcThreadAttributeList=initialize,UpdateProcThreadAttribute=lambda *args:1,
            DeleteProcThreadAttributeList=lambda ptr:deleted.append(1),CreateProcessW=create,CloseHandle=lambda h:closed.append(h) or 1)
        provider=w.NativeAdapter((c,raw,lambda:0))
        with self.assertRaises(w.Refused):provider.create_suspended_atomic(w.Token(1,lambda:None),tuple(w.Token(n,lambda:None) for n in (2,5,7)))
        self.assertEqual(sorted(closed),[82,83]);self.assertEqual(deleted,[1])

    def test_untransferred_job_factory_cleanup_failure_never_confirms_absence(self):
        import ctypes as c
        closed=[]
        provider=w.NativeAdapter((c,dict(CreateJobObjectW=lambda *args:10,CloseHandle=lambda h:closed.append(h) or 0),lambda:0))
        provider._owner_factory=lambda *args:(_ for _ in ()).throw(RuntimeError())
        result=self.run_fake(provider)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED")
        self.assertFalse(result["job_empty"]);self.assertEqual(closed,[10])

    def test_untransferred_pipe_cleanup_uncertainty_keeps_known_job_cleanup(self):
        p=Provider()
        def fail_pipe():raise RuntimeError("unknown partial ownership")
        p.create_pipes=fail_pipe;result=self.run_fake(p)
        self.assertEqual(result["status"],"FAILED");self.assertEqual(result["cleanup"],"UNCONFIRMED")
        self.assertEqual(p.objects[1].close_calls,1)
