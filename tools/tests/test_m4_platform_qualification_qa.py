"""Independent C03 injected fakes only; no native constructor, thread or child."""
import io
import math
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from infra import m4_platform_qualification as q


class Laboratory:
    def __init__(self):
        self.events=[];self.closes=0;self.bad=None;self.unavailable=None
        for name in q.CASES:setattr(self,name,lambda name=name:self.case(name))
    def prepare(self):
        self.events.append("prepare")
        return dict(namespace_nonce="a"*32,owner_sha256="b"*64,restricting_sids_observed=False)
    def case(self,name):
        self.events.append(name)
        if name==self.bad:raise RuntimeError("synthetic-sensitive-canary")
        return dict(status="UNAVAILABLE" if name==self.unavailable else "PASSED",kind="MODEL" if name==q.CASES[-1] else "ACTUAL",code="FIXTURE")
    def observation(self):return dict(stage="FIXTURE",last_error_observed=5,attribution="UNCONFIRMED")
    def close(self):self.closes+=1


class InlineThread:
    def __init__(self,target,args,daemon):self.target=target;self.args=args
    def start(self):self.target(*self.args)
    def join(self,timeout):pass
    def is_alive(self):return False


class Process:
    def __init__(self,stdout=b"ok",stderr=b""):
        self.stdout=io.BytesIO(stdout);self.stderr=io.BytesIO(stderr);self.killed=0;self.waits=0;self.closed=0;self.wait_error=False;self.poll_error=False
        self._handle=SimpleNamespace(Close=self.close_handle)
    def close_handle(self):self.closed+=1
    def wait(self,timeout):
        self.waits+=1
        if self.wait_error and not self.killed:raise TimeoutError()
        return 0
    def poll(self):
        if self.poll_error:raise OSError()
        return None if self.wait_error and not self.killed else 0
    def kill(self):self.killed+=1


class PlatformIndependentQA(unittest.TestCase):
    def test_fixed_full_protocol_no_authority(self):
        lab=Laboratory();out=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(lab.events,["prepare"]+list(q.CASES));self.assertEqual(lab.closes,1)
        self.assertFalse(out["qualification_authority"] or out["production_enabled"])
        self.assertFalse(out["host_observation"]["restricting_sids_observed"])

    def test_each_case_exception_closes_once_and_omits_input(self):
        for name in q.CASES:
            lab=Laboratory();lab.bad=name;out=q.run_protocol(lab,clock=lambda:0)
            self.assertEqual(out["status"],"FAILED_OR_UNCONFIRMED");self.assertEqual(lab.events[-1],name);self.assertEqual(lab.closes,1)
            self.assertNotIn("sensitive",str(out));self.assertEqual(out["failure_observation"]["attribution"],"UNCONFIRMED")

    def test_unavailable_privilege_does_not_qualify(self):
        lab=Laboratory();lab.unavailable="reparse_refusal";out=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(out["status"],"INCOMPLETE_UNAVAILABLE_REQUIRED_CASES")
        self.assertEqual(out["cases"]["reparse_refusal"]["status"],"UNAVAILABLE")

    def test_status_kind_strict_schema_and_injected_model_separation(self):
        for row in (dict(status="PASSED",kind="ACTUAL",code="private path"),dict(status="PASSED",kind="MODEL",code="OK"),dict(status=True,kind="ACTUAL",code="OK"),dict(status="PASSED",kind="ACTUAL",code="OK",raw="canary")):
            lab=Laboratory();setattr(lab,q.CASES[0],lambda row=row:row)
            self.assertEqual(q.run_protocol(lab,clock=lambda:0)["status"],"FAILED_OR_UNCONFIRMED")

    def test_prepare_extra_raw_owner_and_wrong_token_type_refuse(self):
        for changes in (dict(owner="S-1-secret"),dict(restricting_sids_observed=0),dict(owner_sha256="unknown")):
            lab=Laboratory();old=lab.prepare
            def altered(old=old,changes=changes):value=old();value.update(changes);return value
            lab.prepare=altered;out=q.run_protocol(lab,clock=lambda:0)
            self.assertEqual(out["status"],"FAILED_OR_UNCONFIRMED");self.assertEqual(lab.closes,1)

    def test_original_callbacks_survive_prepare_substitution(self):
        lab=Laboratory();original=lab.prepare
        def changed():
            lab.close=lambda:self.fail("replacement close")
            setattr(lab,q.CASES[0],lambda:self.fail("replacement case"))
            return original()
        lab.prepare=changed;self.assertEqual(q.run_protocol(lab,clock=lambda:0)["status"],"MEASURED_MATRIX_ONLY_NOT_PRODUCTION_AUTHORITY");self.assertEqual(lab.closes,1)

    def test_cleanup_exception_never_accepted(self):
        lab=Laboratory()
        def failclose():lab.closes+=1;raise OSError()
        lab.close=failclose;out=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(out["cleanup"],"UNCONFIRMED");self.assertEqual(out["status"],"FAILED_OR_UNCONFIRMED");self.assertEqual(lab.closes,1)

    def test_cleanup_clock_rollback_refuses_after_owed_close(self):
        lab=Laboratory();calls=0
        def clock():
            nonlocal calls
            calls+=1
            return 10 if calls<=21 else 1
        out=q.run_protocol(lab,clock=clock)
        self.assertEqual(out["status"],"FAILED_OR_UNCONFIRMED");self.assertEqual(lab.closes,1)

    def test_nonfinite_or_late_callback_clock_never_accepted(self):
        for second in (math.nan,math.inf,True,-1,61):
            lab=Laboratory();times=iter([0,second])
            out=q.run_protocol(lab,clock=lambda:next(times,0))
            self.assertEqual(out["status"],"FAILED_OR_UNCONFIRMED");self.assertEqual(lab.closes,1)

    def test_child_nonce_parent_strict_exact_binding(self):
        self.assertEqual(q.validate_child_request("a"*32,"21",21),"a"*32)
        for nonce,parent,actual in (("../private","21",21),("a"*32,"021",21),("a"*32,"21",22),("a"*32,"21",True)):
            with self.assertRaises(q.Refused):q.validate_child_request(nonce,parent,actual)

    def test_production_and_invalid_cli_never_construct_native(self):
        class Poison:
            def __getattribute__(self,name):raise AssertionError(name)
        with self.assertRaises(q.Refused):q.production_qualify(Poison())
        with patch.object(q,"WinApi",side_effect=AssertionError()),patch.object(q,"NativeLab",side_effect=AssertionError()),patch("builtins.print"):
            self.assertEqual(q.main([]),1)

    def test_parent_mutation_closes_all_originals_and_stays_failed(self):
        calls=[]
        parent=SimpleNamespace(recheck=lambda:(_ for _ in ()).throw(OSError()))
        fake=SimpleNamespace(closed=False,failed=False,parents=[parent],cleanups=[lambda:calls.append(1),lambda:calls.append(2)])
        with self.assertRaises(q.Refused):q.NativeLab.close(fake)
        self.assertEqual(calls,[2,1])
        with self.assertRaises(q.Refused):q.NativeLab.close(fake)
        self.assertEqual(calls,[2,1])

    def test_alias_creation_unavailable_not_fabricated_pass(self):
        def unavailable(*args):raise q.Unavailable()
        fake=SimpleNamespace(_guard=lambda:None,_api=SimpleNamespace(hardlink=unavailable,reparse=unavailable),root="synthetic",source="synthetic-source")
        self.assertEqual(q.NativeLab.hardlink_duplicate_refusal(fake)["status"],"UNAVAILABLE")
        self.assertEqual(q.NativeLab.reparse_refusal(fake)["status"],"UNAVAILABLE")

    def test_unexpected_accepted_alias_closes_before_refusal(self):
        calls=[];snapshot=SimpleNamespace(close=lambda:calls.append("close"))
        backend=SimpleNamespace(capture_owned=lambda *a,**k:snapshot,ReservationRefused=ValueError)
        fake=SimpleNamespace(_guard=lambda:None,_api=SimpleNamespace(hardlink=lambda *a:None,reparse=lambda *a:None),root="synthetic",source="synthetic-source",created_aliases=0,backend=backend,provider=SimpleNamespace(open_source=lambda path:object()),owner="fixture")
        with self.assertRaises(q.Refused):q.NativeLab.hardlink_duplicate_refusal(fake)
        with self.assertRaises(q.Refused):q.NativeLab.reparse_refusal(fake)
        self.assertEqual(calls,["close","close"])

    def test_backend_namespace_foreign_replacement_preserved(self):
        name="_qa_platform_fake_namespace";registry=q.sys.modules;foreign=object();original=object();registry[name]=foreign
        try:
            with self.assertRaises(q.Refused):q._release_backend_module(registry,name,original)
            self.assertIs(registry[name],foreign)
        finally:del registry[name]

    def test_bounded_fake_child_success_closes_original_resources(self):
        process=Process();self.assertEqual(q._collect_child(process,thread_factory=InlineThread,clock=lambda:0),(b"ok",b""))
        self.assertTrue(process.stdout.closed and process.stderr.closed);self.assertEqual(process.closed,1)

    def test_each_fake_pipe_overflow_refused_at_sentinel(self):
        for pipe in (0,1):
            process=Process(b"x"*4097 if pipe==0 else b"ok",b"x"*4097 if pipe else b"")
            with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=InlineThread,clock=lambda:0)
            self.assertTrue(process.stdout.closed and process.stderr.closed);self.assertEqual(process.closed,1)

    def test_fake_child_timeout_or_poll_failure_attempts_owned_kill_and_close(self):
        for mode in ("timeout","poll"):
            process=Process();process.wait_error=mode=="timeout";process.poll_error=mode=="poll"
            with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=InlineThread,clock=lambda:0)
            self.assertEqual(process.killed,1);self.assertEqual(process.closed,1);self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_reader_failure_still_closes_both_originals(self):
        process=Process();process.stdout.read=lambda n:(_ for _ in ()).throw(OSError())
        with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=InlineThread,clock=lambda:0)
        self.assertTrue(process.stdout.closed and process.stderr.closed);self.assertEqual(process.closed,1)

    @staticmethod
    def source_facts(**changes):
        row=dict(st_dev=2**63+5,st_ino=2**127+11,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=8,st_mtime_ns=123,st_ctime_ns=77,st_file_attributes=0,st_birthtime_ns=13)
        row.update(changes);return SimpleNamespace(**row)

    def test_source_pair_keeps_distinct_clocks_and_rejects_either_change(self):
        pathname=self.source_facts();descriptor=self.source_facts(st_ctime_ns=99)
        path=SimpleNamespace(lstat=lambda:pathname,parents=[]);stream=SimpleNamespace(fileno=lambda:3)
        with patch("os.fstat",return_value=descriptor):
            observed=q._source_identity(path,stream)
            self.assertEqual(observed[0][1],2**127+11);self.assertEqual((observed[0][6],observed[1][6]),(77,99))
            q._recheck_source_identity(path,stream,observed)
            pathname.st_ctime_ns=78
            with self.assertRaises(q.Refused):q._recheck_source_identity(path,stream,observed)
            pathname.st_ctime_ns=77;descriptor.st_ctime_ns=100
            with self.assertRaises(q.Refused):q._recheck_source_identity(path,stream,observed)

    def test_source_pair_missing_birth_and_common_change_refuse(self):
        for changes in (dict(st_birthtime_ns=None),dict(st_birthtime_ns=True),dict(st_birthtime_ns=14),dict(st_ino=2**127+12),dict(st_mtime_ns=124),dict(st_file_attributes=0x400),dict(st_nlink=2)):
            path=SimpleNamespace(lstat=lambda:self.source_facts(),parents=[]);stream=SimpleNamespace(fileno=lambda:3)
            with patch("os.fstat",return_value=self.source_facts(**changes)),self.assertRaises(q.Refused):q._source_identity(path,stream)

    def test_source_parent_change_detected_without_real_files(self):
        parentfacts=self.source_facts(st_mode=stat.S_IFDIR|0o700);parent=SimpleNamespace(lstat=lambda:parentfacts)
        path=SimpleNamespace(lstat=lambda:self.source_facts(),parents=[parent]);stream=SimpleNamespace(fileno=lambda:3)
        with patch("os.fstat",return_value=self.source_facts()):
            original=q._source_identity(path,stream);parentfacts.st_ino+=1
            with self.assertRaises(q.Refused):q._recheck_source_identity(path,stream,original)

    def test_child_cleanup_clock_rollback_refuses_and_closes(self):
        process=Process();ticks=iter([10,1,1,1])
        with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=InlineThread,clock=lambda:next(ticks,1))
        self.assertTrue(process.stdout.closed and process.stderr.closed);self.assertEqual(process.closed,1)
