"""Fake clocks/providers/Win32 functions only. No native construction/children."""
import ctypes as c
import io
import math
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from infra import m4_platform_qualification as q
from infra import evidence_release_reservations as reservations


class FakeLab:
    def __init__(self):
        self.calls = []
        self.closed = 0
        self.results = {n:q._passed("MODEL" if n == q.CASES[-1] else "ACTUAL") for n in q.CASES}
        self.failure = None

    def prepare(self):
        self.calls.append("prepare")
        if self.failure == "prepare": raise RuntimeError("synthetic private canary")
        return dict(namespace_nonce="1"*32,owner_sha256="a"*64,restricting_sids_observed=True)

    def observation(self):
        return dict(stage="FAKE_STAGE",last_error_observed=5,attribution="UNCONFIRMED")

    def close(self):
        self.closed += 1
        if self.failure == "close": raise RuntimeError("synthetic close failure")

    def invoke(self,name):
        self.calls.append(name)
        if self.failure == name: raise RuntimeError("synthetic private canary")
        return dict(self.results[name])


for _name in q.CASES:
    setattr(FakeLab,_name,lambda self,name=_name:self.invoke(name))


class ProtocolTests(unittest.TestCase):
    def test_positive_model_matrix_never_grants_authority(self):
        lab=FakeLab(); result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(lab.calls,["prepare"]+list(q.CASES))
        self.assertEqual(lab.closed,1)
        self.assertEqual(result["status"],"MEASURED_MATRIX_ONLY_NOT_PRODUCTION_AUTHORITY")
        self.assertFalse(result["qualification_authority"] or result["production_enabled"])

    def test_unavailable_fixture_never_passes(self):
        lab=FakeLab()
        lab.results["reparse_refusal"]={"status":"UNAVAILABLE","kind":"ACTUAL","code":"PRIVILEGE_UNAVAILABLE"}
        result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(result["status"],"INCOMPLETE_UNAVAILABLE_REQUIRED_CASES")
        self.assertEqual(result["cases"]["reparse_refusal"]["status"],"UNAVAILABLE")

    def test_every_case_exception_stops_before_later_calls_and_closes(self):
        for name in ("prepare",)+q.CASES:
            with self.subTest(name=name):
                lab=FakeLab();lab.failure=name
                result=q.run_protocol(lab,clock=lambda:0)
                self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")
                self.assertEqual(lab.calls[-1],name)
                self.assertEqual(lab.closed,1)
                self.assertNotIn("canary",str(result))

    def test_failed_case_is_not_successful_global_result(self):
        lab=FakeLab(); lab.results[q.CASES[0]]["status"]="FAILED"
        result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")
        self.assertEqual(lab.calls,["prepare",q.CASES[0]])

    def test_model_result_cannot_claim_actual_fault_measurement(self):
        lab=FakeLab();lab.results[q.CASES[-1]]["kind"]="ACTUAL"
        result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")

    def test_exact_status_kind_strings_required(self):
        class Claimed(str):pass
        for key,value in (("status",Claimed("PASSED")),("kind",Claimed("ACTUAL"))):
            row=q._passed();row[key]=value
            with self.assertRaises(q.Refused):q._case_result(row,"ACTUAL")

    def test_snapshot_callbacks_before_prepare_mutation(self):
        lab=FakeLab(); original=lab.prepare
        def mutate():
            lab.identity_owner_private=lambda: self.fail("replacement used")
            lab.close=lambda: self.fail("replacement close used")
            return original()
        lab.prepare=mutate
        result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(result["status"],"MEASURED_MATRIX_ONLY_NOT_PRODUCTION_AUTHORITY")
        self.assertEqual(lab.closed,1)

    def test_deadline_after_callback_failure_still_closes(self):
        lab=FakeLab(); clock_value=[0]
        def callback():
            clock_value[0]=61
            return q._passed()
        lab.identity_owner_private=callback
        result=q.run_protocol(lab,clock=lambda:clock_value[0])
        self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")
        self.assertEqual(lab.closed,1)
        self.assertNotIn(q.CASES[1],lab.calls)

    def test_invalid_backwards_and_raising_clocks_always_attempt_original_close(self):
        for mode in ("nan","infinite","raises","backwards"):
            calls=[0]
            def clock():
                calls[0]+=1
                if mode=="raises":raise RuntimeError()
                if mode=="nan":return float("nan")
                if mode=="infinite":return float("inf")
                return 2 if calls[0]==1 else 1
            lab=FakeLab();result=q.run_protocol(lab,clock=clock)
            self.assertEqual(lab.closed,1)
            self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")

    def test_late_close_failure_stays_unconfirmed(self):
        lab=FakeLab();lab.failure="close"
        result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")
        self.assertEqual(result["cleanup"],"UNCONFIRMED")

    def test_cleanup_clock_rollback_refuses_after_original_close(self):
        calls=[0]
        def clock():
            calls[0]+=1
            return 10 if calls[0] <= 21 else 1
        lab=FakeLab();result=q.run_protocol(lab,clock=clock)
        self.assertEqual(lab.closed,1)
        self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")
        self.assertEqual(result["cleanup"],"UNCONFIRMED")

    def test_safe_result_schema_rejects_raw_owner_and_arbitrary_paths(self):
        lab=FakeLab();lab.prepare=lambda:dict(owner="S-1-private-canary")
        result=q.run_protocol(lab,clock=lambda:0)
        self.assertEqual(result["status"],"FAILED_OR_UNCONFIRMED")
        self.assertNotIn("private-canary",str(result))
        self.assertNotIn(q.CASES[0],lab.calls)

    def test_child_nonce_parent_binding_rejects_arbitrary_namespace_paths(self):
        self.assertEqual(q.validate_child_request("1"*32,"123",123),"1"*32)
        for nonce,parent,actual in (("../old","123",123),("1"*32,"123",124),
                                    ("1"*32,"-1",-1),("1"*33,"123",123),("1"*32,"123",True)):
            with self.assertRaises(q.Refused):q.validate_child_request(nonce,parent,actual)

    def test_invalid_cli_never_constructs_native_or_calls_child(self):
        for args in ([],["--root","private"],["--qualify-new-synthetic-namespace","extra"]):
            with patch.object(q,"NativeLab") as lab,patch.object(q,"_child") as child,patch("builtins.print"):
                self.assertEqual(q.main(args),1)
                lab.assert_not_called();child.assert_not_called()

    def test_partial_initial_receipt_write_never_constructs_native_lab(self):
        class Report:
            closed=0
            def fileno(self):return 17
            def write(self,raw):return len(raw)-1
            def close(self):self.closed+=1
        report=Report()
        class FakePath:
            def __init__(self,value):self.value=str(value).replace("\\","/")
            def __truediv__(self,other):return FakePath(self.value+"/"+str(other))
            def __eq__(self,other):return isinstance(other,FakePath) and self.value.casefold()==other.value.casefold()
            def absolute(self):return self
            @property
            def parents(self):return ()
            def open(self,mode):
                self.mode=mode
                return report
        with patch("pathlib.Path",side_effect=FakePath),patch("os.fstat",return_value=SimpleNamespace(st_dev=1,st_ino=2)),\
             patch.object(q.sys,"platform","win32"),patch.object(q,"NativeLab") as lab,patch.object(q,"WinApi") as api,patch("builtins.print"):
            self.assertEqual(q.main(["--qualify-new-synthetic-namespace"]),1)
            lab.assert_not_called();api.assert_not_called()
        self.assertEqual(report.closed,1)

    def test_production_boundary_does_not_touch_objects(self):
        class Trap:
            def __getattribute__(self,n):raise AssertionError("touched")
        with self.assertRaises(q.Refused):q.production_qualify(Trap())


class FakeWinApiTests(unittest.TestCase):
    def api(self):
        # Bypass lazy constructor entirely; raw functions below are Python fakes.
        api=q.WinApi.__new__(q.WinApi)
        api.c=c;api.w=SimpleNamespace(HANDLE=c.c_void_p,DWORD=c.c_uint32,BOOL=c.c_int,WORD=c.c_uint16)
        api.clear_error=lambda code:None;api.last_error=lambda:0
        return api

    def test_current_sid_token_is_derived_and_original_resources_freed(self):
        api=self.api();closed=[];freed=[]
        text=c.create_unicode_buffer("S-1-5-21-123")
        def token(process,access,out):
            c.cast(out,c.POINTER(c.c_void_p))[0]=1234
            return 1
        def tokeninfo(handle,kind,buffer,size,needed):
            c.cast(needed,c.POINTER(c.c_uint32))[0]=16
            if buffer is None:return 0
            c.cast(buffer,c.POINTER(c.c_void_p))[0]=999
            return 1
        def sidtext(pointer,out):
            c.cast(out,c.POINTER(c.c_void_p))[0]=c.addressof(text)
            return 1
        api.raw=SimpleNamespace(current=lambda:1,token=token,tokeninfo=tokeninfo,sidtext=sidtext,
                                restricted=lambda h:1,close=lambda h:closed.append(h.value) or 1,
                                free=lambda p:freed.append(p.value) or None)
        self.assertEqual(api.owner(),("S-1-5-21-123",True))
        self.assertEqual(closed,[1234]);self.assertEqual(freed,[c.addressof(text)])

    def test_token_query_failure_still_closes_original_handle(self):
        api=self.api();closed=[]
        def token(process,access,out):
            c.cast(out,c.POINTER(c.c_void_p))[0]=222
            return 1
        api.raw=SimpleNamespace(current=lambda:1,token=token,
            tokeninfo=lambda *a:0,restricted=lambda h:0,sidtext=lambda *a:0,
            close=lambda h:closed.append(h.value) or 1,free=lambda p:None)
        with self.assertRaises(q.Refused):api.owner()
        self.assertEqual(closed,[222])

    def test_acquired_file_closed_when_descriptor_cleanup_raises(self):
        api=self.api();closed=[]
        api.raw=SimpleNamespace(create=lambda *a:333,close=lambda h:closed.append(h) or 1)
        def descriptor(owner,action):
            action(None)
            raise RuntimeError("descriptor free failure")
        api.descriptor=descriptor
        with self.assertRaises(RuntimeError):api.create("synthetic","S-1-5-21",b"x")
        self.assertEqual(closed,[333])

    def test_descriptor_snapshots_original_free_before_action_mutation(self):
        api=self.api();freed=[]
        def sddl(text,version,out,unused):
            self.assertEqual(text,"O:S-1-5-21D:P(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-21)")
            c.cast(out,c.POINTER(c.c_void_p))[0]=444
            return 1
        api.raw=SimpleNamespace(sddl=sddl,free=lambda p:freed.append(p.value) or None)
        def action(attrs):
            api.raw.free=lambda p:self.fail("replacement free called")
            return "fixture"
        self.assertEqual(api.descriptor("S-1-5-21",action),"fixture")
        self.assertEqual(freed,[444])

    def test_sharing_unexpected_success_closes_acquired_original(self):
        api=self.api();closed=[]
        api.raw=SimpleNamespace(create=lambda *a:555,close=lambda h:closed.append(h) or 1)
        with self.assertRaises(q.Refused):api.sharing("synthetic","moved")
        self.assertEqual(closed,[555])

    def test_sharing_retains_close_before_acquisition_callback_mutation(self):
        api=self.api();closed=[]
        def create(*args):
            api.raw.close=lambda h:self.fail("replacement close used")
            return 556
        api.raw=SimpleNamespace(create=create,close=lambda h:closed.append(h) or 1)
        with self.assertRaises(q.Refused):api.sharing("synthetic","moved")
        self.assertEqual(closed,[556])

    def test_native_lab_cleanup_attempts_each_original_once_and_latches(self):
        lab=q.NativeLab(api=object(),backend=object());events=[]
        def fail():events.append("first");raise RuntimeError()
        lab._close_later(lambda:events.append("last"));lab._close_later(fail)
        with self.assertRaises(q.Refused):lab.close()
        with self.assertRaises(q.Refused):lab.close()
        self.assertEqual(events,["first","last"])

    def test_unexpected_accepted_alias_snapshots_are_closed_before_refusal(self):
        for method in ("hardlink_duplicate_refusal","reparse_refusal"):
            closed=[]
            snapshot=SimpleNamespace(close=lambda:closed.append("original"))
            lab=q.NativeLab(api=object(),backend=SimpleNamespace(
                capture_owned=lambda *a,**kw:snapshot,ReservationRefused=reservations.ReservationRefused))
            lab._guard=lambda:None;lab.root="synthetic";lab.source="synthetic-source";lab.owner="fixture"
            lab._api=SimpleNamespace(hardlink=lambda *a:None,reparse=lambda *a:None)
            lab.provider=SimpleNamespace(open_source=lambda path:object())
            with self.assertRaises(q.Refused):getattr(lab,method)()
            self.assertEqual(closed,["original"])

    def test_parent_recheck_failure_still_closes_all_originals_and_latches(self):
        lab=q.NativeLab(api=object(),backend=object());closed=[]
        def fail():raise reservations.ReservationRefused()
        lab.parents=[SimpleNamespace(recheck=fail)]
        lab._close_later(lambda:closed.append(1));lab._close_later(lambda:closed.append(2))
        with self.assertRaises(q.Refused):lab.close()
        with self.assertRaises(q.Refused):lab.close()
        self.assertEqual(closed,[2,1])


class SourceIdentityTests(unittest.TestCase):
    def facts(self,*,directory=False):
        return SimpleNamespace(st_dev=2**63+7,st_ino=2**127+9,st_mode=(stat.S_IFDIR if directory else stat.S_IFREG)|0o600,
            st_nlink=1,st_size=123,st_mtime_ns=1111,st_ctime_ns=2222,st_file_attributes=0,st_birthtime_ns=3333)

    def test_initial_source_facts_preserve_full_integer_widths_and_reject_links(self):
        facts=self.facts();observed=q._source_file_facts(facts)
        self.assertEqual(observed[:2],(2**63+7,2**127+9))
        facts.st_nlink=2
        with self.assertRaises(q.Refused):q._source_file_facts(facts)
        facts.st_nlink=1;facts.st_file_attributes=0x400
        with self.assertRaises(q.Refused):q._source_file_facts(facts)

    def test_initial_source_identity_rechecks_path_and_ancestor_without_file_io(self):
        facts=self.facts();directory=self.facts(directory=True)
        ancestor=SimpleNamespace(lstat=lambda:directory)
        path=SimpleNamespace(lstat=lambda:facts,parents=[ancestor])
        stream=SimpleNamespace(fileno=lambda:17)
        with patch("os.fstat",return_value=facts):
            identity=q._source_identity(path,stream)
            self.assertEqual(identity[0],q._source_file_facts(facts))
            directory.st_file_attributes=0x400
            with self.assertRaises(q.Refused):q._source_identity(path,stream)

    def test_stable_distinct_api_ctimes_preserved_and_each_mutation_refuses(self):
        named=self.facts();descriptor=self.facts();descriptor.st_ctime_ns=4444
        path=SimpleNamespace(lstat=lambda:named,parents=[])
        stream=SimpleNamespace(fileno=lambda:17)
        with patch("os.fstat",return_value=descriptor):
            original=q._source_identity(path,stream)
            self.assertEqual((original[0][6],original[1][6]),(2222,4444))
            q._recheck_source_identity(path,stream,original)
            for subject in (named,descriptor):
                old=subject.st_ctime_ns;subject.st_ctime_ns+=1
                with self.assertRaises(q.Refused):q._recheck_source_identity(path,stream,original)
                subject.st_ctime_ns=old
            named.st_birthtime_ns+=1
            with self.assertRaises(q.Refused):q._recheck_source_identity(path,stream,original)

    def test_missing_or_malformed_birth_clock_refuses(self):
        for value in (None,True,"3333",-1):
            facts=self.facts();facts.st_birthtime_ns=value
            with self.assertRaises(q.Refused):q._source_file_facts(facts)

    def test_backend_module_cleanup_preserves_foreign_replacement(self):
        name="_m4_fake_qualification_fixture";original=object();replacement=object()
        sys.modules[name]=replacement
        try:
            with self.assertRaises(q.Refused):q._release_backend_module(sys.modules,name,original)
            self.assertIs(sys.modules[name],replacement)
        finally:del sys.modules[name]


class ModelOwned:
    def __init__(self,serial,*,directory=False,fault=None):
        self.payload=b"";self.closed=0;self.fault=fault;self.directory=directory
        self.facts=dict(volume=2**63+19,file_id=f"{serial:032x}",attributes=16 if directory else 0,
                        links=1,size=0,disk=True,private=True,owner="fixture-owner")
    def identity(self):return dict(self.facts,size=len(self.payload))
    def read(self,bound):return self.payload[:bound]
    def write(self,raw):
        self.payload=raw[:1] if self.fault=="partial" else raw
        return len(self.payload)
    def flush(self):
        if self.fault=="flush":raise RuntimeError("synthetic flush failure")
    def close(self):
        self.closed+=1
        if self.fault=="close":raise RuntimeError("synthetic close failure")


class ModelProvider:
    def __init__(self,fault):self.fault=fault;self.originals={};self.parents=[]
    def pin_parent(self,path):
        row=ModelOwned(1+len(self.parents),directory=True);self.parents.append(row);return row
    def create_new(self,path,payload):
        if path in self.originals:raise reservations.ReservationRefused()
        row=ModelOwned(999,fault=self.fault);self.originals[path]=row;return row


class InjectedFaultTests(unittest.TestCase):
    def test_partial_write_flush_and_close_leave_consumed_originals_model_only(self):
        for fault in ("partial","flush","close"):
            with self.subTest(fault=fault):
                provider=ModelProvider(fault)
                store=reservations.ProtectedReservationStore(provider,owner="fixture-owner")
                payload=dict(authorization_sha256="a"*64,source_bundle_sha256="b"*64)
                with self.assertRaises(reservations.ReservationRefused):store.reserve("FRESH_PREFLIGHT","1"*32,payload)
                self.assertEqual(len(provider.originals),1)
                original=next(iter(provider.originals.values()))
                self.assertEqual(original.closed,1)
                with self.assertRaises(reservations.ReservationRefused):
                    reservations.ProtectedReservationStore(provider,owner="fixture-owner").reserve("ONE_COMPARISON","1"*32,payload)
                self.assertEqual(len(provider.originals),1)
                self.assertEqual(original.closed,1)


class FakeThread:
    def __init__(self,*,target,args,daemon):self.target=target;self.args=args
    def start(self):self.target(*self.args)
    def join(self,timeout):pass
    def is_alive(self):return False


class FakeProcess:
    def __init__(self,stdout=b"ok",stderr=b"",timeout=False):
        self.stdout=io.BytesIO(stdout);self.stderr=io.BytesIO(stderr)
        self.timeout=timeout;self.killed=0;self.handle_closed=0;self.waits=0
        self._handle=SimpleNamespace(Close=self.close_handle)
    def close_handle(self):self.handle_closed+=1
    def wait(self,timeout):
        self.waits+=1
        if self.timeout and not self.killed:raise TimeoutError()
        return 0
    def poll(self):return None if self.timeout and not self.killed else 0
    def kill(self):self.killed+=1


class FakeChildTests(unittest.TestCase):
    def test_bounded_fake_child_streams_and_original_resources(self):
        process=FakeProcess()
        self.assertEqual(q._collect_child(process,thread_factory=FakeThread,clock=lambda:0),(b"ok",b""))
        self.assertTrue(process.stdout.closed and process.stderr.closed)
        self.assertEqual(process.handle_closed,1)

    def test_overflow_rejects_at_4097_sentinel_and_closes_both_streams(self):
        for out,err in ((b"x"*4097,b""),(b"",b"x"*4097)):
            process=FakeProcess(out,err)
            with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=FakeThread,clock=lambda:0)
            self.assertTrue(process.stdout.closed and process.stderr.closed)
            self.assertEqual(process.handle_closed,1)

    def test_timeout_kills_exact_fake_child_and_closes_originals(self):
        process=FakeProcess(timeout=True)
        with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=FakeThread,clock=lambda:0)
        self.assertEqual(process.killed,1);self.assertEqual(process.waits,2)
        self.assertEqual(process.handle_closed,1)

    def test_poll_failure_still_attempts_kill_and_all_closes(self):
        process=FakeProcess()
        process.poll=lambda:(_ for _ in ()).throw(RuntimeError())
        with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=FakeThread,clock=lambda:0)
        self.assertEqual(process.killed,1);self.assertEqual(process.handle_closed,1)
        self.assertTrue(process.stdout.closed and process.stderr.closed)

    def test_child_cleanup_clock_rollback_or_nonfinite_still_closes_originals(self):
        for last in (1,float("nan"),float("inf")):
            calls=[0]
            def clock():
                calls[0]+=1
                return 10 if calls[0]==1 else last
            process=FakeProcess()
            with self.assertRaises(q.Refused):q._collect_child(process,thread_factory=FakeThread,clock=clock)
            self.assertEqual(process.handle_closed,1)
            self.assertTrue(process.stdout.closed and process.stderr.closed)


if __name__=="__main__":unittest.main()
