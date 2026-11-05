"""Independent v2 restoration fixtures: never actual destinations or CLI."""
from contextlib import ExitStack,redirect_stdout
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

path=Path(__file__).resolve().parents[2]/".cache/m1-runtime/m4-restore-public-results-v2.py"
if not path.is_file():
    # The tool under test lives only in this host's local runtime area; a clean source copy cannot run it.
    raise unittest.SkipTest("local-only restoration tool .cache/m1-runtime/m4-restore-public-results-v2.py is absent")
spec=importlib.util.spec_from_file_location("qa_restoration_v2",path)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def fake(ctime=41,**changes):
    fields=dict(st_dev=2**62+3,st_ino=2**110+5,st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=5,st_mtime_ns=29,st_ctime_ns=ctime,st_file_attributes=0,st_birthtime_ns=17)
    fields.update(changes);return SimpleNamespace(**fields)


class SnapshotIndependentQA(unittest.TestCase):
    def test_distinct_clocks_preserved_and_fullwidth_identity(self):
        a,b=m.file_facts(fake()),m.file_facts(fake(ctime=999))
        self.assertEqual(m.common(a),m.common(b));self.assertNotEqual(a,b)
        self.assertEqual(a[1],2**110+5);self.assertEqual(a[6],41);self.assertEqual(b[6],999)

    def test_both_clock_changes_refuse_without_cross_normalization(self):
        original=(m.file_facts(fake()),m.file_facts(fake(ctime=999)))
        for ptime,ftime in ((42,999),(41,1000),(999,41)):
            p=SimpleNamespace(lstat=lambda:fake(ctime=ptime));f=SimpleNamespace(fileno=lambda:3)
            with patch.object(m.os,"fstat",return_value=fake(ctime=ftime)),self.assertRaises(m.Refused):m.recheck_pair(p,f,original)

    def test_common_identity_and_birthtime_changes_refuse(self):
        for key,value in (("st_dev",7),("st_ino",2**110+6),("st_mode",stat.S_IFREG|0o400),("st_size",6),("st_mtime_ns",30),("st_file_attributes",2),("st_birthtime_ns",18)):
            p=SimpleNamespace(lstat=lambda:fake());f=SimpleNamespace(fileno=lambda:3)
            with patch.object(m.os,"fstat",return_value=fake(**{key:value})),self.assertRaises(m.Refused):m.snapshot_pair(p,f)

    def test_missing_bad_birth_and_disallowed_file_facts_refuse(self):
        for changes in (dict(st_birthtime_ns=None),dict(st_birthtime_ns=True),dict(st_birthtime_ns=-1),dict(st_nlink=2),dict(st_file_attributes=0x400),dict(st_size=m.BOUND+1),dict(st_ino=0),dict(st_mode=stat.S_IFDIR|0o700)):
            with self.assertRaises(m.Refused):m.file_facts(fake(**changes))
        f=fake();del f.st_birthtime_ns
        with self.assertRaises(m.Refused):m.file_facts(f)

    def test_write_short_or_flush_or_fsync_errors_refuse(self):
        stream=SimpleNamespace(write=lambda raw:len(raw)-1)
        with self.assertRaises(m.Refused):m.write_all(stream,b"data")
        stream=SimpleNamespace(write=lambda raw:len(raw),flush=lambda:(_ for _ in ()).throw(OSError()),fileno=lambda:3)
        with self.assertRaises(OSError):m.write_all(stream,b"data")
        stream.flush=lambda:None
        with patch.object(m.os,"fsync",side_effect=OSError()),self.assertRaises(OSError):m.write_all(stream,b"data")

    def test_invalid_cli_does_not_run(self):
        with patch.object(m.sys,"argv",["fixture","--restore-eight-public-failures"]),patch.object(m,"run") as run,patch("builtins.print"):
            self.assertEqual(m.main(),1);run.assert_not_called()


class TemporaryProtocolIndependentQA(unittest.TestCase):
    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.root=Path(self.stack.enter_context(TemporaryDirectory())).resolve()
        self.stack.enter_context(patch.object(m,"ROOT",self.root));self.stack.enter_context(patch.object(m,"__file__",str(self.root/".cache/m1-runtime/m4-restore-public-results-v2.py")))
        path_stat,fd_stat=Path.lstat,os.fstat
        def convert(st,offset):
            fields={key:getattr(st,key) for key in ("st_dev","st_ino","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns")}
            fields.update(st_ctime_ns=fields["st_ctime_ns"]+offset,st_file_attributes=getattr(st,"st_file_attributes",0),st_birthtime_ns=getattr(st,"st_birthtime_ns",17));return SimpleNamespace(**fields)
        self.stack.enter_context(patch.object(Path,"lstat",lambda p:convert(path_stat(p),0)))
        self.stack.enter_context(patch.object(m.os,"fstat",lambda f:convert(fd_stat(f),777)))
        self.write(m.OLD_HELPER,b"qa immutable original source")
        sha=m.digest((self.root/m.OLD_HELPER).read_bytes());self.stack.enter_context(patch.object(m,"OLD_HELPER_SHA",sha))
        failure=dict(schema_version=1,task="TASK-597",status="FAILED_BEFORE_REPORT_RESERVATION_NO_RETRY",helper_sha256=sha,tool_exit=1,report_created=False,fixed_eight_targets_absent=True,historical_missing_count=10,retry_performed=False,cause="UNCONFIRMED",actual_runtime_operations=0)
        raw=json.dumps(failure).encode();self.write(m.OLD_FAILURE,raw);self.stack.enter_context(patch.object(m,"OLD_FAILURE_SHA",m.digest(raw)))
        rows=[];attempts=[];self.sources=[];self.destinations=[]
        for run,n,_,_ in m.ROWS:
            raw=json.dumps(dict(ok=False,synthetic_number=n)).encode();source=f"ai/reports/devops-m2-unlock-state-before-result-{n}.json";dest=f".cache/m1-runtime/mobile-emulator/{run}/result.json"
            self.write(source,raw);self.sources.append((source,raw));self.destinations.append(dest);rows.append((run,n,m.digest(raw),len(raw)));attempts.append(dict(run=run,result=dest,result_sha256=m.digest(raw),exit=1))
        self.stack.enter_context(patch.object(m,"ROWS",tuple(rows)))
        history=json.dumps(dict(task="TASK-088",recorded_at_utc="2026-10-19T09:04:41.762615+00:00",attempts=attempts)).encode();self.write(m.HASH_SOURCE,history);self.stack.enter_context(patch.object(m,"HASH_SOURCE_SHA",m.digest(history)))
        self.stack.enter_context(redirect_stdout(io.StringIO()))

    def write(self,p,raw):
        path=self.root/p;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)

    def report(self):return json.loads((self.root/m.REPORT).read_bytes())

    def test_complete_eight_failed_results_and_no_other_originals(self):
        self.assertEqual(m.run(),0);r=self.report()
        self.assertEqual(r["files_copied"],8);self.assertEqual(r["unresolved"],2);self.assertTrue(r["source_handles_closed"])
        self.assertFalse(r["retry_allowed"] or r["protected_os_qualification"])
        for (source,raw),dest in zip(self.sources,self.destinations):
            self.assertEqual((self.root/source).read_bytes(),raw);self.assertEqual((self.root/dest).read_bytes(),raw);self.assertIs(json.loads(raw)["ok"],False)
        self.assertTrue(all(not (self.root/p).exists() for p in m.UNRESOLVED));self.assertFalse((self.root/m.OLD_REPORT).exists())

    def test_final_source_failure_prevents_every_mutation(self):
        self.write(self.sources[-1][0],b"corrupt")
        self.assertEqual(m.run(),1);self.assertFalse((self.root/m.REPORT).exists());self.assertTrue(all(not (self.root/p).exists() for p in self.destinations))

    def test_old_failure_and_helper_byte_changes_refuse_before_reservation(self):
        for path in (m.OLD_HELPER,m.OLD_FAILURE):
            original=(self.root/path).read_bytes();self.write(path,b"changed")
            self.assertEqual(m.run(),1);self.assertFalse((self.root/m.REPORT).exists());self.write(path,original)

    def test_equal_destination_not_adopted(self):
        self.write(self.destinations[-1],self.sources[-1][1]);self.assertEqual(m.run(),1)
        self.assertFalse((self.root/m.REPORT).exists());self.assertFalse((self.root/self.destinations[0]).exists())

    def test_unresolved_existing_prevents_all_new_outputs(self):
        self.write(m.UNRESOLVED[0],b"foreign")
        self.assertEqual(m.run(),1);self.assertFalse((self.root/m.REPORT).exists());self.assertEqual((self.root/m.UNRESOLVED[0]).read_bytes(),b"foreign")

    def test_consumed_report_blocks_second_operation(self):
        self.assertEqual(m.run(),0);original=(self.root/m.REPORT).read_bytes()
        self.assertEqual(m.run(),1);self.assertEqual((self.root/m.REPORT).read_bytes(),original)

    def test_partial_copy_failure_retained_and_report_failed(self):
        actual=m.copy_one;count=0
        def fail_second(*args):
            nonlocal count
            count+=1
            if count==2:raise OSError()
            return actual(*args)
        with patch.object(m,"copy_one",side_effect=fail_second):self.assertEqual(m.run(),1)
        r=self.report();self.assertEqual(r["files_copied"],1);self.assertEqual(r["status"],"FAILED_PARTIAL_ARTIFACTS_RETAINED_NO_RETRY")
        self.assertTrue((self.root/self.destinations[0]).exists());self.assertFalse((self.root/self.destinations[1]).exists())

    def test_source_clock_mutation_is_sticky_operation_failure(self):
        actual=m.HeldSource.recheck;triggered=False
        def mutate(source):
            nonlocal triggered
            actual(source)
            if source.relative==self.sources[-1][0] and not triggered:
                triggered=True
                p,d=source.original;source.original=(p[:6]+(p[6]+1,)+p[7:],d)
        with patch.object(m.HeldSource,"recheck",mutate):self.assertEqual(m.run(),1)
        self.assertTrue(triggered)

    def test_close_failure_never_becomes_success(self):
        actual=m.HeldSource.close
        def fail_close(source):
            actual(source)
            if source.relative==m.HASH_SOURCE:raise OSError()
        with patch.object(m.HeldSource,"close",fail_close):self.assertEqual(m.run(),1)
        self.assertEqual(self.report()["status"],"FAILED_PARTIAL_ARTIFACTS_RETAINED_NO_RETRY")

    def test_report_reservation_failure_prevents_destination_creation(self):
        self.write(m.REPORT,b"foreign reservation");self.assertEqual(m.run(),1)
        self.assertEqual((self.root/m.REPORT).read_bytes(),b"foreign reservation");self.assertTrue(all(not (self.root/p).exists() for p in self.destinations))
