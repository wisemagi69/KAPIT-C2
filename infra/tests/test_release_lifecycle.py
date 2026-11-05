from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from infra.evidence_release_bridge import ModelAdmission
from infra.evidence_release_lifecycle import ModelFileLedger, drive_model
from infra.evidence_release_schemas import Refused, GATES, FINALIZERS, canonical

def admission(op="FRESH_PREFLIGHT"):
    return ModelAdmission(op,"a"*32,"1"*64,"2"*64,"3"*64,"4"*64,"2026-10-23T15:30:00Z")

class Backend:
    def __init__(self,fault=None): self.calls=[]; self.fault=fault; self.retained=False
    def step(self,name):
        self.calls.append(name)
        if name==self.fault: raise RuntimeError("private-canary")
    def hold(self,*a): self.step("hold")
    def observe(self,gate,*a): self.step(gate); return dict(gate=gate,confirmed=True)
    def reserve_guard(self,*a): self.step("reserve_guard")
    def repeat_live_gates(self,*a): self.step("repeat")
    def mark_create_attempted(self,*a): self.step("attempt")
    def create_original(self,*a): self.step("create"); return dict(cid="c"*64,returncode=0)
    def record_original(self,*a): self.step("record")
    def start_original(self,*a): self.step("start")
    def attach_original(self,*a):
        self.step("attach")
        return dict(returncode=0,stdout=canonical({"schema_version":1,"scope":"PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY","controls":[{"id":i,"category":"CLEAN"} for i in ("raw_upstream","png_strict","png_upstream")],"completed":3}),stderr_bytes=0,closed=True)
    def postflight(self,*a): self.step("postflight")
    def save_candidate(self,*a): self.step("save")
    def cleanup_original(self,*a): self.step("cleanup")
    def finalize(self,name,*a): self.step("finalize_"+name)
    def close_candidate(self,*a): self.step("close")
    def commit_original_guard(self,*a): self.step("commit")
    def confirm_guard_absent(self,*a): self.step("absence"); return True
    def finish_model(self,*a): self.step("finish")
    def retain_refusal_guard(self): self.retained=True; self.step("retain")

class LedgerTests(unittest.TestCase):
    def test_restart_equivalent_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            ModelFileLedger(directory).consume(admission())
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission("ONE_COMPARISON"))
            self.assertEqual(len(list(Path(directory).iterdir())),1)
    def test_partial_write_consumed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("infra.evidence_release_lifecycle.os.write",return_value=1):
                with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
    def test_fsync_failure_consumed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("infra.evidence_release_lifecycle.os.fsync",side_effect=OSError("canary")):
                with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
    def test_close_failure_consumed(self):
        import os
        original=os.close
        def closed_then_raised(fd): original(fd); raise OSError("canary")
        with tempfile.TemporaryDirectory() as directory:
            with patch("infra.evidence_release_lifecycle.os.close",side_effect=closed_then_raised):
                with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())

class LifecycleTests(unittest.TestCase):
    def run_model(self,backend,op="FRESH_PREFLIGHT",clock=lambda:0):
        with tempfile.TemporaryDirectory() as directory: return drive_model(admission(op),ModelFileLedger(directory),backend,clock=clock)
    def test_success_full_preflight(self):
        backend=Backend(); result=self.run_model(backend)
        self.assertEqual(result.gates,GATES); self.assertEqual(result.finalizers,FINALIZERS); self.assertFalse(result.production_eligible)
    def test_success_comparison_original_order(self):
        backend=Backend(); result=self.run_model(backend,"ONE_COMPARISON")
        self.assertTrue(result.create_attempted)
        for first,second in (("attempt","create"),("create","record"),("record","start"),("attach","cleanup"),("cleanup","postflight"),("postflight","save"),("close","commit")):
            self.assertLess(backend.calls.index(first),backend.calls.index(second))
    def test_all_gates_and_finalizers_faults_sticky(self):
        for fault in ("hold",*GATES,"reserve_guard","postflight","save",*["finalize_"+x for x in FINALIZERS],"close","commit","absence","finish"):
            with self.subTest(fault=fault):
                backend=Backend(fault)
                with self.assertRaises(Refused) as caught: self.run_model(backend)
                self.assertIsNone(caught.exception.__context__); self.assertTrue(backend.retained)
                self.assertTrue(all("finalize_"+x in backend.calls for x in FINALIZERS))
    def test_interruption_consumed(self):
        backend=Backend()
        def interrupted(*a): raise KeyboardInterrupt()
        backend.hold=interrupted
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Refused): drive_model(admission(),ModelFileLedger(directory),backend,clock=lambda:0)
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
    def test_create_failure_never_start_cleanup(self):
        backend=Backend("create")
        with self.assertRaises(Refused): self.run_model(backend,"ONE_COMPARISON")
        self.assertNotIn("start",backend.calls); self.assertIn("cleanup",backend.calls)
    def test_record_failure_never_start(self):
        backend=Backend("record")
        with self.assertRaises(Refused): self.run_model(backend,"ONE_COMPARISON")
        self.assertNotIn("start",backend.calls); self.assertIn("cleanup",backend.calls)
    def test_late_gate_no_acceptance(self):
        ticks=[0]
        def clock(): return ticks[0]
        backend=Backend(); original=backend.observe
        def late(*a): ticks[0]=301; return original(*a)
        backend.observe=late
        with self.assertRaises(Refused): self.run_model(backend,clock=clock)
        self.assertTrue(backend.retained)
        self.assertTrue(all("finalize_"+name in backend.calls for name in FINALIZERS))
    def test_guard_delete_pending_denial(self):
        backend=Backend(); backend.confirm_guard_absent=lambda *a:False
        with self.assertRaises(Refused): self.run_model(backend)
        self.assertTrue(backend.retained)
    def test_all_27_category_triples(self):
        import itertools
        for triple in itertools.product(("CLEAN","NOT_CLEAN","ERROR"),repeat=3):
            with self.subTest(triple=triple):
                backend=Backend(); original=backend.attach_original
                def attach(*args):
                    result=original(*args); result["stdout"]=canonical(dict(schema_version=1,scope="PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY",completed=3,controls=[dict(id=i,category=c) for i,c in zip(("raw_upstream","png_strict","png_upstream"),triple)])); return result
                backend.attach_original=attach
                if "ERROR" in triple:
                    with self.assertRaises(Refused): self.run_model(backend,"ONE_COMPARISON")
                else: self.run_model(backend,"ONE_COMPARISON")
    def test_extra_create_shape_keeps_original(self):
        backend=Backend(); backend.create_original=lambda *a:dict(cid="c"*64,returncode=1,extra=True)
        with self.assertRaises(Refused): self.run_model(backend,"ONE_COMPARISON")
        self.assertIn("record",backend.calls); self.assertIn("cleanup",backend.calls); self.assertNotIn("start",backend.calls)
    def test_original_cleanup_callback_held(self):
        backend=Backend(); original=backend.create_original
        def create(*args):
            backend.cleanup_original=lambda *a:(_ for _ in ()).throw(AssertionError("replacement"))
            return original(*args)
        backend.create_original=create; self.run_model(backend,"ONE_COMPARISON")
        self.assertIn("cleanup",backend.calls)
    def test_initial_clock_error_private_consumed(self):
        def clock(): raise RuntimeError("private-canary")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Refused) as caught: drive_model(admission(),ModelFileLedger(directory),Backend(),clock=clock)
            self.assertIsNone(caught.exception.__context__)
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
    def test_missing_backend_callback_private_consumed(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Refused) as caught: drive_model(admission(),ModelFileLedger(directory),object(),clock=lambda:0)
            self.assertIsNone(caught.exception.__context__)
            with self.assertRaises(Refused): ModelFileLedger(directory).consume(admission())
    def test_clock_breakage_still_attempts_five_finalizers(self):
        ticks=[0]; backend=Backend()
        def clock():
            ticks[0]+=1
            if ticks[0]>3: raise RuntimeError("private-clock")
            return 0
        with self.assertRaises(Refused): self.run_model(backend,clock=clock)
        self.assertTrue(all("finalize_"+name in backend.calls for name in FINALIZERS))

if __name__ == "__main__": unittest.main()
