"""Pure controller/finalizer faults; protected IO and CLI are replaced."""
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from dataclasses import asdict,FrozenInstanceError
import hashlib
import ctypes
import json
from datetime import datetime,timedelta,timezone
from io import StringIO
from pathlib import Path
import sys
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import subprocess
import threading

from infra import evidence_detection_controls_controller as c
from infra import evidence_detection_controls_native as adapter
from infra import evidence_detection_controls_provenance as provenance
from infra import evidence_rmdir_proof as old
from infra import evidence_rmdir_diagnostic as diagnostic
from infra import evidence_interpreter_runtime as current
from infra.tests.test_detection_controls import document,encode
from infra.tests.test_strict_failure_details import frame,encoded

TOKEN='f'*32;CID='e'*64
REAL_LIVE_ABSENCES=c._ExecutionContext._live_absences
_EXECUTION_GUARDS=None

def setUpModule():
 global _EXECUTION_GUARDS
 _EXECUTION_GUARDS=ExitStack()
 for module,name in ((ctypes,'WinDLL'),(ctypes,'CDLL'),(subprocess,'Popen'),(threading,'Thread'),(c.os,'scandir')):
  _EXECUTION_GUARDS.enter_context(patch.object(module,name,side_effect=AssertionError('Actual runtime operation forbidden'),create=True))

def tearDownModule():_EXECUTION_GUARDS.close()

class Call:
 def __init__(self,*a):self.docker='fixed-docker';self.config='fixed-config';self.uncertain=False;self.calls=[]
 def __call__(self,*a,**kw):
  self.calls.append(a)
  if a[:2]==('container','create') or a[:1]==('create',):return 0,(CID+'\n').encode(),b'','EXIT'
  selector=a[-1]
  return 1,b'[]\n',('Error response from daemon: No such container: '+selector+'\n').encode(),'EXIT'

def observed(count=14,completed=True,failed=('png_positive',)):
 details=adapter._payload(encode(document()),0)
 if not completed:raise c.DiagnosticUnavailable()
 return adapter.validate_outcome(c.PHASE_ID,{'phase_id':c.PHASE_ID,'observed':True,
  'details':details,'native_eligible':False,'private_input_allowed':False})


def rows():
 result=[]
 for i in range(28):
  token=format(i+1,'032x');cid=format(i+1,'064x')
  fixed={'schema':1,'token':token,'image_id':adapter.IMAGE,'signature_generation':adapter.GENERATION,
   'native_eligible':False,'purpose':'historical-only','expected_name':'kapit-rmdir-proof-public-'+token,
   'expected_labels':{'org.kapit.owner':'historical-owner','org.kapit.purpose':'historical-only','org.kapit.reservation':token}}
  result.append({'directory':diagnostic.STAGE+'/native-run-'+token,'token':token,'original_id':cid,
   'expected_name':fixed['expected_name'],'files':{'reservation.json':{'document':fixed},'create-attempt.json':{},'ownership.json':{},'result.json':{}}})
 return result

def result(stage,binding):
 return {'schema':1,'scope':c.SCOPE,'stage':stage,'status':'REFUSED','completed':False,'native_eligible':False,
  'private_input_allowed':False,'control_state_modified':False,'binding':asdict(binding),
  'finalizers':{name:'NOT_REACHED' for name in c.FINALIZERS},'completed_stages':[],
  'preserved_originals':[],'new_original':None,'observation':None,'recorded_utc':c._utc()}

class Fixture(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close);self.saved=[];self.events=[]
  self.binding=c.binding(hashlib.sha256(b'controller').hexdigest());self.api=Mock();self.call=Call()
  @contextmanager
  def parent_pin(*args,**kwargs):yield
  self.api.pin.side_effect=parent_pin
  self.prepared={'known':'preparation'};self.rows=rows();self.outcome=observed()
  self.patch(c,'_no_pending',Mock(return_value=None));self.markers=[]
  owner=self
  class Pending:
   def __init__(self,stage):self.stage=stage;self.exists=True;self.closed=False;owner.markers.append(self)
   def commit(self):self.exists=False;self.closed=True
   def close(self):self.closed=True
  self.pending_type=Pending;self.patch(c,'_Pending',Pending)
  self.provenance=SimpleNamespace(preserved_originals=Mock(return_value=self.rows),_reservations=Mock())
  self.prior=self.patch(c,'_prior_postflight',Mock(return_value=self.rows))
  self.combined=self.patch(c,'_postflight_reservations',Mock())
  self.pin=self.patch(c,'_pin_sources',Mock(return_value=self.provenance))
  self.patch(old,'corrected_provenance',Mock(return_value=self.prepared))
  self.image=self.patch(current,'verified_image',Mock(return_value={'image_id':adapter.IMAGE,'signature_generation':adapter.GENERATION}))
  self.oci=self.patch(diagnostic,'oci_bytes',Mock());self.patch(diagnostic,'Commands',Call)
  self.cgroup=self.patch(diagnostic.modules()[1],'_require_cgroup_v2',Mock())
  import infra.evidence_interpreter_compile as compiler
  self.legacy=self.patch(compiler,'live_originals',Mock(return_value=SimpleNamespace(consume=Mock())))
  self.live=self.patch(c._ExecutionContext,'_live_absences',Mock());self.patch(diagnostic,'engine',Mock())
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=c.FLOOR+1))
  def journal(root,pins,api,token,fixed,cid,*a):
   return {'directory':diagnostic.STAGE+'/native-run-'+token,'token':token,'original_id':cid,
    'expected_name':fixed['expected_name'],'files':{'reservation.json':{'document':fixed},'create-attempt.json':{},'ownership.json':{},'result.json':{}}}
  self.journal=self.patch(diagnostic,'journal_documents',Mock(side_effect=journal))
  self.patch(c,'_capture_failed_original',Mock(side_effect=lambda root,pins,api,token,cid,binding:{
   'token':token,'original_id':cid,'expected_name':adapter.NAME_PREFIX+token,'files':{},'unconfirmed_documents':[]}))
  self.patch('builtins','print',Mock())
  owner=self
  class Receipt:
   def __init__(self,path,initial):self.path=path;self.stream=SimpleNamespace(closed=False);self.save(initial)
   def save(self,value):owner.saved.append(deepcopy(value))
   def close(self):self.stream.closed=True
  self.receipt_type=Receipt;self.receipt=Receipt(Path('synthetic'),{})
 def patch(self,obj,name,value):
  if type(obj) is str:return self.stack.enter_context(patch(obj+'.'+name,value))
  return self.stack.enter_context(patch.object(obj,name,value))
 def context(self,stage='diagnostic'):
  self.result=result(stage,self.binding)
  return c._ExecutionContext(c._CONTEXT_SEAL,self.api,ExitStack(),self.call,self.receipt,self.result,
   stage,self.prepared,self.binding,Mock(),self.rows if stage=='diagnostic' else None)
 def start(self,ctx):
  ctx.before_phase(c.PHASE_ID,TOKEN);ctx.consume_before_create(c.PHASE_ID)
  ctx.retain_original(c.PHASE_ID,TOKEN,CID);ctx.record_original(c.PHASE_ID,TOKEN,CID)
 def complete(self,ctx,outcome=None):
  self.start(ctx);ctx.attach_started();ctx.attach_finalized(True)
  accepted=ctx.finish_phase(c.PHASE_ID,TOKEN,CID,'ORIGINAL_ID_ABSENT_VERIFIED',self.outcome if outcome is None else outcome)
  return accepted
 def test_two_gib_floor_refuses_before_phase_work(self):
  self.assertEqual(c.FLOOR,2*1024**3)
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=c.FLOOR-1))
  ctx=self.context()
  with self.assertRaises(c.DiagnosticUnavailable):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.image.assert_not_called();self.assertNotIn('active_original_id',self.result)
 def test_exact_two_gib_boundary_allows_fresh_gates_with_native_build_limits_unchanged(self):
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=c.FLOOR))
  ctx=self.context();ctx.before_phase(c.PHASE_ID,TOKEN);self.image.assert_called_once()
  from infra import evidence_interpreter_build as build
  from infra import evidence_native_runtime as runtime
  self.assertEqual(build.MIN_BUILD_FREE_BYTES,6*1024**3)
  self.assertEqual(runtime.LIMITS['scan'],(4*1024**3,120,180))
 def test_exact_seal_type_binding_and_readonly_identity(self):
  ctx=self.context();self.assertIs(c._validate_context(ctx),ctx)
  with self.assertRaises(FrozenInstanceError):ctx.binding.native_sha256='f'*64
  with self.assertRaises(AttributeError):ctx.binding=object()
  ctx._seal=object()
  with self.assertRaises(c.DiagnosticUnavailable):c._validate_context(ctx)
  class Derived(c._ExecutionContext):pass
  derived=Derived(c._CONTEXT_SEAL,self.api,ExitStack(),self.call,self.receipt,self.result,'diagnostic',self.prepared,self.binding,Mock(),self.rows)
  with self.assertRaises(c.DiagnosticUnavailable):c._validate_context(derived)
 def test_one_phase_repeats_all_fresh_gates_and_keeps_parent_guard(self):
  ctx=self.context();self.assertTrue(self.complete(ctx))
  for gate in (self.pin,self.image,self.oci,self.provenance.preserved_originals,self.provenance._reservations,self.cgroup,self.legacy):gate.assert_called_once()
  self.assertEqual(self.live.call_count,2);self.assertEqual(self.result['active_phase'],c.PHASE_ID)
  self.assertEqual(self.result['observation'],self.outcome);self.assertEqual(self.result['finalizers']['phase_pins'],'CONFIRMED')
  with self.assertRaises(c.DiagnosticUnavailable):ctx.before_phase(c.PHASE_ID,'d'*32)
 def test_fresh_reconstructed_originals_must_equal_preflight_copies(self):
  ctx=self.context();self.provenance.preserved_originals.return_value=deepcopy(self.rows)
  self.provenance.preserved_originals.return_value[0]['files']['ownership.json']={'changed':True}
  with self.assertRaises(c.DiagnosticUnavailable):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.assertIsNone(ctx._observation);self.assertEqual(self.result['finalizers']['phase_pins'],'CONFIRMED')
 def test_preflight_creates_no_phase_journal_or_attach(self):
  ctx=self.context('preflight');ctx.preflight();self.journal.assert_not_called()
  self.assertIsNone(ctx._observation);self.assertEqual(self.result['preserved_originals'],self.rows)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_started()
 def test_every_fresh_gate_failure_closes_phase_pins_on_body_error(self):
  for gate in (self.pin,self.image,self.oci,self.provenance.preserved_originals,self.provenance._reservations,self.cgroup,self.legacy,self.live):
   ctx=self.context();prior=gate.side_effect;gate.side_effect=RuntimeError('CANARY')
   with self.subTest(gate=repr(gate)),self.assertRaises(RuntimeError):ctx.before_phase(c.PHASE_ID,TOKEN)
   self.assertIsNone(ctx._observation);self.assertEqual(self.result['finalizers']['phase_pins'],'CONFIRMED');gate.side_effect=prior
 def test_single_use_and_five_second_capability(self):
  ctx=self.context();ctx.before_phase(c.PHASE_ID,TOKEN);ctx.consume_before_create(c.PHASE_ID)
  with self.assertRaises(diagnostic.DiagnosticUnavailable):ctx.consume_before_create(c.PHASE_ID)
  ctx=self.context();ctx.before_phase(c.PHASE_ID,TOKEN);ctx._observation.created-=6
  with self.assertRaises(diagnostic.DiagnosticUnavailable):ctx.consume_before_create(c.PHASE_ID)
 def test_active_save_failure_prevents_all_fresh_work(self):
  ctx=self.context();self.receipt.save=Mock(side_effect=RuntimeError('CANARY'))
  with self.assertRaises(RuntimeError):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.pin.assert_not_called()
 def test_duplicate_original_and_changed_returned_id_refuse(self):
  ctx=self.context();ctx.before_phase(c.PHASE_ID,TOKEN)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.retain_original(c.PHASE_ID,TOKEN,self.rows[0]['original_id'])
  ctx.retain_original(c.PHASE_ID,TOKEN,CID)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.retain_original(c.PHASE_ID,TOKEN,'d'*64)
 def test_phase_pin_failure_keeps_observation_only_as_refused_candidate(self):
  ctx=self.context();self.start(ctx);ctx.attach_started();ctx.attach_finalized(True)
  ctx._phase_pins.close=Mock(side_effect=RuntimeError('CANARY'))
  with self.assertRaises(c.DiagnosticUnavailable):ctx.finish_phase(c.PHASE_ID,TOKEN,CID,'ORIGINAL_ID_ABSENT_VERIFIED',self.outcome)
  self.assertEqual(self.result['observation'],self.outcome);self.assertEqual(self.result['finalizers']['phase_pins'],'UNCONFIRMED')
  with self.assertRaises(c.DiagnosticUnavailable):ctx.close()
  self.assertEqual(self.result['finalizers']['context'],'UNCONFIRMED')
 def test_incomplete_outcome_refuses_instead_of_partial_observation(self):
  for value in ({},{'observed':False}):
   ctx=self.context();self.start(ctx);ctx.attach_started();ctx.attach_finalized(True)
   with self.assertRaises(Exception):ctx.finish_phase(c.PHASE_ID,TOKEN,CID,'ORIGINAL_ID_ABSENT_VERIFIED',value)

 def test_cleanup_after_deadline_space_or_execution_uncertainty_is_original_only(self):
  ctx=self.context();self.start(ctx);ctx._deadline=0;ctx._call.uncertain=True
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=0))
  with self.assertRaises(c.DiagnosticUnavailable):ctx.command('container','inspect',CID)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.cleanup_command('container','inspect',CID)
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=c.FLOOR+1))
  ctx=self.context();self.start(ctx);ctx._call.uncertain=True
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=0))
  ctx.cleanup_command('container','inspect',CID);ctx.cleanup_command('container','rm',CID)
  for args in (('container','rm','a'*64),('container','start',CID),('container','create')):
   with self.assertRaises(c.DiagnosticUnavailable):ctx.cleanup_command(*args)
  for _ in range(6):ctx.cleanup_command('container','inspect',CID)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.cleanup_command('container','inspect',CID)
  self.assertTrue(ctx.call_uncertain)
 def test_attach_notifications_require_durable_owned_id_consumed_cap_and_order(self):
  ctx=self.context()
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_finalized(True)
  ctx.before_phase(c.PHASE_ID,TOKEN)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_started()
  ctx.retain_original(c.PHASE_ID,TOKEN,CID)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_started()
  ctx.record_original(c.PHASE_ID,TOKEN,CID)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_started()
  ctx.consume_before_create(c.PHASE_ID);ctx.attach_started()
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_started()
 def test_pending_attach_interrupt_and_false_notification_are_sticky_uncertain(self):
  ctx=self.context();self.start(ctx);ctx.attach_started()
  self.assertTrue(ctx.call_uncertain);c._cli_finalizer(self.result,ctx,self.call)
  self.assertEqual(self.result['finalizers']['cli'],'UNCONFIRMED')
  ctx.attach_finalized(False)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_finalized(True)
  self.assertTrue(ctx.call_uncertain);c._cli_finalizer(self.result,ctx,self.call)
  self.assertEqual(self.result['finalizers']['cli'],'UNCONFIRMED')
 def test_attach_success_notification_bypasses_work_deadline_and_space(self):
  ctx=self.context();self.start(ctx);ctx.attach_started();ctx._deadline=0
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=0))
  ctx.attach_finalized(True);self.assertFalse(ctx.call_uncertain)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.command('info')
 def test_attach_exact_bool_and_single_notification(self):
  for bad in (1,0,None,'true'):
   ctx=self.context();self.start(ctx);ctx.attach_started()
   with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_finalized(bad)
   self.assertTrue(ctx.call_uncertain)
  ctx=self.context();self.start(ctx);ctx.attach_started();ctx.attach_finalized(True)
  with self.assertRaises(c.DiagnosticUnavailable):ctx.attach_finalized(True)
 def test_finalizer_uncertainty_never_resets_to_confirmed(self):
  ctx=self.context();c.finalizer(self.result,'context','UNCONFIRMED');ctx.close()
  self.assertEqual(self.result['finalizers']['context'],'UNCONFIRMED')
 def test_uncertain_legacy_cli_is_registered_even_when_observation_raises(self):
  ctx=self.context()
  def failed(call):call.uncertain=True;raise RuntimeError('CANARY')
  self.legacy.side_effect=failed
  with self.assertRaises(RuntimeError):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.assertTrue(ctx.call_uncertain);c._cli_finalizer(self.result,ctx,self.call)
  self.assertEqual(self.result['finalizers']['cli'],'UNCONFIRMED')
 def test_uncertain_early_absence_batch_is_registered_before_engine_query(self):
  ctx=self.context()
  def failed(call):call.uncertain=True;raise RuntimeError('CANARY')
  with patch.object(c._ExecutionContext,'_live_absences',REAL_LIVE_ABSENCES),patch.object(diagnostic,'engine',side_effect=failed):
   with self.assertRaises(RuntimeError):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.assertTrue(ctx.call_uncertain);self.assertEqual(len(ctx._calls),3)
  c._cli_finalizer(self.result,ctx,self.call);self.assertEqual(self.result['finalizers']['cli'],'UNCONFIRMED')
 def test_compound_live_image_helper_exception_conservatively_marks_cli_unknown(self):
  ctx=self.context();self.image.side_effect=RuntimeError('CANARY_CLEANUP_UNCERTAINTY')
  with self.assertRaises(RuntimeError):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.assertTrue(ctx.call_uncertain);c._cli_finalizer(self.result,ctx,self.call)
  self.assertEqual(self.result['finalizers']['cli'],'UNCONFIRMED')
 def test_successful_image_helper_return_does_not_leave_pending_cli(self):
  ctx=self.context();ctx.before_phase(c.PHASE_ID,TOKEN)
  self.assertFalse(ctx._helper_cli_incomplete);self.assertFalse(ctx.call_uncertain)
 def test_inherited_input_cli_uncertainty_blocks_capability_immediately(self):
  ctx=self.context();self.call.uncertain=True
  with self.assertRaises(c.DiagnosticUnavailable):ctx.before_phase(c.PHASE_ID,TOKEN)
  self.pin.assert_not_called();self.assertIsNone(ctx._observation)


class TrackedResources(unittest.TestCase):
 def run_manager(self,*,body=False,exit_error=False,enter_error=False,suppress=False):
  r={'finalizers':{name:'NOT_REACHED' for name in c.FINALIZERS}};events=[]
  class Manager:
   def __enter__(self):
    events.append('enter')
    if enter_error:raise RuntimeError('ENTER')
    return 'owned'
   def __exit__(self,typ,value,tb):
    events.append('exit_error' if typ else 'exit_normal')
    if exit_error:raise RuntimeError('EXIT')
    return suppress
  try:
   with c.tracked(Manager(),r,'dedicated_lock'):
    events.append('body')
    if body:raise ValueError('BODY')
  except BaseException as error:return r,events,type(error)
  return r,events,None
 def test_normal_exit_confirmed(self):
  r,e,error=self.run_manager();self.assertEqual(r['finalizers']['dedicated_lock'],'CONFIRMED');self.assertIsNone(error)
 def test_body_exception_records_actual_successful_unwind(self):
  r,e,error=self.run_manager(body=True)
  self.assertEqual(e,['enter','body','exit_error']);self.assertEqual(r['finalizers']['dedicated_lock'],'CONFIRMED');self.assertIs(error,ValueError)
 def test_body_and_exit_failure_leave_sticky_unconfirmed(self):
  r,e,error=self.run_manager(body=True,exit_error=True)
  self.assertEqual(r['finalizers']['dedicated_lock'],'UNCONFIRMED');self.assertIs(error,RuntimeError)
 def test_acquisition_failure_is_not_confirmed(self):
  r,e,error=self.run_manager(enter_error=True)
  self.assertEqual(r['finalizers']['dedicated_lock'],'UNCONFIRMED');self.assertEqual(e,['enter'])
 def test_suppressing_resource_cannot_hide_body_failure(self):
  r,e,error=self.run_manager(body=True,suppress=True)
  self.assertEqual(r['finalizers']['dedicated_lock'],'CONFIRMED');self.assertIs(error,c.DiagnosticUnavailable)


class ExecuteFaults(unittest.TestCase):
 setUp=Fixture.setUp
 patch=Fixture.patch
 def configure(self,kind='normal'):
  self.patch(c,'_reviewed_calibration',Mock(return_value='a'*64));self.patch(c,'_new_receipt',self.receipt_type);self.patch(c.os,'name','nt')
  self.patch(current,'pin_bytes',lambda *a,**kw:b'controller');self.patch(c,'receipt_set',Mock())
  self.patch(c,'preflight_provenance',lambda *a:{'preserved_originals':self.rows})
  owner=self
  @contextmanager
  def resources():
   if kind=='input_enter':raise RuntimeError('CANARY')
   try:yield owner.api,ExitStack(),owner.call,{}
   finally:
    if kind=='input_close':raise RuntimeError('CANARY')
  @contextmanager
  def lock(*a):
   try:yield Mock()
   finally:
    if kind=='lock_close':raise RuntimeError('CANARY')
  self.patch(c,'input_resources',resources);self.patch(old,'existing_proof_lock',lock)
  def execute(ctx):
   if kind=='body_early':raise RuntimeError('CANARY')
   ctx.before_phase(c.PHASE_ID,TOKEN);ctx.consume_before_create(c.PHASE_ID)
   ctx.retain_original(c.PHASE_ID,TOKEN,CID);ctx.record_original(c.PHASE_ID,TOKEN,CID)
   ctx.attach_started()
   if kind=='attach_pending':raise KeyboardInterrupt()
   ctx.attach_finalized(kind!='attach_false')
   if kind=='attach_false':raise RuntimeError('CANARY')
   value=observed(0,False,()) if kind=='partial' else owner.outcome
   if kind=='phase_close':ctx._phase_pins.close=Mock(side_effect=RuntimeError('CANARY'))
   ctx.finish_phase(c.PHASE_ID,TOKEN,CID,'ORIGINAL_ID_ABSENT_VERIFIED',value)
   if kind=='body_late':raise KeyboardInterrupt()
   if kind=='cli':ctx._call.uncertain=True
   return value
  self.patch(adapter,'execute',execute)
  if kind=='receipt_close':
   def close(receipt):raise RuntimeError('CANARY')
   self.patch(self.receipt_type,'close',close)
 def test_preflight_verified_only_all_finalizers_confirmed(self):
  self.configure();value=c.execute('preflight')
  self.assertEqual(value['status'],'VERIFIED');self.assertEqual(value['finalizers'],{name:'CONFIRMED' for name in c.FINALIZERS})
  self.assertIsNone(value['new_original']);self.assertIsNone(value['observation'])
 def test_measurement_success_is_measured_not_strict_verified(self):
  self.configure();value=c.execute('diagnostic')
  self.assertEqual(value['status'],'MEASURED');self.assertTrue(value['completed']);self.assertNotIn('active_case',value)
  self.assertEqual(value['observation'],self.outcome);self.assertEqual(value['finalizers'],{name:'CONFIRMED' for name in c.FINALIZERS})
 def test_semantic_early_failure_reports_observed_exits_not_skipped_flags(self):
  self.configure('body_early')
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  value=self.saved[-1];self.assertEqual(value['status'],'REFUSED')
  for name in ('context','dedicated_lock','input_resources','cli'):self.assertEqual(value['finalizers'][name],'CONFIRMED')
  self.assertEqual(value['finalizers']['phase_pins'],'NOT_REACHED')
 def test_all_closures_confirmed_can_coexist_with_body_refusal(self):
  self.configure('body_late')
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  value=self.saved[-1];self.assertEqual(value['finalizers'],{name:'CONFIRMED' for name in c.FINALIZERS})
  self.assertEqual(value['status'],'REFUSED');self.assertIn('active_case',value);self.assertEqual(value['observation'],self.outcome)
 def test_each_finalizer_failure_refuses_and_keeps_candidate_guard(self):
  for kind,key in (('phase_close','phase_pins'),('lock_close','dedicated_lock'),('input_close','input_resources'),('cli','cli')):
   with self.subTest(kind=kind):
    self.configure(kind)
    with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
    value=self.saved[-1];self.assertEqual(value['finalizers'][key],'UNCONFIRMED');self.assertFalse(value['completed'])
    self.assertEqual(value['status'],'REFUSED');self.assertIn('active_phase',value)
 def test_pending_and_failed_attach_aggregate_cli_unconfirmed(self):
  for kind in ('attach_pending','attach_false'):
   self.configure(kind)
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
   self.assertEqual(self.saved[-1]['finalizers']['cli'],'UNCONFIRMED');self.assertIn('active_phase',self.saved[-1])
 def test_receipt_close_failure_dominates_after_candidate_success(self):
  self.configure('receipt_close')
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  self.assertEqual(self.saved[-1]['status'],'REFUSED');self.assertIn('active_case',self.saved[-1])
 def test_input_enter_failure_leaves_unreached_resources_explicit(self):
  self.configure('input_enter')
  previous=len(self.saved)
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('preflight')
  self.assertEqual(len(self.saved),previous);self.assertEqual(self.markers,[])
 def test_exclusive_receipt_failure_precedes_protected_work(self):
  self.configure();self.patch(c,'_new_receipt',Mock(side_effect=FileExistsError()))
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('preflight')
  self.image.assert_not_called();self.assertEqual(self.markers,[])


class FixedReceiptsAndPostflight(unittest.TestCase):
 def setUp(self):self.enterContext(patch.object(c,'_no_pending',Mock(return_value=None)))
 def receipt(self,refused=False):
  binding=c.binding('a'*64);fixed=adapter.metadata(TOKEN,c.PHASE_ID,binding);owned=diagnostic.modules()[3]
  docs={'reservation.json':fixed,'create-attempt.json':{'schema':1,'token':TOKEN,'create_attempted':True,'native_eligible':False},
   'ownership.json':dict(fixed,original_id=CID),'result.json':{'schema':1,'token':TOKEN,'original_id':CID,
    'ownership_status':'ORIGINAL_ID_ABSENT_VERIFIED','native_eligible':False}}
  files={name:{'document':doc,'bytes':len(owned._canonical(doc)),'sha256':hashlib.sha256(owned._canonical(doc)).hexdigest()} for name,doc in docs.items()}
  journal={'directory':diagnostic.STAGE+'/native-run-'+TOKEN,'token':TOKEN,'original_id':CID,'expected_name':fixed['expected_name'],
   'files':files,'original_cid_and_name_absent_live':True}
  value=result('diagnostic',binding);value.update(status='MEASURED',completed=True,total_seconds=1.0,preserved_originals=rows(),
   finalizers={name:'CONFIRMED' for name in c.FINALIZERS},completed_stages=c.expected_stages('diagnostic'),new_original=journal,observation=observed())
  if refused:
   value.update(status='REFUSED',completed=False,active_case='detection-controls',active_phase=c.PHASE_ID,active_token=TOKEN,active_original_id=CID,
    failure_code='FINALIZER_UNCONFIRMED',failed_stage='FINAL_GATES')
   value['finalizers']['input_resources']='UNCONFIRMED'
  return value,binding
 def test_unfilled_hash_refuses_before_receipt_or_new_code_import(self):
  with patch.object(c,'NATIVE_SHA256',None),patch.object(c,'_new_receipt') as receipt,patch.object(c,'native') as native:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  receipt.assert_not_called();native.assert_not_called()
 def test_closed_stage_surface_and_unknown_receipt_discovery(self):
  for stage in ('strict','pcre','fixtures','diagnostic-v2','../preflight',None,True):
   with self.assertRaises(c.DiagnosticUnavailable):c.receipt_path(stage)
  for name in ('private-scanner-detection-controls-diagnostic-v2.json','private-scanner-detection-controls-diagnostic.json'):
   with patch.object(Path,'glob',return_value=[Path(name)]):
    with self.assertRaises(c.DiagnosticUnavailable):c.receipt_set(Path('.'),'preflight')
 def test_preflight_closed_schema_finalizers_binding_and_active_guards(self):
  binding=c.binding('a'*64);value=result('preflight',binding)
  value.update(status='VERIFIED',completed=True,completed_stages=c.expected_stages('preflight'),preserved_originals=rows(),total_seconds=1.0,
   finalizers={name:'CONFIRMED' for name in c.FINALIZERS})
  def validate(document):
   with patch.object(current,'pin_bytes',return_value=json.dumps(document).encode()):return c.preflight_provenance(Path('.'),ExitStack(),Mock(),binding)
  self.assertEqual(validate(value),value)
  for change in (lambda d:d.update(active_case='x'),lambda d:d.update(schema=True),lambda d:d.update(status='REFUSED'),
   lambda d:d['finalizers'].update(cli='NOT_REACHED'),lambda d:d['binding'].update(native_sha256='f'*64),lambda d:d['preserved_originals'].pop()):
   changed=deepcopy(value);change(changed)
   with self.assertRaises(c.DiagnosticUnavailable):validate(changed)
 def check_reservations(self,value,known):
  root=Path.cwd().resolve()
  directories=[root/diagnostic.STAGE/('native-run-'+row['token']) for row in known]
  documents={row['token']:adapter._json(row['files']['reservation.json']['document']) for row in known}
  token=value.get('token',TOKEN)
  if token not in documents:directories.append(root/diagnostic.STAGE/('native-run-'+token))
  documents[token]=adapter._json(value)
  @contextmanager
  def no_pin(*a,**kw):yield
  def read(root,pins,api,path,**kwargs):return documents[Path(path).parent.name[11:]]
  with patch.object(Path,'glob',return_value=directories),patch.object(current,'pin_bytes',side_effect=read),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:c._postflight_reservations(root,pins,Mock(),known,c.binding('a'*64))

 def test_postflight_allows_only_exact_known_current_original_not_orphans(self):
  binding=c.binding('a'*64);fixed=adapter.metadata(TOKEN,c.PHASE_ID,binding)
  own={'token':TOKEN,'original_id':CID,'expected_name':fixed['expected_name'],
   'files':{'reservation.json':{'document':fixed},'create-attempt.json':{},'ownership.json':{},'result.json':{}}}
  known=rows()+[own];self.check_reservations(fixed,known)
  for change in (lambda d:d.update(image_id='sha256:'+'f'*64),lambda d:d.update(token='d'*32),
   lambda d:d.update(controller_sha256='d'*64),lambda d:d.update(purpose='public-detection-controls-v2')):
   changed=deepcopy(fixed);change(changed)
   if changed['token']!=TOKEN:changed['expected_labels'].update({'org.kapit.reservation':changed['token']})
   with self.assertRaises(c.DiagnosticUnavailable):self.check_reservations(changed,known)
 def test_all28_exact_absences_use_fresh_bounded_batches(self):
  known=rows()+[{'token':TOKEN,'original_id':CID,'expected_name':adapter.NAME_PREFIX+TOKEN}]
  calls=[]
  def factory(*a):value=Call();calls.append(value);return value
  with patch.object(diagnostic,'Commands',factory),patch.object(diagnostic,'engine') as engine:c.live_absences(Call(),known)
  self.assertEqual([len(call.calls) for call in calls],[16,16,16,10]);self.assertEqual(engine.call_count,8)
  with self.assertRaises(c.DiagnosticUnavailable):c.live_absences(Call(),known+[known[-1]])
 def test_postflight_receipt_validates_success_and_refusal_without_granting_clearance(self):
  for refused in (False,True):
   value,binding=self.receipt(refused);self.assertEqual(c._validate_diagnostic_receipt(value,binding),value)
  value,binding=self.receipt(True);value.update(total_seconds=400.0,failure_code='DEADLINE')
  self.assertEqual(c._validate_diagnostic_receipt(value,binding)['status'],'REFUSED')
 def test_closed_postflight_receipt_schema_binding_states_and_records_refuse(self):
  changes=(lambda d:d.update(extra='CANARY'),lambda d:d.update(schema=True),lambda d:d.update(stage='future'),
   lambda d:d.update(status='VERIFIED'),lambda d:d.update(completed=False),lambda d:d['binding'].update(native_sha256='f'*64),
   lambda d:d['finalizers'].update(cli='UNKNOWN'),lambda d:d['observation'].update(observed=False),
   lambda d:d['new_original'].update(extra='CANARY'),lambda d:d['new_original']['files']['ownership.json'].update(sha256='f'*64),
   lambda d:d['preserved_originals'].pop(),lambda d:d.update(total_seconds=True))
  for change in changes:
   value,binding=self.receipt();change(value)
   with self.subTest(change=repr(change)),self.assertRaises((c.DiagnosticUnavailable,adapter.NativeUnavailable)):c._validate_diagnostic_receipt(value,binding)
  value,binding=self.receipt(True);value['active_original_id']='f'*64
  with self.assertRaises(c.DiagnosticUnavailable):c._validate_diagnostic_receipt(value,binding)
 def test_known_postflight_original_replays28_112_and_fresh_saved_prefix_equality(self):
  value,binding=self.receipt(True);saved=value['new_original'];plain=deepcopy(saved);plain.pop('original_cid_and_name_absent_live')
  p=SimpleNamespace(preserved_originals=Mock(return_value=rows()))
  with (patch.object(c,'_pin_sources',return_value=p),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),
   patch.object(diagnostic,'journal_documents',return_value=plain),patch.object(c,'_postflight_reservations') as guard,
   patch.object(c,'_prior_postflight',return_value=rows())):
   actual=c._postflight_originals(Path('.'),ExitStack(),Mock(),binding,{})
  self.assertEqual(len(actual),29);self.assertEqual(sum(len(r['files']) for r in actual),116);guard.assert_called_once()

 def test_postflight_category_contradictions_do_not_gain_known_original_allowance(self):
  for change in (lambda d:d['controls'][0].update(category='ERROR'),
   lambda d:d.update(comparison='PRIVATE_CANARY'),lambda d:d['controls'].clear(),
   lambda d:d.update(scope='PUBLIC_STRICT_FAILURE_IDENTITY_ONLY')):
   value,binding=self.receipt();change(value['observation']['details'])
   with self.assertRaises(Exception):c._validate_diagnostic_receipt(value,binding)
 def test_postflight_rejects_unknown_cross_image_identity_predecessor(self):
  binding=c.binding('a'*64);fixed=adapter.metadata(TOKEN,c.PHASE_ID,binding)
  own={'token':TOKEN,'original_id':CID,'expected_name':fixed['expected_name'],'files':{'reservation.json':{'document':fixed}}}
  known=rows()+[own];unknown=deepcopy(rows()[0]['files']['reservation.json']['document'])
  unknown.update(image_id='sha256:'+'d'*64,purpose='public-strict-identity-only')
  unknown['expected_labels'].update({'org.kapit.owner':'kapit-public-strict-identity-v1'})
  with self.assertRaises(c.DiagnosticUnavailable):self.check_reservations(unknown,known)

class RuntimeLineage(unittest.TestCase):
 def test_old_v1_owner_or_purpose_cannot_gain_postflight_allowance(self):
  fixture=FixedReceiptsAndPostflight();binding=c.binding('a'*64);fixed=adapter.metadata(TOKEN,c.PHASE_ID,binding)
  own={'token':TOKEN,'original_id':CID,'expected_name':fixed['expected_name'],'files':{'reservation.json':{'document':fixed}}}
  known=rows()+[own]
  for owner,purpose in (('kapit-public-strict-category-v1','other'),('other','public-strict-category-only'),('other','public-strict-category-future'),('other','public-strict-category-v1-only'),('other','public-strict-category-extra')):
   value=deepcopy(fixed);value.update(image_id='sha256:'+'d'*64,purpose=purpose);value['expected_labels'].update({'org.kapit.owner':owner,'org.kapit.purpose':purpose})
   with self.assertRaises(c.DiagnosticUnavailable):fixture.check_reservations(value,known)

class RealNativeBoundary(unittest.TestCase):
 setUp=Fixture.setUp
 patch=Fixture.patch
 context=Fixture.context
 def run_phase(self,kind='normal'):
  ctx=self.context();holder={};original_probe=adapter._probe
  def probe(*args):holder['probe']=original_probe(*args);return holder['probe']
  journal=SimpleNamespace(mark_create_attempted=Mock(return_value=None),record_original=Mock(return_value=None),finish=Mock(return_value=None),failed=False)
  @contextmanager
  def reserve(*args):yield journal
  from infra.test_evidence_native_runtime import inspection
  inspections=[]
  def inspect(call,cid):
   probe=holder['probe'];code=0
   document=inspection(probe.phase,exit_code=code)
   document.update(Name='/'+probe.name);document['Config'].update(Labels=probe.labels,Cmd=probe.command)
   from infra import evidence_rmdir_profile as profile
   document['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode()
   inspections.append(code);return document
  attach=Mock(return_value=(0,encode(document())))
  if kind=='interrupt':attach.side_effect=KeyboardInterrupt()
  from infra import evidence_native_attestation as attestation
  with (patch.object(adapter,'_probe',side_effect=probe),patch.object(adapter,'_reserve',reserve),
   patch.object(diagnostic,'inspect',side_effect=inspect),patch.object(diagnostic,'cleanup',return_value='ORIGINAL_ID_ABSENT_VERIFIED'),
   patch.object(adapter,'_attach',attach)):
   if kind=='late':
    ticks=iter((0.0,241.0))
    with patch.object(adapter,'time',SimpleNamespace(monotonic=lambda:next(ticks))):
     with self.assertRaises(adapter.NativeUnavailable):adapter._phase(ctx)
   elif kind=='interrupt':
    with self.assertRaises(adapter.NativeUnavailable):adapter._phase(ctx)
   else:self.assertTrue(adapter._phase(ctx)['observed'])
  return ctx,inspections,journal
 def test_actual_shared_context_expected_exit0_passes_unchanged_inspection(self):
  ctx,codes,journal=self.run_phase();self.assertEqual(codes,[0,0]);self.assertFalse(ctx.call_uncertain)
  self.assertEqual(self.result['observation'],self.outcome);journal.finish.assert_called_once_with('ORIGINAL_ID_ABSENT_VERIFIED')
 def test_actual_shared_context_late_native_error_cannot_retain_accepting_outcome(self):
  ctx,codes,journal=self.run_phase('late')
  self.assertEqual(codes,[0,0]);self.assertIsNone(self.result['observation']);self.assertIn('active_phase',self.result)
  self.assertEqual(self.result['finalizers']['phase_pins'],'CONFIRMED')
 def test_actual_shared_context_attach_interrupt_is_cli_uncertain_and_active(self):
  ctx,codes,journal=self.run_phase('interrupt')
  self.assertTrue(ctx.call_uncertain);self.assertIn('active_phase',self.result)
  self.assertIsNone(self.result['observation']);journal.finish.assert_called_once_with('CLEANUP_UNCONFIRMED')


class InitialReceiptFaults(unittest.TestCase):
 def run_writer(self,kind):
  path=Mock();stream=Mock();path.open.return_value=stream;events=[]
  class Writer:
   def save(self,value):
    events.append('save')
    if kind!='success':raise RuntimeError('CANARY')
   def close(self):
    events.append('close');self.stream.close()
    if kind=='close':raise RuntimeError('CANARY')
  with patch.object(current,'Receipt',Writer):
   if kind=='success':value=c._new_receipt(path,{})
   else:
    with self.assertRaises(c.DiagnosticUnavailable) as error:c._new_receipt(path,{})
    value=error.exception.code
  path.open.assert_called_once_with('xb');return value,events,stream
 def test_initial_save_success_retains_original_owned_handle(self):
  value,events,stream=self.run_writer('success')
  self.assertIs(value.stream,stream);self.assertEqual(events,['save']);stream.close.assert_not_called()
 def test_initial_save_fault_attempts_close_before_any_runtime_resources(self):
  value,events,stream=self.run_writer('write')
  self.assertEqual(value,'RECEIPT_INITIAL_WRITE_REFUSED');self.assertEqual(events,['save','close']);stream.close.assert_called_once()
 def test_initial_save_and_close_fault_is_explicit_uncertainty(self):
  value,events,stream=self.run_writer('close')
  self.assertEqual(value,'RECEIPT_INITIAL_CLOSE_UNCONFIRMED');self.assertEqual(events,['save','close'])


class FailedOriginalCapture(unittest.TestCase):
 def capture(self,mutate=None):
  binding=c.binding('a'*64);fixed=adapter.metadata(TOKEN,c.PHASE_ID,binding);owned=diagnostic.modules()[3]
  docs={'reservation.json':fixed,'create-attempt.json':{'schema':1,'token':TOKEN,'create_attempted':True,'native_eligible':False},
   'ownership.json':dict(fixed,original_id=CID),'result.json':{'schema':1,'token':TOKEN,'original_id':CID,
    'ownership_status':'CLEANUP_UNCONFIRMED','native_eligible':False}}
  if mutate:mutate(docs)
  def read(root,pins,api,path,**kw):
   name=Path(path).name
   if name not in docs:raise FileNotFoundError()
   return owned._canonical(docs[name])
  @contextmanager
  def no_pin(*args,**kwargs):yield
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as directory:
   directory.return_value.pin=no_pin
   with ExitStack() as pins:return c._capture_failed_original(Path('.'),pins,Mock(),TOKEN,CID,binding)
 def test_all_available_canonical_uncertain_journals_remain_finite_facts(self):
  value=self.capture();self.assertEqual(len(value['files']),4);self.assertEqual(value['unconfirmed_documents'],[])
  self.assertEqual(value['files']['result.json']['document']['ownership_status'],'CLEANUP_UNCONFIRMED')
 def test_missing_documents_are_listed_and_never_fabricated(self):
  for name in ('reservation.json','create-attempt.json','ownership.json','result.json'):
   value=self.capture(lambda docs:docs.pop(name));self.assertEqual(value['unconfirmed_documents'],[name]);self.assertNotIn(name,value['files'])
 def test_wrong_original_unknown_status_and_extra_metadata_are_unconfirmed(self):
  for change in (lambda d:d['ownership.json'].update(original_id='d'*64),lambda d:d['result.json'].update(ownership_status='UNKNOWN'),
   lambda d:d['reservation.json'].update(extra='CANARY')):
   self.assertTrue(self.capture(change)['unconfirmed_documents'])


class NewControllerGuards(unittest.TestCase):
 def calibration(self):
  now=datetime.now(timezone.utc)
  return {'schema':1,'scope':'PUBLIC_DETECTION_CONTROLS_CALIBRATION_ONLY','status':'CALIBRATED',
   'completed':True,'binding':asdict(c.binding('a'*64)),'limits':dict(c.CALIBRATION_LIMITS),
   'created_utc':(now-timedelta(seconds=2)).strftime('%Y-%m-%dT%H:%M:%SZ'),
   'expires_utc':(now+timedelta(seconds=120)).strftime('%Y-%m-%dT%H:%M:%SZ'),
   'finalizers':{name:'CONFIRMED' for name in c.FINALIZERS},'native_eligible':False,
   'private_input_allowed':False,'control_state_modified':False}
 def test_missing_calibration_refuses_before_any_receipt_or_runtime_input(self):
  self.assertIsNone(c.CALIBRATION_SHA256)
  for stage in c.STAGES:
   with patch.object(c,'_new_receipt') as receipt,patch.object(c,'input_resources') as resources,patch.object(c,'_base') as base:
    with self.assertRaises(c.DiagnosticUnavailable) as error:c.execute(stage)
    self.assertEqual(error.exception.code,'CALIBRATION_NOT_REVIEWED')
    receipt.assert_not_called();resources.assert_not_called();base.assert_not_called()
 def test_closed_calibration_exact_limits_flags_binding_finalizers(self):
  expected=c.binding('a'*64);value=self.calibration();self.assertEqual(c._validate_calibration(value,expected),value)
  mutations=[lambda d:d.update(extra='PRIVATE_CANARY'),lambda d:d.update(schema=True),
   lambda d:d.update(completed=1),lambda d:d.update(native_eligible=0),lambda d:d.update(private_input_allowed=0),
   lambda d:d.update(control_state_modified=0),lambda d:d['binding'].update(controller_sha256='b'*64),
   lambda d:d['finalizers'].update(cli='UNCONFIRMED')]
  for key in dict(c.CALIBRATION_LIMITS):
   mutations.extend((lambda d,k=key:d['limits'].update({k:True}),lambda d,k=key:d['limits'].update({k:d['limits'][k]+1})))
  for change in mutations:
   altered=deepcopy(value);change(altered)
   with self.assertRaises(c.DiagnosticUnavailable):c._validate_calibration(altered,expected)
 def test_calibration_utc_future_expired_malformed_and_overlong_refuse(self):
  for change in (lambda d:d.update(created_utc=d['expires_utc']),lambda d:d.update(expires_utc=d['created_utc']),
   lambda d:d.update(created_utc='PRIVATE_CANARY'),lambda d:d.update(expires_utc='2099-01-01T00:00:00Z'),
   lambda d:d.update(created_utc='2099-01-01T00:00:00Z'),lambda d:d.update(created_utc='2026-02-30T00:00:00Z')):
   value=self.calibration();change(value)
   with self.assertRaises(Exception):c._validate_calibration(value,c.binding('a'*64))
 def test_calibration_read_uses_only_fixed_reviewed_path_hash(self):
  value=self.calibration();raw=json.dumps(value).encode();digest=hashlib.sha256(raw).hexdigest()
  with patch.object(c,'_reviewed_calibration',return_value=digest),patch.object(current,'pin_bytes',return_value=raw) as reader:
   c.calibration_provenance(Path('.'),ExitStack(),Mock(),c.binding('a'*64))
  self.assertEqual(reader.call_args.args[3],c.CALIBRATION_PATH)
  self.assertEqual(reader.call_args.kwargs['expected'],digest)
 def test_fixed59_manifest_precedes_new_provenance_and_calibration(self):
  events=[]
  def reader(root,pins,api,path,**kwargs):events.append(path);return b''
  with (patch.object(current,'pin_bytes',side_effect=reader),patch.object(provenance,'pin_sources',side_effect=lambda *a:events.append('TRANSITIVE')),
   patch.object(c,'calibration_provenance',side_effect=lambda *a:events.append('CALIBRATION'))):
   c._pin_sources(Path('.'),ExitStack(),Mock(),c.binding('a'*64))
  self.assertEqual(len(c.PINNED_PRIOR),59)
  self.assertEqual(events[:59],[path for path,digest in c.PINNED_PRIOR])
  self.assertGreater(events.index('TRANSITIVE'),58);self.assertEqual(events[-1],'CALIBRATION')
 def test_each_changed_manifest_pin_blocks_inherited_validation(self):
  for denied,digest in c.PINNED_PRIOR:
   def reader(root,pins,api,path,**kwargs):
    if path==denied:raise c.DiagnosticUnavailable()
    return b''
   with patch.object(current,'pin_bytes',side_effect=reader),patch.object(provenance,'pin_sources') as inherited:
    with self.assertRaises(c.DiagnosticUnavailable):c._pin_sources(Path('.'),ExitStack(),Mock(),c.binding('a'*64))
   inherited.assert_not_called()
 def test_discovery_accepts_only_exact_calibration_and_stage_names(self):
  for stage in c.STAGES:
   names=[Path(c.CALIBRATION_PATH),Path(c.receipt_path('preflight'))]
   if stage=='diagnostic':names.append(Path(c.receipt_path('diagnostic')))
   with patch.object(Path,'glob',return_value=names):c.receipt_set(Path('.'),stage)
   for bad in ('private-scanner-detection-controls-calibration-extra.json','private-scanner-detection-controls-other.json'):
    with patch.object(Path,'glob',return_value=names+[Path(bad)]),self.assertRaises(c.DiagnosticUnavailable):c.receipt_set(Path('.'),stage)
 def test_deadline_call_caps_and_refuses_late_normal_return(self):
  raw=Call();raw=Mock(wraps=raw);raw.uncertain=False
  with patch.object(c.time,'monotonic',return_value=100):
   call=c._DeadlineCall(raw,103);call('info',timeout=15)
  self.assertEqual(raw.call_args.kwargs['timeout'],3)
  with patch.object(c.time,'monotonic',side_effect=[100,104]):
   call=c._DeadlineCall(raw,103)
   with self.assertRaises(c.DiagnosticUnavailable):call('info')
   self.assertTrue(call.uncertain)
 def test_main_invalid_arguments_and_output_failures_are_finite(self):
  for argv in (['fixed'],['fixed','PRIVATE_CANARY'],['fixed','preflight','PRIVATE_CANARY']):
   output=StringIO()
   with patch.object(sys,'argv',argv),patch.object(sys,'stdout',output),patch.object(c,'execute') as execute:
    self.assertEqual(c.main(),2)
   self.assertNotIn('PRIVATE',output.getvalue());execute.assert_not_called()
  for stage in c.STAGES:
   output=Mock();output.write.side_effect=RuntimeError('PRIVATE_WRITER_CANARY')
   with patch.object(sys,'argv',['fixed',stage]),patch.object(sys,'stdout',output),patch.object(c,'execute',return_value={'stage':stage,'status':'VERIFIED'}):
    self.assertEqual(c.main(),2)
 def test_preflight_recorded_time_must_be_fresh_and_not_future(self):
  binding=c.binding('a'*64);value=result('preflight',binding)
  value.update(status='VERIFIED',completed=True,completed_stages=c.expected_stages('preflight'),
   preserved_originals=rows(),total_seconds=1.0,finalizers={name:'CONFIRMED' for name in c.FINALIZERS})
  for delta in (-301,301):
   value['recorded_utc']=(datetime.now(timezone.utc)+timedelta(seconds=delta)).strftime('%Y-%m-%dT%H:%M:%SZ')
   with patch.object(c,'_no_pending',Mock()),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),self.assertRaises(c.DiagnosticUnavailable):
    c.preflight_provenance(Path('.'),ExitStack(),Mock(),binding)


class NewContextGuards(unittest.TestCase):
 setUp=Fixture.setUp
 patch=Fixture.patch
 context=Fixture.context
 start=Fixture.start
 def test_pending_attach_timeout_uses_remaining_deadline_then_finalizes(self):
  ctx=self.context();self.start(ctx);ctx.attach_started()
  now=c.time.monotonic();ctx._deadline=now+7
  with patch.object(c.time,'monotonic',return_value=now):self.assertEqual(ctx.attach_timeout(),7)
  self.assertTrue(ctx.call_uncertain)
  ctx.attach_finalized(True);self.assertFalse(ctx.call_uncertain)
 def test_new_unknown_after_attach_cannot_save_observation(self):
  ctx=self.context();self.start(ctx);ctx.attach_started();ctx.attach_finalized(True)
  self.combined.side_effect=c.DiagnosticUnavailable()
  with self.assertRaises(c.DiagnosticUnavailable):ctx.finish_phase(c.PHASE_ID,TOKEN,CID,'ORIGINAL_ID_ABSENT_VERIFIED',self.outcome)
  self.assertIsNone(self.result['observation']);self.assertIn('active_phase',self.result)
  self.assertEqual(len(self.combined.call_args.args[3]),29)
 def test_old28_changed_after_attach_refuses_before29_guard(self):
  ctx=self.context();self.start(ctx);ctx.attach_started();ctx.attach_finalized(True)
  changed=deepcopy(self.rows);changed[0]['original_id']='a'*64;self.prior.return_value=changed
  with self.assertRaises(c.DiagnosticUnavailable):ctx.finish_phase(c.PHASE_ID,TOKEN,CID,'ORIGINAL_ID_ABSENT_VERIFIED',self.outcome)
  self.combined.assert_not_called();self.assertIsNone(self.result['observation'])


class GuardFunction:
 def __init__(self,fn):self.fn=fn
 def __call__(self,*args):return self.fn(*args)


class GuardWindows:
 def __init__(self,fault=None):
  self.user='S-1-5-21-123';self.fault=fault;self.exists=fault=='collision';self.deleted=False
  self.volume=(1<<44)+17;self.identifier=(1<<100)+33;self.payload=b'';self.parents=0;self.closes=[];self.dispositions=[]
  self.k=SimpleNamespace(CreateFileW=GuardFunction(self.create),LocalFree=GuardFunction(lambda *a:None),
   WriteFile=GuardFunction(self.write),FlushFileBuffers=GuardFunction(lambda *a:self.fault!='flush'),
   GetFileInformationByHandle=GuardFunction(self.basic),GetFileInformationByHandleEx=GuardFunction(self.identity),
   GetFileType=GuardFunction(lambda *a:1),SetFileInformationByHandle=GuardFunction(self.disposition),
   CloseHandle=GuardFunction(self.close))
  self.a=SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=GuardFunction(self.descriptor))
 @contextmanager
 def pin(self,path,**kwargs):
  self.parents+=1
  try:yield
  finally:self.parents-=1
 def descriptor(self,text,revision,pointer,unused):self.sddl=text;pointer._obj.value=77;return True
 def create(self,*args):
  self.create_args=args
  if self.exists:return None
  self.exists=True;return 1234
 def verify_acl(self,*args,**kwargs):
  if self.fault=='acl':raise c.DiagnosticUnavailable()
 def write(self,handle,buffer,length,pointer,unused):
  self.payload=ctypes.string_at(buffer,length);pointer._obj.value=length-(1 if self.fault=='write' else 0);return True
 def basic(self,handle,pointer):
  value=pointer._obj;value.attributes=0x400 if self.fault=='reparse' else 0x80
  value.links=2 if self.fault=='links' else 1;value.size_high=0;value.size_low=len(self.payload);return True
 def identity(self,handle,kind,pointer,size):
  if kind!=18 or size!=24:raise AssertionError('Full identity query required')
  value=pointer._obj;value.volume=self.volume
  for index,byte in enumerate(self.identifier.to_bytes(16,'little')):value.identifier[index]=byte
  return True
 def lstat(self,path):
  return SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_file_attributes=0,
   st_dev=self.volume,st_ino=self.identifier,st_size=len(self.payload))
 def disposition(self,handle,kind,pointer,size):
  self.dispositions.append((handle,kind,pointer._obj.delete,size))
  if self.fault=='disposition':return False
  self.deleted=True;return True
 def close(self,handle):
  self.closes.append(handle)
  if self.deleted:self.exists=False
  return self.fault!='close'


class OwnedPendingTests(unittest.TestCase):
 def create(self,api):
  stack=self.enterContext(ExitStack())
  stack.enter_context(patch.object(c,'_pending_windows',return_value=api))
  stack.enter_context(patch.object(c.secrets,'token_hex',return_value='9'*32))
  stack.enter_context(patch.object(Path,'lstat',side_effect=lambda path=None:api.lstat(path)))
  return c._Pending('diagnostic')
 def test_new_only_protected_handle_fullidentity_and_original_disposition(self):
  api=GuardWindows();guard=self.create(api)
  self.assertEqual(api.create_args[0],str(c.ROOT/c.pending_path('diagnostic')))
  self.assertEqual(api.create_args[1:3],(0xc0030000,1))
  self.assertEqual(api.create_args[4:6],(1,0x00200080))
  self.assertEqual(api.parents,3);self.assertEqual(guard.identity[:2],(api.volume,api.identifier))
  self.assertIn('D:P(A;;FA;;;S-1-5-18)(A;;FA;;;S-1-5-21-123)',api.sddl)
  self.assertEqual(json.loads(api.payload)['receipt'],c.receipt_path('diagnostic'))
  guard.commit();self.assertFalse(api.exists);self.assertEqual(api.parents,0)
  self.assertEqual(api.dispositions,[(1234,4,1,1)]);self.assertEqual(api.closes,[1234])
 def test_abort_closes_original_without_disposition_and_retains_guard(self):
  api=GuardWindows();guard=self.create(api);guard.close()
  self.assertTrue(api.exists);self.assertEqual(api.dispositions,[]);self.assertEqual(api.closes,[1234])
 def test_existing_marker_collision_never_deletes_or_closes_foreign_handle(self):
  api=GuardWindows('collision')
  with self.assertRaises(c.DiagnosticUnavailable):self.create(api)
  self.assertTrue(api.exists);self.assertEqual(api.dispositions,[]);self.assertEqual(api.closes,[]);self.assertEqual(api.parents,0)
 def test_write_flush_acl_link_and_reparse_faults_leave_guard(self):
  for fault in ('write','flush','acl','links','reparse'):
   with self.subTest(fault=fault):
    api=GuardWindows(fault)
    with self.assertRaises(c.DiagnosticUnavailable):self.create(api)
    self.assertTrue(api.exists);self.assertEqual(api.dispositions,[]);self.assertEqual(api.closes,[1234])
 def test_changed_identity_or_disposition_fault_cannot_remove_guard(self):
  api=GuardWindows();guard=self.create(api);api.identifier+=1
  with self.assertRaises(c.DiagnosticUnavailable):guard.commit()
  guard.close();self.assertTrue(api.exists);self.assertEqual(api.dispositions,[])
  api=GuardWindows('disposition');guard=self.create(api)
  with self.assertRaises(c.DiagnosticUnavailable):guard.commit()
  guard.close();self.assertTrue(api.exists)
 def test_close_uncertainty_never_retries_handle_or_claims_normal_return(self):
  api=GuardWindows('close');guard=self.create(api)
  with self.assertRaises(c.DiagnosticUnavailable):guard.commit()
  self.assertFalse(api.exists)
  self.assertFalse(guard.closed)
  with self.assertRaises(c.DiagnosticUnavailable):guard.close()
  self.assertEqual(api.closes,[1234])
 def test_absence_guard_refuses_permission_errors_and_unknown_variants(self):
  parent=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0)
  @contextmanager
  def discovery(*args):yield iter(())
  with patch.object(c.os,'scandir',discovery),patch.object(Path,'lstat',side_effect=[parent,FileNotFoundError(),FileNotFoundError()]):
   c._no_pending(c.ROOT)
  for error in (PermissionError('PRIVATE_CANARY'),OSError('PRIVATE_CANARY')):
   with patch.object(c.os,'scandir',discovery),patch.object(Path,'lstat',side_effect=[parent,error]),self.assertRaises(Exception):
    c._no_pending(c.ROOT)
  @contextmanager
  def unknown(*args):yield iter((SimpleNamespace(name='private-scanner-detection-controls-unknown.pending'),))
  with patch.object(Path,'lstat',return_value=parent),patch.object(c.os,'scandir',unknown),self.assertRaises(c.DiagnosticUnavailable):
   c._no_pending(c.ROOT)
  with patch.object(Path,'lstat',return_value=parent),patch.object(c.os,'scandir',side_effect=PermissionError()),self.assertRaises(PermissionError):
   c._no_pending(c.ROOT)
 def test_casefold_namespace_detection_rejects_unknown_and_known_aliases(self):
  parent=SimpleNamespace(st_mode=stat.S_IFDIR,st_file_attributes=0)
  names=('PRIVATE-SCANNER-DETECTION-CONTROLS-X.PENDING',
   'Private-Scanner-Detection-Controls-future.Pending',
   Path(c.receipt_path('preflight')).name.upper(),
   'private-scanner-detection-controls-Preflight.json',
   Path(c.CALIBRATION_PATH).name.upper())
  for name in names:
   @contextmanager
   def discovery(*args):yield iter((SimpleNamespace(name=name),))
   with self.subTest(name=name),patch.object(Path,'lstat',return_value=parent), \
    patch.object(c.os,'scandir',discovery),self.assertRaises(c.DiagnosticUnavailable):
    c._no_pending(c.ROOT)


class PendingReceiptCommitFaults(unittest.TestCase):
 setUp=Fixture.setUp
 patch=Fixture.patch
 configure=ExecuteFaults.configure
 def test_closed_then_raised_receipt_keeps_persisted_candidate_guarded(self):
  self.configure()
  def closed_then_raised(receipt):receipt.stream.closed=True;raise RuntimeError('PRIVATE_CLOSE_CANARY')
  self.patch(self.receipt_type,'close',closed_then_raised)
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  self.assertEqual(self.saved[-1]['status'],'MEASURED')
  self.assertTrue(self.markers[-1].exists)
  with patch.object(c,'_no_pending',side_effect=c.DiagnosticUnavailable()),self.assertRaises(c.DiagnosticUnavailable):
   c._validate_diagnostic_receipt(self.saved[-1],self.binding)
 def test_normal_commit_removes_only_new_owned_guard(self):
  self.configure();value=c.execute('diagnostic')
  self.assertEqual(value['status'],'MEASURED');self.assertFalse(self.markers[-1].exists)
 def test_disposition_failure_preserves_guard_and_refuses(self):
  self.configure()
  self.patch(self.pending_type,'commit',Mock(side_effect=c.DiagnosticUnavailable()))
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  self.assertTrue(self.markers[-1].exists)
 def test_successful_handle_close_with_retained_marker_is_not_success(self):
  self.configure()
  def commit(marker):marker.closed=True
  self.patch(self.pending_type,'commit',commit)
  def absence(root):
   if any(marker.exists for marker in self.markers):raise c.DiagnosticUnavailable()
  self.patch(c,'_no_pending',absence)
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  self.assertTrue(self.markers[-1].exists)
 def test_postcommit_permission_error_refuses_with_parents_still_held(self):
  self.configure();parents=[0]
  @contextmanager
  def pin(*args,**kwargs):
   parents[0]+=1
   try:yield
   finally:parents[0]-=1
  self.api.pin.side_effect=pin
  def absence(root):
   if self.markers:
    self.assertEqual(parents[0],3)
    raise PermissionError('PRIVATE_DELETE_PENDING')
  self.patch(c,'_no_pending',absence)
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('diagnostic')
  self.assertEqual(parents[0],0)


if __name__=='__main__':unittest.main()
