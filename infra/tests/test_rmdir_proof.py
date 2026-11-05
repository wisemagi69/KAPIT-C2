"""Pure fixed-manifest/context/currentness tests with replaced protected IO."""
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from dataclasses import asdict,FrozenInstanceError
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from infra import evidence_rmdir_proof as c
from infra import evidence_rmdir_diagnostic as diagnostic
from infra import evidence_interpreter_runtime as current

class FakeCall:
 def __init__(self,*a):self.docker='fixed-docker';self.config='fixed-config';self.uncertain=False;self.calls=[]
 def __call__(self,*a,**kw):
  self.calls.append(a);selector=a[-1]
  return 1,b'[]\n',('Error response from daemon: No such container: '+selector+'\n').encode(),'EXIT'

class FakeNative:
 OWNER='kapit-public-rmdir-proof-v1'
 @staticmethod
 def metadata(token,phase_id,binding):
  if phase_id not in c.PHASES:raise c.ProofUnavailable()
  return {'schema':1,'token':token,'phase_id':phase_id,'image_id':binding.image_id,
   'signature_generation':binding.signature_generation,'native_eligible':False,
   'purpose':'public-rmdir-proof-only','expected_name':'kapit-rmdir-proof-public-'+token,
   'expected_labels':{'org.kapit.owner':FakeNative.OWNER,'org.kapit.reservation':token,
    'org.kapit.purpose':'public-rmdir-proof-only','org.kapit.profile':binding.profile_sha256,
    'org.kapit.preparation':binding.preparation_sha256,'org.kapit.native':binding.native_sha256}}
 @staticmethod
 def validate_outcome(phase,value):
  c.require(type(value) is dict and set(value)=={'phase_id','passed'} and value['phase_id']==phase and type(value['passed']) is bool)
  return deepcopy(value)
 @staticmethod
 def validate_result(stage,value):
  c.require(value=={'stage':stage,'passed':True});return value

def outcome(phase):return {'phase_id':phase,'passed':True}

def row(index,binding):
 phase=c.PHASES[index];token=format(index+1,'032x');cid=format(index+1,'064x')
 fixed=FakeNative.metadata(token,phase,binding)
 return {'phase_id':phase,'outcome':outcome(phase),'journal':{
  'directory':diagnostic.STAGE+'/native-run-'+token,'token':token,'original_id':cid,
  'expected_name':fixed['expected_name'],'original_cid_and_name_absent_live':True,
  'files':{name:{} for name in ('reservation.json','create-attempt.json','ownership.json','result.json')}}}

class FixedSurface(unittest.TestCase):
 def test_unfilled_native_pin_refuses_before_receipt_or_import(self):
  with patch.object(c,'NATIVE_SHA256',None),patch.object(current,'Receipt') as receipt,patch.object(c,'_native') as imported:
   with self.assertRaises(c.ProofUnavailable):c.execute('preflight')
  receipt.assert_not_called();imported.assert_not_called()
 def test_fixed_26_manifest_and_order(self):
  self.assertEqual(len(c.PHASES),26);self.assertEqual(len(set(c.PHASES)),26)
  self.assertEqual([len(c.stage_phases(s)) for s in c.STAGES],[0,10,1,1,14])
  self.assertEqual(c.PHASES[:2],('confinement:scan:confinement','confinement:scan:preopened_fd'))
  self.assertEqual(c.PHASES[10:12],('strict:scan:strict','pcre:scan:pcre'))
  self.assertEqual(c.PHASES[-2:],('fixture:png_malformed:original','fixture:png_eicar:original'))
 def test_fixed_receipts_and_no_arbitrary_stages(self):
  for stage in c.STAGES:self.assertEqual(c.receipt_path(stage),c.PREFIX+stage+'.json')
  for stage in ('prepare','../strict','strict-v2',None,True):
   with self.assertRaises(c.ProofUnavailable):c.receipt_path(stage)
 def test_stage_limits_do_not_modify_native_limits(self):
  from infra import evidence_native_runtime as runtime
  self.assertEqual(c.LIMITS,{'preflight':300,'confinement':900,'strict':300,'pcre':300,'fixtures':900})
  self.assertEqual(runtime.LIMITS['scan'][2],180)
 def test_receipt_discovery_refuses_future_unknown_or_extra(self):
  for name,stage in (('private-scanner-rmdir-proof-strict-v2.json','strict'),('private-scanner-rmdir-proof-fixtures.json','strict')):
   with patch.object(Path,'glob',return_value=[Path(name)]):
    with self.assertRaises(c.ProofUnavailable):c.receipt_set(Path('.'),stage)
 def test_import_has_no_candidate_adapter_import_or_calls(self):
  import ast
  tree=ast.parse(Path(c.__file__).read_text())
  self.assertFalse(any(isinstance(n,ast.ImportFrom) and any(a.name=='evidence_rmdir_native' for a in n.names) for n in tree.body))
  self.assertFalse(any(isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) for n in tree.body))
 def test_host_protocol_policy_fixture_and_json_sources_are_exact_retained_pins(self):
  expected={'infra/evidence_native_fixtures.py','infra/evidence_native_refresh.py',
   'backend/apps/operations/evidence_scan_protocol.py','backend/apps/operations/evidence_protocol.py',
   'backend/apps/operations/evidence_policy.py'}
  self.assertTrue(expected<=set(c.SOURCE_PINS))
  for path in expected:self.assertEqual(c.digest(Path(path).read_bytes()),c.SOURCE_PINS[path])
 def test_changed_host_fixture_source_refuses_before_native_import(self):
  with patch.object(c,'NATIVE_SHA256','a'*64):binding=c.binding('b'*64)
  def read(root,pins,api,path,**kw):
   if path=='infra/evidence_native_fixtures.py':raise c.ProofUnavailable('SOURCE_CHANGED')
   return b'controller'
  with patch.object(c,'NATIVE_SHA256','a'*64),patch.object(current,'pin_bytes',side_effect=read),patch.object(c,'digest',return_value='b'*64),patch.object(c,'_native') as imported:
   with self.assertRaises(c.ProofUnavailable):c.pin_sources(Path('.'),ExitStack(),Mock(),binding)
  imported.assert_not_called()

class ContextFixture(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.mock(c,'NATIVE_SHA256','a'*64);self.mock(c,'_native',lambda:FakeNative)
  self.binding=c.binding('b'*64);self.receipt=Mock();self.call=FakeCall();self.api=Mock()
  self.prepared={'fixed':'public'};self.events=[]
  self.mock(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=diagnostic.FLOOR+1))
  self.source=self.mock(c,'pin_sources',Mock(side_effect=lambda *a:self.events.append('source')))
  self.preparation=self.mock(c,'corrected_provenance',Mock(return_value=self.prepared))
  self.image=self.mock(current,'verified_image',Mock(return_value={'image_id':diagnostic.IMAGE,'signature_generation':diagnostic.GENERATION}))
  self.oci=self.mock(diagnostic,'oci_bytes',Mock())
  self.historical=[{'original_id':format(i+100,'064x'),'token':format(i+100,'032x'),
   'expected_name':'kapit-scratch-public-'+format(i+100,'032x')} for i in range(15)]
  self.originals=self.mock(c,'historical_originals',Mock(return_value=self.historical))
  self.replay=self.mock(c,'replay_proof_originals',Mock(side_effect=lambda root,pins,api,rows,binding:[v['journal'] for v in rows]))
  self.unknown=self.mock(c,'unknown_reservations',Mock())
  self.mock(diagnostic,'Commands',FakeCall)
  self.cgroup=self.mock(diagnostic.modules()[1],'_require_cgroup_v2',Mock())
  import infra.evidence_interpreter_compile as compiler
  self.live_old=self.mock(compiler,'live_originals',Mock(return_value=SimpleNamespace(consume=Mock())))
  self.live=self.mock(c,'live_absences',Mock())
  self.mock(c,'capture_failed_original',Mock(side_effect=lambda root,pins,api,phase,token,cid,binding:{
   'token':token,'original_id':cid,'expected_name':'kapit-rmdir-proof-public-'+token,'files':{},'unconfirmed_documents':[]}))
  self.mock(diagnostic,'engine',Mock())
  self.mock(diagnostic,'journal_documents',lambda root,pins,api,token,fixed,cid,*a:{
   'directory':diagnostic.STAGE+'/native-run-'+token,'token':token,'original_id':cid,
   'expected_name':fixed['expected_name'],'files':{name:{} for name in
    ('reservation.json','create-attempt.json','ownership.json','result.json')}})
  self.mock('builtins','print',Mock())
 def mock(self,obj,name,value):
  if type(obj) is str:return self.stack.enter_context(patch(obj+'.'+name,value))
  return self.stack.enter_context(patch.object(obj,name,value))
 def context(self,stage):
  start=0 if stage in ('preflight','confinement') else c.END[c.STAGES[c.STAGES.index(stage)-1]]
  rows=[row(i,self.binding) for i in range(start)]
  self.result={'binding':asdict(self.binding),'phase_originals':rows,'completed_manifest':list(c.PHASES[:start])}
  return c._ExecutionContext(c._SEAL,self.api,ExitStack(),self.call,self.receipt,self.result,stage,self.prepared,self.binding,Mock())
 def complete(self,ctx,index):
  phase=c.PHASES[index];token=format(index+1,'032x');cid=format(index+1,'064x')
  ctx.before_phase(phase,token);ctx.consume_before_create(phase);ctx.record_original(phase,token,cid)
  ctx.finish_phase(phase,token,cid,'ORIGINAL_ID_ABSENT_VERIFIED',outcome(phase))
 def test_sealed_exact_type_and_frozen_binding(self):
  ctx=self.context('confinement');self.assertIs(c._validate_context(ctx,'confinement'),ctx)
  with self.assertRaises(FrozenInstanceError):ctx.binding.profile_sha256='f'*64
  with self.assertRaises(AttributeError):ctx.binding='anything'
  with self.assertRaises(c.ProofUnavailable):c._validate_context(SimpleNamespace(_seal=c._SEAL),'confinement')
  with self.assertRaises(c.ProofUnavailable):c._validate_context(ctx,'strict')
  class Derived(c._ExecutionContext):pass
  derived=Derived(c._SEAL,self.api,ExitStack(),self.call,self.receipt,self.result,'confinement',self.prepared,self.binding,Mock())
  with self.assertRaises(c.ProofUnavailable):c._validate_context(derived,'confinement')
 def test_all_26_phases_each_repeat_full_fresh_gates(self):
  for stage in c.STAGES[1:]:
   ctx=self.context(stage)
   for index in range(len(ctx._result['completed_manifest']),c.END[stage]):self.complete(ctx,index)
   self.assertEqual(ctx._result['completed_manifest'],list(c.PHASES[:c.END[stage]]))
  for gate in (self.source,self.preparation,self.image,self.oci,self.originals,self.unknown,self.cgroup,self.live_old):
   self.assertEqual(gate.call_count,26)
  self.assertEqual(self.live.call_count,52)
 def test_preflight_creates_no_phase_or_native_journal(self):
  ctx=self.context('preflight')
  with patch.object(diagnostic,'journal_documents') as journal:ctx.preflight()
  journal.assert_not_called();self.assertEqual(ctx._result['completed_manifest'],[])
  self.assertIsNone(ctx._observation);self.source.assert_called_once()
 def test_currentness_failure_refuses_before_create_capability(self):
  ctx=self.context('confinement');self.image.side_effect=RuntimeError('SYNTHETIC')
  with self.assertRaises(RuntimeError):ctx.before_phase(c.PHASES[0],'1'*32)
  self.assertIsNone(ctx._observation);self.assertEqual(self.result['active_phase'],c.PHASES[0])
  self.assertEqual(self.result['phase_originals'],[])
 def test_every_failed_gate_stops_before_capability(self):
  for gate in (self.source,self.preparation,self.image,self.oci,self.originals,self.unknown,self.cgroup,self.live_old,self.live):
   ctx=self.context('confinement');gate.side_effect=c.ProofUnavailable()
   with self.subTest(gate=repr(gate)),self.assertRaises(c.ProofUnavailable):ctx.before_phase(c.PHASES[0],'1'*32)
   self.assertIsNone(ctx._observation);gate.side_effect=None
   if gate is self.preparation:gate.return_value=self.prepared
   if gate is self.image:gate.return_value={'image_id':diagnostic.IMAGE,'signature_generation':diagnostic.GENERATION}
   if gate is self.originals:gate.return_value=self.historical
   if gate is self.live_old:gate.return_value=SimpleNamespace(consume=Mock())
 def test_wrong_order_duplicate_or_out_of_group_refuses(self):
  for phase in (c.PHASES[1],c.PHASES[10],'fixture:unknown:original'):
   ctx=self.context('confinement')
   with self.assertRaises(c.ProofUnavailable):ctx.before_phase(phase,'1'*32)
  ctx=self.context('confinement');self.complete(ctx,0)
  with self.assertRaises(c.ProofUnavailable):ctx.before_phase(c.PHASES[0],'1'*32)
 def test_durable_active_precedes_fresh_and_original_precedes_next_work(self):
  ctx=self.context('confinement')
  self.receipt.save.side_effect=lambda value:self.events.append('saved')
  ctx.before_phase(c.PHASES[0],'1'*32)
  self.assertLess(self.events.index('saved'),self.events.index('source'))
  ctx.consume_before_create(c.PHASES[0]);ctx.record_original(c.PHASES[0],'1'*32,'2'*64)
  self.assertEqual(self.result['active_original_id'],'2'*64)
 def test_stale_or_reused_capability_refuses(self):
  ctx=self.context('confinement');ctx.before_phase(c.PHASES[0],'1'*32)
  ctx.consume_before_create(c.PHASES[0])
  with self.assertRaises(diagnostic.DiagnosticUnavailable):ctx.consume_before_create(c.PHASES[0])
  ctx=self.context('confinement');ctx.before_phase(c.PHASES[0],'1'*32)
  ctx._observation.created-=6
  with self.assertRaises(diagnostic.DiagnosticUnavailable):ctx.consume_before_create(c.PHASES[0])
 def test_semantic_failure_keeps_actual_journals_and_active_guard(self):
  ctx=self.context('confinement');phase=c.PHASES[0];ctx.before_phase(phase,'1'*32);ctx.record_original(phase,'1'*32,'2'*64)
  self.assertFalse(ctx.finish_phase(phase,'1'*32,'2'*64,'ORIGINAL_ID_ABSENT_VERIFIED',None))
  self.assertEqual(len(self.result['phase_originals']),1);self.assertIsNone(self.result['phase_originals'][0]['outcome'])
  self.assertEqual(self.result['completed_manifest'],[]);self.assertEqual(self.result['active_phase'],phase)
 def test_cleanup_uncertainty_never_advances(self):
  ctx=self.context('strict');phase=c.PHASES[10];ctx.before_phase(phase,'f'*32);ctx.record_original(phase,'f'*32,'e'*64)
  with self.assertRaises(c.ProofUnavailable):ctx.finish_phase(phase,'f'*32,'e'*64,'UNCONFIRMED',outcome(phase))
  self.assertEqual(self.result['completed_manifest'],list(c.PHASES[:10]));self.assertEqual(len(self.result['phase_originals']),10)
 def test_later_fixture_failure_preserves_completed_prefix(self):
  for fail_offset in (0,1,2):
   ctx=self.context('fixtures')
   for index in range(12,12+fail_offset):self.complete(ctx,index)
   index=12+fail_offset;phase=c.PHASES[index];token=format(index+1,'032x');cid=format(index+1,'064x')
   ctx.before_phase(phase,token);ctx.record_original(phase,token,cid)
   self.assertFalse(ctx.finish_phase(phase,token,cid,'ORIGINAL_ID_ABSENT_VERIFIED',None))
   self.assertEqual(self.result['completed_manifest'],list(c.PHASES[:index]));self.assertEqual(len(self.result['phase_originals']),index+1)
 def test_pin_close_uncertainty_keeps_active_guard(self):
  ctx=self.context('confinement');phase=c.PHASES[0];ctx.before_phase(phase,'1'*32);ctx.record_original(phase,'1'*32,'2'*64)
  ctx._phase_pins.close=Mock(side_effect=RuntimeError('SYNTHETIC'))
  with self.assertRaises(c.ProofUnavailable):ctx.finish_phase(phase,'1'*32,'2'*64,'ORIGINAL_ID_ABSENT_VERIFIED',outcome(phase))
  self.assertEqual(self.result['completed_manifest'],[]);self.assertEqual(len(self.result['phase_originals']),1)
 def test_durable_active_failure_stops_before_fresh(self):
  ctx=self.context('confinement');self.receipt.save.side_effect=RuntimeError('SYNTHETIC')
  with self.assertRaises(RuntimeError):ctx.before_phase(c.PHASES[0],'1'*32)
  self.source.assert_not_called()
 def test_finite_failed_harness_frame_is_retained_without_acceptance(self):
  ctx=self.context('strict');phase=c.PHASES[10];ctx.before_phase(phase,'f'*32);ctx.record_original(phase,'f'*32,'e'*64)
  self.assertFalse(ctx.finish_phase(phase,'f'*32,'e'*64,'ORIGINAL_ID_ABSENT_VERIFIED',{'phase_id':phase,'passed':False}))
  self.assertFalse(self.result['phase_originals'][-1]['outcome']['passed'])
  self.assertEqual(len(self.result['completed_manifest']),10)
 def test_wrong_seal_and_canonical_type_refuse(self):
  ctx=self.context('confinement');ctx._seal=object()
  with self.assertRaises(c.ProofUnavailable):c._validate_context(ctx,'confinement')
 def test_deadline_and_disk_refuse_without_capability(self):
  ctx=self.context('confinement');ctx._deadline=0
  with self.assertRaises(c.ProofUnavailable):ctx.before_phase(c.PHASES[0],'1'*32)
 def test_cleanup_bypasses_work_gates_but_only_exact_returned_identity(self):
  ctx=self.context('confinement');phase=c.PHASES[0];ctx.before_phase(phase,'1'*32)
  ctx.retain_original(phase,'1'*32,'2'*64);ctx._deadline=0;ctx._call.uncertain=True
  with self.assertRaises(c.ProofUnavailable):ctx.command('container','inspect','2'*64)
  ctx.cleanup_command('container','inspect','2'*64);ctx.cleanup_command('container','rm','2'*64)
  self.assertTrue(ctx.call_uncertain)
  for args in (('container','start','2'*64),('container','rm','3'*64),('container','inspect','foreign'),('info',)):
   with self.assertRaises(c.ProofUnavailable):ctx.cleanup_command(*args)
 def test_returned_identity_cannot_change_or_adopt_previous(self):
  ctx=self.context('confinement');phase=c.PHASES[0];ctx.before_phase(phase,'1'*32);ctx.retain_original(phase,'1'*32,'2'*64)
  with self.assertRaises(c.ProofUnavailable):ctx.retain_original(phase,'1'*32,'3'*64)
 def test_cleanup_budget_is_fixed_and_never_creates_or_starts(self):
  ctx=self.context('confinement');phase=c.PHASES[0];ctx.before_phase(phase,'1'*32);ctx.retain_original(phase,'1'*32,'2'*64)
  for i in range(8):ctx.cleanup_command('container','inspect','2'*64)
  with self.assertRaises(c.ProofUnavailable):ctx.cleanup_command('container','inspect','2'*64)
  ctx=self.context('confinement');self.mock(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=0))
  with self.assertRaises(c.ProofUnavailable):ctx.before_phase(c.PHASES[0],'1'*32)

class ManifestDenials(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.stack.enter_context(patch.object(c,'NATIVE_SHA256','a'*64))
  self.stack.enter_context(patch.object(c,'_native',return_value=FakeNative))
  self.binding=c.binding('b'*64)
 def test_exact_final26_no_extra_or_missing_and41_total(self):
  rows=[row(i,self.binding) for i in range(26)]
  c.validate_manifest(rows,c.PHASES,self.binding);self.assertEqual(15+len(rows),41)
  self.assertEqual((15+len(rows))*4,164)
  for changed in (rows[:-1],rows+[rows[-1]],list(reversed(rows))):
   with self.assertRaises(c.ProofUnavailable):c.validate_manifest(changed,c.PHASES,self.binding)
 def test_duplicate_original_or_token_refuses(self):
  for key in ('token','original_id'):
   rows=[row(i,self.binding) for i in range(2)];rows[1]['journal'][key]=rows[0]['journal'][key]
   with self.assertRaises(c.ProofUnavailable):c.validate_manifest(rows,c.PHASES[:2],self.binding)
 def test_false_partial_unknown_outcome_or_schema_refuses(self):
  for change in (lambda v:v.update(outcome=None),lambda v:v['outcome'].update(passed=False),
   lambda v:v.update(extra='secret'),lambda v:v['journal'].update(original_cid_and_name_absent_live=False)):
   rows=[row(0,self.binding)];change(rows[0])
   with self.assertRaises(c.ProofUnavailable):c.validate_manifest(rows,c.PHASES[:1],self.binding)
 def test_replay_reconstructs_four_actual_canonical_documents_each_phase(self):
  rows=[row(i,self.binding) for i in range(26)]
  def actual(root,pins,api,token,fixed,cid,files):
   return dict(next(r['journal'] for r in rows if r['journal']['token']==token))
  def journal(*args):
   result=actual(*args);result.pop('original_cid_and_name_absent_live');return result
  with patch.object(diagnostic,'journal_documents',side_effect=journal) as replay:
   self.assertEqual(len(c.replay_proof_originals(Path('.'),ExitStack(),Mock(),rows,self.binding)),26)
  self.assertEqual(replay.call_count,26)


class ExistingSameHandleLock(unittest.TestCase):
 def invoke(self,kind='ok'):
  events=[];stream=Mock();stream.fileno.return_value=51;identity={'volume':'9','file_id':'17'}
  @contextmanager
  def pin(path,**kwargs):
   self.assertEqual(kwargs,{'private':True,'writable':True});events.append('open')
   try:yield stream
   finally:
    events.append('close')
    if kind=='close':raise RuntimeError('SYNTHETIC')
  api=Mock();api.pin=Mock(side_effect=pin)
  runtime=SimpleNamespace(LK_NBLCK=1,LK_UNLCK=2)
  def locking(fd,mode,count):
   self.assertEqual((fd,count),(51,1));events.append('lock' if mode==1 else 'unlock')
   if kind=='unlock' and mode==2:raise RuntimeError('SYNTHETIC')
  runtime.locking=locking
  def exact(handle,path):
   self.assertIs(handle,stream);events.append('exact')
   if kind=='finalcheck' and events.count('exact')==2:raise RuntimeError('SYNTHETIC')
  def full(handle,path,windows):self.assertIs(handle,stream);events.append('identity');return identity
  with patch('infra.evidence_postcompile_continuation.lock_runtime',return_value=runtime),patch('infra.evidence_postcompile_continuation.exact_lock',side_effect=exact),patch.object(diagnostic,'stream_identity',side_effect=full),patch('infra.evidence_postcompile_continuation.atomic_private_lock') as create:
   if kind=='ok':
    with c.existing_proof_lock(api,ExitStack(),{'lock_identity':identity}) as retained:self.assertIs(retained,stream);events.append('body')
   else:
    with self.assertRaises(RuntimeError):
     with c.existing_proof_lock(api,ExitStack(),{'lock_identity':identity}):
      events.append('body')
      if kind=='body':raise RuntimeError('SYNTHETIC')
  create.assert_not_called();api.pin.assert_called_once();return events
 def test_single_existing_handle_read_lock_identity_unlock_close(self):
  self.assertEqual(self.invoke(),['open','exact','identity','lock','body','exact','identity','unlock','close'])
 def test_body_exception_still_rechecks_and_unlocks_same_handle(self):
  self.assertEqual(self.invoke('body'),['open','exact','identity','lock','body','exact','identity','unlock','close'])
 def test_final_check_failure_still_unlocks_and_closes(self):
  self.assertEqual(self.invoke('finalcheck')[-3:],['exact','unlock','close'])
 def test_unlock_failure_still_closes(self):self.assertEqual(self.invoke('unlock')[-2:],['unlock','close'])
 def test_close_failure_dominates(self):self.invoke('close')
 def test_missing_lock_has_no_create_route(self):
  api=Mock();api.pin.side_effect=FileNotFoundError()
  with patch('infra.evidence_postcompile_continuation.lock_runtime',return_value=Mock()),patch('infra.evidence_postcompile_continuation.atomic_private_lock') as create:
   with self.assertRaises(FileNotFoundError):
    with c.existing_proof_lock(api,ExitStack(),{}):self.fail('missing lock accepted')
  create.assert_not_called()


class PublicOriginalReplay(unittest.TestCase):
 def test_all_15_old_originals_60_canonical_documents_reconstructed(self):
  from infra import evidence_scratch_diagnostic as scratch
  _,_,_,owned,_=diagnostic.modules()
  binding=json.loads(Path(diagnostic.OWNED).read_text())
  scratch_receipts={op:Path(scratch.receipt_path(op)).read_bytes() for op in ('preflight','rmdir','lifecycle')}
  corrected={op:Path(diagnostic.receipt_path(op)).read_bytes() for op in ('prepare','preflight','rmdir','lifecycle')}
  rows=binding['journals']+[json.loads(scratch_receipts[op])['original_journal'] for op in ('rmdir','lifecycle')]+[
   json.loads(corrected[op])['original_journal'] for op in ('rmdir','lifecycle')]
  documents={row['directory']+'/'+name:owned._canonical(info['document']) for row in rows for name,info in row['files'].items()}
  reads=[]
  def read(root,pins,api,path,**kw):
   if path in documents:raw=documents[path];reads.append(path)
   elif path in (diagnostic.OWNED,diagnostic.FAILED,'infra/evidence_scratch_diagnostic.py','infra/evidence_rmdir_diagnostic.py'):raw=Path(path).read_bytes()
   elif path in [scratch.receipt_path(op) for op in scratch_receipts]:raw=scratch_receipts[next(op for op in scratch_receipts if path==scratch.receipt_path(op))]
   else:raw=corrected[next(op for op in corrected if path==diagnostic.receipt_path(op))]
   if 'expected' in kw:self.assertEqual(c.digest(raw),kw['expected'])
   return raw
  @contextmanager
  def no_pin(*a,**kw):yield
  prepared=json.loads(corrected['prepare'])['preparation']
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:actual=c.historical_originals(Path('.'),pins,Mock(),prepared)
  self.assertEqual(len(actual),15);self.assertEqual(len(reads),60);self.assertEqual(len(set(reads)),60)
 def test_locked_provenance_uses_only_same_lock_stream_no_new_open(self):
  prepared={'fixed':'record'};stream=Mock();api=Mock();api.pin.side_effect=AssertionError('second lock open')
  with patch.object(current,'pin_bytes',return_value=json.dumps({'preparation':prepared}).encode()) as reads,patch.object(diagnostic,'provenance') as provenance,patch.object(diagnostic,'profile_source'),patch.object(diagnostic,'old_profile_source'),patch('infra.evidence_postcompile_continuation.exact_lock') as exact,patch.object(diagnostic,'entry_identity',return_value={'volume':'1','file_id':'2'}),patch.object(diagnostic,'stream_identity',return_value={'volume':'1','file_id':'3'}) as full,patch.object(diagnostic,'preparation_record',return_value=prepared),patch.object(diagnostic,'binding_digest',return_value=c.PREPARATION_SHA256):
   self.assertEqual(c.corrected_provenance(Path('.'),ExitStack(),api,stream),prepared)
  api.pin.assert_not_called();self.assertIs(exact.call_args.args[0],stream);self.assertIs(full.call_args.args[0],stream)
  self.assertEqual(provenance.call_count,4)
  self.assertEqual([call.kwargs['expected'] for call in reads.call_args_list if 'expected' in call.kwargs],list(c.RMDIR_RECEIPTS.values()))
 def test_bounded_41_live_originals_use_six_fresh_same_engine_batches(self):
  rows=[{'token':format(i+1,'032x'),'original_id':format(i+1,'064x'),
   'expected_name':'kapit-rmdir-proof-public-'+format(i+1,'032x')} for i in range(41)]
  calls=[]
  def factory(*a):value=FakeCall();calls.append(value);return value
  with patch.object(diagnostic,'Commands',factory),patch.object(diagnostic,'engine') as engine:
   c.live_absences(FakeCall(),rows)
  self.assertEqual([len(call.calls) for call in calls],[16,16,16,16,16,2]);self.assertEqual(engine.call_count,12)
  with self.assertRaises(c.ProofUnavailable):c.live_absences(FakeCall(),rows+[rows[0]])
 def test_absence_exact_closed_error_and_selector(self):
  c.absence(FakeCall(),'kapit-rmdir-proof-public-'+'a'*32)
  for selector in ('--all','kapit-rmdir-proof-public-x',None):
   with self.assertRaises(c.ProofUnavailable):c.absence(FakeCall(),selector)
  call=Mock(return_value=(1,b'[]',b'permission denied','EXIT'))
  with self.assertRaises(c.ProofUnavailable):c.absence(call,'a'*64)


class PriorReceiptBoundary(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.stack.enter_context(patch.object(c,'NATIVE_SHA256','a'*64));self.stack.enter_context(patch.object(c,'_native',return_value=FakeNative))
  self.binding=c.binding('b'*64)
 def value(self,stage='confinement'):
  return {'schema':1,'scope':c.SCOPE,'stage':stage,'status':'VERIFIED','completed':True,
   'native_eligible':False,'private_input_allowed':False,'control_state_modified':False,
   'pins_closed':True,'cli_cleanup_confirmed':True,'binding':asdict(self.binding),
   'completed_stages':c.expected_stages(stage),'phase_originals':[row(i,self.binding) for i in range(c.END[stage])],
   'completed_manifest':list(c.PHASES[:c.END[stage]]),'results':{} if stage=='preflight' else {'stage':stage,'passed':True},'total_seconds':1.5}
 def read(self,value,*,bad_journal=False):
  def journal(root,pins,api,token,fixed,cid,files):
   actual=next(deepcopy(row['journal']) for row in value['phase_originals'] if row['journal']['token']==token)
   actual.pop('original_cid_and_name_absent_live')
   if bad_journal:actual['files']['ownership.json']={'changed':True}
   return actual
  with patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch.object(diagnostic,'journal_documents',side_effect=journal):
   return c.prior_stage(Path('.'),ExitStack(),Mock(),value['stage'],self.binding)
 def test_exact_closed_complete_prior_passes(self):self.assertEqual(self.read(self.value()),self.value())
 def test_refused_active_extra_partial_binding_and_finalizer_refuse(self):
  changes=(lambda v:v.update(status='REFUSED'),lambda v:v.update(completed=False),lambda v:v.update(active_case='strict'),
   lambda v:v.update(active_phase='x'),lambda v:v.update(failure_code='X'),lambda v:v.update(schema=True),
   lambda v:v['binding'].update(profile_sha256='f'*64),lambda v:v['completed_manifest'].pop(),
   lambda v:v['phase_originals'].pop(),lambda v:v['results'].update(passed=False),
   lambda v:v.update(pins_closed=False),lambda v:v.update(cli_cleanup_confirmed=False),lambda v:v.update(total_seconds=900))
  for change in changes:
   value=self.value();change(value)
   with self.subTest(change=repr(change)),self.assertRaises(c.ProofUnavailable):self.read(value)
 def test_changed_actual_journal_bytes_refuse_even_saved_receipt_complete(self):
  with self.assertRaises(c.ProofUnavailable):self.read(self.value(),bad_journal=True)
 def test_preflight_cannot_contain_native_results(self):
  value=self.value('preflight');value['results']={'passed':True}
  with self.assertRaises(c.ProofUnavailable):self.read(value)


class ReservationBoundary(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.stack.enter_context(patch.object(c,'NATIVE_SHA256','a'*64));self.stack.enter_context(patch.object(c,'_native',return_value=FakeNative))
  self.binding=c.binding('b'*64);self.saved=row(0,self.binding);self.token=self.saved['journal']['token']
 def check(self,value,rows=(),count=1):
  root=Path('.');directory=root/diagnostic.STAGE/('native-run-'+self.token)
  @contextmanager
  def no_pin(*a,**kw):yield
  with patch.object(Path,'glob',return_value=[directory]*count),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:return c.unknown_reservations(root,pins,Mock(),list(rows),self.binding)
 def test_exact_declared_prefix_reservation_accepted_only_with_token(self):
  value=FakeNative.metadata(self.token,c.PHASES[0],self.binding)
  self.check(value,[self.saved])
  with self.assertRaises(c.ProofUnavailable):self.check(value)
 def test_malformed_schema_validated_before_purpose_filter(self):
  base=FakeNative.metadata(self.token,c.PHASES[0],self.binding)
  for value in ({},dict(base,schema=True),dict(base,token='f'*32),dict(base,image_id='bad'),dict(base,expected_labels={}),dict(base,purpose='')):
   with self.subTest(value=value),self.assertRaises(c.ProofUnavailable):self.check(value)
 def test_unknown_same_owner_or_purpose_cannot_be_adopted(self):
  base=FakeNative.metadata(self.token,c.PHASES[0],self.binding)
  for change in (lambda v:v.update(phase_id=c.PHASES[1]),lambda v:v['expected_labels'].update(extra='x'),lambda v:v.update(purpose='public-rmdir-proof-v2')):
   value=deepcopy(base);change(value)
   with self.assertRaises(c.ProofUnavailable):self.check(value,[self.saved])
 def test_257_discovered_directories_refuse(self):
  with self.assertRaises(c.ProofUnavailable):self.check({},count=257)


class FailedOriginalCapture(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.stack.enter_context(patch.object(c,'NATIVE_SHA256','a'*64));self.stack.enter_context(patch.object(c,'_native',return_value=FakeNative))
  self.binding=c.binding('b'*64);self.phase=c.PHASES[0];self.token='a'*32;self.cid='b'*64
  fixed=FakeNative.metadata(self.token,self.phase,self.binding)
  self.docs={'reservation.json':fixed,'create-attempt.json':{'schema':1,'token':self.token,'create_attempted':True,'native_eligible':False},
   'ownership.json':dict(fixed,original_id=self.cid),'result.json':{'schema':1,'token':self.token,'original_id':self.cid,
    'ownership_status':'CLEANUP_UNCONFIRMED','native_eligible':False}}
 def check(self,docs=None,noncanonical=False):
  _,_,_,owned,_=diagnostic.modules();docs=self.docs if docs is None else docs
  def read(root,pins,api,path,**kw):
   name=Path(path).name
   if name not in docs:raise FileNotFoundError()
   raw=owned._canonical(docs[name]);return raw+b' ' if noncanonical else raw
  @contextmanager
  def no_pin(*a,**kw):yield
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:return c.capture_failed_original(Path('.'),pins,Mock(),self.phase,self.token,self.cid,self.binding)
 def test_all_four_uncertain_original_documents_preserved_canonically(self):
  value=self.check();self.assertEqual(len(value['files']),4);self.assertEqual(value['unconfirmed_documents'],[])
  self.assertEqual(value['files']['result.json']['document']['ownership_status'],'CLEANUP_UNCONFIRMED')
  for info in value['files'].values():
   self.assertEqual(info['sha256'],c.digest(diagnostic.modules()[3]._canonical(info['document'])))
 def test_missing_document_explicitly_unconfirmed_not_synthesized(self):
  for name in self.docs:
   docs=deepcopy(self.docs);docs.pop(name);value=self.check(docs)
   self.assertEqual(value['unconfirmed_documents'],[name]);self.assertNotIn(name,value['files'])
 def test_unknown_status_wrong_original_extra_or_noncanonical_document_unconfirmed(self):
  for change in (lambda v:v['result.json'].update(ownership_status='UNKNOWN'),lambda v:v['ownership.json'].update(original_id='c'*64),lambda v:v['reservation.json'].update(extra='x')):
   docs=deepcopy(self.docs);change(docs);value=self.check(docs)
   self.assertTrue(value['unconfirmed_documents'])
  self.assertEqual(len(self.check(noncanonical=True)['unconfirmed_documents']),4)


class OuterExecution(unittest.TestCase):
 setUp=ContextFixture.setUp
 mock=ContextFixture.mock
 def prepare(self,kind='ok'):
  self.saved=[];owner=self
  class Receipt:
   def __init__(self,path,result):self.stream=SimpleNamespace(closed=False)
   def save(self,value):owner.saved.append(deepcopy(value))
   def close(self):
    if kind=='receipt_close':raise RuntimeError('SYNTHETIC')
    self.stream.closed=True
  self.mock(current,'Receipt',Receipt);self.mock(c.os,'name','nt')
  self.mock(current,'pin_bytes',lambda *a,**k:b'fixed-controller')
  self.mock(c,'receipt_set',Mock())
  @contextmanager
  def guard():yield
  @contextmanager
  def inputs():
   yield self.api,ExitStack(),self.call,{}
   if kind=='input_close':raise RuntimeError('SYNTHETIC')
  @contextmanager
  def lock(*a):
   yield Mock()
   if kind=='lock_close':raise RuntimeError('SYNTHETIC')
  self.mock(diagnostic,'existing_lock_guard',guard)
  import infra.evidence_interpreter_compile as compiler
  self.mock(compiler,'checked_inputs',inputs);self.mock(c,'existing_proof_lock',lock)
  expected_binding=c.binding(c.digest(b'fixed-controller'))
  self.mock(c,'prior_stages',lambda root,pins,api,stage,binding:[row(i,binding) for i in range(0 if stage in ('preflight','confinement') else c.END[c.STAGES[c.STAGES.index(stage)-1]])])
  def native(ctx,stage):
   for index in range(len(ctx._result['completed_manifest']),c.END[stage]):
    phase=c.PHASES[index];token=format(index+1,'032x');cid=format(index+1,'064x')
    ctx.before_phase(phase,token);ctx.consume_before_create(phase);ctx.record_original(phase,token,cid)
    ctx.finish_phase(phase,token,cid,'ORIGINAL_ID_ABSENT_VERIFIED',outcome(phase))
   return {'stage':stage,'passed':True}
  self.mock(FakeNative,'execute',native) if hasattr(FakeNative,'execute') else self.stack.enter_context(patch.object(FakeNative,'execute',native,create=True))
 def test_all_fixed_stage_success_counts_and_final_closed_manifest(self):
  self.prepare()
  for stage in c.STAGES:
   value=c.execute(stage)
   self.assertEqual(value['status'],'VERIFIED');self.assertTrue(value['pins_closed'])
   self.assertEqual(len(value['phase_originals']),c.END[stage]);self.assertNotIn('active_phase',value)
 def test_preflight_never_calls_native_execute(self):
  self.prepare()
  with patch.object(FakeNative,'execute') as native:value=c.execute('preflight')
  native.assert_not_called();self.assertEqual(value['phase_originals'],[])
 def test_lock_input_and_receipt_close_failures_never_succeed(self):
  for kind in ('lock_close','input_close','receipt_close'):
   with self.subTest(kind=kind):
    self.prepare(kind)
    with self.assertRaises(c.ProofUnavailable):c.execute('confinement')
    self.assertFalse(self.saved[-1]['completed']);self.assertEqual(self.saved[-1]['status'],'REFUSED')
    self.assertIn('active_case',self.saved[-1]);self.assertIn('active_phase',self.saved[-1])
 def test_partial_group_result_refuses_and_blocks_success(self):
  self.prepare()
  self.mock(FakeNative,'execute',lambda *a:{'stage':'strict','passed':True})
  with self.assertRaises(c.ProofUnavailable):c.execute('confinement')
  self.assertEqual(self.saved[-1]['failed_stage'],'PUBLIC_MATRIX')
 def test_exclusive_receipt_failure_precedes_every_protected_action(self):
  self.prepare();self.mock(current,'Receipt',Mock(side_effect=FileExistsError()))
  with patch.object(diagnostic,'existing_lock_guard') as guard:
   with self.assertRaises(FileExistsError):c.execute('preflight')
  guard.assert_not_called()

if __name__=='__main__':unittest.main()
