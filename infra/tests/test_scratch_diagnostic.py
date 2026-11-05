"""Pure IO-replaced scratch-controller denial and ownership tests."""
import ast
import hashlib
import json
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from infra import evidence_scratch_diagnostic as c
from infra import evidence_interpreter_runtime as current
from infra import evidence_postcompile_diagnostic as old
from infra.native import scratch_probe as program

TOKEN='a'*32
CID='b'*64

class Call:
 def __init__(self,answer=None):
  self.docker='docker';self.config='config';self.uncertain=False;self.count=0;self.calls=[];self.answer=answer
 def __call__(self,*args,**kw):
  self.calls.append(args);self.count+=1
  if self.answer:return self.answer(*args)
  selector=args[-1]
  return (1,b'[]\n',('Error response from daemon: No such container: '+selector+'\n').encode(),'EXIT')

class ScratchController(unittest.TestCase):
 def test_import_inert_and_cli_closed(self):
  tree=ast.parse(Path(c.__file__).read_text())
  self.assertFalse(any(isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) for n in tree.body))
  self.assertEqual(c.receipt_path('rmdir'),'ai/state/private-scanner-scratch-rmdir.json')
  for operation in ('strict','pcre','../rmdir',None,True):
   with self.assertRaises(c.DiagnosticUnavailable):c.receipt_path(operation)
 def test_unreviewed_refuses_before_receipt(self):
  with patch.object(c,'PROGRAM_SHA256',None),patch.object(current,'Receipt') as receipt:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
   receipt.assert_not_called()
 def test_exact_program_pin(self):
  raw=Path(c.PROGRAM).read_bytes()
  self.assertEqual(hashlib.sha256(raw).hexdigest(),c.PROGRAM_SHA256)
  source=c.transport(raw,'lifecycle')
  self.assertIn("namespace['run']('lifecycle')",source)
  self.assertNotIn("sys.argv",source)
  for operation in ('strict',None,True):
   with self.assertRaises(c.DiagnosticUnavailable):c.transport(raw,operation)
  with self.assertRaises(c.DiagnosticUnavailable):c.transport(raw+b' ', 'rmdir')
 def test_closed_metadata(self):
  a=c.metadata(TOKEN,'rmdir');b=c.metadata(TOKEN,'lifecycle')
  self.assertNotEqual(a['purpose'],b['purpose'])
  self.assertEqual(a['expected_labels']['org.kapit.probe'],c.PROGRAM_SHA256)
  self.assertFalse(a['native_eligible']);self.assertFalse(a['private_input_allowed'])
  for token in ('a'*31,'z'*32,None):
   with self.assertRaises(c.DiagnosticUnavailable):c.metadata(token,'rmdir')
 def test_single_use_observation(self):
  obs=c.Observation(c._LIVE_SEAL,10,lambda:12)
  obs.consume()
  with self.assertRaises(c.DiagnosticUnavailable):obs.consume()
 def test_observation_deadlines(self):
  for now in (9,15.001):
   with self.assertRaises(c.DiagnosticUnavailable):c.Observation(c._LIVE_SEAL,10,lambda:now).consume()
  with self.assertRaises(c.DiagnosticUnavailable):c.Observation(object(),10)
 def test_absence_exact(self):
  call=Call();c.absence(call,CID)
  self.assertEqual(call.calls,[('container','inspect',CID)])
 def test_absence_uncertainty_denied(self):
  for answer in ((0,b'[]',b'','EXIT'),(1,b'',b'','EXIT'),(True,b'[]',b'','EXIT'),
   (1,b'[]',b'permission denied','EXIT'),(1,b'[]',b'','TIMEOUT')):
   with self.subTest(answer=answer),self.assertRaises(c.DiagnosticUnavailable):c.absence(Call(lambda *a:answer),CID)
 def test_absence_selector_injection_denied(self):
  for selector in ('--all','unknown','kapit-scratch-public-x',None):
   with self.assertRaises(c.DiagnosticUnavailable):c.absence(Call(),selector)
 def test_batched_live_absences_same_engine(self):
  rows=[{'original_id':format(i+1,'064x'),'expected_name':'kapit-same-image-public-'+format(i+1,'032x')} for i in range(11)]
  made=[]
  def factory(*a):
   call=Call();made.append(call);return call
  with patch.object(c,'Commands',side_effect=factory),patch.object(c,'engine') as engine:
   c.live_absences(Call(),rows)
  self.assertEqual([len(x.calls) for x in made],[16,6]);self.assertEqual(engine.call_count,4)
 def test_batched_live_uncertainty(self):
  call=Call();call.uncertain=True
  with patch.object(c,'Commands',return_value=call),patch.object(c,'engine'):
   with self.assertRaises(c.DiagnosticUnavailable):c.live_absences(Call(),[{'original_id':CID,'expected_name':'kapit-scratch-public-'+TOKEN}])
 def test_fresh_original_observation(self):
  consumed=Mock();compiler=__import__('infra.evidence_interpreter_compile',fromlist=['x'])
  with patch.object(compiler,'live_originals',return_value=SimpleNamespace(consume=consumed)),patch.object(c,'live_absences') as live:
   obs=c.fresh_observation(Call(),[{}],Call());obs.consume()
   self.assertEqual(consumed.call_count,1);live.assert_called_once()
 def test_cleanup_unknown_id_never_adopts(self):
  call=Call(lambda *a:(0,b'',b'','EXIT'))
  probe=SimpleNamespace(name='kapit-scratch-public-'+TOKEN)
  self.assertEqual(c.cleanup(call,probe,None,True),'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED')
  self.assertEqual([x[1] for x in call.calls],['ls'])
 def test_cleanup_unknown_id_found_denied(self):
  call=Call(lambda *a:(0,CID.encode(),b'','EXIT'))
  with self.assertRaises(c.DiagnosticUnavailable):c.cleanup(call,SimpleNamespace(name='fixed'),None,True)
  self.assertFalse(any('rm' in x for x in call.calls))
 def test_cleanup_owner_mismatch_no_delete(self):
  with patch.object(c,'inspect',return_value={'Id':CID,'Image':'other'}):
   call=Call()
   with self.assertRaises(c.DiagnosticUnavailable):c.cleanup(call,SimpleNamespace(name='fixed',labels={}),CID,True)
   self.assertFalse(call.calls)
 def test_cleanup_targets_exact_original(self):
  probe=SimpleNamespace(name='fixed',labels={'a':'b'})
  value={'Id':CID,'Name':'/fixed','Image':c.IMAGE,'Config':{'Labels':probe.labels},
   'State':{'Running':False,'Restarting':False,'Pid':0}}
  call=Call(lambda *a:(0,b'',b'','EXIT'))
  with patch.object(c,'inspect',return_value=value):self.assertEqual(c.cleanup(call,probe,CID,True),'ORIGINAL_ID_ABSENT_VERIFIED')
  self.assertEqual(call.calls[0],('container','rm',CID))
 def test_inspection_rejects_before_normalization(self):
  probe=SimpleNamespace(name='fixed',labels={},command=['fixed'])
  with patch('infra.evidence_native_runtime.verify_inspection') as verify:
   with self.assertRaises(c.DiagnosticUnavailable):c.inspection({'Id':CID,'Name':'/wrong'},probe,CID)
   verify.assert_not_called()
 def test_existing_locks_guard_writable_no_repair(self):
  entered=[];api=Mock()
  @contextmanager
  def pin(path,**kw):
   entered.append((Path(path).name,kw));yield Mock()
  api.pin=pin
  with patch('infra.evidence_tools.Windows',return_value=api),patch('infra.evidence_postcompile_continuation.exact_lock'):
   with c.existing_lock_guard():pass
  self.assertEqual(entered,[('resume-pcre.lock',{'writable':True,'private':False}),('interpreter.lock',{'writable':True,'private':True})])
  api.protect.assert_not_called()
 def test_existing_lock_missing_refuses(self):
  api=Mock();api.pin.side_effect=FileNotFoundError()
  with patch('infra.evidence_tools.Windows',return_value=api):
   with self.assertRaises(FileNotFoundError):
    with c.existing_lock_guard():self.fail('missing lock accepted')
 def test_expected_stage_order(self):
  self.assertNotIn('DEDICATED_LOCK',c.expected_stages('preflight'))
  self.assertLess(c.expected_stages('lifecycle').index('RMDIR_PROVENANCE'),c.expected_stages('lifecycle').index('PUBLIC_PROBE'))
  for op in ('preflight','rmdir','lifecycle'):self.assertEqual(len(set(c.expected_stages(op))),len(c.expected_stages(op)))
 def test_profile_public_inherited_contract(self):
  from infra import evidence_container as base
  from infra import evidence_container_native as public
  raw=base.canonical(public.startup_profile())
  refresh=c.modules()[0]
  with patch.object(refresh,'pin_bytes',return_value=raw) as pin:
   c.profile_source(Path('.'),ExitStack(),Mock())
  self.assertNotIn('private',pin.call_args.kwargs)
 def test_original_records_exactly_44(self):
  binding=json.loads(Path(c.OWNED).read_text());failed=Path(c.FAILED).read_bytes()
  self.assertEqual(hashlib.sha256(failed).hexdigest(),c.FAILED_SHA)
  self.assertEqual(len(binding['journals']),11)
  self.assertEqual(sum(len(r['files']) for r in binding['journals']),44)
  self.assertEqual(hashlib.sha256(Path(c.OWNED).read_bytes()).hexdigest(),c.OWNED_SHA)
 def test_journal_exact_documents(self):
  _,_,_,owned,_=c.modules();expected=c.metadata(TOKEN,'rmdir')
  docs={'reservation.json':expected,'create-attempt.json':{'schema':1,'token':TOKEN,'create_attempted':True,'native_eligible':False},
   'ownership.json':dict(expected,original_id=CID),'result.json':{'schema':1,'token':TOKEN,'original_id':CID,'ownership_status':'ORIGINAL_ID_ABSENT_VERIFIED','native_eligible':False}}
  @contextmanager
  def no_pin(*a,**k):yield
  with patch('infra.live_recovery_drill.PrivateDirectory') as private,patch.object(current,'pin_bytes',side_effect=lambda *a,**k:owned._canonical(docs[Path(a[3]).name])):
   private.return_value.pin=no_pin
   with ExitStack() as pins:row=c.journal_documents(Path('.'),pins,Mock(),TOKEN,expected,CID)
  self.assertEqual(set(row['files']),set(docs));self.assertEqual(row['original_id'],CID)
 def test_journal_changed_canonical_bytes_denied(self):
  @contextmanager
  def no_pin(*a,**k):yield
  with patch('infra.live_recovery_drill.PrivateDirectory') as private,patch.object(current,'pin_bytes',return_value=b'{}'):
   private.return_value.pin=no_pin
   with self.assertRaises(c.DiagnosticUnavailable):
    with ExitStack() as pins:c.journal_documents(Path('.'),pins,Mock(),TOKEN,c.metadata(TOKEN,'rmdir'),CID)
 def test_frozen_mechanical_clones(self):
  def source(fn):return ast.dump(ast.parse(__import__('inspect').getsource(fn)),include_attributes=False)
  for name in ('Commands','engine','Observation','inspection','inspect','check_owner','cleanup','profile_source'):
   self.assertEqual(source(getattr(c,name)),source(getattr(old,name)),name)


class FakeExecute(unittest.TestCase):
 def setUp(self):
  self.stack=ExitStack();self.addCleanup(self.stack.close)
  self.receipts=[];self.oldcall=Call();self.call=Call()
  self.compiler=__import__('infra.evidence_interpreter_compile',fromlist=['x'])
  @contextmanager
  def checked():yield Mock(),ExitStack(),self.oldcall,{}
  @contextmanager
  def no_guard():yield
  @contextmanager
  def lock(*args):yield
  self.lock=Mock(side_effect=lock)
  self.patch(self.compiler,'checked_inputs',checked)
  self.patch(c,'existing_lock_guard',no_guard)
  self.patch(c.os,'name','nt')
  self.patch(current,'pin_bytes',lambda *a,**k:b'fixed')
  self.patch(c,'profile_source',Mock())
  self.patch(current,'verified_image',lambda *a:{'image_id':c.IMAGE,'signature_generation':c.GENERATION})
  self.patch(c,'oci_bytes',Mock())
  self.patch(c,'original_documents',lambda *a:[{'original_id':CID,'expected_name':'kapit-scratch-public-'+TOKEN}])
  self.patch(c,'unknown_diagnostics',Mock())
  self.patch(c,'Commands',lambda *a:self.call)
  self.patch(c,'fresh_observation',lambda *a:c.Observation(c._LIVE_SEAL,c.time.monotonic()))
  self.patch(c.modules()[1],'_require_cgroup_v2',Mock())
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=c.FLOOR+1))
  self.patch(__import__('infra.evidence_postcompile_continuation',fromlist=['x']),'atomic_private_lock',self.lock)
  self.patch(c,'provenance',lambda *a:None)
  self.patch(c,'engine',Mock())
  self.patch(c,'live_absences',Mock())
  self.patch(c,'journal_documents',lambda *a:{'files':{}})
  owner=self
  class Receipt:
   def __init__(self,path,result):
    self.path=path;self.stream=SimpleNamespace(closed=False);self.values=[];owner.receipts.append(self)
   def save(self,value):self.values.append(deepcopy(value))
   def close(self):self.stream.closed=True
  self.patch(current,'Receipt',Receipt)
 def patch(self,obj,name,value):return self.stack.enter_context(patch.object(obj,name,value))
 def run_fake(self,operation='rmdir'):
  def probe(*args):
   args[5].update(reservation=TOKEN,original_id=CID,cleanup='ORIGINAL_ID_ABSENT_VERIFIED')
   return {'completed':True}
  self.patch(c,'run_probe',probe)
  return c.execute(operation)
 def test_preflight_no_dedicated_lock_no_probe(self):
  with patch.object(c,'run_probe') as probe:
   result=c.execute('preflight')
  probe.assert_not_called();self.lock.assert_not_called()
  self.assertEqual(result['status'],'VERIFIED');self.assertEqual(result['completed_stages'],c.expected_stages('preflight'))
 def test_rmdir_end_to_end_fixed_stages(self):
  result=self.run_fake()
  self.assertEqual(result['status'],'OBSERVED');self.assertTrue(result['pins_closed'])
  self.assertEqual(result['completed_stages'],c.expected_stages('rmdir'));self.lock.assert_called_once()
 def test_missing_provenance_refuses_before_probe(self):
  self.patch(c,'provenance',Mock(side_effect=c.DiagnosticUnavailable()))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called();self.assertEqual(self.receipts[0].values[-1]['failed_stage'],'PREFLIGHT_PROVENANCE')
 def test_current_package_refuses_before_probe(self):
  self.patch(current,'verified_image',Mock(side_effect=RuntimeError('SECRET')))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called();saved=self.receipts[0].values[-1]
  self.assertEqual(saved['failed_stage'],'IMAGE_PACKAGE_UTC');self.assertNotIn('SECRET',json.dumps(saved))
 def test_oci_changed_refuses_before_create(self):
  self.patch(c,'oci_bytes',Mock(side_effect=RuntimeError()))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called();self.assertEqual(self.receipts[0].values[-1]['failed_stage'],'OCI_BYTES')
 def test_unknown_reservation_refuses(self):
  self.patch(c,'unknown_diagnostics',Mock(side_effect=RuntimeError()))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called()
 def test_low_space_refuses(self):
  self.patch(c.shutil,'disk_usage',lambda *a:SimpleNamespace(free=c.FLOOR-1))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called()
 def test_probe_failure_preserved_engine_rechecked(self):
  self.patch(c,'run_probe',Mock(side_effect=c.DiagnosticUnavailable()))
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  c.engine.assert_called_once();self.assertEqual(self.receipts[0].values[-1]['failed_stage'],'PUBLIC_PROBE')
 def test_final_cli_uncertainty_dominates(self):
  self.call.uncertain=True
  with self.assertRaises(c.DiagnosticUnavailable):self.run_fake()
  saved=self.receipts[0].values[-1];self.assertFalse(saved['completed']);self.assertNotIn('measurement',saved)
 def test_lock_close_uncertainty_dominates(self):
  @contextmanager
  def bad(*a):
   yield
   raise RuntimeError('SECRET')
  self.lock.side_effect=bad
  with self.assertRaises(c.DiagnosticUnavailable):self.run_fake()
  saved=self.receipts[0].values[-1]
  self.assertEqual(saved['failed_stage'],'DEDICATED_LOCK_CLOSE');self.assertNotIn('measurement',saved)
 def test_final_receipt_failure_no_success(self):
  def error(*a):raise RuntimeError('SECRET')
  original=c.run_probe
  def probe(*args):
   args[5].update(reservation=TOKEN,original_id=CID,cleanup='ORIGINAL_ID_ABSENT_VERIFIED')
   self.receipts[0].close=error
   return {'completed':True}
  self.patch(c,'run_probe',probe)
  with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  saved=self.receipts[0].values[-1]
  self.assertEqual(saved['failure_code'],'RECEIPT_CLOSE_UNCONFIRMED');self.assertNotIn('measurement',saved)


 def test_lifecycle_prior_checked_and_live_absence_included(self):
  prior={'token':'d'*32,'original_id':'c'*64,'expected_name':'kapit-scratch-public-'+'d'*32,'files':{}}
  provenance=Mock(side_effect=lambda *args:prior if args[3]=='rmdir' else None)
  self.patch(c,'provenance',provenance)
  observed=[]
  def fresh(call,rows,old):
   observed.extend(deepcopy(rows));return c.Observation(c._LIVE_SEAL,c.time.monotonic())
  self.patch(c,'fresh_observation',fresh)
  result=self.run_fake('lifecycle')
  self.assertEqual([call.args[3] for call in provenance.call_args_list],['preflight','rmdir'])
  self.assertIn(prior,observed);self.assertEqual(result['completed_stages'],c.expected_stages('lifecycle'))
  self.assertEqual(c.unknown_diagnostics.call_args.args[3],{'d'*32})
 def test_lifecycle_missing_or_refused_rmdir_stops_before_probe(self):
  for error in (FileNotFoundError(),c.DiagnosticUnavailable()):
   with self.subTest(error=type(error).__name__):
    self.patch(c,'provenance',Mock(side_effect=lambda *args: (_ for _ in ()).throw(error) if args[3]=='rmdir' else None))
    with patch.object(c,'run_probe') as probe:
     with self.assertRaises(c.DiagnosticUnavailable):c.execute('lifecycle')
    probe.assert_not_called();self.assertEqual(self.receipts[-1].values[-1]['failed_stage'],'RMDIR_PROVENANCE')
 def test_lifecycle_unknown_reservation_blocks_create(self):
  self.patch(c,'provenance',lambda *args:{'token':'d'*32,'original_id':'c'*64,'expected_name':'kapit-scratch-public-'+'d'*32} if args[3]=='rmdir' else None)
  self.patch(c,'unknown_diagnostics',Mock(side_effect=c.DiagnosticUnavailable()))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('lifecycle')
  probe.assert_not_called()
 def test_existing_receipt_refuses_before_input_actions(self):
  self.patch(current,'Receipt',Mock(side_effect=FileExistsError()))
  checked=self.patch(self.compiler,'checked_inputs',Mock())
  guard=self.patch(c,'existing_lock_guard',Mock())
  with self.assertRaises(FileExistsError):c.execute('rmdir')
  checked.assert_not_called();guard.assert_not_called()


class RunProbeFailures(unittest.TestCase):
 def check_journal_failure(self,where):
  _,runtime,attach,_,_=c.modules()
  journal=SimpleNamespace(mark_create_attempted=Mock(),record_original=Mock(),finish=Mock(),failed=False)
  if where=='attempt':journal.mark_create_attempted.side_effect=RuntimeError()
  if where=='original':journal.record_original.side_effect=RuntimeError()
  if where=='finish':journal.finish.side_effect=RuntimeError()
  @contextmanager
  def reserve(*a):yield journal
  call=Call(lambda *a:(0,(CID+'\n').encode(),b'','EXIT'))
  result={};observation=Mock()
  with patch.object(c,'reserve',reserve),patch.object(c,'create_args',return_value=['container','create']),   patch.object(c,'transport',return_value='fixed'),patch.object(runtime,'_Phase',return_value=SimpleNamespace(token=TOKEN)),   patch.object(c,'cleanup',return_value='ORIGINAL_ID_ABSENT_VERIFIED') as cleanup,   patch.object(c,'inspection',side_effect=RuntimeError()),patch.object(runtime,'_require_cgroup_v2'),   patch.object(c,'inspect'),patch.object(attach,'_attach') as start:
   with self.assertRaises((RuntimeError,c.DiagnosticUnavailable)):
    c.run_probe(Path('.'),call,Path('fixed'),b'fixed',observation,result,'rmdir')
   start.assert_not_called()
  return call,result,observation,cleanup
 def test_failed_attempt_journal_no_create(self):
  call,result,observation,cleanup=self.check_journal_failure('attempt')
  self.assertFalse(call.calls);observation.consume.assert_not_called()
 def test_failed_original_journal_no_start(self):
  call,result,observation,cleanup=self.check_journal_failure('original')
  self.assertEqual(call.calls,[('container','create')]);self.assertEqual(result['cleanup'],'UNCONFIRMED')
 def test_failed_result_journal_dominates(self):
  call,result,observation,cleanup=self.check_journal_failure('finish')
  self.assertEqual(result['cleanup'],'UNCONFIRMED')
 def test_exact_returned_id_cleanup(self):
  call,result,observation,cleanup=self.check_journal_failure('inspect')
  self.assertEqual(cleanup.call_args.args[2],CID);observation.consume.assert_called_once()


class PriorProvenance(unittest.TestCase):
 def value(self):
  return {'schema':1,'scope':c.SCOPE,'stage':'preflight','status':'VERIFIED','completed':True,
   'native_eligible':False,'private_input_allowed':False,'control_state_modified':False,
   'pins_closed':True,'cli_cleanup_confirmed':True,'image_id':c.IMAGE,'signature_generation':c.GENERATION,
   'program_sha256':c.PROGRAM_SHA256,'source_pins':c.SOURCE_PINS,'completed_stages':c.expected_stages('preflight'),
   'controller_sha256':hashlib.sha256(b'source').hexdigest(),'total_seconds':1.5}
 def check(self,value):
  def read(*args,**kw):
   return b'source' if args[3]=='infra/evidence_scratch_diagnostic.py' else json.dumps(value).encode()
  with patch.object(current,'pin_bytes',read):return c.provenance(Path('.'),ExitStack(),Mock(),'preflight')
 def test_exact_provenance_passes(self):self.assertEqual(self.check(self.value()),self.value())
 def test_bool_schema_denied(self):
  value=self.value();value['schema']=True
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_extra_key_denied(self):
  value=self.value();value['exception_class']='Secret'
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_partial_stage_denied(self):
  value=self.value();value['completed_stages'].pop()
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_wrong_stage_order_denied(self):
  value=self.value();value['completed_stages'].reverse()
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_changed_source_denied(self):
  value=self.value();value['controller_sha256']='1'*64
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_refused_denied(self):
  value=self.value();value['status']='REFUSED'
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_private_grant_denied(self):
  value=self.value();value['private_input_allowed']=True
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)
 def test_close_uncertainty_denied(self):
  value=self.value();value['pins_closed']=False
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value)


class TransportAndReceiptSet(unittest.TestCase):
 def test_transport_unexpected_host_error_controlled(self):
  raw=b"def run(operation): raise RuntimeError('SYNTHETIC')\n"
  with patch.object(c,'PROGRAM_SHA256',hashlib.sha256(raw).hexdigest()):source=c.transport(raw,'rmdir')
  with self.assertRaises(SystemExit) as raised:exec(source,{})
  self.assertEqual(raised.exception.code,2)
 def test_unknown_receipt_refuses(self):
  root=Mock();directory=Mock();root.__truediv__=Mock(return_value=directory)
  directory.glob.return_value=[Path('private-scanner-scratch-rmdir-v2.json')]
  with self.assertRaises(c.DiagnosticUnavailable):c.receipt_set(root)


class PriorRmdirAndReservations(unittest.TestCase):
 def setup_value(self):
  expected=c.metadata(TOKEN,'rmdir');_,_,_,owned,_=c.modules()
  docs={'reservation.json':expected,'create-attempt.json':{'schema':1,'token':TOKEN,'create_attempted':True,'native_eligible':False},
   'ownership.json':dict(expected,original_id=CID),'result.json':{'schema':1,'token':TOKEN,'original_id':CID,'ownership_status':'ORIGINAL_ID_ABSENT_VERIFIED','native_eligible':False}}
  files={name:{'bytes':len(owned._canonical(doc)),'sha256':hashlib.sha256(owned._canonical(doc)).hexdigest(),'document':doc} for name,doc in docs.items()}
  row={'directory':c.STAGE+'/native-run-'+TOKEN,'token':TOKEN,'original_id':CID,'expected_name':expected['expected_name'],'files':files,'original_cid_and_name_absent_live':True}
  value=PriorProvenance().value();value.update(stage='rmdir',status='OBSERVED',completed_stages=c.expected_stages('rmdir'),
   measurement={'schema':1,'scope':'PUBLIC_SCRATCH_DIAGNOSTIC_ONLY','operation':'rmdir','completed':True,'failed_stage':'NONE',
    'observation':'EPERM','snapshots':[],'native_eligible':False,'private_input_allowed':False},
   reservation=TOKEN,original_id=CID,cleanup='ORIGINAL_ID_ABSENT_VERIFIED',original_journal=row,same_engine_sha256=c.ENGINE)
  return value,docs
 def check(self,value,docs):
  _,_,_,owned,_=c.modules();reads=[]
  def read(*args,**kw):
   name=args[3];reads.append(name)
   if name=='infra/evidence_scratch_diagnostic.py':return b'source'
   if name==c.receipt_path('rmdir'):return json.dumps(value).encode()
   return owned._canonical(docs[Path(name).name])
  @contextmanager
  def nop(*a,**kw):yield
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=nop
   with ExitStack() as pins:result=c.provenance(Path('.'),pins,Mock(),'rmdir')
  return result,reads
 def test_actual_four_journals_and_rmdir_frame_pass(self):
  value,docs=self.setup_value();result,reads=self.check(value,docs)
  self.assertEqual(len([name for name in reads if 'native-run-' in name]),4)
  self.assertEqual(result['files'],value['original_journal']['files'])
 def test_corrupted_measurement_denied(self):
  value,docs=self.setup_value();value['measurement']['observation']='UNKNOWN'
  with self.assertRaises((c.DiagnosticUnavailable,program.ProbeUnavailable)):self.check(value,docs)
 def test_refused_measurement_denied(self):
  value,docs=self.setup_value();value['measurement'].update(completed=False,failed_stage='native_abi',observation='NONE')
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value,docs)
 def test_each_saved_journal_hash_change_denied(self):
  for name in ('reservation.json','create-attempt.json','ownership.json','result.json'):
   value,docs=self.setup_value();value['original_journal']['files'][name]['sha256']='1'*64
   with self.subTest(name=name),self.assertRaises(c.DiagnosticUnavailable):self.check(value,docs)
 def test_changed_actual_ownership_denied(self):
  value,docs=self.setup_value();docs['ownership.json']['original_id']='c'*64
  with self.assertRaises(c.DiagnosticUnavailable):self.check(value,docs)
 def test_missing_actual_result_denied(self):
  value,docs=self.setup_value();docs.pop('result.json')
  with self.assertRaises(KeyError):self.check(value,docs)
 def test_unknown_partial_reservation_denied(self):
  expected=c.metadata(TOKEN,'rmdir')
  for value in ({},dict(expected,expected_labels={}),dict(expected,token='c'*32),dict(expected,purpose='')):
   root=Path('.')
   directory=Path(c.STAGE+'/native-run-'+TOKEN)
   @contextmanager
   def nop(*a,**kw):yield
   with patch.object(Path,'glob',return_value=[directory]),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
    private.return_value.pin=nop
    with self.subTest(value=value),self.assertRaises(c.DiagnosticUnavailable):
     with ExitStack() as pins:c.unknown_diagnostics(root,pins,Mock(),set())

 def reservations(self,value,allowed=(),directories=None):
  directory=Path(c.STAGE+'/native-run-'+TOKEN)
  @contextmanager
  def nop(*a,**kw):yield
  with patch.object(Path,'glob',return_value=[directory] if directories is None else directories),   patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=nop
   with ExitStack() as pins:c.unknown_diagnostics(Path('.'),pins,Mock(),set(allowed))
 def test_missing_owner_or_purpose_denied(self):
  for key in ('org.kapit.owner','org.kapit.purpose'):
   value=c.metadata(TOKEN,'rmdir');value['expected_labels'].pop(key)
   with self.subTest(key=key),self.assertRaises(c.DiagnosticUnavailable):self.reservations(value)
 def test_valid_old_non_scratch_reservation_allowed(self):
  _,_,_,owned,_=c.modules()
  value=json.loads(Path(c.OWNED).read_text())['journals'][0]['files']['reservation.json']['document']
  value['token']=TOKEN
  value['expected_labels'].update({'org.kapit.reservation':TOKEN,'org.kapit.run':TOKEN})
  self.reservations(value)
 def test_current_scratch_requires_exact_prior_token(self):
  value=c.metadata(TOKEN,'rmdir')
  with self.assertRaises(c.DiagnosticUnavailable):self.reservations(value)
  self.reservations(value,[TOKEN])
 def test_current_lifecycle_reservation_never_adopted(self):
  with self.assertRaises(c.DiagnosticUnavailable):self.reservations(c.metadata(TOKEN,'lifecycle'),[TOKEN])
 def test_directory_budget_refuses_257(self):
  with self.assertRaises(c.DiagnosticUnavailable):self.reservations({},directories=[Path('native-run-'+TOKEN)]*257)


class FullRunProbe(unittest.TestCase):
 def invoke(self,kind='success'):
  _,runtime,attach,_,_=c.modules();events=[]
  journal=SimpleNamespace(mark_create_attempted=Mock(side_effect=lambda:events.append('attempt')),
   record_original=Mock(side_effect=lambda cid:events.append('owned')),finish=Mock(),failed=False)
  @contextmanager
  def reserve(*a):yield journal
  def created(*a):events.append('create');return 0,(CID+'\n').encode(),b'','EXIT'
  call=Call(created);result={};observation=SimpleNamespace(consume=lambda:events.append('fresh'))
  frame={'schema':1,'scope':'PUBLIC_SCRATCH_DIAGNOSTIC_ONLY','operation':'rmdir','completed':True,'failed_stage':'NONE',
   'observation':'EPERM','snapshots':[],'native_eligible':False,'private_input_allowed':False}
  output=json.dumps(frame).encode();code=0
  if kind=='oversize':output=b'x'*4097
  if kind=='nonzero':code=2
  def start(*a,**kw):
   events.append('start')
   if kind=='timeout':raise c.DiagnosticUnavailable('ATTACH_FINAL_DEADLINE')
   return code,output
  after={'State':{'OOMKilled':False,'ExitCode':0,'Pid':0}}
  if kind=='oom':after['State']['OOMKilled']=True
  cleanup=Mock(return_value='ORIGINAL_ID_ABSENT_VERIFIED')
  if kind=='cleanup':cleanup.side_effect=RuntimeError()
  with patch.object(c,'reserve',reserve),patch.object(c,'create_args',return_value=['container','create']),   patch.object(c,'transport',return_value='fixed'),patch.object(runtime,'_Phase',return_value=SimpleNamespace(token=TOKEN)),   patch.object(c,'cleanup',cleanup),patch.object(c,'inspection'),patch.object(runtime,'_require_cgroup_v2'),   patch.object(c,'inspect',return_value=after),patch.object(attach,'_attach',start),   patch.object(c.shutil,'disk_usage',return_value=SimpleNamespace(free=c.FLOOR+1)):
   if kind=='success':payload=c.run_probe(Path('.'),call,Path('fixed'),b'fixed',observation,result,'rmdir')
   else:
    with self.assertRaises(c.DiagnosticUnavailable):c.run_probe(Path('.'),call,Path('fixed'),b'fixed',observation,result,'rmdir')
    payload=None
  return payload,result,events,journal,cleanup
 def test_success_owned_before_start_and_original_cleanup(self):
  payload,result,events,journal,cleanup=self.invoke()
  self.assertTrue(payload['completed']);self.assertEqual(events,['attempt','fresh','create','owned','start'])
  self.assertEqual(cleanup.call_args.args[2],CID);journal.finish.assert_called_once_with('ORIGINAL_ID_ABSENT_VERIFIED')
 def test_oversize_output_refuses_and_cleans(self):
  _,result,_,journal,cleanup=self.invoke('oversize');cleanup.assert_called_once();self.assertEqual(result['cleanup'],'ORIGINAL_ID_ABSENT_VERIFIED')
 def test_nonzero_attach_refuses_and_cleans(self):
  _,_,_,_,cleanup=self.invoke('nonzero');cleanup.assert_called_once()
 def test_attach_timeout_refuses_and_cleans(self):
  _,_,_,_,cleanup=self.invoke('timeout');cleanup.assert_called_once()
 def test_oom_refuses(self):self.invoke('oom')
 def test_final_cleanup_failure_dominates_measurement(self):
  payload,result,_,journal,_=self.invoke('cleanup')
  self.assertIsNone(payload);self.assertEqual(result['cleanup'],'UNCONFIRMED');journal.finish.assert_called_once_with('CLEANUP_UNCONFIRMED')

if __name__=='__main__':unittest.main()
