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
from infra import evidence_rmdir_diagnostic as c
from infra import evidence_interpreter_runtime as current
from infra import evidence_postcompile_diagnostic as old
from infra.native import scratch_probe as program

TOKEN='a'*32
PREPARATION={'schema':1,'synthetic':'fixture'}
PREP_SHA=c.binding_digest(PREPARATION)
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
  self.assertEqual(c.receipt_path('rmdir'),'ai/state/private-scanner-rmdir-rmdir.json')
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
  a=c.metadata(TOKEN,'rmdir',PREP_SHA);b=c.metadata(TOKEN,'lifecycle',PREP_SHA)
  self.assertNotEqual(a['purpose'],b['purpose'])
  self.assertEqual(a['expected_labels']['org.kapit.probe'],c.PROGRAM_SHA256)
  self.assertFalse(a['native_eligible']);self.assertFalse(a['private_input_allowed'])
  for token in ('a'*31,'z'*32,None):
   with self.assertRaises(c.DiagnosticUnavailable):c.metadata(token,'rmdir',PREP_SHA)
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
   c.old_profile_source(Path('.'),ExitStack(),Mock())
  self.assertNotIn('private',pin.call_args.kwargs)
 def test_original_records_exactly_44(self):
  binding=json.loads(Path(c.OWNED).read_text());failed=Path(c.FAILED).read_bytes()
  self.assertEqual(hashlib.sha256(failed).hexdigest(),c.FAILED_SHA)
  self.assertEqual(len(binding['journals']),11)
  self.assertEqual(sum(len(r['files']) for r in binding['journals']),44)
  self.assertEqual(hashlib.sha256(Path(c.OWNED).read_bytes()).hexdigest(),c.OWNED_SHA)
 def test_journal_exact_documents(self):
  _,_,_,owned,_=c.modules();expected=c.metadata(TOKEN,'rmdir',PREP_SHA)
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
    with ExitStack() as pins:c.journal_documents(Path('.'),pins,Mock(),TOKEN,c.metadata(TOKEN,'rmdir',PREP_SHA),CID)
 def test_frozen_mechanical_clones(self):
  def source(fn):return ast.dump(ast.parse(__import__('inspect').getsource(fn)),include_attributes=False)
  for name in ('Commands','engine','Observation','inspect','check_owner','cleanup'):
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
  def lock(*args):yield False
  self.lock=Mock(side_effect=lock)
  self.patch(self.compiler,'checked_inputs',checked)
  self.patch(c,'existing_lock_guard',no_guard)
  self.patch(c.os,'name','nt')
  self.patch(current,'pin_bytes',lambda *a,**k:b'fixed')
  self.patch(c,'profile_source',Mock())
  self.patch(c,'old_profile_source',Mock())
  self.patch(c,'checked_constants',Mock())
  self.patch(c,'accepted_preparation',lambda *a:PREPARATION)
  self.patch(c,'prepare_objects',lambda *a:PREPARATION)
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
   return {'completed':True,'observation':'REMOVED','snapshots':[]}
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
   yield False
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
   return {'completed':True,'observation':'REMOVED','snapshots':[]}
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
  result={'preparation_sha256':PREP_SHA};observation=Mock()
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
   'native_eligible':False,'private_input_allowed':False,'control_state_modified':False,'profile_sha256':c.NEW_PROFILE_SHA256,
   'profile_module_sha256':c.PROFILE_MODULE_SHA256,'preparation':PREPARATION,'preparation_sha256':PREP_SHA,
   'pins_closed':True,'cli_cleanup_confirmed':True,'image_id':c.IMAGE,'signature_generation':c.GENERATION,
   'program_sha256':c.PROGRAM_SHA256,'source_pins':c.SOURCE_PINS,'completed_stages':c.expected_stages('preflight'),
   'controller_sha256':hashlib.sha256(b'source').hexdigest(),'total_seconds':1.5}
 def check(self,value):
  def read(*args,**kw):
   return b'source' if args[3]=='infra/evidence_rmdir_diagnostic.py' else json.dumps(value).encode()
  with patch.object(current,'pin_bytes',read):return c.provenance(Path('.'),ExitStack(),Mock(),'preflight',PREPARATION)
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
  directory.glob.return_value=[Path('private-scanner-rmdir-rmdir-v3.json')]
  with self.assertRaises(c.DiagnosticUnavailable):c.receipt_set(root)


class PriorRmdirAndReservations(unittest.TestCase):
 def setup_value(self):
  expected=c.metadata(TOKEN,'rmdir',PREP_SHA);_,_,_,owned,_=c.modules()
  docs={'reservation.json':expected,'create-attempt.json':{'schema':1,'token':TOKEN,'create_attempted':True,'native_eligible':False},
   'ownership.json':dict(expected,original_id=CID),'result.json':{'schema':1,'token':TOKEN,'original_id':CID,'ownership_status':'ORIGINAL_ID_ABSENT_VERIFIED','native_eligible':False}}
  files={name:{'bytes':len(owned._canonical(doc)),'sha256':hashlib.sha256(owned._canonical(doc)).hexdigest(),'document':doc} for name,doc in docs.items()}
  row={'directory':c.STAGE+'/native-run-'+TOKEN,'token':TOKEN,'original_id':CID,'expected_name':expected['expected_name'],'files':files,'original_cid_and_name_absent_live':True}
  value=PriorProvenance().value();value.update(stage='rmdir',status='OBSERVED',completed_stages=c.expected_stages('rmdir'),
   measurement={'schema':1,'scope':'PUBLIC_SCRATCH_DIAGNOSTIC_ONLY','operation':'rmdir','completed':True,'failed_stage':'NONE',
    'observation':'REMOVED','snapshots':[],'native_eligible':False,'private_input_allowed':False},
   reservation=TOKEN,original_id=CID,cleanup='ORIGINAL_ID_ABSENT_VERIFIED',original_journal=row,same_engine_sha256=c.ENGINE,correction_observed=True)
  return value,docs
 def check(self,value,docs):
  _,_,_,owned,_=c.modules();reads=[]
  def read(*args,**kw):
   name=args[3];reads.append(name)
   if name=='infra/evidence_rmdir_diagnostic.py':return b'source'
   if name==c.receipt_path('rmdir'):return json.dumps(value).encode()
   return owned._canonical(docs[Path(name).name])
  @contextmanager
  def nop(*a,**kw):yield
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=nop
   with ExitStack() as pins:result=c.provenance(Path('.'),pins,Mock(),'rmdir',PREPARATION)
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
  expected=c.metadata(TOKEN,'rmdir',PREP_SHA)
  for value in ({},dict(expected,expected_labels={}),dict(expected,token='c'*32),dict(expected,purpose='')):
   root=Path('.')
   directory=Path(c.STAGE+'/native-run-'+TOKEN)
   @contextmanager
   def nop(*a,**kw):yield
   with patch.object(Path,'glob',return_value=[directory]),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
    private.return_value.pin=nop
    with self.subTest(value=value),self.assertRaises(c.DiagnosticUnavailable):
     with ExitStack() as pins:c.unknown_diagnostics(root,pins,Mock(),set(),PREP_SHA)

 def reservations(self,value,allowed=(),directories=None):
  directory=Path(c.STAGE+'/native-run-'+TOKEN)
  @contextmanager
  def nop(*a,**kw):yield
  with patch.object(Path,'glob',return_value=[directory] if directories is None else directories),   patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=nop
   with ExitStack() as pins:c.unknown_diagnostics(Path('.'),pins,Mock(),set(allowed),PREP_SHA)
 def test_missing_owner_or_purpose_denied(self):
  for key in ('org.kapit.owner','org.kapit.purpose'):
   value=c.metadata(TOKEN,'rmdir',PREP_SHA);value['expected_labels'].pop(key)
   with self.subTest(key=key),self.assertRaises(c.DiagnosticUnavailable):self.reservations(value)
 def test_valid_old_non_scratch_reservation_allowed(self):
  _,_,_,owned,_=c.modules()
  value=json.loads(Path(c.OWNED).read_text())['journals'][0]['files']['reservation.json']['document']
  value['token']=TOKEN
  value['expected_labels'].update({'org.kapit.reservation':TOKEN,'org.kapit.run':TOKEN})
  self.reservations(value)
 def test_current_scratch_requires_exact_prior_token(self):
  value=c.metadata(TOKEN,'rmdir',PREP_SHA)
  with self.assertRaises(c.DiagnosticUnavailable):self.reservations(value)
  self.reservations(value,[TOKEN])
 def test_current_lifecycle_reservation_never_adopted(self):
  with self.assertRaises(c.DiagnosticUnavailable):self.reservations(c.metadata(TOKEN,'lifecycle',PREP_SHA),[TOKEN])
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
  call=Call(created);result={'preparation_sha256':PREP_SHA};observation=SimpleNamespace(consume=lambda:events.append('fresh'))
  frame={'schema':1,'scope':'PUBLIC_SCRATCH_DIAGNOSTIC_ONLY','operation':'rmdir','completed':True,'failed_stage':'NONE',
   'observation':'REMOVED','snapshots':[],'native_eligible':False,'private_input_allowed':False}
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


class PreparationAndCorrection(unittest.TestCase):
 def test_profile_module_pin_and_exact_derived_hash(self):
  from infra import evidence_rmdir_profile as profile
  self.assertEqual(hashlib.sha256(Path(c.PROFILE_MODULE).read_bytes()).hexdigest(),c.PROFILE_MODULE_SHA256)
  self.assertEqual(profile.profile_digest(),c.NEW_PROFILE_SHA256)
 def test_unreviewed_profile_module_stops_before_receipt(self):
  with patch.object(c,'PROFILE_MODULE_SHA256',None),patch.object(current,'Receipt') as receipt:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('prepare')
  receipt.assert_not_called()
 def test_binding_is_carried_by_closed_metadata(self):
  expected=c.metadata(TOKEN,'rmdir',PREP_SHA)
  self.assertEqual(expected['profile_sha256'],c.NEW_PROFILE_SHA256)
  self.assertEqual(expected['preparation_sha256'],PREP_SHA)
  self.assertEqual(expected['expected_labels']['org.kapit.profile'],c.NEW_PROFILE_SHA256)
  self.assertEqual(expected['expected_labels']['org.kapit.preparation'],PREP_SHA)
  for value in (None,True,'x'*64,'a'*63):
   with self.assertRaises(c.DiagnosticUnavailable):c.metadata(TOKEN,'rmdir',value)
 def test_rmdir_unexpected_finite_observation_not_correction(self):
  for observation in ('EPERM','OTHER_ERRNO'):
   self.assertFalse(c.correction_observed({'observation':observation},'rmdir'))
  self.assertTrue(c.correction_observed({'observation':'REMOVED'},'rmdir'))
 def lifecycle(self):
  return {'snapshots':[{'stage':stage,'scan':'CLEAN' if stage in ('strict_png','upstream_png') else 'NONE',
   'counts':{'regular':0,'directory':0,'symlink':0,'other':0}} for stage in
   ('fresh_start','scanner_initialization','strict_png','upstream_png','engine_close')]}
 def test_lifecycle_requires_empty_at_every_stage(self):
  self.assertTrue(c.correction_observed(self.lifecycle(),'lifecycle'))
  for i in range(5):
   for kind in ('regular','directory','symlink','other'):
    value=self.lifecycle();value['snapshots'][i]['counts'][kind]=1
    self.assertFalse(c.correction_observed(value,'lifecycle'))
 def test_lifecycle_requires_both_clean_scans(self):
  for i in (2,3):
   for scan in ('ERROR','NOT_CLEAN','NONE'):
    value=self.lifecycle();value['snapshots'][i]['scan']=scan
    self.assertFalse(c.correction_observed(value,'lifecycle'))
 def test_exact_effective_new_profile_required_before_old_validator(self):
  from infra import evidence_rmdir_profile as profile
  from infra.test_evidence_native_runtime import phase,inspection
  for mode in ('scan','decode'):
   p=phase(mode);fixed=c.metadata(p.token,'rmdir',PREP_SHA)
   from dataclasses import replace
   p=replace(p,candidate=type(p.candidate)(c.IMAGE,c.GENERATION))
   probe=c.Probe(p,fixed,'fixed','rmdir');doc=inspection(p)
   doc.update(Name='/'+probe.name,Image=c.IMAGE)
   doc['Config'].update(Labels=probe.labels,Cmd=probe.command)
   doc['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode()
   before=deepcopy(doc);c.inspection(doc,probe,'e'*64)
   self.assertEqual(doc,before)
   doc['HostConfig']['SecurityOpt'][1]='seccomp=unconfined'
   with patch('infra.evidence_native_runtime.verify_inspection') as validate:
    with self.assertRaises(profile.ProfileUnavailable):c.inspection(doc,probe,'e'*64)
   validate.assert_not_called()
 def test_all_13_originals_batched_without_frozen_limit_mutation(self):
  from infra import evidence_scratch_diagnostic as frozen
  rows=[{'original_id':format(i+1,'064x'),'expected_name':'kapit-scratch-public-'+format(i+1,'032x')} for i in range(13)]
  made=[]
  def factory(*a):value=Call();made.append(value);return value
  with patch.object(c,'Commands',factory),patch.object(c,'engine') as engine:c.live_absences(Call(),rows)
  self.assertEqual([len(v.calls) for v in made],[16,10]);self.assertEqual(engine.call_count,4)
  with self.assertRaises(frozen.DiagnosticUnavailable):frozen.live_absences(Call(),rows)
 def test_14_originals_lifecycle_bound_and_over_budget(self):
  rows=[{'original_id':CID,'expected_name':'kapit-rmdir-public-'+TOKEN}]*14
  with patch.object(c,'Commands',return_value=Call()),patch.object(c,'engine'):c.live_absences(Call(),rows)
  with self.assertRaises(c.DiagnosticUnavailable):c.live_absences(Call(),rows+[rows[0]])
 def test_public_profile_pin_never_requests_private_dacl(self):
  from infra import evidence_rmdir_profile as profile
  with patch.object(current,'pin_bytes',return_value=profile.profile_bytes()) as read:
   c.profile_source(Path('.'),ExitStack(),Mock())
  self.assertEqual(read.call_args.kwargs,{'expected':c.NEW_PROFILE_SHA256})
 def test_old_and_both_scratch_receipts_pinned_then_actual_journals(self):
  from infra import evidence_scratch_diagnostic as scratch
  rows=[{'original_id':format(i+1,'064x'),'token':format(i+1,'032x')} for i in range(11)]
  extras={op:{'original_id':format(i+12,'064x'),'token':format(i+12,'032x')} for i,op in enumerate(('rmdir','lifecycle'))}
  with patch.object(c,'interpreter_original_documents',return_value=rows),patch.object(current,'pin_bytes') as read,patch.object(scratch,'provenance',side_effect=lambda *args:extras.get(args[3])) as prior:
   result=c.original_documents(Path('.'),ExitStack(),Mock())
  self.assertEqual(len(result),13);self.assertEqual(prior.call_count,3)
  self.assertEqual([call.kwargs['expected'] for call in read.call_args_list],list(c.SCRATCH_RECEIPTS.values()))
 def test_changed_prior_scratch_receipt_blocks(self):
  with patch.object(c,'interpreter_original_documents',return_value=[]),patch.object(current,'pin_bytes',side_effect=c.DiagnosticUnavailable()):
   with self.assertRaises(c.DiagnosticUnavailable):c.original_documents(Path('.'),ExitStack(),Mock())
 def test_prior_rmdir_unexpected_cannot_start_lifecycle(self):
  helper=PriorRmdirAndReservations();value,docs=helper.setup_value()
  value['measurement']['observation']='EPERM';value['correction_observed']=False
  with self.assertRaises(c.DiagnosticUnavailable):helper.check(value,docs)
 def test_prepare_provenance_requires_exact_profile_and_binding(self):
  helper=PriorProvenance()
  for key,bad in (('profile_sha256','f'*64),('profile_module_sha256','f'*64),('preparation_sha256','f'*64),('preparation',{})):
   value=helper.value();value[key]=bad
   with self.subTest(key=key),self.assertRaises(c.DiagnosticUnavailable):helper.check(value)


class ExclusiveCreation(unittest.TestCase):
 def invoke(self,kind='ok'):
  import os,tempfile
  api=Mock();record={}
  with tempfile.TemporaryDirectory() as directory:
   path=Path(directory)/'profile.json';raw=b'public-fixture'
   def create(*args):
    record['args']=args
    if kind=='invalid':return c.ctypes.c_void_p(-1).value
    return os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_BINARY,0o600)
   api.k.CreateFileW.side_effect=create
   if kind=='exists':path.write_bytes(b'existing')
   original=c.stream_identity
   identity=Mock(wraps=original)
   if kind=='identity':identity.side_effect=c.DiagnosticUnavailable()
   def query(handle,kind,pointer,size):
    observed=os.fstat(handle);value=pointer._obj;value.volume=observed.st_dev
    value.identifier[:]=observed.st_ino.to_bytes(16,'little');return True
   api.k.GetFileInformationByHandleEx.side_effect=query
   with patch('infra.evidence_tools.checked',side_effect=lambda x:x),patch('infra.evidence_postcompile_continuation.lock_runtime',return_value=SimpleNamespace(open_osfhandle=lambda handle,flags:handle,get_osfhandle=lambda fd:fd)),patch.object(c,'stream_identity',identity):
    if kind=='ok':
     result=c.create_profile(path,api,raw)
     self.assertEqual(path.read_bytes(),raw);self.assertEqual(result,c.entry_identity(path))
    else:
     with self.assertRaises(c.DiagnosticUnavailable):c.create_profile(path,api,raw)
   if kind=='exists':self.assertEqual(path.read_bytes(),b'existing')
  return api,record
 def test_create_uses_create_new_no_descriptor_original_handle(self):
  api,record=self.invoke();args=record['args']
  self.assertEqual(args[2],1);self.assertIsNone(args[3]);self.assertEqual(args[4],1)
  api.protect.assert_not_called();api.verify_acl.assert_not_called()
 def test_existing_never_overwritten(self):
  api,_=self.invoke('exists');api.k.CreateFileW.assert_not_called()
 def test_create_failure_refuses(self):self.invoke('invalid')
 def test_same_created_handle_identity_uncertainty_refuses(self):self.invoke('identity')
 def test_prepare_refuses_existing_profile_or_lock_before_create(self):
  import tempfile
  for target in (c.PROFILE,c.DEDICATED_LOCK):
   with tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary);path=root/target;path.parent.mkdir(parents=True);path.write_bytes(b'old')
    with patch.object(c,'create_profile') as create:
     with self.assertRaises(c.DiagnosticUnavailable):c.prepare_objects(root,ExitStack(),Mock())
    create.assert_not_called();self.assertEqual(path.read_bytes(),b'old')
 def test_prepare_lock_requires_new_creation(self):
  import tempfile
  @contextmanager
  def existing(*a):yield False
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);(root/c.STAGE).mkdir(parents=True)
   with patch('infra.evidence_tools.checked',side_effect=lambda x:x),patch.object(c,'create_profile',return_value={'volume':'1','file_id':'2'}),patch('infra.evidence_postcompile_continuation.atomic_private_lock',existing):
    with self.assertRaises(c.DiagnosticUnavailable):c.prepare_objects(root,ExitStack(),Mock())
 def test_profile_close_failure_not_accepted(self):
  import tempfile
  path=Path('synthetic');stream=Mock();stream.write.return_value=3;stream.read.return_value=b'abc';stream.close.side_effect=RuntimeError('SYNTHETIC')
  api=Mock();api.k.CreateFileW.return_value=50
  with patch.object(Path,'exists',return_value=False),patch.object(Path,'is_symlink',return_value=False),patch('infra.evidence_tools.checked',side_effect=lambda x:x),patch('infra.evidence_postcompile_continuation.lock_runtime',return_value=SimpleNamespace(open_osfhandle=lambda *a:51)),patch.object(c.os,'fdopen',return_value=stream),patch.object(c.os,'fsync'),patch.object(c,'stream_identity',return_value={'volume':'1','file_id':'2'}):
   with self.assertRaises(RuntimeError):c.create_profile(path,api,b'abc')
 def test_later_existing_lock_never_recreated(self):
  api=Mock();api.pin.side_effect=FileNotFoundError()
  record={'schema':1,'profile_path':c.PROFILE,'profile_sha256':c.NEW_PROFILE_SHA256,'profile_bytes':2384,
   'profile_identity':{},'lock_path':c.DEDICATED_LOCK,'lock_identity':{},'parent_identity':{},'profile_module_sha256':c.PROFILE_MODULE_SHA256}
  with patch.object(c,'profile_source'),patch('infra.evidence_postcompile_continuation.atomic_private_lock') as create:
   with self.assertRaises(FileNotFoundError):c.prepared_objects(Path('.'),ExitStack(),api,record)
  create.assert_not_called()

 def test_profile_creation_shortwrite_fsync_transfer_close_and_retained_identity_failures(self):
  import os,tempfile
  for kind in ('shortwrite','fsync','transfer','close','entry'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temporary:
    path=Path(temporary)/'profile';api=Mock();owned=[]
    def create(*a):
     fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_BINARY,0o600);owned.append(fd);return fd
    api.k.CreateFileW.side_effect=create
    api.k.CloseHandle.side_effect=lambda fd:(os.close(fd) or True)
    def transfer(fd,flags):
     if kind=='transfer':raise OSError('SYNTHETIC')
     return fd
    original_fdopen=os.fdopen
    class Stream:
     def __init__(self,fd):self.stream=original_fdopen(fd,'r+b',buffering=0)
     def __getattr__(self,name):return getattr(self.stream,name)
     def write(self,raw):
      result=self.stream.write(raw);return result-1 if kind=='shortwrite' else result
     def close(self):
      self.stream.close()
      if kind=='close':raise OSError('SYNTHETIC')
    actual_identity={'volume':'1','file_id':'2'}
    with patch('infra.evidence_tools.checked',side_effect=lambda x:x),patch('infra.evidence_postcompile_continuation.lock_runtime',return_value=SimpleNamespace(open_osfhandle=transfer)),patch.object(c.os,'fdopen',side_effect=lambda fd,*a,**kw:Stream(fd)),patch.object(c.os,'fsync',side_effect=OSError('SYNTHETIC') if kind=='fsync' else None),patch.object(c,'stream_identity',return_value=actual_identity),patch.object(c,'entry_identity',return_value={'volume':'1','file_id':'3'} if kind=='entry' else actual_identity):
     with self.assertRaises((c.DiagnosticUnavailable,OSError)):c.create_profile(path,api,b'abc')
    for fd in owned:
     with self.assertRaises(OSError):os.fstat(fd)


class AllOriginalJournalReplay(unittest.TestCase):
 def test_reconstructs_all_52_actual_canonical_journals_without_protected_io(self):
  from infra import evidence_scratch_diagnostic as scratch
  _,_,_,owned,_=c.modules()
  binding=json.loads(Path(c.OWNED).read_text())
  receipts={op:Path(scratch.receipt_path(op)).read_bytes() for op in ('preflight','rmdir','lifecycle')}
  rows=binding['journals']+[json.loads(receipts[op])['original_journal'] for op in ('rmdir','lifecycle')]
  documents={row['directory']+'/'+name:owned._canonical(info['document']) for row in rows for name,info in row['files'].items()}
  reads=[]
  def read(root,pins,api,path,**kw):
   if path in documents:raw=documents[path];reads.append(path)
   elif path in (c.OWNED,c.FAILED,'infra/evidence_scratch_diagnostic.py'):raw=Path(path).read_bytes()
   else:raw=receipts[next(op for op in receipts if path==scratch.receipt_path(op))]
   if 'expected' in kw:self.assertEqual(hashlib.sha256(raw).hexdigest(),kw['expected'])
   return raw
  @contextmanager
  def no_pin(*a,**kw):yield
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:actual=c.original_documents(Path('.'),pins,Mock())
  self.assertEqual(len(actual),13);self.assertEqual(len(reads),52)
  self.assertEqual(len(set(reads)),52)
  self.assertTrue(all(len(row['files'])==4 for row in actual))


class PreparationExecution(unittest.TestCase):
 setUp=FakeExecute.setUp
 patch=FakeExecute.patch
 run_fake=FakeExecute.run_fake
 def test_prepare_has_no_image_or_container_work(self):
  with patch.object(c,'run_probe') as probe,patch.object(current,'verified_image') as image,patch.object(c,'oci_bytes') as oci:
   value=c.execute('prepare')
  probe.assert_not_called();image.assert_not_called();oci.assert_not_called();self.lock.assert_not_called()
  self.assertEqual(value['status'],'PREPARED');self.assertTrue(value['control_state_modified'])
  self.assertEqual(value['completed_stages'],c.expected_stages('prepare'))
 def test_preparation_failure_no_probe_or_recreation(self):
  self.patch(c,'accepted_preparation',Mock(side_effect=c.DiagnosticUnavailable()))
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called();self.lock.assert_not_called()
  self.assertEqual(self.receipts[-1].values[-1]['failed_stage'],'PREPARATION_PROVENANCE')
 def test_unexpected_finite_measurement_preserved_without_correction(self):
  def probe(*args):
   args[5].update(reservation=TOKEN,original_id=CID,cleanup='ORIGINAL_ID_ABSENT_VERIFIED')
   return {'completed':True,'observation':'EPERM'}
  self.patch(c,'run_probe',probe);value=c.execute('rmdir')
  self.assertTrue(value['completed']);self.assertFalse(value['correction_observed'])
  self.assertEqual(value['measurement']['observation'],'EPERM')
 def test_recreated_dedicated_lock_refuses_before_gates(self):
  @contextmanager
  def created(*a):yield True
  self.lock.side_effect=created
  with patch.object(c,'run_probe') as probe:
   with self.assertRaises(c.DiagnosticUnavailable):c.execute('rmdir')
  probe.assert_not_called();self.assertEqual(self.receipts[-1].values[-1]['failed_stage'],'DEDICATED_LOCK')


class FullIdentityABI(unittest.TestCase):
 def identity(self,kind='ok'):
  import stat
  volume=0xfedcba9876543210;identifier=0xfedcba98765432100123456789abcdef
  observed=SimpleNamespace(st_dev=volume,st_ino=identifier,st_size=2384,st_nlink=1,st_mode=stat.S_IFREG)
  # Deliberately different fstat legacy identity cannot truncate full FileIdInfo.
  fstat=SimpleNamespace(st_dev=0x76543210,st_ino=0x89abcdef,st_size=2384,st_nlink=1,st_mode=stat.S_IFREG)
  path=Mock();path.stat.return_value=observed;api=Mock();stream=Mock();stream.fileno.return_value=51
  def query(handle,info,pointer,size):
   self.assertEqual((handle,info,size),(987,18,24));value=pointer._obj
   value.volume=volume if kind!='volume' else volume&0xffffffff
   value.identifier[:]=(identifier if kind!='identifier' else identifier&0xffffffffffffffff).to_bytes(16,'little')
   return kind!='query'
  api.k.GetFileInformationByHandleEx.side_effect=query
  with patch('infra.evidence_tools.checked',return_value=path),patch.object(c.os,'fstat',return_value=fstat),patch('infra.evidence_postcompile_continuation.lock_runtime',return_value=SimpleNamespace(get_osfhandle=lambda fd:987)):
   if kind=='ok':return c.stream_identity(stream,path,api),volume,identifier
   with self.assertRaises(c.DiagnosticUnavailable):c.stream_identity(stream,path,api)
 def test_full_64bit_volume_and_128bit_identifier_not_legacy_truncated(self):
  actual,volume,identifier=self.identity()
  self.assertEqual(actual,{'volume':str(volume),'file_id':str(identifier)})
 def test_truncated_volume_refuses(self):self.identity('volume')
 def test_truncated_identifier_refuses(self):self.identity('identifier')
 def test_query_failure_refuses(self):self.identity('query')
 def test_cli_unexpected_finite_observation_exits_two(self):
  value={'status':'OBSERVED','stage':'rmdir','correction_observed':False}
  parser=Mock();parser.parse_args.return_value=SimpleNamespace(operation='rmdir')
  with patch.object(c.argparse,'ArgumentParser',return_value=parser),patch.object(c,'execute',return_value=value),patch('builtins.print') as output:
   with self.assertRaises(SystemExit) as error:c.main()
  self.assertEqual(error.exception.code,2);output.assert_called_once()
 def test_cli_expected_correction_has_zero_exit(self):
  value={'status':'OBSERVED','stage':'rmdir','correction_observed':True}
  parser=Mock();parser.parse_args.return_value=SimpleNamespace(operation='rmdir')
  with patch.object(c.argparse,'ArgumentParser',return_value=parser),patch.object(c,'execute',return_value=value),patch('builtins.print'):c.main()


if __name__=='__main__':unittest.main()


