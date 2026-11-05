"""Fixed public corrected-profile matrices; import is inert, root executes CLI.

No private input, issuer/key activation, policy/provider override or retry API.
The sealed context is an internal source-bound bridge, not saved clearance.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack,contextmanager
from dataclasses import dataclass,asdict
from copy import deepcopy
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import shutil
import time

ROOT=Path(__file__).resolve().parents[1]
PREFIX='ai/state/private-scanner-rmdir-proof-'
SCOPE='PUBLIC_CORRECTED_RMDIR_FULL_MATRIX_ONLY'
NATIVE='infra/evidence_rmdir_native.py'
NATIVE_SHA256='8c45db9e71e67656bdb20fb47c008d4c9419c7664e40010ef2adbbc5fc5deed0'
CONTRACT='062dd3e446b62e52bef1ee04d630db0441dd1360e46d4751807747f5e7bcdf7f'
STAGES=('preflight','confinement','strict','pcre','fixtures')
LIMITS={'preflight':300,'confinement':900,'strict':300,'pcre':300,'fixtures':900}
SCENARIOS=('confinement','preopened_fd','shm_namespace','storage','x32')
FIXTURES=('png_clean','png_metadata','jpeg_clean','jpeg_metadata','png_malformed','png_eicar')
PHASES=tuple('confinement:'+mode+':'+scenario for mode in ('scan','decode') for scenario in SCENARIOS)+(
 'strict:scan:strict','pcre:scan:pcre')+tuple('fixture:'+fixture+':'+phase for fixture in FIXTURES
 for phase in (('original','decode','derivative') if fixture in FIXTURES[:4] else ('original',)))
END={'preflight':0,'confinement':10,'strict':11,'pcre':12,'fixtures':26}
PREREQUISITES={stage:STAGES[:index] for index,stage in enumerate(STAGES)}
RMDIR_RECEIPTS={
 'prepare':'6794cfea93e71d39b4df6610be73f2a838f165350e8f61c94dff39fac98d184c',
 'preflight':'b2188bdb777b3cbd151200bd5935959333f6d8de8eb0447c196e6e39cfb5f1b6',
 'rmdir':'2d30584ea4a7fc6ead0ef97d6af6ec1d3e25d5de50835e8b57c4ef27dcc36a66',
 'lifecycle':'daebe1ab66825446eb7eef4dee6e67eedf2327fb1531b3f4824967087e947ba0'}
PREPARATION_SHA256='098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f'
SOURCE_PINS={
 'infra/evidence_rmdir_diagnostic.py':'488c2b810b14e76f90ca5a1bf77e2599511d38cdcee51537d01908a0277b174f',
 'infra/evidence_rmdir_profile.py':'73300666b534c7fe1d36140ea7d28464c2ececaf1ab520f2c7afa483c4ecbbfc',
 'infra/evidence_native_fixtures.py':'05ca32ff7d44a97953eeeadfcd81b26671dd19a2702c9448cdb9f1f911098408',
 'infra/evidence_native_refresh.py':'15c4852888eb369d9b61a46516ced9b14813994fd76fd2cf20b325d00818bfc3',
 'backend/apps/operations/evidence_scan_protocol.py':'a7b277e7697e59e41b95014499f56276cde55af710b8065cb213fca0e5295973',
 'backend/apps/operations/evidence_protocol.py':'c4df88f7f2c0da2fd9307ec1b1330f08e37454089f5e906f3073fdc3429f5d9d',
 'backend/apps/operations/evidence_policy.py':'753d77708453eca0cfe9c4ea8eeccfdd9cc075c508db50521231f9bda478626b'}
_SEAL=object()

class ProofUnavailable(RuntimeError):
 def __init__(self,code='RMDIR_PROOF_REFUSED'):
  self.code=code;super().__init__(code)

def require(value,code='RMDIR_PROOF_REFUSED'):
 if value is not True:raise ProofUnavailable(code)

def modules():
 from infra import evidence_rmdir_diagnostic as diagnostic
 from infra import evidence_interpreter_runtime as current
 return diagnostic,current,None

def _native():
 from infra import evidence_rmdir_native as native
 return native

def reviewed_constants():
 require(type(NATIVE_SHA256) is str and re.fullmatch('[0-9a-f]{64}',NATIVE_SHA256) is not None,
  'NATIVE_SOURCE_NOT_REVIEWED')

def stage_phases(stage):
 require(type(stage) is str and stage in STAGES)
 start=0 if stage in ('preflight','confinement') else END[STAGES[STAGES.index(stage)-1]]
 return PHASES[start:END[stage]]

def receipt_path(stage):
 require(type(stage) is str and stage in STAGES)
 return PREFIX+stage+'.json'

def digest(raw):return hashlib.sha256(raw).hexdigest()

@dataclass(frozen=True,slots=True)
class _Binding:
 image_id:str
 signature_generation:str
 profile_sha256:str
 preparation_sha256:str
 native_sha256:str
 controller_sha256:str
 contract:str

def binding(controller_sha256):
 diagnostic,_,_=modules()
 reviewed_constants()
 require(type(controller_sha256) is str and re.fullmatch('[0-9a-f]{64}',controller_sha256) is not None)
 return _Binding(diagnostic.IMAGE,diagnostic.GENERATION,diagnostic.NEW_PROFILE_SHA256,
  PREPARATION_SHA256,NATIVE_SHA256,controller_sha256,CONTRACT)

def receipt_set(root,current_stage):
 paths=list(islice((root/'ai/state').glob('private-scanner-rmdir-proof-*.json'),7))
 allowed={Path(receipt_path(stage)).name for stage in STAGES[:STAGES.index(current_stage)+1]}
 require(len(paths)<=len(allowed) and all(path.name in allowed for path in paths),'UNKNOWN_PROOF_RECEIPT')

def pin_sources(root,pins,api,expected_binding):
 diagnostic,current,_=modules()
 require(type(expected_binding) is _Binding and expected_binding==binding(expected_binding.controller_sha256))
 raw=current.pin_bytes(root,pins,api,'infra/evidence_rmdir_proof.py',expected=expected_binding.controller_sha256)
 require(digest(raw)==expected_binding.controller_sha256)
 for path,expected in {**diagnostic.SOURCE_PINS,**SOURCE_PINS,NATIVE:NATIVE_SHA256}.items():
  current.pin_bytes(root,pins,api,path,expected=expected)
 # These retained public programs/helpers are never supplied by the caller.
 from infra import evidence_native_attestation as attestation
 for path,expected in attestation.PINS:
  current.pin_bytes(root,pins,api,Path(path).relative_to(root).as_posix(),expected=expected,maximum=262144)

def corrected_provenance(root,pins,api,lock_stream=None):
 diagnostic,current,_=modules()
 for stage,expected in RMDIR_RECEIPTS.items():
  current.pin_bytes(root,pins,api,diagnostic.receipt_path(stage),expected=expected)
 if lock_stream is None:prepared=diagnostic.accepted_preparation(root,pins,api)
 else:
  from infra.evidence_postcompile_continuation import exact_lock
  value=current.document(current.pin_bytes(root,pins,api,diagnostic.receipt_path('prepare')))
  prepared=value.get('preparation')
  diagnostic.provenance(root,pins,api,'prepare',prepared)
  diagnostic.profile_source(root,pins,api)
  exact_lock(lock_stream,root/diagnostic.DEDICATED_LOCK)
  observed=diagnostic.preparation_record(root,diagnostic.entry_identity(root/diagnostic.PROFILE),
   diagnostic.stream_identity(lock_stream,root/diagnostic.DEDICATED_LOCK,api))
  require(prepared==observed,'PREPARATION_CHANGED')
 diagnostic.old_profile_source(root,pins,api)
 require(diagnostic.binding_digest(prepared)==PREPARATION_SHA256,'PREPARATION_CHANGED')
 for stage in ('preflight','rmdir','lifecycle'):diagnostic.provenance(root,pins,api,stage,prepared)
 return prepared

def historical_originals(root,pins,api,prepared):
 diagnostic,_,_=modules()
 rows=diagnostic.original_documents(root,pins,api)
 rows += [diagnostic.provenance(root,pins,api,stage,prepared) for stage in ('rmdir','lifecycle')]
 require(len(rows)==15 and len({row['token'] for row in rows})==15 and
  len({row['original_id'] for row in rows})==15,'HISTORICAL_ORIGINALS_CHANGED')
 return rows

def absence(call,selector):
 diagnostic,_,_=modules()
 require(type(selector) is str and (re.fullmatch('[0-9a-f]{64}',selector) is not None or
  re.fullmatch('kapit-(?:same-image|scratch|rmdir|rmdir-proof)-public-[0-9a-f]{32}',selector) is not None))
 code,out,err,reason=call('container','inspect',selector)
 require(type(code) is int and code==1 and reason=='EXIT' and out in (b'[]',b'[]\n',b'[]\r\n') and
  err in tuple(('Error response from daemon: No such container: '+selector+end).encode('ascii')
   for end in ('','\n','\r\n')),'ORIGINAL_ABSENCE_UNCONFIRMED')

def live_absences(call,rows):
 diagnostic,_,_=modules()
 require(type(rows) is list and 1<=len(rows)<=64)
 require(len({row['original_id'] for row in rows})==len(rows) and len({row['token'] for row in rows})==len(rows))
 for offset in range(0,len(rows),8):
  batch=diagnostic.Commands(call.docker,call.config);started=time.monotonic()
  diagnostic.engine(batch)
  for row in rows[offset:offset+8]:absence(batch,row['original_id']);absence(batch,row['expected_name'])
  diagnostic.engine(batch)
  require(not batch.uncertain and time.monotonic()-started<300)

def validate_manifest(rows,expected,expected_binding):
 _,_,_=modules();native=_native()
 require(type(rows) is list and len(rows)==len(expected) and len(rows)<=26,'MANIFEST_COUNT_CHANGED')
 tokens=set();cids=set()
 for row,phase in zip(rows,expected):
  require(type(row) is dict and set(row)=={'phase_id','outcome','journal'} and row['phase_id']==phase,'MANIFEST_ORDER_CHANGED')
  outcome=native.validate_outcome(phase,row['outcome'])
  require(outcome==row['outcome'] and outcome.get('passed') is True,'PHASE_NOT_PASSED')
  journal=row['journal']
  require(type(journal) is dict and type(journal.get('token')) is str and type(journal.get('original_id')) is str)
  fixed=native.metadata(journal['token'],phase,expected_binding)
  require(journal.get('expected_name')==fixed['expected_name'] and
   journal.get('original_cid_and_name_absent_live') is True and type(journal.get('files')) is dict and
   set(journal['files'])=={'reservation.json','create-attempt.json','ownership.json','result.json'})
  require(journal['token'] not in tokens and journal['original_id'] not in cids,'MANIFEST_DUPLICATE')
  tokens.add(journal['token']);cids.add(journal['original_id'])
 return rows

def replay_proof_originals(root,pins,api,rows,expected_binding):
 diagnostic,_,_=modules();native=_native()
 validate_manifest(rows,PHASES[:len(rows)],expected_binding)
 result=[]
 for row in rows:
  saved=row['journal'];fixed=native.metadata(saved['token'],row['phase_id'],expected_binding)
  actual=diagnostic.journal_documents(root,pins,api,saved['token'],fixed,saved['original_id'],saved['files'])
  require(saved==dict(actual,original_cid_and_name_absent_live=True),'PROOF_JOURNAL_CHANGED')
  result.append(actual)
 return result

def capture_failed_original(root,pins,api,phase,token,cid,expected_binding):
 """Copy available closed canonical facts after uncertainty; never clearance."""
 diagnostic,current,_=modules();native=_native()
 from infra.live_recovery_drill import PrivateDirectory
 fixed=native.metadata(token,phase,expected_binding)
 directory=diagnostic.STAGE+'/native-run-'+token
 result={'directory':directory,'token':token,'original_id':cid,'expected_name':fixed['expected_name'],
  'files':{},'unconfirmed_documents':[],'original_cid_and_name_absent_live':False}
 names=('reservation.json','create-attempt.json','ownership.json','result.json')
 try:pins.enter_context(PrivateDirectory().pin(root/directory,private=True,directory=True))
 except BaseException:
  result['unconfirmed_documents']=list(names);return result
 for name in names:
  try:
   raw=current.pin_bytes(root,pins,api,directory+'/'+name,private=True,maximum=8192)
   value=current.document(raw)
   if name=='reservation.json':expected=fixed
   elif name=='create-attempt.json':expected={'schema':1,'token':token,'create_attempted':True,'native_eligible':False}
   elif name=='ownership.json':expected=dict(fixed,original_id=cid)
   else:
    from infra import evidence_native_ownership as owned
    require(value.get('ownership_status') in owned.STATUSES and value.get('original_id') in (None,cid))
    expected={'schema':1,'token':token,'original_id':value['original_id'],
     'ownership_status':value['ownership_status'],'native_eligible':False}
   require(value==expected and raw==diagnostic.modules()[3]._canonical(expected))
   result['files'][name]={'bytes':len(raw),'sha256':digest(raw),'document':value}
  except BaseException:result['unconfirmed_documents'].append(name)
 return result

def prior_stage(root,pins,api,stage,expected_binding):
 _,current,_=modules();native=_native()
 value=current.document(current.pin_bytes(root,pins,api,receipt_path(stage),maximum=262144))
 require(type(value) is dict and set(value)=={'schema','scope','stage','status','completed','native_eligible',
  'private_input_allowed','control_state_modified','pins_closed','cli_cleanup_confirmed','binding',
  'completed_stages','phase_originals','completed_manifest','results','total_seconds'},'PRIOR_SCHEMA_CHANGED')
 require(type(value['schema']) is int and value['schema']==1 and value['scope']==SCOPE and value['stage']==stage and
  value['status']=='VERIFIED' and value['completed'] is True and value['native_eligible'] is False and
  value['private_input_allowed'] is False and value['control_state_modified'] is False and
  value['pins_closed'] is True and value['cli_cleanup_confirmed'] is True and value['binding']==asdict(expected_binding) and
  value['completed_stages']==expected_stages(stage) and value['completed_manifest']==list(PHASES[:END[stage]]) and
  type(value['total_seconds']) in (int,float) and 0<=value['total_seconds']<LIMITS[stage],'PRIOR_STAGE_UNCONFIRMED')
 validate_manifest(value['phase_originals'],PHASES[:END[stage]],expected_binding)
 if stage=='preflight':require(value['results']=={})
 else:require(native.validate_result(stage,value['results'])==value['results'])
 replay_proof_originals(root,pins,api,value['phase_originals'],expected_binding)
 return value

def prior_stages(root,pins,api,stage,expected_binding):
 rows=[]
 for earlier in PREREQUISITES[stage]:
  value=prior_stage(root,pins,api,earlier,expected_binding)
  require(value['phase_originals'][:len(rows)]==rows,'PRIOR_PREFIX_CHANGED')
  rows=value['phase_originals']
 return deepcopy(rows)

def unknown_reservations(root,pins,api,rows,expected_binding):
 diagnostic,current,_=modules();native=_native()
 from infra.live_recovery_drill import PrivateDirectory
 allowed={row['journal']['token']:native.metadata(row['journal']['token'],row['phase_id'],expected_binding) for row in rows}
 directories=list(islice((root/diagnostic.STAGE).glob('native-run-*'),257))
 require(len(directories)<=256,'RESERVATION_BUDGET')
 for directory in directories:
  require(re.fullmatch('native-run-[0-9a-f]{32}',directory.name) is not None,'UNKNOWN_RESERVATION')
  pins.enter_context(PrivateDirectory().pin(directory,private=True,directory=True))
  raw=current.pin_bytes(root,pins,api,(directory/'reservation.json').relative_to(root).as_posix(),private=True,maximum=8192)
  value=current.document(raw);labels=value.get('expected_labels')
  require(type(value.get('schema')) is int and value['schema']==1 and value.get('token')==directory.name[11:] and
   type(value.get('image_id')) is str and re.fullmatch('sha256:[0-9a-f]{64}',value['image_id']) is not None and
   type(value.get('signature_generation')) is str and re.fullmatch('[0-9a-f]{64}',value['signature_generation']) is not None and
   value.get('native_eligible') is False and type(value.get('purpose')) is str and bool(value['purpose']) and
   type(labels) is dict and all(type(k) is str and type(v) is str for k,v in labels.items()) and
   bool(labels.get('org.kapit.owner')) and bool(labels.get('org.kapit.purpose')) and
   labels.get('org.kapit.reservation')==value['token'],'UNKNOWN_RESERVATION')
  if labels['org.kapit.owner']==native.OWNER or value['purpose'].startswith('public-rmdir-proof-'):
   require(value['token'] in allowed and value==allowed[value['token']],'UNKNOWN_PROOF_RESERVATION')

def expected_stages(stage):
 return ['INPUTS','PRIOR_STAGES','EXISTING_LOCK','FRESH_PREFLIGHT' if stage=='preflight' else 'PUBLIC_MATRIX',
  'FINAL_RESOURCES','LOCK_CLOSE','INPUT_CLOSE','FINAL_CLI']


class _ExecutionContext:
 """Private fixed-method context. No mutable policy/provider/callback fields."""
 __slots__=('_seal','_binding','_api','_pins','_oldcall','_receipt','_result','_stage','_prepared',
  '_call','_observation','_active_phase','_active_token','_phase_pins','_deadline','_closed','_lock_stream',
  '_returned_cid','_cleanup_call','_cleanup_count')
 def __init__(self,seal,api,pins,oldcall,receipt,result,stage,prepared,expected_binding,lock_stream):
  require(seal is _SEAL and type(expected_binding) is _Binding and expected_binding==binding(expected_binding.controller_sha256))
  require(stage in STAGES and type(result) is dict and result['binding']==asdict(expected_binding))
  self._seal=seal;self._binding=expected_binding;self._api=api;self._pins=pins;self._oldcall=oldcall
  self._receipt=receipt;self._result=result;self._stage=stage;self._prepared=deepcopy(prepared)
  self._call=None;self._observation=None;self._active_phase=None;self._active_token=None;self._phase_pins=None
  self._deadline=time.monotonic()+LIMITS[stage];self._closed=False
  self._lock_stream=lock_stream
  self._returned_cid=None;self._cleanup_call=None;self._cleanup_count=0
 @property
 def root(self):return ROOT
 @property
 def profile(self):return ROOT/modules()[0].PROFILE
 @property
 def binding(self):return self._binding
 @property
 def api(self):return self._api
 @property
 def pins(self):return self._phase_pins if self._phase_pins is not None else self._pins
 @property
 def docker(self):return self._oldcall.docker
 @property
 def config(self):return self._oldcall.config
 @property
 def stage(self):return self._stage
 @property
 def call_uncertain(self):
  return bool((self._call is not None and self._call.uncertain) or
   (self._cleanup_call is not None and self._cleanup_call.uncertain))
 def _save(self):self._receipt.save(self._result)
 def _limits(self):
  require(not self._closed and time.monotonic()<self._deadline,'STAGE_DEADLINE')
  require(shutil.disk_usage(ROOT).free>=modules()[0].FLOOR,'LOW_SPACE')
  require(self._call is None or not self._call.uncertain,'CLI_UNCERTAIN')
 def command(self,*args,timeout=15):
  self._limits();require(self._call is not None)
  return self._call(*args,timeout=timeout)
 def cleanup_command(self,*args,timeout=15):
  diagnostic,_,native=modules();native=_native()
  require(self._active_phase is not None and self._active_token is not None)
  name=native.metadata(self._active_token,self._active_phase,self.binding)['expected_name']
  cid=self._returned_cid
  allowed=[('container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}')]
  if cid is not None:allowed += [('container','inspect',cid),('container','kill','--signal','KILL',cid),
   ('container','rm',cid),('container','ls','--all','--no-trunc','--filter','id='+cid,'--format','{{.ID}}')]
  require(args in allowed and self._cleanup_count<8,'CLEANUP_COMMAND_REFUSED')
  if self._cleanup_call is None:self._cleanup_call=diagnostic.Commands(self.docker,self.config)
  self._cleanup_count+=1
  return self._cleanup_call(*args,timeout=timeout)
 def _fresh(self):
  diagnostic,current,_=modules();self._limits()
  require(self._phase_pins is None)
  stack=ExitStack();self._phase_pins=stack
  try:
   pin_sources(ROOT,stack,self._api,self._binding)
   prepared=corrected_provenance(ROOT,stack,self._api,self._lock_stream)
   require(prepared==self._prepared,'PREPARATION_CHANGED')
   actual=current.verified_image(ROOT,stack,self._api)
   require(actual.get('image_id')==self.binding.image_id and actual.get('signature_generation')==self.binding.signature_generation)
   diagnostic.oci_bytes(ROOT,stack,self._api,actual)
   rows=list(historical_originals(ROOT,stack,self._api,prepared))
   rows+=replay_proof_originals(ROOT,stack,self._api,self._result['phase_originals'],self._binding)
   require(len(rows)==15+len(self._result['completed_manifest']) and len(rows)<=41,'MANIFEST_COUNT_CHANGED')
   unknown_reservations(ROOT,stack,self._api,self._result['phase_originals'],self._binding)
   self._call=diagnostic.Commands(self.docker,self.config)
   diagnostic.modules()[1]._require_cgroup_v2(self._call);self._limits()
   from infra import evidence_interpreter_compile as compiler
   legacy=diagnostic.Commands(self.docker,self.config)
   compiler.live_originals(legacy).consume()
   require(not legacy.uncertain)
   live_absences(self._call,rows)
   require(not self._call.uncertain)
   self._observation=diagnostic.Observation(diagnostic._LIVE_SEAL,time.monotonic())
  except BaseException:
   self._phase_pins=None;stack.close();raise
 def before_phase(self,phase_id,token):
  _validate_context(self,self._stage);self._limits()
  require(self._active_phase is None and self._observation is None,'PHASE_ALREADY_ACTIVE')
  completed=self._result['completed_manifest'];validate_manifest(self._result['phase_originals'],PHASES[:len(completed)],self.binding)
  require(completed==list(PHASES[:len(completed)]) and len(completed)<END[self._stage] and
   phase_id==PHASES[len(completed)] and phase_id in stage_phases(self._stage),'PHASE_ORDER_CHANGED')
  require(type(token) is str and re.fullmatch('[0-9a-f]{32}',token) is not None and
   token not in {row['journal']['token'] for row in self._result['phase_originals']})
  self._active_phase=phase_id;self._active_token=token
  self._returned_cid=None;self._cleanup_call=None;self._cleanup_count=0
  self._result.update(active_case=self._stage,active_phase=phase_id,active_token=token)
  self._save();self._fresh()
  print(json.dumps({'event':'START_PUBLIC_PHASE','stage':self._stage,'phase':phase_id}),flush=True)
 def consume_before_create(self,phase_id):
  self._limits();require(phase_id==self._active_phase and self._observation is not None)
  self._observation.consume()
 def retain_original(self,phase_id,token,cid):
  require(phase_id==self._active_phase and token==self._active_token and
   type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid) is not None and cid!='0'*64)
  require(self._returned_cid in (None,cid),'ORIGINAL_ID_CHANGED')
  require(cid not in {row['journal']['original_id'] for row in self._result['phase_originals']})
  self._returned_cid=cid
 def record_original(self,phase_id,token,cid):
  self._limits();self.retain_original(phase_id,token,cid)
  self._result['active_original_id']=cid;self._save()
 def finish_phase(self,phase_id,token,cid,cleanup,outcome):
  diagnostic,_,_=modules();native=_native()
  require(phase_id==self._active_phase and token==self._active_token and self._phase_pins is not None)
  primary=None;accepted=False
  try:
   require(cleanup=='ORIGINAL_ID_ABSENT_VERIFIED' and self._result.get('active_original_id')==cid,'PHASE_CLEANUP_UNCONFIRMED')
   fixed=native.metadata(token,phase_id,self.binding)
   journal=diagnostic.journal_documents(ROOT,self._phase_pins,self._api,token,fixed,cid)
   live_absences(self._call,[journal]);journal['original_cid_and_name_absent_live']=True
   checked=None if outcome is None else native.validate_outcome(phase_id,outcome)
   row={'phase_id':phase_id,'outcome':checked,'journal':journal}
   self._result['phase_originals'].append(row);self._save()
   diagnostic.engine(self._call)
   require(not self.call_uncertain)
   accepted=checked is not None and checked.get('passed') is True
   if accepted:self._limits()
  except BaseException as error:
   primary=error
   # Even uncertain journal/status paths retain every available closed fact.
   # Missing/changed documents remain explicit; none are synthesized/adopted.
   try:
    failed=capture_failed_original(ROOT,self._phase_pins,self._api,phase_id,token,cid,self.binding)
    if type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid) is not None:
     try:
      live_absences(self._call,[failed]);failed['original_cid_and_name_absent_live']=True
     except BaseException:pass
    self._result['failed_original']=failed;self._save()
   except BaseException:primary=ProofUnavailable('FAILED_ORIGINAL_CAPTURE_UNCONFIRMED')
  finally:
   try:self._phase_pins.close()
   except BaseException:primary=ProofUnavailable('PHASE_PIN_CLOSE_UNCONFIRMED');accepted=False
   self._phase_pins=None
  if primary is not None:raise primary
  if not accepted:return False
  self._result['completed_manifest'].append(phase_id)
  self._result.pop('active_original_id',None);self._result.pop('active_token',None)
  self._save();self._active_phase=None;self._active_token=None;self._observation=None
  print(json.dumps({'event':'DONE_PUBLIC_PHASE','stage':self._stage,'phase':phase_id}),flush=True)
  return True
 def preflight(self):
  require(self._stage=='preflight');self._fresh();self._observation.consume()
  self._phase_pins.close();self._phase_pins=None;self._observation=None
 def close(self):
  self._closed=True
  if self._phase_pins is not None:
   stack=self._phase_pins;self._phase_pins=None;stack.close()

def _validate_context(context,stage):
 require(type(context) is _ExecutionContext and context._seal is _SEAL and not context._closed and
  type(context._binding) is _Binding and context._binding==binding(context._binding.controller_sha256) and
  context.stage==stage and stage in STAGES and stage!='preflight','CONTEXT_REFUSED')
 return context

@contextmanager
def existing_proof_lock(api,pins,prepared):
 diagnostic,_,_=modules()
 from infra.evidence_postcompile_continuation import exact_lock,lock_runtime
 runtime=lock_runtime();path=ROOT/diagnostic.DEDICATED_LOCK
 # No create branch. Every byte read and identity check uses this same handle.
 with api.pin(path,private=True,writable=True) as stream:
  exact_lock(stream,path)
  require(diagnostic.stream_identity(stream,path,api)==prepared['lock_identity'],'LOCK_CHANGED')
  stream.seek(0);runtime.locking(stream.fileno(),runtime.LK_NBLCK,1)
  try:
   yield stream
  finally:
   try:
    exact_lock(stream,path)
    require(diagnostic.stream_identity(stream,path,api)==prepared['lock_identity'],'LOCK_CHANGED')
   finally:
    stream.seek(0);runtime.locking(stream.fileno(),runtime.LK_UNLCK,1)

def execute(stage):
 reviewed_constants();require(type(stage) is str and stage in STAGES)
 require(os.name=='nt' and Path.cwd().resolve()==ROOT,'WINDOWS_ROOT_ONLY')
 diagnostic,current,_=modules()
 from infra import evidence_interpreter_compile as compiler
 result={'schema':1,'scope':SCOPE,'stage':stage,'status':'REFUSED','completed':False,
  'native_eligible':False,'private_input_allowed':False,'control_state_modified':False,'pins_closed':False,
  'cli_cleanup_confirmed':False,'binding':None,'completed_stages':[],'phase_originals':[],
  'completed_manifest':[],'results':{}}
 receipt=current.Receipt(ROOT/receipt_path(stage),result)
 started=time.monotonic();checkpoint=None;failure=None;context=None;payload=None;oldcall=None
 def mark(name):
  nonlocal checkpoint
  require(name in expected_stages(stage))
  if checkpoint is not None:result['completed_stages'].append(checkpoint)
  checkpoint=name
 try:
  mark('INPUTS');receipt_set(ROOT,stage)
  with diagnostic.existing_lock_guard(),compiler.checked_inputs() as (api,pins,oldcall,_):
   source=current.pin_bytes(ROOT,pins,api,'infra/evidence_rmdir_proof.py')
   expected_binding=binding(digest(source));result['binding']=asdict(expected_binding)
   pin_sources(ROOT,pins,api,expected_binding)
   native=_native()
   prepared=corrected_provenance(ROOT,pins,api)
   mark('PRIOR_STAGES');rows=prior_stages(ROOT,pins,api,stage,expected_binding)
   result.update(phase_originals=rows,completed_manifest=list(PHASES[:len(rows)]))
   mark('EXISTING_LOCK')
   with existing_proof_lock(api,pins,prepared) as lock_stream:
    context=_ExecutionContext(_SEAL,api,pins,oldcall,receipt,result,stage,prepared,expected_binding,lock_stream)
    if stage=='preflight':mark('FRESH_PREFLIGHT');context.preflight();payload={}
    else:
     mark('PUBLIC_MATRIX');payload=native.execute(context,stage)
     require(native.validate_result(stage,payload)==payload)
    require(result['completed_manifest']==list(PHASES[:END[stage]]))
    validate_manifest(result['phase_originals'],PHASES[:END[stage]],expected_binding)
    mark('FINAL_RESOURCES');context._limits();require(not oldcall.uncertain)
    context.close();mark('LOCK_CLOSE')
   mark('INPUT_CLOSE')
  result['pins_closed']=True
  mark('FINAL_CLI');require(not oldcall.uncertain and time.monotonic()-started<LIMITS[stage])
  result['cli_cleanup_confirmed']=True;result['completed_stages'].append(checkpoint);checkpoint=None
 except BaseException:
  failure=True;result['failure_code']='RMDIR_PROOF_REFUSED'
  if checkpoint is not None:result['failed_stage']=checkpoint
 finally:
  if context is not None:
   try:context.close()
   except BaseException:failure=True;result['failure_code']='CONTEXT_CLOSE_UNCONFIRMED'
  elapsed=time.monotonic()-started
  if not 0<=elapsed<LIMITS[stage]:failure=True;result['failure_code']='STAGE_DEADLINE'
  active_guard={name:result[name] for name in ('active_case','active_phase','active_token','active_original_id') if name in result}
  if failure is None:
   result.update(status='VERIFIED',completed=True,results=payload)
   result.pop('active_case',None);result.pop('active_phase',None)
  result['total_seconds']=round(elapsed,3)
  try:receipt.save(result);receipt.close()
  except BaseException:
   result.update(status='REFUSED',completed=False,failure_code='RECEIPT_CLOSE_UNCONFIRMED')
   result.update(active_guard)
   try:
    if not receipt.stream.closed:receipt.save(result)
   except BaseException:pass
   try:receipt.close()
   except BaseException:pass
   raise ProofUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
 require(failure is None)
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('stage',choices=STAGES)
 value=execute(parser.parse_args().stage)
 print(json.dumps({'status':value['status'],'receipt':receipt_path(value['stage']),'native_eligible':False}),flush=True)

if __name__=='__main__':main()
