"""One currentness-gated PUBLIC failure-category diagnostic; inert import.

Fixed preflight/diagnostic only. No acceptance-suite retry or private activation.
Root retains externally reviewed canonical executing bytes through operation.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from dataclasses import dataclass,asdict
import hashlib
from itertools import islice
import json
import math
import os
from pathlib import Path
import re
import shutil
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
SCOPE='PUBLIC_STRICT_FAILURE_CATEGORY_DIAGNOSTIC_ONLY'
CONTRACT='6c0f7fa9a86afc96ad4a677df9eab9d76264de8df51cd7be1b1fb911e34459b5'
PHASE_ID='strict-category:scan:strict'
PREFIX='ai/state/private-scanner-strict-category-'
NATIVE='infra/evidence_strict_category_native.py'
NATIVE_SHA256='ca07edf6d213f487bbd904aff1f0c922188bba49b3d183f725141fe884ea1906'
PROVENANCE='infra/evidence_strict_category_provenance.py'
PROVENANCE_SHA256='4c0e432cbd6956c6525cd39aede199d041f28e11e46820d1b624d416c02948bb'
TELEMETRY_SHA256='dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'
FAILED_SHA256='7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00'
FLOOR=6*1024**3
STAGES=('preflight','diagnostic')
FINALIZERS=('context','phase_pins','dedicated_lock','input_resources','cli')
STATES=('NOT_REACHED','CONFIRMED','UNCONFIRMED')
FRESH_GATES=('SOURCE_PINS','CORRECTED_PREPARATION','IMAGE_PACKAGE_UTC','OCI_BYTES','PRESERVED_ORIGINALS',
 'UNKNOWN_RESERVATIONS','CGROUP_DISK','HISTORICAL_ORIGINAL_ABSENCE','CURRENT_ORIGINAL_ABSENCE')
_CONTEXT_SEAL=object()

class DiagnosticUnavailable(RuntimeError):
 def __init__(self,code='STRICT_CATEGORY_DIAGNOSTIC_REFUSED'):
  self.code=code;super().__init__(code)

def require(value,code='STRICT_CATEGORY_DIAGNOSTIC_REFUSED'):
 if value is not True:raise DiagnosticUnavailable(code)

def inherited():
 from infra import evidence_rmdir_proof as old
 from infra import evidence_rmdir_diagnostic as diagnostic
 from infra import evidence_interpreter_runtime as current
 return old,diagnostic,current

def _base():
 from infra import evidence_rmdir_diagnostic as diagnostic
 from infra import evidence_interpreter_runtime as current
 return diagnostic,current

def native():
 from infra import evidence_strict_category_native as adapter
 return adapter

def reviewed_constants():
 for value in (NATIVE_SHA256,PROVENANCE_SHA256,TELEMETRY_SHA256):
  require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None and value!='0'*64,'SOURCE_NOT_REVIEWED')

@dataclass(frozen=True,slots=True)
class _Binding:
 image_id:str
 signature_generation:str
 profile_sha256:str
 preparation_sha256:str
 native_sha256:str
 controller_sha256:str
 provenance_sha256:str
 telemetry_sha256:str
 failed_receipt_sha256:str
 contract:str

def binding(controller_sha256):
 reviewed_constants();require(type(controller_sha256) is str and re.fullmatch('[0-9a-f]{64}',controller_sha256) is not None)
 return _Binding('sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa',
  '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3',
  'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733',
  '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f',
  NATIVE_SHA256,controller_sha256,PROVENANCE_SHA256,TELEMETRY_SHA256,FAILED_SHA256,CONTRACT)

def _pin_sources(root,pins,api,expected):
 _,current=_base()
 require(type(expected) is _Binding and expected==binding(expected.controller_sha256))
 current.pin_bytes(root,pins,api,'infra/evidence_strict_category_controller.py',expected=expected.controller_sha256)
 current.pin_bytes(root,pins,api,PROVENANCE,expected=PROVENANCE_SHA256)
 from infra import evidence_strict_category_provenance as provenance
 provenance.pin_sources(root,pins,api,expected)
 return provenance

def receipt_path(stage):
 require(type(stage) is str and stage in STAGES)
 return PREFIX+stage+'.json'

def receipt_set(root,stage):
 paths=list(islice((root/'ai/state').glob('private-scanner-strict-category-*.json'),4))
 allowed={Path(receipt_path(value)).name for value in (('preflight',) if stage=='preflight' else STAGES)}
 require(len(paths)<=len(allowed) and all(path.name in allowed for path in paths),'UNKNOWN_RECEIPT')

def finalizer(result,name,state):
 require(name in FINALIZERS and state in STATES)
 if result['finalizers'][name]!='UNCONFIRMED':result['finalizers'][name]=state

@contextmanager
def tracked(manager,result,name):
 """Observe manager exit on normal AND exceptional body paths; never infer it."""
 try:resource=manager.__enter__()
 except BaseException:
  finalizer(result,name,'UNCONFIRMED');raise
 try:yield resource
 except BaseException:
  info=sys.exc_info()
  try:suppressed=manager.__exit__(*info)
  except BaseException:
   finalizer(result,name,'UNCONFIRMED');raise
  finalizer(result,name,'CONFIRMED')
  # Fixed internal resource managers must never suppress a work failure.
  if suppressed:raise DiagnosticUnavailable('BODY_EXCEPTION_SUPPRESSED')
  raise
 else:
  try:manager.__exit__(None,None,None)
  except BaseException:
   finalizer(result,name,'UNCONFIRMED');raise
  finalizer(result,name,'CONFIRMED')

@contextmanager
def input_resources():
 diagnostic,_=_base()
 from infra import evidence_interpreter_compile as compiler
 with diagnostic.existing_lock_guard(),compiler.checked_inputs() as values:yield values

def expected_stages(stage):
 result=['INPUTS','SOURCES','CORRECTED_PREPARATION']
 if stage=='diagnostic':result+=['PREFLIGHT_PROVENANCE']
 return result+['EXISTING_LOCK','FRESH_PREFLIGHT' if stage=='preflight' else 'PUBLIC_DIAGNOSTIC','FINAL_GATES']

def preflight_provenance(root,pins,api,expected):
 _,_,current=inherited()
 value=current.document(current.pin_bytes(root,pins,api,receipt_path('preflight'),maximum=262144))
 keys={'schema','scope','stage','status','completed','native_eligible','private_input_allowed','control_state_modified',
  'binding','finalizers','completed_stages','preserved_originals','new_original','observation','total_seconds'}
 require(type(value) is dict and set(value)==keys and type(value.get('schema')) is int and value['schema']==1 and
  value['scope']==SCOPE and value['stage']=='preflight' and value['status']=='VERIFIED' and value['completed'] is True and
  value['native_eligible'] is False and value['private_input_allowed'] is False and value['control_state_modified'] is False and
  value['binding']==asdict(expected) and value['completed_stages']==expected_stages('preflight') and
  value['finalizers']=={name:'CONFIRMED' for name in FINALIZERS} and value['new_original'] is None and
  value['observation'] is None and type(value['total_seconds']) in (int,float) and 0<=value['total_seconds']<300)
 rows=value['preserved_originals']
 require(type(rows) is list and len(rows)==27 and sum(len(row['files']) for row in rows)==108 and
  len({row['token'] for row in rows})==27 and len({row['original_id'] for row in rows})==27)
 return value

def absence(call,selector):
 require(type(selector) is str and (re.fullmatch('[0-9a-f]{64}',selector) is not None or
  re.fullmatch('kapit-(?:same-image|scratch|rmdir|rmdir-proof|strict-identity|strict-category)-public-[0-9a-f]{32}',selector) is not None))
 code,out,err,reason=call('container','inspect',selector)
 require(type(code) is int and code==1 and reason=='EXIT' and out in (b'[]',b'[]\n',b'[]\r\n') and
  err in tuple(('Error response from daemon: No such container: '+selector+end).encode('ascii') for end in ('','\n','\r\n')))

def live_absences(call,rows):
 _,diagnostic,_=inherited()
 require(type(rows) is list and 1<=len(rows)<=28 and len({row['token'] for row in rows})==len(rows) and
  len({row['original_id'] for row in rows})==len(rows))
 for offset in range(0,len(rows),8):
  batch=diagnostic.Commands(call.docker,call.config);started=time.monotonic();diagnostic.engine(batch)
  for row in rows[offset:offset+8]:absence(batch,row['original_id']);absence(batch,row['expected_name'])
  diagnostic.engine(batch);require(not batch.uncertain and time.monotonic()-started<300)

class _ExecutionContext:
 __slots__=('_seal','_binding','_api','_pins','_oldcall','_receipt','_result','_stage','_prepared','_lock_stream',
  '_call','_cleanup_call','_cleanup_count','_observation','_phase_pins','_active_token','_returned_cid',
  '_closed','_phase_attempted','_deadline','_attach_attempted','_attach_confirmed','_attach_uncertain','_attach_notification','_preflight_rows',
  '_calls','_helper_cli_incomplete')
 def __init__(self,seal,api,pins,oldcall,receipt,result,stage,prepared,expected,lock_stream,preflight_rows=None):
  require(seal is _CONTEXT_SEAL and type(expected) is _Binding and expected==binding(expected.controller_sha256) and
   stage in STAGES and result['binding']==asdict(expected))
  require((stage=='preflight' and preflight_rows is None) or (stage=='diagnostic' and type(preflight_rows) is list and len(preflight_rows)==27))
  self._seal=seal;self._binding=expected;self._api=api;self._pins=pins;self._oldcall=oldcall
  self._receipt=receipt;self._result=result;self._stage=stage;self._prepared=deepcopy(prepared);self._lock_stream=lock_stream
  self._call=None;self._cleanup_call=None;self._cleanup_count=0;self._observation=None;self._phase_pins=None
  self._active_token=None;self._returned_cid=None;self._closed=False;self._phase_attempted=False
  self._deadline=time.monotonic()+300;self._attach_attempted=False;self._attach_confirmed=False;self._attach_uncertain=False
  self._attach_notification=False
  self._preflight_rows=deepcopy(preflight_rows)
  self._calls=[];self._helper_cli_incomplete=False
 @property
 def root(self):return ROOT
 @property
 def profile(self):return ROOT/inherited()[1].PROFILE
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
  return bool(self._oldcall.uncertain or any(call.uncertain for call in self._calls) or self._helper_cli_incomplete or self._attach_uncertain or
   (self._attach_attempted and not self._attach_confirmed))
 def _new_call(self):
  call=inherited()[1].Commands(self.docker,self.config);self._calls.append(call);return call
 def _live_absences(self,rows):
  require(type(rows) is list and 1<=len(rows)<=28 and len({row['token'] for row in rows})==len(rows) and
   len({row['original_id'] for row in rows})==len(rows))
  for offset in range(0,len(rows),8):
   call=self._new_call();started=time.monotonic();inherited()[1].engine(call)
   for row in rows[offset:offset+8]:absence(call,row['original_id']);absence(call,row['expected_name'])
   inherited()[1].engine(call);require(not call.uncertain and time.monotonic()-started<300)
 def attach_started(self):
  _validate_context(self);self._limits()
  require(self._active_token is not None and not self._attach_attempted and self._returned_cid is not None and
   self._result.get('active_original_id')==self._returned_cid and self._observation is not None and self._observation.used)
  self._attach_attempted=True
 def attach_finalized(self,confirmed):
  _validate_context(self)
  require(self._attach_attempted and not self._attach_notification and type(confirmed) is bool)
  self._attach_notification=True
  if confirmed and not self._attach_uncertain:self._attach_confirmed=True
  else:self._attach_uncertain=True
 def _save(self):self._receipt.save(self._result)
 def _limits(self):
  require(not self._closed and time.monotonic()<self._deadline,'DEADLINE')
  require(shutil.disk_usage(ROOT).free>=FLOOR,'LOW_SPACE')
  require(not self.call_uncertain,'CLI_UNCONFIRMED')
 def command(self,*args,timeout=15):
  self._limits();require(self._call is not None)
  return self._call(*args,timeout=timeout)
 def cleanup_command(self,*args,timeout=15):
  require(self._active_token is not None)
  name=native().metadata(self._active_token,PHASE_ID,self.binding)['expected_name'];cid=self._returned_cid
  allowed=[('container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}}')]
  if cid is not None:allowed += [('container','inspect',cid),('container','kill','--signal','KILL',cid),
   ('container','rm',cid),('container','ls','--all','--no-trunc','--filter','id='+cid,'--format','{{.ID}}')]
  require(args in allowed and self._cleanup_count<8,'CLEANUP_COMMAND_REFUSED')
  if self._cleanup_call is None:self._cleanup_call=self._new_call()
  self._cleanup_count+=1;return self._cleanup_call(*args,timeout=timeout)
 def _close_phase(self):
  if self._phase_pins is None:return
  stack=self._phase_pins;self._phase_pins=None
  try:stack.close()
  except BaseException:
   finalizer(self._result,'phase_pins','UNCONFIRMED');raise
  finalizer(self._result,'phase_pins','CONFIRMED')
 def _fresh(self):
  old,diagnostic,current=inherited();self._limits();require(self._phase_pins is None)
  stack=ExitStack();self._phase_pins=stack
  gate='SOURCE_PINS'
  try:
   provenance=_pin_sources(ROOT,stack,self._api,self.binding)
   gate='CORRECTED_PREPARATION'
   prepared=old.corrected_provenance(ROOT,stack,self._api,self._lock_stream)
   require(prepared==self._prepared)
   gate='IMAGE_PACKAGE_UTC'
   self._helper_cli_incomplete=True
   actual=current.verified_image(ROOT,stack,self._api)
   self._helper_cli_incomplete=False
   require(actual.get('image_id')==self.binding.image_id and actual.get('signature_generation')==self.binding.signature_generation)
   gate='OCI_BYTES'
   diagnostic.oci_bytes(ROOT,stack,self._api,actual)
   gate='PRESERVED_ORIGINALS'
   rows=provenance.preserved_originals(ROOT,stack,self._api,prepared)
   require(len(rows)==27 and sum(len(row['files']) for row in rows)==108)
   if self._stage=='diagnostic':require(rows==self._preflight_rows,'PREFLIGHT_ORIGINALS_CHANGED')
   gate='UNKNOWN_RESERVATIONS'
   provenance.unknown_reservations(ROOT,stack,self._api,rows)
   self._result['preserved_originals']=deepcopy(rows)
   self._call=self._new_call()
   gate='CGROUP_DISK'
   diagnostic.modules()[1]._require_cgroup_v2(self._call);self._limits()
   from infra import evidence_interpreter_compile as compiler
   legacy=self._new_call()
   gate='HISTORICAL_ORIGINAL_ABSENCE'
   compiler.live_originals(legacy).consume();require(not legacy.uncertain)
   gate='CURRENT_ORIGINAL_ABSENCE'
   self._live_absences(rows)
   require(not self._call.uncertain)
   self._observation=diagnostic.Observation(diagnostic._LIVE_SEAL,time.monotonic())
  except BaseException:
   self._result['failed_gate']=gate
   self._close_phase();raise
 def before_phase(self,phase_id,token):
  _validate_context(self);self._limits()
  require(phase_id==PHASE_ID and not self._phase_attempted and type(token) is str and re.fullmatch('[0-9a-f]{32}',token) is not None)
  self._phase_attempted=True;self._active_token=token
  self._result.update(active_case='strict-category',active_phase=PHASE_ID,active_token=token)
  self._save();self._fresh()
  require(token not in {row['token'] for row in self._result['preserved_originals']})
  print(json.dumps({'event':'START_PUBLIC_DIAGNOSTIC','phase':PHASE_ID}),flush=True)
 def consume_before_create(self,phase_id):
  self._limits();require(phase_id==PHASE_ID and self._active_token is not None and self._observation is not None)
  self._observation.consume()
 def retain_original(self,phase_id,token,cid):
  require(phase_id==PHASE_ID and token==self._active_token and type(cid) is str and
   re.fullmatch('[0-9a-f]{64}',cid) is not None and cid!='0'*64 and self._returned_cid in (None,cid))
  require(cid not in {row['original_id'] for row in self._result['preserved_originals']})
  self._returned_cid=cid
 def record_original(self,phase_id,token,cid):
  self._limits();self.retain_original(phase_id,token,cid)
  self._result['active_original_id']=cid;self._save()
 def finish_phase(self,phase_id,token,cid,cleanup,outcome):
  old,diagnostic,_=inherited()
  require(phase_id==PHASE_ID and token==self._active_token and self._phase_pins is not None)
  primary=None;observed=False
  try:
   require(cleanup=='ORIGINAL_ID_ABSENT_VERIFIED' and self._result.get('active_original_id')==cid)
   fixed=native().metadata(token,PHASE_ID,self.binding)
   journal=diagnostic.journal_documents(ROOT,self._phase_pins,self._api,token,fixed,cid)
   self._live_absences([journal]);journal['original_cid_and_name_absent_live']=True
   self._result['new_original']=journal
   if outcome is not None:self._result['observation']=native().validate_outcome(PHASE_ID,outcome)
   self._save();diagnostic.engine(self._call)
   require(not self.call_uncertain)
   observed=outcome is not None and outcome['observed'] is True
  except BaseException as error:
   primary=error
   try:
    failed=_capture_failed_original(ROOT,self._phase_pins,self._api,token,cid,self.binding)
    if type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid) is not None:
     try:self._live_absences([failed]);failed['original_cid_and_name_absent_live']=True
     except BaseException:pass
    self._result['failed_original']=failed;self._save()
   except BaseException:primary=DiagnosticUnavailable('FAILED_ORIGINAL_CAPTURE_UNCONFIRMED')
  finally:
   try:self._close_phase()
   except BaseException:primary=DiagnosticUnavailable('PHASE_PIN_CLOSE_UNCONFIRMED')
  if primary is not None:raise primary
  # No active-marker clearing or acceptance advancement here. Parent body and
  # every finalizer must still return normally, even if finite data was saved.
  return observed
 def preflight(self):
  require(self._stage=='preflight');self._fresh();self._observation.consume();self._close_phase();self._observation=None
 def close(self):
  self._closed=True
  try:
   self._close_phase()
   require(self._result['finalizers']['phase_pins']!='UNCONFIRMED')
  except BaseException:
   finalizer(self._result,'context','UNCONFIRMED');raise
  finalizer(self._result,'context','CONFIRMED')

def _validate_context(context):
 require(type(context) is _ExecutionContext and context._seal is _CONTEXT_SEAL and not context._closed and
  type(context.binding) is _Binding and context.binding==binding(context.binding.controller_sha256) and context.stage=='diagnostic')
 return context

def _capture_failed_original(root,pins,api,token,cid,expected):
 # Fixed new metadata; copy available documents without fabricating missing ones.
 _,diagnostic,current=inherited()
 from infra.live_recovery_drill import PrivateDirectory
 fixed=native().metadata(token,PHASE_ID,expected);directory=diagnostic.STAGE+'/native-run-'+token
 result={'directory':directory,'token':token,'original_id':cid,'expected_name':fixed['expected_name'],
  'files':{},'unconfirmed_documents':[],'original_cid_and_name_absent_live':False}
 names=('reservation.json','create-attempt.json','ownership.json','result.json')
 try:pins.enter_context(PrivateDirectory().pin(root/directory,private=True,directory=True))
 except BaseException:result['unconfirmed_documents']=list(names);return result
 for name in names:
  try:
   raw=current.pin_bytes(root,pins,api,directory+'/'+name,private=True,maximum=8192);value=current.document(raw)
   if name=='reservation.json':document=fixed
   elif name=='create-attempt.json':document={'schema':1,'token':token,'create_attempted':True,'native_eligible':False}
   elif name=='ownership.json':document=dict(fixed,original_id=cid)
   else:
    owned=diagnostic.modules()[3];require(value.get('ownership_status') in owned.STATUSES and value.get('original_id') in (None,cid))
    document={'schema':1,'token':token,'original_id':value['original_id'],'ownership_status':value['ownership_status'],'native_eligible':False}
   require(value==document and raw==diagnostic.modules()[3]._canonical(document))
   result['files'][name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'document':value}
  except BaseException:result['unconfirmed_documents'].append(name)
 return result

def _cli_finalizer(result,context,oldcall):
 if oldcall is None:return
 finalizer(result,'cli','UNCONFIRMED' if oldcall.uncertain or (context is not None and context.call_uncertain) else 'CONFIRMED')

def _new_receipt(path,initial):
 """Same exclusive original-handle writer, with explicit initial-fault close."""
 from infra.evidence_interpreter_runtime import Receipt
 receipt=Receipt.__new__(Receipt)
 receipt.path=path;receipt.stream=path.open('xb')
 try:receipt.save(initial)
 except BaseException:
  try:receipt.close()
  except BaseException:raise DiagnosticUnavailable('RECEIPT_INITIAL_CLOSE_UNCONFIRMED') from None
  raise DiagnosticUnavailable('RECEIPT_INITIAL_WRITE_REFUSED') from None
 return receipt

def _postflight_reservations(root,pins,api,rows,expected):
 """Only the exact fixed-receipt original may extend precreate discovery."""
 _,diagnostic,current=inherited();adapter=native()
 from infra.live_recovery_drill import PrivateDirectory
 from infra import evidence_rmdir_native as old_native
 require(type(expected) is _Binding and expected==binding(expected.controller_sha256))
 require(type(rows) is list and len(rows)==28 and len({row['token'] for row in rows})==28 and
  len({row['original_id'] for row in rows})==28)
 allowed={row['token']:row['files']['reservation.json']['document'] for row in rows}
 own=[row for row in rows if row['files']['reservation.json']['document']['expected_labels'].get('org.kapit.owner')==adapter.OWNER]
 require(len(own)==1)
 fixed=adapter.metadata(own[0]['token'],PHASE_ID,expected)
 require(allowed[own[0]['token']]==fixed)
 directories=list(islice((root/diagnostic.STAGE).glob('native-run-*'),257));require(len(directories)<=256)
 for directory in directories:
  require(re.fullmatch('native-run-[0-9a-f]{32}',directory.name) is not None)
  pins.enter_context(PrivateDirectory().pin(directory,private=True,directory=True))
  value=current.document(current.pin_bytes(root,pins,api,(directory/'reservation.json').relative_to(root).as_posix(),private=True,maximum=8192))
  labels=value.get('expected_labels')
  require(type(value.get('schema')) is int and value['schema']==1 and value.get('token')==directory.name[11:] and
   type(value.get('image_id')) is str and re.fullmatch('sha256:[0-9a-f]{64}',value['image_id']) is not None and
   type(value.get('signature_generation')) is str and re.fullmatch('[0-9a-f]{64}',value['signature_generation']) is not None and
   value.get('native_eligible') is False and type(value.get('purpose')) is str and bool(value['purpose']) and
   type(labels) is dict and all(type(key) is str and type(item) is str for key,item in labels.items()) and
   bool(labels.get('org.kapit.owner')) and bool(labels.get('org.kapit.purpose')) and labels.get('org.kapit.reservation')==value['token'])
  if labels['org.kapit.owner']==adapter.OWNER or value['purpose'].startswith('public-strict-category'):
   require(value==fixed)
  elif labels['org.kapit.owner'] in (old_native.OWNER,'kapit-public-strict-identity-v1') or value['purpose'].startswith(('public-rmdir-proof-','public-strict-identity')):
   require(value['token'] in allowed and value==allowed[value['token']])

def _postflight_originals(root,pins,api,expected,prepared):
 """Read-only known-original replay; never a new capability or activation."""
 diagnostic,current=_base();provenance=_pin_sources(root,pins,api,expected)
 value=current.document(current.pin_bytes(root,pins,api,receipt_path('diagnostic'),maximum=262144))
 _validate_diagnostic_receipt(value,expected)
 journal=value.get('new_original');require(type(journal) is dict)
 token=journal.get('token');cid=journal.get('original_id')
 fixed=native().metadata(token,PHASE_ID,expected)
 actual=diagnostic.journal_documents(root,pins,api,token,fixed,cid,journal.get('files'))
 require(journal==dict(actual,original_cid_and_name_absent_live=True))
 if value['status']=='REFUSED':
  require(value.get('active_token')==token and value.get('active_original_id')==cid and
   value.get('active_phase')==PHASE_ID and value.get('active_case')=='strict-category')
 preserved=provenance.preserved_originals(root,pins,api,prepared)
 require(value['preserved_originals']==preserved)
 rows=preserved+[actual]
 require(len(rows)==28 and sum(len(row['files']) for row in rows)==112 and len({row['token'] for row in rows})==28 and
  len({row['original_id'] for row in rows})==28)
 _postflight_reservations(root,pins,api,rows,expected)
 return rows

def _validate_diagnostic_receipt(value,expected):
 base={'schema','scope','stage','status','completed','native_eligible','private_input_allowed','control_state_modified',
  'binding','finalizers','completed_stages','preserved_originals','new_original','observation','total_seconds'}
 refusal={'active_case','active_phase','active_token','active_original_id','failure_code','failed_stage','failed_original','failed_gate'}
 require(type(value) is dict and base<=set(value)<=base|refusal and type(value['schema']) is int and value['schema']==1 and
  value['scope']==SCOPE and value['stage']=='diagnostic' and value['binding']==asdict(expected) and
  value['native_eligible'] is False and value['private_input_allowed'] is False and value['control_state_modified'] is False and
  value['status'] in ('MEASURED','REFUSED') and type(value['completed']) is bool and
  value['completed'] is (value['status']=='MEASURED') and type(value['total_seconds']) in (int,float) and
  math.isfinite(value['total_seconds']) and 0<=value['total_seconds'])
 states=value['finalizers']
 require(type(states) is dict and set(states)==set(FINALIZERS) and all(type(state) is str and state in STATES for state in states.values()))
 stages=value['completed_stages'];expected_stages_list=expected_stages('diagnostic')
 require(type(stages) is list and len(stages)<=len(expected_stages_list) and stages==expected_stages_list[:len(stages)])
 if value['observation'] is not None:native().validate_outcome(PHASE_ID,value['observation'])
 rows=value['preserved_originals']
 require(type(rows) is list and len(rows)==27 and sum(len(row['files']) for row in rows)==108 and
  len({row['token'] for row in rows})==27 and len({row['original_id'] for row in rows})==27)
 journal=value['new_original'];require(type(journal) is dict and set(journal)=={'directory','token','original_id','expected_name',
  'files','original_cid_and_name_absent_live'} and journal['original_cid_and_name_absent_live'] is True and
  type(journal['files']) is dict and set(journal['files'])=={'reservation.json','create-attempt.json','ownership.json','result.json'})
 fixed=native().metadata(journal.get('token'),PHASE_ID,expected)
 require(journal.get('expected_name')==fixed['expected_name'] and type(journal.get('original_id')) is str and
  re.fullmatch('[0-9a-f]{64}',journal['original_id']) is not None)
 _validate_failed_capture(dict(journal,unconfirmed_documents=[]),journal,expected)
 require(journal['files']['result.json']['document']['ownership_status']=='ORIGINAL_ID_ABSENT_VERIFIED')
 if value['status']=='MEASURED':
  require(set(value)==base and stages==expected_stages_list and all(state=='CONFIRMED' for state in states.values()) and
   value['observation'] is not None and value['observation']['observed'] is True and value['total_seconds']<300)
 else:
  require(value.get('active_case')=='strict-category' and value.get('active_phase')==PHASE_ID and
   value.get('active_token')==journal['token'] and value.get('active_original_id')==journal['original_id'] and
   value.get('failure_code') in ('STRICT_CATEGORY_DIAGNOSTIC_REFUSED','CONTEXT_CLOSE_UNCONFIRMED',
    'FINALIZER_UNCONFIRMED','DEADLINE','RECEIPT_CLOSE_UNCONFIRMED'))
  if 'failed_stage' in value:require(value['failed_stage'] in expected_stages_list)
  if 'failed_gate' in value:require(value['failed_gate'] in FRESH_GATES)
  if 'failed_original' in value:_validate_failed_capture(value['failed_original'],journal,expected)
 return value

def _validate_failed_capture(value,journal,expected):
 _,diagnostic,_=inherited();owned=diagnostic.modules()[3]
 require(type(value) is dict and set(value)=={'directory','token','original_id','expected_name','files',
  'unconfirmed_documents','original_cid_and_name_absent_live'} and value['token']==journal['token'] and
  value['original_id']==journal['original_id'] and value['expected_name']==journal['expected_name'] and
  value['directory']==diagnostic.STAGE+'/native-run-'+journal['token'] and type(value['original_cid_and_name_absent_live']) is bool)
 names={'reservation.json','create-attempt.json','ownership.json','result.json'}
 require(type(value['files']) is dict and set(value['files'])<=names and type(value['unconfirmed_documents']) is list and
  all(type(name) is str and name in names for name in value['unconfirmed_documents']) and
  len(set(value['unconfirmed_documents']))==len(value['unconfirmed_documents']) and
  set(value['files']).isdisjoint(value['unconfirmed_documents']) and set(value['files'])|set(value['unconfirmed_documents'])==names)
 fixed=native().metadata(journal['token'],PHASE_ID,expected)
 for name,info in value['files'].items():
  require(type(info) is dict and set(info)=={'bytes','sha256','document'})
  document=info['document']
  if name=='reservation.json':wanted=fixed
  elif name=='create-attempt.json':wanted={'schema':1,'token':journal['token'],'create_attempted':True,'native_eligible':False}
  elif name=='ownership.json':wanted=dict(fixed,original_id=journal['original_id'])
  else:
   require(type(document) is dict and document.get('ownership_status') in owned.STATUSES and document.get('original_id') in (None,journal['original_id']))
   wanted={'schema':1,'token':journal['token'],'original_id':document['original_id'],
    'ownership_status':document['ownership_status'],'native_eligible':False}
  raw=owned._canonical(wanted)
  require(owned._canonical(document)==raw and type(info['bytes']) is int and info['bytes']==len(raw) and
   info['sha256']==hashlib.sha256(raw).hexdigest())

def execute(stage):
 reviewed_constants();require(type(stage) is str and stage in STAGES)
 require(os.name=='nt' and Path.cwd().resolve()==ROOT,'WINDOWS_ROOT_ONLY')
 diagnostic,current=_base()
 result={'schema':1,'scope':SCOPE,'stage':stage,'status':'REFUSED','completed':False,'native_eligible':False,
  'private_input_allowed':False,'control_state_modified':False,'binding':None,
  'finalizers':{name:'NOT_REACHED' for name in FINALIZERS},'completed_stages':[],
  'preserved_originals':[],'new_original':None,'observation':None}
 receipt=_new_receipt(ROOT/receipt_path(stage),result)
 started=time.monotonic();failure=None;checkpoint=None;context=None;oldcall=None;outcome=None
 def mark(name):
  nonlocal checkpoint
  require(name in expected_stages(stage))
  if checkpoint is not None:result['completed_stages'].append(checkpoint)
  checkpoint=name
 try:
  mark('INPUTS');receipt_set(ROOT,stage)
  with tracked(input_resources(),result,'input_resources') as (api,pins,oldcall,_):
   mark('SOURCES')
   raw=current.pin_bytes(ROOT,pins,api,'infra/evidence_strict_category_controller.py')
   expected=binding(hashlib.sha256(raw).hexdigest());result['binding']=asdict(expected)
   _pin_sources(ROOT,pins,api,expected)
   old,_,_=inherited()
   mark('CORRECTED_PREPARATION');prepared=old.corrected_provenance(ROOT,pins,api)
   preflight_rows=None
   if stage=='diagnostic':
    mark('PREFLIGHT_PROVENANCE');preflight_rows=preflight_provenance(ROOT,pins,api,expected)['preserved_originals']
   mark('EXISTING_LOCK')
   with tracked(old.existing_proof_lock(api,pins,prepared),result,'dedicated_lock') as lock_stream:
    context=_ExecutionContext(_CONTEXT_SEAL,api,pins,oldcall,receipt,result,stage,prepared,expected,lock_stream,preflight_rows)
    try:
     if stage=='preflight':mark('FRESH_PREFLIGHT');context.preflight()
     else:
      mark('PUBLIC_DIAGNOSTIC');outcome=native().validate_outcome(PHASE_ID,native().execute(context))
      require(outcome['observed'] is True and result['new_original'] is not None and result['observation']==outcome)
     mark('FINAL_GATES');context._limits();require(not oldcall.uncertain)
    finally:context.close()
  _cli_finalizer(result,context,oldcall)
  require(all(result['finalizers'][name]=='CONFIRMED' for name in FINALIZERS) and time.monotonic()-started<300)
  result['completed_stages'].append(checkpoint);checkpoint=None
 except BaseException:
  failure=True;result['failure_code']='STRICT_CATEGORY_DIAGNOSTIC_REFUSED'
  if checkpoint is not None:result['failed_stage']=checkpoint
 finally:
  if context is not None:
   try:context.close()
   except BaseException:failure=True;result['failure_code']='CONTEXT_CLOSE_UNCONFIRMED'
  _cli_finalizer(result,context,oldcall)
  if any(state=='UNCONFIRMED' for state in result['finalizers'].values()):
   failure=True;result['failure_code']='FINALIZER_UNCONFIRMED'
  elapsed=time.monotonic()-started
  if not 0<=elapsed<300:failure=True;result['failure_code']='DEADLINE'
  active={name:result[name] for name in ('active_case','active_phase','active_token','active_original_id') if name in result}
  if failure is None:
   result.update(status='VERIFIED' if stage=='preflight' else 'MEASURED',completed=True)
   for name in active:result.pop(name,None)
  result['total_seconds']=round(elapsed,3)
  try:receipt.save(result);receipt.close()
  except BaseException:
   result.update(status='REFUSED',completed=False,failure_code='RECEIPT_CLOSE_UNCONFIRMED');result.update(active)
   try:
    if not receipt.stream.closed:receipt.save(result)
   except BaseException:pass
   try:receipt.close()
   except BaseException:pass
   raise DiagnosticUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
 require(failure is None)
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('stage',choices=STAGES)
 value=execute(parser.parse_args().stage)
 print(json.dumps({'status':value['status'],'receipt':receipt_path(value['stage']),'native_eligible':False}),flush=True)

if __name__=='__main__':main()
