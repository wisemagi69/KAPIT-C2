"""Fixed public rmdir-profile correction observations. Import is inert; only root runs the CLI.

Frozen scratch ownership/attach/currentness mechanisms are copied unchanged
except fixed new profile/purposes/receipts, preparation provenance, bounded
13/14-original discovery, and validated profile-only inspection normalization.
No frozen module globals, worker, POLICY or final helper filters are changed.
"""
from __future__ import annotations
import argparse
import base64
import ctypes as ctypes
from ctypes import wintypes as wintypes
import stat
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
from itertools import islice
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
STAGE = '.cache/m1-runtime/private-scanner-build'
PROGRAM = 'infra/native/scratch_probe.py'
PROGRAM_SHA256 = 'd08e9b0830409cc80b07a5a0dee3521a45254fc1292067914c2aa486856ccbd5'
IMAGE = 'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa'
GENERATION = '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3'
ENGINE = 'ddd3c2221b89b743c98388fa5a6d127bf00c088f0c9566b963244caa1e892557'
OLD_POLICY = '1e2b71ab05a6905a3c9edfe056cf83ddb4df0170560f1f04a0e7978741358105'
OWNER = 'kapit-public-rmdir-profile-v2'
OLD_PROFILE = STAGE + '/abi3-startup-profile.json'
PROFILE = STAGE + '/abi3-startup-rmdir-v2.json'
PROFILE_MODULE = 'infra/evidence_rmdir_profile.py'
PROFILE_MODULE_SHA256 = '73300666b534c7fe1d36140ea7d28464c2ececaf1ab520f2c7afa483c4ecbbfc'
NEW_PROFILE_SHA256 = 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733'
DEDICATED_LOCK = STAGE + '/rmdir-profile.lock'
PROFILE_SHA256 = '389b9d083fc90982a51f999c9cfc1858cb660654d8d01dd5bc28da0a4e0523a7'
OWNED = 'ai/state/private-scanner-interpreter-owned.json'
OWNED_SHA = 'fc5e9cbeb20c4dfe733b2e21268300154d479a5610dc23bd55f812261d24ce71'
FAILED = 'ai/state/private-scanner-interpreter-suite-strict.json'
FAILED_SHA = '5e4c3ecf276264ee5849313ec4c589ef9ff38552a89f0d6635ae216cc19cdfdb'
PREFIX = 'ai/state/private-scanner-rmdir-'
SCOPE = 'PUBLIC_RMDIR_PROFILE_CORRECTION_ONLY'
FLOOR = 2 * 1024**3
_LIVE_SEAL = object()
SOURCE_PINS = {
 'infra/evidence_scratch_diagnostic.py':'e259821dcf8ad4f9eb9d36dbd0b21b1c741b219981fe0da4f96496fec2b4b690',
 'infra/evidence_interpreter_compile.py':'4822490b0d38f487ddd06c1a9760e8c3783dec627634a7bc630179a84e683085',
 'infra/evidence_interpreter_runtime.py':'bc7b15fd9b1d202e07a43b07c626b131a1fdc029bd367ed6baa974a5378951b0',
 'infra/evidence_interpreter_prepare.py':'c872db46201610ce2cb4f6f0bb5419d8145996b83be619cb1edf7625191c33fb',
 'infra/evidence_interpreter_oci.py':'339caf0d659a8a995a66ee40476dcd8874816692036e9d466f4312f153bdb40b',
 'infra/evidence_postcompile_diagnostic.py':'5a24dbfa6de043730faa10c9ec3a8ba46fff8446d44fa82401977698dfda69ff',
 'infra/evidence_postcompile_continuation.py':'43411a87c68935ecf3989017b2a541fac2b43bf56c4f578d3a602aee39723bac',
 'infra/evidence_native_ownership.py':'6544725a99a0d9941db347ea3c81b8d3e8ea8f58ae88886289c320ee6f2ef4d1',
}

class DiagnosticUnavailable(RuntimeError):
 def __init__(self, code='SCRATCH_DIAGNOSTIC_REFUSED'):
  self.code=code
  super().__init__(code)

def require(value, code='SCRATCH_DIAGNOSTIC_REFUSED'):
 if value is not True: raise DiagnosticUnavailable(code)

def modules():
 from infra import evidence_native_refresh_runtime as refresh
 from infra import evidence_native_runtime as runtime
 from infra import evidence_native_attestation as attestation
 from infra import evidence_native_ownership as ownership
 from infra import evidence_container as base
 return refresh,runtime,attestation,ownership,base

def checked_constants():
 require(type(PROGRAM_SHA256) is str and re.fullmatch('[0-9a-f]{64}',PROGRAM_SHA256) is not None,
         'PROGRAM_NOT_REVIEWED')
 require(type(PROFILE_MODULE_SHA256) is str and re.fullmatch('[0-9a-f]{64}', PROFILE_MODULE_SHA256) is not None, 'PROFILE_NOT_REVIEWED')

def receipt_path(operation):
 require(type(operation) is str and operation in ('prepare','preflight','rmdir','lifecycle'))
 return PREFIX+operation+'.json'
class Commands:
    """Bounded fixed-endpoint authless controls; uncertainty is sticky."""
    def __init__(self, docker, config):
        self.docker, self.config = docker, config
        self.count = 0; self.uncertain = False

    def __call__(self, *args, timeout=15):
        refresh, _, _, _, base = modules()
        try:
            require(0 < timeout <= 15 and self.count < 64)
            self.count += 1
            argv = [str(self.docker), '--host', refresh.HOST, '--config', str(self.config), *args]
            require(len(subprocess.list2cmdline(argv)) < 30000)
            result = base._bounded_command(argv, timeout=timeout, maximum=65536)
            code, out, err, reason = result
            require(type(code) is int and type(out) is bytes and type(err) is bytes
                and len(out) <= 65536 and len(err) <= 65536 and reason == 'EXIT')
            return result
        except BaseException:
            self.uncertain = True
            raise

def engine(call):
    code, out, err, reason = call('info', '--format', '{{.ID}}')
    require(code == 0 and reason == 'EXIT' and not err and 1 <= len(out) <= 256)
    value = out.rstrip(b'\r\n')
    require(value and b'\n' not in value and b'\r' not in value
        and hashlib.sha256(value).hexdigest() == ENGINE, 'ENGINE_CHANGED')

class Observation:
    """Only created by fresh same-engine observations; no serialized clearance."""
    def __init__(self, seal, created, clock=time.monotonic):
        require(seal is _LIVE_SEAL)
        self.created, self.clock, self.used = created, clock, False

    def consume(self):
        require(not self.used and 0 <= self.clock() - self.created <= 5, 'LIVE_POSTFLIGHT_STALE')
        self.used = True

def create_args(probe, profile):
    _, runtime, _, _, _ = modules()
    require(type(probe) is Probe and probe.fixed == metadata(probe.phase.token, probe.operation, probe.fixed['preparation_sha256']))
    original = runtime.create_args(probe.phase, profile_path=profile)
    require(original[-7:] == [IMAGE, *probe.phase.command])
    args = []; index = 0
    while index < len(original) - 7:
        if original[index] == '--label': index += 2; continue
        if original[index] == '--name': args.extend(['--name', probe.name]); index += 2; continue
        args.append(original[index]); index += 1
    for key, value in sorted(probe.labels.items()): args.extend(['--label', key + '=' + value])
    args += [IMAGE, *probe.command]
    require(len(subprocess.list2cmdline(args)) < 28000)
    return args

def inspection(value, probe, cid):
    _, runtime, _, _, _ = modules()
    from infra import evidence_container_native as public
    require(type(value) is dict and value.get('Id') == cid and value.get('Name') == '/' + probe.name
        and value.get('Image') == IMAGE and type(value.get('Config')) is dict
        and value['Config'].get('Labels') == probe.labels and value['Config'].get('Cmd') == probe.command)
    require(public._environment(value['Config'].get('Env')) == runtime.EFFECTIVE_ENV,
        'DIAGNOSTIC_ENVIRONMENT_CHANGED')
    from infra import evidence_rmdir_profile as profile_module
    normalized = profile_module.normalize_inspection(value)
    normalized['Name'] = '/' + probe.phase.name
    normalized['Config'].update(Labels=probe.phase.labels, Cmd=probe.phase.command)
    runtime.verify_inspection(normalized, probe.phase, container_id=cid)

def inspect(call, selector):
    refresh, _, _, _, _ = modules()
    code, out, err, reason = call('container', 'inspect', selector)
    require(code == 0 and reason == 'EXIT' and not err)
    values = refresh.document(b'{"items":' + out + b'}')['items']
    require(type(values) is list and len(values) == 1 and type(values[0]) is dict)
    return values[0]

def check_owner(value, probe, cid):
    require(value.get('Id') == cid and value.get('Name') == '/' + probe.name and value.get('Image') == IMAGE
        and value.get('Config', {}).get('Labels') == probe.labels, 'DIAGNOSTIC_OWNERSHIP_UNCONFIRMED')

def cleanup(call, probe, cid, attempted):
    status = 'NOT_CREATED'
    if attempted:
        if cid is None:
            code, out, err, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
                'name=^/' + probe.name + '$', '--format', '{{.ID}}')
            require(code == 0 and reason == 'EXIT' and not out.strip() and not err)
            status = 'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED'
        else:
            value = inspect(call, cid); check_owner(value, probe, cid)
            if value.get('State', {}).get('Running') is True:
                code, _, err, reason = call('container', 'kill', '--signal', 'KILL', cid)
                require(code == 0 and reason == 'EXIT' and not err)
            value = inspect(call, cid); check_owner(value, probe, cid)
            state = value.get('State', {})
            require(state.get('Running') is False and state.get('Restarting') is False
                and type(state.get('Pid')) is int and state['Pid'] == 0)
            code, _, err, reason = call('container', 'rm', cid)
            require(code == 0 and reason == 'EXIT' and not err)
            code, out, err, reason = call('container', 'ls', '--all', '--no-trunc', '--filter', 'id=' + cid, '--format', '{{.ID}}')
            require(code == 0 and reason == 'EXIT' and not out.strip() and not err)
            status = 'ORIGINAL_ID_ABSENT_VERIFIED'
    return status

def old_profile_source(root, pins, api):
    """Exact inherited public-profile pin contract; caller holds protected parent.

    The existing attestation pins this public file for identity, reparse and
    hardlink safety, then checks its fixed bytes. It is not a private-file DACL.
    """
    refresh, _, _, _, base = modules()
    from infra import evidence_container_native as public
    raw = refresh.pin_bytes(root, pins, api, OLD_PROFILE, expected=PROFILE_SHA256)
    require(raw == base.canonical(public.startup_profile()), 'PROFILE_BYTES_CHANGED')
    return raw


def metadata(token, operation, preparation_sha256):
 _,_,_,owned,_=modules()
 require(operation in ('rmdir','lifecycle') and type(operation) is str)
 require(type(token) is str and owned.TOKEN.fullmatch(token) is not None)
 checked_constants()
 require(type(preparation_sha256) is str and re.fullmatch('[0-9a-f]{64}',preparation_sha256) is not None)
 purpose='public-rmdir-profile-'+operation+'-only'
 labels={'org.kapit.owner':OWNER,'org.kapit.run':token,'org.kapit.reservation':token,
  'org.kapit.purpose':purpose,'org.kapit.mode':'scan','org.kapit.policy':OLD_POLICY,
  'org.kapit.scenario':operation,'org.kapit.probe':PROGRAM_SHA256,'org.kapit.generation':GENERATION,
  'org.kapit.profile':NEW_PROFILE_SHA256,'org.kapit.preparation':preparation_sha256}
 result={'schema':1,'token':token,'image_id':IMAGE,'signature_generation':GENERATION,
  'purpose':purpose,'mode':'scan','scenario':operation,'phase':'diagnostic','source_policy':OLD_POLICY,
  'source_sha256':PROGRAM_SHA256,'profile_sha256':NEW_PROFILE_SHA256,'preparation_sha256':preparation_sha256,
  'expected_name':'kapit-rmdir-public-'+token,
  'expected_labels':labels,'native_eligible':False,'private_input_allowed':False}
 owned._canonical(result)
 return result

@contextmanager
def reserve(token, operation, preparation_sha256):
 _,_,_,owned,_=modules()
 fixed=metadata(token,operation,preparation_sha256);host=owned._Host(token);journal=None
 try:
  host.__enter__();journal=owned._Journal(host,fixed)
  journal._save('reservation.json',fixed)
  yield journal
 finally:
  if journal is None:host.close()
  elif not journal.closed:journal.finish('CLEANUP_UNCONFIRMED')

@dataclass(frozen=True)
class Probe:
 phase:object
 fixed:dict
 program:str
 operation:str
 @property
 def name(self):return self.fixed['expected_name']
 @property
 def labels(self):return self.fixed['expected_labels']
 @property
 def command(self):return ['-I','-B','-c',self.program]

def transport(raw,operation):
 checked_constants()
 require(operation in ('rmdir','lifecycle') and type(operation) is str)
 require(type(raw) is bytes and 0<len(raw)<=16384 and hashlib.sha256(raw).hexdigest()==PROGRAM_SHA256)
 encoded=base64.b64encode(raw).decode('ascii')
 return ("import base64,hashlib,json\nraw=base64.b64decode('"+encoded+"',validate=True)\n"
  "assert hashlib.sha256(raw).hexdigest()=='"+PROGRAM_SHA256+"'\n"
  "namespace={'__name__':'kapit_fixed_scratch'}\n"
  "try:\n"
  " exec(compile(raw,'<fixed-public-scratch>','exec'),namespace)\n"
  " value=namespace['run']('"+operation+"')\n"
  " print(json.dumps(value,sort_keys=True,separators=(',',':')))\n"
  "except BaseException: raise SystemExit(2) from None\n"
  "raise SystemExit(0 if value['completed'] else 2)\n")

def absence(call,selector):
 require(type(selector) is str and (re.fullmatch('[0-9a-f]{64}',selector) is not None or
  re.fullmatch('kapit-(?:same-image|scratch|rmdir)-public-[0-9a-f]{32}',selector) is not None))
 code,out,err,reason=call('container','inspect',selector)
 require(type(code) is int and code==1 and reason=='EXIT' and out in (b'[]',b'[]\n',b'[]\r\n') and
  err in tuple(('Error response from daemon: No such container: '+selector+end).encode('ascii')
   for end in ('','\n','\r\n')),'ORIGINAL_ABSENCE_UNCONFIRMED')

def live_absences(call,rows):
 require(type(rows) is list and 1<=len(rows)<=14)
 for offset in range(0,len(rows),8):
  batch=Commands(call.docker,call.config);started=time.monotonic()
  engine(batch)
  for row in rows[offset:offset+8]:
   absence(batch,row['original_id']);absence(batch,row['expected_name'])
  engine(batch)
  require(not batch.uncertain and time.monotonic()-started<300)

def journal_documents(root,pins,api,token,expected,cid,files=None):
 from infra import evidence_interpreter_runtime as current
 from infra.live_recovery_drill import PrivateDirectory
 _,_,_,owned,_=modules()
 require(type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid) is not None and cid!='0'*64)
 directory=STAGE+'/native-run-'+token
 pins.enter_context(PrivateDirectory().pin(root/directory,private=True,directory=True))
 docs={'reservation.json':expected,
  'create-attempt.json':{'schema':1,'token':token,'create_attempted':True,'native_eligible':False},
  'ownership.json':dict(expected,original_id=cid),
  'result.json':{'schema':1,'token':token,'original_id':cid,
   'ownership_status':'ORIGINAL_ID_ABSENT_VERIFIED','native_eligible':False}}
 if files is not None:require(type(files) is dict and set(files)==set(docs))
 copied={}
 for name,doc in docs.items():
  raw=current.pin_bytes(root,pins,api,directory+'/'+name,private=True,maximum=8192)
  require(raw==owned._canonical(doc) and current.document(raw)==doc,'ORIGINAL_JOURNAL_CHANGED')
  row={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'document':doc}
  if files is not None:require(row==files[name],'ORIGINAL_JOURNAL_CHANGED')
  copied[name]=row
 return {'directory':directory,'token':token,'original_id':cid,
  'expected_name':expected['expected_name'],'files':copied}

def interpreter_original_documents(root,pins,api):
 from infra import evidence_interpreter_runtime as current
 _,_,_,owned,_=modules()
 failure=current.document(current.pin_bytes(root,pins,api,FAILED,expected=FAILED_SHA))
 require(failure.get('status')=='REFUSED' and failure.get('image_id')==IMAGE and
  failure.get('signature_generation')==GENERATION and failure.get('pins_closed') is True and
  failure.get('active_case')=={'name':'strict','mode':'scan'} and failure.get('results')==[] and
  failure.get('diagnostic',{}).get('result',{}).get('diagnostic')==
   {'kind':'VALUE_ERROR','location':{'function':'_scratch_empty','line':131,'source':'WORKER'},'stage':'SCRATCH_CLEANUP'})
 binding=current.document(current.pin_bytes(root,pins,api,OWNED,expected=OWNED_SHA))
 require(binding.get('status')=='VERIFIED' and binding.get('image_id')==IMAGE and
  binding.get('signature_generation')==GENERATION and binding.get('pins_closed') is True and
  binding.get('native_eligible') is False and binding.get('private_input_allowed') is False and
  binding.get('same_engine_sha256')==ENGINE and type(binding.get('journals')) is list and len(binding['journals'])==11)
 rows=[]
 for row in binding['journals']:
  require(type(row) is dict and type(row.get('files')) is dict)
  saved=row['files']['reservation.json']['document']
  expected=owned._metadata(**{key:saved[key] for key in ('token','image_id','signature_generation',
   'purpose','mode','scenario','phase','source_policy','expected_labels')})
  require(saved==expected and expected['image_id']==IMAGE and expected['signature_generation']==GENERATION)
  actual=journal_documents(root,pins,api,row['token'],expected,row['original_id'],row['files'])
  require(all(row.get(key)==actual[key] for key in actual))
  rows.append(actual)
 require(len({row['original_id'] for row in rows})==11 and len({row['token'] for row in rows})==11)
 return rows

def oci_bytes(root,pins,api,actual):
 from infra import evidence_interpreter_runtime as current
 from infra import evidence_interpreter_oci as oci
 from infra.live_recovery_drill import PrivateDirectory
 acquisition=current.document(current.pin_bytes(root,pins,api,
  'ai/state/private-scanner-interpreter-oci-acquisition.json',
  expected='6cce2ecd3451fce9fea4cce466aba005d5557b29d7077b5eaa51bc96a6d075e3'))
 proof=current.document(current.pin_bytes(root,pins,api,'ai/state/private-scanner-interpreter-oci-verified.json',
  expected='89fcfe31b3cc3f6887c25954747c5c3fd71596d815d22c48ef5e15e1e5107919'))
 require(acquisition.get('status')=='ACQUIRED_AND_OCI_BYTES_VERIFIED' and acquisition.get('pins_closed') is True and
  acquisition.get('image_id')==IMAGE and acquisition.get('cli_reaped') is True and acquisition.get('cli_uncertain') is False)
 directory=acquisition.get('directory')
 require(type(directory) is str and re.fullmatch(re.escape(STAGE)+'/oci-interpreter-[0-9a-f]{32}',directory) is not None)
 pins.enter_context(PrivateDirectory().pin(root/directory,private=True,directory=True))
 archive=root/directory/'image.tar'
 stream=pins.enter_context(api.pin(archive,private=True))
 observed=oci.verify_archive(stream,archive,oci.inventory(archive),actual,acquisition,deadline=time.monotonic()+120)
 require(proof==dict(observed,pins_closed=True),'OCI_BYTES_CHANGED')

def provenance(root,pins,api,operation,preparation):
 from infra import evidence_interpreter_runtime as current
 path=receipt_path(operation)
 value=current.document(current.pin_bytes(root,pins,api,path))
 require(type(value.get('schema')) is int and value.get('schema')==1 and value.get('scope')==SCOPE and value.get('stage')==operation and
  value.get('status')==('PREPARED' if operation=='prepare' else 'VERIFIED' if operation=='preflight' else 'OBSERVED') and value.get('completed') is True and
  value.get('image_id')==IMAGE and value.get('signature_generation')==GENERATION and
  value.get('program_sha256')==PROGRAM_SHA256 and value.get('source_pins')==SOURCE_PINS and
  value.get('pins_closed') is True and value.get('cli_cleanup_confirmed') is True and
  value.get('native_eligible') is False and value.get('private_input_allowed') is False and
  'failed_stage' not in value and 'failure_code' not in value and
  type(value.get('total_seconds')) in (int,float) and 0<=value['total_seconds']<600,'PRIOR_OPERATION_UNCONFIRMED')
 require(set(value)=={'schema','scope','stage','status','completed','native_eligible','private_input_allowed',
  'control_state_modified','pins_closed','cli_cleanup_confirmed','image_id','signature_generation',
  'program_sha256','source_pins','completed_stages','controller_sha256','total_seconds',
  'profile_sha256','profile_module_sha256','preparation','preparation_sha256'} | (set() if operation in ('prepare','preflight') else
  {'measurement','reservation','original_id','cleanup','original_journal','same_engine_sha256','correction_observed'}),'PRIOR_SCHEMA_CHANGED')
 require(value.get('controller_sha256')==hashlib.sha256(current.pin_bytes(root,pins,api,'infra/evidence_rmdir_diagnostic.py')).hexdigest(),'PRIOR_SOURCE_CHANGED')
 require(value.get('control_state_modified') is (operation=='prepare') and value.get('completed_stages')==expected_stages(operation),'PRIOR_OPERATION_UNCONFIRMED')
 require(value.get('profile_sha256')==NEW_PROFILE_SHA256 and value.get('profile_module_sha256')==PROFILE_MODULE_SHA256 and
  value.get('preparation')==preparation and value.get('preparation_sha256')==binding_digest(preparation),'PREPARATION_CHANGED')
 if operation in ('prepare','preflight'):
  require('measurement' not in value and 'reservation' not in value)
 else:
  from infra.native import scratch_probe as program
  frame=json.dumps(value.get('measurement'),separators=(',',':')).encode('ascii')
  require(program.parse_result(frame,operation)['completed'] is True)
  require(value.get('cleanup')=='ORIGINAL_ID_ABSENT_VERIFIED' and value.get('same_engine_sha256')==ENGINE)
  require(value.get('correction_observed') is True and correction_observed(value['measurement'],operation),'CORRECTION_NOT_OBSERVED')
  expected=metadata(value.get('reservation'),operation,binding_digest(preparation))
  actual=journal_documents(root,pins,api,expected['token'],expected,value.get('original_id'),
   value.get('original_journal',{}).get('files'))
  require(value.get('original_journal')==dict(actual,original_cid_and_name_absent_live=True))
  return actual
 return value

def unknown_diagnostics(root,pins,api,allowed,preparation_sha256):
 from infra import evidence_interpreter_runtime as current
 from infra.live_recovery_drill import PrivateDirectory
 directories=list(islice((root/STAGE).glob('native-run-*'),257))
 require(len(directories)<=256,'UNKNOWN_DIAGNOSTIC')
 for directory in directories:
  require(re.fullmatch('native-run-[0-9a-f]{32}',directory.name) is not None)
  pins.enter_context(PrivateDirectory().pin(directory,private=True,directory=True))
  raw=current.pin_bytes(root,pins,api,(directory/'reservation.json').relative_to(root).as_posix(),private=True,maximum=8192)
  value=current.document(raw)
  labels=value.get('expected_labels')
  require(type(value.get('schema')) is int and value['schema']==1 and
   value.get('token')==directory.name.removeprefix('native-run-') and
   type(value.get('image_id')) is str and re.fullmatch('sha256:[0-9a-f]{64}',value['image_id']) is not None and
   type(value.get('signature_generation')) is str and re.fullmatch('[0-9a-f]{64}',value['signature_generation']) is not None and
   value.get('native_eligible') is False and type(value.get('purpose')) is str and bool(value['purpose']) and
   type(labels) is dict and all(type(key) is str and type(item) is str for key,item in labels.items()) and
   bool(labels.get('org.kapit.owner')) and bool(labels.get('org.kapit.purpose')) and
   labels.get('org.kapit.reservation')==value['token'],'UNKNOWN_DIAGNOSTIC')
  if value.get('expected_labels',{}).get('org.kapit.owner')==OWNER or str(value.get('purpose','')).startswith('public-rmdir-profile-'):
   require(value.get('token') in allowed and value==metadata(value['token'],'rmdir',preparation_sha256) and directory.name=='native-run-'+value['token'],'UNKNOWN_DIAGNOSTIC')


def fresh_observation(call,rows,oldcall):
 from infra import evidence_interpreter_compile as compiler
 compiler.live_originals(oldcall).consume()
 live_absences(call,rows)
 require(not call.uncertain and not oldcall.uncertain)
 return Observation(_LIVE_SEAL,time.monotonic())

def run_probe(root,call,profile,raw,observation,result,operation):
 _,runtime,attestation,_,_=modules()
 from backend.apps.operations import evidence_scan_protocol as protocol
 from infra.native import scratch_probe as program
 token=uuid.uuid4().hex
 phase=runtime._Phase(runtime.Candidate(IMAGE,GENERATION),
  protocol.Binding('scan',secrets.token_hex(32),OLD_POLICY,GENERATION),token)
 probe=Probe(phase,metadata(token,operation,result['preparation_sha256']),transport(raw,operation),operation)
 args=create_args(probe,profile)
 cid=None;attempted=False;journal_uncertain=False;primary=None;payload=None;started=time.monotonic()
 with reserve(token,operation,result['preparation_sha256']) as journal:
  try:
   journal.mark_create_attempted()
   observation.consume()
   attempted=True
   code,out,err,reason=call(*args)
   cid=runtime._original_create_id(out)
   if cid is not None:
    try:journal.record_original(cid)
    except BaseException:journal_uncertain=True;raise
   require(code==0 and reason=='EXIT' and not err and cid is not None)
   result.update(original_id=cid,reservation=token)
   runtime._require_cgroup_v2(call);inspection(inspect(call,cid),probe,cid);runtime._require_cgroup_v2(call)
   attach_started=time.monotonic()
   cli_exit,output=attestation._attach([str(call.docker),'--host',modules()[0].HOST,'--config',str(call.config),
    'container','start','--attach','--interactive',cid],timeout=runtime.LIMITS['scan'][2])
   require(time.monotonic()-attach_started<runtime.LIMITS['scan'][2],'ATTACH_FINAL_DEADLINE')
   require(type(output) is bytes and len(output)<=4096,'OUTPUT_LIMIT')
   runtime._require_cgroup_v2(call)
   after=inspect(call,cid);inspection(after,probe,cid);state=after['State']
   require(type(cli_exit) is int and cli_exit==0 and state.get('OOMKilled') is False and
    type(state.get('ExitCode')) is int and state['ExitCode']==0 and type(state.get('Pid')) is int and state['Pid']==0)
   payload=program.parse_result(output,operation)
   require(payload['completed'] is True,'PROGRAM_INCOMPLETE')
  except BaseException as error:primary=error
  finally:
   uncertain=False
   try:status=cleanup(call,probe,cid,attempted)
   except BaseException:status='CLEANUP_UNCONFIRMED';uncertain=True
   uncertain=uncertain or call.uncertain or journal_uncertain or journal.failed
   try:journal.finish('CLEANUP_UNCONFIRMED' if uncertain else status)
   except BaseException:uncertain=True
   result['cleanup']='UNCONFIRMED' if uncertain else status
   if uncertain:raise DiagnosticUnavailable('DIAGNOSTIC_CLEANUP_UNCONFIRMED') from None
  require(time.monotonic()-started<240 and shutil.disk_usage(root).free>=FLOOR,'DIAGNOSTIC_FINAL_LIMIT')
  if primary is not None:raise primary
 require(payload is not None)
 return payload


@contextmanager
def existing_lock_guard():
 # Retain existing writable-sharing handles without writing any bytes or ACL.
 # This prohibits the compiler facade's create-if-absent branch on preflight.
 from infra.evidence_tools import Windows
 from infra.evidence_postcompile_continuation import exact_lock
 api=Windows()
 with ExitStack() as retained:
  for name,private in (('resume-pcre.lock',False),('interpreter.lock',True)):
   path=ROOT/STAGE/name
   stream=retained.enter_context(api.pin(path,writable=True,private=private))
   exact_lock(stream,path)
  yield


def binding_digest(value):
 return hashlib.sha256(modules()[4].canonical(value)).hexdigest()

def entry_identity(path):
 from infra.evidence_tools import checked
 value=checked(path).stat()
 require(value.st_ino>0 and value.st_dev>0 and value.st_nlink>=1,'IDENTITY_UNCONFIRMED')
 return {'volume':str(value.st_dev),'file_id':str(value.st_ino)}

class FileIdentity(ctypes.Structure):
 _fields_=[('volume',ctypes.c_ulonglong),('identifier',ctypes.c_ubyte*16)]

def stream_identity(stream,path,api):
 from infra.evidence_tools import checked
 from infra.evidence_postcompile_continuation import lock_runtime
 value=os.fstat(stream.fileno());entry=checked(path).stat()
 identity=FileIdentity();query=api.k.GetFileInformationByHandleEx
 query.argtypes,query.restype=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD],wintypes.BOOL
 require(ctypes.sizeof(FileIdentity)==24 and FileIdentity.identifier.offset==8 and
  bool(query(lock_runtime().get_osfhandle(stream.fileno()),18,ctypes.byref(identity),ctypes.sizeof(identity))),
  'FULL_IDENTITY_UNAVAILABLE')
 identifier=int.from_bytes(bytes(identity.identifier),'little')
 require(stat.S_ISREG(value.st_mode) and value.st_nlink==1 and
  stat.S_ISREG(entry.st_mode) and entry.st_nlink==1 and
  value.st_size==entry.st_size and identity.volume==entry.st_dev and identifier==entry.st_ino,
  'IDENTITY_UNCONFIRMED')
 return entry_identity(path)

def create_profile(path,api,raw):
 """Exclusive inherited public file, same created handle through fsync/close.

 No security descriptor, permission repair, replace, delete or existing adoption.
 Retained protected ancestors are owned by compiler.checked_inputs().
 """
 from infra.evidence_tools import checked
 from infra.evidence_postcompile_continuation import lock_runtime
 checked(path.parent)
 require(not path.exists() and not path.is_symlink(),'PROFILE_EXISTS')
 handle=None;fd=None;stream=None;identity=None
 try:
  handle=api.k.CreateFileW(str(path),0x20000|0x80000000|0x40000000,
   1,None,1,0x00200000,None)
  require(handle not in (None,ctypes.c_void_p(-1).value),'PROFILE_CREATE_REFUSED')
  fd=lock_runtime().open_osfhandle(handle,os.O_BINARY|os.O_RDWR);handle=None
  stream=os.fdopen(fd,'r+b',buffering=0);fd=None
  require(stream.write(raw)==len(raw),'PROFILE_WRITE_UNCONFIRMED')
  stream.flush();os.fsync(stream.fileno());stream.seek(0)
  require(stream.read(len(raw)+1)==raw,'PROFILE_WRITE_UNCONFIRMED')
  identity=stream_identity(stream,path,api)
 finally:
  try:
   if stream is not None:stream.close();require(stream.closed,'PROFILE_CLOSE_UNCONFIRMED')
   elif fd is not None:os.close(fd)
  finally:
   if handle not in (None,ctypes.c_void_p(-1).value):
    require(bool(api.k.CloseHandle(handle)),'PROFILE_CLOSE_UNCONFIRMED')
 require(identity is not None and entry_identity(path)==identity,'PROFILE_IDENTITY_CHANGED')
 return identity

def profile_source(root,pins,api):
 from infra import evidence_interpreter_runtime as current
 from infra import evidence_rmdir_profile as profile_module
 raw=current.pin_bytes(root,pins,api,PROFILE,expected=NEW_PROFILE_SHA256)
 require(raw==profile_module.profile_bytes() and profile_module.profile_digest()==NEW_PROFILE_SHA256,
  'NEW_PROFILE_CHANGED')
 return raw

def preparation_record(root,profile_identity,lock_identity):
 return {'schema':1,'profile_path':PROFILE,'profile_sha256':NEW_PROFILE_SHA256,
  'profile_bytes':len(__import__('infra.evidence_rmdir_profile',fromlist=['profile_bytes']).profile_bytes()),
  'profile_identity':profile_identity,'lock_path':DEDICATED_LOCK,'lock_identity':lock_identity,
  'parent_identity':entry_identity(root/STAGE),'profile_module_sha256':PROFILE_MODULE_SHA256}

def prepare_objects(root,pins,api):
 from infra.evidence_postcompile_continuation import atomic_private_lock
 from infra import evidence_rmdir_profile as profile_module
 require(not (root/PROFILE).exists() and not (root/PROFILE).is_symlink() and
  not (root/DEDICATED_LOCK).exists() and not (root/DEDICATED_LOCK).is_symlink(),'PREPARATION_EXISTS')
 parent=entry_identity(root/STAGE)
 identity=create_profile(root/PROFILE,api,profile_module.profile_bytes())
 with atomic_private_lock(root/DEDICATED_LOCK,api) as created:
  require(created is True,'PREPARATION_EXISTS')
  lock_identity=entry_identity(root/DEDICATED_LOCK)
 require(entry_identity(root/STAGE)==parent,'PARENT_CHANGED')
 record=preparation_record(root,identity,lock_identity)
 prepared_objects(root,pins,api,record)
 return record

def prepared_objects(root,pins,api,record):
 from infra.evidence_postcompile_continuation import exact_lock
 require(type(record) is dict and set(record)=={'schema','profile_path','profile_sha256',
  'profile_bytes','profile_identity','lock_path','lock_identity','parent_identity','profile_module_sha256'},
  'PREPARATION_CHANGED')
 profile_source(root,pins,api)
 # Retained existing writable-sharing handle disallows deletion/recreation.
 stream=pins.enter_context(api.pin(root/DEDICATED_LOCK,private=True,writable=True))
 exact_lock(stream,root/DEDICATED_LOCK)
 observed=preparation_record(root,entry_identity(root/PROFILE),stream_identity(stream,root/DEDICATED_LOCK,api))
 require(type(record.get('schema')) is int and type(record.get('profile_bytes')) is int and record==observed,'PREPARATION_CHANGED')

def accepted_preparation(root,pins,api):
 from infra import evidence_interpreter_runtime as current
 raw=current.pin_bytes(root,pins,api,receipt_path('prepare'))
 value=current.document(raw)
 record=value.get('preparation')
 provenance(root,pins,api,'prepare',record)
 prepared_objects(root,pins,api,record)
 return record

SCRATCH_RECEIPTS={
 'preflight':'4985ba9d2b5a3a423849d17cd24a78fd9845a4780d52b2c0f4762ec5e898353a',
 'rmdir':'14f892f690b2341989602d64a70a714b244d7b66ee2f064bacfbc435094167f2',
 'lifecycle':'388d09843d68fa4efad7a089900de9bf6940417c906e079bd60a651b7e4f864a'}

def original_documents(root,pins,api):
 from infra import evidence_interpreter_runtime as current
 from infra import evidence_scratch_diagnostic as scratch
 rows=interpreter_original_documents(root,pins,api)
 for operation,expected in SCRATCH_RECEIPTS.items():
  current.pin_bytes(root,pins,api,scratch.receipt_path(operation),expected=expected)
  actual=scratch.provenance(root,pins,api,operation)
  if operation!='preflight':rows.append(actual)
 require(len(rows)==13 and len({row['original_id'] for row in rows})==13 and
  len({row['token'] for row in rows})==13,'ORIGINALS_CHANGED')
 return rows

def correction_observed(value,operation):
 if operation=='rmdir':return value.get('observation')=='REMOVED'
 require(operation=='lifecycle')
 return all(row['counts']=={'regular':0,'directory':0,'symlink':0,'other':0} and
  row['scan']==('CLEAN' if row['stage'] in ('strict_png','upstream_png') else 'NONE')
  for row in value['snapshots'])

def expected_stages(operation):
 if operation=='prepare':return ['INPUTS','OLD_PROFILE','EXCLUSIVE_PREPARATION','FINAL_LIMITS','INPUT_CLOSE','FINAL_CLI']
 names=['INPUTS','PREPARATION_PROVENANCE']
 if operation!='preflight':names+=['PREFLIGHT_PROVENANCE']
 if operation=='lifecycle':names+=['RMDIR_PROVENANCE']
 if operation!='preflight':names+=['DEDICATED_LOCK']
 names+=['PROFILE','IMAGE_PACKAGE_UTC','OCI_BYTES','ORIGINAL_DOCUMENTS','UNKNOWN_RESERVATIONS','CGROUP_LIMITS','LIVE_ORIGINALS']
 if operation!='preflight':names+=['PUBLIC_PROBE','NEW_ORIGINAL_JOURNALS','DEDICATED_LOCK_CLOSE']
 return names+['FINAL_LIMITS','INPUT_CLOSE','FINAL_CLI']

def receipt_set(root):
 paths=list(islice((root/'ai/state').glob('private-scanner-rmdir-*.json'),6))
 require(len(paths)<=4 and all(path.name in {Path(receipt_path(op)).name for op in
  ('prepare','preflight','rmdir','lifecycle')} for path in paths),'UNKNOWN_RECEIPT')

def execute(operation):
 checked_constants()
 require(Path.cwd().resolve()==ROOT and os.name=='nt','WINDOWS_ROOT_ONLY')
 path=receipt_path(operation)
 from infra import evidence_interpreter_compile as compiler
 from infra import evidence_interpreter_runtime as current
 from infra.evidence_postcompile_continuation import atomic_private_lock
 result={'schema':1,'scope':SCOPE,'stage':operation,'status':'REFUSED','completed':False,
  'native_eligible':False,'private_input_allowed':False,'control_state_modified':operation=='prepare',
  'pins_closed':False,'cli_cleanup_confirmed':False,'image_id':IMAGE,'signature_generation':GENERATION,
  'program_sha256':PROGRAM_SHA256,'source_pins':SOURCE_PINS,'completed_stages':[],
  'profile_sha256':NEW_PROFILE_SHA256,'profile_module_sha256':PROFILE_MODULE_SHA256,
  'preparation':None,'preparation_sha256':None}
 receipt=current.Receipt(ROOT/path,result)
 stage=None;failure=None;started=time.monotonic();payload=None;call=None;oldcall=None;body_completed=False
 def mark(name):
  nonlocal stage
  require(type(name) is str and name in CHECKPOINTS)
  if stage is not None:result['completed_stages'].append(stage)
  stage=name
 try:
  mark('INPUTS');receipt_set(ROOT)
  with existing_lock_guard(), compiler.checked_inputs() as (api,pins,oldcall,_):
   result['controller_sha256']=hashlib.sha256(current.pin_bytes(ROOT,pins,api,'infra/evidence_rmdir_diagnostic.py')).hexdigest()
   for name,expected in SOURCE_PINS.items():current.pin_bytes(ROOT,pins,api,name,expected=expected)
   current.pin_bytes(ROOT,pins,api,PROFILE_MODULE,expected=PROFILE_MODULE_SHA256)
   raw=current.pin_bytes(ROOT,pins,api,PROGRAM,maximum=16384,expected=PROGRAM_SHA256)
   require(not any((ROOT/receipt_path(value)).exists() for value in
    ('preflight','rmdir','lifecycle') if operation=='prepare'),'PRIOR_OPERATION_UNCONFIRMED')
   if operation=='prepare':
    mark('OLD_PROFILE');old_profile_source(ROOT,pins,api)
    mark('EXCLUSIVE_PREPARATION');prepared=prepare_objects(ROOT,pins,api)
   else:
    mark('PREPARATION_PROVENANCE');prepared=accepted_preparation(ROOT,pins,api)
   result.update(preparation=prepared,preparation_sha256=binding_digest(prepared))
   prior=None
   if operation=='preflight':
    require(not any((ROOT/receipt_path(value)).exists() for value in ('rmdir','lifecycle')),'PRIOR_OPERATION_UNCONFIRMED')
   elif operation in ('rmdir','lifecycle'):
    mark('PREFLIGHT_PROVENANCE');provenance(ROOT,pins,api,'preflight',prepared)
    require(operation=='lifecycle' or not (ROOT/receipt_path('lifecycle')).exists(),'PRIOR_OPERATION_UNCONFIRMED')
   if operation=='lifecycle':
    mark('RMDIR_PROVENANCE');prior=provenance(ROOT,pins,api,'rmdir',prepared)
   def gates():
    nonlocal call
    mark('PROFILE');old_profile_source(ROOT,pins,api);profile_source(ROOT,pins,api)
    mark('IMAGE_PACKAGE_UTC');actual=current.verified_image(ROOT,pins,api)
    require(actual.get('image_id')==IMAGE and actual.get('signature_generation')==GENERATION)
    mark('OCI_BYTES');oci_bytes(ROOT,pins,api,actual)
    mark('ORIGINAL_DOCUMENTS');rows=original_documents(ROOT,pins,api)
    if prior is not None:rows.append(prior)
    mark('UNKNOWN_RESERVATIONS');unknown_diagnostics(ROOT,pins,api,set() if prior is None else {prior['token']},result['preparation_sha256'])
    call=Commands(oldcall.docker,oldcall.config)
    mark('CGROUP_LIMITS');modules()[1]._require_cgroup_v2(call)
    require(shutil.disk_usage(ROOT).free>=FLOOR,'LOW_SPACE')
    mark('LIVE_ORIGINALS');observation=fresh_observation(call,rows,oldcall)
    if operation=='preflight':observation.consume();return None
    mark('PUBLIC_PROBE')
    measured=None
    try:measured=run_probe(ROOT,call,ROOT/PROFILE,raw,observation,result,operation)
    finally:engine(call)
    mark('NEW_ORIGINAL_JOURNALS')
    fixed=metadata(result['reservation'],operation,result['preparation_sha256'])
    row=journal_documents(ROOT,pins,api,result['reservation'],fixed,result['original_id'])
    live_absences(call,[row]);row['original_cid_and_name_absent_live']=True
    result.update(original_journal=row,same_engine_sha256=ENGINE)
    return measured
   if operation=='preflight':payload=gates()
   elif operation in ('rmdir','lifecycle'):
    mark('DEDICATED_LOCK')
    with atomic_private_lock(ROOT/DEDICATED_LOCK,api) as created:
     require(created is False,'PREPARED_LOCK_RECREATED')
     payload=gates();mark('DEDICATED_LOCK_CLOSE')
   mark('FINAL_LIMITS')
   require((call is None or not call.uncertain) and not oldcall.uncertain and shutil.disk_usage(ROOT).free>=FLOOR)
   body_completed=True;mark('INPUT_CLOSE')
  require(body_completed,'BODY_INCOMPLETE');result['pins_closed']=True
  mark('FINAL_CLI');require((call is None or not call.uncertain) and not oldcall.uncertain)
  result['cli_cleanup_confirmed']=True;result['completed_stages'].append(stage);stage=None
 except BaseException:
  failure=True;result['failure_code']='RMDIR_DIAGNOSTIC_REFUSED'
  if stage is not None:result['failed_stage']=stage
 finally:
  elapsed=time.monotonic()-started
  if not 0<=elapsed<600:failure=True;result['failure_code']='FINAL_DEADLINE'
  if failure is None:
   result.update(status='PREPARED' if operation=='prepare' else 'VERIFIED' if operation=='preflight' else 'OBSERVED',completed=True)
   if operation in ('rmdir','lifecycle'):
    result.update(measurement=payload,correction_observed=correction_observed(payload,operation))
  result['total_seconds']=round(elapsed,3)
  try:receipt.save(result);receipt.close()
  except BaseException:
   result.update(status='REFUSED',completed=False,failure_code='RECEIPT_CLOSE_UNCONFIRMED')
   result.pop('measurement',None);result.pop('correction_observed',None)
   try:
    if not receipt.stream.closed:receipt.save(result)
   except BaseException:pass
   try:receipt.close()
   except BaseException:pass
   raise DiagnosticUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
 require(failure is None)
 return result

CHECKPOINTS=('INPUTS','OLD_PROFILE','EXCLUSIVE_PREPARATION','PREPARATION_PROVENANCE','PREFLIGHT_PROVENANCE',
 'RMDIR_PROVENANCE','DEDICATED_LOCK','PROFILE','IMAGE_PACKAGE_UTC','OCI_BYTES','ORIGINAL_DOCUMENTS',
 'UNKNOWN_RESERVATIONS','CGROUP_LIMITS','LIVE_ORIGINALS','PUBLIC_PROBE','NEW_ORIGINAL_JOURNALS',
 'DEDICATED_LOCK_CLOSE','FINAL_LIMITS','INPUT_CLOSE','FINAL_CLI')

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('operation',choices=('prepare','preflight','rmdir','lifecycle'))
 value=execute(parser.parse_args().operation)
 print(json.dumps({'status':value['status'],'receipt':receipt_path(value['stage']),'native_eligible':False}),flush=True)
 if value.get('correction_observed') is False:raise SystemExit(2)

if __name__=='__main__':main()


