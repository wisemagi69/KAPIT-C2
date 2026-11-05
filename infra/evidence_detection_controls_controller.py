"""Protected PUBLIC detection-control comparison; inert and calibration-closed.

Fixed preflight/diagnostic only. No acceptance-suite retry or private activation.
Root retains externally reviewed canonical executing bytes through operation.
"""
from __future__ import annotations
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from dataclasses import dataclass,asdict
from datetime import datetime,timezone
import hashlib
from itertools import islice
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import sys
import time

PINNED_PRIOR=(('infra/native/strict_probe.py', '021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078'), ('infra/evidence_rmdir_native.py', '8c45db9e71e67656bdb20fb47c008d4c9419c7664e40010ef2adbbc5fc5deed0'), ('infra/evidence_rmdir_proof.py', '875cc59993b130316da12e1ba42c7580d4752e3e50d993f2673bcac64bef5acb'), ('infra/evidence_rmdir_profile.py', '73300666b534c7fe1d36140ea7d28464c2ececaf1ab520f2c7afa483c4ecbbfc'), ('infra/evidence_rmdir_diagnostic.py', '488c2b810b14e76f90ca5a1bf77e2599511d38cdcee51537d01908a0277b174f'), ('ai/state/private-scanner-rmdir-proof-strict.json', '793cc6f8c063451de4205f24ba6d7da1eb9e3db4016915771d53c9b6ca56632b'), ('ai/state/private-scanner-rmdir-proof-confinement.json', '38bb820b726ccdd63aee03048c18094eceeaaa0286352afda3e8e084e70fe59f'), ('ai/state/private-scanner-rmdir-proof-preflight.json', 'c28e6af994b05eb2f0fcbe6a5a461faafff165efb8f070c0117987d2bd767ed6'), ('ai/state/private-scanner-rmdir-prepare.json', '6794cfea93e71d39b4df6610be73f2a838f165350e8f61c94dff39fac98d184c'), ('ai/state/private-scanner-rmdir-preflight.json', 'b2188bdb777b3cbd151200bd5935959333f6d8de8eb0447c196e6e39cfb5f1b6'), ('ai/state/private-scanner-rmdir-rmdir.json', '2d30584ea4a7fc6ead0ef97d6af6ec1d3e25d5de50835e8b57c4ef27dcc36a66'), ('ai/state/private-scanner-rmdir-lifecycle.json', 'daebe1ab66825446eb7eef4dee6e67eedf2327fb1531b3f4824967087e947ba0'), ('infra/evidence_strict_failure_details.py', '53e1659253f48c69c7b4b11b8cdc1be758e58a123965198bb2ed87264868cd17'), ('infra/tests/test_strict_failure_details.py', 'ee0450ad68078118f56368531e9c860801394beab53a8e4d8c9584ed633b81e0'), ('infra/evidence_strict_identity_native.py', '09541b9b06aa0cb542060189a00c332e376ed0ade43a6a3c30c4d0cce224c702'), ('infra/evidence_strict_identity_provenance.py', 'bbed594d3a4df209da52fd7c2047f9d6440f21dab6e74ab1ce2628d2955ed41e'), ('infra/evidence_strict_identity_controller.py', '57f6ce840525cc3b7103f12c76f607e3d855a5144531593125036b8a172c6a75'), ('infra/tests/test_strict_identity_native.py', 'e6aeeb20e0d685eb46afcdbbcc285ee348a8bdc5be06e9a1c4677bc2875b5508'), ('infra/tests/test_strict_identity_provenance.py', 'c2166aab803e717fbbf94e5e8e7145f61e669885a7a85dc115aa77978cbcb60f'), ('infra/tests/test_strict_identity_controller.py', 'bcab5e5647ef50e72182712004b1c1235e786e540277ed54d597bf6a9a99970b'), ('ai/state/private-scanner-strict-identity-preflight.json', 'b4eb091896576885764c22061a14f4a4ebbceac70a4e2b435728fe883447d5e7'), ('ai/state/private-scanner-strict-identity-diagnostic.json', '7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00'), ('infra/evidence_strict_failure_categories.py', 'dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'), ('infra/tests/test_strict_failure_categories.py', '3d1509b474d686df86c960abfa78f2cddca411df21b6e5c09f4a41ac668eebdb'), ('infra/evidence_strict_category_native.py', 'ca07edf6d213f487bbd904aff1f0c922188bba49b3d183f725141fe884ea1906'), ('infra/evidence_strict_category_provenance.py', '4c0e432cbd6956c6525cd39aede199d041f28e11e46820d1b624d416c02948bb'), ('infra/evidence_strict_category_controller.py', '9a79b57949712f82990c323e3ca617f6a26170c0adfa10957de3d06102d1c671'), ('infra/tests/test_strict_category_native.py', 'cf0379a03f6c9ccba62e554327b6db8819ac054276a6bd1d4004f5bb60a78909'), ('infra/tests/test_strict_category_provenance.py', '7f8ee1bdea923e9dff4cac5e492b790c560d42d70304d40af4737e6b2d972350'), ('infra/tests/test_strict_category_controller.py', '5dfb84b182c0f4bfb68fd595c2db73ec0923a39bf2e48c8ace3f338a4c65c616'), ('ai/state/private-scanner-strict-category-preflight.json', '71c9569d33ce61aa9833bb6820514f8552db120de56e29794cf616f70ab2e973'), ('infra/evidence_strict_category_v2_native.py', 'eac33f8f4efc387878181b06d6041a8c6bc5621ee343be862e6cd1027739d40c'), ('infra/evidence_strict_category_v2_provenance.py', '2765f686193f6bce18f20aeed450a4cc83c5e277b38eacd6b4dc5da53190366c'), ('infra/evidence_strict_category_v2_controller.py', '0ad4d0bed59de2a5e6de25573ace28c8a7162e59baea008358cf38db0f1c9134'), ('infra/tests/test_strict_category_v2_native.py', '2c7bc937535717017a991642efaaabc17ffbfe19afc5e2bdfdbad7f9b64a5748'), ('infra/tests/test_strict_category_v2_provenance.py', '159a072d48829ae670564884d1e2dc2a2a535ea106dd449fcc1519fe91aa2b84'), ('infra/tests/test_strict_category_v2_controller.py', '6f28b4e86288924e747807c94931625a297bc8b1596d69fbb61a53783aaf2796'), ('docs/scanner-detection-control-plan.md', 'd15e2b5a0790e001490b7b8823b628e82711d5def4a612be32715533fa0f24dc'), ('ai/reports/security-detection-control-plan.md', '2da5810b59f600104f2959a8d80c2727e126c5893cdf6db6c310e618d17a4984'), ('ai/reports/scanner-category-diagnostic-integration.json', 'e1a4a3adfc7e2282e6e974d5f3a6b911b2aaaf8bca0057a165e7e98f1074f34b'), ('ai/reports/devops-category-cause-audit.md', '81f80d2cde2e7b00255fb2d47e754b61d170d4a7b0a38bb436b4716b81e7aa20'), ('ai/state/private-scanner-strict-category-v2-preflight.json', 'f360b5e4e2cfce59cca8f7c9397e49e9f0fb48ce025546b8cc36f4e0c6c3cd0a'), ('ai/state/private-scanner-strict-category-v2-diagnostic.json', '896d45b92c1db7ce640539ed9fff9fac017266c628b9839eb56b0f396eb02f7f'), ('infra/evidence_detection_controls.py', '137ebe3fcc2458e5ef56b4989371236385b0ab2fa4038812b24b9a7aa7336c03'), ('infra/tests/test_detection_controls.py', '3f930964a0127373913af1123cddf611411cc780fdf81f7a03209f10b60dceac'), ('ai/reports/detection-controls-parser-integration.json', 'cf2c3a338e26312a940b02058b3ba91e3bce4eb57e740f30bf72a36428a4f878'), ('ai/reports/qa-detection-controls-parser.md', '429ea5c7d1a8777e59671acab382dc1c9a8727397930339401a51bbf35faa2e0'), ('ai/reports/security-detection-controls-parser.md', 'eb0f83654fb69137c50283e22a5cd212c4af5338a43721bb9e979c2a5d3d9213'), ('backend/apps/operations/evidence_native_worker.py', '3cebed0fbccb579dc6890f28071b80936d194876c69957eb4820f2564713c991'), ('infra/native/detection_controls_probe.py', '1da130bb36efcf1763b8de439164596ea0d8af659dd53188f0b1099c44088677'), ('infra/tests/test_detection_controls_probe.py', '8b14ea4a6384eb4ab30b2662c48223ac5fca1d9b6f9cf92d19620d84da00511d'), ('ai/reports/detection-controls-program-integration.json', '7ba8ce6048eb2c9d6d94c72a820a68584c84f6e9abc37369e2351afa0e7ac6d1'), ('ai/reports/security-detection-controls-program.md', 'e49e22e5c81ad8599c9f46ed0edaa828e30e26d6ecaa0c28ec650145047e291e'), ('ai/reports/qa-detection-controls-program.md', 'c8e3799d2708b285625912470d789eaea907717bfaf923229779fdad59ef2610'), ('infra/evidence_detection_controls_provenance.py', '5c128db13977664e2ea9acaaf1b7fc4acfed49c386d29e8d76eed4c36b4f058f'), ('infra/tests/test_detection_controls_provenance.py', '45fd657e6eab140eff9cfd99748139dc88a5a2606208b2be6769414144c87df4'), ('ai/reports/detection-controls-provenance-integration.json', '6f46062fd46cb829cac7877ad7d411624bbda75e7c74314eacbb19b7005203ab'), ('ai/reports/security-detection-controls-provenance.md', '862463b08502ba67a05fe6b382bbc59cee511c019e56cd5755e0f5745da820be'), ('ai/reports/qa-detection-controls-provenance.md', '3d6678278c54c34ee51cd7c1659f46cd8152c7586b990272f70990538550a828'))

ROOT=Path(__file__).resolve().parents[1]
SCOPE='PUBLIC_DETECTION_CONTROLS_DIAGNOSTIC_ONLY'
CONTRACT='5be9b2d4233f7db867f29d4594bf52726736df10566943cecf953bc1bf477db1'
PHASE_ID='detection-controls:scan:comparison'
PREFIX='ai/state/private-scanner-detection-controls-'
NATIVE='infra/evidence_detection_controls_native.py'
NATIVE_SHA256='f235367f72d558e1e78c418f3be8034639d3b8b126674f5135527de1d2a8b581'
PROVENANCE='infra/evidence_detection_controls_provenance.py'
PROVENANCE_SHA256='5c128db13977664e2ea9acaaf1b7fc4acfed49c386d29e8d76eed4c36b4f058f'
PARSER_SHA256='137ebe3fcc2458e5ef56b4989371236385b0ab2fa4038812b24b9a7aa7336c03'
CONSUMED_SHA256='896d45b92c1db7ce640539ed9fff9fac017266c628b9839eb56b0f396eb02f7f'
PROBE_SHA256='1da130bb36efcf1763b8de439164596ea0d8af659dd53188f0b1099c44088677'
CONTRACT_PATH='docs/scanner-detection-control-controller-contract.json'
CALIBRATION_PATH='ai/state/private-scanner-detection-controls-calibration.json'
CALIBRATION_SHA256=None
CALIBRATION_LIMITS=(('runtime_floor_bytes',2147483648),('build_floor_bytes',6442450944),
 ('scan_memory_bytes',4294967296),('cpu_seconds',120),('attach_seconds',180),
 ('controller_seconds',300),('command_seconds',15),('reap_join_seconds',5),
 ('cleanup_command_limit',8),('stdout_bytes',4096),('stderr_discard_bytes',16384))
FLOOR=2*1024**3
STAGES=('preflight','diagnostic')
FINALIZERS=('context','phase_pins','dedicated_lock','input_resources','cli')
STATES=('NOT_REACHED','CONFIRMED','UNCONFIRMED')
FRESH_GATES=('SOURCE_PINS','CORRECTED_PREPARATION','IMAGE_PACKAGE_UTC','OCI_BYTES','PRESERVED_ORIGINALS',
 'UNKNOWN_RESERVATIONS','CGROUP_DISK','HISTORICAL_ORIGINAL_ABSENCE','CURRENT_ORIGINAL_ABSENCE')
_CONTEXT_SEAL=object()

class DiagnosticUnavailable(RuntimeError):
 def __init__(self,code='DETECTION_CONTROLS_DIAGNOSTIC_REFUSED'):
  allowed={'DETECTION_CONTROLS_DIAGNOSTIC_REFUSED','SOURCE_NOT_REVIEWED','CALIBRATION_NOT_REVIEWED',
   'UNKNOWN_RECEIPT','DEADLINE','LOW_SPACE','CLI_UNCONFIRMED','CLEANUP_COMMAND_REFUSED',
   'PREFLIGHT_ORIGINALS_CHANGED','BODY_EXCEPTION_SUPPRESSED','WINDOWS_ROOT_ONLY',
   'RECEIPT_INITIAL_CLOSE_UNCONFIRMED','RECEIPT_INITIAL_WRITE_REFUSED','RECEIPT_CLOSE_UNCONFIRMED',
   'CONTEXT_CLOSE_UNCONFIRMED','FINALIZER_UNCONFIRMED','FAILED_ORIGINAL_CAPTURE_UNCONFIRMED',
   'PHASE_PIN_CLOSE_UNCONFIRMED'}
  self.code=code if type(code) is str and code in allowed else 'DETECTION_CONTROLS_DIAGNOSTIC_REFUSED'
  super().__init__(self.code)

def require(value,code='DETECTION_CONTROLS_DIAGNOSTIC_REFUSED'):
 if value is not True:raise DiagnosticUnavailable(code)


def _reviewed_calibration():
 require(type(CALIBRATION_SHA256) is str and re.fullmatch('[0-9a-f]{64}',CALIBRATION_SHA256) is not None
  and CALIBRATION_SHA256!='0'*64,'CALIBRATION_NOT_REVIEWED')
 return CALIBRATION_SHA256


def _utc():return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _timestamp(value):
 require(type(value) is str and re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',value) is not None)
 result=datetime.strptime(value,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
 require(result.strftime('%Y-%m-%dT%H:%M:%SZ')==value)
 return result


def _validate_calibration(value,expected):
 keys={'schema','scope','status','completed','binding','limits','created_utc','expires_utc',
  'finalizers','native_eligible','private_input_allowed','control_state_modified'}
 require(type(value) is dict and set(value)==keys and type(value['schema']) is int and value['schema']==1
  and value['scope']=='PUBLIC_DETECTION_CONTROLS_CALIBRATION_ONLY' and value['status']=='CALIBRATED'
  and value['completed'] is True and value['native_eligible'] is False and value['private_input_allowed'] is False
  and value['control_state_modified'] is False and value['binding']==asdict(expected)
  and type(value['limits']) is dict and set(value['limits'])==dict(CALIBRATION_LIMITS).keys()
  and all(type(value['limits'][key]) is int and value['limits'][key]==limit for key,limit in CALIBRATION_LIMITS)
  and value['finalizers']=={name:'CONFIRMED' for name in FINALIZERS})
 created,expires=_timestamp(value['created_utc']),_timestamp(value['expires_utc'])
 require(0<(expires-created).total_seconds()<=3600 and created<=datetime.now(timezone.utc)<expires)
 return value


def calibration_provenance(root,pins,api,expected):
 _,current=_base()
 digest=_reviewed_calibration()
 value=current.document(current.pin_bytes(root,pins,api,CALIBRATION_PATH,expected=digest,maximum=262144))
 return _validate_calibration(value,expected)


def pending_path(stage):
 require(type(stage) is str and stage in STAGES)
 return PREFIX+stage+'.pending'


def _no_pending(root):
 """Absence only for FileNotFound; access/reparse/unknown errors refuse."""
 parent=(root/'ai/state').lstat()
 require(stat.S_ISDIR(parent.st_mode) and not getattr(parent,'st_file_attributes',0)&0x400)
 allowed={Path(CALIBRATION_PATH).name}|{Path(receipt_path(stage)).name for stage in STAGES}
 with os.scandir(root/'ai/state') as entries:
  discovered=list(islice(entries,4097))
 require(len(discovered)<=4096)
 for entry in discovered:
  require(type(entry.name) is str)
  if entry.name.casefold().startswith('private-scanner-detection-controls-'):require(entry.name in allowed)
 for stage in STAGES:
  try:(root/pending_path(stage)).lstat()
  except FileNotFoundError:continue
  raise DiagnosticUnavailable()


def _pending_windows():
 from infra.evidence_tools import Windows
 return Windows()


class _Pending:
 """Fresh refusal guard. Deletion uses only its exclusive original handle.

 This cannot serialize proof of its own last CloseHandle. Absence is therefore
 never sufficient without an externally observed normal controller return.
 """
 def __init__(self,stage):
  require(type(stage) is str and stage in STAGES)
  self.path=ROOT/pending_path(stage);self.handle=None;self.identity=None;self.closed=False
  self.parents=ExitStack();self._close_failed=False
  self.api=_pending_windows()
  try:
   for directory in (ROOT,ROOT/'ai',ROOT/'ai/state'):
    self.parents.enter_context(self.api.pin(directory,directory=True,private=False))
   self._create(stage)
  except BaseException:
   self.close()
   raise
 def _create(self,stage):
  import ctypes as c
  from ctypes import wintypes as w
  api=self.api
  self.payload=native()._json({'schema':1,'stage':stage,'contract':CONTRACT,
   'receipt':receipt_path(stage),'nonce':secrets.token_hex(16)})
  require(len(self.payload)<=1024)
  class Attributes(c.Structure):
   _fields_=[('length',w.DWORD),('descriptor',c.c_void_p),('inherit',w.BOOL)]
  descriptor=c.c_void_p()
  sids=list(dict.fromkeys(('S-1-5-18',api.user)))
  text='O:'+api.user+'D:P'+''.join('(A;;FA;;;'+sid+')' for sid in sids)
  require(bool(api.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(text,1,c.byref(descriptor),None)))
  try:
   try:
    attributes=Attributes(c.sizeof(Attributes),descriptor,False)
    handle=api.k.CreateFileW(str(self.path),0xc0030000,1,c.byref(attributes),1,0x00200080,None)
    require(type(handle) is int and handle not in (0,c.c_void_p(-1).value))
    self.handle=handle
   finally:require(not api.k.LocalFree(descriptor))
   require(api.verify_acl(self.handle,directory=False) is None)
   write=api.k.WriteFile
   write.argtypes,write.restype=[w.HANDLE,c.c_void_p,w.DWORD,c.POINTER(w.DWORD),c.c_void_p],w.BOOL
   flush=api.k.FlushFileBuffers;flush.argtypes,flush.restype=[w.HANDLE],w.BOOL
   written=w.DWORD(0);buffer=c.create_string_buffer(self.payload)
   require(bool(write(self.handle,buffer,len(self.payload),c.byref(written),None)) and written.value==len(self.payload))
   require(bool(flush(self.handle)))
   self.identity=self._verify()
  except BaseException:
   self.close()
   raise
 def _verify(self):
  import ctypes as c
  from ctypes import wintypes as w
  class Information(c.Structure):
   _fields_=[('attributes',w.DWORD),('creation',w.FILETIME),('access',w.FILETIME),('write',w.FILETIME),
    ('volume',w.DWORD),('size_high',w.DWORD),('size_low',w.DWORD),('links',w.DWORD),('index_high',w.DWORD),('index_low',w.DWORD)]
  class Identity(c.Structure):
   _fields_=[('volume',c.c_ulonglong),('identifier',c.c_ubyte*16)]
  require(self.handle is not None)
  basic=Information();identity=Identity();api=self.api
  query=api.k.GetFileInformationByHandle;query.argtypes,query.restype=[w.HANDLE,c.POINTER(Information)],w.BOOL
  full=api.k.GetFileInformationByHandleEx;full.argtypes,full.restype=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL
  kind=api.k.GetFileType;kind.argtypes,kind.restype=[w.HANDLE],w.DWORD
  require(c.sizeof(Identity)==24 and Identity.identifier.offset==8
   and bool(query(self.handle,c.byref(basic))) and bool(full(self.handle,18,c.byref(identity),c.sizeof(identity)))
   and kind(self.handle)==1 and not basic.attributes&(0x10|0x400) and basic.links==1)
  observed=self.path.lstat();identifier=int.from_bytes(bytes(identity.identifier),'little')
  require(stat.S_ISREG(observed.st_mode) and observed.st_nlink==1
   and not getattr(observed,'st_file_attributes',0)&0x400 and observed.st_dev==identity.volume
   and observed.st_ino==identifier and observed.st_size==len(self.payload)
   and (basic.size_high<<32|basic.size_low)==len(self.payload))
  result=(identity.volume,identifier,basic.attributes,basic.links)
  if self.identity is not None:require(result==self.identity)
  return result
 def commit(self):
  import ctypes as c
  from ctypes import wintypes as w
  self._verify()
  class Disposition(c.Structure):_fields_=[('delete',c.c_ubyte)]
  fn=self.api.k.SetFileInformationByHandle
  fn.argtypes,fn.restype=[w.HANDLE,c.c_int,c.c_void_p,w.DWORD],w.BOOL
  value=Disposition(1)
  require(bool(fn(self.handle,4,c.byref(value),c.sizeof(value))))
  self.close()
 def close(self):
  failed=self._close_failed
  if self.handle is not None:
   handle,self.handle=self.handle,None
   try:require(bool(self.api.k.CloseHandle(handle)))
   except BaseException:failed=True
  try:self.parents.close()
  except BaseException:failed=True
  self._close_failed=failed
  self.closed=not failed
  if failed:raise DiagnosticUnavailable()


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
 from infra import evidence_detection_controls_native as adapter
 return adapter

def reviewed_constants():
 for value in (NATIVE_SHA256,PROVENANCE_SHA256,PARSER_SHA256,PROBE_SHA256,CONSUMED_SHA256,CONTRACT):
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
 parser_sha256:str
 probe_sha256:str
 consumed_receipt_sha256:str
 contract:str

def binding(controller_sha256):
 reviewed_constants();require(type(controller_sha256) is str and re.fullmatch('[0-9a-f]{64}',controller_sha256) is not None)
 return _Binding('sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa',
  '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3',
  'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733',
  '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f',
  NATIVE_SHA256,controller_sha256,PROVENANCE_SHA256,PARSER_SHA256,PROBE_SHA256,CONSUMED_SHA256,CONTRACT)

def _pin_sources(root,pins,api,expected):
 from infra import evidence_interpreter_runtime as current
 for path,digest in PINNED_PRIOR:current.pin_bytes(root,pins,api,path,expected=digest)
 require(type(expected) is _Binding and expected==binding(expected.controller_sha256))
 fixed=(('infra/evidence_detection_controls_controller.py',expected.controller_sha256),
  (NATIVE,NATIVE_SHA256),(PROVENANCE,PROVENANCE_SHA256),
  ('infra/evidence_detection_controls.py',PARSER_SHA256),
  ('infra/native/detection_controls_probe.py',PROBE_SHA256),(CONTRACT_PATH,CONTRACT))
 for path,digest in fixed:current.pin_bytes(root,pins,api,path,expected=digest)
 from infra import evidence_detection_controls_provenance as provenance
 provenance.pin_sources(root,pins,api)
 calibration_provenance(root,pins,api,expected)
 return provenance


def receipt_path(stage):
 require(type(stage) is str and stage in STAGES)
 return PREFIX+stage+'.json'

def receipt_set(root,stage):
 require(type(stage) is str and stage in STAGES)
 paths=list(islice((root/'ai/state').glob('private-scanner-detection-controls-*'),6))
 allowed={Path(CALIBRATION_PATH).name}|{Path(receipt_path(value)).name
  for value in (('preflight',) if stage=='preflight' else STAGES)}|{Path(pending_path(value)).name for value in STAGES}
 require(len(paths)<=len(allowed) and len({path.name for path in paths})==len(paths)
  and all(path.name in allowed for path in paths),'UNKNOWN_RECEIPT')


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
 _no_pending(root)
 _,_,current=inherited()
 value=current.document(current.pin_bytes(root,pins,api,receipt_path('preflight'),maximum=262144))
 keys={'schema','scope','stage','status','completed','native_eligible','private_input_allowed','control_state_modified',
  'binding','finalizers','completed_stages','preserved_originals','new_original','observation','total_seconds','recorded_utc'}
 require(type(value) is dict and set(value)==keys and type(value.get('schema')) is int and value['schema']==1 and
  value['scope']==SCOPE and value['stage']=='preflight' and value['status']=='VERIFIED' and value['completed'] is True and
  value['native_eligible'] is False and value['private_input_allowed'] is False and value['control_state_modified'] is False and
  value['binding']==asdict(expected) and value['completed_stages']==expected_stages('preflight') and
  value['finalizers']=={name:'CONFIRMED' for name in FINALIZERS} and value['new_original'] is None and
  value['observation'] is None and type(value['total_seconds']) in (int,float) and 0<=value['total_seconds']<300)
 require(0<=(datetime.now(timezone.utc)-_timestamp(value['recorded_utc'])).total_seconds()<=300)
 rows=value['preserved_originals']
 require(type(rows) is list and len(rows)==28 and sum(len(row['files']) for row in rows)==112 and
  len({row['token'] for row in rows})==28 and len({row['original_id'] for row in rows})==28)
 return value


class _DeadlineCall:
 """Register every owned CLI and cap work by its whole-controller deadline."""
 def __init__(self,raw,deadline):self.raw=raw;self.deadline=deadline;self._uncertain=False
 @property
 def docker(self):return self.raw.docker
 @property
 def config(self):return self.raw.config
 @property
 def uncertain(self):return bool(self._uncertain or self.raw.uncertain)
 @uncertain.setter
 def uncertain(self,value):self._uncertain=bool(value) or self._uncertain
 def __call__(self,*args,timeout=15):
  try:
   require(type(timeout) in (int,float) and math.isfinite(timeout) and 0<timeout<=15)
   if self.deadline is not None:
    remaining=self.deadline-time.monotonic();require(remaining>0,'DEADLINE');timeout=min(timeout,remaining)
   result=self.raw(*args,timeout=timeout)
   if self.deadline is not None:require(time.monotonic()<self.deadline,'DEADLINE')
   return result
  except BaseException:self._uncertain=True;raise

def absence(call,selector):
 require(type(selector) is str and (re.fullmatch('[0-9a-f]{64}',selector) is not None or
  re.fullmatch('kapit-(?:same-image|scratch|rmdir|rmdir-proof|strict-identity|strict-category|strict-category-v2|detection-controls)-public-[0-9a-f]{32}',selector) is not None))
 code,out,err,reason=call('container','inspect',selector)
 require(type(code) is int and code==1 and reason=='EXIT' and out in (b'[]',b'[]\n',b'[]\r\n') and
  err in tuple(('Error response from daemon: No such container: '+selector+end).encode('ascii') for end in ('','\n','\r\n')))

def live_absences(call,rows):
 _,diagnostic,_=inherited()
 require(type(rows) is list and 1<=len(rows)<=29 and len({row['token'] for row in rows})==len(rows) and
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
 def __init__(self,seal,api,pins,oldcall,receipt,result,stage,prepared,expected,lock_stream,preflight_rows=None,deadline=None):
  require(seal is _CONTEXT_SEAL and type(expected) is _Binding and expected==binding(expected.controller_sha256) and
   stage in STAGES and result['binding']==asdict(expected))
  require((stage=='preflight' and preflight_rows is None) or (stage=='diagnostic' and type(preflight_rows) is list and len(preflight_rows)==28))
  self._seal=seal;self._binding=expected;self._api=api;self._pins=pins;self._oldcall=oldcall
  self._receipt=receipt;self._result=result;self._stage=stage;self._prepared=deepcopy(prepared);self._lock_stream=lock_stream
  self._call=None;self._cleanup_call=None;self._cleanup_count=0;self._observation=None;self._phase_pins=None
  self._active_token=None;self._returned_cid=None;self._closed=False;self._phase_attempted=False
  self._deadline=time.monotonic()+300 if deadline is None else deadline
  require(type(self._deadline) in (int,float) and math.isfinite(self._deadline))
  self._attach_attempted=False;self._attach_confirmed=False;self._attach_uncertain=False
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
 def _new_call(self,cleanup=False):
  call=_DeadlineCall(inherited()[1].Commands(self.docker,self.config),self._deadline)
  self._calls.append(call);return call
 def _live_absences(self,rows):
  require(type(rows) is list and 1<=len(rows)<=29 and len({row['token'] for row in rows})==len(rows) and
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
 def attach_timeout(self):
  _validate_context(self)
  require(not self._closed and time.monotonic()<self._deadline,'DEADLINE')
  require(shutil.disk_usage(ROOT).free>=FLOOR,'LOW_SPACE')
  require(not self._oldcall.uncertain and not any(call.uncertain for call in self._calls)
   and not self._helper_cli_incomplete and not self._attach_uncertain,'CLI_UNCONFIRMED')
  require(self._attach_attempted and not self._attach_notification)
  remaining=self._deadline-time.monotonic();require(remaining>0,'DEADLINE')
  return min(180,remaining)
 def attach_finalized(self,confirmed):
  _validate_context(self)
  require(self._attach_attempted and not self._attach_notification and type(confirmed) is bool)
  self._attach_notification=True
  if confirmed and not self._attach_uncertain:self._attach_confirmed=True
  else:self._attach_uncertain=True
 def _save(self):require(self._receipt.save(self._result) is None)
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
  if self._cleanup_call is None:self._cleanup_call=self._new_call(cleanup=True)
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
   require(len(rows)==28 and sum(len(row['files']) for row in rows)==112)
   if self._stage=='diagnostic':require(rows==self._preflight_rows,'PREFLIGHT_ORIGINALS_CHANGED')
   gate='UNKNOWN_RESERVATIONS'
   provenance._reservations(ROOT,stack,self._api,rows,current,diagnostic)
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
  self._result.update(active_case='detection-controls',active_phase=PHASE_ID,active_token=token)
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
   prior=_prior_postflight(ROOT,self._phase_pins,self._api,self._prepared)
   require(prior==self._result['preserved_originals'])
   combined=prior+[journal]
   _postflight_reservations(ROOT,self._phase_pins,self._api,combined,self.binding)
   self._live_absences(combined);journal['original_cid_and_name_absent_live']=True
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
 """Exact all29 guard; the frozen strict28 guard remains unchanged."""
 _,diagnostic,current=inherited()
 from infra.live_recovery_drill import PrivateDirectory
 require(type(expected) is _Binding and expected==binding(expected.controller_sha256))
 require(type(rows) is list and len(rows)==29 and sum(len(row['files']) for row in rows)==116
  and len({row['token'] for row in rows})==29 and len({row['original_id'] for row in rows})==29)
 allowed={row['token']:row['files']['reservation.json']['document'] for row in rows}
 own=[row for row in rows if row['files']['reservation.json']['document']['expected_labels'].get('org.kapit.owner')==native().OWNER]
 require(len(own)==1)
 fixed=native().metadata(own[0]['token'],PHASE_ID,expected)
 require(native()._json(allowed[own[0]['token']])==native()._json(fixed))
 directories=list(islice((root/diagnostic.STAGE).glob('native-run-*'),257));require(len(directories)<=256)
 seen=set()
 for directory in directories:
  require(re.fullmatch('native-run-[0-9a-f]{32}',directory.name) is not None)
  token=directory.name[11:];require(token not in seen);seen.add(token)
  pins.enter_context(PrivateDirectory().pin(directory,private=True,directory=True))
  raw=current.pin_bytes(root,pins,api,(directory/'reservation.json').relative_to(root).as_posix(),private=True,maximum=8192)
  value=current.document(raw)
  require(token in allowed and type(value) is dict and value==allowed[token]
   and raw==native()._json(allowed[token]))
 require(seen==set(allowed))


def _prior_postflight(root,pins,api,prepared):
 # After our reservation exists, strict28 rejects it by design. Authenticate and
 # use its unchanged underlying category replay; then apply our strict29 guard.
 from infra import evidence_detection_controls_provenance as provenance
 current,category,old_provenance,expected=provenance._pin_sources(root,pins,api)
 value=current.document(current.pin_bytes(root,pins,api,provenance._RECEIPT,
  expected=dict(provenance.PINNED_INPUTS)[provenance._RECEIPT]))
 provenance._validate_consumed(value,category,expected)
 rows=category._postflight_originals(root,pins,api,expected,prepared)
 provenance._row_set(rows)
 return rows


def _postflight_originals(root,pins,api,expected,prepared):
 diagnostic,current=_base();_pin_sources(root,pins,api,expected)
 value=current.document(current.pin_bytes(root,pins,api,receipt_path('diagnostic')))
 _validate_diagnostic_receipt(value,expected)
 journal=value['new_original'];token=journal['token'];cid=journal['original_id']
 fixed=native().metadata(token,PHASE_ID,expected)
 actual=diagnostic.journal_documents(root,pins,api,token,fixed,cid,journal['files'])
 require(journal==dict(actual,original_cid_and_name_absent_live=True))
 preserved=_prior_postflight(root,pins,api,prepared)
 require(value['preserved_originals']==preserved)
 rows=preserved+[actual]
 _postflight_reservations(root,pins,api,rows,expected)
 return rows


def _validate_diagnostic_receipt(value,expected):
 _no_pending(ROOT)
 base={'schema','scope','stage','status','completed','native_eligible','private_input_allowed','control_state_modified',
  'binding','finalizers','completed_stages','preserved_originals','new_original','observation','total_seconds','recorded_utc'}
 refusal={'active_case','active_phase','active_token','active_original_id','failure_code','failed_stage','failed_original','failed_gate'}
 require(type(value) is dict and base<=set(value)<=base|refusal and type(value['schema']) is int and value['schema']==1 and
  value['scope']==SCOPE and value['stage']=='diagnostic' and value['binding']==asdict(expected) and
  value['native_eligible'] is False and value['private_input_allowed'] is False and value['control_state_modified'] is False and
  value['status'] in ('MEASURED','REFUSED') and type(value['completed']) is bool and
  value['completed'] is (value['status']=='MEASURED') and type(value['total_seconds']) in (int,float) and
  math.isfinite(value['total_seconds']) and 0<=value['total_seconds'])
 _timestamp(value['recorded_utc'])
 states=value['finalizers']
 require(type(states) is dict and set(states)==set(FINALIZERS) and all(type(state) is str and state in STATES for state in states.values()))
 stages=value['completed_stages'];expected_stages_list=expected_stages('diagnostic')
 require(type(stages) is list and len(stages)<=len(expected_stages_list) and stages==expected_stages_list[:len(stages)])
 if value['observation'] is not None:native().validate_outcome(PHASE_ID,value['observation'])
 rows=value['preserved_originals']
 require(type(rows) is list and len(rows)==28 and sum(len(row['files']) for row in rows)==112 and
  len({row['token'] for row in rows})==28 and len({row['original_id'] for row in rows})==28)
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
  require(value.get('active_case')=='detection-controls' and value.get('active_phase')==PHASE_ID and
   value.get('active_token')==journal['token'] and value.get('active_original_id')==journal['original_id'] and
   value.get('failure_code') in ('DETECTION_CONTROLS_DIAGNOSTIC_REFUSED','CONTEXT_CLOSE_UNCONFIRMED',
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

def _execute(stage):
 reviewed_constants();require(type(stage) is str and stage in STAGES)
 require(os.name=='nt' and Path.cwd().resolve()==ROOT,'WINDOWS_ROOT_ONLY')
 diagnostic,current=_base()
 result={'schema':1,'scope':SCOPE,'stage':stage,'status':'REFUSED','completed':False,'native_eligible':False,
  'private_input_allowed':False,'control_state_modified':False,'binding':None,
  'finalizers':{name:'NOT_REACHED' for name in FINALIZERS},'completed_stages':[],
  'preserved_originals':[],'new_original':None,'observation':None,'recorded_utc':_utc()}
 receipt=None;parent_pins=ExitStack()
 started=time.monotonic();failure=None;checkpoint=None;context=None;oldcall=None;outcome=None;pending=None
 def mark(name):
  nonlocal checkpoint
  require(name in expected_stages(stage))
  if checkpoint is not None:result['completed_stages'].append(checkpoint)
  checkpoint=name
 try:
  mark('INPUTS')
  with tracked(input_resources(),result,'input_resources') as (api,pins,oldcall,_):
   for directory in (ROOT,ROOT/'ai',ROOT/'ai/state'):
    parent_pins.enter_context(api.pin(directory,directory=True,private=False))
   _no_pending(ROOT);receipt_set(ROOT,stage)
   receipt=_new_receipt(ROOT/receipt_path(stage),result)
   mark('SOURCES')
   raw=current.pin_bytes(ROOT,pins,api,'infra/evidence_detection_controls_controller.py')
   expected=binding(hashlib.sha256(raw).hexdigest());result['binding']=asdict(expected)
   _pin_sources(ROOT,pins,api,expected)
   old,_,_=inherited()
   mark('CORRECTED_PREPARATION');prepared=old.corrected_provenance(ROOT,pins,api)
   preflight_rows=None
   if stage=='diagnostic':
    mark('PREFLIGHT_PROVENANCE');preflight_rows=preflight_provenance(ROOT,pins,api,expected)['preserved_originals']
   mark('EXISTING_LOCK')
   with tracked(old.existing_proof_lock(api,pins,prepared),result,'dedicated_lock') as lock_stream:
    pending=_Pending(stage)
    context=_ExecutionContext(_CONTEXT_SEAL,api,pins,oldcall,receipt,result,stage,prepared,expected,lock_stream,preflight_rows,deadline=started+300)
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
  failure=True;result['failure_code']='DETECTION_CONTROLS_DIAGNOSTIC_REFUSED'
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
  result['recorded_utc']=_utc()
  if receipt is None:
   try:parent_pins.close()
   except BaseException:finalizer(result,'input_resources','UNCONFIRMED')
   raise DiagnosticUnavailable()
  try:
   require(receipt.save(result) is None);require(receipt.close() is None)
   require(receipt.stream.closed is True)
  except BaseException:
   result.update(status='REFUSED',completed=False,failure_code='RECEIPT_CLOSE_UNCONFIRMED');result.update(active)
   try:
    if not receipt.stream.closed:receipt.save(result)
   except BaseException:pass
   try:receipt.close()
   except BaseException:pass
   if pending is not None:
    try:pending.close()
    except BaseException:pass
   try:parent_pins.close()
   except BaseException:finalizer(result,'input_resources','UNCONFIRMED')
   raise DiagnosticUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
  try:
   if pending is not None:
    if failure is None:
     require(time.monotonic()-started<300,'DEADLINE')
     require(pending.commit() is None and pending.closed is True)
     require(_no_pending(ROOT) is None)
    else:require(pending.close() is None)
   try:parent_pins.close()
   except BaseException:
    finalizer(result,'input_resources','UNCONFIRMED');raise
   require(time.monotonic()-started<300,'DEADLINE')
  except BaseException:
   result.update(status='REFUSED',completed=False);result.update(active);failure=True
   if pending is not None:
    try:pending.close()
    except BaseException:pass
   try:parent_pins.close()
   except BaseException:finalizer(result,'input_resources','UNCONFIRMED')
 require(failure is None)
 return result

def execute(stage):
 # The missing reviewed calibration pin refuses before receipt or runtime inputs.
 _reviewed_calibration()
 failed=False;result=None
 try:result=_execute(stage)
 except BaseException:failed=True
 if failed:raise DiagnosticUnavailable()
 return result


def _emit(value):
 try:
  text=json.dumps(value,separators=(',',':'))+'\n'
  count=sys.stdout.write(text)
  if type(count) is not int or count!=len(text):return False
  sys.stdout.flush()
 except BaseException:return False
 return True


def main():
 if len(sys.argv)!=2 or sys.argv[1] not in STAGES:
  _emit({'status':'REFUSED','native_eligible':False});return 2
 failed=False;value=None
 try:value=execute(sys.argv[1])
 except BaseException:failed=True
 if failed:
  _emit({'status':'REFUSED','native_eligible':False});return 2
 return 0 if _emit({'status':value['status'],'receipt':receipt_path(value['stage']),
  'native_eligible':False}) else 2


if __name__=='__main__':raise SystemExit(main())
