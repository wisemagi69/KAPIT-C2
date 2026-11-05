"""Immutable negative-chain replay for one PUBLIC identity diagnostic.

Import is inert. Callers retain exact source pins before loading new native code.
This module never executes acceptance controllers or clears consumed evidence.
"""
from dataclasses import asdict,is_dataclass
import hashlib
from itertools import islice
import re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OLD_CONTROLLER='infra/evidence_rmdir_proof.py'
OLD_CONTROLLER_SHA256='875cc59993b130316da12e1ba42c7580d4752e3e50d993f2673bcac64bef5acb'
OLD_NATIVE='infra/evidence_rmdir_native.py'
OLD_NATIVE_SHA256='8c45db9e71e67656bdb20fb47c008d4c9419c7664e40010ef2adbbc5fc5deed0'
TELEMETRY='infra/evidence_strict_failure_details.py'
TELEMETRY_SHA256='53e1659253f48c69c7b4b11b8cdc1be758e58a123965198bb2ed87264868cd17'
STRICT='infra/native/strict_probe.py'
STRICT_SHA256='021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078'
FAILED='ai/state/private-scanner-rmdir-proof-strict.json'
FAILED_SHA256='793cc6f8c063451de4205f24ba6d7da1eb9e3db4016915771d53c9b6ca56632b'
OLD_RECEIPTS={
 'preflight':'c28e6af994b05eb2f0fcbe6a5a461faafff165efb8f070c0117987d2bd767ed6',
 'confinement':'38bb820b726ccdd63aee03048c18094eceeaaa0286352afda3e8e084e70fe59f',
 'strict':FAILED_SHA256}
TOKEN='ef0242ed1315474b81a0981e22139870'
CID='5f4b376048bcd4b948704a15df145d1f00c1d616d2a73627a0d58e2b3a7c7985'
OWNER='kapit-public-strict-identity-v1'
PURPOSE='public-strict-identity-only'
CONTRACT='e464951efcc96b21d8284ddf403c5d34ee7b82d012d72c788dca7765d0b95863'
PHASE_ID='strict-identity:scan:strict'
BINDING_FIELDS=frozenset(('image_id','signature_generation','profile_sha256','preparation_sha256',
 'native_sha256','controller_sha256','provenance_sha256','telemetry_sha256','failed_receipt_sha256','contract'))

class ProvenanceUnavailable(RuntimeError):
 def __str__(self):return 'STRICT_IDENTITY_PROVENANCE_UNAVAILABLE'

def require(value):
 if value is not True:raise ProvenanceUnavailable()

def inherited():
 from infra import evidence_rmdir_proof as old
 from infra import evidence_interpreter_runtime as current
 from infra import evidence_rmdir_diagnostic as diagnostic
 return old,current,diagnostic

def old_binding():
 old,_,_=inherited()
 return old._Binding('sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa',
  '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3',
  'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733',
  '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f',
  OLD_NATIVE_SHA256,OLD_CONTROLLER_SHA256,'062dd3e446b62e52bef1ee04d630db0441dd1360e46d4751807747f5e7bcdf7f')

def binding_fields(binding):
 require(is_dataclass(binding) and not isinstance(binding,type))
 fields=asdict(binding);require(set(fields)==BINDING_FIELDS)
 old=old_binding()
 require(fields['image_id']==old.image_id and fields['signature_generation']==old.signature_generation and
  fields['profile_sha256']==old.profile_sha256 and fields['preparation_sha256']==old.preparation_sha256 and
  fields['telemetry_sha256']==TELEMETRY_SHA256 and fields['failed_receipt_sha256']==FAILED_SHA256 and fields['contract']==CONTRACT)
 require(all(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None for key,value in fields.items() if key!='image_id'))
 return fields

def pin_sources(root,pins,api,binding):
 # Pin immutable old code before importing it or invoking its source-pin helper.
 from infra import evidence_interpreter_runtime as current
 current.pin_bytes(root,pins,api,OLD_CONTROLLER,expected=OLD_CONTROLLER_SHA256)
 current.pin_bytes(root,pins,api,OLD_NATIVE,expected=OLD_NATIVE_SHA256)
 old,_,_=inherited();fields=binding_fields(binding)
 old.pin_sources(root,pins,api,old_binding())
 sources={
  'infra/evidence_strict_identity_controller.py':fields['controller_sha256'],
  'infra/evidence_strict_identity_provenance.py':fields['provenance_sha256'],
  'infra/evidence_strict_identity_native.py':fields['native_sha256'],
  TELEMETRY:TELEMETRY_SHA256,STRICT:STRICT_SHA256}
 for path,expected in sources.items():current.pin_bytes(root,pins,api,path,expected=expected)

def validate_failed_evidence(value,accepted_prefix):
 old,_,_=inherited();expected_binding=old_binding()
 expected_keys={'schema','scope','stage','status','completed','native_eligible','private_input_allowed',
  'control_state_modified','pins_closed','cli_cleanup_confirmed','binding','completed_stages','phase_originals',
  'completed_manifest','results','total_seconds','active_case','active_phase','active_token','active_original_id',
  'failed_stage','failure_code'}
 require(type(value) is dict and set(value)==expected_keys)
 require(type(value['schema']) is int and value['schema']==1 and value['scope']==old.SCOPE and
  value['stage']=='strict' and value['status']=='REFUSED' and value['completed'] is False and
  value['native_eligible'] is False and value['private_input_allowed'] is False and value['control_state_modified'] is False and
  value['pins_closed'] is False and value['cli_cleanup_confirmed'] is False and value['binding']==asdict(expected_binding) and
  value['completed_stages']==['INPUTS','PRIOR_STAGES','EXISTING_LOCK'] and
  value['completed_manifest']==list(old.PHASES[:10]) and value['results']=={} and
  value['active_case']=='strict' and value['active_phase']=='strict:scan:strict' and
  value['active_token']==TOKEN and value['active_original_id']==CID and value['failed_stage']=='PUBLIC_MATRIX' and
  value['failure_code']=='RMDIR_PROOF_REFUSED' and type(value['total_seconds']) in (int,float) and
  0<=value['total_seconds']<300)
 rows=value['phase_originals']
 require(type(rows) is list and len(rows)==11 and rows[:10]==accepted_prefix)
 # The negative last row is never submitted to a passed-manifest validator.
 old.validate_manifest(rows[:10],old.PHASES[:10],expected_binding)
 last=rows[-1]
 require(type(last) is dict and set(last)=={'phase_id','outcome','journal'} and last['phase_id']=='strict:scan:strict')
 expected={'phase_id':'strict:scan:strict','passed':False,'native_eligible':False,'private_input_allowed':False,
  'result':{'diagnostic':{'stage':'CASES','kind':'REFUSED','location':{'source':'UNKNOWN','function':'UNKNOWN','line':0}},
   'completed':True,'passed':False,'case_count':14,'native_eligible':False}}
 require(last['outcome']==expected)
 from infra import evidence_rmdir_native as native
 require(native.validate_outcome(last['phase_id'],last['outcome'])==expected)
 journal=last['journal']
 require(type(journal) is dict and journal.get('token')==TOKEN and journal.get('original_id')==CID and
  journal.get('original_cid_and_name_absent_live') is True)
 require(len({row['journal']['token'] for row in rows})==11 and len({row['journal']['original_id'] for row in rows})==11)
 return last

def preserved_originals(root,pins,api,prepared):
 old,current,diagnostic=inherited();prior_binding=old_binding()
 for stage,expected in OLD_RECEIPTS.items():
  current.pin_bytes(root,pins,api,old.receipt_path(stage),expected=expected,maximum=262144)
 before=old.prior_stage(root,pins,api,'preflight',prior_binding)
 require(before['phase_originals']==[])
 confinement=old.prior_stage(root,pins,api,'confinement',prior_binding)
 accepted=confinement['phase_originals']
 failed=current.document(current.pin_bytes(root,pins,api,FAILED,expected=FAILED_SHA256,maximum=262144))
 last=validate_failed_evidence(failed,accepted)
 rows=old.historical_originals(root,pins,api,prepared)
 # prior_stage already replayed the forty accepted proof documents; its copied
 # canonical rows are returned without reopening those forty a second time.
 rows=list(rows)+[row['journal'] for row in accepted]
 from infra import evidence_rmdir_native as native
 saved=last['journal'];fixed=native.metadata(TOKEN,last['phase_id'],prior_binding)
 actual=diagnostic.journal_documents(root,pins,api,TOKEN,fixed,CID,saved.get('files'))
 require(saved==dict(actual,original_cid_and_name_absent_live=True))
 rows.append(actual)
 require(len(rows)==26 and len({row['token'] for row in rows})==26 and
  len({row['original_id'] for row in rows})==26 and sum(len(row['files']) for row in rows)==104)
 return rows

def unknown_reservations(root,pins,api,rows):
 """Precreate-only guard; never adopts a previous identity diagnostic.

 Postflight of the one known owned new original is a separate controller
 operation authenticated from its fixed receipt, not this guard's allowance.
 """
 old,current,diagnostic=inherited()
 from infra.live_recovery_drill import PrivateDirectory
 from infra import evidence_rmdir_native as native
 allowed={row['token']:row['files']['reservation.json']['document'] for row in rows}
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
   bool(labels.get('org.kapit.owner')) and bool(labels.get('org.kapit.purpose')) and
   labels.get('org.kapit.reservation')==value['token'])
  if labels['org.kapit.owner']==OWNER or value['purpose'].startswith('public-strict-identity'):
   # No previous diagnostic reservation is authorized, regardless of image.
   raise ProvenanceUnavailable()
  if labels['org.kapit.owner']==native.OWNER or value['purpose'].startswith('public-rmdir-proof-'):
   require(value['token'] in allowed and value==allowed[value['token']])
