"""Inert category diagnostic provenance; no old-module/provider mutation."""
from dataclasses import asdict,is_dataclass
from itertools import islice
from pathlib import Path
import re

IDENTITY_CONTROLLER='infra/evidence_strict_identity_controller.py'
IDENTITY_CONTROLLER_SHA256='57f6ce840525cc3b7103f12c76f607e3d855a5144531593125036b8a172c6a75'
IDENTITY_NATIVE='infra/evidence_strict_identity_native.py'
IDENTITY_NATIVE_SHA256='09541b9b06aa0cb542060189a00c332e376ed0ade43a6a3c30c4d0cce224c702'
IDENTITY_PROVENANCE='infra/evidence_strict_identity_provenance.py'
IDENTITY_PROVENANCE_SHA256='bbed594d3a4df209da52fd7c2047f9d6440f21dab6e74ab1ce2628d2955ed41e'
IDENTITY_PREFLIGHT_SHA256='b4eb091896576885764c22061a14f4a4ebbceac70a4e2b435728fe883447d5e7'
FAILED='ai/state/private-scanner-strict-identity-diagnostic.json'
FAILED_SHA256='7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00'
TELEMETRY='infra/evidence_strict_failure_categories.py'
TELEMETRY_SHA256='dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'
CONTRACT='6c0f7fa9a86afc96ad4a677df9eab9d76264de8df51cd7be1b1fb911e34459b5'
OWNER='kapit-public-strict-category-v1'
PURPOSE='public-strict-category-only'
BINDING_FIELDS=frozenset(('image_id','signature_generation','profile_sha256','preparation_sha256',
 'native_sha256','controller_sha256','provenance_sha256','telemetry_sha256','failed_receipt_sha256','contract'))

class ProvenanceUnavailable(RuntimeError):
 def __str__(self):return 'STRICT_CATEGORY_PROVENANCE_UNAVAILABLE'

def require(value):
 if value is not True:raise ProvenanceUnavailable()

def inherited():
 from infra import evidence_strict_identity_controller as identity
 from infra import evidence_interpreter_runtime as current
 from infra import evidence_rmdir_diagnostic as diagnostic
 return identity,current,diagnostic

def identity_binding():return inherited()[0].binding(IDENTITY_CONTROLLER_SHA256)

def binding_fields(binding):
 require(is_dataclass(binding) and not isinstance(binding,type))
 fields=asdict(binding);require(set(fields)==BINDING_FIELDS)
 old=identity_binding()
 require(fields['image_id']==old.image_id and fields['signature_generation']==old.signature_generation and
  fields['profile_sha256']==old.profile_sha256 and fields['preparation_sha256']==old.preparation_sha256 and
  fields['telemetry_sha256']==TELEMETRY_SHA256 and fields['failed_receipt_sha256']==FAILED_SHA256 and fields['contract']==CONTRACT)
 require(all(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None and value!='0'*64
  for key,value in fields.items() if key!='image_id'))
 return fields

def pin_sources(root,pins,api,binding):
 from infra import evidence_interpreter_runtime as current
 for path,expected in ((IDENTITY_CONTROLLER,IDENTITY_CONTROLLER_SHA256),(IDENTITY_NATIVE,IDENTITY_NATIVE_SHA256),
  (IDENTITY_PROVENANCE,IDENTITY_PROVENANCE_SHA256),
  ('ai/state/private-scanner-strict-identity-preflight.json',IDENTITY_PREFLIGHT_SHA256),(FAILED,FAILED_SHA256)):
  current.pin_bytes(root,pins,api,path,expected=expected)
 identity,_,_=inherited();fields=binding_fields(binding)
 identity._pin_sources(root,pins,api,identity_binding())
 sources={'infra/evidence_strict_category_controller.py':fields['controller_sha256'],
  'infra/evidence_strict_category_provenance.py':fields['provenance_sha256'],
  'infra/evidence_strict_category_native.py':fields['native_sha256'],TELEMETRY:TELEMETRY_SHA256}
 for path,expected in sources.items():current.pin_bytes(root,pins,api,path,expected=expected)

def validate_consumed_identity(value):
 identity,_,_=inherited();binding=identity_binding()
 identity._validate_diagnostic_receipt(value,binding)
 require(value['status']=='MEASURED' and value['completed'] is True and value['observation']['observed'] is True and
  value['observation']['details']['completed'] is True and value['observation']['details']['case_count']==14 and
  value['observation']['details']['failed_case_ids']==['eicar_png'] and
  value['finalizers']=={name:'CONFIRMED' for name in identity.FINALIZERS})
 return value

def preserved_originals(root,pins,api,prepared):
 identity,current,_=inherited();old_binding=identity_binding()
 current.pin_bytes(root,pins,api,identity.receipt_path('preflight'),expected=IDENTITY_PREFLIGHT_SHA256,maximum=262144)
 value=current.document(current.pin_bytes(root,pins,api,FAILED,expected=FAILED_SHA256,maximum=262144))
 validate_consumed_identity(value)
 preflight=identity.preflight_provenance(root,pins,api,old_binding)
 require(preflight['preserved_originals']==value['preserved_originals'])
 rows=identity._postflight_originals(root,pins,api,old_binding,prepared)
 require(len(rows)==27 and len({row['token'] for row in rows})==27 and len({row['original_id'] for row in rows})==27 and
  sum(len(row['files']) for row in rows)==108)
 return rows

def unknown_reservations(root,pins,api,rows):
 """Precreate only: no category original may exist, even on another image."""
 identity,current,diagnostic=inherited()
 from infra.live_recovery_drill import PrivateDirectory
 from infra import evidence_strict_identity_native as identity_native
 from infra import evidence_rmdir_native as proof_native
 require(type(rows) is list and len(rows)==27 and len({row['token'] for row in rows})==27)
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
   bool(labels.get('org.kapit.owner')) and bool(labels.get('org.kapit.purpose')) and labels.get('org.kapit.reservation')==value['token'])
  if labels['org.kapit.owner']==OWNER or value['purpose'].startswith('public-strict-category'):
   raise ProvenanceUnavailable()
  if labels['org.kapit.owner'] in (identity_native.OWNER,proof_native.OWNER) or value['purpose'].startswith(('public-strict-identity','public-rmdir-proof-')):
   require(value['token'] in allowed and value==allowed[value['token']])
