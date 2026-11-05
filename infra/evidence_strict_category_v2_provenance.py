"""Inert category v2 diagnostic provenance; no old-module/provider mutation."""
from dataclasses import asdict,is_dataclass
from itertools import islice
from pathlib import Path
import re
import math

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
CONTRACT='0de876c7b300cba9eca275c63273e5910633cbdc9ab813127e404ea5c48a6e42'
OWNER='kapit-public-strict-category-v2'
PURPOSE='public-strict-category-v2-only'
BINDING_FIELDS=frozenset(('image_id','signature_generation','profile_sha256','preparation_sha256',
 'native_sha256','controller_sha256','provenance_sha256','telemetry_sha256','failed_receipt_sha256','contract'))

PINNED_PRIOR=(('infra/native/strict_probe.py', '021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078'), ('infra/evidence_rmdir_native.py', '8c45db9e71e67656bdb20fb47c008d4c9419c7664e40010ef2adbbc5fc5deed0'), ('infra/evidence_rmdir_proof.py', '875cc59993b130316da12e1ba42c7580d4752e3e50d993f2673bcac64bef5acb'), ('infra/evidence_rmdir_profile.py', '73300666b534c7fe1d36140ea7d28464c2ececaf1ab520f2c7afa483c4ecbbfc'), ('infra/evidence_rmdir_diagnostic.py', '488c2b810b14e76f90ca5a1bf77e2599511d38cdcee51537d01908a0277b174f'), ('ai/state/private-scanner-rmdir-proof-strict.json', '793cc6f8c063451de4205f24ba6d7da1eb9e3db4016915771d53c9b6ca56632b'), ('ai/state/private-scanner-rmdir-proof-confinement.json', '38bb820b726ccdd63aee03048c18094eceeaaa0286352afda3e8e084e70fe59f'), ('ai/state/private-scanner-rmdir-proof-preflight.json', 'c28e6af994b05eb2f0fcbe6a5a461faafff165efb8f070c0117987d2bd767ed6'), ('ai/state/private-scanner-rmdir-prepare.json', '6794cfea93e71d39b4df6610be73f2a838f165350e8f61c94dff39fac98d184c'), ('ai/state/private-scanner-rmdir-preflight.json', 'b2188bdb777b3cbd151200bd5935959333f6d8de8eb0447c196e6e39cfb5f1b6'), ('ai/state/private-scanner-rmdir-rmdir.json', '2d30584ea4a7fc6ead0ef97d6af6ec1d3e25d5de50835e8b57c4ef27dcc36a66'), ('ai/state/private-scanner-rmdir-lifecycle.json', 'daebe1ab66825446eb7eef4dee6e67eedf2327fb1531b3f4824967087e947ba0'), ('infra/evidence_strict_failure_details.py', '53e1659253f48c69c7b4b11b8cdc1be758e58a123965198bb2ed87264868cd17'), ('infra/tests/test_strict_failure_details.py', 'ee0450ad68078118f56368531e9c860801394beab53a8e4d8c9584ed633b81e0'), ('infra/evidence_strict_identity_native.py', '09541b9b06aa0cb542060189a00c332e376ed0ade43a6a3c30c4d0cce224c702'), ('infra/evidence_strict_identity_provenance.py', 'bbed594d3a4df209da52fd7c2047f9d6440f21dab6e74ab1ce2628d2955ed41e'), ('infra/evidence_strict_identity_controller.py', '57f6ce840525cc3b7103f12c76f607e3d855a5144531593125036b8a172c6a75'), ('infra/tests/test_strict_identity_native.py', 'e6aeeb20e0d685eb46afcdbbcc285ee348a8bdc5be06e9a1c4677bc2875b5508'), ('infra/tests/test_strict_identity_provenance.py', 'c2166aab803e717fbbf94e5e8e7145f61e669885a7a85dc115aa77978cbcb60f'), ('infra/tests/test_strict_identity_controller.py', 'bcab5e5647ef50e72182712004b1c1235e786e540277ed54d597bf6a9a99970b'), ('ai/state/private-scanner-strict-identity-preflight.json', 'b4eb091896576885764c22061a14f4a4ebbceac70a4e2b435728fe883447d5e7'), ('ai/state/private-scanner-strict-identity-diagnostic.json', '7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00'), ('infra/evidence_strict_failure_categories.py', 'dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'), ('infra/tests/test_strict_failure_categories.py', '3d1509b474d686df86c960abfa78f2cddca411df21b6e5c09f4a41ac668eebdb'), ('infra/evidence_strict_category_native.py', 'ca07edf6d213f487bbd904aff1f0c922188bba49b3d183f725141fe884ea1906'), ('infra/evidence_strict_category_provenance.py', '4c0e432cbd6956c6525cd39aede199d041f28e11e46820d1b624d416c02948bb'), ('infra/evidence_strict_category_controller.py', '9a79b57949712f82990c323e3ca617f6a26170c0adfa10957de3d06102d1c671'), ('infra/tests/test_strict_category_native.py', 'cf0379a03f6c9ccba62e554327b6db8819ac054276a6bd1d4004f5bb60a78909'), ('infra/tests/test_strict_category_provenance.py', '7f8ee1bdea923e9dff4cac5e492b790c560d42d70304d40af4737e6b2d972350'), ('infra/tests/test_strict_category_controller.py', '5dfb84b182c0f4bfb68fd595c2db73ec0923a39bf2e48c8ace3f338a4c65c616'), ('ai/state/private-scanner-strict-category-preflight.json', '71c9569d33ce61aa9833bb6820514f8552db120de56e29794cf616f70ab2e973'))
V1_PREFLIGHT='ai/state/private-scanner-strict-category-preflight.json'
V1_BINDING={'contract': '6c0f7fa9a86afc96ad4a677df9eab9d76264de8df51cd7be1b1fb911e34459b5', 'controller_sha256': '9a79b57949712f82990c323e3ca617f6a26170c0adfa10957de3d06102d1c671', 'failed_receipt_sha256': '7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00', 'image_id': 'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa', 'native_sha256': 'ca07edf6d213f487bbd904aff1f0c922188bba49b3d183f725141fe884ea1906', 'preparation_sha256': '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f', 'profile_sha256': 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733', 'provenance_sha256': '4c0e432cbd6956c6525cd39aede199d041f28e11e46820d1b624d416c02948bb', 'signature_generation': '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3', 'telemetry_sha256': 'dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'}

def _pin_prior(root,pins,api):
 from infra import evidence_interpreter_runtime as current
 for path,expected in PINNED_PRIOR:current.pin_bytes(root,pins,api,path,expected=expected,maximum=262144)

def validate_v1_preflight(value):
 require(type(value) is dict and set(value)=={'completed', 'private_input_allowed', 'failure_code', 'new_original', 'stage', 'status', 'completed_stages', 'observation', 'finalizers', 'preserved_originals', 'binding', 'control_state_modified', 'scope', 'schema', 'native_eligible', 'total_seconds', 'failed_stage'} and value['binding']==V1_BINDING)
 require(value==dict({'binding': {'contract': '6c0f7fa9a86afc96ad4a677df9eab9d76264de8df51cd7be1b1fb911e34459b5', 'controller_sha256': '9a79b57949712f82990c323e3ca617f6a26170c0adfa10957de3d06102d1c671', 'failed_receipt_sha256': '7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00', 'image_id': 'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa', 'native_sha256': 'ca07edf6d213f487bbd904aff1f0c922188bba49b3d183f725141fe884ea1906', 'preparation_sha256': '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f', 'profile_sha256': 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733', 'provenance_sha256': '4c0e432cbd6956c6525cd39aede199d041f28e11e46820d1b624d416c02948bb', 'signature_generation': '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3', 'telemetry_sha256': 'dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'}, 'completed': False, 'completed_stages': ['INPUTS', 'SOURCES', 'CORRECTED_PREPARATION', 'EXISTING_LOCK'], 'control_state_modified': False, 'failed_stage': 'FRESH_PREFLIGHT', 'failure_code': 'STRICT_CATEGORY_DIAGNOSTIC_REFUSED', 'finalizers': {'cli': 'CONFIRMED', 'context': 'CONFIRMED', 'dedicated_lock': 'CONFIRMED', 'input_resources': 'CONFIRMED', 'phase_pins': 'NOT_REACHED'}, 'native_eligible': False, 'new_original': None, 'observation': None, 'preserved_originals': [], 'private_input_allowed': False, 'schema': 1, 'scope': 'PUBLIC_STRICT_FAILURE_CATEGORY_DIAGNOSTIC_ONLY', 'stage': 'preflight', 'status': 'REFUSED', 'total_seconds': 0.252},total_seconds=value.get('total_seconds')))
 require(type(value['schema']) is int and all(type(value[key]) is bool for key in ('completed','control_state_modified','native_eligible','private_input_allowed')))
 require(type(value['binding']) is dict and all(type(item) is str for item in value['binding'].values()) and
  type(value['finalizers']) is dict and all(type(item) is str for item in value['finalizers'].values()) and
  type(value['preserved_originals']) is list and type(value['completed_stages']) is list)
 elapsed=value['total_seconds']
 require(type(elapsed) in (int,float) and math.isfinite(elapsed) and 0<=elapsed<300)
 return value

class ProvenanceUnavailable(RuntimeError):
 def __str__(self):return 'STRICT_CATEGORY_V2_PROVENANCE_UNAVAILABLE'

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
 _pin_prior(root,pins,api)
 validate_v1_preflight(current.document(current.pin_bytes(root,pins,api,V1_PREFLIGHT,expected=dict(PINNED_PRIOR)[V1_PREFLIGHT],maximum=262144)))
 identity,_,_=inherited();fields=binding_fields(binding)
 identity._pin_sources(root,pins,api,identity_binding())
 sources={'infra/evidence_strict_category_v2_controller.py':fields['controller_sha256'],
  'infra/evidence_strict_category_v2_provenance.py':fields['provenance_sha256'],
  'infra/evidence_strict_category_v2_native.py':fields['native_sha256'],TELEMETRY:TELEMETRY_SHA256}
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
 _pin_prior(root,pins,api)
 from infra import evidence_interpreter_runtime as current
 validate_v1_preflight(current.document(current.pin_bytes(root,pins,api,V1_PREFLIGHT,expected=dict(PINNED_PRIOR)[V1_PREFLIGHT],maximum=262144)))
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
  if labels['org.kapit.owner'] in (OWNER,'kapit-public-strict-category-v1') or value['purpose'].startswith('public-strict-category'):
   raise ProvenanceUnavailable()
  if labels['org.kapit.owner'] in (identity_native.OWNER,proof_native.OWNER) or value['purpose'].startswith(('public-strict-identity','public-rmdir-proof-')):
   require(value['token'] in allowed and value==allowed[value['token']])
