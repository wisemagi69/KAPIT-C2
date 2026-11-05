"""Public copied metadata and synthetic protected-IO replacement only."""
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from dataclasses import make_dataclass
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch

from infra import evidence_strict_identity_provenance as p
from infra import evidence_rmdir_proof as old
from infra import evidence_rmdir_native as native
from infra import evidence_rmdir_diagnostic as diagnostic
from infra import evidence_interpreter_runtime as current


class PublicReplay(unittest.TestCase):
 def setUp(self):
  self.failed=json.loads(Path(p.FAILED).read_text())
  self.accepted=json.loads(Path(old.receipt_path('confinement')).read_text())['phase_originals']
 def test_exact_negative_chain_is_not_a_passed_manifest(self):
  result=p.validate_failed_evidence(self.failed,self.accepted)
  self.assertFalse(result['outcome']['passed']);self.assertEqual(result['journal']['token'],p.TOKEN)
  with self.assertRaises(old.ProofUnavailable):old.validate_manifest(self.failed['phase_originals'],old.PHASES[:11],p.old_binding())
 def test_closed_schema_flags_stages_binding_and_active_identity_refuse(self):
  changes=(lambda v:v.update(extra='CANARY'),lambda v:v.update(status='VERIFIED'),lambda v:v.update(completed=True),
   lambda v:v.update(schema=True),lambda v:v.update(pins_closed=True),lambda v:v.update(cli_cleanup_confirmed=True),
   lambda v:v.update(active_case='pcre'),lambda v:v.update(active_phase='pcre:scan:pcre'),lambda v:v.update(active_token='f'*32),
   lambda v:v.update(active_original_id='f'*64),lambda v:v.update(failed_stage='INPUT_CLOSE'),lambda v:v['completed_stages'].append('FINAL_CLI'),
   lambda v:v['binding'].update(profile_sha256='f'*64),lambda v:v.update(total_seconds=True),lambda v:v.update(results={'passed':True}))
  for change in changes:
   value=deepcopy(self.failed);change(value)
   with self.subTest(change=repr(change)),self.assertRaises((p.ProvenanceUnavailable,old.ProofUnavailable)):p.validate_failed_evidence(value,self.accepted)
 def test_negative_outcome_case_count_and_finite_diagnostic_must_match(self):
  changes=(lambda v:v['phase_originals'][-1]['outcome'].update(passed=True),
   lambda v:v['phase_originals'][-1]['outcome']['result'].update(case_count=13),
   lambda v:v['phase_originals'][-1]['outcome']['result'].update(case_count=14.0),
   lambda v:v['phase_originals'][-1]['outcome']['result'].update(completed=False),
   lambda v:v['phase_originals'][-1]['outcome']['result']['diagnostic'].update(stage='SCRATCH_CLEANUP'),
   lambda v:v['phase_originals'][-1]['outcome']['result'].update(failed_case_ids=['png_positive']))
  for change in changes:
   value=deepcopy(self.failed);change(value)
   with self.subTest(change=repr(change)),self.assertRaises((p.ProvenanceUnavailable,native.NativeUnavailable)):p.validate_failed_evidence(value,self.accepted)
 def test_accepted_prefix_cannot_be_replaced_reordered_or_duplicated(self):
  for change in (lambda v:v['phase_originals'].pop(0),lambda v:v['phase_originals'].reverse(),
   lambda v:v['phase_originals'].__setitem__(0,deepcopy(v['phase_originals'][1])),lambda v:v['completed_manifest'].pop()):
   value=deepcopy(self.failed);change(value)
   with self.assertRaises(p.ProvenanceUnavailable):p.validate_failed_evidence(value,self.accepted)
 def replay(self,mutation=None):
  from infra import evidence_scratch_diagnostic as scratch
  owned=diagnostic.modules()[3]
  historical=json.loads(Path(diagnostic.OWNED).read_text())['journals']
  historical += [json.loads(Path(scratch.receipt_path(stage)).read_text())['original_journal'] for stage in ('rmdir','lifecycle')]
  historical += [json.loads(Path(diagnostic.receipt_path(stage)).read_text())['original_journal'] for stage in ('rmdir','lifecycle')]
  rows=historical+[row['journal'] for row in self.failed['phase_originals']]
  docs={row['directory']+'/'+name:owned._canonical(info['document']) for row in rows for name,info in row['files'].items()}
  if mutation:mutation(docs)
  reads=[]
  def read(root,pins,api,path,**kw):
   if path in docs:raw=docs[path];reads.append(path)
   elif 'native-run-' in path:raise FileNotFoundError()
   else:raw=Path(path).read_bytes()
   if 'expected' in kw:p.require(hashlib.sha256(raw).hexdigest()==kw['expected'])
   return raw
  @contextmanager
  def no_pin(*a,**kw):yield
  prepared=json.loads(Path(diagnostic.receipt_path('prepare')).read_text())['preparation']
  with patch.object(current,'pin_bytes',read),patch('infra.live_recovery_drill.PrivateDirectory') as directory:
   directory.return_value.pin=no_pin
   with ExitStack() as pins:result=p.preserved_originals(Path('.'),pins,Mock(),prepared)
  return result,reads
 def test_all_26_distinct_originals_and_104_actual_canonical_documents(self):
  rows,reads=self.replay()
  self.assertEqual(len(rows),26);self.assertEqual(len({r['token'] for r in rows}),26)
  self.assertEqual(len({r['original_id'] for r in rows}),26);self.assertEqual(len(reads),104)
  self.assertEqual(len(set(reads)),104);self.assertEqual(sum(len(r['files']) for r in rows),104)
  self.assertEqual(rows[-1]['original_id'],p.CID)
 def test_each_changed_failed_original_journal_refuses(self):
  directory=self.failed['phase_originals'][-1]['journal']['directory']
  for name in ('reservation.json','create-attempt.json','ownership.json','result.json'):
   def mutate(docs):docs[directory+'/'+name]+=b' '
   with self.subTest(name=name),self.assertRaises(diagnostic.DiagnosticUnavailable):self.replay(mutate)
 def test_missing_negative_original_document_refuses(self):
  name=self.failed['phase_originals'][-1]['journal']['directory']+'/ownership.json'
  with self.assertRaises(FileNotFoundError):self.replay(lambda docs:docs.pop(name))
 def test_duplicate_between_historical_and_proof_refuses(self):
  with patch.object(old,'historical_originals',return_value=[self.failed['phase_originals'][-1]['journal']]*15):
   with self.assertRaises(p.ProvenanceUnavailable):self.replay()


class SourcePins(unittest.TestCase):
 def binding(self,**changed):
  old_binding=p.old_binding();values={name:'a'*64 for name in p.BINDING_FIELDS}
  values.update(image_id=old_binding.image_id,signature_generation=old_binding.signature_generation,
   profile_sha256=old_binding.profile_sha256,preparation_sha256=old_binding.preparation_sha256,
   telemetry_sha256=p.TELEMETRY_SHA256,failed_receipt_sha256=p.FAILED_SHA256,contract=p.CONTRACT)
  values.update(changed);kind=make_dataclass('SyntheticBinding',[(name,str) for name in values],frozen=True)
  return kind(**values)
 def test_all_ten_binding_fields_and_frozen_values_required(self):
  self.assertEqual(set(p.binding_fields(self.binding())),p.BINDING_FIELDS)
  for changed in ({'native_sha256':None},{'contract':'a'*64},{'failed_receipt_sha256':'a'*64},{'profile_sha256':'a'*64}):
   with self.assertRaises(p.ProvenanceUnavailable):p.binding_fields(self.binding(**changed))
  with self.assertRaises(p.ProvenanceUnavailable):p.binding_fields({})
 def test_pin_old_sources_before_helper_import_new_sources_before_return(self):
  reads=[];events=[];binding=self.binding()
  def read(root,pins,api,path,**kw):reads.append((path,kw['expected']));events.append(path)
  def inherited():events.append('OLD_IMPORT');return old,current,diagnostic
  with patch.object(current,'pin_bytes',read),patch.object(p,'inherited',side_effect=inherited),patch.object(old,'pin_sources') as transitive:
   p.pin_sources(Path('.'),ExitStack(),Mock(),binding)
  self.assertEqual([item[0] for item in reads[:2]],[p.OLD_CONTROLLER,p.OLD_NATIVE])
  self.assertLess(events.index(p.OLD_NATIVE),events.index('OLD_IMPORT'))
  transitive.assert_called_once();self.assertEqual(len(reads),7)
  self.assertIn(('infra/evidence_strict_identity_controller.py',binding.controller_sha256),reads)
  self.assertIn((p.TELEMETRY,p.TELEMETRY_SHA256),reads)
 def test_changed_old_source_prevents_import_and_new_source_work(self):
  with patch.object(current,'pin_bytes',side_effect=p.ProvenanceUnavailable()),patch.object(p,'inherited') as inherited:
   with self.assertRaises(p.ProvenanceUnavailable):p.pin_sources(Path('.'),ExitStack(),Mock(),object())
  inherited.assert_not_called()


class ReservationDenials(unittest.TestCase):
 def setUp(self):
  self.failed=json.loads(Path(p.FAILED).read_text());self.saved=self.failed['phase_originals'][0]['journal']
  self.base=deepcopy(self.saved['files']['reservation.json']['document'])
 def check(self,value,allowed=True,count=1):
  root=Path('.');directory=root/diagnostic.STAGE/('native-run-'+value.get('token',self.base['token']))
  @contextmanager
  def no_pin(*a,**kw):yield
  with patch.object(Path,'glob',return_value=[directory]*count),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:p.unknown_reservations(root,pins,Mock(),[self.saved] if allowed else [])
 def test_exact_old_proof_prefix_reservation_accepted(self):self.check(self.base)
 def test_unknown_old_owner_refuses_even_other_image(self):
  value=deepcopy(self.base);value['image_id']='sha256:'+'f'*64
  with self.assertRaises(p.ProvenanceUnavailable):self.check(value)
  with self.assertRaises(p.ProvenanceUnavailable):self.check(self.base,False)
 def test_any_new_diagnostic_owner_or_purpose_refuses_across_images(self):
  for owner,purpose in ((p.OWNER,'different-purpose'),('different-owner',p.PURPOSE)):
   value=deepcopy(self.base);value['image_id']='sha256:'+'f'*64;value['purpose']=purpose
   value['expected_labels'].update({'org.kapit.owner':owner,'org.kapit.purpose':purpose})
   with self.subTest(owner=owner),self.assertRaises(p.ProvenanceUnavailable):self.check(value)
 def test_malformed_base_checked_before_nonmatching_owner_filter(self):
  for value in ({},dict(self.base,schema=True),dict(self.base,image_id='bad'),dict(self.base,expected_labels={}),dict(self.base,purpose='')):
   with self.subTest(value=value),self.assertRaises(p.ProvenanceUnavailable):self.check(value)
 def test_directory_limit_is_256(self):
  with self.assertRaises(p.ProvenanceUnavailable):self.check(self.base,count=257)


if __name__=='__main__':unittest.main()
