"""Synthetic protected replay from copied public27-original metadata only."""
from contextlib import ExitStack,contextmanager
from copy import deepcopy
from dataclasses import make_dataclass
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import Mock,patch

from infra import evidence_strict_category_provenance as p
from infra import evidence_strict_identity_controller as identity
from infra import evidence_strict_identity_native as identity_native
from infra import evidence_rmdir_diagnostic as diagnostic
from infra import evidence_interpreter_runtime as current

class CategoryProvenance(unittest.TestCase):
 def setUp(self):
  self.value=json.loads(Path(p.FAILED).read_text())
  self.rows=self.value['preserved_originals']+[self.value['new_original']]
 def test_exact_consumed_identity_is_measured_not_old_strict_acceptance(self):
  value=p.validate_consumed_identity(self.value)
  self.assertEqual(value['observation']['details']['failed_case_ids'],['eicar_png']);self.assertEqual(len(self.rows),27)
 def test_changed_binding_status_flags_finalizers_phase_and_failed_id_refuse(self):
  changes=(lambda d:d.update(status='REFUSED'),lambda d:d.update(completed=False),lambda d:d.update(stage='future'),
   lambda d:d.update(extra='CANARY'),lambda d:d['binding'].update(native_sha256='f'*64),
   lambda d:d['finalizers'].update(cli='UNCONFIRMED'),lambda d:d['observation']['details'].update(failed_case_ids=['png_positive']),
   lambda d:d['observation']['details'].update(case_count=13),lambda d:d['observation'].update(observed=False))
  for change in changes:
   value=deepcopy(self.value);change(value)
   with self.subTest(change=repr(change)),self.assertRaises((p.ProvenanceUnavailable,identity.DiagnosticUnavailable,identity_native.NativeUnavailable)):
    p.validate_consumed_identity(value)
 def replay(self,mutate=None):
  owned=diagnostic.modules()[3]
  docs={row['directory']+'/'+name:owned._canonical(info['document']) for row in self.rows for name,info in row['files'].items()}
  if mutate:mutate(docs)
  reads=[]
  def read(root,pins,api,path,**kw):
   if path in docs:raw=docs[path];reads.append(path)
   elif 'native-run-' in path:raise FileNotFoundError()
   else:raw=Path(path).read_bytes()
   if 'expected' in kw:p.require(hashlib.sha256(raw).hexdigest()==kw['expected'])
   return raw
  @contextmanager
  def no_pin(*a,**kw):yield
  root=Path.cwd().resolve();directories=[root/row['directory'] for row in self.rows]
  prepared=json.loads(Path(diagnostic.receipt_path('prepare')).read_text())['preparation']
  with patch.object(current,'pin_bytes',read),patch.object(Path,'glob',return_value=directories),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:result=p.preserved_originals(root,pins,Mock(),prepared)
  return result,reads
 def test_all27_distinct_originals_and108_actual_canonical_documents(self):
  result,reads=self.replay()
  self.assertEqual(len(result),27);self.assertEqual(len({r['token'] for r in result}),27)
  self.assertEqual(len({r['original_id'] for r in result}),27);self.assertEqual(sum(len(r['files']) for r in result),108)
  self.assertEqual(len(set(reads)),108);self.assertEqual(len(reads),135)
 def test_each_changed_consumed_identity_original_document_refuses(self):
  directory=self.value['new_original']['directory']
  for name in ('reservation.json','create-attempt.json','ownership.json','result.json'):
   def mutate(docs):docs[directory+'/'+name]+=b' '
   with self.subTest(name=name),self.assertRaises(diagnostic.DiagnosticUnavailable):self.replay(mutate)
 def test_missing_consumed_original_is_not_adopted_from_saved_metadata(self):
  name=self.value['new_original']['directory']+'/ownership.json'
  with self.assertRaises(FileNotFoundError):self.replay(lambda docs:docs.pop(name))
 def test_old_negative_strict_guard_and_false_flags_preserved_during_replay(self):
  original=Path('ai/state/private-scanner-rmdir-proof-strict.json').read_bytes();self.replay()
  self.assertEqual(original,Path('ai/state/private-scanner-rmdir-proof-strict.json').read_bytes())
  saved=json.loads(original);self.assertFalse(saved['pins_closed']);self.assertEqual(saved['active_case'],'strict')

class Pins(unittest.TestCase):
 def binding(self,**changes):
  old=p.identity_binding();fields={name:'a'*64 for name in p.BINDING_FIELDS}
  fields.update(image_id=old.image_id,signature_generation=old.signature_generation,profile_sha256=old.profile_sha256,
   preparation_sha256=old.preparation_sha256,telemetry_sha256=p.TELEMETRY_SHA256,failed_receipt_sha256=p.FAILED_SHA256,contract=p.CONTRACT)
  fields.update(changes);kind=make_dataclass('SyntheticBinding',[(name,str) for name in fields],frozen=True);return kind(**fields)
 def test_closed_binding_keeps_exact_consumed_receipt_category_parser_contract(self):
  self.assertEqual(set(p.binding_fields(self.binding())),p.BINDING_FIELDS)
  for changed in ({'native_sha256':None},{'provenance_sha256':'0'*64},{'failed_receipt_sha256':'f'*64},{'telemetry_sha256':'f'*64},{'contract':'f'*64}):
   with self.assertRaises(p.ProvenanceUnavailable):p.binding_fields(self.binding(**changed))
 def test_three_old_identity_sources_pinned_before_import_and_new_sources_return(self):
  events=[];binding=self.binding();original=p.inherited
  def inherited():events.append('IDENTITY_IMPORT');return original()
  def read(root,pins,api,path,**kw):events.append(path)
  with patch.object(current,'pin_bytes',read),patch.object(p,'inherited',side_effect=inherited),patch.object(identity,'_pin_sources') as transitive:
   p.pin_sources(Path('.'),ExitStack(),Mock(),binding)
  self.assertEqual(events[:3],[p.IDENTITY_CONTROLLER,p.IDENTITY_NATIVE,p.IDENTITY_PROVENANCE])
  self.assertEqual(events[3:5],['ai/state/private-scanner-strict-identity-preflight.json',p.FAILED]);self.assertGreater(events.index('IDENTITY_IMPORT'),4);transitive.assert_called_once()
  self.assertIn('infra/evidence_strict_category_controller.py',events);self.assertIn(p.TELEMETRY,events)
 def test_changed_consumed_receipt_pin_stops_before_inherited_binding_or_validator(self):
  for denied in ('ai/state/private-scanner-strict-identity-preflight.json',p.FAILED):
   events=[]
   def read(root,pins,api,path,**kw):
    events.append(path)
    if path==denied:raise p.ProvenanceUnavailable()
   with patch.object(current,'pin_bytes',side_effect=read),patch.object(p,'inherited') as inherited:
    with self.assertRaises(p.ProvenanceUnavailable):p.pin_sources(Path('.'),ExitStack(),Mock(),object())
   inherited.assert_not_called();self.assertEqual(events[-1],denied)
 def test_changed_old_source_stops_before_old_import_or_new_load(self):
  with patch.object(current,'pin_bytes',side_effect=p.ProvenanceUnavailable()),patch.object(p,'inherited') as inherited:
   with self.assertRaises(p.ProvenanceUnavailable):p.pin_sources(Path('.'),ExitStack(),Mock(),object())
  inherited.assert_not_called()

class Reservations(unittest.TestCase):
 def setUp(self):
  value=json.loads(Path(p.FAILED).read_text());self.rows=value['preserved_originals']+[value['new_original']]
  self.base=deepcopy(self.rows[-1]['files']['reservation.json']['document'])
 def check(self,value,count=1):
  directory=Path(diagnostic.STAGE+'/native-run-'+value.get('token',self.base['token']))
  @contextmanager
  def no_pin(*a,**kw):yield
  with patch.object(Path,'glob',return_value=[directory]*count),patch.object(current,'pin_bytes',return_value=json.dumps(value).encode()),patch('infra.live_recovery_drill.PrivateDirectory') as private:
   private.return_value.pin=no_pin
   with ExitStack() as pins:p.unknown_reservations(Path('.'),pins,Mock(),self.rows)
 def test_known_consumed_identity_owner_allowed_exactly(self):self.check(self.base)
 def test_unknown_identity_owner_or_changed_image_refuses(self):
  for change in (lambda d:d.update(image_id='sha256:'+'f'*64),lambda d:d.update(token='f'*32),lambda d:d.update(extra='CANARY')):
   value=deepcopy(self.base);change(value)
   if value['token']!=self.base['token']:value['expected_labels'].update({'org.kapit.reservation':value['token']})
   with self.assertRaises(p.ProvenanceUnavailable):self.check(value)
 def test_every_new_category_owner_or_purpose_refuses_before_image_filter(self):
  for owner,purpose in ((p.OWNER,'other'),('other',p.PURPOSE)):
   value=deepcopy(self.base);value.update(image_id='sha256:'+'f'*64,purpose=purpose)
   value['expected_labels'].update({'org.kapit.owner':owner,'org.kapit.purpose':purpose})
   with self.assertRaises(p.ProvenanceUnavailable):self.check(value)
 def test_base_malformed_even_other_owner_is_rejected(self):
  for value in ({},dict(self.base,schema=True),dict(self.base,image_id='bad'),dict(self.base,expected_labels={}),dict(self.base,purpose='')):
   with self.assertRaises(p.ProvenanceUnavailable):self.check(value)
 def test_bounded256_discovery_refuses_257(self):
  with self.assertRaises(p.ProvenanceUnavailable):self.check(self.base,257)

if __name__=='__main__':unittest.main()
