"""Synthetic failure-frame coverage; no native calls or protected IO."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from infra import evidence_strict_failure_details as details
from infra.native import strict_probe as strict


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def frame(failed=('png_positive',), *, count=14, completed=True, stage='CASES'):
    rows=[]
    for name,kind,expected in strict.FAILURE_CASES[:count]:
        observed='ERROR' if expected=='NONCLEAN' else expected
        if name in failed:observed='CLEAN' if expected=='NONCLEAN' else 'ERROR'
        upstream='NOT_RUN' if kind=='PRECONDITION' else 'CLEAN'
        passed=observed!='CLEAN' if expected=='NONCLEAN' else observed==expected
        rows.append({'case':name,'kind':kind,'strict':observed,'upstream':upstream,'passed':passed,
                     'normalization_observed':observed!='CLEAN' and upstream=='CLEAN'})
    return {'schema':1,'scope':'PUBLIC_STRICT_NATIVE_PROBE_ONLY','completed':completed,'passed':False,
            'cases':rows,'native_eligible':False,'diagnostic':{'stage':stage,'kind':'REFUSED',
            'location':{'source':'UNKNOWN','function':'UNKNOWN','line':0}}}


class StrictFailureDetails(unittest.TestCase):
    def refused(self,raw):
        with self.assertRaises(strict.ProbeUnavailable) as error:details.parse_failure_details(raw)
        self.assertEqual(str(error.exception),'PUBLIC_NATIVE_PROBE_UNAVAILABLE')

    def test_exact_nine_key_output_and_failure_only_flags(self):
        value=details.parse_failure_details(encoded(frame()))
        self.assertEqual(set(value),{'schema','scope','private_input_allowed','diagnostic','completed',
                                     'passed','case_count','native_eligible','failed_case_ids'})
        self.assertIs(type(value['schema']),int);self.assertEqual(value['schema'],1)
        self.assertEqual(value['scope'],'PUBLIC_STRICT_FAILURE_DETAILS_ONLY')
        self.assertEqual(value['failed_case_ids'],['png_positive']);self.assertEqual(value['case_count'],14)
        self.assertIs(value['completed'],True)
        for name in ('passed','native_eligible','private_input_allowed'):self.assertIs(value[name],False)
        self.assertEqual(json.loads(encoded(value)),value)

    def test_every_literal_case_failure_retains_only_its_identity(self):
        for name in strict.CASE_IDS:
            with self.subTest(case=name):
                self.assertEqual(details.parse_failure_details(encoded(frame((name,))))['failed_case_ids'],[name])

    def test_distinct_failures_previously_collapsing_to_identical_summary_differ(self):
        first=encoded(frame(('png_positive',)));second=encoded(frame(('engine_max_scan',)))
        self.assertEqual(strict.parse_failure(first),strict.parse_failure(second))
        self.assertNotEqual(details.parse_failure_details(first)['failed_case_ids'],details.parse_failure_details(second)['failed_case_ids'])

    def test_multiple_failures_keep_literal_order_not_requested_order(self):
        requested=('engine_max_scan','eicar_png','png_positive','fmap_short')
        self.assertEqual(details.parse_failure_details(encoded(frame(requested)))['failed_case_ids'],
                         [name for name in strict.CASE_IDS if name in requested])

    def test_all_fourteen_can_fail_without_weakening_expectations(self):
        result=details.parse_failure_details(encoded(frame(strict.CASE_IDS)))
        self.assertEqual(result['failed_case_ids'],list(strict.CASE_IDS));self.assertIs(result['passed'],False)

    def test_partial_prefix_can_retain_valid_failed_ids(self):
        for count in range(1,14):
            name=strict.CASE_IDS[count-1]
            with self.subTest(count=count):
                value=details.parse_failure_details(encoded(frame((name,),count=count,completed=False)))
                self.assertEqual(value['case_count'],count);self.assertEqual(value['failed_case_ids'],[name])
                self.assertIs(value['completed'],False)

    def test_partial_prefix_with_only_passed_rows_remains_failure(self):
        for count in range(1,14):
            with self.subTest(count=count):
                value=details.parse_failure_details(encoded(frame((),count=count,completed=False)))
                self.assertEqual(value['failed_case_ids'],[]);self.assertIs(value['passed'],False)
                self.assertIs(value['completed'],False);self.assertEqual(value['case_count'],count)

    def test_zero_case_initialization_failure_is_preserved(self):
        for stage in ('WORKER_IMPORT','CONFIGURATION','PUBLIC_IMAGES','SCANNER_INITIALIZATION'):
            with self.subTest(stage=stage):
                source=frame((),count=0,completed=False,stage=stage)
                value=details.parse_failure_details(encoded(source))
                self.assertEqual(value['diagnostic'],source['diagnostic']);self.assertEqual(value['failed_case_ids'],[])
                self.assertEqual(value['case_count'],0);self.assertIs(value['completed'],False)

    def test_engine_or_scratch_finalizer_failure_overrides_all_passed_rows(self):
        for stage in ('ENGINE_CLEANUP','SCRATCH_CLEANUP'):
            with self.subTest(stage=stage):
                source=frame((),completed=False,stage=stage)
                source['diagnostic'].update(kind='VALUE_ERROR',location={'source':'WORKER','function':'_scratch_empty','line':131})
                value=details.parse_failure_details(encoded(source))
                self.assertEqual(value['diagnostic'],source['diagnostic']);self.assertEqual(value['failed_case_ids'],[])
                self.assertEqual(value['case_count'],14);self.assertIs(value['completed'],False)

    def test_finalizer_failure_can_preserve_also_failed_case_ids(self):
        source=frame(('eicar_png',),completed=False,stage='ENGINE_CLEANUP')
        value=details.parse_failure_details(encoded(source))
        self.assertEqual(value['failed_case_ids'],['eicar_png']);self.assertIs(value['completed'],False)

    def test_completed_semantic_failure_requires_nonempty_subset_and_full_order(self):
        self.refused(encoded(frame(())))
        self.refused(encoded(frame(('png_positive',),count=13)))

    def test_success_saved_lossy_summary_and_own_telemetry_are_rejected(self):
        success=frame(());success.update(passed=True);success.pop('diagnostic')
        self.refused(encoded(success))
        self.refused(encoded(strict.parse_failure(encoded(frame()))))
        self.refused(encoded(details.parse_failure_details(encoded(frame()))))

    def test_validator_runs_before_same_immutable_bytes_are_decoded_again(self):
        raw=encoded(frame());events=[];original_validator=strict.parse_failure;original_decoder=strict._failure_document
        def validator(value):
            self.assertIs(value,raw);events.append('validator_enter')
            result=original_validator(value);events.append('validator_exit');return result
        def decoder(value):self.assertIs(value,raw);events.append('decode');return original_decoder(value)
        with patch.object(strict,'parse_failure',side_effect=validator),patch.object(strict,'_failure_document',side_effect=decoder):
            details.parse_failure_details(raw)
        self.assertEqual(events,['validator_enter','decode','validator_exit','decode'])

    def test_refused_validator_stops_before_detail_decoder(self):
        with patch.object(strict,'parse_failure',side_effect=strict.ProbeUnavailable()),patch.object(strict,'_failure_document') as decoder:
            self.refused(b'invalid')
        decoder.assert_not_called()

    def test_exact_bytes_type_and_boundaries(self):
        class BytesSubclass(bytes):pass
        for raw in (None,True,1,{},[],encoded(frame()).decode(),bytearray(encoded(frame())),memoryview(encoded(frame())),BytesSubclass(encoded(frame())),b'',b'0',b' '*16385):
            with self.subTest(kind=type(raw).__name__,length=len(raw) if hasattr(raw,'__len__') else None):self.refused(raw)
        raw=encoded(frame());maximum=raw+b' '*(16384-len(raw))
        self.assertEqual(details.parse_failure_details(maximum)['failed_case_ids'],['png_positive'])
        self.refused(maximum+b' ')

    def test_malformed_unicode_duplicate_and_nonfinite_json_are_rejected(self):
        good=encoded(frame())
        changes=(b'not json',b'\xff',b'null',b'false',b'[]',b'{}',b'{',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":-Infinity}',
                 good.replace(b'"schema":1',b'"schema":1,"schema":1'),
                 good.replace(b'"stage":"CASES"',b'"stage":"CASES","stage":"CASES"'),
                 good.replace(b'"case":"png_positive"',b'"case":"png_positive","case":"png_positive"'),
                 good.replace(b'"schema":1',b'"schema":NaN'))
        for raw in changes:
            with self.subTest(raw=raw[:40]):self.refused(raw)

    def test_invalid_case_identity_duplicate_reordering_and_kind_are_rejected(self):
        changes=(lambda d:d['cases'][0].update(case='UNKNOWN'),lambda d:d['cases'][1].update(case='png_positive'),
                 lambda d:d['cases'].reverse(),lambda d:d['cases'][0].update(kind='PARSER'),
                 lambda d:d['cases'].append(deepcopy(d['cases'][-1])),lambda d:d['cases'].insert(0,d['cases'].pop(1)))
        for change in changes:
            value=frame();change(value)
            with self.subTest(change=repr(change)):self.refused(encoded(value))

    def test_type_boolean_category_and_predicate_contradictions_are_rejected(self):
        changes=(lambda d:d.update(schema=True),lambda d:d.update(schema=1.0),lambda d:d.update(completed=1),
                 lambda d:d.update(passed=0),lambda d:d.update(native_eligible=0),lambda d:d.update(cases={}),
                 lambda d:d['cases'][0].update(passed=0),lambda d:d['cases'][0].update(passed=True),
                 lambda d:d['cases'][0].update(strict='UNKNOWN'),lambda d:d['cases'][0].update(strict=False),
                 lambda d:d['cases'][0].update(upstream='UNKNOWN'),lambda d:d['cases'][0].update(upstream='NOT_RUN'),
                 lambda d:d['cases'][8].update(upstream='CLEAN'),lambda d:d['cases'][0].update(normalization_observed=False),
                 lambda d:d['cases'][0].update(normalization_observed=1),lambda d:d['cases'][0].update(extra='CANARY'))
        for change in changes:
            value=frame();change(value)
            with self.subTest(change=repr(change)):self.refused(encoded(value))

    def test_diagnostic_unknown_schema_types_and_locations_refuse(self):
        changes=(lambda d:d['diagnostic'].update(stage='UNKNOWN'),lambda d:d['diagnostic'].update(kind='UNKNOWN'),
                 lambda d:d['diagnostic']['location'].update(line=True),lambda d:d['diagnostic']['location'].update(line=1),
                 lambda d:d['diagnostic']['location'].update(source='HOST'),lambda d:d['diagnostic']['location'].update(function='CANARY'),
                 lambda d:d['diagnostic'].update(extra='CANARY'),lambda d:d.update(extra='CANARY'))
        for change in changes:
            value=frame();change(value)
            with self.subTest(change=repr(change)):self.refused(encoded(value))

    def test_input_and_output_mutations_cannot_affect_later_calls(self):
        source=frame();raw=encoded(source);first=details.parse_failure_details(raw)
        first['failed_case_ids'].append('CANARY');first['diagnostic']['location']['function']='CANARY'
        first.update(completed=False,native_eligible=True)
        second=details.parse_failure_details(raw)
        self.assertEqual(second['failed_case_ids'],['png_positive']);self.assertNotIn('CANARY',encoded(second).decode())
        self.assertEqual(raw,encoded(source));self.assertIsNot(first['diagnostic'],second['diagnostic'])

    def test_only_literal_ids_and_finite_diagnostic_survive_without_rows_or_payloads(self):
        value=details.parse_failure_details(encoded(frame(('eicar_png','engine_max_file'))))
        self.assertEqual(value['failed_case_ids'],['eicar_png','engine_max_file'])
        for forbidden in ('cases','strict','upstream','payload','path','sha256','exception','kind'):
            self.assertNotIn(forbidden,value)
        raw=encoded(frame()).replace(b'png_positive',b'CANARY_PRIVATE_CONTENT',1)
        self.refused(raw)

    def test_import_is_inert_without_native_execution_io_or_hashing(self):
        code=compile(Path(details.__file__).read_bytes(),'<synthetic-module>','exec');namespace={'__name__':'inert_details'}
        with patch.object(strict,'main',side_effect=AssertionError('native')),patch.object(strict,'_run',side_effect=AssertionError('native')),patch.object(strict,'_exercise',side_effect=AssertionError('native')),patch('builtins.open',side_effect=AssertionError('IO')),patch.object(strict,'parse_failure',side_effect=AssertionError('parse during import')):
            exec(code,namespace)
        self.assertEqual(namespace['__all__'],('parse_failure_details',));self.assertNotIn('main',namespace)


if __name__=='__main__':unittest.main()
