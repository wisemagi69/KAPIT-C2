"""Synthetic categories/regression coverage; no native or protected IO."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from infra import evidence_strict_failure_categories as categories
from infra import evidence_strict_failure_details as identity
from infra.native import strict_probe as strict
from infra.tests.test_strict_failure_details import frame,encoded


class FailureCategories(unittest.TestCase):
    def refused(self,raw):
        with self.assertRaises(strict.ProbeUnavailable) as error:categories.parse_failure_categories(raw)
        self.assertEqual(str(error.exception),'PUBLIC_NATIVE_PROBE_UNAVAILABLE')

    def test_exact_ten_field_schema_and_four_field_failed_records(self):
        value=categories.parse_failure_categories(encoded(frame(('eicar_png',))))
        self.assertEqual(set(value),{'schema','scope','private_input_allowed','native_eligible','passed',
            'diagnostic','completed','case_count','failed_case_ids','failed_cases'})
        self.assertIs(type(value['schema']),int);self.assertEqual(value['schema'],1)
        self.assertEqual(value['scope'],'PUBLIC_STRICT_FAILURE_CATEGORIES_ONLY')
        for key in ('native_eligible','private_input_allowed','passed'):self.assertIs(value[key],False)
        self.assertEqual(value['failed_case_ids'],['eicar_png']);self.assertEqual(value['case_count'],14)
        self.assertEqual(set(value['failed_cases'][0]),{'case','strict','upstream','normalization_observed'})
        self.assertEqual(json.loads(encoded(value)),value)

    def test_clean_and_error_eicar_failures_stay_distinct_without_changing_not_clean_expectation(self):
        outputs=[];identities=[]
        for observed in ('CLEAN','ERROR'):
            source=frame(('eicar_png',));row=source['cases'][2]
            row.update(strict=observed,passed=False,upstream='CLEAN',normalization_observed=observed!='CLEAN')
            raw=encoded(source);outputs.append(categories.parse_failure_categories(raw));identities.append(identity.parse_failure_details(raw))
        self.assertEqual(identities[0],identities[1]);self.assertNotEqual(outputs[0],outputs[1])
        self.assertEqual([v['failed_cases'][0]['strict'] for v in outputs],['CLEAN','ERROR'])
        for value in outputs:self.assertIs(value['passed'],False)
        source=frame((),completed=False);source['cases'][2].update(strict='NOT_CLEAN')
        self.assertNotIn('eicar_png',categories.parse_failure_categories(encoded(source))['failed_case_ids'])

    def test_each_literal_failure_retains_its_validated_categories_only(self):
        for name in strict.CASE_IDS:
            with self.subTest(case=name):
                source=frame((name,));raw=encoded(source);value=categories.parse_failure_categories(raw)
                expected=next(row for row in source['cases'] if row['case']==name)
                self.assertEqual(value['failed_cases'],[{key:expected[key] for key in ('case','strict','upstream','normalization_observed')}])
                self.assertEqual(value['failed_case_ids'],[name])

    def test_multiple_or_all_failures_keep_suite_order_and_maximum_fourteen(self):
        for requested in (('engine_max_scan','eicar_png','png_positive'),tuple(reversed(strict.CASE_IDS))):
            value=categories.parse_failure_categories(encoded(frame(requested)))
            expected=[name for name in strict.CASE_IDS if name in requested]
            self.assertEqual(value['failed_case_ids'],expected);self.assertEqual([row['case'] for row in value['failed_cases']],expected)
            self.assertLessEqual(len(value['failed_cases']),14)

    def test_all_valid_upstream_categories_preserve_normalization_consistency(self):
        for observed in ('CLEAN','ERROR'):
            for upstream in ('CLEAN','NOT_CLEAN','ERROR'):
                source=frame(('eicar_png',));source['cases'][2].update(strict=observed,upstream=upstream,
                    normalization_observed=observed!='CLEAN' and upstream=='CLEAN')
                row=categories.parse_failure_categories(encoded(source))['failed_cases'][0]
                self.assertEqual(row['upstream'],upstream)
                self.assertIs(row['normalization_observed'],observed!='CLEAN' and upstream=='CLEAN')
        source=frame(('fmap_null',))
        self.assertEqual(categories.parse_failure_categories(encoded(source))['failed_cases'][0]['upstream'],'NOT_RUN')

    def test_partial_zero_and_finalizer_failures_never_gain_acceptance(self):
        for count in range(15):
            with self.subTest(count=count):
                failed=() if count==0 else (strict.CASE_IDS[count-1],)
                value=categories.parse_failure_categories(encoded(frame(failed,count=count,completed=False)))
                self.assertEqual(value['case_count'],count);self.assertEqual(value['failed_case_ids'],list(failed))
                self.assertIs(value['completed'],False);self.assertIs(value['passed'],False)
        for stage in ('ENGINE_CLEANUP','SCRATCH_CLEANUP'):
            source=frame((),completed=False,stage=stage);value=categories.parse_failure_categories(encoded(source))
            self.assertEqual(value['failed_cases'],[]);self.assertEqual(value['failed_case_ids'],[])
            self.assertEqual(value['diagnostic'],source['diagnostic']);self.assertEqual(value['case_count'],14)
            self.assertIs(value['completed'],False)

    def test_passing_partial_rows_are_omitted_without_erasing_failure(self):
        source=frame((),count=7,completed=False);value=categories.parse_failure_categories(encoded(source))
        self.assertEqual(value['failed_cases'],[]);self.assertEqual(value['case_count'],7);self.assertIs(value['passed'],False)

    def test_validated_failure_runs_first_before_decoding_identical_immutable_bytes(self):
        raw=encoded(frame());events=[];validate=strict.parse_failure;decode=strict._failure_document
        def first(value):
            self.assertIs(value,raw);events.append('validator');result=validate(value);events.append('validated');return result
        def second(value):self.assertIs(value,raw);events.append('decoder');return decode(value)
        with patch.object(strict,'parse_failure',side_effect=first),patch.object(strict,'_failure_document',side_effect=second):
            categories.parse_failure_categories(raw)
        self.assertEqual(events,['validator','decoder','validated','decoder'])

    def test_validation_refusal_prevents_detail_extraction(self):
        with patch.object(strict,'parse_failure',side_effect=strict.ProbeUnavailable()),patch.object(strict,'_failure_document') as decoder:
            self.refused(b'rejected')
        decoder.assert_not_called()

    def test_contradictory_categories_passed_and_normalization_refuse(self):
        changes=(lambda d:d['cases'][2].update(passed=True),lambda d:d['cases'][2].update(passed=0),
            lambda d:d['cases'][2].update(normalization_observed=False),lambda d:d['cases'][2].update(normalization_observed=1),
            lambda d:d['cases'][2].update(strict='NOT_CLEAN'),lambda d:d['cases'][2].update(strict='UNKNOWN'),
            lambda d:d['cases'][2].update(upstream='UNKNOWN'),lambda d:d['cases'][2].update(upstream='NOT_RUN'),
            lambda d:d['cases'][8].update(upstream='CLEAN'))
        for change in changes:
            source=frame(('eicar_png',));change(source)
            with self.subTest(change=repr(change)):self.refused(encoded(source))

    def test_unknown_duplicate_reordered_ids_and_extra_row_fields_refuse(self):
        changes=(lambda d:d['cases'][2].update(case='UNKNOWN'),lambda d:d['cases'][2].update(case='png_positive'),
            lambda d:d['cases'].reverse(),lambda d:d['cases'][2].update(extra='CANARY'),
            lambda d:d['cases'][2].update(kind='PARSER'),lambda d:d['cases'].append(deepcopy(d['cases'][-1])))
        for change in changes:
            source=frame(('eicar_png',));change(source)
            with self.subTest(change=repr(change)):self.refused(encoded(source))

    def test_boolean_top_level_diagnostic_and_schema_contradictions_refuse(self):
        changes=(lambda d:d.update(schema=True),lambda d:d.update(schema=1.0),lambda d:d.update(completed=1),
            lambda d:d.update(passed=0),lambda d:d.update(native_eligible=0),lambda d:d.update(extra='CANARY'),
            lambda d:d['diagnostic'].update(stage='UNKNOWN'),lambda d:d['diagnostic']['location'].update(line=True))
        for change in changes:
            source=frame();change(source)
            with self.subTest(change=repr(change)):self.refused(encoded(source))

    def test_exact_input_type_and_size_boundaries(self):
        class BytesSubclass(bytes):pass
        raw=encoded(frame())
        for bad in (None,True,{},[],raw.decode(),bytearray(raw),memoryview(raw),BytesSubclass(raw),b'',b'0',b' '*16385):
            with self.subTest(kind=type(bad).__name__):self.refused(bad)
        padded=raw+b' '*(16384-len(raw))
        self.assertEqual(categories.parse_failure_categories(padded)['case_count'],14);self.refused(padded+b' ')

    def test_malformed_utf8_nonfinite_and_duplicate_json_refuse(self):
        raw=encoded(frame())
        bad=(b'\xff',b'not json',b'null',b'false',b'[]',b'{}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":-Infinity}',
             raw.replace(b'"schema":1',b'"schema":1,"schema":1'),
             raw.replace(b'"strict":"ERROR"',b'"strict":"ERROR","strict":"ERROR"',1),
             raw.replace(b'"stage":"CASES"',b'"stage":"CASES","stage":"CASES"'))
        for value in bad:
            with self.subTest(prefix=value[:30]):self.refused(value)

    def test_success_completed_no_failures_lossy_summary_and_transforms_refuse(self):
        source=frame(());source.update(passed=True);source.pop('diagnostic');self.refused(encoded(source))
        self.refused(encoded(frame(())))
        raw=encoded(frame())
        for value in (strict.parse_failure(raw),identity.parse_failure_details(raw),categories.parse_failure_categories(raw)):
            self.refused(encoded(value))

    def test_detached_results_and_arrays_cannot_mutate_input_or_future_results(self):
        source=frame(('eicar_png',));raw=encoded(source);first=categories.parse_failure_categories(raw)
        first['failed_cases'][0].update(case='CANARY',strict='CANARY');first['failed_case_ids'].append('CANARY')
        first['diagnostic']['location']['function']='CANARY'
        next_result=categories.parse_failure_categories(raw)
        self.assertEqual(next_result['failed_case_ids'],['eicar_png']);self.assertEqual(next_result['failed_cases'][0]['case'],'eicar_png')
        self.assertNotIn('CANARY',encoded(next_result).decode());self.assertEqual(raw,encoded(source))

    def test_only_failed_closed_fields_survive_without_passing_rows_raw_codes_or_payloads(self):
        value=categories.parse_failure_categories(encoded(frame(('eicar_png',))))
        self.assertEqual(len(value['failed_cases']),1);self.assertNotIn('png_positive',encoded(value).decode())
        for field in ('cases','payload','path','sha256','return_code','exception','expected','kind','passed'):
            self.assertNotIn(field,value['failed_cases'][0])
        source=frame(('eicar_png',));source['cases'][2]['native_message']='CANARY_PRIVATE_CONTENT';self.refused(encoded(source))

    def test_import_is_inert_and_exposes_no_cli_or_native_execution(self):
        code=compile(Path(categories.__file__).read_bytes(),'<synthetic>','exec');namespace={'__name__':'inert_categories'}
        with patch('builtins.open',side_effect=AssertionError('IO')),patch.object(strict,'parse_failure',side_effect=AssertionError('parse')),\
             patch.object(strict,'_run',side_effect=AssertionError('native')),patch.object(strict,'main',side_effect=AssertionError('main')):
            exec(code,namespace)
        self.assertEqual(namespace['__all__'],('parse_failure_categories',));self.assertNotIn('main',namespace)


if __name__=='__main__':unittest.main()
