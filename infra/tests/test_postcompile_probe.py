"""Pure finite-classifier fixtures. No native library or container is loaded."""
import ctypes
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infra.native import postcompile_probe as probe


def encoded(doc):return json.dumps(doc,separators=(',',':')).encode('ascii')


def fixture(rows=(('17',0,0),), *, configuration_fail=False, close_fail=False, scratch_fail=False):
    events=[]
    class Scanner:
        def __init__(self):
            events.append('construct')
            try:self._check_limits()
            except BaseException:
                self.close();raise

        def _check_limits(self):
            for field,observed,flag in rows:
                error = ctypes.c_int(flag)
                if type(observed) is not int or field not in probe.EXPECTED or observed != probe.EXPECTED[field] or error.value:
                    raise ValueError('SECRET NATIVE DETAILS MUST NOT ESCAPE')

        def close(self):
            events.append('close')
            if close_fail:raise RuntimeError('SECRET cleanup details')

    def configuration():
        events.append('configuration')
        if configuration_fail:raise ValueError('SECRET configuration details')

    def scratch():
        events.append('scratch')
        if scratch_fail:raise RuntimeError('SECRET scratch details')

    return SimpleNamespace(NativeScanner=Scanner,load_configuration=configuration,_scratch_empty=scratch),events


class DiagnosticTests(unittest.TestCase):
    def test_first_original_failure_only_returns_field_and_finite_mode(self):
        worker,events=fixture((('0',33554432,0),('17',0,0),('25',0,0)))
        result=probe.run(worker)
        self.assertEqual(result,probe._result('FIRST_MISMATCH','17','AUTO'))
        self.assertEqual(events,['configuration','construct','close','scratch'])
        text=encoded(result)
        self.assertNotIn(b'SECRET',text);self.assertNotIn(b'observed',text);self.assertNotIn(b'error',text)
        self.assertFalse(result['native_eligible']);self.assertFalse(result['private_input_allowed'])

    def test_fixed_mode_categories_and_arbitrary_values_are_finite(self):
        for value,category in ((0,'AUTO'),(1,'JIT'),(3,'TEST'),(4,'OFF'),(-1,'UNKNOWN'),(2**1000,'UNKNOWN'),(True,'INVALID_TYPE'),
                               ('SECRET','INVALID_TYPE'),(None,'INVALID_TYPE'),(object(),'INVALID_TYPE')):
            with self.subTest(category=category):
                worker,_=fixture((('17',value,0),));result=probe.run(worker)
                self.assertEqual(result,probe._result('FIRST_MISMATCH','17',category))

    def test_expected_interpreter_is_not_mismatch_and_constructor_success_is_distinct(self):
        worker,events=fixture((('17',2,0),('26',4,0)))
        self.assertEqual(probe.run(worker),probe._result('NO_MISMATCH'))
        self.assertEqual(events,['configuration','construct','close','scratch'])

    def test_other_field_values_never_exposed_and_getter_errors_dominate_values(self):
        for field in probe.FIELDS-{'17'}:
            worker,_=fixture(((field,-123456789,0),))
            self.assertEqual(probe.run(worker),probe._result('FIRST_MISMATCH',field,'VALUE_MISMATCH'))
        for value in (0,True,'SECRET'):
            worker,_=fixture((('17',value,1),))
            self.assertEqual(probe.run(worker),probe._result('FIRST_MISMATCH','17','GETTER_ERROR'))

    def test_unknown_fields_bool_as_field_and_subclass_strings_refuse(self):
        class EvilString(str):pass
        for field in ('99',17,True,None,EvilString('17')):
            with self.subTest(field_type=type(field).__name__):
                worker,_=fixture(((field,0,0),));result=probe.run(worker)
                self.assertEqual(result,probe._result('UNCLASSIFIED'))

    def test_error_must_be_exact_ctypes_integer_before_property_access(self):
        touched=[]
        class Evil:
            @property
            def value(self):touched.append(True);raise AssertionError('must not execute')
        for flag in (Evil(),True,0,None,ctypes.c_longlong(0)):
            def target():
                field='17';observed=0;error=flag
                raise ValueError('SECRET')
            worker=SimpleNamespace(NativeScanner=SimpleNamespace(_check_limits=target))
            try:target()
            except ValueError as exc:self.assertEqual(probe.classify(exc,worker),probe._result('UNCLASSIFIED'))
        self.assertEqual(touched,[])

    def test_spoofed_name_and_qualname_frame_cannot_match_original_code(self):
        worker,_=fixture()
        def forged():
            field='17';observed=0;error=ctypes.c_int(0)
            raise ValueError('SECRET')
        forged.__name__='_check_limits';forged.__qualname__='NativeScanner._check_limits'
        try:forged()
        except ValueError as exc:self.assertEqual(probe.classify(exc,worker),probe._result('UNCLASSIFIED'))

    def test_original_context_is_not_read_when_constructor_cleanup_replaces_exception(self):
        worker,events=fixture(close_fail=True)
        result=probe.run(worker)
        self.assertFalse(result['completed']);self.assertEqual(result['field'],'NONE')
        self.assertEqual(events,['configuration','construct','close','scratch'])

    def test_cleanup_failure_dominates_mismatch_and_no_mismatch(self):
        for rows in ((('17',0,0),),(('17',2,0),)):
            worker,_=fixture(rows,scratch_fail=True)
            self.assertEqual(probe.run(worker),probe._result('CLEANUP_FAILED'))
        worker,_=fixture((('17',2,0),),close_fail=True)
        self.assertEqual(probe.run(worker),probe._result('CLEANUP_FAILED'))

    def test_configuration_failure_never_constructs_engine_and_still_checks_scratch(self):
        worker,events=fixture(configuration_fail=True)
        self.assertEqual(probe.run(worker),probe._result('CONFIGURATION_REFUSED'))
        self.assertEqual(events,['configuration','scratch'])

    def test_duplicate_matching_frames_and_overlong_traceback_refuse(self):
        def recursive(depth):
            field='17';observed=0;error=ctypes.c_int(0)
            if depth:recursive(depth-1)
            raise ValueError('SECRET')
        worker=SimpleNamespace(NativeScanner=SimpleNamespace(_check_limits=recursive))
        for depth in (1,40):
            try:recursive(depth)
            except ValueError as exc:self.assertEqual(probe.classify(exc,worker),probe._result('UNCLASSIFIED'))

    def test_known_type_matching_expected_value_cannot_be_fabricated_as_mismatch(self):
        def target():
            field='17';observed=2;error=ctypes.c_int(0)
            raise ValueError('SECRET unrelated failure')
        worker=SimpleNamespace(NativeScanner=SimpleNamespace(_check_limits=target))
        try:target()
        except ValueError as exc:self.assertEqual(probe.classify(exc,worker),probe._result('UNCLASSIFIED'))

    def test_closed_result_schema_types_modes_and_no_eligibility(self):
        good=probe._result('FIRST_MISMATCH','17','AUTO')
        self.assertEqual(probe.parse_result(encoded(good)),good)
        for updates in ({'schema':True},{'completed':1},{'native_eligible':True},{'private_input_allowed':True},{'passed':True},
                        {'scope':'PUBLIC_STRICT_NATIVE_PROBE_ONLY'},{'field':'99'},{'field':17},{'category':0},
                        {'field':'0','category':'AUTO'},{'category':'INTERPRETER'},{'category':'SECRET'},
                        {'observation':'NO_MISMATCH'},{'observation':'CLEANUP_FAILED'},{'completed':False}):
            with self.subTest(updates=updates),self.assertRaises(probe.ProbeUnavailable):probe.parse_result(encoded({**good,**updates}))
        for observation in probe.FAILURES|{'NO_MISMATCH'}:
            result=probe._result(observation)
            self.assertEqual(probe.parse_result(encoded(result)),result)

    def test_duplicate_nonfinite_deep_huge_and_nonbyte_json_refuse(self):
        for raw in (b'{"schema":1,"schema":1}',b'{"x":NaN}',b'['*40+b'0'+b']'*40,b' '*4097,'{}',b'\xff'):
            with self.subTest(type=type(raw).__name__),self.assertRaises(probe.ProbeUnavailable):probe.parse_result(raw)

    def test_main_rejects_arguments_before_import_and_never_reads_stdin(self):
        with patch.object(probe.sys,'argv',['fixed','unexpected']),patch.object(probe.sys,'stdin',new=object()),patch.object(probe.sys,'stdout',new_callable=io.StringIO) as output:
            self.assertEqual(probe.main(),2);self.assertEqual(output.getvalue(),'')


if __name__ == '__main__':unittest.main()
