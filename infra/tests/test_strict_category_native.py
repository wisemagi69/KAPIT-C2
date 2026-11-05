"""Pure fake IO: no native execution or protected input."""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from infra import evidence_strict_category_native as native
from infra.tests.test_strict_failure_details import frame, encoded
from infra.tests.test_rmdir_native import Journal
from infra.test_evidence_native_runtime import inspection

from infra import evidence_native_attestation as attestation
from infra import evidence_native_runtime as runtime
from infra import evidence_native_ownership as ownership
from infra import evidence_rmdir_profile as profile
from infra import evidence_rmdir_diagnostic as mechanics

CID='e'*64
TOKEN='d'*32

def binding():
    return SimpleNamespace(image_id=native.IMAGE,signature_generation=native.GENERATION,
        profile_sha256=native.PROFILE_SHA256,preparation_sha256=native.PREPARATION_SHA256,
        native_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),controller_sha256='a'*64,
        provenance_sha256='b'*64,telemetry_sha256=native.TELEMETRY_SHA256,
        failed_receipt_sha256=native.FAILED_RECEIPT_SHA256,contract=native.CONTRACT)

def probe():return native._probe(TOKEN,native.PHASE_ID,binding())

def inspected(p):
    d=inspection(p.phase,exit_code=2)
    d.update(Name='/'+p.name)
    d['Config'].update(Labels=p.labels,Cmd=p.command)
    d['HostConfig']['SecurityOpt'][1]='seccomp='+profile.profile_bytes().decode('ascii')
    return d

class Context:
    def __init__(self):
        self.binding=binding();self.stage='diagnostic';self.call_uncertain=False;self.events=[]
        self.profile=Path('C:/fixed/profile');self.docker=Path('C:/fixed/docker');self.config=Path('C:/fixed/config')
        self.command=Mock(side_effect=self._command);self.cleanup_command=Mock()
        for name in ('before_phase','consume_before_create','retain_original','record_original'):
            setattr(self,name,Mock(side_effect=lambda *args,n=name:self.events.append(n)))
        self.attach_started=Mock(side_effect=lambda:self.events.append('attach_started'))
        self.attach_finalized=Mock(side_effect=lambda confirmed:self.events.append(('attach_finalized',confirmed)))
        self.finish_phase=Mock(side_effect=lambda *args:self.events.append('finish_phase') or True)
    def _command(self,*args,**kwargs):
        self.events.append('create');return 0,CID.encode()+b'\n',b'','EXIT'

class NativeCategory(unittest.TestCase):
    def harness(self,ctx,*,failure=None,payload=None,exit_code=2,cleanup_error=None,inspect_error=None,post=None,attach_error=None):
        p=probe();j=Journal(ctx.events,failure)
        @contextmanager
        def reserve(*args):yield j
        def inspect(*args):
            ctx.events.append('inspect')
            if inspect_error:raise inspect_error
            value=inspected(p)
            if post and ctx.events.count('inspect')==2:post(value)
            return value
        def attach(*args,**kwargs):
            ctx.events.append('attach')
            if attach_error is not None:raise attach_error
            return exit_code,encoded(frame() if payload is None else payload)
        stack=self.enterContext(ExitStack())
        for obj,name,value in ((native,'_probe',Mock(return_value=p)),(native,'_reserve',reserve),
            (native,'_check_context',Mock()),(runtime,'_require_cgroup_v2',Mock()),
            (mechanics,'inspect',Mock(side_effect=inspect)),(attestation,'_attach',attach),
            (mechanics,'cleanup',Mock(return_value='ORIGINAL_ID_ABSENT_VERIFIED',side_effect=cleanup_error))):
            stack.enter_context(patch.object(obj,name,value))
        return j

    def test_metadata_binds_all_sources_consumed_failure_and_new_owner(self):
        d=native.metadata(TOKEN,native.PHASE_ID,binding())
        self.assertEqual(d['expected_labels']['org.kapit.owner'],native.OWNER)
        self.assertEqual(d['expected_name'],native.NAME_PREFIX+TOKEN)
        for key in ('native','controller','provenance','telemetry','failed_receipt'):
            self.assertEqual(d[key+'_sha256'],d['expected_labels']['org.kapit.'+key])
        self.assertFalse(d['native_eligible']);self.assertFalse(d['private_input_allowed'])

    def test_wrong_binding_or_phase_rejected(self):
        for key in vars(binding()):
            b=binding();setattr(b,key,'wrong')
            with self.assertRaises(Exception):native.metadata(TOKEN,native.PHASE_ID,b)
        for token,phase in ((True,native.PHASE_ID),('a'*31,native.PHASE_ID),(TOKEN,'strict:scan:strict')):
            with self.assertRaises(Exception):native.metadata(token,phase,binding())

    def test_bad_metadata_never_reserves(self):
        d=native.metadata(TOKEN,native.PHASE_ID,binding());d['schema']=True
        with patch.object(ownership,'_Host') as host:
            with self.assertRaises(Exception):
                with native._reserve(d,binding()):pass
        host.assert_not_called()

    def test_fixed_program_and_resource_arguments(self):
        p=probe();args=native.create_args(p,Path('C:/fixed/profile'))
        self.assertEqual(p.command,['-I','-B','-c',attestation._strict_program()])
        self.assertEqual(args[-5:],[native.IMAGE,*p.command])
        self.assertEqual(args[args.index('--memory')+1],str(runtime.LIMITS['scan'][0]))
        self.assertEqual(args[args.index('--name')+1],p.name)

    def test_effective_inspection_checks_identity_and_resources_before_normalization(self):
        p=probe();good=inspected(p);native.verify_inspection(good,p,CID)
        for mutate in (lambda d:d.update(Name='/other'),lambda d:d['Config'].update(Cmd=['other']),
            lambda d:d['Config']['Labels'].update(extra='bad'),lambda d:d['HostConfig'].update(Memory=1),
            lambda d:d['HostConfig'].update(SecurityOpt=['seccomp=unconfined'])):
            d=deepcopy(good);mutate(d)
            with self.assertRaises(Exception):native.verify_inspection(d,p,CID)

    def test_complete_failure_retains_only_literal_ids(self):
        d=native._payload(encoded(frame(('png_positive','engine_max_scan'))),2)
        self.assertEqual(d['failed_case_ids'],['png_positive','engine_max_scan']);self.assertNotIn('cases',d)
        o={'phase_id':native.PHASE_ID,'observed':True,'details':d,'native_eligible':False,'private_input_allowed':False}
        self.assertEqual(native.validate_outcome(native.PHASE_ID,o),o)

    def test_partial_zero_and_finalizer_failures_remain_unobserved(self):
        for f in (frame((),count=0,completed=False,stage='CONFIGURATION'),
            frame(('png_positive',),count=2,completed=False),frame((),completed=False,stage='SCRATCH_CLEANUP')):
            d=native._payload(encoded(f),2)
            o={'phase_id':native.PHASE_ID,'observed':False,'details':d,'native_eligible':False,'private_input_allowed':False}
            self.assertEqual(native.validate_outcome(native.PHASE_ID,o),o)
            with self.assertRaises(Exception):native.validate_outcome(native.PHASE_ID,{**o,'observed':True})

    def test_success_exit_unknown_and_malformed_frames_refuse(self):
        for code in (True,0,1,3):
            with self.assertRaises(Exception):native._payload(encoded(frame()),code)
        for raw in (b'{}',b'private error',b'x'*16385,bytearray(encoded(frame()))):
            with self.assertRaises(Exception):native._payload(raw,2)
        bad=frame();bad['passed']=True;bad.pop('diagnostic')
        with self.assertRaises(Exception):native._payload(encoded(bad),2)

    def test_closed_details_reject_duplicates_unknown_reordered_and_private_fields(self):
        d=native._payload(encoded(frame(('png_positive','engine_max_scan'))),2)
        for change in ({'failed_case_ids':['png_positive','png_positive']},{'failed_case_ids':['unknown']},
            {'failed_case_ids':['engine_max_scan','png_positive']},{'case_count':True},{'raw':'private'},
            {'failed_case_ids':[]},{'private_input_allowed':True}):
            with self.assertRaises(Exception):native._details({**d,**change})

    def test_expected_failure_runs_post_inspection_before_finish(self):
        c=Context();j=self.harness(c);out=native._phase(c)
        self.assertTrue(out['observed']);self.assertTrue(j.closed)
        self.assertEqual(c.events[:12],['before_phase','attempt','consume_before_create','create','retain_original',
            'journal-original','record_original','inspect','attach_started','attach',('attach_finalized',True),'inspect']);self.assertEqual(c.events[-1],'finish_phase')
        self.assertTrue(c.finish_phase.call_args.args[-1]['observed'])

    def test_partial_frame_is_saved_without_becoming_observed(self):
        c=Context();self.harness(c,payload=frame((),count=0,completed=False))
        out=native._phase(c);self.assertFalse(out['observed']);self.assertEqual(c.events.count('inspect'),2)

    def test_journal_original_failure_forbids_inspection_and_start(self):
        c=Context();self.harness(c,failure='record')
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        self.assertNotIn('inspect',c.events);self.assertNotIn('attach',c.events)
        mechanics.cleanup.assert_called_once();self.assertIsNone(c.finish_phase.call_args.args[-1])

    def test_parent_original_failure_forbids_start_but_cleans_original(self):
        c=Context();c.record_original.side_effect=ValueError('private');self.harness(c)
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        self.assertNotIn('attach',c.events);mechanics.cleanup.assert_called_once()

    def test_attempt_failure_never_consumes_or_creates(self):
        c=Context();self.harness(c,failure='attempt')
        with self.assertRaises(Exception):native._phase(c)
        c.consume_before_create.assert_not_called();c.command.assert_not_called()

    def test_stale_capability_never_creates(self):
        c=Context();c.consume_before_create.side_effect=ValueError('private');self.harness(c)
        with self.assertRaises(Exception):native._phase(c)
        c.command.assert_not_called();self.assertNotIn('attach',c.events)

    def test_postrun_oom_pid_exit_mismatch_refuses_after_cleanup(self):
        for key,value in (('OOMKilled',True),('Pid',42),('ExitCode',0)):
            with self.subTest(key=key):
                c=Context();self.harness(c,post=lambda d,k=key,v=value:d['State'].update({k:v}))
                with self.assertRaises(Exception):native._phase(c)
                mechanics.cleanup.assert_called_once()

    def test_postrun_cgroup_failure_cleans_and_refuses(self):
        c=Context();self.harness(c);runtime._require_cgroup_v2.side_effect=[None,None,ValueError('private')]
        with self.assertRaises(Exception):native._phase(c)
        mechanics.cleanup.assert_called_once()

    def test_unexpected_success_cleans_without_measurement(self):
        c=Context();self.harness(c,exit_code=0)
        with self.assertRaises(Exception):native._phase(c)
        self.assertIsNone(c.finish_phase.call_args.args[-1]);mechanics.cleanup.assert_called_once()

    def test_cleanup_failure_dominates_complete_observation(self):
        c=Context();self.harness(c,cleanup_error=ValueError('private'))
        with self.assertRaises(native.NativeUnavailable) as e:native._phase(c)
        self.assertEqual(e.exception.code,'STRICT_CATEGORY_NATIVE_CLEANUP_UNCONFIRMED')
        self.assertIsNone(c.finish_phase.call_args.args[-1])

    def test_journal_finalizer_failure_dominates_complete_observation(self):
        c=Context();self.harness(c,failure='finish')
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        self.assertIsNone(c.finish_phase.call_args.args[-1])

    def test_sticky_cli_uncertainty_dominates_observation(self):
        c=Context();c.call_uncertain=True;self.harness(c)
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        self.assertIsNone(c.finish_phase.call_args.args[-1])

    def test_parent_finalizer_exception_dominates_complete_observation(self):
        c=Context();self.harness(c);c.finish_phase.side_effect=ValueError('private')
        with self.assertRaises(native.NativeUnavailable):native._phase(c)

    def test_parent_rejects_record_without_success_promotion(self):
        c=Context();self.harness(c);c.finish_phase.side_effect=None;c.finish_phase.return_value=False
        with self.assertRaises(native.NativeUnavailable):native._phase(c)

    def test_error_text_is_finite_even_on_host_exception(self):
        c=Context();self.harness(c,inspect_error=ValueError('SECRET private raw'))
        with self.assertRaises(native.NativeUnavailable) as e:native._phase(c)
        self.assertNotIn('SECRET',str(e.exception));self.assertNotIn('private',str(e.exception))

    def test_arbitrary_context_cannot_select_execution(self):
        with self.assertRaises(Exception):native._check_context(SimpleNamespace(stage='diagnostic',binding=binding()))

    def test_import_has_no_project_import_io_or_execution(self):
        import ast
        source=Path(native.__file__).read_text()
        tree=ast.parse(source)
        for node in tree.body:
            if isinstance(node,ast.ImportFrom):self.assertFalse((node.module or '').startswith(('infra','backend')))
            if isinstance(node,ast.Import):
                self.assertFalse(any(n.name.startswith(('infra','backend')) for n in node.names))
        # Fresh module compilation with external IO primitives denied.
        ns={'__name__':'inert_native_import'}
        import sys, types
        mod=types.ModuleType(ns['__name__']);sys.modules[mod.__name__]=mod
        try:
            with patch('builtins.open',side_effect=AssertionError('IO forbidden')), patch('subprocess.Popen',side_effect=AssertionError('exec forbidden')):
                exec(compile(source,'<public-source>','exec'),mod.__dict__)
        finally:sys.modules.pop(mod.__name__,None)

    def test_cleanup_receives_only_returned_original_even_on_work_failure(self):
        c=Context();self.harness(c,inspect_error=ValueError('private'))
        with self.assertRaises(Exception):native._phase(c)
        args=mechanics.cleanup.call_args.args
        self.assertIs(args[0],c.cleanup_command);self.assertEqual(args[2],CID);self.assertIs(args[3],True)

    def test_body_deadline_failure_cannot_return_observation(self):
        c=Context();self.harness(c)
        with patch.object(native.time,'monotonic',side_effect=[0,10000]):
            with self.assertRaises(native.NativeUnavailable):native._phase(c)
        mechanics.cleanup.assert_called_once()
        self.assertIsNone(c.finish_phase.call_args.args[-1])

    def test_outcome_closed_shape_and_observed_booleans(self):
        d=native._payload(encoded(frame()),2)
        good={'phase_id':native.PHASE_ID,'observed':True,'details':d,'native_eligible':False,'private_input_allowed':False}
        for update in ({'observed':1},{'observed':False},{'phase_id':'strict:scan:strict'},{'native_eligible':True},{'raw':b'private'}):
            with self.assertRaises(Exception):native.validate_outcome(native.PHASE_ID,{**good,**update})

    def test_attach_exception_records_unconfirmed_before_cleanup(self):
        c=Context();self.harness(c,attach_error=ValueError('private'))
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        c.attach_started.assert_called_once_with();c.attach_finalized.assert_called_once_with(False)
        self.assertLess(c.events.index(('attach_finalized',False)),c.events.index('finish_phase'))
        self.assertIsNone(c.finish_phase.call_args.args[-1]);mechanics.cleanup.assert_called_once()

    def test_attach_interrupt_records_unconfirmed_and_refuses(self):
        c=Context();self.harness(c,attach_error=KeyboardInterrupt())
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        c.attach_finalized.assert_called_once_with(False)
        self.assertIsNone(c.finish_phase.call_args.args[-1]);mechanics.cleanup.assert_called_once()

    def test_successful_attach_closure_precedes_parse_refusal(self):
        c=Context();self.harness(c,exit_code=0)
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        c.attach_started.assert_called_once_with();c.attach_finalized.assert_called_once_with(True)
        self.assertIsNone(c.finish_phase.call_args.args[-1]);mechanics.cleanup.assert_called_once()

    def test_late_body_interrupt_invalidates_previously_validated_outcome(self):
        c=Context();self.harness(c)
        with patch.object(native.time,'monotonic',side_effect=[0,KeyboardInterrupt()]):
            with self.assertRaises(native.NativeUnavailable):native._phase(c)
        c.attach_finalized.assert_called_once_with(True)
        self.assertIsNone(c.finish_phase.call_args.args[-1]);mechanics.cleanup.assert_called_once()

    def test_pre_attach_refusal_never_notifies_attach(self):
        c=Context();self.harness(c,failure='record')
        with self.assertRaises(native.NativeUnavailable):native._phase(c)
        c.attach_started.assert_not_called();c.attach_finalized.assert_not_called()

    def test_eicar_clean_and_error_remain_distinct_nonpassing_categories(self):
        outputs=[]
        for observed in ('CLEAN','ERROR'):
            f=frame(('eicar_png',));f['cases'][2].update(strict=observed,upstream='CLEAN',
                normalization_observed=observed!='CLEAN')
            d=native._payload(encoded(f),2);outputs.append(d)
            self.assertEqual(d['failed_cases'],[{'case':'eicar_png','strict':observed,'upstream':'CLEAN',
                'normalization_observed':observed!='CLEAN'}]);self.assertFalse(d['passed'])
        self.assertNotEqual(outputs[0],outputs[1])

    def test_every_failed_literal_is_validated_against_unchanged_expectation(self):
        from infra.native import strict_probe
        for name in strict_probe.CASE_IDS:
            with self.subTest(case=name):
                d=native._payload(encoded(frame((name,))),2)
                self.assertEqual(d['failed_case_ids'],[name]);self.assertEqual(d['failed_cases'][0]['case'],name)
                self.assertEqual(native._details(d),d)

    def test_details_reject_passing_category_even_with_literal_failed_id(self):
        from infra.native import strict_probe
        for name,kind,expected in strict_probe.FAILURE_CASES:
            with self.subTest(case=name):
                d=native._payload(encoded(frame((name,))),2)
                d['failed_cases'][0].update(strict='ERROR' if expected=='NONCLEAN' else expected)
                d['failed_cases'][0]['normalization_observed']=d['failed_cases'][0]['strict']!='CLEAN' and d['failed_cases'][0]['upstream']=='CLEAN'
                with self.assertRaises(Exception):native._details(d)

    def test_details_reject_wrong_row_keys_types_enums_and_normalization(self):
        good=native._payload(encoded(frame(('eicar_png',))),2)
        for update in ({'case':'png_positive'},{'strict':'VIRUS'},{'strict':True},{'upstream':'NOT_RUN'},
            {'upstream':False},{'normalization_observed':0},{'normalization_observed':False},{'raw':'private'}):
            d=deepcopy(good);d['failed_cases'][0].update(update)
            with self.assertRaises(Exception):native._details(d)
        for rows in (None,{},[],[good['failed_cases'][0],good['failed_cases'][0]]):
            with self.assertRaises(Exception):native._details({**good,'failed_cases':rows})

    def test_precondition_requires_not_run_upstream_and_false_normalization(self):
        good=native._payload(encoded(frame(('fmap_null',))),2)
        self.assertEqual(good['failed_cases'][0]['upstream'],'NOT_RUN')
        self.assertIs(good['failed_cases'][0]['normalization_observed'],False)
        for upstream in ('CLEAN','NOT_CLEAN','ERROR'):
            d=deepcopy(good);d['failed_cases'][0]['upstream']=upstream
            with self.assertRaises(Exception):native._details(d)

    def test_partial_prefix_cannot_claim_later_failed_rows(self):
        d=native._payload(encoded(frame(('png_positive',),count=1,completed=False)),2)
        other=native._payload(encoded(frame(('eicar_png',))),2)
        d.update(failed_case_ids=other['failed_case_ids'],failed_cases=other['failed_cases'])
        with self.assertRaises(Exception):native._details(d)

    def test_failed_rows_match_literal_order_exactly_and_no_passing_rows_survive(self):
        good=native._payload(encoded(frame(('png_positive','eicar_png','engine_max_scan'))),2)
        self.assertEqual(len(good['failed_cases']),3)
        d=deepcopy(good);d['failed_cases'].reverse()
        with self.assertRaises(Exception):native._details(d)
        d=deepcopy(good);d['failed_cases'][0]['passed']=False
        with self.assertRaises(Exception):native._details(d)

    def test_closed_details_have_ten_fields_and_failed_rows_only_four(self):
        good=native._payload(encoded(frame(('eicar_png',))),2)
        self.assertEqual(len(good),10);self.assertEqual(len(good['failed_cases'][0]),4)
        self.assertNotIn('cases',good);self.assertFalse(any(key in str(good) for key in ('return_code','error_text','payload','digest')))
        c=Context();self.harness(c,payload=frame(('eicar_png',)));out=native._phase(c)
        self.assertEqual(out['details']['failed_cases'],good['failed_cases']);self.assertTrue(out['observed'])
        self.assertEqual(c.events.count('inspect'),2)

    def test_all_valid_nonprecondition_upstream_categories_retain_exact_normalization(self):
        for observed in ('CLEAN','ERROR'):
            for upstream in ('CLEAN','NOT_CLEAN','ERROR'):
                f=frame(('eicar_png',));f['cases'][2].update(strict=observed,upstream=upstream,
                    normalization_observed=observed!='CLEAN' and upstream=='CLEAN')
                row=native._payload(encoded(f),2)['failed_cases'][0]
                self.assertEqual(row['strict'],observed);self.assertEqual(row['upstream'],upstream)
                self.assertIs(row['normalization_observed'],observed!='CLEAN' and upstream=='CLEAN')

    def test_category_frame_bound_rejects_oversize_even_if_json_otherwise_valid(self):
        raw=encoded(frame(('eicar_png',)))
        self.assertLess(len(raw),16384)
        self.assertEqual(native._payload(raw+b' '*(16384-len(raw)),2)['failed_case_ids'],['eicar_png'])
        with self.assertRaises(Exception):native._payload(raw+b' '*(16385-len(raw)),2)

if __name__=='__main__':unittest.main()
