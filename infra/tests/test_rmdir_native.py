"""Pure native-adapter tests: fake host/CLI/exchange, no Docker/native IO."""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from infra import evidence_rmdir_native as native
from infra.test_evidence_native_runtime import inspection
from infra.test_evidence_native_attestation import strict_payload, pcre_payload, public_payload

CID = 'e'*64
TOKEN = 'd'*32


def binding():
    return SimpleNamespace(image_id=native.IMAGE,signature_generation=native.GENERATION,
        profile_sha256=native.PROFILE_SHA256,preparation_sha256=native.PREPARATION_SHA256,
        native_sha256=hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),
        controller_sha256='a'*64,contract=native.CONTRACT)


def probe(phase_id='confinement:scan:confinement'):
    return native._probe(TOKEN,phase_id,binding())


def inspected(value, *, running=False, exit_code=0):
    doc=inspection(value.phase,running=running,exit_code=exit_code)
    doc.update(Name='/'+value.name)
    doc['Config'].update(Labels=value.labels,Cmd=value.command)
    doc['HostConfig']['SecurityOpt'][1]='seccomp='+native.profile.profile_bytes().decode('ascii')
    return doc


def payload(phase_id):
    kind,_,scenario,_=native._parts(phase_id)
    if kind=='strict':return strict_payload()
    if kind=='pcre':
        result=pcre_payload();result.update(harness_cleanup=True,failure_stage='NONE')
        return result
    return public_payload(SimpleNamespace(scenario=scenario))


def outcome(phase_id):
    kind,_,fixture,part=native._parts(phase_id)
    if kind=='fixture':
        code='DECODE_COMPLETE' if part=='decode' else 'SCAN_CLEAN' if part=='derivative' else native.fixtures.fixture(fixture).expected_original_code
        result={'code':code,'width':1 if part=='decode' else None,'height':1 if part=='decode' else None}
    else:result=payload(phase_id)
    return {'phase_id':phase_id,'passed':True,'result':result,'native_eligible':False,'private_input_allowed':False}


def failure_payload(kind):
    frame=payload('strict:scan:strict' if kind=='strict' else 'pcre:scan:pcre')
    frame.update(completed=False,passed=False)
    if kind=='strict':
        frame['diagnostic']={'stage':'SCRATCH_CLEANUP','kind':'VALUE_ERROR',
                            'location':{'source':'WORKER','function':'_scratch_empty','line':131}}
    else:
        frame.update(failure_stage='CLEANUP',harness_cleanup=False,
                     diagnostic={'stage':'CLEANUP','kind':'VALUE_ERROR',
                                 'location':{'source':'WORKER','function':'_scratch_empty','line':131}})
    return frame


class Journal:
    def __init__(self, events, fail=None):self.events=events;self.fail=fail;self.failed=False;self.closed=False
    def mark_create_attempted(self):
        self.events.append('attempt')
        if self.fail=='attempt':self.failed=True;raise ValueError('private')
    def record_original(self,cid):
        self.events.append('journal-original')
        if self.fail=='record':self.failed=True;raise ValueError('private')
    def finish(self,status):
        self.events.append(('journal-finish',status));self.closed=True
        if self.fail=='finish':raise ValueError('private')


class Context:
    def __init__(self,stage='strict'):
        self.binding=binding();self.stage=stage;self.events=[];self.call_uncertain=False
        self.profile=Path('C:/fixed/profile.json');self.docker=Path('C:/fixed/docker.exe');self.config=Path('C:/fixed/config')
        self.command=Mock(side_effect=self._command);self.cleanup_command=Mock(return_value=(0,b'',b'','EXIT'))
        self.before_phase=Mock(side_effect=lambda *args:self.events.append('fresh-gates'))
        self.consume_before_create=Mock(side_effect=lambda *args:self.events.append('consume'))
        self.retain_original=Mock(side_effect=lambda *args:self.events.append('retain-original'))
        self.record_original=Mock(side_effect=lambda *args:self.events.append('outer-original'))
        def finish(*args):
            self.events.append('finish-phase')
            return args[-1] is not None and args[-1]['passed'] is True
        self.finish_phase=Mock(side_effect=finish)
    def _command(self,*args,**kwargs):
        if args[0]=='create':self.events.append('create');return 0,CID.encode()+b'\n',b'','EXIT'
        return 0,b'',b'','EXIT'


class NativeTests(unittest.TestCase):
    def harness(self, context, phase_id, *, fail=None, attach_error=None, cleanup_error=None,
                exchange=None, semantic=None, inspection_error=None):
        p=probe(phase_id);events=context.events;journal=Journal(events,fail)
        @contextmanager
        def reserve(*args):yield journal
        def inspect_fake(*args):events.append('inspect');return inspected(p,exit_code=0 if exchange is None else exchange[2])
        def attach(*args,**kwargs):
            events.append('attach')
            if attach_error:raise attach_error
            return (159 if phase_id.endswith(':x32') else 0),native._json(payload(phase_id) if semantic is None else semantic)
        stack=self.enterContext(__import__('contextlib').ExitStack())
        for target,name,value in ((native,'_probe',Mock(return_value=p)),(native,'_reserve',reserve),
            (native,'_check_context',Mock()),
            (native.runtime,'_require_cgroup_v2',Mock()),(native.mechanics,'inspect',Mock(side_effect=inspect_fake)),
            (native,'verify_inspection',Mock(side_effect=inspection_error)),(native.attestation,'_attach',attach),
            (native.mechanics,'cleanup',Mock(side_effect=cleanup_error,return_value='ORIGINAL_ID_ABSENT_VERIFIED'))):
            stack.enter_context(patch.object(target,name,value))
        if exchange is not None:stack.enter_context(patch.object(native.runtime,'_exchange',return_value=exchange))
        return journal

    def test_manifest_is_exact26_and_stage_counts10_1_1_14(self):
        self.assertEqual(len(native.PHASES),26);self.assertEqual(len(set(native.PHASES)),26)
        self.assertEqual([len(native.stage_phases(stage)) for stage in native.STAGES],[10,1,1,14])
        self.assertEqual(native.stage_phases('confinement'),tuple('confinement:'+mode+':'+case
             for mode in ('scan','decode') for case in sorted(native.attestation.SCENARIOS)))
        self.assertEqual(native.PHASES[10:12],('strict:scan:strict','pcre:scan:pcre'))

    def test_metadata_binds_exact_closed_profile_preparation_native_contract(self):
        for phase_id in native.PHASES:
            doc=native.metadata(TOKEN,phase_id,binding())
            self.assertEqual(doc['expected_name'],native.NAME_PREFIX+TOKEN)
            self.assertEqual(doc['expected_labels']['org.kapit.profile'],native.PROFILE_SHA256)
            self.assertEqual(doc['expected_labels']['org.kapit.native'],binding().native_sha256)
            self.assertEqual(doc['proof_contract'],native.CONTRACT)
            self.assertFalse(doc['native_eligible']);self.assertFalse(doc['private_input_allowed'])
        for token,phase_id in ((True,native.PHASES[0]),('a'*31,native.PHASES[0]),(TOKEN,'confinement:scan:unknown')):
            with self.assertRaises(native.NativeUnavailable):native.metadata(token,phase_id,binding())
        for key,value in (('image_id','sha256:'+'0'*64),('profile_sha256','0'*64),('preparation_sha256','0'*64),('native_sha256',None),('contract','wrong')):
            bound=binding();setattr(bound,key,value)
            with self.assertRaises(native.NativeUnavailable):native.metadata(TOKEN,native.PHASES[0],bound)

    def test_malformed_reservation_never_reaches_host(self):
        fixed=native.metadata(TOKEN,native.PHASES[0],binding());fixed['schema']=True
        with patch.object(native.ownership,'_Host') as host:
            with self.assertRaises(native.NativeUnavailable):
                with native._reserve(fixed,binding()):pass
        host.assert_not_called()

    def test_effective_profile_and_name_labels_program_checked_before_normalization(self):
        for phase_id in (native.PHASES[0],'confinement:decode:storage','fixture:png_clean:decode'):
            p=probe(phase_id);doc=inspected(p);before=deepcopy(doc)
            native.verify_inspection(doc,p,CID)
            self.assertEqual(doc,before)
            for change in (lambda d:d['Config']['Labels'].update(unexpected='private'),
                           lambda d:d.update(Name='/other'),lambda d:d['Config'].update(Cmd=['other']),
                           lambda d:d['HostConfig'].update(SecurityOpt=['no-new-privileges=true','seccomp=unconfined']),
                           lambda d:d['HostConfig'].update(Memory=True)):
                wrong=deepcopy(doc);change(wrong)
                with self.assertRaises(Exception):native.verify_inspection(wrong,p,CID)

    def test_create_arguments_preserve_resource_mode_and_use_only_fixed_namespace(self):
        for mode in ('scan','decode'):
            p=probe('confinement:'+mode+':storage');args=native.create_args(p,Path('C:/fixed/profile.json'))
            old=native.runtime.create_args(p.phase,profile_path=Path('C:/fixed/profile.json'))
            def resource(values):
                result=[];i=0
                while i<len(values)-7:
                    if values[i] in ('--name','--label'):i+=2;continue
                    result.append(values[i]);i+=1
                return result
            self.assertEqual(resource(args[:len(args)-len(p.command)]+p.phase.command),resource(old))
            self.assertEqual(args[args.index('--memory')+1],str(native.runtime.LIMITS[mode][0]))
            self.assertEqual(args[args.index('--name')+1],p.name)

    def test_strict_and_pcre_require_exact_full_14_and_8_rows(self):
        for phase_id,count in (('strict:scan:strict',14),('pcre:scan:pcre',8)):
            frame=payload(phase_id)
            self.assertEqual(len(native._payload(phase_id,native._json(frame),0)['cases']),count)
            for change in (lambda d:d.update(completed=False),lambda d:d.update(passed=False),
                           lambda d:d['cases'].pop(),lambda d:d['cases'].reverse(),
                           lambda d:d['cases'][0].update(passed=False),lambda d:d.update(native_eligible=True)):
                wrong=deepcopy(frame);change(wrong)
                with self.assertRaises(Exception):native._payload(phase_id,native._json(wrong),0)
            for exit_code in (True,1,2):
                with self.assertRaises(native.NativeUnavailable):native._payload(phase_id,native._json(frame),exit_code)

    def test_failed_strict_and_pcre_keep_only_validated_finite_summary(self):
        for kind,count in (('strict',14),('pcre',8)):
            phase_id=kind+':scan:'+kind
            with self.assertRaises(native.NativeUnavailable) as error:
                native._payload(phase_id,native._json(failure_payload(kind)),2)
            summary=error.exception.failure_summary
            self.assertEqual(summary['case_count'],count);self.assertFalse(summary['passed'])
            self.assertNotIn('cases',summary);self.assertNotIn('raw',summary)
            failed={'phase_id':phase_id,'passed':False,'result':summary,'native_eligible':False,'private_input_allowed':False}
            self.assertEqual(native.validate_outcome(phase_id,failed),failed)
            group={'schema':1,'scope':native.SCOPE,'stage':kind,'status':'VERIFIED','results':[failed],
                   'phase_count':1,'native_eligible':False,'private_input_allowed':False}
            with self.assertRaises(native.NativeUnavailable):native.validate_result(kind,group)
            for change in (lambda d:d.update(case_count=True),lambda d:d.update(case_count=count+1),
                           lambda d:d.update(raw='private'),lambda d:d['diagnostic']['location'].update(function='arbitrary')):
                wrong=deepcopy(summary);change(wrong)
                with self.assertRaises(Exception):native.validate_outcome(phase_id,{**failed,'result':wrong})

    def test_failure_frame_with_invalid_partial_rows_cannot_emit_summary(self):
        for kind in ('strict','pcre'):
            frame=failure_payload(kind);frame['cases'][0]['case']='arbitrary'
            with self.assertRaises(native.NativeUnavailable) as error:
                native._payload(kind+':scan:'+kind,native._json(frame),2)
            self.assertFalse(hasattr(error.exception,'failure_summary'))

    def test_exact_closed_group_result_order_type_and_no_payload_fields(self):
        stage='strict';good={'schema':1,'scope':native.SCOPE,'stage':stage,'status':'VERIFIED',
             'results':[outcome('strict:scan:strict')],'phase_count':1,'native_eligible':False,'private_input_allowed':False}
        self.assertEqual(native.validate_result(stage,good),good)
        for updates in ({'phase_count':True},{'results':[]},{'native_eligible':True},{'extra':b'private'}, {'stage':'pcre'}):
            with self.assertRaises(Exception):native.validate_result(stage,{**good,**updates})
        bad=deepcopy(good);bad['results'][0]['result']['raw_payload']='private'
        with self.assertRaises(Exception):native.validate_result(stage,bad)

    def test_durable_attempt_and_original_precede_inspect_start_input(self):
        ctx=Context();journal=self.harness(ctx,'strict:scan:strict')
        measured,_=native._phase(ctx,'strict:scan:strict')
        self.assertTrue(measured['passed'])
        expected=('fresh-gates','attempt','consume','create','retain-original','journal-original','outer-original','inspect','attach')
        self.assertEqual(tuple(ctx.events[:9]),expected)
        self.assertEqual(ctx.events[-2:],[('journal-finish','ORIGINAL_ID_ABSENT_VERIFIED'),'finish-phase'])
        self.assertTrue(journal.closed);self.assertTrue(ctx.finish_phase.call_args.args[-1]['passed'])

    def test_attempt_or_capability_failure_never_creates_or_starts(self):
        for where in ('attempt','consume'):
            ctx=Context();journal=self.harness(ctx,'strict:scan:strict',fail='attempt' if where=='attempt' else None)
            if where=='consume':ctx.consume_before_create.side_effect=ValueError('stale')
            with self.assertRaises(native.NativeUnavailable):native._phase(ctx,'strict:scan:strict')
            self.assertNotIn('create',ctx.events);self.assertNotIn('attach',ctx.events)
            self.assertTrue(journal.closed);self.assertIsNone(ctx.finish_phase.call_args.args[-1])

    def test_cid_journal_or_outer_write_failure_allows_only_cleanup(self):
        for where in ('record','outer'):
            ctx=Context();self.harness(ctx,'strict:scan:strict',fail='record' if where=='record' else None)
            if where=='outer':ctx.record_original.side_effect=OSError('private')
            with self.assertRaises(native.NativeUnavailable):native._phase(ctx,'strict:scan:strict')
            self.assertNotIn('inspect',ctx.events);self.assertNotIn('attach',ctx.events)
            native.mechanics.cleanup.assert_called_once()
            self.assertIsNone(ctx.finish_phase.call_args.args[-1])

    def test_attach_parser_inspection_and_wrong_outcome_stop_with_cleanup(self):
        for kind in ('attach','parser','inspection'):
            ctx=Context();kwargs={'attach_error':ValueError('private')} if kind=='attach' else {'semantic':{}} if kind=='parser' else {'inspection_error':ValueError('private')}
            self.harness(ctx,'strict:scan:strict',**kwargs)
            with self.assertRaises(native.NativeUnavailable):native._phase(ctx,'strict:scan:strict')
            native.mechanics.cleanup.assert_called_once()
            self.assertIsNone(ctx.finish_phase.call_args.args[-1])

    def test_valid_failure_summary_is_retained_without_claiming_cleanup_uncertainty(self):
        ctx=Context();self.harness(ctx,'strict:scan:strict',semantic=failure_payload('strict'))
        with self.assertRaises(native.NativeUnavailable) as error:native._phase(ctx,'strict:scan:strict')
        self.assertEqual(error.exception.code,'RMDIR_NATIVE_REFUSED')
        self.assertEqual(ctx.finish_phase.call_args.args[-2],'ORIGINAL_ID_ABSENT_VERIFIED')
        self.assertFalse(ctx.finish_phase.call_args.args[-1]['passed'])
        self.assertEqual(ctx.finish_phase.call_args.args[-1]['result']['case_count'],14)

    def test_wrong_stopped_state_or_cli_exit_never_accepts_success_payload(self):
        for update in ({'OOMKilled':True},{'Pid':True},{'ExitCode':2},{'Running':True}):
            ctx=Context();self.harness(ctx,'strict:scan:strict')
            current=native.mechanics.inspect.side_effect
            def values(*args):
                doc=current(*args);doc['State'].update(update);return doc
            native.mechanics.inspect.side_effect=values
            # Real inspection, not the parser, handles Running. Restore it here.
            native.verify_inspection.side_effect=lambda doc,p,cid,**kw:native.require(doc['State']['Running'] is False)
            with self.assertRaises(native.NativeUnavailable):native._phase(ctx,'strict:scan:strict')
            self.assertIsNone(ctx.finish_phase.call_args.args[-1])

    def test_cleanup_journal_cli_and_outer_finalizers_dominate_success(self):
        for where in ('cleanup','finish','cli','outer'):
            ctx=Context();self.harness(ctx,'strict:scan:strict',fail='finish' if where=='finish' else None,
                                       cleanup_error=OSError('private') if where=='cleanup' else None)
            if where=='cli':ctx.call_uncertain=True
            if where=='outer':ctx.finish_phase.side_effect=OSError('private')
            with self.assertRaises(native.NativeUnavailable) as error:native._phase(ctx,'strict:scan:strict')
            self.assertEqual(error.exception.code,'RMDIR_NATIVE_CLEANUP_UNCONFIRMED')
            self.assertNotIn('private',str(error.exception))

    def test_fixture_decode_checks_1x1_metadata_before_phase_acceptance(self):
        derivative=native.fixtures.fixture('png_clean').data
        ctx=Context('fixtures')
        self.harness(ctx,'fixture:png_clean:decode',exchange=({'code':'DECODE_COMPLETE','width':1,'height':1},derivative,0))
        measured,(_,data)=native._phase(ctx,'fixture:png_clean:decode',data=b'PUBLIC',media='image/png')
        self.assertEqual(data,derivative);self.assertEqual(measured['result'],{'code':'DECODE_COMPLETE','width':1,'height':1})
        self.assertTrue(ctx.finish_phase.call_args.args[-1]['passed'])

    def test_fixture_invalid_metadata_or_dimensions_never_commits_outcome(self):
        for data,width in ((native.fixtures.fixture('png_metadata').data,1),(native.fixtures.fixture('png_clean').data,2)):
            ctx=Context('fixtures');self.harness(ctx,'fixture:png_clean:decode',exchange=({'code':'DECODE_COMPLETE','width':width,'height':1},data,0))
            with self.assertRaises(native.NativeUnavailable):native._phase(ctx,'fixture:png_clean:decode',data=b'PUBLIC',media='image/png')
            self.assertIsNone(ctx.finish_phase.call_args.args[-1])

    def test_execute_rejects_unsealed_context_before_any_native_operation(self):
        with patch.object(native,'_phase') as run:
            with self.assertRaises(Exception):native.execute(Context(),'strict')
        run.assert_not_called()

    def test_private_phase_also_rejects_unsealed_context_before_fresh_or_host(self):
        ctx=Context()
        with patch.object(native,'_reserve') as host:
            with self.assertRaises(Exception):native._phase(ctx,'strict:scan:strict')
        ctx.before_phase.assert_not_called();host.assert_not_called()

    def execute_fixture(self, fail_at=None):
        from infra import evidence_rmdir_proof as outer
        ctx=Context('fixtures');calls=[]
        def phase_fake(context,phase_id,*,data=None,media=None):
            calls.append(phase_id)
            if len(calls)==fail_at:raise native.NativeUnavailable()
            header=outcome(phase_id)['result']
            return outcome(phase_id),(header,native.fixtures.fixture('png_clean').data)
        with patch.object(outer,'_validate_context'),patch.object(native.attestation,'_pins'),patch.object(native,'_phase',side_effect=phase_fake):
            if fail_at:
                with self.assertRaises(native.NativeUnavailable):native.execute(ctx,'fixtures')
            else:
                result=native.execute(ctx,'fixtures');self.assertEqual(result['phase_count'],14)
        return calls

    def test_fixture_exact14_phase_branches_and_no_payloads_in_summary(self):
        calls=self.execute_fixture();self.assertEqual(tuple(calls),native.stage_phases('fixtures'))
        self.assertEqual(calls[-2:],['fixture:png_malformed:original','fixture:png_eicar:original'])

    def test_fixture_failures_at_each_pipeline_phase_stop_without_later_phase(self):
        for index in (1,2,3,4,5,6,13,14):
            calls=self.execute_fixture(fail_at=index)
            self.assertEqual(tuple(calls),native.stage_phases('fixtures')[:index])


if __name__ == '__main__':unittest.main()
