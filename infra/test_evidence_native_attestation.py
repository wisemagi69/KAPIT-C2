"""Same-image controller mocks and owned Python children only; no native/Docker."""
from contextlib import nullcontext
from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zlib

from infra import evidence_native_attestation as suite
from infra.test_evidence_native_runtime import candidate,inspection,image


def probe(scenario='confinement',mode='scan'):
    b=suite.protocol.Binding(mode,'c'*64,suite.runtime.POLICY_SHA256,candidate().signature_generation)
    return suite._Probe(suite.runtime._Phase(candidate(),b,'d'*32),scenario)


def inspected(p,**kwargs):
    value=inspection(p.phase,**kwargs)
    value['Name']='/'+p.name;value['Config'].update(Labels=p.labels,Cmd=p.command)
    return value


def public_payload(p):
    return {'schema':1,'purpose':'PUBLIC_ABI3_CONFINEMENT','scenario':p.scenario,'policy':suite.public.POLICY_ID,
        'landlock_abi':3,'checks':{name:True for name in suite.public.CHECKS[p.scenario]},
        'native_validation':'DISABLED','private_input_allowed':False}


def strict_payload():
    rows=[]
    for name,kind,expected in suite.CASES:
        strict='ERROR' if expected=='NONCLEAN' else expected
        upstream='NOT_RUN' if kind=='PRECONDITION' else 'NOT_CLEAN' if expected=='NOT_CLEAN' else 'CLEAN'
        rows.append({'case':name,'kind':kind,'strict':strict,'upstream':upstream,'passed':True,
                     'normalization_observed':strict!='CLEAN' and upstream=='CLEAN'})
    return {'schema':1,'scope':'PUBLIC_STRICT_NATIVE_PROBE_ONLY','completed':True,'passed':True,'cases':rows,'native_eligible':False}


def pcre_payload():
    expected=(('match_limit','MATCHLIMIT','CLEAN','ERROR'),('depth_limit','DEPTHLIMIT','CLEAN','ERROR'),
              ('match_nomatch','NOMATCH','CLEAN','CLEAN'),('depth_nomatch','NOMATCH','CLEAN','CLEAN'),
              ('match_positive','POSITIVE','VIRUS','VIRUS'),('depth_positive','POSITIVE','VIRUS','VIRUS'),
              ('ordinary_nomatch','NOMATCH','CLEAN','CLEAN'),('restored_control','NOMATCH','CLEAN','CLEAN'))
    return {'schema':1,'scope':'PUBLIC_PCRE_NATIVE_REGRESSION_ONLY','completed':True,'passed':True,
            'cases':[{'case':name,'direct':direct,'upstream':upstream,'strict':strict,'orders_completed':2,
                      'passed':True,'normalization_observed':upstream=='CLEAN' and strict=='ERROR'} for name,direct,upstream,strict in expected],
            'harness_cleanup':True,'failure_stage':'NONE','native_eligible':False}


def failure_payload(scenario):
    value=strict_payload() if scenario=='strict' else pcre_payload()
    value.update(completed=False,passed=False,cases=[])
    stage='CONFIGURATION' if scenario=='strict' else 'PROVIDER'
    value['diagnostic']={'stage':stage,'kind':'OS_ERROR',
        'location':{'source':'WORKER','function':'load_configuration','line':120}}
    if scenario=='pcre':value['failure_stage']=stage
    return value


class FixedPolicyTests(unittest.TestCase):
    def test_previous_pcre_pin_cannot_authenticate_new_readback_source(self):
        old='423d0249f3d49555e5695b13c050702a91e6dbf30cf367f90f229746a0221b29'
        stale=tuple((path,old if path==suite.PCRE else digest) for path,digest in suite.PINS)
        with patch.object(suite,'PINS',stale),patch.object(suite.base,'_bounded_command',side_effect=AssertionError('daemon forbidden')) as command:
            with self.assertRaises(suite.ProbeUnavailable):suite._pcre_program()
            command.assert_not_called()

    def test_pcre_fixed_compressed_loader_checks_complete_source_before_exec(self):
        p=probe('pcre');program=p.command[-1];raw=suite.PCRE.read_bytes()
        args=suite.create_args(p,profile_path='C:/owned/profile.json')
        self.assertLess(len(subprocess.list2cmdline(args)),30000)
        self.assertIn(suite.ownership_journal.PCRE_PROBE,program)
        self.assertIn('d.decompress(packed,'+str(len(raw)+1)+')',program)
        self.assertNotIn('.flush(',program)
        self.assertEqual(p.labels['org.kapit.probe'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(p.labels['org.kapit.scenario'],'pcre')
        compiled=compile(program,'<fixed-loader-test>','exec');stub=compile('pass','<no-harness-execution>','exec');seen=[]
        def fake_compile(source,name,mode):seen.append((source,name));return stub
        with patch('builtins.compile',side_effect=fake_compile):exec(compiled,{})
        self.assertEqual(seen,[(raw,'<fixed-public-pcre>')])
        packed=base64.b64decode(re.search(r"base64.b64decode\('([^']+)'",program)[1],validate=True)
        malformed=[]
        for data in (packed[:-1],packed+b'garbage',packed+packed,zlib.compress(raw+b'x'),zlib.compress(raw[:-1])):
            changed=re.sub(r"base64.b64decode\('[^']+',validate=True\)","base64.b64decode('"+base64.b64encode(data).decode()+"',validate=True)",program)
            changed=changed.replace('assert len(packed)=='+str(len(packed)), 'assert len(packed)=='+str(len(data)))
            malformed.append(changed)
        malformed.append(program.replace(suite.ownership_journal.PCRE_PROBE,'0'*64))
        for text in malformed:
            code=compile(text,'<invalid-fixed-loader-test>','exec')
            with patch('builtins.compile',side_effect=AssertionError('must not compile harness')) as compiling:
                with self.assertRaises((AssertionError,zlib.error)):exec(code,{})
                compiling.assert_not_called()
        with self.assertRaises(suite.ProbeUnavailable):suite.create_args(probe('pcre','decode'),profile_path='C:/owned/profile.json')
        with self.assertRaises(suite.ProbeUnavailable):suite.create_args(p,profile_path='C:/'+('x'*30000))
        with self.assertRaises(TypeError):suite._pcre_program('caller script')
    def test_sources_are_pinned_no_caller_code_or_input_and_exact_production_caps(self):
        suite._pins()
        for mode in ('scan','decode'):
            for scenario in sorted(suite.SCENARIOS):
                p=probe(scenario,mode);args=suite.create_args(p,profile_path='C:/owned/profile.json')
                self.assertEqual(args[-6:],[candidate().image_id,*p.command])
                self.assertIn('--interactive',args);self.assertIn('--pull=never',args)
                self.assertEqual(args[args.index('--memory')+1],str(suite.runtime.LIMITS[mode][0]))
                self.assertEqual(args[args.index('--memory-swap')+1],str(suite.runtime.LIMITS[mode][0]))
                self.assertIn('cpu='+str(suite.runtime.LIMITS[mode][1])+':'+str(suite.runtime.LIMITS[mode][1]),args)
                self.assertNotIn('--mount',args);self.assertNotIn('--volume',args)
        p=probe('strict');program=p.command[-1]
        compile(program,'<fixed-test>','exec')
        self.assertIn(suite.PINS[3][1],program)
        self.assertEqual(len(p.command),4)
        with patch.object(suite,'PINS',((suite.PINS[0][0],'0'*64),)):
            with self.assertRaises(suite.ProbeUnavailable):suite._pins()
        for scenario in ('strict','../x',True):
            with self.assertRaises(suite.ProbeUnavailable):suite.run_public_probe(candidate(),scenario,docker_path='C:/d',profile_path='C:/p')

    def test_exact_public_difference_is_checked_before_runtime_normalization(self):
        for mode in ('scan','decode'):
            p=probe(mode=mode);good=inspected(p)
            suite.verify_inspection(good,p,container_id='e'*64)
            for section,key,value in (('Config','Cmd',['arbitrary']),('Config','Labels',{}),('Config','StdinOnce',False),
                ('Config','Env',['PATH=PRIVATE_CANARY']),('HostConfig','Memory',True),('HostConfig','MemorySwap',0),
                ('HostConfig','PidsLimit',2),('HostConfig','IpcMode','host')):
                changed=deepcopy(good);changed[section][key]=value
                with self.assertRaises(Exception):suite.verify_inspection(changed,p,container_id='e'*64)
        self.assertIn("extra=os.open('/dev/null',os.O_WRONLY)",suite.public.probe_program())

    def test_strict_closed_parser_recomputes_pass_normalization_kinds_and_order(self):
        good=strict_payload();self.assertEqual(suite._strict_payload(json.dumps(good).encode()),good)
        variants=[good|{'schema':True},good|{'extra':'PRIVATE_CANARY'},good|{'native_eligible':True}]
        for field,value in (('case','unknown'),('kind','unknown'),('strict','CLEAN'),('upstream','NOT_RUN'),
                            ('passed',False),('normalization_observed',False)):
            changed=deepcopy(good);changed['cases'][3][field]=value;variants.append(changed)
        changed=deepcopy(good);changed['cases'].reverse();variants.append(changed)
        changed=deepcopy(good);changed['cases'][0]['raw']='PRIVATE_CANARY';variants.append(changed)
        for value in variants:
            with self.assertRaises(suite.ProbeUnavailable):suite._strict_payload(json.dumps(value).encode())
        for raw in (json.dumps(good).encode('utf-16'),b'{"schema":1,"schema":1}',b'x'*65537):
            with self.assertRaises(suite.ProbeUnavailable):suite._strict_payload(raw)
        failed=deepcopy(good);failed['completed']=False;failed['passed']=False
        self.assertFalse(suite._strict_payload(json.dumps(failed).encode())['passed'])


class OwnedLifecycleTests(unittest.TestCase):
    def exercise(self,scenario='confinement',mode='scan',*,lost_id=False,remaining=b'',interrupt=False,
                 cleanup_fail=False,uncertain_stage=None,bad_image=False,failed_case=False,oom=False,bad_exit=False,
                 journal_fail=None,image_changes=None,remove_cmd=False,create_code=0,create_reason='EXIT',cgroup_results=None,oom_policy_after_start=False,raw_override=None):
        p=probe(scenario,mode);calls=[];state={'created':False,'running':False,'removed':False,'started':False,'events':[],'journal':[]}
        class Host:
            def __init__(self,token):pass
            def __enter__(self):return self
            def save(self,name,document):
                state['events'].append(name);state['journal'].append((name,document))
                if journal_fail==name:raise OSError('PRIVATE_CANARY')
            def close(self):
                state['events'].append('journal_closed')
                if journal_fail=='close':raise OSError('PRIVATE_CANARY')
        def call(argv,**kwargs):
            args=argv[3:];calls.append(args)
            state['events'].append('docker_'+('_'.join(args[:2]) if args[0]!='create' else 'create'))
            if args==['info','--format','{{.CgroupVersion}}']:
                count=state.get('cgroup_checks',0);state['cgroup_checks']=count+1
                result=cgroup_results[count] if cgroup_results else (0,b'2\n',b'','EXIT')
                if isinstance(result,BaseException):raise result
                return result
            stage=('image' if args[:2]==['image','inspect'] else 'create' if args[0]=='create' else
                   'rm' if args[:2]==['container','rm'] else 'other')
            if stage==uncertain_stage and not state.get('uncertain'):
                state['uncertain']=True
                if stage=='create':state['created']=True
                raise suite.base.ContainerUnavailable('CONTAINER_CLEANUP_UNCONFIRMED')
            if stage=='image':
                value=image(p.phase)
                if image_changes:value['Config'].update(image_changes)
                if remove_cmd:value['Config'].pop('Cmd',None)
                if bad_image:value['Config']['Env'].append('LD_PRELOAD=PRIVATE_CANARY')
                return 0,json.dumps([value]).encode(),b'','EXIT'
            if args[:2]==['container','ls']:return 0,(b'' if state['removed'] or not state['created'] else remaining),b'','EXIT'
            if stage=='create':
                self.assertIn('create-attempt.json',state['events'])
                state['created']=True
                return create_code,(b'unknown-id' if lost_id else b'e'*64),b'',create_reason
            if args[:2]==['container','inspect']:
                value=inspected(p,running=state['running'],exit_code=(137 if bad_exit else 159 if scenario=='x32' else 2 if failed_case else 0))
                if state['started']:value['HostConfig']['OomKillDisable']=oom_policy_after_start
                if oom and state['started']:value['State']['OOMKilled']=True
                return 0,json.dumps([value]).encode(),b'','EXIT'
            if args[:2]==['container','kill']:
                if cleanup_fail:raise OSError('PRIVATE_CANARY')
                state['running']=False;return 0,b'',b'','EXIT'
            if stage=='rm':
                if cleanup_fail:raise OSError('PRIVATE_CANARY')
                state['removed']=True;return 0,b'',b'','EXIT'
            raise AssertionError('UNEXPECTED_MOCK_COMMAND')
        def attach(argv,*,timeout):
            state['events'].append('attach');self.assertIn('ownership.json',state['events'])
            self.assertEqual(argv[-1],'e'*64);self.assertEqual(timeout,suite.runtime.LIMITS[mode][2])
            state.update(started=True,running=True)
            if interrupt:raise KeyboardInterrupt()
            state['running']=False
            value=pcre_payload() if scenario=='pcre' else strict_payload() if scenario=='strict' else public_payload(p)
            if failed_case:
                if scenario in ('strict','pcre'):value=failure_payload(scenario)
                else:value['checks']['installed']=False
            return (137 if bad_exit else 159 if scenario=='x32' else 2 if failed_case else 0),raw_override if raw_override is not None else json.dumps(value).encode()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);docker=root/'docker.exe';profile=root/'profile.json'
            docker.write_bytes(b'public');profile.write_bytes(suite.base.canonical(suite.public.startup_profile()))
            with patch('infra.evidence_tools.Windows',return_value=SimpleNamespace(pin=lambda *a,**k:nullcontext())), \
                 patch.object(suite.ownership_journal,'_Host',Host), \
                 patch.object(suite.uuid,'uuid4',return_value=SimpleNamespace(hex=p.phase.token)), \
                 patch.object(suite.secrets,'token_hex',return_value=p.phase.binding.nonce), \
                 patch.object(suite.base,'_bounded_command',side_effect=call),patch.object(suite,'_attach',side_effect=attach):
                try:return suite._run(candidate(),scenario,mode,docker_path=docker,profile_path=profile),calls,state
                except BaseException as error:return error,calls,state

    def test_pcre_parent_uses_closed_eight_case_parser_and_preserves_cleanup_boundaries(self):
        value,_,state=self.exercise('pcre',oom_policy_after_start=None)
        self.assertIsInstance(value,dict);self.assertEqual(value['result'],pcre_payload())
        self.assertFalse(value['strict_helper_confinement']);self.assertFalse(value['native_eligible']);self.assertFalse(value['private_input_allowed'])
        self.assertTrue(state['removed']);self.assertEqual(state['cgroup_checks'],4)
        metadata=next(doc for name,doc in state['journal'] if name=='ownership.json')
        self.assertEqual(metadata['scenario'],'pcre');self.assertEqual(metadata['mode'],'scan')
        self.assertEqual(metadata['expected_labels']['org.kapit.probe'],suite.ownership_journal.PCRE_PROBE)
        for kwargs in ({'journal_fail':'ownership.json'},{'journal_fail':'result.json'},{'cleanup_fail':True},
                       {'cgroup_results':[(0,b'2',b'','EXIT'),(0,b'1',b'','EXIT')]},
                       {'failed_case':True},{'bad_exit':True}):
            failure,_,state=self.exercise('pcre',**kwargs)
            self.assertIsInstance(failure,suite.ProbeUnavailable)
            if kwargs.get('journal_fail')=='ownership.json':self.assertFalse(state['started'])
            if kwargs.get('cleanup_fail'):self.assertEqual(failure.code,'CANDIDATE_CLEANUP_UNCONFIRMED')
        good=pcre_payload();variants=[]
        for key,changed in [('completed',False),('passed',False),('harness_cleanup',False),('native_eligible',True),('failure_stage','RESULT'),('schema',True)]:
            variants.append(good|{key:changed})
        for key,changed in [('case','unknown'),('direct','NOMATCH'),('strict','CLEAN'),('orders_completed',1),('orders_completed',True),('normalization_observed',False),('raw_signature','do not forward')]:
            item=deepcopy(good);item['cases'][0][key]=changed;variants.append(item)
        item=deepcopy(good);item['cases'].reverse();variants.append(item)
        item=deepcopy(good);item['cases'].pop();variants.append(item)
        raws=[json.dumps(item).encode() for item in variants]+[b'{"schema":1,"schema":1}',b'x'*8193,json.dumps(good).encode('utf-16')]
        for raw in raws:
            failure,_,state=self.exercise('pcre',raw_override=raw)
            self.assertEqual(failure.code,'CANDIDATE_PROBE_UNAVAILABLE');self.assertTrue(state['removed'])
            self.assertFalse(hasattr(failure,'diagnostic'))
        with patch.object(suite,'_run',return_value={'fixed':'result'}) as run:
            self.assertEqual(suite.run_pcre_probe(candidate(),docker_path='C:/docker',profile_path='C:/profile'),{'fixed':'result'})
            self.assertEqual(run.call_args.args,(candidate(),'pcre','scan'))
        with self.assertRaises(suite.ProbeUnavailable):suite.run_public_probe(candidate(),'pcre',docker_path='C:/docker',profile_path='C:/profile')
        with patch.object(suite.subprocess,'list2cmdline',return_value='x'*30000):
            failure,calls,state=self.exercise('pcre')
        self.assertEqual(failure.code,'CANDIDATE_PROBE_UNAVAILABLE');self.assertEqual(calls,[]);self.assertFalse(state['created'])

    def test_closed_failure_on_zero_or_nonzero_is_diagnostic_only_and_rows_are_omitted(self):
        for scenario in ('strict','pcre'):
            for nonzero in (False,True):
                value=failure_payload(scenario)
                # A valid completed prefix is checked, then excluded from output.
                value['cases']=(strict_payload() if scenario=='strict' else pcre_payload())['cases'][:1]
                error,_,state=self.exercise(scenario,failed_case=nonzero,raw_override=json.dumps(value).encode())
                self.assertEqual(error.code,'CANDIDATE_PROBE_UNAVAILABLE');self.assertTrue(state['removed'])
                summary=error.diagnostic
                self.assertEqual(summary['cleanup'],'OWNED_CONTAINER_ABSENT_VERIFIED')
                self.assertFalse(summary['private_input_allowed']);self.assertFalse(summary['result']['passed'])
                self.assertFalse(summary['result']['native_eligible']);self.assertEqual(summary['result']['case_count'],1)
                self.assertEqual(summary['result']['diagnostic'],value['diagnostic'])
                self.assertNotIn('cases',summary['result'])
            good=strict_payload() if scenario=='strict' else pcre_payload()
            error,_,state=self.exercise(scenario,failed_case=True,raw_override=json.dumps(good).encode())
            self.assertEqual(error.code,'CANDIDATE_PROBE_UNAVAILABLE');self.assertTrue(state['removed'])
            self.assertFalse(hasattr(error,'diagnostic'))

    def test_malformed_failure_locations_prefix_types_and_canaries_never_escape(self):
        for scenario in ('strict','pcre'):
            original=failure_payload(scenario);variants=[]
            for field,bad in (('stage','PRIVATE_CANARY'),('kind','PRIVATE_CANARY'),('extra','PRIVATE_CANARY')):
                value=deepcopy(original);value['diagnostic'][field]=bad;variants.append(value)
            for field,bad in (('source','PRIVATE_CANARY'),('function','PRIVATE_CANARY'),('line',True),('line',2049)):
                value=deepcopy(original);value['diagnostic']['location'][field]=bad;variants.append(value)
            for field,bad in (('completed',1),('passed',0),('native_eligible',0),('schema',True),('extra','PRIVATE_CANARY')):
                value=deepcopy(original);value[field]=bad;variants.append(value)
            for field,bad in (('case','PRIVATE_CANARY'),('passed',False)):
                value=deepcopy(original)
                value['cases']=(strict_payload() if scenario=='strict' else pcre_payload())['cases'][:1]
                value['cases'][0][field]=bad;variants.append(value)
            raw_variants=[json.dumps(v).encode() for v in variants]
            raw_variants += [json.dumps(original).encode().replace(b'"schema": 1',b'"schema": 1, "schema": 1'),
                             json.dumps(original).encode('utf-16'),b'x'*65537]
            for raw in raw_variants:
                error,_,state=self.exercise(scenario,failed_case=True,raw_override=raw)
                self.assertEqual(error.code,'CANDIDATE_PROBE_UNAVAILABLE');self.assertTrue(state['removed'])
                self.assertFalse(hasattr(error,'diagnostic'));self.assertNotIn('PRIVATE_CANARY',str(error))

    def test_failure_diagnostic_cleanup_and_journal_uncertainty_dominate(self):
        for scenario in ('strict','pcre'):
            for kwargs in ({'cleanup_fail':True},{'journal_fail':'result.json'},{'journal_fail':'close'}):
                error,_,_=self.exercise(scenario,failed_case=True,**kwargs)
                self.assertEqual(error.code,'CANDIDATE_CLEANUP_UNCONFIRMED')
                self.assertEqual(error.diagnostic['cleanup'],'UNCONFIRMED')
                self.assertFalse(error.diagnostic['result']['passed'])

    def test_v2_rechecks_precreate_normal_prestart_post_and_cleanup_is_independent(self):
        for bad_index in range(4):
            replies=[(0,b'2',b'','EXIT')]*4;replies[bad_index]=(0,b'1',b'','EXIT')
            value,calls,state=self.exercise(cgroup_results=replies)
            self.assertEqual(value.code,'CANDIDATE_PROBE_UNAVAILABLE');self.assertEqual(state['cgroup_checks'],bad_index+1)
            if bad_index==0:self.assertFalse(state['created'])
            else:self.assertTrue(state['removed'])
            if bad_index<=2:self.assertFalse(state['started'])
            last=max(i for i,args in enumerate(calls) if args[0]=='info')
            self.assertFalse(any(args[0]=='info' for args in calls[last+1:]))
        for mode in ('scan','decode'):
            value,_,state=self.exercise(mode=mode,oom_policy_after_start=None)
            self.assertIsInstance(value,dict);self.assertEqual(state['cgroup_checks'],4);self.assertTrue(state['removed'])
        for bad in (True,0,'null'):
            value,_,state=self.exercise(oom_policy_after_start=bad)
            self.assertIsInstance(value,Exception);self.assertTrue(state['removed'])
        for result in ((True,b'2',b'','EXIT'),(1,b'2',b'','EXIT'),(0,b'2',b'','WALL_LIMIT'),(0,b'',b'','EXIT')):
            value,_,state=self.exercise(cgroup_results=[result])
            self.assertIsInstance(value,Exception);self.assertFalse(state['created'])
        for bad_index in (1,2,3):
            replies=[(0,b'2',b'','EXIT')]*4
            replies[bad_index]=suite.base.ContainerUnavailable('CONTAINER_CLEANUP_UNCONFIRMED')
            value,_,state=self.exercise(cgroup_results=replies)
            self.assertEqual(value.code,'CANDIDATE_CLEANUP_UNCONFIRMED');self.assertTrue(state['removed'])

    def test_all_five_scenarios_both_modes_and_strict_use_only_original_id_cleanup(self):
        for mode in ('scan','decode'):
            for scenario in sorted(suite.SCENARIOS):
                value,calls,state=self.exercise(scenario,mode)
                self.assertIsInstance(value,dict);self.assertTrue(state['removed'])
                self.assertFalse(value['native_eligible']);self.assertFalse(value['private_input_allowed'])
                self.assertEqual(value['declared_signature_generation'],candidate().signature_generation)
                self.assertNotIn('signature_generation',value)
                self.assertLess(state['events'].index('create-attempt.json'),state['events'].index('docker_create'))
                self.assertLess(state['events'].index('ownership.json'),state['events'].index('docker_container_inspect'))
                self.assertLess(state['events'].index('ownership.json'),state['events'].index('attach'))
                self.assertEqual(state['journal'][-1][1]['ownership_status'],'ORIGINAL_ID_ABSENT_VERIFIED')
                for args in calls:
                    if args[:2] in (['container','inspect'],['container','kill'],['container','rm']):self.assertEqual(args[-1],'e'*64)
        value,_,_=self.exercise('strict');self.assertFalse(value['strict_helper_confinement'])

    def test_image_no_command_forms_and_inherited_build_labels_are_validated_before_create(self):
        for kwargs in ({'remove_cmd':True},{'image_changes':{'Cmd':None}},{'image_changes':{'Cmd':[]}}):
            value,_,_=self.exercise(**kwargs);self.assertIsInstance(value,dict)
        for command in (False,0,'',{},['python3']):
            value,_,state=self.exercise(image_changes={'Cmd':command})
            self.assertIsInstance(value,Exception);self.assertFalse(state['created'])
        for labels in (None,{}, {'org.kapit.owner':'kapit-public-native-runtime-v1','org.kapit.reservation':'A'*32},
                       {'org.kapit.owner':'kapit-public-native-runtime-v1','org.kapit.reservation':'f'*32,'extra':'CANARY'}):
            value,_,state=self.exercise(image_changes={'Labels':labels})
            self.assertIsInstance(value,Exception);self.assertFalse(state['created'])

    def test_journal_failures_are_sticky_and_record_failure_allows_cleanup_only(self):
        for failure in ('reservation.json','create-attempt.json','ownership.json','result.json','close'):
            value,calls,state=self.exercise(journal_fail=failure)
            self.assertEqual(value.code,'CANDIDATE_CLEANUP_UNCONFIRMED')
            if failure in ('reservation.json','create-attempt.json','ownership.json'):self.assertFalse(state['started'])
            if failure=='create-attempt.json':self.assertFalse(state['created'])
            if failure=='ownership.json':
                self.assertTrue(state['removed'])
                self.assertEqual(sum(args[:2]==['container','inspect'] for args in calls),2)
                self.assertEqual(state['journal'][-1][1]['ownership_status'],'CLEANUP_UNCONFIRMED')
            if failure in ('result.json','close'):self.assertTrue(state['removed'])

    def test_nonzero_create_retains_durable_original_and_preserves_primary_denial(self):
        for code,reason in ((1,'EXIT'),(1,'COMMAND_ERROR'),(0,'WALL_LIMIT')):
            error,calls,state=self.exercise(create_code=code,create_reason=reason)
            self.assertEqual(error.code,'CANDIDATE_PROBE_UNAVAILABLE')
            self.assertFalse(state['started']);self.assertTrue(state['removed'])
            self.assertLess(state['events'].index('ownership.json'),state['events'].index('docker_container_inspect'))
            self.assertEqual(state['journal'][-1][1]['ownership_status'],'ORIGINAL_ID_ABSENT_VERIFIED')
            self.assertEqual(sum(args[:2]==['container','inspect'] for args in calls),2)
        error,_,state=self.exercise(create_code=1,journal_fail='ownership.json')
        self.assertEqual(error.code,'CANDIDATE_CLEANUP_UNCONFIRMED')
        self.assertFalse(state['started']);self.assertTrue(state['removed'])
        self.assertEqual(state['journal'][-1][1]['ownership_status'],'CLEANUP_UNCONFIRMED')

    def test_unknown_id_never_adopts_and_uncertainty_survives_daemon_absence(self):
        error,calls,_=self.exercise(lost_id=True,remaining=b'f'*64)
        self.assertEqual(error.code,'CANDIDATE_CLEANUP_UNCONFIRMED')
        self.assertFalse(any(args[:2] in (['container','inspect'],['container','kill'],['container','rm']) for args in calls))
        for stage in ('image','create','rm'):
            error,_,_=self.exercise(uncertain_stage=stage)
            self.assertEqual(error.code,'CANDIDATE_CLEANUP_UNCONFIRMED')

    def test_interrupt_and_cleanup_priority_and_bad_image_before_start(self):
        error,_,state=self.exercise(interrupt=True)
        self.assertIsInstance(error,KeyboardInterrupt);self.assertTrue(state['removed'])
        error,_,_=self.exercise(interrupt=True,cleanup_fail=True)
        self.assertEqual(error.code,'CANDIDATE_CLEANUP_UNCONFIRMED')
        error,_,state=self.exercise(bad_image=True);self.assertIsInstance(error,Exception);self.assertFalse(state['started'])

    def test_x32_requires159_not_oom_or_generic_exit_and_failure_is_not_success(self):
        for kwargs in ({'oom':True},{'bad_exit':True}):
            error,_,state=self.exercise('x32',**kwargs);self.assertIsInstance(error,suite.ProbeUnavailable);self.assertTrue(state['removed'])
        error,_,state=self.exercise('strict',failed_case=True)
        self.assertIsInstance(error,suite.ProbeUnavailable)
        self.assertEqual(error.diagnostic['cleanup'],'OWNED_CONTAINER_ABSENT_VERIFIED')
        self.assertFalse(error.diagnostic['result']['passed']);self.assertTrue(state['removed'])


class ActualOwnedPythonTests(unittest.TestCase):
    def test_late_stderr_failure_during_join_rejects_a_successful_public_child(self):
        original_thread=suite.threading.Thread
        class DelayedErrors:
            ident=None
            def __init__(self,target,args):self.target,self.args=target,args
            def start(self):self.ident=1
            def join(self,timeout):
                with patch.object(suite.os,'read',side_effect=OSError('PRIVATE_CANARY')):self.target(*self.args)
            def is_alive(self):return False
        def thread(*args,**kwargs):
            if kwargs['args'][2] is False:return DelayedErrors(kwargs['target'],kwargs['args'])
            return original_thread(*args,**kwargs)
        with patch.object(suite.threading,'Thread',side_effect=thread):
            with self.assertRaises(suite.ProbeUnavailable) as caught:
                suite._attach([sys.executable,'-B','-c',"import os;os.write(1,b'PUBLIC')"],timeout=3)
        self.assertEqual(caught.exception.code,'CANDIDATE_PROBE_UNAVAILABLE')

    def test_late_zero_exit_observed_at_first_poll_cannot_skip_wall_limit(self):
        class Pipe:
            closed=False
            def fileno(self):return 42
            def close(self):self.closed=True
        child=SimpleNamespace(stdin=Pipe(),stdout=Pipe(),stderr=Pipe(),poll=lambda:0,wait=lambda timeout:0)
        with patch.object(suite.subprocess,'Popen',return_value=child),patch.object(suite.os,'read',return_value=b''), \
             patch.object(suite.time,'monotonic',side_effect=[0.,2.]):
            with self.assertRaises(suite.ProbeUnavailable):suite._attach(['PUBLIC_TEST_COMMAND'],timeout=1)
        self.assertTrue(all(pipe.closed for pipe in (child.stdin,child.stdout,child.stderr)))

    def test_anonymous_empty_stdin_and_independent_stdout_stderr_bounds(self):
        source="import os,stat;assert stat.S_ISFIFO(os.fstat(0).st_mode);os.write(1,b'PUBLIC');os.write(2,b'PUBLIC')"
        code,out=suite._attach([sys.executable,'-B','-c',source],timeout=3)
        self.assertEqual((code,out),(0,b'PUBLIC'))
        for descriptor,size in ((1,65537),(2,16385)):
            source='import os;os.write('+str(descriptor)+",b'x'*"+str(size)+')'
            with self.assertRaises(suite.ProbeUnavailable):suite._attach([sys.executable,'-B','-c',source],timeout=3)

    def test_wall_and_interrupt_cleanup_reap_only_retained_python_handles(self):
        original=subprocess.Popen;children=[]
        def launch(*args,**kwargs):
            child=original(*args,**kwargs);children.append(child);return child
        with patch.object(suite.subprocess,'Popen',side_effect=launch):
            with self.assertRaises(suite.ProbeUnavailable):suite._attach([sys.executable,'-B','-c','import time;time.sleep(20)'],timeout=.2)
        with patch.object(suite.subprocess,'Popen',side_effect=launch),patch.object(suite.time,'sleep',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):suite._attach([sys.executable,'-B','-c','import time;time.sleep(20)'],timeout=3)
        for child in children:
            self.assertIsNotNone(child.poll());self.assertTrue(all(pipe.closed for pipe in (child.stdin,child.stdout,child.stderr)))


if __name__=='__main__':unittest.main()
