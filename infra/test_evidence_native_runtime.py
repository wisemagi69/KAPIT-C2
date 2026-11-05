"""Public fixture/controller/protocol boundaries. No Docker/native scanner."""
from contextlib import nullcontext
from copy import deepcopy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from infra import evidence_native_runtime as runtime
from infra import evidence_native_fixtures as fixtures
from infra.test_evidence_container import inspection as old_inspection
from backend.apps.operations import evidence_scan_protocol as protocol
from backend.apps.operations.evidence_policy import inspect_container


def candidate():return runtime.Candidate('sha256:'+'a'*64,'b'*64)
def binding(mode='scan'):return protocol.Binding(mode,'c'*64,runtime.POLICY_SHA256,'b'*64)
def phase(mode='scan'):return runtime._Phase(candidate(),binding(mode),'d'*32)


def inspection(p, *, running=False, exit_code=0):
    legacy=runtime.base.ProbePolicy(runtime.public.BASE_IMAGE,p.candidate.image_id,p.token,'identity')
    value=old_inspection(legacy)
    value.update(Id='e'*64,Name='/'+p.name)
    value['Config'].update(Labels=p.labels,Cmd=p.command,OpenStdin=True,StdinOnce=True,
        Entrypoint=[runtime.ENTRYPOINT],Env=[k+'='+v for k,v in runtime.EFFECTIVE_ENV.items()])
    memory,cpu,_=runtime.LIMITS[p.binding.mode]
    value['HostConfig'].update(Memory=memory,MemorySwap=memory,OomKillDisable=False,
        SecurityOpt=['no-new-privileges=true','seccomp='+runtime.base.canonical(runtime.public.startup_profile()).decode()],
        Ulimits=[{'Name':'cpu','Soft':cpu,'Hard':cpu},{'Name':'core','Soft':0,'Hard':0},
                 {'Name':'fsize','Soft':runtime.base.SCRATCH,'Hard':runtime.base.SCRATCH},{'Name':'nofile','Soft':32,'Hard':32}])
    value['State'].update(Running=running,Pid=22 if running else 0,ExitCode=exit_code,OOMKilled=False)
    return value


def image(p):
    return {'Id':p.candidate.image_id,'Os':'linux','Architecture':'amd64','Config':{
        'Entrypoint':[runtime.ENTRYPOINT,'-I','-B','-m',runtime.MODULE],'Cmd':[],
        'Labels':{'org.kapit.owner':'kapit-public-native-runtime-v1','org.kapit.reservation':'f'*32},
        'WorkingDir':'/scratch','User':'65532:65532','Env':[k+'='+v for k,v in runtime.IMAGE_ENV.items()]}}


class PolicyTests(unittest.TestCase):
    def test_cgroup_version_result_is_fresh_exact_bounded_and_never_a_flag(self):
        for raw in (b'2',b'2\n',b'2\r\n'):
            call=Mock(return_value=(0,raw,b'','EXIT'))
            runtime._require_cgroup_v2(call,timeout=3)
            call.assert_called_once_with('info','--format','{{.CgroupVersion}}',timeout=3)
        for result in [(True,b'2',b'','EXIT'),(1,b'2',b'','EXIT'),(0,b'2',b'','WALL_LIMIT')]+[
                (0,raw,b'','EXIT') for raw in (b'1',b'',b'3',b' 2 ',b'2\n2',b'2\nextra',b'\xff',b'2\x00','2',None)]:
            with self.assertRaises(runtime.NativeUnavailable):runtime._require_cgroup_v2(Mock(return_value=result))

    def test_present_false_or_null_oom_policy_all_states_preserves_resource_types(self):
        for mode in ('scan','decode'):
            for running in (False,True):
                p=phase(mode)
                for value in (False,None):
                    doc=inspection(p,running=running);doc['HostConfig']['OomKillDisable']=value
                    runtime.verify_inspection(doc,p,container_id='e'*64,running=running)
                for value in (True,0,1,'false','null',{},[]):
                    doc=inspection(p,running=running);doc['HostConfig']['OomKillDisable']=value
                    with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(doc,p,container_id='e'*64,running=running)
                doc=inspection(p,running=running);doc['HostConfig'].pop('OomKillDisable')
                with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(doc,p,container_id='e'*64,running=running)
                for field in ('Memory','MemorySwap'):
                    doc=inspection(p,running=running);doc['HostConfig'].update(OomKillDisable=None);doc['HostConfig'][field]=True
                    with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(doc,p,container_id='e'*64,running=running)
    def test_build_labels_and_no_image_command_representations_are_exact(self):
        p=phase();good=image(p)
        for command in (None,[]):
            value=deepcopy(good);value['Config']['Cmd']=command;runtime.verify_image(value,p.candidate)
        value=deepcopy(good);value['Config'].pop('Cmd');runtime.verify_image(value,p.candidate)
        for command in (False,0,'',{},['python3']):
            value=deepcopy(good);value['Config']['Cmd']=command
            with self.assertRaises(runtime.NativeUnavailable):runtime.verify_image(value,p.candidate)
        labels=good['Config']['Labels']
        for changed in (None,{},labels|{'extra':'PRIVATE_CANARY'},labels|{'org.kapit.owner':'other'},
                        labels|{'org.kapit.reservation':'A'*32},labels|{'org.kapit.reservation':False}):
            value=deepcopy(good);value['Config']['Labels']=changed
            with self.assertRaises(runtime.NativeUnavailable):runtime.verify_image(value,p.candidate)
        args=runtime.create_args(p,profile_path='C:/profile.json')
        self.assertIn('org.kapit.reservation='+p.token,args)
        self.assertIn('org.kapit.owner='+runtime.OWNER,args)
        changed=inspection(p);changed['Config']['Labels']['org.kapit.reservation']='f'*32
        with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(changed,p,container_id='e'*64)

    def test_stdout_reader_enforces_total_budget_before_returning_excess(self):
        reader=runtime._BoundedReader(SimpleNamespace(fileno=lambda:42),10)
        with patch.object(runtime.os,'read',side_effect=[b'x'*8,b'y'*3]) as reading:
            self.assertEqual(reader.read(8),b'x'*8)
            with self.assertRaises(runtime.NativeUnavailable):reader.read(3)
        self.assertEqual(reading.call_args_list[0].args,(42,8))

    def test_private_ingress_always_closed_and_only_source_fixed_fixture_ids_exist(self):
        for fn in (runtime.run_scan,runtime.decode):
            with self.assertRaises(runtime.NativeUnavailable):fn(b'PRIVATE_CANARY',ready=True,proof={'PASS':True})
        for value in ('../image.png',b'png_clean','private','',True):
            with self.assertRaises(ValueError):fixtures.fixture(value)
        for value in ('sha256:'+'A'*64,'a'*64):
            with self.assertRaises(runtime.NativeUnavailable):runtime.Candidate(value,'b'*64)
        with self.assertRaises(runtime.NativeUnavailable):runtime.Candidate(candidate().image_id,'0'*64)

    def test_fixed_public_png_jpeg_metadata_and_malformed_fixtures_have_bounded_framing(self):
        for name in fixtures.IDS-{'png_malformed'}:
            value=fixtures.fixture(name)
            info=inspect_container(value.data,value.media_type)
            self.assertEqual((info.width,info.height),(1,1))
            self.assertLess(len(value.data),1024)
        with self.assertRaises(Exception):inspect_container(fixtures.fixture('png_malformed').data,'image/png')
        self.assertEqual(fixtures.fixture('png_eicar').expected_original_code,'SCAN_NOT_CLEAN')
        self.assertFalse(fixtures.derivative_metadata_absent(fixtures.fixture('png_metadata').data))

    def test_production_phase_limits_entrypoint_empty_stdin_and_no_mount_or_secret_args(self):
        for mode in ('scan','decode'):
            p=phase(mode);args=runtime.create_args(p,profile_path='C:/owned/profile.json')
            memory,cpu,wall=runtime.LIMITS[mode]
            self.assertIn('--interactive',args);self.assertIn('--pull=never',args)
            self.assertEqual(args[args.index('--memory')+1],str(memory))
            self.assertEqual(args[args.index('--memory-swap')+1],str(memory))
            self.assertIn('cpu='+str(cpu)+':'+str(cpu),args)
            self.assertEqual(wall,180 if mode=='scan' else 30)
            self.assertEqual(args[-7:],[p.candidate.image_id,*p.command])
            for forbidden in ('--volume','--mount','--privileged','--publish'):self.assertNotIn(forbidden,args)

    def test_exact_config_and_nested_limit_types_fail_closed(self):
        for mode in ('scan','decode'):
            p=phase(mode);good=inspection(p)
            runtime.verify_inspection(good,p,container_id='e'*64)
            variants=[]
            for section,key,value in [('Config','StdinOnce',False),('Config','Cmd',['untrusted']),
                ('Config','Entrypoint',['/usr/local/bin/python3']),('HostConfig','Memory',True),
                ('HostConfig','PidsLimit',2),('HostConfig','OomKillDisable',True),('HostConfig','IpcMode','host'),
                ('HostConfig','Binds',['private:/data'])]:
                changed=deepcopy(good);changed[section][key]=value;variants.append(changed)
            changed=deepcopy(good);changed['HostConfig']['Ulimits'][1]['Soft']=False;variants.append(changed)
            for changed in variants:
                with self.assertRaises(runtime.NativeUnavailable):runtime.verify_inspection(changed,p,container_id='e'*64)


class LifecycleTests(unittest.TestCase):
    def exercise(self, *, create_output=None, remaining=b'', interrupt=False, fail_cleanup=False,
                 bad_ready_state=False, env_injection=False, bad_image=False, existing=False, uncertain_stage=None,journal_fail=None,
                 create_code=0,create_reason='EXIT',cgroup_results=None,oom_after_start=False):
        p=phase();calls=[];state={'created':False,'started':False,'killed':False,'removed':False,'live':False,'events':[],'journal':[]}
        class Host:
            def __init__(self,token):pass
            def __enter__(self):return self
            def save(self,name,document):
                state['events'].append(name);state['journal'].append((name,document))
                if journal_fail==name:raise OSError('PRIVATE_CANARY_JOURNAL')
            def close(self):
                state['events'].append('journal_closed')
                if journal_fail=='close':raise OSError('PRIVATE_CANARY_CLOSE')
        def uncertainty(stage):
            if stage==uncertain_stage and not state.get('uncertainty_raised'):
                state['uncertainty_raised']=True
                raise runtime.base.ContainerUnavailable('CONTAINER_CLEANUP_UNCONFIRMED')
        def call(argv,**kwargs):
            args=argv[3:];calls.append(args)
            state.setdefault('command_timeouts',[]).append((args,kwargs.get('timeout')))
            state['events'].append('docker_'+('_'.join(args[:2]) if args[0]!='create' else 'create'))
            if args[0]=='create':self.assertIn('create-attempt.json',state['events'])
            if args==['info','--format','{{.CgroupVersion}}']:
                count=state.get('cgroup_checks',0);state['cgroup_checks']=count+1
                result=cgroup_results[count] if cgroup_results else (0,b'2\n',b'','EXIT')
                if isinstance(result,BaseException):raise result
                return result
            if args[:2]==['image','inspect']:
                uncertainty('image')
                doc=image(p)
                if bad_image:doc['Config']['Env'].append('LD_PRELOAD=PRIVATE_CANARY')
                return 0,json.dumps([doc]).encode(),b'','EXIT'
            if args[:2]==['container','ls']:
                if not state['created']:uncertainty('initial_ls')
                if state['removed']:uncertainty('absence')
                if not state['created']:return 0,(b'f'*64 if existing else b''),b'','EXIT'
                return 0,(b'' if state['removed'] else remaining),b'','EXIT'
            if args[0]=='create':
                state['created']=True
                uncertainty('create')
                return create_code,(create_output if create_output is not None else b'e'*64),b'',create_reason
            if args[:2]==['container','inspect']:
                uncertainty('inspect')
                self.assertEqual(args[-1],'e'*64)
                doc=inspection(p,running=state['started'] and not state['killed'])
                if state['started']:doc['HostConfig']['OomKillDisable']=oom_after_start
                if bad_ready_state and state['started']:doc['HostConfig']['IpcMode']='host'
                if env_injection:doc['Config']['Env'].append('HTTP_PROXY=PRIVATE_CANARY')
                return 0,json.dumps([doc]).encode(),b'','EXIT'
            if args[:2]==['container','kill']:
                uncertainty('kill')
                if fail_cleanup:raise OSError('PRIVATE_CANARY')
                state['killed']=True;return 0,b'',b'','EXIT'
            if args[:2]==['container','rm']:
                uncertainty('rm')
                if fail_cleanup:raise OSError('PRIVATE_CANARY')
                state['removed']=True;return 0,b'',b'','EXIT'
            raise AssertionError('UNKNOWN_MOCK_CLI_ACTION')
        def exchange(argv,b,data,media,*,live_check):
            self.assertIn('ownership.json',state['events'])
            state['events'].append('attach')
            state['started']=True
            live_check(5.0);state['live']=True
            if interrupt:raise KeyboardInterrupt()
            state['killed']=True
            return {'code':'SCAN_CLEAN'},b'',0
        with patch.object(runtime,'uuid',SimpleNamespace(uuid4=lambda:SimpleNamespace(hex=p.token))), \
             patch.object(runtime.secrets,'token_hex',return_value=p.binding.nonce), \
             patch.object(runtime.ownership_journal,'_Host',Host), \
             patch.object(runtime.base,'_bounded_command',side_effect=call),patch.object(runtime,'_exchange',side_effect=exchange):
            try:return runtime._phase(p.candidate,'scan',b'PUBLIC','image/png',fixture_id='png_clean',stage='original_scan',docker_path='C:/docker.exe',profile_path='C:/profile.json'),calls,state
            except BaseException as error:return error,calls,state

    def test_ownership_pin_chain_refusal_precedes_every_daemon_action(self):
        self.assertEqual(runtime.OWNERSHIP_SHA256,runtime.hashlib.sha256(Path(runtime.ownership_journal.__file__).read_bytes()).hexdigest())
        with patch.object(runtime,'OWNERSHIP_SHA256','0'*64):
            value,calls,state=self.exercise()
        self.assertEqual(value.code,'NATIVE_FIXTURE_UNAVAILABLE')
        self.assertEqual(calls,[]);self.assertFalse(state['created'])
        with patch.object(runtime.subprocess,'list2cmdline',return_value='x'*30000):
            value,calls,state=self.exercise()
        self.assertEqual(value.code,'NATIVE_FIXTURE_UNAVAILABLE');self.assertEqual(calls,[]);self.assertFalse(state['created'])

    def test_v2_checked_each_boundary_and_change_never_skips_owned_cleanup(self):
        for bad_index in range(4):
            replies=[(0,b'2\n',b'','EXIT')]*4;replies[bad_index]=(0,b'1\n',b'','EXIT')
            value,calls,state=self.exercise(cgroup_results=replies)
            self.assertEqual(value.code,'NATIVE_FIXTURE_UNAVAILABLE')
            self.assertEqual(state['cgroup_checks'],bad_index+1)
            if bad_index==0:self.assertFalse(state['created'])
            else:self.assertTrue(state['removed'])
            if bad_index<=1:self.assertFalse(state['started'])
            if bad_index==2:self.assertFalse(state['live'])
            if bad_index:
                info_indices=[i for i,args in enumerate(calls) if args[0]=='info']
                self.assertTrue(all(args[0]!='info' for args in calls[info_indices[-1]+1:]))
        for result in ((1,b'2',b'','EXIT'),(0,b'2',b'','WALL_LIMIT'),(0,b'',b'','EXIT')):
            value,_,state=self.exercise(cgroup_results=[result])
            self.assertIsInstance(value,runtime.NativeUnavailable);self.assertFalse(state['created'])
        for bad_index in (1,2,3):
            replies=[(0,b'2',b'','EXIT')]*4
            replies[bad_index]=runtime.base.ContainerUnavailable('CONTAINER_CLEANUP_UNCONFIRMED')
            value,_,state=self.exercise(cgroup_results=replies)
            self.assertEqual(value.code,'NATIVE_CLEANUP_UNCONFIRMED');self.assertTrue(state['removed'])

    def test_documented_null_after_start_and_shared_live_deadline(self):
        with patch.object(runtime.time,'monotonic',side_effect=[100.0,103.0]):
            value,_,state=self.exercise(oom_after_start=None)
        self.assertEqual(value[0]['code'],'SCAN_CLEAN');self.assertEqual(state['cgroup_checks'],4)
        inspections=[timeout for args,timeout in state['command_timeouts'] if args[:2]==['container','inspect']]
        self.assertEqual(inspections[1],2.0)
        with patch.object(runtime.time,'monotonic',side_effect=[100.0,106.0]):
            value,_,state=self.exercise(oom_after_start=None)
        self.assertIsInstance(value,runtime.NativeUnavailable);self.assertTrue(state['removed'])
        self.assertFalse(state['live'])
        for bad in (True,0,'null'):
            value,_,state=self.exercise(oom_after_start=bad)
            self.assertIsInstance(value,runtime.NativeUnavailable);self.assertTrue(state['removed']);self.assertFalse(state['live'])

    def test_exact_create_id_is_only_cleanup_authority_and_live_check_precedes_request(self):
        value,calls,state=self.exercise()
        self.assertEqual(value[0]['code'],'SCAN_CLEAN');self.assertTrue(state['removed'] and state['live'])
        for args in calls:
            if args[:2] in (['container','inspect'],['container','kill'],['container','rm']):self.assertEqual(args[-1],'e'*64)
        events=state['events']
        self.assertLess(events.index('create-attempt.json'),events.index('docker_create'))
        self.assertLess(events.index('docker_create'),events.index('ownership.json'))
        self.assertLess(events.index('ownership.json'),events.index('docker_container_inspect'))
        self.assertLess(events.index('ownership.json'),events.index('attach'))
        self.assertEqual(state['journal'][-1][1]['ownership_status'],'ORIGINAL_ID_ABSENT_VERIFIED')

    def test_journal_failures_never_start_or_clear_uncertainty_after_verified_cleanup(self):
        for failure in ('reservation.json','create-attempt.json','ownership.json','result.json','close'):
            value,calls,state=self.exercise(journal_fail=failure)
            self.assertEqual(value.code,'NATIVE_CLEANUP_UNCONFIRMED')
            if failure in ('reservation.json','create-attempt.json','ownership.json'):self.assertFalse(state['started'])
            if failure=='ownership.json':
                self.assertTrue(state['removed'])
                self.assertEqual(state['journal'][-1][1]['ownership_status'],'CLEANUP_UNCONFIRMED')
                self.assertEqual(sum(args[:2]==['container','inspect'] for args in calls),2)  # Cleanup only.
            if failure=='create-attempt.json':self.assertFalse(state['created'])
            if failure=='result.json':self.assertTrue(state['removed'])

    def test_failed_create_with_valid_original_id_is_durable_before_cleanup_and_never_starts(self):
        for code,reason in ((1,'EXIT'),(1,'COMMAND_ERROR'),(0,'WALL_LIMIT')):
            value,calls,state=self.exercise(create_code=code,create_reason=reason)
            self.assertEqual(value.code,'NATIVE_FIXTURE_UNAVAILABLE')
            self.assertFalse(state['started']);self.assertTrue(state['removed'])
            self.assertLess(state['events'].index('ownership.json'),state['events'].index('docker_container_inspect'))
            self.assertEqual(state['journal'][-1][1]['ownership_status'],'ORIGINAL_ID_ABSENT_VERIFIED')
            self.assertEqual(next(doc for name,doc in state['journal'] if name=='ownership.json')['original_id'],'e'*64)
            self.assertEqual(sum(args[:2]==['container','inspect'] for args in calls),2)
        value,_,state=self.exercise(create_code=1,journal_fail='ownership.json')
        self.assertEqual(value.code,'NATIVE_CLEANUP_UNCONFIRMED')
        self.assertFalse(state['started']);self.assertTrue(state['removed'])
        self.assertEqual(state['journal'][-1][1]['ownership_status'],'CLEANUP_UNCONFIRMED')

    def test_unknown_create_id_never_adopts_name_or_stops_another_child(self):
        for output in (b'',b'name',b'e'*64+b'\n'+b'f'*64,b'\xff'):
            value,calls,state=self.exercise(create_output=output,remaining=b'f'*64)
            self.assertEqual(value.code,'NATIVE_CLEANUP_UNCONFIRMED')
            self.assertFalse(any(args[:2] in (['container','inspect'],['container','kill'],['container','rm']) for args in calls))

    def test_interruption_cleanup_and_cleanup_failure_dominance(self):
        value,_,state=self.exercise(interrupt=True)
        self.assertIsInstance(value,KeyboardInterrupt);self.assertTrue(state['removed'] and state['killed'])
        value,_,_=self.exercise(interrupt=True,fail_cleanup=True)
        self.assertEqual(value.code,'NATIVE_CLEANUP_UNCONFIRMED')

    def test_bounded_cli_cleanup_uncertainty_is_sticky_at_every_lifecycle_boundary(self):
        for stage in ('image','initial_ls','create','inspect','kill','rm','absence'):
            value,calls,state=self.exercise(uncertain_stage=stage,interrupt=stage=='kill')
            self.assertIsInstance(value,runtime.NativeUnavailable)
            self.assertEqual(value.code,'NATIVE_CLEANUP_UNCONFIRMED')
            self.assertTrue(state['uncertainty_raised'])
            if stage=='create':
                self.assertFalse(any(args[:2] in (['container','inspect'],['container','kill'],['container','rm']) for args in calls))
            if stage=='inspect':self.assertTrue(state['removed'])

    def test_changed_live_config_or_injected_env_never_authorizes_request(self):
        for kwargs in ({'bad_ready_state':True},{'env_injection':True},{'bad_image':True},{'existing':True}):
            value,_,state=self.exercise(**kwargs)
            self.assertIsInstance(value,Exception);self.assertFalse(state['live'])


CHILD = r'''
import sys,time
from backend.apps.operations import evidence_scan_protocol as p
from infra.evidence_native_fixtures import fixture
b=p.Binding(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]);case=sys.argv[5]
if case=='stall':time.sleep(20)
if case=='stderr':sys.stderr.buffer.write(b'x'*20000);sys.stderr.buffer.flush()
ready=(p.Binding(b.mode,'f'*64,b.policy_sha256,b.signature_generation) if case=='wrong_ready' else
 p.Binding(b.mode,b.nonce,b.policy_sha256,'f'*64) if case=='wrong_generation' else
 p.Binding(b.mode,b.nonce,'f'*64,b.signature_generation) if case=='wrong_policy' else
 p.Binding('decode' if b.mode=='scan' else 'scan',b.nonce,b.policy_sha256,b.signature_generation) if case=='wrong_mode' else b)
p.write_ready(sys.stdout.buffer,ready)
media,data=p.read_request(sys.stdin.buffer,b)
if case=='extra':
 p.write_result(sys.stdout.buffer,b,'SCAN_CLEAN');sys.stdout.buffer.write(b'EXTRA');sys.stdout.buffer.flush()
elif case=='reflection':p.write_request(sys.stdout.buffer,b,data,media)
elif case=='nonclean':p.write_result(sys.stdout.buffer,b,'SCAN_NOT_CLEAN');raise SystemExit(2)
elif b.mode=='scan':p.write_result(sys.stdout.buffer,b,'SCAN_CLEAN')
else:p.write_result(sys.stdout.buffer,b,'DECODE_COMPLETE',data=fixture('png_clean').data,width=1,height=1)
'''


class ActualPythonPipeTests(unittest.TestCase):
    def test_late_zero_completion_cannot_skip_deadline_when_loop_condition_finishes(self):
        original_event=threading.Event;events=[];written=original_event();clock={'late':False}
        class Pipe:
            closed=False
            def fileno(self):return 42
            def write(self,data):return len(data)
            def flush(self):pass
            def close(self):self.closed=True;written.set()
        class Child:
            stdin=Pipe();stdout=Pipe();stderr=Pipe();returncode=None
            def poll(self):
                if len(events)>=4 and events[2].is_set() and events[3].is_set():
                    clock['late']=True;self.returncode=0;return 0
                return None
            def wait(self,timeout):return 0
            def kill(self):self.returncode=-9
        child=Child()
        def event():
            value=original_event();events.append(value);return value
        def result(stream,bound):
            if not written.wait(2):raise AssertionError('PUBLIC_WRITER_DID_NOT_CLOSE')
            return {'code':'SCAN_CLEAN'},b''
        with patch.object(runtime.threading,'Event',side_effect=event),patch.object(runtime.subprocess,'Popen',return_value=child), \
             patch.object(runtime.protocol,'read_ready',return_value=None),patch.object(runtime.protocol,'read_result',side_effect=result), \
             patch.object(runtime.os,'read',return_value=b''),patch.object(runtime.time,'monotonic',side_effect=lambda:1000. if clock['late'] else 0.):
            with self.assertRaises(runtime.NativeUnavailable) as caught:
                runtime._exchange(['PUBLIC_TEST_COMMAND'],binding(),b'PUBLIC','image/png',live_check=lambda remaining:None)
        self.assertTrue(clock['late']);self.assertEqual(child.returncode,0)
        self.assertEqual(caught.exception.code,'NATIVE_FIXTURE_UNAVAILABLE')
        self.assertTrue(all(pipe.closed for pipe in (child.stdin,child.stdout,child.stderr)))

    def test_stderr_failure_first_observed_during_join_invalidates_pending_success(self):
        original_thread=runtime.threading.Thread
        original_popen=subprocess.Popen;children=[]
        def launch(*args,**kwargs):
            child=original_popen(*args,**kwargs);children.append(child);return child
        class DelayedErrors:
            ident=None
            def __init__(self,target):self.target=target
            def start(self):self.ident=1
            def join(self,timeout):
                with patch.object(runtime.os,'read',side_effect=OSError('PRIVATE_CANARY_LATE_READ')):
                    self.target()
            def is_alive(self):return False
        def thread_factory(*args,**kwargs):
            if kwargs.get('target').__name__=='errors':return DelayedErrors(kwargs['target'])
            return original_thread(*args,**kwargs)
        with patch.object(runtime.threading,'Thread',side_effect=thread_factory),patch.object(runtime.subprocess,'Popen',side_effect=launch):
            with self.assertRaises(runtime.NativeUnavailable) as caught:self.exchange()
        self.assertEqual(caught.exception.code,'NATIVE_FIXTURE_UNAVAILABLE')
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].poll())
        self.assertTrue(all(pipe.closed for pipe in (children[0].stdin,children[0].stdout,children[0].stderr)))

    def exchange(self,case='good',mode='scan',live=None):
        b=binding(mode)
        return runtime._exchange([sys.executable,'-B','-c',CHILD,b.mode,b.nonce,b.policy_sha256,b.signature_generation,case],
            b,fixtures.fixture('png_clean').data,'image/png',live_check=live or (lambda remaining:None))

    def test_short_ready_then_request_eof_and_result_complete_without_buffer_deadlock(self):
        for mode in ('scan','decode'):
            seen=[];header,data,code=self.exchange(mode=mode,live=lambda remaining:seen.append('LIVE'))
            self.assertEqual(seen,['LIVE']);self.assertEqual(code,0)
            self.assertEqual(header['code'],'SCAN_CLEAN' if mode=='scan' else 'DECODE_COMPLETE')
            self.assertEqual(bool(data),mode=='decode')

    def test_wrong_ready_extra_reflection_and_stderr_overflow_refuse(self):
        for case in ('wrong_ready','wrong_generation','wrong_policy','wrong_mode','extra','reflection','stderr'):
            seen=[]
            with self.assertRaises(runtime.NativeUnavailable):self.exchange(case,live=lambda remaining:seen.append('LIVE'))
            if case.startswith('wrong_'):self.assertEqual(seen,[])

    def test_actual_nonclean_result_exit2_is_preserved_without_success(self):
        header,data,code=self.exchange('nonclean')
        self.assertEqual(header['code'],'SCAN_NOT_CLEAN');self.assertEqual(data,b'');self.assertEqual(code,2)

    def test_wall_and_live_interrupt_reap_exact_python_handle_and_join_streams(self):
        original=subprocess.Popen;children=[]
        def launch(*args,**kwargs):
            child=original(*args,**kwargs);children.append(child);return child
        with patch.object(runtime.subprocess,'Popen',side_effect=launch),patch.dict(runtime.LIMITS,{'scan':(4294967296,120,.3)}):
            with self.assertRaises(runtime.NativeUnavailable):self.exchange('stall')
        with patch.object(runtime.subprocess,'Popen',side_effect=launch):
            with self.assertRaises(KeyboardInterrupt):self.exchange(live=lambda remaining:(_ for _ in ()).throw(KeyboardInterrupt()))
        self.assertEqual(len(children),2)
        for child in children:
            self.assertIsNotNone(child.poll())
            self.assertTrue(all(pipe.closed for pipe in (child.stdin,child.stdout,child.stderr)))


class PipelineTests(unittest.TestCase):
    def exercise(self,fixture_id='png_metadata',*,bad_derivative=False,wrong_scan=False):
        calls=[]
        def phase_run(c,mode,data,media,**kwargs):
            self.assertEqual(kwargs['fixture_id'],fixture_id)
            self.assertEqual(kwargs['stage'],('original_scan','decode','derivative_scan')[len(calls)])
            calls.append((mode,data,media))
            if mode=='decode':
                return {'code':'DECODE_COMPLETE'},fixtures.fixture('png_metadata' if bad_derivative else 'png_clean').data
            return {'code':('SCAN_CLEAN' if wrong_scan else fixtures.fixture(fixture_id).expected_original_code) if len(calls)==1 else 'SCAN_CLEAN'},b''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);docker=root/'docker.exe';profile=root/'profile.json'
            docker.write_bytes(b'public fixture');profile.write_bytes(runtime.base.canonical(runtime.public.startup_profile()))
            with patch('infra.evidence_tools.Windows',return_value=SimpleNamespace(pin=lambda *a,**k:nullcontext())), \
                 patch.object(runtime,'_phase',side_effect=phase_run):
                value=runtime.run_fixture_pipeline(candidate(),fixture_id,docker_path=docker,profile_path=profile)
        return value,calls

    def test_three_phase_pipeline_uses_normalized_derivative_and_returns_no_bytes_or_identities(self):
        value,calls=self.exercise()
        self.assertEqual([mode for mode,_,_ in calls],['scan','decode','scan'])
        self.assertEqual(calls[2][1],fixtures.fixture('png_clean').data)
        self.assertEqual(value['phase_count'],3);self.assertEqual((value['width'],value['height']),(1,1))
        self.assertFalse(value['private_input_allowed']);self.assertEqual(value['native_eligibility'],'DISABLED')
        self.assertNotIn('sha256',json.dumps(value));self.assertNotIn('METADATA',json.dumps(value))

    def test_nonclean_and_malformed_stop_before_decoder_and_wrong_expected_code_refuses(self):
        for fixture_id in ('png_eicar','png_malformed'):
            value,calls=self.exercise(fixture_id)
            self.assertEqual(len(calls),1);self.assertEqual(value['phase_count'],1)
            with self.assertRaises(runtime.NativeUnavailable):self.exercise(fixture_id,wrong_scan=True)

    def test_metadata_in_derivative_refuses_instead_of_becoming_scan_or_success(self):
        with self.assertRaises(Exception):self.exercise(bad_derivative=True)


if __name__ == '__main__':unittest.main()
