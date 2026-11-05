"""Public-controller policy/mock lifecycle and owned Python CLI tests only.

No Docker, Linux syscall, private evidence, native library or trust activation.
"""
from contextlib import nullcontext
from copy import deepcopy
import io
import itertools
import errno
import json
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from infra import evidence_container_native as native
from infra.test_evidence_container import inspection as old_inspection


def policy(scenario='confinement'):
    return native.NativeProbePolicy('sha256:' + 'b'*64, 'c'*32, scenario)


def inspection(p, running=False):
    result = old_inspection(p.legacy)
    result['Name'] = '/' + p.name
    result['Config'].update(Labels=p.labels, OpenStdin=True, StdinOnce=True,
        Cmd=['-I', '-B', '-c', native.probe_program(), p.scenario], Env=[k+'='+v for k,v in native.FIXED_ENV.items()])
    result['HostConfig']['SecurityOpt'] = ['no-new-privileges=true', 'seccomp=' + native.canonical(native.startup_profile()).decode()]
    result['State'].update(Running=running, Pid=123 if running else 0, ExitCode=159 if p.scenario=='x32' else 0, OOMKilled=False)
    return result


def payload(p):
    return {'schema': 1, 'purpose': 'PUBLIC_ABI3_CONFINEMENT', 'scenario': p.scenario,
        'policy': native.POLICY_ID, 'landlock_abi': 3,
        'checks': {name: True for name in native.CHECKS[p.scenario]},
        'native_validation': 'DISABLED', 'private_input_allowed': False}


def failure_payload():
    return {'schema': 1, 'purpose': 'PUBLIC_ABI3_FAILURE', 'scenario': 'confinement',
        'stage': 'INSTALL', 'failure_class': 'CONFINEMENT_UNAVAILABLE',
        'helper_function': '_scratch', 'helper_line': 190,
        'native_validation': 'DISABLED', 'private_input_allowed': False}


class NativePublicPolicyTests(unittest.TestCase):
    def test_shm_namespace_distinguishes_absence_fact_from_actual_creation_denial(self):
        start=native._PROBE.index('def shm_namespace_checks():')
        end=native._PROBE.index("if scenario=='preopened_fd':",start)
        code=compile(native._PROBE[start:end],'<fixed-shm>','exec')
        denied_source=native._PROBE[native._PROBE.index('def denied(action):'):native._PROBE.index('def blocked(number,')]
        for absent,error_number,created,dev_mode,raises in (
            (True,errno.EPERM,False,stat.S_IFDIR,False),
            (True,errno.EACCES,False,stat.S_IFDIR,False),
            (True,errno.EROFS,False,stat.S_IFDIR,False),
            (True,errno.ENOENT,False,stat.S_IFDIR,False),
            (True,None,True,stat.S_IFDIR,False),
            (False,errno.EEXIST,False,stat.S_IFDIR,False),
            (None,errno.EPERM,False,stat.S_IFDIR,True),
            (True,errno.EPERM,False,stat.S_IFLNK,True)):
            calls=[];checks={}
            def lstat(path):
                calls.append(('lstat',path))
                if path=='/dev':return SimpleNamespace(st_mode=dev_mode)
                self.assertEqual(path,'/dev/shm')
                if absent is True:raise FileNotFoundError(errno.ENOENT,'private fixed fixture')
                if absent is None:raise OSError(errno.EACCES,'private fixed fixture')
                return SimpleNamespace(st_mode=stat.S_IFDIR)
            def mkdir(path):
                calls.append(('mkdir',path));self.assertEqual(path,'/dev/shm')
                if not created:raise OSError(error_number,'private fixed fixture')
            namespace={'checks':checks,'os':SimpleNamespace(lstat=lstat,mkdir=mkdir),'stat':stat,'errno':errno}
            exec(compile(denied_source,'<fixed-denied>','exec'),namespace)
            exec(code,namespace)
            if raises:
                with self.assertRaises((OSError,SystemExit)):namespace['shm_namespace_checks']()
                self.assertFalse(any(name=='mkdir' for name,_ in calls))
            else:
                checks.update(namespace['shm_namespace_checks']())
                self.assertEqual(checks['shm_absent'],absent)
                self.assertEqual(checks['shm_create_denied'],error_number in (errno.EPERM,errno.EACCES,errno.EROFS))
                self.assertEqual(calls,[('lstat','/dev'),('lstat','/dev/shm'),('mkdir','/dev/shm')])
        branch=native._PROBE[native._PROBE.index("elif scenario=='shm_namespace':"):native._PROBE.index("elif scenario=='storage':")]
        self.assertIn("source.read()==b'public'",branch)
        self.assertIn("helper.install_abi3_confinement(fd)",native.probe_program())
        self.assertNotIn('outside_create_shm',native.CHECKS['confinement'])
        self.assertEqual(native._PROBE.count('checks.update(shm_namespace_checks())'),2)

    def test_full_confinement_requires_each_namespace_fact_independently(self):
        good=payload(policy())
        for name in ('dev_directory','shm_absent','shm_create_denied'):
            failed=deepcopy(good);failed['checks'][name]=False
            raw=json.dumps(failed).encode()
            with self.assertRaises(native.ContainerUnavailable):native._payload(raw,'confinement')
            self.assertEqual(native._failed_check_frame(raw,'confinement')['failed_check_names'],[name])
        old=deepcopy(good)
        for name in ('dev_directory','shm_absent','shm_create_denied'):old['checks'].pop(name)
        old['checks']['outside_create_shm']=True
        self.assertIsNone(native._failed_check_frame(json.dumps(old).encode(),'confinement'))
        with self.assertRaises(native.ContainerUnavailable):native._payload(json.dumps(old).encode(),'confinement')

    def test_split_outside_create_preserves_all_true_equivalence_and_runs_every_path(self):
        start=native._PROBE.index(" for name,path in (('outside_create_root'")
        end=native._PROBE.index(" stage='SHM_NAMESPACE'",start)
        source=''.join(line[1:]+'\n' for line in native._PROBE[start:end].splitlines())
        expected=[('outside_create_root','/kapit-public-outside'),('outside_create_tmp','/tmp/kapit-public-outside'),
                  ('outside_create_dev','/dev/kapit-public-outside')]
        for answers in itertools.product((False,True),repeat=3):
            visited=[];checks={};by_path={path:answer for (_,path),answer in zip(expected,answers)}
            def opening(path,mode):
                self.assertEqual(mode,'wb');visited.append(path);return by_path[path]
            exec(compile(source,'<fixed-outside-checks>','exec'),
                 {'checks':checks,'denied':lambda action:action(),'open':opening})
            self.assertEqual(visited,[path for _,path in expected])
            self.assertEqual(checks,{name:answer for (name,_),answer in zip(expected,answers)})
            self.assertEqual(all(checks.values()),all(answers))
        self.assertIn("checks[name]=denied(lambda path=path:open(path,'wb'))",source)
        self.assertNotIn('outside_create',native.CHECKS['confinement'])

    def test_failed_checks_extract_only_exact_closed_boolean_shape_and_never_succeed(self):
        p=policy();good=payload(p)
        self.assertIsNone(native._failed_check_frame(json.dumps(good).encode(),p.scenario))
        failed=deepcopy(good);failed['checks']['proc_write']=False;failed['checks']['device_write']=False
        raw=json.dumps(failed).encode()
        frame=native._failed_check_frame(raw,p.scenario)
        self.assertEqual(frame['purpose'],'PUBLIC_ABI3_CHECK_FAILURE')
        self.assertEqual(frame['failed_check_names'],['device_write','proc_write'])
        with self.assertRaises(native.ContainerUnavailable):native._payload(raw,p.scenario)
        with self.assertRaises(native.ContainerUnavailable):native._payload(json.dumps(frame).encode(),p.scenario)
        variants=[failed|{'extra':'PRIVATE_CANARY'},failed|{'landlock_abi':True},failed|{'scenario':'storage'}]
        for checks in ({**failed['checks'],'UNKNOWN_PRIVATE':False}, {**failed['checks'],'proc_write':0},
                       {k:v for k,v in failed['checks'].items() if k!='installed'}):
            variants.append(failed|{'checks':checks})
        for value in variants:
            self.assertIsNone(native._failed_check_frame(json.dumps(value).encode(),p.scenario))
        for invalid in (raw.decode().encode('utf-16'),b'{"schema":1,"schema":1}',b'{}',raw+b'{}'):
            self.assertIsNone(native._failed_check_frame(invalid,p.scenario))

    def test_fixed_failure_wrapper_never_serializes_exception_detail(self):
        output=io.StringIO()
        with patch.object(native, '_PROBE', "stage='POSITIVE_CONTROL'\nraise OSError('PRIVATE_CANARY_EXCEPTION')\n"), \
             patch.object(sys, 'argv', ['public', 'confinement']), patch('sys.stdout', output):
            program=native.probe_program()
            with self.assertRaises(SystemExit) as caught: exec(compile(program,'<public-probe>','exec'), {})
        self.assertEqual(caught.exception.code,2)
        self.assertNotIn('PRIVATE_CANARY',output.getvalue())
        frame=native._failure_frame(output.getvalue().encode(),'confinement')
        self.assertEqual(frame['stage'],'POSITIVE_CONTROL')
        self.assertEqual(frame['failure_class'],'OS_ERROR')

    def test_failure_wrapper_follows_bounded_suppressed_helper_context_without_details(self):
        body=("exec(compile(\"def require():\\n raise RuntimeError('PRIVATE_INNER')\\n"
              "def _scratch():\\n require()\\n"
              "def install_abi3_confinement():\\n try:_scratch()\\n"
              " except Exception:raise RuntimeError('PRIVATE_OUTER') from None\\n\","
              "'<public-confinement>','exec'),helper.__dict__)\n"
              "stage='INSTALL'\nhelper.install_abi3_confinement()\n")
        output=io.StringIO()
        with patch.object(native,'_PROBE',body),patch.object(sys,'argv',['public','confinement']),patch('sys.stdout',output):
            with self.assertRaises(SystemExit):exec(compile(native.probe_program(),'<public-probe>','exec'),{})
        frame=native._failure_frame(output.getvalue().encode(),'confinement')
        self.assertEqual(frame['helper_function'],'_scratch')
        self.assertEqual(frame['helper_line'],4)
        self.assertNotIn('PRIVATE_',output.getvalue())

    def test_failure_frame_is_closed_and_cannot_be_success(self):
        good=failure_payload()
        self.assertEqual(native._failure_frame(json.dumps(good).encode(),'confinement'),good)
        variants=[good|{'message':'PRIVATE_CANARY'}, good|{'stage':'PRIVATE_CANARY'},
            good|{'helper_function':'arbitrary'},good|{'helper_line':True},good|{'helper_line':2001},
            good|{'helper_function':'NONE'},good|{'schema':True},good|{'failure_class':'arbitrary'},
            good|{'private_input_allowed':True},good|{'scenario':'storage'}]
        for value in variants:
            self.assertIsNone(native._failure_frame(json.dumps(value).encode(),'confinement'))
        for raw in (json.dumps(good).encode('utf-16'),b'{"schema":1,"schema":1}',b'X'*4097):
            self.assertIsNone(native._failure_frame(raw,'confinement'))
        with self.assertRaises(native.ContainerUnavailable):native._payload(json.dumps(good).encode(),'confinement')

    def test_defaults_and_scan_never_enable_private_input(self):
        value = native.preparation()
        self.assertFalse(value['private_input_allowed'])
        self.assertEqual(value['native_validation'], 'DISABLED')
        self.assertEqual(value['status'], 'PREPARED_NOT_EXECUTED')
        with self.assertRaises(native.ContainerUnavailable): native.native_scan(b'public', ready=True)

    def test_fixed_image_token_scenarios_and_embedded_frozen_helper(self):
        p = policy()
        self.assertTrue(native.BASE_IMAGE.endswith('9bbb8720ae0a24a6ca8dd678bfdf57818fe70caf54c52a53ec01d8db43405056'))
        for scenario in ('private', '../input', True):
            with self.assertRaises(native.ContainerUnavailable): native.NativeProbePolicy(p.image_id,p.token,scenario)
        for token in ('x'*32, 'c'*31, '../unsafe'):
            with self.assertRaises(native.ContainerUnavailable): native.NativeProbePolicy(p.image_id,token,'confinement')
        source = native.probe_program()
        compile(source, '<public-only>', 'exec')
        self.assertIn(native.HELPER_SHA256, source)
        self.assertIn('helper.install_abi3_confinement(fd)', source)
        self.assertNotIn('sys.stdin', source)
        self.assertNotIn('input(', source)
        self.assertIn("checks['ioctl']=blocked(16", source)
        self.assertIn("('/proc/self/mem','/proc/self/comm')", source)
        self.assertIn("with open(alias,'ab') as output:output.write(b'!');output.flush();output.truncate(6)", source)
        self.assertNotIn('os.truncate(alias,6)', source)
        self.assertIn("os.truncate('/etc/hostname',0)", source)
        self.assertIn('errno.EPERM,errno.EACCES,errno.EROFS', source)
        denied_source=native._PROBE[native._PROBE.index('def denied(action):'):native._PROBE.index('def shm_namespace_checks():')]
        self.assertNotIn('errno.ENOENT', denied_source)
        with patch.object(native, 'HELPER', SimpleNamespace(read_bytes=lambda: b'changed')):
            with self.assertRaises(native.ContainerUnavailable): native.probe_program()

    def test_startup_admits_only_exact_trusted_landlock_and_filter_initialization(self):
        profile = native.startup_profile()
        self.assertEqual(profile['architectures'], ['SCMP_ARCH_X86_64'])
        self.assertEqual(profile['defaultAction'], 'SCMP_ACT_ERRNO')
        general = set(profile['syscalls'][0]['names'])
        self.assertIn('ftruncate',general)
        self.assertNotIn('truncate',general)
        self.assertTrue(general.isdisjoint({'prctl','seccomp','landlock_create_ruleset','landlock_add_rule','landlock_restrict_self','ioctl','socket','clone'}))
        def allowed(name, args):
            for row in profile['syscalls']:
                if name not in row['names']: continue
                if all((args[v['index']] == v['value']) if v['op']=='SCMP_CMP_EQ' else (args[v['index']] != v['value']) for v in row.get('args',[])):
                    return True
            return False
        self.assertTrue(allowed('landlock_create_ruleset',(0,0,1)))
        self.assertTrue(allowed('landlock_create_ruleset',(123,8,0)))
        self.assertFalse(allowed('landlock_create_ruleset',(123,16,0)))
        self.assertFalse(allowed('landlock_create_ruleset',(0,8,0)))
        self.assertTrue(allowed('prctl',(38,1,0,0,0)))
        self.assertTrue(allowed('prctl',(39,0,0,0,0)))
        self.assertFalse(allowed('prctl',(22,2,123,0,0)))
        self.assertTrue(allowed('seccomp',(1,1,123)))
        self.assertFalse(allowed('seccomp',(1,0,123)))
        self.assertFalse(allowed('seccomp',(1,1,0)))

    def test_create_keeps_empty_stdin_and_has_no_mount_pull_or_private_payload(self):
        args = native.create_args(policy(),profile_path='C:/owned/profile.json')
        self.assertIn('--interactive',args)
        self.assertIn('--pull=never',args)
        self.assertNotIn('--pid',args)
        self.assertNotIn('--volume',args)
        self.assertNotIn('--mount',args)
        self.assertEqual(args[-6:], [native.BASE_IMAGE,'-I','-B','-c',native.probe_program(),'confinement'])
        self.assertLess(len(subprocess.list2cmdline(args)),30000)

    def test_exact_new_config_and_old_resource_policy_both_apply(self):
        p=policy(); value=inspection(p)
        self.assertFalse(native.verify_inspection(value,p,container_id='d'*64)['private_input_allowed'])
        variants=[]
        for key,val in (('OpenStdin',False),('StdinOnce',False),('StdinOnce',1),('StdinOnce',None),('Tty',True),('Cmd',['unreviewed']),('Labels',{})):
            d=deepcopy(value);d['Config'][key]=val;variants.append(d)
        for key,val in (('Memory',0),('PidsLimit',10),('ReadonlyRootfs',False),('IpcMode','host'),('Binds',['/private:/data'])):
            d=deepcopy(value);d['HostConfig'][key]=val;variants.append(d)
        d=deepcopy(value);profile=native.startup_profile();profile['syscalls'][1]['args'][0]['value']=False
        d['HostConfig']['SecurityOpt']=['no-new-privileges=true','seccomp='+json.dumps(profile)];variants.append(d)
        for d in variants:
            with self.assertRaises(native.ContainerUnavailable): native.verify_inspection(d,p,container_id='d'*64)

    def test_closed_payload_rejects_unknown_fields_false_checks_float_abi_and_duplicate_json(self):
        p=policy(); good=payload(p)
        self.assertEqual(native._payload(json.dumps(good).encode(),p.scenario),good)
        variants=[good|{'private_input_allowed':True},good|{'extra':'PRIVATE_CANARY'},good|{'landlock_abi':3.0},good|{'landlock_abi':True},
                  good|{'landlock_abi':2},good|{'scenario':'storage'},good|{'schema':True}]
        changed=deepcopy(good);changed['checks']['installed']=False;variants.append(changed)
        changed=deepcopy(good);changed['checks']['installed']=1;variants.append(changed)
        changed=deepcopy(good);changed['checks'].pop('scratch_write');variants.append(changed)
        for value in variants:
            with self.assertRaises(native.ContainerUnavailable): native._payload(json.dumps(value).encode(),p.scenario)
        for raw in (b'{}{}',b'{"schema":1,"schema":1}',b'{"x":NaN}',json.dumps(good).encode('utf-16')):
            with self.assertRaises(native.ContainerUnavailable): native._payload(raw,p.scenario)

    def test_environment_parser_has_exact_unique_bounded_keys_and_no_type_coercion(self):
        self.assertEqual(native._environment(['PATH=/public','HOME=/scratch']),{'PATH':'/public','HOME':'/scratch'})
        for values in (None, ['HOME=/scratch','HOME=/other'], ['NO_SEPARATOR'], ['A=private\nvalue'], [True], ['1BAD=value']):
            with self.assertRaises(native.ContainerUnavailable): native._environment(values)


class InteractivePythonTests(unittest.TestCase):
    def test_empty_stdin_is_pipe_open_during_child_and_never_written(self):
        code,out,err,reason=native._interactive_command([sys.executable,'-I','-B','-c',
            'import os,stat;print(stat.S_ISFIFO(os.fstat(0).st_mode))'],timeout=5)
        self.assertEqual((code,out.strip(),err,reason),(0,b'True',b'','EXIT'))

    def test_output_and_wall_bounds_reap_only_owned_python_child(self):
        for fd in (1,2):
            code,out,err,reason=native._interactive_command([sys.executable,'-I','-B','-c',
                'import os\nwhile True:os.write('+str(fd)+',b"s"*4096)'],timeout=5,maximum=4096)
            self.assertEqual(reason,'OUTPUT_LIMIT')
            self.assertLessEqual(len(out),4096);self.assertLessEqual(len(err),4096)
        code,_,_,reason=native._interactive_command([sys.executable,'-I','-B','-c','import time;time.sleep(5)'],timeout=.05)
        self.assertEqual(reason,'WALL_LIMIT');self.assertNotEqual(code,0)
        code,out,err,reason=native._interactive_command([sys.executable,'-I','-B','-c',
            'import os;os.write(1,b"s"*3000);os.write(2,b"t"*3000)'],timeout=5,maximum=4096)
        self.assertEqual(reason,'OUTPUT_LIMIT')
        self.assertLessEqual(len(out)+len(err),4096)

    def test_keyboard_interrupt_and_reader_start_failure_close_all_three_owned_pipes(self):
        real=subprocess.Popen
        for failure in ('interrupt','thread'):
            handles=[]
            def spawn(*args,**kwargs):
                value=real(*args,**kwargs);handles.append(value);return value
            with patch.object(native.subprocess,'Popen',side_effect=spawn):
                context=(patch.object(native.time,'sleep',side_effect=KeyboardInterrupt) if failure=='interrupt'
                         else patch.object(threading.Thread,'start',side_effect=OSError('private detail')))
                with context:
                    with self.assertRaises(KeyboardInterrupt if failure=='interrupt' else native.ContainerUnavailable):
                        native._interactive_command([sys.executable,'-I','-B','-c','import time;time.sleep(5)'],timeout=5)
            self.assertEqual(len(handles),1)
            self.assertIsInstance(handles[0].returncode,int)
            self.assertTrue(all(getattr(handles[0],x).closed for x in ('stdin','stdout','stderr')))


class ControllerMockTests(unittest.TestCase):
    def exercise(self, *, scenario='confinement', create_output=None, remaining=b'', interrupted=False,
                 fail_cleanup=False, bad_exit=False, running_after=False, existing=False, injected_env=False, boolean_exit=False,
                 failure_raw=None, failure_exit=2):
        p=policy(scenario);calls=[];state={'created':False,'killed':False,'removed':False,'started':False}
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);docker=root/'docker.exe';profile=root/'profile.json'
            docker.write_bytes(b'public synthetic fixture');profile.write_bytes(native.canonical(native.startup_profile()))
            def call(argv,**kwargs):
                args=argv[3:];calls.append(args)
                if args[:2]==['image','inspect']:
                    return 0,json.dumps([{'Id':p.image_id,'RepoDigests':[native.BASE_IMAGE],'Os':'linux','Architecture':'amd64','Config':{}}]).encode(),b'','EXIT'
                if args[:2]==['container','ls']:
                    if not state['created']: return 0,(b'e'*64 if existing else b''),b'','EXIT'
                    if state['removed']:return 0,b'',b'','EXIT'
                    return 0,remaining,b'','EXIT'
                if args[0]=='create':
                    state['created']=True
                    if create_output is not None:return 0,create_output,b'','EXIT'
                    return 0,b'd'*64+b'\n',b'','EXIT'
                if args[:2]==['container','inspect']:
                    self.assertEqual(args[-1],'d'*64)
                    d=inspection(p,running=state['started'] and running_after and not state['killed'])
                    if injected_env:d['Config']['Env'].append('HTTP_PROXY=PRIVATE_FIXTURE_CANARY')
                    if bad_exit and state['started']:d['State']['ExitCode']=137;d['State']['OOMKilled']=True
                    if boolean_exit and state['started']:d['State']['ExitCode']=False
                    if failure_raw is not None and state['started']:d['State']['ExitCode']=failure_exit
                    return 0,json.dumps([d]).encode(),b'','EXIT'
                if args[:2]==['container','kill']:
                    if fail_cleanup:raise OSError('private stop detail')
                    state['killed']=True;return 0,b'',b'','EXIT'
                if args[:2]==['container','rm']:
                    if fail_cleanup:raise OSError('private rm detail')
                    state['removed']=True;return 0,b'',b'','EXIT'
                raise AssertionError('Unknown mocked CLI action')
            def attach(argv,**kwargs):
                calls.append(argv[3:]);state['started']=True
                self.assertTrue(argv[-1]=='d'*64 and '--interactive' in argv)
                if interrupted:raise KeyboardInterrupt()
                if failure_raw is not None:return failure_exit,failure_raw,b'PRIVATE_CANARY_STDERR','EXIT'
                return (159 if scenario=='x32' else 0),json.dumps(payload(p)).encode(),b'',('WALL_LIMIT' if running_after else 'EXIT')
            api=SimpleNamespace(pin=lambda *args,**kwargs:nullcontext())
            with patch('infra.evidence_tools.Windows',return_value=api), \
                 patch.object(native.base,'_bounded_command',side_effect=call),patch.object(native,'_interactive_command',side_effect=attach):
                try:return native.run_public_probe(p,docker_path=docker,profile_path=profile),calls,state
                except BaseException as error:return error,calls,state

    def test_failure_diagnostic_attaches_only_closed_frame_and_actual_exits_after_cleanup(self):
        raw=json.dumps(failure_payload()).encode()
        error,_,state=self.exercise(failure_raw=raw)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertEqual(error.code,'CONTAINER_PROBE_UNAVAILABLE')
        self.assertEqual(error.diagnostic['failure'],failure_payload())
        self.assertEqual((error.diagnostic['cli_exit'],error.diagnostic['worker_exit']),(2,2))
        self.assertEqual(error.diagnostic['cleanup'],'OWNED_CONTAINER_ABSENT_VERIFIED')
        self.assertTrue(state['removed'])
        self.assertNotIn('PRIVATE_CANARY',json.dumps(error.diagnostic))
        error,_,_=self.exercise(failure_raw=raw,fail_cleanup=True)
        self.assertEqual(error.code,'CONTAINER_CLEANUP_UNCONFIRMED')
        self.assertEqual(error.diagnostic['cleanup'],'UNCONFIRMED')
        error,_,_=self.exercise(failure_raw=json.dumps(failure_payload()|{'message':'PRIVATE_CANARY'}).encode())
        self.assertFalse(hasattr(error,'diagnostic'))

    def test_zero_exit_false_checks_remain_failure_with_closed_names_and_verified_cleanup(self):
        value=payload(policy());value['checks']['proc_write']=False
        error,_,state=self.exercise(failure_raw=json.dumps(value).encode(),failure_exit=0)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertEqual(error.code,'CONTAINER_PROBE_UNAVAILABLE')
        self.assertEqual(error.diagnostic['failure']['failed_check_names'],['proc_write'])
        self.assertEqual((error.diagnostic['cli_exit'],error.diagnostic['worker_exit']),(0,0))
        self.assertEqual(error.diagnostic['cleanup'],'OWNED_CONTAINER_ABSENT_VERIFIED')
        self.assertTrue(state['removed'])

    def test_public_lifecycle_has_exact_new_id_cleanup_and_no_native_readiness(self):
        for scenario in sorted(native.SCENARIOS):
            value,calls,state=self.exercise(scenario=scenario)
            self.assertIsInstance(value,dict)
            self.assertEqual(value['cleanup'],'OWNED_CONTAINER_ABSENT_VERIFIED')
            self.assertFalse(value['private_input_allowed']);self.assertEqual(value['native_validation'],'DISABLED')
            self.assertTrue(state['removed'])
            self.assertTrue(all(args[-1]=='d'*64 for args in calls if args[:2] in (['container','inspect'],['container','rm'])))

    def test_x32_requires_sigsys_exit_not_oom_or_generic_kill(self):
        error,_,state=self.exercise(scenario='x32',bad_exit=True)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertTrue(state['removed'])
        error,_,state=self.exercise(boolean_exit=True)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertTrue(state['removed'])

    def test_missing_malformed_create_id_never_adopts_stops_or_removes_by_name(self):
        for output in (b'',b'name-not-id',b'd'*64+b'\n'+b'e'*64,b'\xff'):
            error,calls,_=self.exercise(create_output=output,remaining=b'e'*64)
            self.assertIsInstance(error,native.ContainerUnavailable)
            self.assertEqual(error.code,'CONTAINER_CLEANUP_UNCONFIRMED')
            self.assertFalse(any(args[:2] in (['container','inspect'],['container','kill'],['container','rm']) for args in calls))

    def test_preexisting_name_refuses_without_create_or_adoption(self):
        error,calls,_=self.exercise(existing=True)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertFalse(any(args[0]=='create' for args in calls))

    def test_interruption_or_wall_still_cleans_exact_owned_running_child(self):
        error,_,state=self.exercise(interrupted=True,running_after=True)
        self.assertIsInstance(error,KeyboardInterrupt)
        self.assertTrue(state['killed'] and state['removed'])
        error,_,state=self.exercise(running_after=True)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertTrue(state['killed'] and state['removed'])

    def test_cleanup_uncertainty_dominates_interrupt(self):
        error,_,_=self.exercise(interrupted=True,running_after=True,fail_cleanup=True)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertEqual(error.code,'CONTAINER_CLEANUP_UNCONFIRMED')

    def test_docker_proxy_or_host_environment_injection_refuses_before_start(self):
        error,calls,state=self.exercise(injected_env=True)
        self.assertIsInstance(error,native.ContainerUnavailable)
        self.assertFalse(state['started'])
        self.assertTrue(state['removed'])
        self.assertFalse(any(args[:2]==['container','start'] for args in calls))
