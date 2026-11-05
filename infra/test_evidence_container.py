"""Policy rejection tests. These do not claim Docker/kernel containment."""
import copy
from contextlib import nullcontext
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from infra import evidence_container as candidate


def policy():
    return candidate.ProbePolicy('docker.io/library/python@sha256:' + 'a'*64, 'sha256:'+'b'*64, 'c'*32, 'identity')


def inspection(p):
    return {'Id': 'd'*64, 'Name': '/'+p.name, 'Image': p.image_id, 'Mounts': [],
        'Config': {'Labels': p.labels, 'User': '65532:65532', 'WorkingDir': '/scratch',
            'Entrypoint': ['/usr/local/bin/python3'], 'Cmd': ['-I','-B','-c',candidate.probe_program(),p.scenario],
            'Tty': False, 'OpenStdin': False, 'Healthcheck': {'Test':['NONE']}},
        'HostConfig': {'ReadonlyRootfs': True, 'NetworkMode':'none','IpcMode':'none','PidMode':'',
            'CgroupnsMode':'private','Privileged':False,'Memory':candidate.MEMORY,'MemorySwap':candidate.MEMORY,
            'NanoCpus':1000000000,'PidsLimit':1,'Tmpfs':{'/scratch':candidate.TMPFS},
            'LogConfig':{'Type':'none','Config':{}},'RestartPolicy':{'Name':'no','MaximumRetryCount':0},
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges=true','seccomp='+candidate.canonical(candidate.seccomp_profile()).decode()],
            'Ulimits':[{'Name':'cpu','Soft':2,'Hard':2},{'Name':'core','Soft':0,'Hard':0},
                {'Name':'fsize','Soft':candidate.SCRATCH,'Hard':candidate.SCRATCH},{'Name':'nofile','Soft':32,'Hard':32}]},
        'State':{'Running':False,'Paused':False,'Restarting':False}}


class PolicyTests(unittest.TestCase):
    def assert_refused(self, d, p=None):
        with self.assertRaises(candidate.ContainerUnavailable):
            candidate.verify_inspection(d, p or policy(), container_id='d'*64)

    def test_metadata_never_grants_private_input_or_containment(self):
        p=policy()
        self.assertEqual(candidate.verify_inspection(inspection(p),p,container_id='d'*64),
            {'configuration_verified':True,'containment_proven':False,'private_input_allowed':False})
        with self.assertRaises(candidate.ContainerUnavailable):candidate.native_scan(b'synthetic')

    def test_mutable_remote_nonpython_or_ambiguous_identity_refused(self):
        for image in ('python:latest','python@sha256:'+'a'*64,'evil.example/python@sha256:'+'a'*64,
                      'docker.io/library/python@sha256:'+'A'*64):
            with self.subTest(image=image),self.assertRaises(candidate.ContainerUnavailable):
                candidate.ProbePolicy(image,'sha256:'+'b'*64,'c'*32,'identity')
        for token in ('../escape','c'*31,'C'*32,True):
            with self.subTest(token=token),self.assertRaises(candidate.ContainerUnavailable):
                candidate.ProbePolicy(policy().image,policy().image_id,token,'identity')

    def test_foreign_container_and_wrong_image_or_labels_refused(self):
        for key,value in (('Id','e'*64),('Name','/other'),('Image','sha256:'+'e'*64)):
            d=inspection(policy());d[key]=value;self.assert_refused(d)
        d=inspection(policy());d['Config']['Labels']['org.kapit.run']='e'*32;self.assert_refused(d)

    def test_privilege_network_logging_storage_or_resource_drift_refused(self):
        for key,value in {'Privileged':True,'ReadonlyRootfs':False,'NetworkMode':'host','IpcMode':'host',
            'PidMode':'host','CgroupnsMode':'host','Memory':0,'MemorySwap':-1,'NanoCpus':0,'PidsLimit':0,
            'Tmpfs':{'/scratch':'size=1g'},'CapAdd':['SYS_ADMIN'],'CapDrop':[],
            'LogConfig':{'Type':'json-file','Config':{}},'RestartPolicy':{'Name':'always','MaximumRetryCount':0},
            'Binds':['/host:/data:ro'],'Devices':[{'PathOnHost':'/dev/sda'}],
            'PortBindings':{'80/tcp':[{'HostPort':'80'}]},'GroupAdd':['0'],
            'Mounts':[{'Type':'volume','Target':'/data'}],'Sysctls':{'kernel.shmmax':'1000000'}}.items():
            with self.subTest(key=key):
                d=inspection(policy());d['HostConfig'][key]=value;self.assert_refused(d)

    def test_spoofed_seccomp_or_missing_total_cpu_bound_refused(self):
        for opts in (['no-new-privileges=true','seccomp=unconfined'],
                     ['no-new-privileges=true','seccomp=/some/file.json'],
                     ['no-new-privileges=true','seccomp={}']):
            d=inspection(policy());d['HostConfig']['SecurityOpt']=opts;self.assert_refused(d)
        d=inspection(policy());d['HostConfig']['Ulimits'][0]['Hard']=200;self.assert_refused(d)

    def test_worker_entrypoint_unexpected_mount_and_pause_refused(self):
        for key,value in (('User','0'),('Tty',True),('OpenStdin',True),('Entrypoint',['/bin/sh']),
                          ('Cmd',['-c','unreviewed']),('Volumes',{'/data':{}})):
            d=inspection(policy());d['Config'][key]=value;self.assert_refused(d)
        d=inspection(policy());d['Mounts']=[{'Type':'bind','Destination':'/host','RW':False}];self.assert_refused(d)
        d=inspection(policy());d['State']['Paused']=True;self.assert_refused(d)

    def test_default_pid_namespace_mode_requires_exact_empty_not_shared_or_unknown(self):
        p = policy()
        candidate.verify_inspection(inspection(p), p, container_id='d'*64)
        self.assertNotIn('--pid', candidate.create_args(p, profile_path='C:/fixed/profile.json'))
        for mode in ('host', 'container:'+'e'*64, 'private', None, False):
            with self.subTest(mode=mode):
                document = inspection(p)
                document['HostConfig']['PidMode'] = mode
                self.assert_refused(document)

    def test_official_digest_still_requires_platform_and_no_volumes(self):
        p=policy();d={'Id':p.image_id,'RepoDigests':[p.image],'Os':'linux','Architecture':'amd64','Config':{}}
        candidate.verify_image(d,p)
        for key,value in (('Os','windows'),('Architecture','arm64'),('RepoDigests',[])):
            changed=copy.deepcopy(d);changed[key]=value
            with self.assertRaises(candidate.ContainerUnavailable):candidate.verify_image(changed,p)
        for key in ('Volumes','OnBuild','Healthcheck'):
            changed=copy.deepcopy(d);changed['Config'][key]={'unknown':True}
            with self.assertRaises(candidate.ContainerUnavailable):candidate.verify_image(changed,p)

    def test_official_python_alias_is_exact_same_digest_not_registry_or_repository_suffix(self):
        p = policy()
        digest = p.image.split('@', 1)[1]
        document = {'Id':p.image_id,'RepoDigests':['python@'+digest],'Os':'linux','Architecture':'amd64','Config':{}}
        candidate.verify_image(document, p)
        for digests in (['evil.example/python@'+digest], ['library/python@'+digest], ['docker.io/other/python@'+digest],
                        ['python@sha256:'+'e'*64], ['python@'+digest,'evil.example/python@'+digest],
                        ['python@'+digest,'python@'+digest]):
            with self.subTest(digests=digests), self.assertRaises(candidate.ContainerUnavailable):
                candidate.verify_image(document | {'RepoDigests':digests}, p)

    def test_seccomp_excludes_socket_process_mount_ipc_and_ioctl(self):
        profile=candidate.seccomp_profile()
        allowed=set(profile['syscalls'][0]['names'])
        self.assertTrue({'socket','connect','clone','clone3','fork','vfork','ioctl','mount','unshare','setns',
            'ptrace','mq_open','shmget','memfd_create','bpf','userfaultfd','io_uring_setup'}.isdisjoint(allowed))
        self.assertEqual(profile['defaultAction'],'SCMP_ACT_ERRNO')

    def test_landlock_query_accepts_supported_old_or_unavailable_kernel_without_containment_claim(self):
        for abi in (1, 4, 5, 16):
            value = {'schema':1,'scenario':'landlock_abi','abi':abi,'required':5,
                     'available':abi >= 5,'errno':0,'private_input_allowed':False}
            self.assertEqual(candidate.landlock_observation(value), value)
        for error in (1, 38, 95):
            value = {'schema':1,'scenario':'landlock_abi','abi':0,'required':5,
                     'available':False,'errno':error,'private_input_allowed':False}
            self.assertEqual(candidate.landlock_observation(value), value)
        with self.assertRaises(candidate.ContainerUnavailable): candidate.native_scan(b'public synthetic')

    def test_landlock_unknown_shape_errno_abi_and_inconsistent_availability_refuse(self):
        value = {'schema':1,'scenario':'landlock_abi','abi':5,'required':5,
                 'available':True,'errno':0,'private_input_allowed':False}
        changed = [value | {'abi':-1}, value | {'abi':17}, value | {'abi':True}, value | {'errno':2},
                   value | {'errno':True}, value | {'required':4}, value | {'available':False},
                   value | {'private_input_allowed':True}, value | {'extra':'unknown'},
                   value | {'abi':0}, value | {'errno':38}, value | {'schema':True}]
        for field in value:
            missing = dict(value); missing.pop(field); changed.append(missing)
        for payload in changed:
            with self.subTest(keys=sorted(payload)), self.assertRaises(candidate.ContainerUnavailable):
                candidate.landlock_observation(payload)

    def test_startup_filter_only_allows_landlock_query_not_rule_or_restriction_syscalls(self):
        profile = candidate.seccomp_profile()
        allowed = {name for row in profile['syscalls'] for name in row['names']}
        self.assertTrue({'landlock_add_rule','landlock_restrict_self'}.isdisjoint(allowed))
        self.assertNotIn('landlock_create_ruleset', profile['syscalls'][0]['names'])
        query = profile['syscalls'][1]
        self.assertEqual(query['names'], ['landlock_create_ruleset'])
        def permits(args):
            return all(rule['op'] == 'SCMP_CMP_EQ' and args[rule['index']] == rule['value'] for rule in query['args'])
        self.assertTrue(permits((0, 0, 1)))
        for attrs, size, flags in ((1, 0, 1), (0, 8, 1), (0, 0, 0), (0, 0, 2), (1, 8, 0)):
            self.assertFalse(permits((attrs, size, flags)))
        p = candidate.ProbePolicy(policy().image, policy().image_id, policy().token, 'landlock_abi')
        args = candidate.create_args(p, profile_path='C:/fixed/public/profile-v2.json')
        self.assertEqual(args[-1], 'landlock_abi')
        self.assertIn('libc.syscall(444,None,0,1)', candidate.probe_program())

    def test_query_filter_tampering_cannot_pass_actual_policy_verification(self):
        for index, value in ((0, 1), (1, 8), (2, 0), (2, 2)):
            with self.subTest(index=index, value=value):
                profile = candidate.seccomp_profile()
                profile['syscalls'][1]['args'][index]['value'] = value
                document = inspection(policy())
                document['HostConfig']['SecurityOpt'] = ['no-new-privileges=true', 'seccomp='+candidate.canonical(profile).decode()]
                self.assert_refused(document)
        for index in range(3):
            profile = candidate.seccomp_profile()
            profile['syscalls'][1]['args'].pop(index)
            document = inspection(policy())
            document['HostConfig']['SecurityOpt'] = ['no-new-privileges=true', 'seccomp='+candidate.canonical(profile).decode()]
            self.assert_refused(document)

    def test_create_has_no_pull_no_host_mount_and_only_fixed_synthetic_command(self):
        args=candidate.create_args(policy(),profile_path='C:/owned/profile.json')
        self.assertIn('--pull=never',args)
        self.assertEqual(args[-6:], [policy().image,'-I','-B','-c',candidate.probe_program(),'identity'])
        self.assertNotIn('--privileged',args)
        self.assertNotIn('--volume',args)
        compile(candidate.probe_program(),'<synthetic-probe>','exec')

    def test_actual_parent_capture_bounds_both_output_streams(self):
        for fd in (1, 2):
            code, out, err, reason = candidate._bounded_command([sys.executable, '-I', '-B', '-c',
                'import os\nwhile True:os.write('+str(fd)+',b"s"*4096)'], timeout=5, maximum=4096)
            self.assertEqual(reason, 'OUTPUT_LIMIT')
            self.assertLessEqual(len(out), 4096)
            self.assertLessEqual(len(err), 4096)
            self.assertIsInstance(code, int)

    def test_actual_parent_wall_timeout_reaps_exact_child(self):
        code, out, err, reason = candidate._bounded_command([sys.executable, '-I', '-B', '-c',
            'import time;time.sleep(5)'], timeout=.05, maximum=4096)
        self.assertEqual(reason, 'WALL_LIMIT')
        self.assertNotEqual(code, 0)

    def owned_cli(self, *, injection=None, seconds=30):
        """Retain the real direct Python child, including real teardown handles."""
        real_popen = subprocess.Popen
        handles = []
        def spawn(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            handles.append((process, process.kill, process.wait))
            if injection is not None:
                injection(process)
            return process
        try:
            with patch.object(candidate.subprocess, 'Popen', side_effect=spawn):
                yield handles, [sys.executable, '-I', '-B', '-c', 'import time;time.sleep('+str(seconds)+')']
        finally:
            for process, kill, wait in handles:
                # Test-owned recovery only, retained handle, never PID lookup.
                if process.returncode is None:
                    kill()
                wait(timeout=5)

    def test_actual_keyboard_interrupt_still_kills_reaps_and_joins_owned_cli(self):
        import contextlib
        with contextlib.contextmanager(self.owned_cli)() as (handles, args):
            with patch.object(candidate.time, 'sleep', side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt): candidate._bounded_command(args, timeout=5)
            self.assertEqual(len(handles), 1)
            self.assertIsInstance(handles[0][0].returncode, int)
            self.assertTrue(handles[0][0].stdout.closed)
            self.assertTrue(handles[0][0].stderr.closed)

    def test_actual_reader_start_failure_still_stops_owned_cli(self):
        import contextlib
        with contextlib.contextmanager(self.owned_cli)() as (handles, args):
            with patch.object(threading.Thread, 'start', side_effect=OSError('private startup canary')):
                with self.assertRaises(candidate.ContainerUnavailable) as failure:
                    candidate._bounded_command(args, timeout=5)
            self.assertEqual(failure.exception.code, 'CONTAINER_PROBE_UNAVAILABLE')
            self.assertIsInstance(handles[0][0].returncode, int)
            self.assertTrue(handles[0][0].stdout.closed)

    def test_actual_wait_failure_maps_fixed_error_after_retained_handle_reap(self):
        import contextlib
        def inject(process):
            original = process.wait
            first = True
            def wait(*args, **kwargs):
                nonlocal first
                if first:
                    first = False
                    raise OSError('private wait canary')
                return original(*args, **kwargs)
            process.wait = wait
        with contextlib.contextmanager(self.owned_cli)(injection=inject, seconds=.01) as (handles, args):
            with self.assertRaises(candidate.ContainerUnavailable) as failure:
                candidate._bounded_command(args, timeout=5)
            self.assertEqual(failure.exception.code, 'CONTAINER_PROBE_UNAVAILABLE')
            self.assertIsInstance(handles[0][0].returncode, int)
            self.assertNotIn('private', str(failure.exception))

    def test_actual_cleanup_uncertainty_dominates_interrupt_without_losing_owned_handle(self):
        import contextlib
        def inject(process):
            def refused(*args, **kwargs): raise OSError('private cleanup canary')
            process.kill = refused
            process.wait = refused
        real_join = threading.Thread.join
        def bounded_test_join(thread, timeout=None):
            # Do not wait ten seconds for a deliberately unkillable seam; the
            # finally below still owns the actual real kill/wait capabilities.
            return real_join(thread, timeout=.05)
        with contextlib.contextmanager(self.owned_cli)(injection=inject) as (handles, args):
            with patch.object(candidate.time, 'sleep', side_effect=KeyboardInterrupt), \
                 patch.object(threading.Thread, 'join', new=bounded_test_join):
                with self.assertRaises(candidate.ContainerUnavailable) as failure:
                    candidate._bounded_command(args, timeout=5)
            self.assertEqual(failure.exception.code, 'CONTAINER_CLEANUP_UNCONFIRMED')
            self.assertEqual(len(handles), 1)
        self.assertIsInstance(handles[0][0].returncode, int)

    def test_actual_cleanup_wait_interrupt_is_fixed_uncertainty_not_raw_exception(self):
        import contextlib
        def inject(process):
            calls = 0
            def wait(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 1: raise OSError('private wait canary')
                raise KeyboardInterrupt()
            process.wait = wait
        with contextlib.contextmanager(self.owned_cli)(injection=inject, seconds=.01) as (handles, args):
            with self.assertRaises(candidate.ContainerUnavailable) as failure:
                candidate._bounded_command(args, timeout=5)
            self.assertEqual(failure.exception.code, 'CONTAINER_CLEANUP_UNCONFIRMED')
        self.assertIsInstance(handles[0][0].returncode, int)

    def ambiguous_create(self, *, remaining=None, creation_output=b'', initial=None, interrupted=False):
        p = policy()
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker, profile = root / 'docker.exe', root / 'profile.json'
            docker.write_bytes(b'public synthetic executable fixture')
            profile.write_bytes(candidate.canonical(candidate.seccomp_profile()))
            def call(argv, **kwargs):
                args = argv[3:]
                calls.append(args)
                if args[:2] == ['image', 'inspect']:
                    document = {'Id':p.image_id,'RepoDigests':[p.image],'Os':'linux','Architecture':'amd64','Config':{}}
                    return 0, json.dumps([document]).encode(), b'', 'EXIT'
                if args[:2] == ['container', 'ls']:
                    if len(calls) == 2:
                        return 0, b'' if initial is None else initial, b'', 'EXIT'
                    if isinstance(remaining, BaseException): raise remaining
                    return 0, b'' if remaining is None else remaining, b'', 'EXIT'
                if args[0] == 'create':
                    if interrupted: raise KeyboardInterrupt()
                    return (0 if creation_output else 1), creation_output, b'private CLI error canary', 'EXIT'
                raise AssertionError('No name adoption/inspect/stop/remove allowed')
            api = SimpleNamespace(pin=lambda *args, **kwargs: nullcontext())
            with patch('infra.evidence_tools.Windows', return_value=api), \
                 patch.object(candidate, '_bounded_command', side_effect=call):
                try:
                    candidate.run_synthetic_probe(p, docker_path=docker, profile_path=profile)
                except BaseException as error:
                    return error, calls
        self.fail('Ambiguous creation can never produce a successful probe')

    def test_ambiguous_create_existing_or_unknown_name_is_preserved_without_adoption(self):
        for remaining in (b'd'*64+b'\n', OSError('private inspect canary'), KeyboardInterrupt()):
            with self.subTest(remaining=type(remaining).__name__):
                failure, calls = self.ambiguous_create(remaining=remaining)
                self.assertIsInstance(failure, candidate.ContainerUnavailable)
                self.assertEqual(failure.code, 'CONTAINER_CLEANUP_UNCONFIRMED')
                self.assertFalse(any(args[:2] in (['container','inspect'], ['container','kill'], ['container','rm']) for args in calls))
                self.assertEqual(calls[-1], ['container','ls','--all','--no-trunc','--filter',
                    'name=^/'+policy().name+'$','--format','{{.ID}}'])

    def test_ambiguous_create_confirmed_absence_preserves_fixed_primary_failure(self):
        failure, calls = self.ambiguous_create()
        self.assertEqual(failure.code, 'CONTAINER_PROBE_UNAVAILABLE')
        self.assertEqual(len(calls), 4)

    def test_malformed_creation_id_is_never_a_cleanup_capability(self):
        for malformed in (b'name-not-ID', b'd'*63, b'd'*64+b'\n' + b'e'*64, b'\xff'):
            with self.subTest(length=len(malformed)):
                failure, calls = self.ambiguous_create(creation_output=malformed, remaining=b'd'*64)
                self.assertEqual(failure.code, 'CONTAINER_CLEANUP_UNCONFIRMED')
                self.assertFalse(any(args[:2] == ['container','inspect'] for args in calls))

    def test_create_interrupt_runs_absence_check_and_uncertainty_dominates(self):
        failure, _ = self.ambiguous_create(interrupted=True)
        self.assertIsInstance(failure, KeyboardInterrupt)
        failure, _ = self.ambiguous_create(interrupted=True, remaining=b'd'*64)
        self.assertIsInstance(failure, candidate.ContainerUnavailable)
        self.assertEqual(failure.code, 'CONTAINER_CLEANUP_UNCONFIRMED')

    def test_preexisting_name_is_never_created_inspected_or_stopped(self):
        failure, calls = self.ambiguous_create(initial=b'd'*64)
        self.assertEqual(failure.code, 'CONTAINER_IDENTITY_CHANGED')
        self.assertEqual(len(calls), 2)


if __name__=='__main__':unittest.main()
