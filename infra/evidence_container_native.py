"""Public-only ABI3 probe controller. Private native execution remains CLOSED.

No imports launch Docker/read keys. The root alone explicitly executes probes.
This partial stage is NOT a signature/image scanner or native trust issuer.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
import time

from infra import evidence_container as base

ROOT = Path(__file__).resolve().parents[1]
BASE_IMAGE = 'docker.io/library/python@sha256:9bbb8720ae0a24a6ca8dd678bfdf57818fe70caf54c52a53ec01d8db43405056'
BASE_SHA256 = '921f26e53ea67ebb066d534f682cef7fed215c708fed9426b14231e1b1043628'
HELPER = ROOT / 'backend/apps/operations/evidence_linux.py'
HELPER_SHA256 = 'de930340e056f64157e4ab82e6a528a2ff362477278a5e711d815606e96de0bb'
OWNER = 'kapit-public-abi3-probe-v1'
POLICY_ID = 'linux-amd64-landlock3-seccomp-v1'
SCENARIOS = frozenset({'confinement', 'storage', 'x32', 'preopened_fd', 'shm_namespace'})
FIXED_ENV = {'HOME': '/scratch', 'TMPDIR': '/scratch', 'TMP': '/scratch', 'TEMP': '/scratch', 'PYTHONDONTWRITEBYTECODE': '1'}
ContainerUnavailable = base.ContainerUnavailable
require = base.require
canonical = base.canonical


def preparation():
    return {'schema': 1, 'status': 'PREPARED_NOT_EXECUTED', 'scope': 'PUBLIC_ABI3_ONLY',
            'native_validation': 'DISABLED', 'private_input_allowed': False,
            'policy': POLICY_ID, 'scenarios': sorted(SCENARIOS)}


def startup_profile():
    """Trusted initialization only; final helper installs the stricter filter."""
    calls = sorted(set(base.seccomp_profile()['syscalls'][0]['names']) -
                   {'prctl', 'seccomp', 'landlock_create_ruleset', 'landlock_add_rule', 'landlock_restrict_self'})
    def arg(index, value, op='SCMP_CMP_EQ'):
        return {'index': index, 'value': value, 'op': op}
    return {'defaultAction': 'SCMP_ACT_ERRNO', 'defaultErrnoRet': 1,
            'architectures': ['SCMP_ARCH_X86_64'], 'syscalls': [
                {'names': calls, 'action': 'SCMP_ACT_ALLOW'},
                {'names': ['landlock_create_ruleset'], 'action': 'SCMP_ACT_ALLOW',
                 'args': [arg(0, 0), arg(1, 0), arg(2, 1)]},
                {'names': ['landlock_create_ruleset'], 'action': 'SCMP_ACT_ALLOW',
                 'args': [arg(0, 0, 'SCMP_CMP_NE'), arg(1, 8), arg(2, 0)]},
                {'names': ['landlock_add_rule'], 'action': 'SCMP_ACT_ALLOW', 'args': [arg(1, 1), arg(3, 0)]},
                {'names': ['landlock_restrict_self'], 'action': 'SCMP_ACT_ALLOW', 'args': [arg(1, 0)]},
                {'names': ['prctl'], 'action': 'SCMP_ACT_ALLOW',
                 'args': [arg(0, 38), arg(1, 1), arg(2, 0), arg(3, 0), arg(4, 0)]},
                {'names': ['prctl'], 'action': 'SCMP_ACT_ALLOW',
                 'args': [arg(0, 39), arg(1, 0), arg(2, 0), arg(3, 0), arg(4, 0)]},
                {'names': ['seccomp'], 'action': 'SCMP_ACT_ALLOW',
                 'args': [arg(0, 1), arg(1, 1), arg(2, 0, 'SCMP_CMP_NE')]},
            ]}


def profile_digest():
    return hashlib.sha256(canonical(startup_profile())).hexdigest()


@dataclass(frozen=True)
class NativeProbePolicy:
    image_id: str
    token: str
    scenario: str

    def __post_init__(self):
        # The image repository digest is fixed, never supplied by the caller.
        base.ProbePolicy(BASE_IMAGE, self.image_id, self.token, 'identity')
        require(type(self.scenario) is str and self.scenario in SCENARIOS)

    @property
    def legacy(self):
        return base.ProbePolicy(BASE_IMAGE, self.image_id, self.token, 'identity')

    @property
    def name(self):
        return 'kapit-public-abi3-' + self.token

    @property
    def labels(self):
        return {'org.kapit.owner': OWNER, 'org.kapit.run': self.token,
                'org.kapit.policy': profile_digest(), 'org.kapit.helper': HELPER_SHA256,
                'org.kapit.purpose': 'public-abi3-only', 'org.kapit.scenario': self.scenario}


CHECKS = {
    'confinement': frozenset({'installed', 'scratch_write', 'scratch_alias', 'outside_create_root', 'outside_create_tmp',
        'outside_create_dev', 'dev_directory', 'shm_absent', 'shm_create_denied', 'outside_truncate',
        'proc_write', 'device_write', 'ioctl', 'inet', 'inet6', 'unix', 'fork', 'exec', 'clone', 'clone3',
        'kill', 'sysv_ipc', 'mq_ipc', 'memfd', 'io_uring', 'mount', 'namespace', 'handle_open',
        'process_vm', 'prctl', 'seccomp', 'landlock', 'prlimit_mutation'}),
    'storage': frozenset({'installed', 'byte_quota', 'inode_quota'}),
    'x32': frozenset({'installed', 'x32_attempted'}),
    'preopened_fd': frozenset({'unexpected_fd_refused'}),
    'shm_namespace': frozenset({'installed', 'scratch_write', 'dev_directory', 'shm_absent', 'shm_create_denied'}),
}
FAILURE_STAGES = frozenset({'HELPER_LOAD', 'INITIALIZATION', 'ABI_QUERY', 'SCRATCH_OPEN',
    'INSTALL', 'PREOPENED_GUARD', 'POSITIVE_CONTROL', 'DENIAL_CHECKS', 'STORAGE', 'X32', 'EMIT', 'SHM_NAMESPACE'})
FAILURE_CLASSES = frozenset({'OS_ERROR', 'CONFINEMENT_UNAVAILABLE', 'SYSTEM_EXIT', 'UNEXPECTED'})
HELPER_FUNCTIONS = frozenset({'NONE', 'require', '_supported', '_read', '_status', '_process',
    '_mounts', '_scratch', '_descriptors', 'install_abi3_confinement', 'abi', 'no_new_privileges',
    'create_abi3', 'rule', 'restrict', 'seccomp', 'scratch_filesystem', 'filter_program'})


_PROBE = r'''
import ctypes,errno,fcntl,json,os,resource,socket,stat,sys
stage='INITIALIZATION'
scenario=sys.argv[1]
libc=ctypes.CDLL(None,use_errno=True)
libc.syscall.restype=ctypes.c_long
stage='ABI_QUERY'
abi=int(libc.syscall(ctypes.c_long(444),ctypes.c_void_p(),ctypes.c_size_t(0),ctypes.c_uint(1)))
if abi<3:raise SystemExit(2)
stage='SCRATCH_OPEN'
fd=os.open('/scratch',os.O_PATH|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
checks={}
def emit():
 print(json.dumps({'schema':1,'purpose':'PUBLIC_ABI3_CONFINEMENT','scenario':scenario,
  'policy':'linux-amd64-landlock3-seccomp-v1','landlock_abi':abi,'checks':checks,
  'native_validation':'DISABLED','private_input_allowed':False},sort_keys=True,separators=(',',':')),flush=True)
def denied(action):
 try:
  value=action()
  if hasattr(value,'close'):value.close()
  return False
 except OSError as error:return error.errno in (errno.EPERM,errno.EACCES,errno.EROFS)
def blocked(number,*args):
 ctypes.set_errno(0)
 result=libc.syscall(ctypes.c_long(number),*args)
 if result==-1:return ctypes.get_errno() in (errno.EPERM,errno.EACCES,errno.EROFS)
 if number==319 and result>=0:os.close(result)
 if number==57 and result==0:os._exit(3)
 return False
def shm_namespace_checks():
 result={}
 dev=os.lstat('/dev')
 result['dev_directory']=stat.S_ISDIR(dev.st_mode) and not stat.S_ISLNK(dev.st_mode)
 if not result['dev_directory']:raise SystemExit(2)
 try:os.lstat('/dev/shm')
 except OSError as error:
  if error.errno!=errno.ENOENT:raise
  result['shm_absent']=True
 else:result['shm_absent']=False
 result['shm_create_denied']=denied(lambda:os.mkdir('/dev/shm'))
 return result
if scenario=='preopened_fd':
 stage='PREOPENED_GUARD'
 extra=os.open('/dev/null',os.O_WRONLY)
 try:
  try:helper.install_abi3_confinement(fd)
  except helper.ConfinementUnavailable:checks['unexpected_fd_refused']=True
  else:checks['unexpected_fd_refused']=False
 finally:os.close(extra)
 emit();raise SystemExit(0)
stage='INSTALL'
helper.install_abi3_confinement(fd)
checks['installed']=True
if scenario=='confinement':
 stage='POSITIVE_CONTROL'
 with open('/scratch/positive','wb') as output:output.write(b'public');output.flush();os.fsync(output.fileno())
 with open('/scratch/positive','rb') as source:checks['scratch_write']=source.read()==b'public'
 alias='/proc/self/fd/'+str(fd)+'/positive'
 with open(alias,'ab') as output:output.write(b'!');output.flush();output.truncate(6)
 checks['scratch_alias']=os.stat('/scratch/positive').st_ino==os.stat(alias).st_ino and os.stat(alias).st_size==6
 os.unlink('/scratch/positive')
 stage='DENIAL_CHECKS'
 for name,path in (('outside_create_root','/kapit-public-outside'),('outside_create_tmp','/tmp/kapit-public-outside'),
  ('outside_create_dev','/dev/kapit-public-outside')):
  checks[name]=denied(lambda path=path:open(path,'wb'))
 stage='SHM_NAMESPACE'
 checks.update(shm_namespace_checks())
 stage='DENIAL_CHECKS'
 checks['outside_truncate']=denied(lambda:os.truncate('/etc/hostname',0))
 checks['proc_write']=all(denied(lambda path=path:open(path,'wb')) for path in ('/proc/self/mem','/proc/self/comm'))
 checks['device_write']=all(denied(lambda path=path:open(path,'wb')) for path in ('/dev/null','/proc/self/root/dev/null'))
 result=ctypes.c_uint32(0)
 checks['ioctl']=blocked(16,ctypes.c_int(1),ctypes.c_ulong(0x541B),ctypes.byref(result))
 for name,family in (('inet',socket.AF_INET),('inet6',socket.AF_INET6),('unix',socket.AF_UNIX)):
  checks[name]=denied(lambda family=family:socket.socket(family))
 checks['fork']=blocked(57)
 checks['exec']=blocked(59,ctypes.c_void_p(),ctypes.c_void_p(),ctypes.c_void_p())
 checks['clone']=blocked(56,ctypes.c_ulong(0),ctypes.c_void_p(),ctypes.c_void_p(),ctypes.c_void_p(),ctypes.c_void_p())
 checks['clone3']=blocked(435,ctypes.c_void_p(),ctypes.c_size_t(0))
 checks['kill']=blocked(62,ctypes.c_int(1),ctypes.c_int(0))
 checks['sysv_ipc']=blocked(29,ctypes.c_int(0),ctypes.c_size_t(4096),ctypes.c_int(0o1600))
 checks['mq_ipc']=blocked(240,ctypes.c_void_p(),ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p())
 checks['memfd']=blocked(319,ctypes.c_char_p(b'public'),ctypes.c_uint(0))
 checks['io_uring']=blocked(425,ctypes.c_uint(1),ctypes.c_void_p())
 checks['mount']=blocked(165,ctypes.c_void_p(),ctypes.c_void_p(),ctypes.c_void_p(),ctypes.c_ulong(0),ctypes.c_void_p())
 checks['namespace']=blocked(272,ctypes.c_int(0x10000000))
 checks['handle_open']=blocked(304,ctypes.c_int(-1),ctypes.c_void_p(),ctypes.c_int(0))
 checks['process_vm']=blocked(311,ctypes.c_int(1),ctypes.c_void_p(),ctypes.c_ulong(0),ctypes.c_void_p(),ctypes.c_ulong(0),ctypes.c_ulong(0))
 checks['prctl']=blocked(157,ctypes.c_int(39),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0),ctypes.c_ulong(0))
 checks['seccomp']=blocked(317,ctypes.c_uint(1),ctypes.c_uint(1),ctypes.c_void_p())
 checks['landlock']=blocked(444,ctypes.c_void_p(),ctypes.c_size_t(0),ctypes.c_uint(1))
 limits=(ctypes.c_uint64*2)(1,2)
 checks['prlimit_mutation']=blocked(302,ctypes.c_int(0),ctypes.c_int(0),ctypes.byref(limits),ctypes.c_void_p())
elif scenario=='shm_namespace':
 stage='POSITIVE_CONTROL'
 with open('/scratch/positive','wb') as output:output.write(b'public');output.flush();os.fsync(output.fileno())
 with open('/scratch/positive','rb') as source:checks['scratch_write']=source.read()==b'public'
 os.unlink('/scratch/positive')
 stage='SHM_NAMESPACE'
 checks.update(shm_namespace_checks())
elif scenario=='storage':
 stage='STORAGE'
 total=0;full=False
 try:
  for part in range(5):
   with open('/scratch/fill'+str(part),'wb',buffering=0) as output:
    for _ in range(256):total+=output.write(b'0'*65536)
 except OSError as error:full=error.errno==errno.ENOSPC
 checks['byte_quota']=full and 0<total<=67108864
 for part in range(5):
  try:os.unlink('/scratch/fill'+str(part))
  except FileNotFoundError:pass
 count=0;full=False
 try:
  for part in range(130):
   with open('/scratch/inode'+str(part),'wb'):pass
   count+=1
 except OSError as error:full=error.errno==errno.ENOSPC
 checks['inode_quota']=full and 0<count<128
elif scenario=='x32':
 stage='X32'
 checks['x32_attempted']=True;emit()
 libc.syscall(ctypes.c_long(0x40000000|39))
 raise SystemExit(3)
else:raise SystemExit(2)
stage='EMIT'
emit()
'''


def probe_program():
    raw = HELPER.read_bytes()
    require(len(raw) <= 262144 and hashlib.sha256(raw).hexdigest() == HELPER_SHA256)
    encoded = base64.b64encode(raw).decode('ascii')
    body = ("import base64,hashlib,types\nraw=base64.b64decode('" + encoded + "')\n"
            "assert hashlib.sha256(raw).hexdigest()=='" + HELPER_SHA256 + "'\n"
            "helper=types.ModuleType('public_confinement')\n"
            "exec(compile(raw,'<public-confinement>','exec'),helper.__dict__)\n" + _PROBE)
    # Fixed public-only exception frame: never serialize an exception message,
    # filename, argv, locals, source or traceback. A nonzero exit remains failure.
    return ("import json,sys\nstage='HELPER_LOAD'\ntry:\n" +
            ''.join(' '+line+'\n' for line in body.splitlines()) +
            "except BaseException as error:\n"
            " if isinstance(error,SystemExit) and error.code==0:raise\n"
            " failure_class=('OS_ERROR' if isinstance(error,OSError) else 'SYSTEM_EXIT' if isinstance(error,SystemExit) else 'CONFINEMENT_UNAVAILABLE' if type(error).__name__=='ConfinementUnavailable' else 'UNEXPECTED')\n"
            " helper_function='NONE';helper_line=0;context=error\n"
            " for _ in range(4):\n"
            "  if context is None:break\n"
            "  trace=context.__traceback__\n"
            "  for _ in range(32):\n"
            "   if trace is None:break\n"
            "   name=trace.tb_frame.f_code.co_name\n"
            "   if trace.tb_frame.f_code.co_filename=='<public-confinement>' and name in " + repr(sorted(HELPER_FUNCTIONS - {'NONE', 'require'})) + ":\n"
            "    if name!='install_abi3_confinement' or helper_function=='NONE':helper_function=name;helper_line=trace.tb_lineno\n"
            "   trace=trace.tb_next\n"
            "  context=context.__context__\n"
            " print(json.dumps({'schema':1,'purpose':'PUBLIC_ABI3_FAILURE','scenario':sys.argv[1],'stage':stage,'failure_class':failure_class,'helper_function':helper_function,'helper_line':helper_line,'native_validation':'DISABLED','private_input_allowed':False},sort_keys=True,separators=(',',':')),flush=True)\n"
            " raise SystemExit(2) from None\n")


def create_args(policy, *, profile_path):
    require(type(policy) is NativeProbePolicy and type(profile_path) is str and bool(profile_path) and '\x00' not in profile_path)
    args = ['create', '--interactive', '--pull=never', '--name', policy.name, '--platform', 'linux/amd64',
        '--read-only', '--network', 'none', '--ipc', 'none', '--cgroupns', 'private', '--user', '65532:65532',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--security-opt', 'seccomp=' + profile_path,
        '--log-driver', 'none', '--no-healthcheck', '--restart', 'no', '--memory', str(base.MEMORY),
        '--memory-swap', str(base.MEMORY), '--cpus', '1', '--pids-limit', '1', '--ulimit', 'cpu=2:2',
        '--ulimit', 'core=0:0', '--ulimit', 'fsize=67108864:67108864', '--ulimit', 'nofile=32:32',
        '--tmpfs', '/scratch:' + base.TMPFS, '--workdir', '/scratch', '--env', 'HOME=/scratch',
        '--env', 'TMPDIR=/scratch', '--env', 'TMP=/scratch', '--env', 'TEMP=/scratch',
        '--env', 'PYTHONDONTWRITEBYTECODE=1', '--entrypoint', '/usr/local/bin/python3']
    for key, value in sorted(policy.labels.items()):
        args.extend(['--label', key + '=' + value])
    args.extend([BASE_IMAGE, '-I', '-B', '-c', probe_program(), policy.scenario])
    require(len(subprocess.list2cmdline(args)) < 30000)
    return args


def verify_inspection(document, policy, *, container_id, running=False):
    """Validate changed fields exactly BEFORE reusing the old resource checker."""
    require(type(document) is dict and document.get('Name') == '/' + policy.name and document.get('Id') == container_id,
            'CONTAINER_IDENTITY_CHANGED')
    config, host = document.get('Config'), document.get('HostConfig')
    require(type(config) is dict and type(host) is dict, 'CONTAINER_CONFIGURATION_CHANGED')
    require(config.get('Labels') == policy.labels and config.get('OpenStdin') is True
            and config.get('StdinOnce') is True and config.get('Tty') is False
            and config.get('Cmd') == ['-I', '-B', '-c', probe_program(), policy.scenario], 'CONTAINER_CONFIGURATION_CHANGED')
    opts = host.get('SecurityOpt')
    require(type(opts) is list and len(opts) == 2 and 'no-new-privileges=true' in opts, 'CONTAINER_CONFIGURATION_CHANGED')
    values = [x[8:] for x in opts if type(x) is str and x.startswith('seccomp=')]
    require(len(values) == 1, 'CONTAINER_CONFIGURATION_CHANGED')
    try:
        require(canonical(json.loads(values[0])) == canonical(startup_profile()), 'CONTAINER_CONFIGURATION_CHANGED')
    except (ValueError, TypeError):
        raise ContainerUnavailable('CONTAINER_CONFIGURATION_CHANGED') from None
    # Only already-exact-checked differences are normalized; all other actual
    # fields undergo the reviewed old strict image/resource/mount/owner checks.
    old = deepcopy(document)
    old['Name'] = '/' + policy.legacy.name
    old['Config']['Labels'] = policy.legacy.labels
    old['Config']['OpenStdin'] = False
    old['Config']['Cmd'] = ['-I', '-B', '-c', base.probe_program(), 'identity']
    old['HostConfig']['SecurityOpt'] = ['no-new-privileges=true', 'seccomp=' + canonical(base.seccomp_profile()).decode('ascii')]
    base.verify_inspection(old, policy.legacy, container_id=container_id, running=running)
    return {'configuration_verified': True, 'private_input_allowed': False, 'native_validation': 'DISABLED'}


def _environment(values):
    require(type(values) is list and len(values) <= 64, 'CONTAINER_CONFIGURATION_CHANGED')
    result = {}
    for item in values:
        require(type(item) is str and 0 < len(item) <= 4096 and '\x00' not in item and '\n' not in item and '\r' not in item,
                'CONTAINER_CONFIGURATION_CHANGED')
        key, separator, value = item.partition('=')
        require(bool(separator) and key not in result and base.re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}', key) is not None,
                'CONTAINER_CONFIGURATION_CHANGED')
        result[key] = value
    return result


def _interactive_command(argv, *, timeout=30, maximum=65536):
    """Keep empty stdin PIPE alive; bounded stdout/stderr and exact child reap.

    This is only public source execution, never an input transport. No stdin
    bytes are written. Killing this CLI never proves its container stopped.
    """
    require(type(timeout) in (int, float) and 0 < timeout <= 60)
    require(type(maximum) is int and 0 < maximum <= 65536)
    env = {k: v for k, v in os.environ.items() if k.upper() in {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
    process, threads = None, []
    buffers = [bytearray(), bytearray()]
    capture_lock = threading.Lock()
    exceeded, failed = threading.Event(), threading.Event()
    def read(pipe, target):
        try:
            while data := pipe.read(4096):
                with capture_lock:
                    if sum(len(value) for value in buffers) + len(data) > maximum:
                        exceeded.set(); break
                    target.extend(data)
        except Exception:
            failed.set()
        finally:
            try: pipe.close()
            except Exception: failed.set()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, shell=False, close_fds=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for pipe, target in zip((process.stdout, process.stderr), buffers):
            thread = threading.Thread(target=read, args=(pipe, target), daemon=True)
            threads.append(thread); thread.start()
        deadline, reason = time.monotonic() + timeout, 'EXIT'
        while process.poll() is None:
            require(not failed.is_set(), 'CONTAINER_PROBE_UNAVAILABLE')
            if exceeded.is_set() or time.monotonic() >= deadline:
                reason = 'OUTPUT_LIMIT' if exceeded.is_set() else 'WALL_LIMIT'
                process.kill(); break
            time.sleep(.01)
        process.wait(timeout=5)
        for thread in threads: thread.join(timeout=5)
        require(not failed.is_set() and all(not t.is_alive() for t in threads), 'CONTAINER_PROBE_UNAVAILABLE')
        if exceeded.is_set(): reason = 'OUTPUT_LIMIT'
        return process.returncode, bytes(buffers[0]), bytes(buffers[1]), reason
    except ContainerUnavailable:
        raise
    except Exception:
        raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None
    finally:
        if process is not None:
            stopped, joined = False, True
            try:
                try:
                    if process.poll() is None: process.kill()
                except Exception: process.kill()
                code = process.wait(timeout=5)
                stopped = type(code) is int and process.poll() is not None
            except BaseException: stopped = False
            for thread in threads:
                if thread.ident is not None:
                    try: thread.join(timeout=5); joined = joined and not thread.is_alive()
                    except BaseException: joined = False
            if stopped and joined:
                for pipe in (process.stdin, process.stdout, process.stderr):
                    try: pipe.close()
                    except BaseException: joined = False
            require(stopped and joined, 'CONTAINER_CLEANUP_UNCONFIRMED')


def _probe_shape(raw, scenario):
    """Validate the entire closed result shape before exposing any check names."""
    require(type(raw) is bytes and 0 < len(raw) <= 65536)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs, parse_constant=lambda _: require(False))
        require(type(value) is dict and set(value) == {'schema', 'purpose', 'scenario', 'policy', 'landlock_abi',
            'checks', 'native_validation', 'private_input_allowed'})
        require(type(value['schema']) is int and value['schema'] == 1 and value['purpose'] == 'PUBLIC_ABI3_CONFINEMENT'
                and value['scenario'] == scenario and value['policy'] == POLICY_ID and value['private_input_allowed'] is False
                and value['native_validation'] == 'DISABLED' and type(value['landlock_abi']) is int and 3 <= value['landlock_abi'] <= 16)
        require(type(value['checks']) is dict and set(value['checks']) == CHECKS[scenario]
                and all(type(v) is bool for v in value['checks'].values()))
        return value
    except Exception:
        raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None


def _payload(raw, scenario):
    value = _probe_shape(raw, scenario)
    require(all(value['checks'].values()), 'CONTAINER_PROBE_UNAVAILABLE')
    return value


def _failed_check_frame(raw, scenario):
    """Only allowlisted false names from a fully valid shape, never raw data."""
    try:
        value = _probe_shape(raw, scenario)
        names = sorted(name for name, passed in value['checks'].items() if not passed)
        if not names: return None
        return {'schema': 1, 'purpose': 'PUBLIC_ABI3_CHECK_FAILURE', 'scenario': scenario,
                'failed_check_names': names, 'native_validation': 'DISABLED', 'private_input_allowed': False}
    except Exception:
        return None


def _failure_frame(raw, scenario):
    """Return only a validated fixed public diagnostic; malformed data is discarded."""
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value
    try:
        require(type(raw) is bytes and 0 < len(raw) <= 4096)
        value = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False))
        require(type(value) is dict and set(value) == {'schema', 'purpose', 'scenario', 'stage',
            'failure_class', 'helper_function', 'helper_line', 'native_validation', 'private_input_allowed'})
        require(type(value['schema']) is int and value['schema'] == 1 and value['purpose'] == 'PUBLIC_ABI3_FAILURE'
                and value['scenario'] == scenario and value['native_validation'] == 'DISABLED'
                and value['private_input_allowed'] is False)
        require(type(value['stage']) is str and value['stage'] in FAILURE_STAGES
                and type(value['failure_class']) is str and value['failure_class'] in FAILURE_CLASSES
                and type(value['helper_function']) is str and value['helper_function'] in HELPER_FUNCTIONS
                and type(value['helper_line']) is int and 0 <= value['helper_line'] <= 2000
                and ((value['helper_function'] == 'NONE') == (value['helper_line'] == 0)))
        return value
    except Exception:
        return None


def run_public_probe(policy, *, docker_path, profile_path):
    """Root-only. Exact fresh ID only; lost create output never grants adoption."""
    require(type(policy) is NativeProbePolicy and os.name == 'nt')
    require(hashlib.sha256(Path(base.__file__).read_bytes()).hexdigest() == BASE_SHA256)
    docker_path, profile_path = Path(docker_path), Path(profile_path)
    require(docker_path.is_absolute() and profile_path.is_absolute())
    from infra.evidence_tools import Windows
    api = Windows()
    container_id, created, result, diagnostic = None, False, None, None
    def call(*args, **options):
        return base._bounded_command([str(docker_path), '--host', base.ENDPOINT, *args], timeout=options.get('timeout', 15), maximum=options.get('maximum', 1048576))
    def document(*args):
        code, out, _, reason = call(*args)
        require(code == 0 and reason == 'EXIT', 'CONTAINER_PROBE_UNAVAILABLE')
        try: value = json.loads(out)
        except (ValueError, TypeError): raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None
        require(type(value) is list and len(value) == 1 and type(value[0]) is dict, 'CONTAINER_PROBE_UNAVAILABLE')
        return value[0]
    def ownership(value):
        require(value.get('Id') == container_id and value.get('Name') == '/' + policy.name and value.get('Image') == policy.image_id
                and value.get('Config', {}).get('Labels') == policy.labels, 'CONTAINER_IDENTITY_CHANGED')
    with api.pin(docker_path), api.pin(profile_path), api.pin(HELPER, private=False), api.pin(Path(base.__file__), private=False):
        require(profile_path.read_bytes() == canonical(startup_profile()))
        image = document('image', 'inspect', BASE_IMAGE)
        base.verify_image(image, policy.legacy)
        expected_env = _environment(image['Config'].get('Env', [])) | FIXED_ENV
        code, out, _, reason = call('container', 'ls', '--all', '--no-trunc', '--filter', 'name=^/' + policy.name + '$', '--format', '{{.ID}}')
        require(code == 0 and reason == 'EXIT' and not out.strip(), 'CONTAINER_IDENTITY_CHANGED')
        try:
            created = True
            code, out, _, reason = call(*create_args(policy, profile_path=str(profile_path)))
            require(code == 0 and reason == 'EXIT', 'CONTAINER_PROBE_UNAVAILABLE')
            try: value = out.decode('ascii').strip()
            except UnicodeError: raise ContainerUnavailable('CONTAINER_IDENTITY_CHANGED') from None
            require(base.ID.fullmatch(value) is not None, 'CONTAINER_IDENTITY_CHANGED')
            container_id = value
            before = document('container', 'inspect', container_id)
            verify_inspection(before, policy, container_id=container_id)
            require(_environment(before['Config'].get('Env')) == expected_env, 'CONTAINER_CONFIGURATION_CHANGED')
            code, out, _, reason = _interactive_command([str(docker_path), '--host', base.ENDPOINT, 'container', 'start',
                '--attach', '--interactive', container_id], timeout=30, maximum=65536)
            after = document('container', 'inspect', container_id)
            verify_inspection(after, policy, container_id=container_id)
            require(_environment(after['Config'].get('Env')) == expected_env, 'CONTAINER_CONFIGURATION_CHANGED')
            require(reason == 'EXIT' and after['State'].get('OOMKilled') is False and after['State'].get('Pid') == 0,
                    'CONTAINER_PROBE_UNAVAILABLE')
            frame = _failure_frame(out, policy.scenario) or _failed_check_frame(out, policy.scenario)
            worker_exit = after['State'].get('ExitCode')
            if (frame is not None and type(code) is int and type(worker_exit) is int
                    and -2147483648 <= code <= 2147483647 and -2147483648 <= worker_exit <= 2147483647):
                diagnostic = {'schema': 1, 'scope': 'PUBLIC_ABI3_ONLY', 'failure': frame,
                    'cli_exit': code, 'worker_exit': worker_exit, 'cleanup': 'UNCONFIRMED',
                    'native_validation': 'DISABLED', 'private_input_allowed': False}
            expected_exit = 159 if policy.scenario == 'x32' else 0
            require(type(code) is int and code == expected_exit and type(after['State'].get('ExitCode')) is int
                    and after['State']['ExitCode'] == expected_exit,
                    'CONTAINER_PROBE_UNAVAILABLE')
            payload = _payload(out, policy.scenario)
            result = {'schema': 1, 'status': 'PUBLIC_ABI3_PROBE_VERIFIED', 'scope': 'PUBLIC_ABI3_ONLY', 'scenario': policy.scenario,
                'policy': POLICY_ID, 'helper_sha256': HELPER_SHA256, 'profile_sha256': profile_digest(),
                'probe': payload, 'x32_kill_verified': policy.scenario == 'x32',
                'native_validation': 'DISABLED', 'private_input_allowed': False}
        except ContainerUnavailable as error:
            if diagnostic is not None: error.diagnostic = diagnostic
            raise
        finally:
            if created:
                try:
                    if container_id is None:
                        code, out, _, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
                            'name=^/' + policy.name + '$', '--format', '{{.ID}}')
                        require(code == 0 and reason == 'EXIT' and not out.strip(), 'CONTAINER_CLEANUP_UNCONFIRMED')
                    else:
                        value = document('container', 'inspect', container_id); ownership(value)
                        if value['State'].get('Running'):
                            call('container', 'kill', '--signal', 'KILL', container_id)
                        value = document('container', 'inspect', container_id); ownership(value)
                        require(value['State'].get('Running') is False and value['State'].get('Restarting') is False
                                and value['State'].get('Pid') == 0, 'CONTAINER_CLEANUP_UNCONFIRMED')
                        code, _, _, reason = call('container', 'rm', container_id)
                        require(code == 0 and reason == 'EXIT', 'CONTAINER_CLEANUP_UNCONFIRMED')
                        code, out, _, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
                            'id=' + container_id, '--format', '{{.ID}}')
                        require(code == 0 and reason == 'EXIT' and not out.strip(), 'CONTAINER_CLEANUP_UNCONFIRMED')
                        if result is not None: result['cleanup'] = 'OWNED_CONTAINER_ABSENT_VERIFIED'
                        if diagnostic is not None: diagnostic['cleanup'] = 'OWNED_CONTAINER_ABSENT_VERIFIED'
                except BaseException:
                    error = ContainerUnavailable('CONTAINER_CLEANUP_UNCONFIRMED')
                    if diagnostic is not None:
                        diagnostic['cleanup'] = 'UNCONFIRMED'
                        error.diagnostic = diagnostic
                    raise error from None
        require(profile_path.read_bytes() == canonical(startup_profile()))
    return result


def native_scan(*args, **kwargs):
    raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE')


if __name__ == '__main__':
    print(json.dumps(preparation(), sort_keys=True))
