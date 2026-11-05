"""Optional Linux containment candidate. No private-evidence execution/activation.

This module builds and checks a deliberately restricted SYNTHETIC probe boundary.
Its receipts cannot satisfy evidence_tools._verify_native_trust. Image provenance,
second-stage filtering/Landlock and actual native scanner proofs remain separate.
Never pass a photograph, coordinate, key, DB credential or source path here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

ENDPOINT = 'npipe:////./pipe/dockerDesktopLinuxEngine'
OWNER = 'kapit-private-evidence-synthetic-probe-v1'
IMAGE = re.compile(r'docker\.io/library/python@sha256:[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[0-9a-f]{32}\Z')
ID = re.compile(r'[0-9a-f]{64}\Z')
SCRATCH = 64 * 1024 * 1024
INODES = 128
MEMORY = 256 * 1024 * 1024
TMPFS = 'rw,noexec,nosuid,nodev,size=67108864,nr_inodes=128,mode=0700,uid=65532,gid=65532'
SCENARIOS = frozenset({'identity', 'storage', 'network', 'cpu', 'memory', 'output', 'wall', 'landlock_abi'})
LANDLOCK_REQUIRED_ABI = 5
LANDLOCK_QUERY_ERRNOS = frozenset({0, 1, 38, 95})  # Linux success, EPERM, ENOSYS, EOPNOTSUPP.


class ContainerUnavailable(RuntimeError):
    def __init__(self, code='CONTAINER_POLICY_UNAVAILABLE'):
        self.code = code if code in {'CONTAINER_POLICY_UNAVAILABLE', 'CONTAINER_IMAGE_UNAVAILABLE',
            'CONTAINER_IDENTITY_CHANGED', 'CONTAINER_CONFIGURATION_CHANGED',
            'CONTAINER_PROBE_UNAVAILABLE', 'CONTAINER_CLEANUP_UNCONFIRMED'} else 'CONTAINER_POLICY_UNAVAILABLE'
        super().__init__(self.code)


def require(value, code='CONTAINER_POLICY_UNAVAILABLE'):
    if value is not True:
        raise ContainerUnavailable(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def seccomp_profile():
    """Probe startup allowlist; absent calls fail EPERM. Not native-tool acceptance."""
    calls = '''access arch_prctl brk chdir clock_getres clock_gettime close close_range dup dup2 dup3
        execve exit exit_group faccessat faccessat2 fchdir fcntl fstat fstatfs fsync ftruncate futex
        getcwd getdents64 getegid geteuid getgid getgroups getpid getppid getrandom getresgid getresuid
        getrlimit getrusage gettid getuid lseek madvise mkdir mkdirat mmap mprotect mremap munmap
        nanosleep newfstatat open openat poll ppoll pread64 prlimit64 pselect6 read readlink readlinkat
        readv restart_syscall rseq rt_sigaction rt_sigprocmask rt_sigreturn sched_getaffinity
        sched_yield select set_robust_list set_tid_address sigaltstack stat statfs statx sysinfo
        time times uname unlink unlinkat write writev clock_nanosleep gettimeofday'''.split()
    return {'defaultAction': 'SCMP_ACT_ERRNO', 'defaultErrnoRet': 1,
            'syscalls': [{'names': sorted(calls), 'action': 'SCMP_ACT_ALLOW'},
                         {'names': ['landlock_create_ruleset'], 'action': 'SCMP_ACT_ALLOW',
                          'args': [{'index': 0, 'value': 0, 'op': 'SCMP_CMP_EQ'},
                                   {'index': 1, 'value': 0, 'op': 'SCMP_CMP_EQ'},
                                   {'index': 2, 'value': 1, 'op': 'SCMP_CMP_EQ'}]}]}


def profile_digest():
    return hashlib.sha256(canonical(seccomp_profile())).hexdigest()


def landlock_observation(payload):
    """A recognized unavailable query is evidence, never a containment pass."""
    require(type(payload) is dict and set(payload) == {'schema', 'scenario', 'abi', 'required',
        'available', 'errno', 'private_input_allowed'}, 'CONTAINER_PROBE_UNAVAILABLE')
    require(type(payload['schema']) is int and payload['schema'] == 1 and payload['scenario'] == 'landlock_abi'
        and type(payload['abi']) is int and 0 <= payload['abi'] <= 16
        and type(payload['required']) is int and payload['required'] == LANDLOCK_REQUIRED_ABI
        and type(payload['available']) is bool and type(payload['errno']) is int
        and payload['errno'] in LANDLOCK_QUERY_ERRNOS and payload['private_input_allowed'] is False,
        'CONTAINER_PROBE_UNAVAILABLE')
    if payload['errno'] == 0:
        require(payload['abi'] >= 1 and payload['available'] == (payload['abi'] >= LANDLOCK_REQUIRED_ABI),
            'CONTAINER_PROBE_UNAVAILABLE')
    else:
        require(payload['abi'] == 0 and payload['available'] is False, 'CONTAINER_PROBE_UNAVAILABLE')
    return dict(payload)


@dataclass(frozen=True)
class ProbePolicy:
    image: str
    image_id: str
    token: str
    scenario: str

    def __post_init__(self):
        require(type(self.image) is str and IMAGE.fullmatch(self.image) is not None)
        require(type(self.image_id) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id) is not None)
        require(type(self.token) is str and TOKEN.fullmatch(self.token) is not None)
        require(type(self.scenario) is str and self.scenario in SCENARIOS)

    @property
    def name(self):
        return 'kapit-evidence-probe-' + self.token

    @property
    def labels(self):
        return {'org.kapit.owner': OWNER, 'org.kapit.run': self.token,
                'org.kapit.policy': profile_digest(), 'org.kapit.purpose': 'synthetic-only'}


def verify_image(document, policy):
    require(type(document) is dict and document.get('Id') == policy.image_id, 'CONTAINER_IMAGE_UNAVAILABLE')
    require(document.get('Os') == 'linux' and document.get('Architecture') == 'amd64', 'CONTAINER_IMAGE_UNAVAILABLE')
    digests = document.get('RepoDigests')
    # Docker's official-library normalization is explicit and exact; no generic
    # suffix matching or registry/repository substitution is allowed.
    aliases = {policy.image, policy.image.removeprefix('docker.io/library/')}
    require(type(digests) is list and 1 <= len(digests) <= 2 and
            all(type(value) is str and value in aliases for value in digests)
            and len(set(digests)) == len(digests), 'CONTAINER_IMAGE_UNAVAILABLE')
    config = document.get('Config')
    require(type(config) is dict, 'CONTAINER_IMAGE_UNAVAILABLE')
    require(not config.get('Volumes') and not config.get('Healthcheck') and not config.get('OnBuild'), 'CONTAINER_IMAGE_UNAVAILABLE')


def create_args(policy, *, profile_path):
    """Only public synthetic program/limits; profile must be exclusively pinned by caller."""
    require(type(policy) is ProbePolicy)
    require(type(profile_path) is str and bool(profile_path) and '\x00' not in profile_path)
    args = ['create', '--pull=never', '--name', policy.name, '--platform', 'linux/amd64',
        '--read-only', '--network', 'none', '--ipc', 'none', '--cgroupns', 'private',
        '--user', '65532:65532', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
        '--security-opt', 'seccomp=' + profile_path, '--log-driver', 'none', '--no-healthcheck',
        '--restart', 'no', '--memory', str(MEMORY), '--memory-swap', str(MEMORY), '--cpus', '1',
        '--pids-limit', '1', '--ulimit', 'cpu=2:2', '--ulimit', 'core=0:0',
        '--ulimit', 'fsize=67108864:67108864', '--ulimit', 'nofile=32:32',
        '--tmpfs', '/scratch:' + TMPFS, '--workdir', '/scratch',
        '--env', 'HOME=/scratch', '--env', 'TMPDIR=/scratch', '--env', 'TMP=/scratch',
        '--env', 'TEMP=/scratch', '--env', 'PYTHONDONTWRITEBYTECODE=1',
        '--entrypoint', '/usr/local/bin/python3']
    for key, value in sorted(policy.labels.items()):
        args.extend(['--label', key + '=' + value])
    args.extend([policy.image, '-I', '-B', '-c', probe_program(), policy.scenario])
    return args


def verify_inspection(document, policy, *, container_id, running=False):
    """Verify configuration/ownership only. Does NOT attest kernel enforcement."""
    require(type(container_id) is str and ID.fullmatch(container_id) is not None, 'CONTAINER_IDENTITY_CHANGED')
    require(type(document) is dict and document.get('Id') == container_id and
            document.get('Name') == '/' + policy.name and document.get('Image') == policy.image_id,
            'CONTAINER_IDENTITY_CHANGED')
    config, host, state = (document.get(k) for k in ('Config', 'HostConfig', 'State'))
    require(all(type(x) is dict for x in (config, host, state)), 'CONTAINER_CONFIGURATION_CHANGED')
    require(config.get('Labels') == policy.labels and config.get('User') == '65532:65532' and
            config.get('WorkingDir') == '/scratch' and config.get('Entrypoint') == ['/usr/local/bin/python3'] and
            config.get('Cmd') == ['-I', '-B', '-c', probe_program(), policy.scenario] and
            config.get('Tty') is False and config.get('OpenStdin') is False and
            not config.get('Volumes') and config.get('Healthcheck') == {'Test': ['NONE']},
            'CONTAINER_CONFIGURATION_CHANGED')
    # Docker's private PID namespace is the default empty mode, not the invalid
    # CLI spelling "private". Host/container sharing remains forbidden.
    exact = {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'IpcMode': 'none', 'PidMode': '',
        'CgroupnsMode': 'private', 'Privileged': False, 'Memory': MEMORY, 'MemorySwap': MEMORY,
        'NanoCpus': 1000000000, 'PidsLimit': 1, 'Tmpfs': {'/scratch': TMPFS},
        'LogConfig': {'Type': 'none', 'Config': {}}, 'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}}
    for key, expected in exact.items():
        # Equality alone permits true ==1; enforce top-level scalar types.
        require(host.get(key) == expected and type(host.get(key)) is type(expected), 'CONTAINER_CONFIGURATION_CHANGED')
    require(host.get('CapAdd') in (None, []) and host.get('CapDrop') == ['ALL'], 'CONTAINER_CONFIGURATION_CHANGED')
    opts = host.get('SecurityOpt')
    require(type(opts) is list and len(opts) == 2 and 'no-new-privileges=true' in opts and
            any(type(x) is str and x.startswith('seccomp=') and x != 'seccomp=unconfined' for x in opts),
            'CONTAINER_CONFIGURATION_CHANGED')
    # Bind the actual normalized seccomp content, not a caller-controlled filename.
    sec = next(x[8:] for x in opts if x.startswith('seccomp='))
    try:
        parsed = json.loads(sec)
    except (ValueError, TypeError):
        raise ContainerUnavailable('CONTAINER_CONFIGURATION_CHANGED') from None
    require(parsed == seccomp_profile(), 'CONTAINER_CONFIGURATION_CHANGED')
    for key in ('Binds', 'Mounts', 'Devices', 'DeviceRequests', 'PortBindings', 'Links', 'VolumesFrom',
                'ExtraHosts', 'GroupAdd', 'Dns', 'DnsOptions', 'DnsSearch', 'StorageOpt', 'Sysctls'):
        require(not host.get(key), 'CONTAINER_CONFIGURATION_CHANGED')
    limits = host.get('Ulimits')
    require(type(limits) is list and len(limits) == 4, 'CONTAINER_CONFIGURATION_CHANGED')
    require(sorted(limits, key=lambda x: x.get('Name', '')) == sorted([
        {'Name': 'cpu', 'Soft': 2, 'Hard': 2}, {'Name': 'core', 'Soft': 0, 'Hard': 0},
        {'Name': 'fsize', 'Soft': SCRATCH, 'Hard': SCRATCH}, {'Name': 'nofile', 'Soft': 32, 'Hard': 32}],
        key=lambda x: x['Name']), 'CONTAINER_CONFIGURATION_CHANGED')
    require(document.get('Mounts') in ([], [{'Type': 'tmpfs', 'Source': '', 'Destination': '/scratch',
                'Mode': '', 'RW': True, 'Propagation': ''}]), 'CONTAINER_CONFIGURATION_CHANGED')
    require(state.get('Running') is running and state.get('Paused') is False and state.get('Restarting') is False,
            'CONTAINER_CONFIGURATION_CHANGED')
    return {'configuration_verified': True, 'containment_proven': False, 'private_input_allowed': False}


def probe_program():
    """Public fixed synthetic-only payload; never reads stdin or host/user data."""
    return '''import errno,json,os,resource,socket,sys,time
scenario=sys.argv[1]
def emit(v):
 print(json.dumps(v,sort_keys=True,separators=(",",":")),flush=True)
def denied(call):
 try:
  obj=call()
  if hasattr(obj,"close"):obj.close()
  return False
 except OSError as e:return e.errno in (errno.EPERM,errno.EACCES,errno.EROFS,errno.ENOSYS,errno.ENOENT)
if scenario=="landlock_abi":
 import ctypes
 libc=ctypes.CDLL(None,use_errno=True)
 libc.syscall.argtypes=[ctypes.c_long,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_uint]
 libc.syscall.restype=ctypes.c_long
 ctypes.set_errno(0)
 # Query only, fixed Linux amd64 syscall444; no ruleset or restriction created.
 abi=libc.syscall(444,None,0,1)
 error=ctypes.get_errno() if abi==-1 else 0
 if abi==-1:
  if error not in (errno.ENOSYS,errno.EPERM,errno.EOPNOTSUPP):raise SystemExit(2)
  abi=0
 elif not 1<=abi<=16:raise SystemExit(2)
 emit({"schema":1,"scenario":scenario,"abi":abi,"required":5,
  "available":error==0 and abi>=5,"errno":error,"private_input_allowed":False})
elif scenario=="identity":
 st=os.statvfs("/scratch")
 emit({"schema":1,"scenario":scenario,"uid_ok":os.getuid()==65532,"gid_ok":os.getgid()==65532,
  "scratch_bytes_bounded":st.f_blocks*st.f_frsize<=67108864,"scratch_inodes_bounded":0<st.f_files<=128,
  "cpu_total_bounded":resource.getrlimit(resource.RLIMIT_CPU)==(2,2),
  "core_disabled":resource.getrlimit(resource.RLIMIT_CORE)==(0,0),
  "outside_create_denied":all(denied(lambda p=p:open(p,"wb")) for p in
   ("/kapit-synthetic-probe","/tmp/kapit-synthetic-probe","/dev/kapit-synthetic-probe","/dev/shm/kapit-synthetic-probe")),
  "fork_denied":denied(os.fork),"socket_denied":denied(lambda:socket.socket()),"private_input_allowed":False})
elif scenario=="storage":
 total=0;full=False
 try:
  block=b"0"*65536
  for part in range(5):
   with open("/scratch/fill"+str(part),"wb",buffering=0) as f:
    for _ in range(256):
     n=f.write(block);total+=n
 except OSError as e:full=e.errno==errno.ENOSPC
 for part in range(5):
  try:os.unlink("/scratch/fill"+str(part))
  except FileNotFoundError:pass
 count=0;inode=False
 try:
  for n in range(130):
   with open("/scratch/n"+str(n),"wb"):pass
   count+=1
 except OSError as e:inode=e.errno==errno.ENOSPC
 emit({"schema":1,"scenario":scenario,"byte_quota_enforced":full and 0<total<=67108864,
  "inode_quota_enforced":inode and 0<count<128,"private_input_allowed":False})
elif scenario=="network":
 emit({"schema":1,"scenario":scenario,"inet_denied":denied(lambda:socket.socket(socket.AF_INET)),
  "inet6_denied":denied(lambda:socket.socket(socket.AF_INET6)),"unix_denied":denied(lambda:socket.socket(socket.AF_UNIX)),
  "private_input_allowed":False})
elif scenario=="cpu":
 while True:pass
elif scenario=="memory":
 parts=[]
 while True:parts.append(bytearray(8*1024*1024))
elif scenario=="output":
 while True:os.write(1,b"S"*65536)
elif scenario=="wall":
 while True:time.sleep(1)
else:raise SystemExit(2)
'''


def native_scan(*args, **kwargs):
    """No receipt/config/test boolean can unlock private execution."""
    raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE')


def _bounded_command(argv, *, timeout, maximum=1048576):
    """Bound both CLI pipes. Killing this CLI never attests container cleanup."""
    require(type(maximum) is int and 0 < maximum <= 1048576)
    require(type(timeout) in (int, float) and 0 < timeout <= 60)
    env = {key: value for key, value in os.environ.items()
           if key.upper() in {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
    process, threads = None, []
    buffers = [bytearray(), bytearray()]
    exceeded, failed = threading.Event(), threading.Event()

    def read_pipe(pipe, target):
        try:
            while True:
                data = pipe.read(4096)
                if not data:
                    break
                if len(target) + len(data) > maximum:
                    exceeded.set()
                    break
                target.extend(data)
        except Exception:
            failed.set()
        finally:
            try:
                pipe.close()
            except Exception:
                failed.set()

    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, shell=False, close_fds=True)
        for pipe, target in zip((process.stdout, process.stderr), buffers):
            thread = threading.Thread(target=read_pipe, args=(pipe, target), daemon=True)
            threads.append(thread)  # Also track a failed start without joining it.
            thread.start()
        deadline = time.monotonic() + timeout
        reason = 'EXIT'
        while process.poll() is None:
            require(not failed.is_set(), 'CONTAINER_PROBE_UNAVAILABLE')
            if exceeded.is_set() or time.monotonic() >= deadline:
                reason = 'OUTPUT_LIMIT' if exceeded.is_set() else 'WALL_LIMIT'
                process.kill()  # Exact Popen process owned by this call only.
                break
            time.sleep(.01)
        process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=5)
        require(not failed.is_set() and all(not thread.is_alive() for thread in threads), 'CONTAINER_PROBE_UNAVAILABLE')
        if exceeded.is_set():
            reason = 'OUTPUT_LIMIT'
        return process.returncode, bytes(buffers[0]), bytes(buffers[1]), reason
    except ContainerUnavailable:
        raise
    except Exception:
        raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None
    finally:
        if process is not None:
            stopped = False
            # Stop and reap even on KeyboardInterrupt, failed thread startup,
            # failed wait/poll or ordinary I/O failure. No name/PID fallback.
            try:
                try:
                    if process.poll() is None:
                        process.kill()
                except Exception:
                    process.kill()  # Still only our retained direct handle.
                code = process.wait(timeout=5)
                stopped = type(code) is int and process.poll() is not None
            except BaseException:
                stopped = False
            joined = True
            for thread in threads:
                if thread.ident is not None:
                    try:
                        thread.join(timeout=5)
                        joined = joined and not thread.is_alive()
                    except BaseException:
                        joined = False
            # Do not block closing a buffered stream still owned by a reader
            # whose child stop is unconfirmed. Preserve uncertainty instead.
            if stopped and joined:
                for pipe in (process.stdout, process.stderr):
                    try:
                        pipe.close()
                    except BaseException:
                        joined = False
            require(stopped and joined, 'CONTAINER_CLEANUP_UNCONFIRMED')


def run_synthetic_probe(policy, *, docker_path, profile_path):
    """Root-only explicit synthetic execution; never an application tools receipt.

    Only the fixed local daemon, verified immutable image and exact new owned ID
    are used. Existing images are read by exact verified digest; no pull/build,
    daemon change or unrelated container listing/stop/removal occurs here.
    """
    require(type(policy) is ProbePolicy and os.name == 'nt')
    docker_path, profile_path = Path(docker_path), Path(profile_path)
    require(docker_path.is_absolute() and profile_path.is_absolute())
    from infra.evidence_tools import Windows
    api = Windows()
    container_id, created, result = None, False, None

    def call(*args, timeout=15, maximum=1048576):
        return _bounded_command([str(docker_path), '--host', ENDPOINT, *args], timeout=timeout, maximum=maximum)

    def document(*args):
        code, out, _, reason = call(*args)
        require(code == 0 and reason == 'EXIT', 'CONTAINER_PROBE_UNAVAILABLE')
        try:
            values = json.loads(out)
        except (ValueError, TypeError):
            raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None
        require(type(values) is list and len(values) == 1 and type(values[0]) is dict,
                'CONTAINER_PROBE_UNAVAILABLE')
        return values[0]

    def ownership(d):
        require(d.get('Id') == container_id and d.get('Name') == '/' + policy.name and
            d.get('Image') == policy.image_id and d.get('Config', {}).get('Labels') == policy.labels,
            'CONTAINER_IDENTITY_CHANGED')

    with api.pin(docker_path), api.pin(profile_path):
        require(profile_path.read_bytes() == canonical(seccomp_profile()))
        verify_image(document('image', 'inspect', policy.image), policy)
        code, out, _, reason = call('container', 'ls', '--all', '--filter', 'name=^/' + policy.name + '$', '--format', '{{.ID}}')
        require(code == 0 and reason == 'EXIT' and not out.strip(), 'CONTAINER_IDENTITY_CHANGED')
        try:
            # Set before create: ambiguous creation is not silently called clean.
            created = True
            code, out, _, reason = call(*create_args(policy, profile_path=str(profile_path)))
            require(code == 0 and reason == 'EXIT', 'CONTAINER_PROBE_UNAVAILABLE')
            emitted_id = out.decode('ascii', errors='strict').strip()
            require(ID.fullmatch(emitted_id) is not None, 'CONTAINER_IDENTITY_CHANGED')
            container_id = emitted_id  # Ownership never comes from an invalid/name response.
            verify_inspection(document('container', 'inspect', container_id), policy, container_id=container_id)
            started = time.monotonic()
            code, out, _, reason = call('container', 'start', '--attach', container_id,
                timeout=5 if policy.scenario in {'wall', 'output'} else 20, maximum=65536)
            after = document('container', 'inspect', container_id)
            ownership(after)
            result = {'schema': 1, 'purpose': 'SYNTHETIC_CONTAINMENT_PROBE_ONLY', 'scenario': policy.scenario,
                'cli_exit': code, 'limit': reason, 'seconds': round(time.monotonic() - started, 3),
                'container_exit': after['State'].get('ExitCode'), 'oom_killed': after['State'].get('OOMKilled'),
                'configuration_verified': True, 'native_validation': 'DISABLED', 'private_input_allowed': False}
            if policy.scenario == 'landlock_abi':
                require(code == 0 and reason == 'EXIT', 'CONTAINER_PROBE_UNAVAILABLE')
                try:
                    payload = json.loads(out)
                except (ValueError, TypeError):
                    raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None
                result['probe'] = landlock_observation(payload)
                result['capability'] = 'CAPABILITY_OBSERVED'
            elif policy.scenario in {'identity', 'storage', 'network'}:
                require(code == 0 and reason == 'EXIT', 'CONTAINER_PROBE_UNAVAILABLE')
                try:
                    payload = json.loads(out)
                except (ValueError, TypeError):
                    raise ContainerUnavailable('CONTAINER_PROBE_UNAVAILABLE') from None
                require(type(payload) is dict and payload.get('schema') == 1 and
                    payload.get('scenario') == policy.scenario and payload.get('private_input_allowed') is False)
                fields = {'identity': {'uid_ok', 'gid_ok', 'scratch_bytes_bounded', 'scratch_inodes_bounded',
                    'cpu_total_bounded', 'core_disabled', 'outside_create_denied', 'fork_denied', 'socket_denied'},
                    'storage': {'byte_quota_enforced', 'inode_quota_enforced'},
                    'network': {'inet_denied', 'inet6_denied', 'unix_denied'}}[policy.scenario]
                require(set(payload) == fields | {'schema', 'scenario', 'private_input_allowed'} and
                    type(payload['schema']) is int, 'CONTAINER_PROBE_UNAVAILABLE')
                require(all(type(v) is bool and v is True for k, v in payload.items()
                    if k not in {'schema', 'scenario', 'private_input_allowed'}), 'CONTAINER_PROBE_UNAVAILABLE')
                result['probe'] = payload
            elif policy.scenario == 'cpu':
                require(reason == 'EXIT' and after['State'].get('ExitCode') in (137, 152) and
                    after['State'].get('OOMKilled') is False and not after['State'].get('Running'),
                    'CONTAINER_PROBE_UNAVAILABLE')
            elif policy.scenario == 'memory':
                require(reason == 'EXIT' and after['State'].get('OOMKilled') is True and
                    not after['State'].get('Running'), 'CONTAINER_PROBE_UNAVAILABLE')
            else:
                require(reason == ('WALL_LIMIT' if policy.scenario == 'wall' else 'OUTPUT_LIMIT'),
                    'CONTAINER_PROBE_UNAVAILABLE')
        finally:
            if created:
                # A failed create may have left an owned container despite lost output.
                try:
                    if container_id is None:
                        # Lost/malformed create output is NOT ownership. Check
                        # exact-name absence only; never inspect/adopt/stop a
                        # discovered name, even if its labels happen to match.
                        code, out, _, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
                            'name=^/' + policy.name + '$', '--format', '{{.ID}}')
                        require(code == 0 and reason == 'EXIT' and not out.strip(), 'CONTAINER_CLEANUP_UNCONFIRMED')
                    else:
                        d = document('container', 'inspect', container_id)
                        ownership(d)
                        if d.get('State', {}).get('Running'):
                            call('container', 'kill', '--signal', 'KILL', container_id)
                        d = document('container', 'inspect', container_id)
                        ownership(d)
                        require(d.get('State', {}).get('Running') is False and
                            d['State'].get('Restarting') is False and d['State'].get('Pid') == 0,
                            'CONTAINER_CLEANUP_UNCONFIRMED')
                        code, _, _, reason = call('container', 'rm', container_id)
                        require(code == 0 and reason == 'EXIT', 'CONTAINER_CLEANUP_UNCONFIRMED')
                        code, out, _, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
                            'id=' + container_id, '--format', '{{.ID}}')
                        require(code == 0 and reason == 'EXIT' and not out.strip(), 'CONTAINER_CLEANUP_UNCONFIRMED')
                        if result is not None:
                            result['cleanup'] = 'OWNED_CONTAINER_ABSENT_VERIFIED'
                except BaseException:
                    raise ContainerUnavailable('CONTAINER_CLEANUP_UNCONFIRMED') from None
        require(profile_path.read_bytes() == canonical(seccomp_profile()))
    return result
