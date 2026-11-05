"""Owned native-worker controller, source-fixed PUBLIC fixtures only.

Candidate declarations/READY are not artifact trust or native proof. No private
ingress is implemented; future protected-current-generation integration is separate.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import io
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
import uuid

from infra import evidence_container as base
from infra import evidence_container_native as public
from infra import evidence_native_ownership as ownership_journal
from infra.evidence_native_fixtures import fixture, derivative_metadata_absent
from backend.apps.operations import evidence_scan_protocol as protocol
from backend.apps.operations.evidence_native_worker import POLICY_SHA256
from backend.apps.operations.evidence_policy import inspect_container

OWNER = 'kapit-public-native-fixture-v1'
MODULE = 'kapit_evidence.evidence_native_worker'
LIMITS = {'scan': (4294967296, 120, 180), 'decode': (1073741824, 20, 30)}
STDERR_LIMIT = 16384
OUTPUT_LIMIT = 5242880 + 2 * (4096 + 4)
IMAGE_ENV = {'PATH':'/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'PYTHON_VERSION':'3.14.0','PYTHON_SHA256':'2299dae542d395ce3883aca00d3c910307cd68e0b2f7336098c8e7b7eee9f3e9',
    'PYTHONDONTWRITEBYTECODE':'1','PYTHONUNBUFFERED':'1','HOME':'/nonexistent','TMPDIR':'/scratch',
    'LD_LIBRARY_PATH':'/opt/clamav/lib:/opt/closure/lib'}
EFFECTIVE_ENV = IMAGE_ENV | {'TMP':'/scratch','TEMP':'/scratch'}
ENTRYPOINT = '/usr/local/bin/python'
OWNERSHIP_SHA256 = '6544725a99a0d9941db347ea3c81b8d3e8ea8f58ae88886289c320ee6f2ef4d1'


class NativeUnavailable(RuntimeError):
    def __init__(self, code='NATIVE_FIXTURE_UNAVAILABLE'):
        self.code = code if code in {'NATIVE_FIXTURE_UNAVAILABLE', 'NATIVE_CLEANUP_UNCONFIRMED'} else 'NATIVE_FIXTURE_UNAVAILABLE'
        super().__init__(self.code)


def require(value, code='NATIVE_FIXTURE_UNAVAILABLE'):
    if value is not True: raise NativeUnavailable(code)


def _require_cgroup_v2(call, *, timeout=15):
    """Fresh bounded local-daemon observation; never a cached/caller flag."""
    code,out,_,reason = call('info','--format','{{.CgroupVersion}}',timeout=timeout)
    require(type(code) is int and code == 0 and reason == 'EXIT' and
            type(out) is bytes and out in (b'2',b'2\n',b'2\r\n'))


@dataclass(frozen=True)
class Candidate:
    """PUBLIC artifact declaration only. No receipt/key/ready enabling flags."""
    image_id: str
    signature_generation: str

    def __post_init__(self):
        require(type(self.image_id) is str and base.re.fullmatch(r'sha256:[0-9a-f]{64}', self.image_id) is not None)
        require(type(self.signature_generation) is str and protocol.HEX.fullmatch(self.signature_generation) is not None
                and self.signature_generation != '0' * 64)


@dataclass(frozen=True)
class _Phase:
    candidate: Candidate
    binding: protocol.Binding
    token: str

    @property
    def name(self): return 'kapit-native-public-' + self.token

    @property
    def labels(self):
        return {'org.kapit.owner': OWNER, 'org.kapit.run': self.token, 'org.kapit.reservation': self.token,
                'org.kapit.purpose': 'public-native-fixtures-only',
                'org.kapit.mode': self.binding.mode, 'org.kapit.policy': POLICY_SHA256}

    @property
    def command(self): return ['-I', '-B', '-m', MODULE, self.binding.mode, self.binding.nonce]


def create_args(phase, *, profile_path):
    require(type(phase) is _Phase and phase.binding.mode in LIMITS)
    memory, cpu, _ = LIMITS[phase.binding.mode]
    args = ['create', '--interactive', '--pull=never', '--name', phase.name, '--platform', 'linux/amd64',
        '--read-only', '--network', 'none', '--ipc', 'none', '--cgroupns', 'private', '--user', '65532:65532',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true', '--security-opt', 'seccomp=' + str(profile_path),
        '--log-driver', 'none', '--no-healthcheck', '--restart', 'no', '--memory', str(memory), '--memory-swap', str(memory),
        '--cpus', '1', '--pids-limit', '1', '--ulimit', 'cpu=' + str(cpu) + ':' + str(cpu),
        '--ulimit', 'core=0:0', '--ulimit', 'fsize=67108864:67108864', '--ulimit', 'nofile=32:32',
        '--tmpfs', '/scratch:' + base.TMPFS, '--workdir', '/scratch', '--entrypoint', ENTRYPOINT]
    for key, value in sorted(EFFECTIVE_ENV.items()): args.extend(['--env', key + '=' + value])
    for key, value in sorted(phase.labels.items()): args.extend(['--label', key + '=' + value])
    return args + [phase.candidate.image_id, *phase.command]


def verify_image(image, candidate):
    """Exact reviewed build-label shape; both inherited keys are overwritten."""
    require(type(image) is dict and image.get('Id') == candidate.image_id
            and image.get('Os') == 'linux' and image.get('Architecture') == 'amd64')
    config = image.get('Config')
    require(type(config) is dict and not config.get('Volumes') and not config.get('Healthcheck') and not config.get('OnBuild')
        and config.get('Entrypoint') == [ENTRYPOINT,'-I','-B','-m',MODULE]
        and config.get('User') == '65532:65532' and config.get('WorkingDir') == '/scratch')
    command = config.get('Cmd')
    require(command is None or (type(command) is list and len(command) == 0))
    labels = config.get('Labels')
    require(type(labels) is dict and set(labels) == {'org.kapit.owner','org.kapit.reservation'}
        and labels['org.kapit.owner'] == 'kapit-public-native-runtime-v1'
        and type(labels['org.kapit.reservation']) is str
        and base.TOKEN.fullmatch(labels['org.kapit.reservation']) is not None)
    require(public._environment(config.get('Env')) == IMAGE_ENV)


def _original_create_id(raw):
    """Retain only the exact original create output, independently of exit code."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 256:return None
    try:value=raw.decode('ascii').strip()
    except UnicodeError:return None
    return value if base.ID.fullmatch(value) is not None else None


def verify_inspection(document, phase, *, container_id, running=False):
    """Exact new differences first, then old strict invariant checks unchanged."""
    require(type(document) is dict and document.get('Id') == container_id and document.get('Name') == '/' + phase.name
            and document.get('Image') == phase.candidate.image_id)
    config, host = document.get('Config'), document.get('HostConfig')
    require(type(config) is dict and type(host) is dict)
    memory, cpu, _ = LIMITS[phase.binding.mode]
    require(config.get('Labels') == phase.labels and config.get('Cmd') == phase.command
            and config.get('OpenStdin') is True and config.get('StdinOnce') is True and config.get('Tty') is False
            and config.get('Entrypoint') == [ENTRYPOINT] and not config.get('OnBuild'))
    require(type(host.get('Memory')) is int and host['Memory'] == memory
            and type(host.get('MemorySwap')) is int and host['MemorySwap'] == memory
            and 'OomKillDisable' in host and (host['OomKillDisable'] is False or host['OomKillDisable'] is None))
    limits = [{'Name': 'cpu', 'Soft': cpu, 'Hard': cpu}, {'Name': 'core', 'Soft': 0, 'Hard': 0},
              {'Name': 'fsize', 'Soft': base.SCRATCH, 'Hard': base.SCRATCH}, {'Name': 'nofile', 'Soft': 32, 'Hard': 32}]
    actual = host.get('Ulimits')
    require(type(actual) is list and len(actual) == 4 and all(type(x) is dict for x in actual))
    require(base.canonical(sorted(actual, key=lambda x:x.get('Name', ''))) == base.canonical(sorted(limits, key=lambda x:x['Name'])))
    opts = host.get('SecurityOpt')
    require(type(opts) is list and len(opts) == 2 and 'no-new-privileges=true' in opts)
    policies = [value[8:] for value in opts if type(value) is str and value.startswith('seccomp=')]
    try: require(len(policies) == 1 and base.canonical(json.loads(policies[0])) == base.canonical(public.startup_profile()))
    except Exception: raise NativeUnavailable() from None
    # Normalize only exact-checked new differences for the old immutable resource,
    # mount/namespace/identity/entrypoint/user/healthcheck checks.
    legacy = base.ProbePolicy(public.BASE_IMAGE, phase.candidate.image_id, phase.token, 'identity')
    old = deepcopy(document)
    old.update(Name='/' + legacy.name)
    old['Config'].update(Labels=legacy.labels, OpenStdin=False, Entrypoint=['/usr/local/bin/python3'],
                        Cmd=['-I', '-B', '-c', base.probe_program(), 'identity'])
    old['HostConfig'].update(Memory=base.MEMORY, MemorySwap=base.MEMORY,
        Ulimits=[dict(value, Soft=2, Hard=2) if value['Name']=='cpu' else value for value in limits],
        SecurityOpt=['no-new-privileges=true', 'seccomp=' + base.canonical(base.seccomp_profile()).decode('ascii')])
    try: base.verify_inspection(old, legacy, container_id=container_id, running=running)
    except Exception: raise NativeUnavailable() from None


class _BoundedReader:
    def __init__(self, pipe, limit): self.pipe, self.limit, self.count = pipe, limit, 0

    def read(self, size):
        require(type(size) is int and 0 <= size <= 5242880)
        # os.read returns available bytes. Buffered read(4096) can wait forever on
        # a READY frame shorter than4096 while the child awaits the request.
        data = os.read(self.pipe.fileno(), min(size, 65536)) if size else b''
        self.count += len(data)
        require(self.count <= self.limit)
        return data


def _exchange(argv, binding, data, media, *, live_check):
    """Internal capability only: caller never supplies callbacks via public API."""
    process = None; threads = []; ready = threading.Event(); failed = threading.Event(); finished = threading.Event()
    writer_done = threading.Event(); result = []; completed = False
    deadline = time.monotonic() + LIMITS[binding.mode][2]
    def fail(): failed.set()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, shell=False, bufsize=0, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            env={key:value for key,value in os.environ.items() if key.upper() in {'SYSTEMROOT','WINDIR','TEMP','TMP'}})
        def output():
            try:
                stream = _BoundedReader(process.stdout, 65536 if binding.mode == 'scan' else OUTPUT_LIMIT)
                protocol.read_ready(stream, binding); ready.set()
                result.append(protocol.read_result(stream, binding))
            except BaseException: fail()
            finally: finished.set()
        def errors():
            try:
                total = 0
                while True:
                    block = os.read(process.stderr.fileno(), 4096)
                    if not block: return
                    total += len(block)
                    require(total <= STDERR_LIMIT)
            except BaseException: fail()
        def write():
            try: protocol.write_request(process.stdin, binding, data, media)
            except BaseException: fail()
            finally:
                try: process.stdin.close()
                except BaseException: fail()
                writer_done.set()
        def start(target):
            thread = threading.Thread(target=target, daemon=True); threads.append(thread); thread.start()
        start(output); start(errors)
        while not ready.wait(.01):
            require(not failed.is_set() and not finished.is_set() and time.monotonic() < deadline and process.poll() is None)
        require(not failed.is_set() and not finished.is_set() and time.monotonic() < deadline)
        live_check(deadline - time.monotonic())  # Bound live inspection to remaining phase wall time.
        require(not failed.is_set() and not finished.is_set() and time.monotonic() < deadline and process.poll() is None)
        start(write)
        while not (finished.is_set() and writer_done.is_set() and process.poll() is not None):
            require(not failed.is_set() and time.monotonic() < deadline)
            time.sleep(.01)
        require(not failed.is_set() and len(result) == 1 and time.monotonic() < deadline)
        header, payload = result[0]
        expected = 0 if header['code'] in {'SCAN_CLEAN', 'DECODE_COMPLETE'} else 2
        require(type(process.returncode) is int and process.returncode == expected)
        completed = True
        return header, payload, process.returncode
    except NativeUnavailable: raise
    except Exception: raise NativeUnavailable() from None
    finally:
        if process is not None:
            stopped, joined = False, True
            try:
                if process.poll() is None: process.kill()
                code = process.wait(timeout=5)
                stopped = type(code) is int and process.poll() is not None
            except BaseException: pass
            for thread in threads:
                if thread.ident is not None:
                    try: thread.join(timeout=5); joined = joined and not thread.is_alive()
                    except BaseException: joined = False
            if stopped and joined:
                for pipe in (process.stdin, process.stdout, process.stderr):
                    try: pipe.close()
                    except BaseException: joined = False
            require(stopped and joined, 'NATIVE_CLEANUP_UNCONFIRMED')
            # Stderr may report overflow/read failure only while its final join
            # completes. It must still invalidate a pending successful return.
            if completed: require(not failed.is_set())


def _phase(candidate, mode, data, media, *, fixture_id, stage, docker_path, profile_path):
    require(hashlib.sha256(Path(ownership_journal.__file__).read_bytes()).hexdigest() == OWNERSHIP_SHA256)
    binding = protocol.Binding(mode, secrets.token_hex(32), POLICY_SHA256, candidate.signature_generation)
    phase = _Phase(candidate, binding, uuid.uuid4().hex)
    container_id = None; created = False; result = None; cli_cleanup_uncertain = False
    def call(*args, timeout=15):
        nonlocal cli_cleanup_uncertain
        try:
            argv=[str(docker_path),'--host',base.ENDPOINT,*args]
            require(len(subprocess.list2cmdline(argv))<30000)
            return base._bounded_command(argv,timeout=timeout,maximum=1048576)
        except base.ContainerUnavailable as error:
            if error.code == 'CONTAINER_CLEANUP_UNCONFIRMED':
                cli_cleanup_uncertain = True
                raise NativeUnavailable('NATIVE_CLEANUP_UNCONFIRMED') from None
            raise NativeUnavailable() from None
        except Exception: raise NativeUnavailable() from None
    def document(*args, timeout=15):
        code, out, _, reason = call(*args, timeout=timeout)
        require(code == 0 and reason == 'EXIT')
        try: value = json.loads(out)
        except Exception: raise NativeUnavailable() from None
        require(type(value) is list and len(value) == 1 and type(value[0]) is dict)
        return value[0]
    def ownership(value):
        require(value.get('Id') == container_id and value.get('Name') == '/' + phase.name
                and value.get('Image') == candidate.image_id and value.get('Config', {}).get('Labels') == phase.labels)
    _require_cgroup_v2(call)
    image = document('image', 'inspect', candidate.image_id)
    verify_image(image,candidate)
    expected_env = EFFECTIVE_ENV
    code, out, _, reason = call('container','ls','--all','--no-trunc','--filter','name=^/'+phase.name+'$','--format','{{.ID}}')
    require(code == 0 and reason == 'EXIT' and not out.strip())
    try:
        with ownership_journal.reserve(token=phase.token,image_id=candidate.image_id,
                signature_generation=candidate.signature_generation,purpose='native-fixture',mode=mode,
                scenario=fixture_id,phase=stage,source_policy=POLICY_SHA256,expected_labels=phase.labels) as journal:
            journal_uncertain=False
            try:
                try:journal.mark_create_attempted()
                except BaseException:journal_uncertain=True;raise NativeUnavailable('NATIVE_CLEANUP_UNCONFIRMED') from None
                created = True
                code, out, _, reason = call(*create_args(phase, profile_path=profile_path))
                container_id = _original_create_id(out)
                if container_id is not None:
                    try:journal.record_original(container_id)
                    except BaseException:journal_uncertain=True;raise NativeUnavailable('NATIVE_CLEANUP_UNCONFIRMED') from None
                require(type(code) is int and code == 0 and reason == 'EXIT' and container_id is not None)
                # Normal inspection/start/input are forbidden until durable save,
                # ACL verification and read-pin all complete successfully.
                _require_cgroup_v2(call)
                before = document('container','inspect',container_id)
                verify_inspection(before,phase,container_id=container_id)
                require(public._environment(before['Config'].get('Env')) == expected_env)
                def live(remaining):
                    require(type(remaining) is float and remaining > 0)
                    live_deadline = time.monotonic()+remaining
                    _require_cgroup_v2(call,timeout=min(15,remaining))
                    inspect_remaining = live_deadline-time.monotonic()
                    require(inspect_remaining > 0)
                    current = document('container','inspect',container_id,timeout=min(15,inspect_remaining))
                    verify_inspection(current,phase,container_id=container_id,running=True)
                    require(type(current['State'].get('Pid')) is int and current['State']['Pid'] > 0
                            and public._environment(current['Config'].get('Env')) == expected_env)
                header, payload, exit_code = _exchange([str(docker_path),'--host',base.ENDPOINT,'container','start','--attach','--interactive',container_id],
                                                     binding,data,media,live_check=live)
                _require_cgroup_v2(call)
                after = document('container','inspect',container_id)
                verify_inspection(after,phase,container_id=container_id)
                require(public._environment(after['Config'].get('Env')) == expected_env
                        and after['State'].get('OOMKilled') is False and type(after['State'].get('Pid')) is int and after['State']['Pid'] == 0
                        and type(after['State'].get('ExitCode')) is int and after['State']['ExitCode'] == exit_code)
                result = (header,payload)
            finally:
                status='NOT_CREATED';uncertain=False
                try:
                    if created:
                        if container_id is None:
                            code,out,_,reason=call('container','ls','--all','--no-trunc','--filter','name=^/'+phase.name+'$','--format','{{.ID}}')
                            require(code == 0 and reason == 'EXIT' and not out.strip())
                            status='CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED'
                        else:
                            # Root-authorized cleanup-only inspection is permitted
                            # after a durable-save failure; never normal execution.
                            value=document('container','inspect',container_id);ownership(value)
                            if value['State'].get('Running'):call('container','kill','--signal','KILL',container_id)
                            value=document('container','inspect',container_id);ownership(value)
                            require(value['State'].get('Running') is False and value['State'].get('Restarting') is False
                                    and type(value['State'].get('Pid')) is int and value['State']['Pid']==0)
                            code,_,_,reason=call('container','rm',container_id);require(code==0 and reason=='EXIT')
                            code,out,_,reason=call('container','ls','--all','--no-trunc','--filter','id='+container_id,'--format','{{.ID}}')
                            require(code==0 and reason=='EXIT' and not out.strip())
                            status='ORIGINAL_ID_ABSENT_VERIFIED'
                    require(not cli_cleanup_uncertain and not journal_uncertain)
                except BaseException:uncertain=True
                try:journal.finish('CLEANUP_UNCONFIRMED' if uncertain else status)
                except BaseException:uncertain=True
                if uncertain:raise NativeUnavailable('NATIVE_CLEANUP_UNCONFIRMED') from None
    except ownership_journal.OwnershipUnavailable:
        raise NativeUnavailable('NATIVE_CLEANUP_UNCONFIRMED') from None
    return result


def run_fixture_pipeline(candidate, fixture_id, *, docker_path, profile_path):
    """Root-only candidate test. Image bytes are obtainable ONLY by fixed ID."""
    require(type(candidate) is Candidate and os.name == 'nt')
    try: public_fixture = fixture(fixture_id)
    except Exception: raise NativeUnavailable() from None
    docker_path, profile_path = Path(docker_path), Path(profile_path)
    require(docker_path.is_absolute() and profile_path.is_absolute())
    from infra.evidence_tools import Windows
    api = Windows()
    with api.pin(docker_path), api.pin(profile_path), api.pin(Path(ownership_journal.__file__),private=False):
        require(profile_path.read_bytes() == base.canonical(public.startup_profile()))
        original, _ = _phase(candidate,'scan',public_fixture.data,public_fixture.media_type,fixture_id=fixture_id,stage='original_scan',docker_path=docker_path,profile_path=profile_path)
        require(original['code'] == public_fixture.expected_original_code)
        codes = [original['code']]
        width = height = None
        if original['code'] == 'SCAN_CLEAN':
            decoded, derivative = _phase(candidate,'decode',public_fixture.data,public_fixture.media_type,fixture_id=fixture_id,stage='decode',docker_path=docker_path,profile_path=profile_path)
            require(decoded['code'] == 'DECODE_COMPLETE')
            info = inspect_container(derivative,'image/png',normalized=True)
            require(info.width == info.height == 1 and derivative_metadata_absent(derivative))
            codes.append(decoded['code']); width,height=info.width,info.height
            final,_ = _phase(candidate,'scan',derivative,'image/png',fixture_id=fixture_id,stage='derivative_scan',docker_path=docker_path,profile_path=profile_path)
            require(final['code'] == 'SCAN_CLEAN');codes.append(final['code'])
        require(profile_path.read_bytes() == base.canonical(public.startup_profile()))
    return {'schema':1,'purpose':'PUBLIC_NATIVE_FIXTURE_ONLY','status':'EXPECTED_FIXTURE_OUTCOME',
            'phase_codes':codes,'phase_count':len(codes),'width':width,'height':height,
            'cleanup':'ALL_OWNED_CONTAINERS_ABSENT_VERIFIED','native_eligibility':'DISABLED','private_input_allowed':False}


def run_scan(*args, **kwargs): raise NativeUnavailable()
def decode(*args, **kwargs): raise NativeUnavailable()
