"""Fixed PUBLIC detection controls diagnostic; inert until sealed execution.

No private input, caller data/program/path/provider or activation API exists.
Historical helpers, worker, policy, profile and failure guards stay unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time
import uuid

IMAGE = 'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa'
GENERATION = '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3'
PROFILE_SHA256 = 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733'
PREPARATION_SHA256 = '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f'
CONSUMED_RECEIPT_SHA256 = '896d45b92c1db7ce640539ed9fff9fac017266c628b9839eb56b0f396eb02f7f'
PARSER_SHA256 = '137ebe3fcc2458e5ef56b4989371236385b0ab2fa4038812b24b9a7aa7336c03'
PROBE_SHA256 = '1da130bb36efcf1763b8de439164596ea0d8af659dd53188f0b1099c44088677'
CONTRACT = '5be9b2d4233f7db867f29d4594bf52726736df10566943cecf953bc1bf477db1'
OWNER = 'kapit-public-detection-controls-v1'
PURPOSE = 'public-detection-controls-only'
NAME_PREFIX = 'kapit-detection-controls-public-'
PHASE_ID = 'detection-controls:scan:comparison'
PHASES = (PHASE_ID,)
SCOPE = 'PUBLIC_DETECTION_CONTROLS_DIAGNOSTIC_ONLY'
SHA = re.compile('[0-9a-f]{64}\\Z')
TOKEN = re.compile('[0-9a-f]{32}\\Z')


def _modules():
    # Outer reviewed controller pins every transitive source before this first use.
    from infra import evidence_native_attestation as attestation
    from infra import evidence_native_runtime as runtime
    from infra import evidence_native_ownership as ownership
    from infra import evidence_container_native as public
    from infra import evidence_rmdir_profile as profile
    from infra import evidence_rmdir_diagnostic as mechanics
    from infra.native import detection_controls_probe as strict_probe
    from infra import evidence_detection_controls as telemetry
    from backend.apps.operations import evidence_scan_protocol as protocol
    return attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol


class NativeUnavailable(RuntimeError):
    def __init__(self, code='DETECTION_CONTROLS_NATIVE_REFUSED'):
        self.code = code if code in ('DETECTION_CONTROLS_NATIVE_REFUSED', 'DETECTION_CONTROLS_NATIVE_CLEANUP_UNCONFIRMED') else 'DETECTION_CONTROLS_NATIVE_REFUSED'
        super().__init__(self.code)


def require(value):
    if value is not True: raise NativeUnavailable()


def _program():
    """Fixed bounded child bytes, authenticated before embedding and in child."""
    with (Path(__file__).resolve().parents[1] / 'infra/native/detection_controls_probe.py').open('rb') as stream:
        raw = stream.read(262145)
    require(type(raw) is bytes and 0 < len(raw) <= 262144 and
            hashlib.sha256(raw).hexdigest() == PROBE_SHA256)
    encoded = base64.b64encode(raw).decode('ascii')
    result = ("import base64,hashlib\nraw=base64.b64decode('"+encoded+"',validate=True)\n"
        "assert hashlib.sha256(raw).hexdigest()=='"+PROBE_SHA256+"'\n"
        "exec(compile(raw,'<fixed-public-detection-controls>','exec'),{'__name__':'__main__'})\n")
    require(len(result) < 26000)
    return result


def _attach(argv, *, timeout):
    """Owned fixed CLI transport: bounded drains and explicit closure evidence.

    The sealed phase constructs argv. No native diagnostics or arbitrary errors
    are returned. Reader late failures/overflow remain sticky after process exit.
    """
    require(type(timeout) in (int, float) and not isinstance(timeout, bool)
            and 0 < timeout <= 180)
    process = None
    threads = []
    failed = False
    reaped = False
    output = bytearray()
    signal = threading.Event()
    deadline = time.monotonic() + timeout

    def drain(stream, limit, retain):
        total = 0
        try:
            while True:
                chunk = stream.read(1024)
                if type(chunk) is not bytes:
                    signal.set()
                    return
                if not chunk:
                    return
                total += len(chunk)
                if total > limit:
                    signal.set()
                    return
                if retain:
                    output.extend(chunk)
        except BaseException:
            signal.set()

    code = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, bufsize=0, close_fds=True,
            env={key:os.environ[key] for key in ('SYSTEMROOT','WINDIR','TEMP','TMP') if key in os.environ},
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        require(process.stdin is not None and process.stdout is not None and process.stderr is not None)
        # Empty stdin stays open throughout the attach, then closes in finalizer.
        for stream, limit, retain in ((process.stdout, 4096, True), (process.stderr, 16384, False)):
            thread = threading.Thread(target=drain, args=(stream, limit, retain), daemon=True)
            threads.append(thread)
            thread.start()
        while True:
            require(not signal.is_set())
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            try:
                code = process.wait(timeout=min(0.1, remaining))
                reaped = True
                require(time.monotonic() < deadline)
                break
            except subprocess.TimeoutExpired:
                continue
        require(type(code) is int and code == 0)
    except BaseException:
        failed = True
    finally:
        if process is not None:
            if not reaped:
                try:
                    process.kill()
                except BaseException:
                    failed = True
                try:
                    code = process.wait(timeout=5)
                    reaped = type(code) is int
                except BaseException:
                    failed = True
            for thread in threads:
                try:
                    thread.join(timeout=5)
                    if thread.is_alive():
                        failed = True
                except BaseException:
                    failed = True
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                        if not stream.closed:
                            failed = True
                    except BaseException:
                        failed = True
            failed = failed or not reaped or signal.is_set()
            try:
                if not time.monotonic() < deadline:
                    failed = True
            except BaseException:
                failed = True
    if failed:
        raise NativeUnavailable('DETECTION_CONTROLS_NATIVE_CLEANUP_UNCONFIRMED')
    return code, bytes(output)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _binding(value):
    require(value.image_id == IMAGE and value.signature_generation == GENERATION and
            value.profile_sha256 == PROFILE_SHA256 and value.preparation_sha256 == PREPARATION_SHA256 and
            value.contract == CONTRACT and value.consumed_receipt_sha256 == CONSUMED_RECEIPT_SHA256 and
            value.parser_sha256 == PARSER_SHA256 and value.probe_sha256 == PROBE_SHA256)
    for name in ('native_sha256','controller_sha256','provenance_sha256'):
        digest = getattr(value, name)
        require(type(digest) is str and SHA.fullmatch(digest) is not None and digest != '0'*64)


def metadata(token, phase_id, binding):
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    require(type(token) is str and TOKEN.fullmatch(token) is not None and phase_id == PHASE_ID)
    _binding(binding)
    labels = {'org.kapit.owner':OWNER, 'org.kapit.run':token, 'org.kapit.reservation':token,
        'org.kapit.purpose':PURPOSE, 'org.kapit.mode':'scan', 'org.kapit.scenario':'comparison',
        'org.kapit.phase':'comparison', 'org.kapit.policy':runtime.POLICY_SHA256,
        'org.kapit.probe':PROBE_SHA256, 'org.kapit.generation':GENERATION,
        'org.kapit.profile':PROFILE_SHA256, 'org.kapit.preparation':PREPARATION_SHA256,
        'org.kapit.contract':CONTRACT}
    for name in ('native','controller','provenance','parser','probe','consumed_receipt'):
        labels['org.kapit.'+name] = getattr(binding,name+'_sha256')
    fixed = {'schema':1, 'token':token, 'image_id':IMAGE, 'signature_generation':GENERATION,
        'purpose':PURPOSE, 'mode':'scan', 'scenario':'comparison', 'phase':'comparison', 'phase_id':phase_id,
        'source_policy':runtime.POLICY_SHA256, 'source_sha256':PROBE_SHA256,
        'profile_sha256':PROFILE_SHA256, 'preparation_sha256':PREPARATION_SHA256,
        'proof_contract':CONTRACT, 'expected_name':NAME_PREFIX+token, 'expected_labels':labels,
        'native_eligible':False, 'private_input_allowed':False}
    for name in ('native','controller','provenance','parser','probe','consumed_receipt'):
        fixed[name+'_sha256'] = getattr(binding,name+'_sha256')
    ownership._canonical(fixed)
    return fixed


@contextmanager
def _reserve(fixed, binding):
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    require(type(fixed) is dict and _json(fixed) == _json(metadata(fixed.get('token'), fixed.get('phase_id'), binding)))
    host = ownership._Host(fixed['token'])
    journal = None
    try:
        host.__enter__()
        journal = ownership._Journal(host, fixed)
        journal._save('reservation.json', fixed)
        yield journal
    finally:
        if journal is None: host.close()
        elif not journal.closed: journal.finish('CLEANUP_UNCONFIRMED')


@dataclass(frozen=True)
class _Probe:
    phase: object
    fixed: dict
    command: list

    @property
    def name(self): return self.fixed['expected_name']

    @property
    def labels(self): return self.fixed['expected_labels']


def _probe(token, phase_id, binding):
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    fixed = metadata(token, phase_id, binding)
    phase = runtime._Phase(runtime.Candidate(IMAGE, GENERATION),
        protocol.Binding('scan', secrets.token_hex(32), runtime.POLICY_SHA256, GENERATION), token)
    return _Probe(phase, fixed, ['-I','-B','-c',_program()])


def create_args(probe, profile_path):
    """Retain every frozen mode/resource argument; fixed identity/program only."""
    _, runtime, *_ = _modules()
    source = runtime.create_args(probe.phase, profile_path=profile_path)
    require(source[-7:] == [IMAGE, *probe.phase.command])
    result = []
    index = 0
    while index < len(source)-7:
        if source[index] == '--label': index += 2; continue
        if source[index] == '--name': result.extend(['--name', probe.name]); index += 2; continue
        result.append(source[index]); index += 1
    for key, value in sorted(probe.labels.items()): result.extend(['--label', key+'='+value])
    result += [IMAGE, *probe.command]
    require(len(subprocess.list2cmdline(result)) < 30000)
    return result


def verify_inspection(value, probe, cid, *, running=False):
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    require(type(value) is dict and value.get('Id') == cid and value.get('Image') == IMAGE and
            value.get('Name') == '/'+probe.name and type(value.get('Config')) is dict and
            value['Config'].get('Labels') == probe.labels and value['Config'].get('Cmd') == probe.command and
            public._environment(value['Config'].get('Env')) == runtime.EFFECTIVE_ENV)
    normalized = profile.normalize_inspection(value)
    normalized['Name'] = '/'+probe.phase.name
    normalized['Config'].update(Labels=probe.phase.labels, Cmd=probe.phase.command)
    runtime.verify_inspection(normalized, probe.phase, container_id=cid, running=running)



def _details(value):
    _, _, _, _, _, _, _, parser, _ = _modules()
    require(type(value) is dict and set(value) == {'controls', 'comparison'})
    observation = parser.parse_detection_controls(_json({'schema_version': 1,
        'scope': 'PUBLIC_DETECTION_CONTROL_COMPARISON_ONLY', 'controls': value['controls'], 'completed': 3}), 0)
    require(type(value['comparison']) is str and
            value['comparison'] == parser.compare_detection_controls(observation).value)
    return deepcopy(value)


def _payload(raw, exit_code):
    failed = False
    result = None
    try:
        _, _, _, _, _, _, _, parser, _ = _modules()
        observation = parser.parse_detection_controls(raw, exit_code)
        result = {'controls': [{'id': name, 'category': getattr(observation, name)}
            for name in ('raw_upstream', 'png_strict', 'png_upstream')],
            'comparison': parser.compare_detection_controls(observation).value}
    except BaseException:
        failed = True
    if failed:
        raise NativeUnavailable()
    return result


def validate_outcome(phase_id, outcome):
    require(phase_id == PHASE_ID and type(outcome) is dict and set(outcome) ==
        {'phase_id','observed','details','native_eligible','private_input_allowed'} and
        outcome['phase_id'] == PHASE_ID and outcome['observed'] is True and
        outcome['native_eligible'] is False and outcome['private_input_allowed'] is False)
    _details(outcome['details'])
    return deepcopy(outcome)


def _check_context(context):
    from infra import evidence_detection_controls_controller as outer
    outer._validate_context(context)
    require(context.stage == 'diagnostic')
    _binding(context.binding)


def _phase(context):
    _check_context(context)
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    phase_id = PHASE_ID
    token = uuid.uuid4().hex
    require(context.before_phase(phase_id, token) is None)
    probe = _probe(token, phase_id, context.binding)
    args = create_args(probe, context.profile)
    cid = None; attempted = False; journal_uncertain = False
    primary = None; outcome = None
    started = time.monotonic()
    with _reserve(probe.fixed, context.binding) as journal:
        try:
            require(journal.mark_create_attempted() is None); attempted = True
            require(context.consume_before_create(phase_id) is None)
            code, output, error, reason = context.command(*args)
            cid = runtime._original_create_id(output)
            if cid is not None:
                require(context.retain_original(phase_id, token, cid) is None)
                try:
                    require(journal.record_original(cid) is None)
                    require(context.record_original(phase_id, token, cid) is None)
                except BaseException: journal_uncertain = True; raise
            require(type(code) is int and code == 0 and reason == 'EXIT' and not error and cid is not None)
            runtime._require_cgroup_v2(context.command)
            verify_inspection(mechanics.inspect(context.command, cid), probe, cid)
            runtime._require_cgroup_v2(context.command)
            argv = [str(context.docker), '--host', mechanics.modules()[0].HOST, '--config', str(context.config),
                    'container', 'start', '--attach', '--interactive', cid]
            context.attach_started()
            try:
                exit_code, raw = _attach(argv, timeout=context.attach_timeout())
            except BaseException:
                context.attach_finalized(False)
                raise
            else:
                context.attach_finalized(True)
            details = _payload(raw, exit_code)
            # Finite observations must still pass every stopped-state gate.
            runtime._require_cgroup_v2(context.command)
            after = mechanics.inspect(context.command, cid)
            verify_inspection(after, probe, cid)
            state = after['State']
            require(state.get('OOMKilled') is False and type(state.get('Pid')) is int and state['Pid'] == 0 and
                    type(state.get('ExitCode')) is int and state['ExitCode'] == exit_code)
            outcome = validate_outcome(phase_id, {'phase_id':phase_id,
                'observed':True,
                'details':details, 'native_eligible':False, 'private_input_allowed':False})
            require(time.monotonic()-started < runtime.LIMITS['scan'][2]+60)
        except BaseException as error:
            primary = error
            outcome = None
        finally:
            uncertain = False
            try: status = mechanics.cleanup(context.cleanup_command, probe, cid, attempted)
            except BaseException: status = 'CLEANUP_UNCONFIRMED'; uncertain = True
            uncertain = uncertain or context.call_uncertain or journal_uncertain or journal.failed
            try: require(journal.finish('CLEANUP_UNCONFIRMED' if uncertain else status) is None)
            except BaseException: uncertain = True
            try:
                accepted = context.finish_phase(phase_id, token, cid, 'CLEANUP_UNCONFIRMED' if uncertain else status,
                                                None if uncertain else outcome)
                require(type(accepted) is bool)
                if not accepted and primary is None: primary = NativeUnavailable()
            except BaseException: uncertain = True
            if uncertain: raise NativeUnavailable('DETECTION_CONTROLS_NATIVE_CLEANUP_UNCONFIRMED') from None
        if primary is not None: raise NativeUnavailable() from None
    require(outcome is not None)
    return outcome


def execute(context):
    """Sole sealed controller context; no caller-selected native behavior."""
    failed = False
    result = None
    try:
        _check_context(context)
        require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == context.binding.native_sha256)
        attestation, *_ = _modules()
        attestation._pins()
        result = _phase(context)
    except BaseException:
        failed = True
    if failed:
        raise NativeUnavailable()
    return result
