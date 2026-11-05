"""Exact-profile PUBLIC matrices; inert until the sealed outer context executes.

No private input, caller data/program/path/provider or activation API exists.
Historical helpers, worker, policy, profile and failure guards stay unchanged.
"""
from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
import uuid

from infra import evidence_native_attestation as attestation
from infra import evidence_native_runtime as runtime
from infra import evidence_native_ownership as ownership
from infra import evidence_container_native as public
from infra import evidence_rmdir_profile as profile
from infra import evidence_rmdir_diagnostic as mechanics
from infra import evidence_native_fixtures as fixtures
from infra.native import pcre_probe, strict_probe
from backend.apps.operations import evidence_scan_protocol as protocol
from backend.apps.operations.evidence_policy import inspect_container

IMAGE = 'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa'
GENERATION = '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3'
PROFILE_SHA256 = 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733'
PREPARATION_SHA256 = '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f'
CONTRACT = '062dd3e446b62e52bef1ee04d630db0441dd1360e46d4751807747f5e7bcdf7f'
OWNER = 'kapit-public-rmdir-proof-v1'
NAME_PREFIX = 'kapit-rmdir-proof-public-'
SCOPE = 'PUBLIC_RMDIR_PROFILE_NATIVE_MATRICES_ONLY'
FIXTURES = ('png_clean', 'png_metadata', 'jpeg_clean', 'jpeg_metadata', 'png_malformed', 'png_eicar')
SCENARIOS = ('confinement', 'preopened_fd', 'shm_namespace', 'storage', 'x32')
PHASES = tuple('confinement:'+mode+':'+case for mode in ('scan', 'decode') for case in SCENARIOS) + (
    'strict:scan:strict', 'pcre:scan:pcre') + tuple('fixture:'+name+':'+part for name in FIXTURES
    for part in (('original', 'decode', 'derivative') if name in FIXTURES[:4] else ('original',)))
STAGES = ('confinement', 'strict', 'pcre', 'fixtures')
SHA = re.compile('[0-9a-f]{64}\\Z')
TOKEN = re.compile('[0-9a-f]{32}\\Z')


class NativeUnavailable(RuntimeError):
    def __init__(self, code='RMDIR_NATIVE_REFUSED'):
        self.code = code if code in ('RMDIR_NATIVE_REFUSED', 'RMDIR_NATIVE_CLEANUP_UNCONFIRMED') else 'RMDIR_NATIVE_REFUSED'
        super().__init__(self.code)


def require(value):
    if value is not True: raise NativeUnavailable()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def stage_phases(stage):
    require(type(stage) is str and stage in STAGES)
    prefix = 'fixture:' if stage == 'fixtures' else stage+':'
    return tuple(value for value in PHASES if value.startswith(prefix))


def _parts(phase_id):
    require(type(phase_id) is str and phase_id in PHASES)
    kind, middle, last = phase_id.split(':')
    return kind, ('decode' if last == 'decode' else 'scan') if kind == 'fixture' else middle, middle if kind == 'fixture' else last, last if kind == 'fixture' else 'probe'


def _binding(value):
    require(value.image_id == IMAGE and value.signature_generation == GENERATION and
            value.profile_sha256 == PROFILE_SHA256 and value.preparation_sha256 == PREPARATION_SHA256 and
            value.contract == CONTRACT and type(value.native_sha256) is str and SHA.fullmatch(value.native_sha256) is not None and
            value.native_sha256 != '0'*64 and type(value.controller_sha256) is str and SHA.fullmatch(value.controller_sha256) is not None and
            value.controller_sha256 != '0'*64)


def metadata(token, phase_id, binding):
    """Closed versioned metadata only; old ownership allowlist is untouched."""
    require(type(token) is str and TOKEN.fullmatch(token) is not None)
    _binding(binding)
    kind, mode, scenario, part = _parts(phase_id)
    source = '3cebed0fbccb579dc6890f28071b80936d194876c69957eb4820f2564713c991' if kind == 'fixture' else (
        ownership.STRICT_PROBE if kind == 'strict' else ownership.PCRE_PROBE if kind == 'pcre' else ownership.PUBLIC_PROBE)
    labels = {'org.kapit.owner': OWNER, 'org.kapit.run': token, 'org.kapit.reservation': token,
        'org.kapit.purpose': 'public-rmdir-proof-only', 'org.kapit.mode': mode,
        'org.kapit.policy': runtime.POLICY_SHA256, 'org.kapit.scenario': scenario, 'org.kapit.phase': part,
        'org.kapit.probe': source, 'org.kapit.profile': PROFILE_SHA256,
        'org.kapit.preparation': PREPARATION_SHA256, 'org.kapit.native': binding.native_sha256,
        'org.kapit.contract': CONTRACT}
    fixed = {'schema': 1, 'token': token, 'image_id': IMAGE, 'signature_generation': GENERATION,
        'purpose': 'public-rmdir-proof-only', 'mode': mode, 'scenario': scenario, 'phase': part,
        'phase_id': phase_id, 'source_policy': runtime.POLICY_SHA256, 'source_sha256': source,
        'profile_sha256': PROFILE_SHA256, 'preparation_sha256': PREPARATION_SHA256,
        'native_sha256': binding.native_sha256, 'proof_contract': CONTRACT,
        'expected_name': NAME_PREFIX+token, 'expected_labels': labels,
        'native_eligible': False, 'private_input_allowed': False}
    ownership._canonical(fixed)
    return fixed


@contextmanager
def _reserve(fixed, binding):
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
    fixed = metadata(token, phase_id, binding)
    kind, mode, scenario, _ = _parts(phase_id)
    phase = runtime._Phase(runtime.Candidate(IMAGE, GENERATION),
        protocol.Binding(mode, secrets.token_hex(32), runtime.POLICY_SHA256, GENERATION), token)
    if kind == 'fixture': command = phase.command
    elif kind == 'strict': command = ['-I', '-B', '-c', attestation._strict_program()]
    elif kind == 'pcre': command = ['-I', '-B', '-c', attestation._pcre_program()]
    else: command = ['-I', '-B', '-c', public.probe_program(), scenario]
    return _Probe(phase, fixed, command)


def create_args(probe, profile_path):
    """Retain every frozen mode/resource argument; fixed identity/program only."""
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
    require(type(value) is dict and value.get('Id') == cid and value.get('Image') == IMAGE and
            value.get('Name') == '/'+probe.name and type(value.get('Config')) is dict and
            value['Config'].get('Labels') == probe.labels and value['Config'].get('Cmd') == probe.command and
            public._environment(value['Config'].get('Env')) == runtime.EFFECTIVE_ENV)
    normalized = profile.normalize_inspection(value)
    normalized['Name'] = '/'+probe.phase.name
    normalized['Config'].update(Labels=probe.phase.labels, Cmd=probe.phase.command)
    runtime.verify_inspection(normalized, probe.phase, container_id=cid, running=running)


def _payload(phase_id, raw, exit_code):
    kind, _, scenario, _ = _parts(phase_id)
    require(type(exit_code) is int and type(raw) is bytes and len(raw) <= 65536)
    try:
        if kind == 'strict':
            value = attestation._strict_payload(raw)
            require(exit_code == 0 and value['completed'] is True and value['passed'] is True and
                    tuple(row['case'] for row in value['cases']) == strict_probe.CASE_IDS)
        elif kind == 'pcre':
            value = pcre_probe.parse_success(raw)
            require(exit_code == 0 and tuple(row['case'] for row in value['cases']) == pcre_probe.CASE_IDS)
        else:
            require(kind == 'confinement' and exit_code == (159 if scenario == 'x32' else 0))
            value = public._payload(raw, scenario)
    except Exception:
        failure = NativeUnavailable()
        if kind in ('strict', 'pcre'):
            try:
                summary = (strict_probe if kind == 'strict' else pcre_probe).parse_failure(raw)
                failure.failure_summary = _finite_failure(kind, summary)
            except Exception: pass
        raise failure from None
    return value


def _finite_failure(kind, summary):
    require(kind in ('strict', 'pcre'))
    keys = {'diagnostic', 'completed', 'passed', 'case_count', 'native_eligible'}
    if kind == 'pcre': keys.add('harness_cleanup')
    maximum = 14 if kind == 'strict' else 8
    require(type(summary) is dict and set(summary) == keys and type(summary['completed']) is bool and
            summary['passed'] is False and summary['native_eligible'] is False and
            type(summary['case_count']) is int and 0 <= summary['case_count'] <= maximum and
            (not summary['completed'] or summary['case_count'] == maximum))
    if kind == 'pcre': require(type(summary['harness_cleanup']) is bool)
    (strict_probe if kind == 'strict' else pcre_probe)._validate_diagnostic(summary['diagnostic'])
    return deepcopy(summary)


def validate_outcome(phase_id, outcome):
    require(type(outcome) is dict and set(outcome) == {'phase_id', 'passed', 'result', 'native_eligible', 'private_input_allowed'} and
            outcome['phase_id'] == phase_id and type(outcome['passed']) is bool and
            outcome['native_eligible'] is False and outcome['private_input_allowed'] is False)
    kind, _, scenario, part = _parts(phase_id)
    value = outcome['result']
    if outcome['passed'] is False:
        _finite_failure(kind, value)
        return deepcopy(outcome)
    if kind == 'fixture':
        require(type(value) is dict and set(value) == {'code', 'width', 'height'})
        expected = 'DECODE_COMPLETE' if part == 'decode' else 'SCAN_CLEAN' if part == 'derivative' else fixtures.fixture(scenario).expected_original_code
        require(type(value['code']) is str and value['code'] == expected)
        if part == 'decode': require(type(value['width']) is int and type(value['height']) is int and value['width'] == value['height'] == 1)
        else: require(value['width'] is None and value['height'] is None)
    else:
        _payload(phase_id, _json(value), 159 if scenario == 'x32' else 0)
    return deepcopy(outcome)


def validate_result(stage, result):
    require(type(result) is dict and set(result) == {'schema', 'scope', 'stage', 'status', 'results', 'phase_count', 'native_eligible', 'private_input_allowed'} and
            type(result['schema']) is int and result['schema'] == 1 and result['scope'] == SCOPE and result['stage'] == stage and
            result['status'] == 'VERIFIED' and result['native_eligible'] is False and result['private_input_allowed'] is False and
            type(result['results']) is list and type(result['phase_count']) is int)
    expected = stage_phases(stage)
    require(len(result['results']) == result['phase_count'] == len(expected))
    for phase_id, outcome in zip(expected, result['results']): require(validate_outcome(phase_id, outcome)['passed'] is True)
    return deepcopy(result)


def _check_context(context, stage):
    from infra import evidence_rmdir_proof as outer
    outer._validate_context(context, stage)
    require(outer.PHASES == PHASES and context.stage == stage)
    _binding(context.binding)


def _phase(context, phase_id, *, data=None, media=None):
    kind, _, _, _ = _parts(phase_id)
    _check_context(context, 'fixtures' if kind == 'fixture' else kind)
    token = uuid.uuid4().hex
    context.before_phase(phase_id, token)
    probe = _probe(token, phase_id, context.binding)
    args = create_args(probe, context.profile)
    cid = None; attempted = False; journal_uncertain = False
    primary = None; outcome = None; returned = None
    started = time.monotonic()
    with _reserve(probe.fixed, context.binding) as journal:
        try:
            journal.mark_create_attempted(); attempted = True
            context.consume_before_create(phase_id)
            code, output, error, reason = context.command(*args)
            cid = runtime._original_create_id(output)
            if cid is not None:
                context.retain_original(phase_id, token, cid)
                try:
                    journal.record_original(cid)
                    context.record_original(phase_id, token, cid)
                except BaseException: journal_uncertain = True; raise
            require(type(code) is int and code == 0 and reason == 'EXIT' and not error and cid is not None)
            runtime._require_cgroup_v2(context.command)
            verify_inspection(mechanics.inspect(context.command, cid), probe, cid)
            runtime._require_cgroup_v2(context.command)
            argv = [str(context.docker), '--host', mechanics.modules()[0].HOST, '--config', str(context.config),
                    'container', 'start', '--attach', '--interactive', cid]
            if phase_id.startswith('fixture:'):
                def live(remaining):
                    require(type(remaining) is float and remaining > 0)
                    deadline = time.monotonic()+remaining
                    runtime._require_cgroup_v2(context.command, timeout=min(15, remaining))
                    left = deadline-time.monotonic(); require(left > 0)
                    code, raw, error, reason = context.command('container', 'inspect', cid, timeout=min(15, left))
                    require(type(code) is int and code == 0 and reason == 'EXIT' and not error)
                    from infra.evidence_native_refresh import document
                    values = document(raw)
                    require(type(values) is list and len(values) == 1)
                    verify_inspection(values[0], probe, cid, running=True)
                    require(type(values[0]['State'].get('Pid')) is int and values[0]['State']['Pid'] > 0)
                header, payload, exit_code = runtime._exchange(argv, probe.phase.binding, data, media, live_check=live)
                kind, _, scenario, part = _parts(phase_id)
                result = {'code': header['code'], 'width': None, 'height': None}
                if part == 'decode':
                    info = inspect_container(payload, 'image/png', normalized=True)
                    require(info.width == info.height == 1 and fixtures.derivative_metadata_absent(payload))
                    require(type(header.get('width')) is int and type(header.get('height')) is int and header['width'] == header['height'] == 1)
                    result.update(width=1, height=1)
                returned = (header, payload)
            else:
                exit_code, raw = attestation._attach(argv, timeout=runtime.LIMITS[probe.phase.binding.mode][2])
                result = _payload(phase_id, raw, exit_code)
            runtime._require_cgroup_v2(context.command)
            after = mechanics.inspect(context.command, cid)
            verify_inspection(after, probe, cid)
            state = after['State']
            require(state.get('OOMKilled') is False and type(state.get('Pid')) is int and state['Pid'] == 0 and
                    type(state.get('ExitCode')) is int and type(exit_code) is int and state['ExitCode'] == exit_code)
            outcome = validate_outcome(phase_id, {'phase_id': phase_id, 'passed': True, 'result': result,
                'native_eligible': False, 'private_input_allowed': False})
            require(time.monotonic()-started < runtime.LIMITS[probe.phase.binding.mode][2]+60)
        except BaseException as error:
            primary = error; outcome = None
            if type(error) is NativeUnavailable and hasattr(error, 'failure_summary'):
                outcome = validate_outcome(phase_id, {'phase_id': phase_id, 'passed': False,
                    'result': error.failure_summary, 'native_eligible': False, 'private_input_allowed': False})
        finally:
            uncertain = False
            try: status = mechanics.cleanup(context.cleanup_command, probe, cid, attempted)
            except BaseException: status = 'CLEANUP_UNCONFIRMED'; uncertain = True
            uncertain = uncertain or context.call_uncertain or journal_uncertain or journal.failed
            try: journal.finish('CLEANUP_UNCONFIRMED' if uncertain else status)
            except BaseException: uncertain = True
            try:
                accepted = context.finish_phase(phase_id, token, cid, 'CLEANUP_UNCONFIRMED' if uncertain else status,
                                                None if uncertain else outcome)
                require(type(accepted) is bool)
                if not accepted and primary is None: primary = NativeUnavailable()
            except BaseException: uncertain = True
            if uncertain: raise NativeUnavailable('RMDIR_NATIVE_CLEANUP_UNCONFIRMED') from None
        if primary is not None: raise NativeUnavailable() from None
    require(outcome is not None)
    return outcome, returned


def execute(context, stage):
    """Only the fixed outer source constructs and validates this sealed context."""
    _check_context(context, stage)
    require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == context.binding.native_sha256)
    attestation._pins()
    outcomes = []
    if stage == 'fixtures':
        for name in FIXTURES:
            fixture = fixtures.fixture(name)
            original, _ = _phase(context, 'fixture:'+name+':original', data=fixture.data, media=fixture.media_type)
            outcomes.append(original)
            if fixture.expected_original_code == 'SCAN_CLEAN':
                decoded, (_, derivative) = _phase(context, 'fixture:'+name+':decode', data=fixture.data, media=fixture.media_type)
                outcomes.append(decoded)
                final, _ = _phase(context, 'fixture:'+name+':derivative', data=derivative, media='image/png')
                outcomes.append(final)
    else:
        for phase_id in stage_phases(stage):
            outcome, _ = _phase(context, phase_id)
            outcomes.append(outcome)
    return validate_result(stage, {'schema': 1, 'scope': SCOPE, 'stage': stage, 'status': 'VERIFIED',
        'results': outcomes, 'phase_count': len(outcomes), 'native_eligible': False, 'private_input_allowed': False})
