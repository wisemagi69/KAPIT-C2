"""Fixed PUBLIC strict failure category v2 diagnostic; inert until sealed execution.

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

IMAGE = 'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa'
GENERATION = '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3'
PROFILE_SHA256 = 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733'
PREPARATION_SHA256 = '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f'
FAILED_RECEIPT_SHA256 = '7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00'
TELEMETRY_SHA256 = 'dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'
CONTRACT = '0de876c7b300cba9eca275c63273e5910633cbdc9ab813127e404ea5c48a6e42'
OWNER = 'kapit-public-strict-category-v2'
PURPOSE = 'public-strict-category-v2-only'
NAME_PREFIX = 'kapit-strict-category-v2-public-'
PHASE_ID = 'strict-category-v2:scan:strict'
PHASES = (PHASE_ID,)
SCOPE = 'PUBLIC_STRICT_FAILURE_CATEGORY_V2_DIAGNOSTIC_ONLY'
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
    from infra.native import strict_probe
    from infra import evidence_strict_failure_categories as telemetry
    from backend.apps.operations import evidence_scan_protocol as protocol
    return attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol


class NativeUnavailable(RuntimeError):
    def __init__(self, code='STRICT_CATEGORY_V2_NATIVE_REFUSED'):
        self.code = code if code in ('STRICT_CATEGORY_V2_NATIVE_REFUSED', 'STRICT_CATEGORY_V2_NATIVE_CLEANUP_UNCONFIRMED') else 'STRICT_CATEGORY_V2_NATIVE_REFUSED'
        super().__init__(self.code)


def require(value):
    if value is not True: raise NativeUnavailable()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _binding(value):
    require(value.image_id == IMAGE and value.signature_generation == GENERATION and
            value.profile_sha256 == PROFILE_SHA256 and value.preparation_sha256 == PREPARATION_SHA256 and
            value.contract == CONTRACT and value.failed_receipt_sha256 == FAILED_RECEIPT_SHA256 and
            value.telemetry_sha256 == TELEMETRY_SHA256)
    for name in ('native_sha256','controller_sha256','provenance_sha256'):
        digest = getattr(value, name)
        require(type(digest) is str and SHA.fullmatch(digest) is not None and digest != '0'*64)


def metadata(token, phase_id, binding):
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    require(type(token) is str and TOKEN.fullmatch(token) is not None and phase_id == PHASE_ID)
    _binding(binding)
    labels = {'org.kapit.owner':OWNER, 'org.kapit.run':token, 'org.kapit.reservation':token,
        'org.kapit.purpose':PURPOSE, 'org.kapit.mode':'scan', 'org.kapit.scenario':'strict',
        'org.kapit.phase':'diagnostic', 'org.kapit.policy':runtime.POLICY_SHA256,
        'org.kapit.probe':ownership.STRICT_PROBE, 'org.kapit.generation':GENERATION,
        'org.kapit.profile':PROFILE_SHA256, 'org.kapit.preparation':PREPARATION_SHA256,
        'org.kapit.contract':CONTRACT}
    for name in ('native','controller','provenance','telemetry','failed_receipt'):
        labels['org.kapit.'+name] = getattr(binding,name+'_sha256')
    fixed = {'schema':1, 'token':token, 'image_id':IMAGE, 'signature_generation':GENERATION,
        'purpose':PURPOSE, 'mode':'scan', 'scenario':'strict', 'phase':'diagnostic', 'phase_id':phase_id,
        'source_policy':runtime.POLICY_SHA256, 'source_sha256':ownership.STRICT_PROBE,
        'profile_sha256':PROFILE_SHA256, 'preparation_sha256':PREPARATION_SHA256,
        'proof_contract':CONTRACT, 'expected_name':NAME_PREFIX+token, 'expected_labels':labels,
        'native_eligible':False, 'private_input_allowed':False}
    for name in ('native','controller','provenance','telemetry','failed_receipt'):
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
    return _Probe(phase, fixed, ['-I','-B','-c',attestation._strict_program()])


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
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    require(type(value) is dict and set(value) == {'schema','scope','private_input_allowed','diagnostic',
            'completed','passed','case_count','native_eligible','failed_case_ids','failed_cases'})
    require(type(value['schema']) is int and value['schema'] == 1 and value['scope'] == 'PUBLIC_STRICT_FAILURE_CATEGORIES_ONLY'
        and value['private_input_allowed'] is False and value['native_eligible'] is False and value['passed'] is False
        and type(value['completed']) is bool and type(value['case_count']) is int and 0 <= value['case_count'] <= 14)
    strict_probe._validate_diagnostic(value['diagnostic'])
    ids = value['failed_case_ids']
    require(type(ids) is list and all(type(item) is str for item in ids))
    require(ids == [item for item in strict_probe.CASE_IDS[:value['case_count']] if item in ids])
    rows = value['failed_cases']
    require(type(rows) is list and len(rows) == len(ids))
    expectations = {name:(kind,expected) for name,kind,expected in strict_probe.FAILURE_CASES}
    for name, row in zip(ids, rows):
        require(type(row) is dict and set(row) == {'case','strict','upstream','normalization_observed'}
            and type(row['case']) is str and row['case'] == name
            and type(row['strict']) is str and row['strict'] in ('CLEAN','NOT_CLEAN','ERROR')
            and type(row['upstream']) is str and row['upstream'] in ('CLEAN','NOT_CLEAN','ERROR','NOT_RUN')
            and type(row['normalization_observed']) is bool)
        kind, expected = expectations[name]
        require((row['upstream'] == 'NOT_RUN') is (kind == 'PRECONDITION'))
        passed = row['strict'] != 'CLEAN' if expected == 'NONCLEAN' else row['strict'] == expected
        require(passed is False and row['normalization_observed'] is
            (row['strict'] != 'CLEAN' and row['upstream'] == 'CLEAN'))
    require(not value['completed'] or (value['case_count'] == 14 and bool(ids)))
    return deepcopy(value)


def _payload(raw, exit_code):
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    require(type(exit_code) is int and exit_code == 2 and type(raw) is bytes and len(raw) <= 16384)
    try: return _details(telemetry.parse_failure_categories(raw))
    except Exception: raise NativeUnavailable() from None


def validate_outcome(phase_id, outcome):
    require(phase_id == PHASE_ID and type(outcome) is dict and set(outcome) ==
        {'phase_id','observed','details','native_eligible','private_input_allowed'} and
        outcome['phase_id'] == PHASE_ID and type(outcome['observed']) is bool and
        outcome['native_eligible'] is False and outcome['private_input_allowed'] is False)
    details = _details(outcome['details'])
    observed = details['completed'] and details['case_count'] == 14 and bool(details['failed_case_ids'])
    require(outcome['observed'] is observed)
    return deepcopy(outcome)


def _check_context(context):
    from infra import evidence_strict_category_v2_controller as outer
    outer._validate_context(context)
    require(context.stage == 'diagnostic')
    _binding(context.binding)


def _phase(context):
    _check_context(context)
    attestation, runtime, ownership, public, profile, mechanics, strict_probe, telemetry, protocol = _modules()
    phase_id = PHASE_ID
    token = uuid.uuid4().hex
    context.before_phase(phase_id, token)
    probe = _probe(token, phase_id, context.binding)
    args = create_args(probe, context.profile)
    cid = None; attempted = False; journal_uncertain = False
    primary = None; outcome = None
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
            context.attach_started()
            try:
                exit_code, raw = attestation._attach(argv, timeout=runtime.LIMITS['scan'][2])
            except BaseException:
                context.attach_finalized(False)
                raise
            else:
                context.attach_finalized(True)
            details = _payload(raw, exit_code)
            # Expected failure is data. It must still pass every stopped-state gate.
            runtime._require_cgroup_v2(context.command)
            after = mechanics.inspect(context.command, cid)
            verify_inspection(after, probe, cid)
            state = after['State']
            require(state.get('OOMKilled') is False and type(state.get('Pid')) is int and state['Pid'] == 0 and
                    type(state.get('ExitCode')) is int and state['ExitCode'] == exit_code)
            outcome = validate_outcome(phase_id, {'phase_id':phase_id,
                'observed':details['completed'] and details['case_count'] == 14 and bool(details['failed_case_ids']),
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
            try: journal.finish('CLEANUP_UNCONFIRMED' if uncertain else status)
            except BaseException: uncertain = True
            try:
                accepted = context.finish_phase(phase_id, token, cid, 'CLEANUP_UNCONFIRMED' if uncertain else status,
                                                None if uncertain else outcome)
                require(type(accepted) is bool)
                if not accepted and primary is None: primary = NativeUnavailable()
            except BaseException: uncertain = True
            if uncertain: raise NativeUnavailable('STRICT_CATEGORY_V2_NATIVE_CLEANUP_UNCONFIRMED') from None
        if primary is not None: raise NativeUnavailable() from None
    require(outcome is not None)
    return outcome


def execute(context):
    """Sole sealed controller context; no caller-selected native behavior."""
    _check_context(context)
    require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == context.binding.native_sha256)
    attestation, *_ = _modules()
    attestation._pins()
    return _phase(context)
