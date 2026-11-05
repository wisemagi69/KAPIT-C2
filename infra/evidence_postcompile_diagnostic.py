"""One fixed PUBLIC postcompile diagnostic. Import is inert; CLI has no options.

This distinct diagnostic cannot clear a strict-suite failure or private ingress.
Only the orchestrator executes this module; tests replace every host boundary.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
STAGE = '.cache/m1-runtime/private-scanner-build'
PRIOR_RECEIPT = 'ai/state/private-scanner-postcompile-diagnostic-pcre.json'
PRIOR_RECEIPT_SHA256 = '3a806b13312656a8436bb1efad91f600ffe14cf53032e2a0255e4a05428dc9b5'
RECEIPT = 'ai/state/private-scanner-postcompile-diagnostic-v2-pcre.json'
PROGRAM = 'infra/native/postcompile_probe.py'
PROGRAM_SHA256 = 'a923bf94a91fe07183ea8964eba46fc7bdb92352fa6d9f017d3c0dd031f1ecb3'
IMAGE = 'sha256:bff3b3ae6dfa4115c40f7348efac5ecded7cd437d0053a8af77db1c079af1463'
GENERATION = '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3'
ENGINE = 'ddd3c2221b89b743c98388fa5a6d127bf00c088f0c9566b963244caa1e892557'
OLD_TOKEN = '7fe9d29d175d4df0858a1b72875db394'
OLD_CID = '98f45dbac6d159ae9a7e5f9db7d72d77aabb785614b6bfd4ffbb21badf9cd597'
OLD_NAME = 'kapit-same-image-public-' + OLD_TOKEN
OLD_FAILURE = 'ai/state/private-scanner-refresh-suite-pcre-strict-0f0d67983db84d5786024e86cb9a62b9.json'
OLD_POLICY = '1e2b71ab05a6905a3c9edfe056cf83ddb4df0170560f1f04a0e7978741358105'
OWNER = 'kapit-public-postcompile-diagnostic-v1'
PURPOSE = 'public-postcompile-readback-only'
PROFILE = STAGE + '/abi3-startup-profile.json'
PROFILE_SHA256 = '389b9d083fc90982a51f999c9cfc1858cb660654d8d01dd5bc28da0a4e0523a7'
SOURCE_PINS = {
    'infra/evidence_native_refresh_runtime.py': '685271a88da7d6af12b6c26a99373420b9af0195d5aa7cd6953cea5c51259b17',
    'infra/evidence_native_refresh.py': '15c4852888eb369d9b61a46516ced9b14813994fd76fd2cf20b325d00818bfc3',
    'infra/evidence_native_runtime.py': '69af8b1564726ddde37ea8aa49ebf86a4419118b474e1bbd9098279568775c82',
    'infra/evidence_native_attestation.py': 'f3394eb061eec6696132c331207e1160a89775694e9e1bd565569c8f6c2a6c73',
    'infra/evidence_native_ownership.py': '6544725a99a0d9941db347ea3c81b8d3e8ea8f58ae88886289c320ee6f2ef4d1',
    'infra/evidence_container.py': '921f26e53ea67ebb066d534f682cef7fed215c708fed9426b14231e1b1043628',
    'infra/evidence_container_native.py': '86573ad4bbe9078b47a805786fa2aaeaec003abbe734b87ad6bfd72e63c02c15',
    'infra/evidence_tools.py': 'b3d57248598364fabb208ea303a00139e27c5db1dc3746c95e32eda240f7202c',
    'infra/live_recovery_drill.py': 'cd6d9608399f0995b865da142611432b0c8a95ea1a9501b143dabebdc004388c',
    'backend/apps/operations/evidence_native_worker.py': '3cebed0fbccb579dc6890f28071b80936d194876c69957eb4820f2564713c991',
    'backend/apps/operations/evidence_scan_protocol.py': 'a7b277e7697e59e41b95014499f56276cde55af710b8065cb213fca0e5295973',
}
ORIGINAL_PINS = {
    OLD_FAILURE: ('7dfd5133d1d0fcf25a7e4d6855b0551660bf23a6a63bf2d0136c265825a67db0', 4218),
    STAGE + '/native-run-' + OLD_TOKEN + '/reservation.json': ('7091be03473976d9fc983c75eb38fd9568258421acb8bee77c29c273c4ca5ddc', 944),
    STAGE + '/native-run-' + OLD_TOKEN + '/create-attempt.json': ('a68c36ed7fcbaaffa0a2d1f84e33b6f55f96ec589261609e693bfd8e02b073dc', 103),
    STAGE + '/native-run-' + OLD_TOKEN + '/ownership.json': ('e07f70e5faf21e73eb407f5b98e7751ad2474e33db4dd1f53a970ff7602c87c8', 1025),
    STAGE + '/native-run-' + OLD_TOKEN + '/result.json': ('fe14d62fdc8d63209f050387adbe8b22e920e05724826339f106465828309262', 209),
}
FLOOR = 2 * 1024**3


class DiagnosticUnavailable(RuntimeError):
    def __init__(self, code='POSTCOMPILE_DIAGNOSTIC_REFUSED'):
        self.code = code
        super().__init__(code)


def require(value, code='POSTCOMPILE_DIAGNOSTIC_REFUSED'):
    if value is not True:
        raise DiagnosticUnavailable(code)


def modules():
    from infra import evidence_native_refresh_runtime as refresh
    from infra import evidence_native_runtime as runtime
    from infra import evidence_native_attestation as attestation
    from infra import evidence_native_ownership as ownership
    from infra import evidence_container as base
    return refresh, runtime, attestation, ownership, base


def original_documents(root, pins, api):
    refresh, _, _, _, _ = modules()
    from infra.live_recovery_drill import PrivateDirectory
    pins.enter_context(PrivateDirectory().pin(root / STAGE / ('native-run-' + OLD_TOKEN), private=True, directory=True))
    docs = {}
    for name, (expected, size) in ORIGINAL_PINS.items():
        raw = refresh.pin_bytes(root, pins, api, name, private=name.startswith(STAGE), expected=expected)
        require(len(raw) == size, 'ORIGINAL_BYTES_CHANGED')
        docs[Path(name).name] = refresh.document(raw)
    failure = docs[Path(OLD_FAILURE).name]
    require(failure.get('status') == 'REFUSED' and failure.get('image_id') == IMAGE
        and failure.get('signature_generation') == GENERATION and failure.get('native_eligible') is False
        and failure.get('private_input_allowed') is False and failure.get('active_case') == {'mode': 'scan', 'name': 'strict'}
        and failure.get('diagnostic', {}).get('result', {}).get('case_count') == 0,
        'ORIGINAL_FAILURE_CHANGED')
    labels = {'org.kapit.mode': 'scan', 'org.kapit.owner': 'kapit-same-image-public-probe-v1',
        'org.kapit.policy': OLD_POLICY, 'org.kapit.probe': '021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078',
        'org.kapit.purpose': 'same-image-public-only', 'org.kapit.reservation': OLD_TOKEN,
        'org.kapit.run': OLD_TOKEN, 'org.kapit.scenario': 'strict'}
    reservation = {'schema': 1, 'token': OLD_TOKEN, 'image_id': IMAGE, 'signature_generation': GENERATION,
        'purpose': 'same-image-probe', 'mode': 'scan', 'scenario': 'strict', 'phase': 'probe',
        'source_policy': OLD_POLICY, 'expected_name': OLD_NAME, 'expected_labels': labels, 'native_eligible': False}
    require(docs['reservation.json'] == reservation
        and docs['ownership.json'] == dict(reservation, original_id=OLD_CID)
        and docs['create-attempt.json'] == {'schema': 1, 'token': OLD_TOKEN, 'create_attempted': True, 'native_eligible': False}
        and docs['result.json'] == {'schema': 1, 'token': OLD_TOKEN, 'original_id': OLD_CID,
            'ownership_status': 'ORIGINAL_ID_ABSENT_VERIFIED', 'native_eligible': False}, 'ORIGINAL_JOURNAL_CHANGED')


class Commands:
    """Bounded fixed-endpoint authless controls; uncertainty is sticky."""
    def __init__(self, docker, config):
        self.docker, self.config = docker, config
        self.count = 0; self.uncertain = False

    def __call__(self, *args, timeout=15):
        refresh, _, _, _, base = modules()
        try:
            require(0 < timeout <= 15 and self.count < 64)
            self.count += 1
            argv = [str(self.docker), '--host', refresh.HOST, '--config', str(self.config), *args]
            require(len(subprocess.list2cmdline(argv)) < 30000)
            result = base._bounded_command(argv, timeout=timeout, maximum=65536)
            code, out, err, reason = result
            require(type(code) is int and type(out) is bytes and type(err) is bytes
                and len(out) <= 65536 and len(err) <= 65536 and reason == 'EXIT')
            return result
        except BaseException:
            self.uncertain = True
            raise


def engine(call):
    code, out, err, reason = call('info', '--format', '{{.ID}}')
    require(code == 0 and reason == 'EXIT' and not err and 1 <= len(out) <= 256)
    value = out.rstrip(b'\r\n')
    require(value and b'\n' not in value and b'\r' not in value
        and hashlib.sha256(value).hexdigest() == ENGINE, 'ENGINE_CHANGED')


def absent(call, selector):
    require(selector in (OLD_CID, OLD_NAME))
    code, out, err, reason = call('container', 'inspect', selector)
    require(type(code) is int and code == 1 and reason == 'EXIT'
        and out in (b'[]\n', b'[]\r\n', b'[]')
        and err in tuple(('Error response from daemon: No such container: ' + selector + ending).encode('ascii')
            for ending in ('\n', '\r\n', '')), 'ORIGINAL_ABSENCE_UNCONFIRMED')


class Observation:
    """Only created by fresh same-engine observations; no serialized clearance."""
    def __init__(self, seal, created, clock=time.monotonic):
        require(seal is _LIVE_SEAL)
        self.created, self.clock, self.used = created, clock, False

    def consume(self):
        require(not self.used and 0 <= self.clock() - self.created <= 5, 'LIVE_POSTFLIGHT_STALE')
        self.used = True


_LIVE_SEAL = object()


def observe_original(call):
    started = time.monotonic(); initial_count = call.count
    engine(call); absent(call, OLD_CID); absent(call, OLD_NAME); engine(call)
    require(not call.uncertain and call.count - initial_count == 4
        and time.monotonic() - started < 60, 'POSTFLIGHT_UNCONFIRMED')
    return Observation(_LIVE_SEAL, time.monotonic())


def metadata(token):
    """Closed new purpose; never accepts caller image, generation or labels."""
    _, _, _, ownership, _ = modules()
    require(type(token) is str and ownership.TOKEN.fullmatch(token) is not None
        and token != OLD_TOKEN and type(PROGRAM_SHA256) is str
        and ownership.HASH.fullmatch(PROGRAM_SHA256) is not None)
    labels = {'org.kapit.owner': OWNER, 'org.kapit.run': token, 'org.kapit.reservation': token,
        'org.kapit.purpose': PURPOSE, 'org.kapit.mode': 'scan', 'org.kapit.policy': OLD_POLICY,
        'org.kapit.scenario': 'postcompile', 'org.kapit.probe': PROGRAM_SHA256,
        'org.kapit.generation': GENERATION}
    result = {'schema': 1, 'token': token, 'image_id': IMAGE, 'signature_generation': GENERATION,
        'purpose': PURPOSE, 'mode': 'scan', 'scenario': 'postcompile', 'phase': 'diagnostic',
        'source_policy': OLD_POLICY, 'source_sha256': PROGRAM_SHA256,
        'expected_name': 'kapit-postcompile-public-' + token, 'expected_labels': labels,
        'native_eligible': False, 'private_input_allowed': False}
    ownership._canonical(result)
    return result


@contextmanager
def reserve(token):
    _, _, _, ownership, _ = modules()
    fixed = metadata(token); host = ownership._Host(token); journal = None
    try:
        host.__enter__()
        journal = ownership._Journal(host, fixed)
        journal._save('reservation.json', fixed)
        yield journal
    finally:
        if journal is None:
            host.close()
        elif not journal.closed:
            journal.finish('CLEANUP_UNCONFIRMED')


@dataclass(frozen=True)
class Probe:
    phase: object
    fixed: dict
    program: str

    @property
    def name(self): return self.fixed['expected_name']
    @property
    def labels(self): return self.fixed['expected_labels']
    @property
    def command(self): return ['-I', '-B', '-c', self.program]


def transport(raw):
    require(type(PROGRAM_SHA256) is str and type(raw) is bytes and 0 < len(raw) <= 16384
        and hashlib.sha256(raw).hexdigest() == PROGRAM_SHA256, 'PROGRAM_PIN_CHANGED')
    encoded = base64.b64encode(raw).decode('ascii')
    return ("import base64,hashlib\nraw=base64.b64decode('" + encoded + "',validate=True)\n"
        "assert hashlib.sha256(raw).hexdigest()=='" + PROGRAM_SHA256 + "'\n"
        "exec(compile(raw,'<fixed-public-postcompile>','exec'),{'__name__':'__main__'})\n")


def create_args(probe, profile):
    _, runtime, _, _, _ = modules()
    require(type(probe) is Probe and probe.fixed == metadata(probe.phase.token))
    original = runtime.create_args(probe.phase, profile_path=profile)
    require(original[-7:] == [IMAGE, *probe.phase.command])
    args = []; index = 0
    while index < len(original) - 7:
        if original[index] == '--label': index += 2; continue
        if original[index] == '--name': args.extend(['--name', probe.name]); index += 2; continue
        args.append(original[index]); index += 1
    for key, value in sorted(probe.labels.items()): args.extend(['--label', key + '=' + value])
    args += [IMAGE, *probe.command]
    require(len(subprocess.list2cmdline(args)) < 28000)
    return args


def inspection(value, probe, cid):
    _, runtime, _, _, _ = modules()
    from infra import evidence_container_native as public
    require(type(value) is dict and value.get('Id') == cid and value.get('Name') == '/' + probe.name
        and value.get('Image') == IMAGE and type(value.get('Config')) is dict
        and value['Config'].get('Labels') == probe.labels and value['Config'].get('Cmd') == probe.command)
    require(public._environment(value['Config'].get('Env')) == runtime.EFFECTIVE_ENV,
        'DIAGNOSTIC_ENVIRONMENT_CHANGED')
    normalized = deepcopy(value)
    normalized['Name'] = '/' + probe.phase.name
    normalized['Config'].update(Labels=probe.phase.labels, Cmd=probe.phase.command)
    runtime.verify_inspection(normalized, probe.phase, container_id=cid)


def inspect(call, selector):
    refresh, _, _, _, _ = modules()
    code, out, err, reason = call('container', 'inspect', selector)
    require(code == 0 and reason == 'EXIT' and not err)
    values = refresh.document(b'{"items":' + out + b'}')['items']
    require(type(values) is list and len(values) == 1 and type(values[0]) is dict)
    return values[0]


def check_owner(value, probe, cid):
    require(value.get('Id') == cid and value.get('Name') == '/' + probe.name and value.get('Image') == IMAGE
        and value.get('Config', {}).get('Labels') == probe.labels, 'DIAGNOSTIC_OWNERSHIP_UNCONFIRMED')


def cleanup(call, probe, cid, attempted):
    status = 'NOT_CREATED'
    if attempted:
        if cid is None:
            code, out, err, reason = call('container', 'ls', '--all', '--no-trunc', '--filter',
                'name=^/' + probe.name + '$', '--format', '{{.ID}}')
            require(code == 0 and reason == 'EXIT' and not out.strip() and not err)
            status = 'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED'
        else:
            value = inspect(call, cid); check_owner(value, probe, cid)
            if value.get('State', {}).get('Running') is True:
                code, _, err, reason = call('container', 'kill', '--signal', 'KILL', cid)
                require(code == 0 and reason == 'EXIT' and not err)
            value = inspect(call, cid); check_owner(value, probe, cid)
            state = value.get('State', {})
            require(state.get('Running') is False and state.get('Restarting') is False
                and type(state.get('Pid')) is int and state['Pid'] == 0)
            code, _, err, reason = call('container', 'rm', cid)
            require(code == 0 and reason == 'EXIT' and not err)
            code, out, err, reason = call('container', 'ls', '--all', '--no-trunc', '--filter', 'id=' + cid, '--format', '{{.ID}}')
            require(code == 0 and reason == 'EXIT' and not out.strip() and not err)
            status = 'ORIGINAL_ID_ABSENT_VERIFIED'
    return status


def run_probe(root, call, profile, raw, observation, result):
    _, runtime, attestation, _, _ = modules()
    from backend.apps.operations import evidence_scan_protocol as protocol
    from infra.native import postcompile_probe as program
    token = uuid.uuid4().hex
    phase = runtime._Phase(runtime.Candidate(IMAGE, GENERATION),
        protocol.Binding('scan', secrets.token_hex(32), OLD_POLICY, GENERATION), token)
    probe = Probe(phase, metadata(token), transport(raw))
    args = create_args(probe, profile)
    cid = None; attempted = False; journal_uncertain = False; primary = None; payload = None
    started = time.monotonic()
    with reserve(token) as journal:
        try:
            journal.mark_create_attempted()
            observation.consume()  # Sole consumption site, immediately before create.
            attempted = True
            code, out, err, reason = call(*args)
            cid = runtime._original_create_id(out)
            if cid is not None:
                try: journal.record_original(cid)
                except BaseException:
                    journal_uncertain = True
                    raise
            require(code == 0 and reason == 'EXIT' and not err and cid is not None)
            result['original_id'] = cid; result['reservation'] = token
            runtime._require_cgroup_v2(call)
            inspection(inspect(call, cid), probe, cid)
            runtime._require_cgroup_v2(call)
            attach_started = time.monotonic()
            cli_exit, output = attestation._attach([str(call.docker), '--host', modules()[0].HOST,
                '--config', str(call.config), 'container', 'start', '--attach', '--interactive', cid],
                timeout=runtime.LIMITS['scan'][2])
            require(time.monotonic() - attach_started < runtime.LIMITS['scan'][2], 'ATTACH_FINAL_DEADLINE')
            runtime._require_cgroup_v2(call)
            after = inspect(call, cid); inspection(after, probe, cid)
            state = after['State']
            require(type(cli_exit) is int and cli_exit == 0 and state.get('OOMKilled') is False
                and type(state.get('ExitCode')) is int and state['ExitCode'] == 0
                and type(state.get('Pid')) is int and state['Pid'] == 0)
            payload = program.parse_result(output)
            require(payload['completed'] is True)
        except BaseException as error:
            primary = error
        finally:
            uncertain = False
            try: status = cleanup(call, probe, cid, attempted)
            except BaseException: status = 'CLEANUP_UNCONFIRMED'; uncertain = True
            uncertain = uncertain or call.uncertain or journal_uncertain or journal.failed
            try: journal.finish('CLEANUP_UNCONFIRMED' if uncertain else status)
            except BaseException: uncertain = True
            result['cleanup'] = 'UNCONFIRMED' if uncertain else status
            if uncertain:
                raise DiagnosticUnavailable('DIAGNOSTIC_CLEANUP_UNCONFIRMED') from None
        require(time.monotonic() - started < 240 and shutil.disk_usage(root).free >= FLOOR,
            'DIAGNOSTIC_FINAL_LIMIT')
        if primary is not None: raise primary
    require(payload is not None)
    return payload


@contextmanager
def legacy_lock(api):
    """Exact existing launcher lock contract under the pinned protected stage.

    This one path must already exist. Never create, protect or rewrite it.
    Ordinary writable pin retains identity/reparse/hardlink protections.
    """
    import msvcrt
    with api.pin(ROOT / STAGE / 'resume-pcre.lock', writable=True) as lock:
        require(os.fstat(lock.fileno()).st_size == 1, 'LEGACY_LOCK_CHANGED')
        lock.seek(0)
        require(lock.read(2) == b'0', 'LEGACY_LOCK_CHANGED')
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        try: yield
        finally:
            lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def preserved_refusal(root, pins, api):
    """Fixed precreate failure provenance only; never live clearance."""
    refresh, _, _, _, _ = modules()
    raw = refresh.pin_bytes(root, pins, api, PRIOR_RECEIPT, expected=PRIOR_RECEIPT_SHA256)
    require(len(raw) == 503, 'PRIOR_REFUSAL_CHANGED')
    expected = {'schema': 1, 'scope': 'PUBLIC_POSTCOMPILE_CONTROLLER_DIAGNOSTIC_ONLY',
        'status': 'REFUSED', 'completed': False, 'control_state_modified': False,
        'native_eligible': False, 'pins_closed': True, 'private_input_allowed': False,
        'image_id': IMAGE, 'signature_generation': GENERATION,
        'failure_code': 'POSTCOMPILE_DIAGNOSTIC_REFUSED', 'total_seconds': 0.022}
    require(refresh.document(raw) == expected, 'PRIOR_REFUSAL_CHANGED')


def profile_source(root, pins, api):
    """Exact inherited public-profile pin contract; caller holds protected parent.

    The existing attestation pins this public file for identity, reparse and
    hardlink safety, then checks its fixed bytes. It is not a private-file DACL.
    """
    refresh, _, _, _, base = modules()
    from infra import evidence_container_native as public
    raw = refresh.pin_bytes(root, pins, api, PROFILE, expected=PROFILE_SHA256)
    require(raw == base.canonical(public.startup_profile()), 'PROFILE_BYTES_CHANGED')
    return raw


@contextmanager
def exclusive_lock(path, api):
    import msvcrt
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError: pass
    else:
        try:
            # Only this exclusively created empty file may receive its private
            # file DACL. Existing locks are checked and never repaired.
            api.protect(path)
            os.write(descriptor, b'0'); os.fsync(descriptor)
        finally: os.close(descriptor)
    with api.pin(path, private=True, writable=True) as lock:
        require(os.fstat(lock.fileno()).st_size == 1, 'LOCK_CHANGED')
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        try: yield
        finally:
            lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def unknown_diagnostics(root, pins, api):
    refresh, _, _, _, _ = modules()
    from infra.live_recovery_drill import PrivateDirectory
    paths = list((root / STAGE).glob('native-run-*'))
    require(len(paths) <= 256, 'PRIOR_DIAGNOSTIC_UNCONFIRMED')
    for path in paths:
        pins.enter_context(PrivateDirectory().pin(path, private=True, directory=True))
        raw = refresh.pin_bytes(root, pins, api, str((path / 'reservation.json').relative_to(root)), private=True, maximum=8192)
        value = refresh.document(raw)
        require(value.get('purpose') != PURPOSE and value.get('expected_labels', {}).get('org.kapit.owner') != OWNER,
            'PRIOR_DIAGNOSTIC_UNCONFIRMED')


def execute():
    require(os.name == 'nt', 'WINDOWS_ROOT_ONLY')
    refresh, runtime, _, _, base = modules()
    from infra.evidence_tools import Windows
    from infra.live_recovery_drill import PrivateDirectory
    from infra import evidence_container_native as public
    result = {'schema': 1, 'scope': 'PUBLIC_POSTCOMPILE_CONTROLLER_DIAGNOSTIC_ONLY', 'status': 'REFUSED',
        'completed': False, 'native_eligible': False, 'private_input_allowed': False,
        'control_state_modified': False, 'pins_closed': False, 'image_id': IMAGE, 'signature_generation': GENERATION}
    receipt = refresh.Receipt(ROOT / RECEIPT, result)
    pins = ExitStack(); failure = None; payload = None; stage = None; started = time.monotonic()
    try:
        api = Windows()
        # Keep every ancestor pinned against replacement through final close.
        path = ROOT
        pins.enter_context(api.pin(path, directory=True))
        for part in Path(STAGE).parts:
            path /= part; pins.enter_context(api.pin(path, directory=True))
        pins.enter_context(PrivateDirectory().pin(ROOT / STAGE, private=True, directory=True))
        for name, expected in SOURCE_PINS.items():
            refresh.pin_bytes(ROOT, pins, api, name, expected=expected)
        require(type(PROGRAM_SHA256) is str, 'PROGRAM_NOT_REVIEWED')
        raw = refresh.pin_bytes(ROOT, pins, api, PROGRAM, expected=PROGRAM_SHA256)
        stage = 'PROFILE_PIN'
        profile_source(ROOT, pins, api)
        stage = None
        preserved_refusal(ROOT, pins, api)
        docker, _, config, _ = refresh.tools(ROOT, pins, api)
        call = Commands(docker, config)
        with legacy_lock(api), \
             exclusive_lock(ROOT / STAGE / 'postcompile-diagnostic.lock', api):
            saved = refresh.verified_image(ROOT, pins, api)
            require(saved.get('image_id') == IMAGE and saved.get('signature_generation') == GENERATION)
            original_documents(ROOT, pins, api)
            unknown_diagnostics(ROOT, pins, api)
            runtime._require_cgroup_v2(call)
            require(shutil.disk_usage(ROOT).free >= FLOOR, 'LOW_SPACE')
            observation = observe_original(call)
            payload = run_probe(ROOT, call, ROOT / PROFILE, raw, observation, result)
            engine(call)
            require(not call.uncertain and shutil.disk_usage(ROOT).free >= FLOOR)
    except BaseException as error:
        failure = error
        # Never copy arbitrary exception text, native output or traceback.
        result['failure_code'] = error.code if type(error) is DiagnosticUnavailable else 'POSTCOMPILE_DIAGNOSTIC_REFUSED'
        if stage == 'PROFILE_PIN': result['failed_stage'] = 'PROFILE_PIN'
    finally:
        try: pins.close(); result['pins_closed'] = True
        except BaseException:
            failure = DiagnosticUnavailable('PIN_CLOSE_UNCONFIRMED'); result['failure_code'] = failure.code
        if time.monotonic() - started >= 600:
            failure = DiagnosticUnavailable('FINAL_DEADLINE'); result['failure_code'] = failure.code
        if failure is None:
            result.update(status='OBSERVED', completed=True, measurement=payload)
        result['total_seconds'] = round(time.monotonic() - started, 3)
        try:
            receipt.save(result)
            receipt.close()
        except BaseException:
            # No return/printed success follows a failed final write/handle.
            # Try to preserve a refusal through the original writer only;
            # never reopen/adopt an existing receipt after close uncertainty.
            result.update(status='REFUSED', completed=False, failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            result.pop('measurement', None)
            try:
                if not receipt.stream.closed: receipt.save(result)
            except BaseException: pass
            try: receipt.close()
            except BaseException: pass
            raise DiagnosticUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
    require(failure is None)
    return result


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    value = execute()
    print(json.dumps({'status': value['status'], 'receipt': RECEIPT, 'native_eligible': False}), flush=True)


if __name__ == '__main__':
    main()
