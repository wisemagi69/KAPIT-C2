"""Root-only fresh PUBLIC runtime development; no private ingress or activation.

Import is inert. The command line accepts a fixed stage only: image, generation,
context, tool paths and prior success cannot be supplied by a caller.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
STAGE_REL = '.cache/m1-runtime/private-scanner-build'
PACKAGE = 'ai/state/private-scanner-interpreter-package.json'
BUILD = 'ai/state/private-scanner-interpreter-runtime-build.json'
IMAGE = 'ai/state/private-scanner-interpreter-runtime-image.json'
CONTEXT = STAGE_REL + '/ctx-runtime-interpreter'
COMPILER = 'sha256:da1c3669871cc8c38d928d4e49d25777e00d51626c3c4c60a673a1852f2658d6'
LIBRARY = '43dfe05dbdf3365897013f2d67c7ba4669ceb1cd2c6389ac18d552d7a3beeeab'
PREPARATION_SHA256 = 'c872db46201610ce2cb4f6f0bb5419d8145996b83be619cb1edf7625191c33fb'
SOURCE_PINS = {
    'infra/evidence_interpreter_compile.py': '4822490b0d38f487ddd06c1a9760e8c3783dec627634a7bc630179a84e683085',
    'infra/evidence_native_runtime.py': '69af8b1564726ddde37ea8aa49ebf86a4419118b474e1bbd9098279568775c82',
    'infra/evidence_native_attestation.py': 'f3394eb061eec6696132c331207e1160a89775694e9e1bd565569c8f6c2a6c73',
    'infra/evidence_native_ownership.py': '6544725a99a0d9941db347ea3c81b8d3e8ea8f58ae88886289c320ee6f2ef4d1',
    'infra/evidence_container.py': '921f26e53ea67ebb066d534f682cef7fed215c708fed9426b14231e1b1043628',
}
DOCKER_SHA256 = '0d24d78cfc6262aefc82e175123d0f0d81d416882b12893002383168a8ca6935'
BUILDX_SHA256 = 'cfe42fbcbf18f9701b330284b3a28855d1a5d6f58d76dd2b97c8ab09ae24ae8a'
PROFILE_SHA256 = '389b9d083fc90982a51f999c9cfc1858cb660654d8d01dd5bc28da0a4e0523a7'
HOST = 'npipe:////./pipe/dockerDesktopLinuxEngine'
OWNER = 'kapit-public-native-runtime-v1'
HEX = re.compile(r'[0-9a-f]{64}\Z')
ID = re.compile(r'sha256:[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[0-9a-f]{32}\Z')
WALL = 300
FLOOR = 2 * 1024**3
INITIAL = 3 * 1024**3
OUTPUT_LIMIT = 2 * 1024**2


class RefreshUnavailable(RuntimeError):
    def __init__(self, code='FRESH_RUNTIME_UNAVAILABLE'):
        self.code = code
        super().__init__(code)


def require(value, code='FRESH_RUNTIME_UNAVAILABLE'):
    if value is not True:
        raise RefreshUnavailable(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def document(raw):
    """Bounded closed JSON: duplicate keys, nonfinite constants and depth refuse."""
    require(type(raw) is bytes and 0 < len(raw) <= 262144)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False))
        pending = [(value, 0)]; count = 0
        while pending:
            item, depth = pending.pop(); count += 1
            require(depth <= 20 and count <= 20000)
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
            else:
                require(type(item) in (str, int, bool, type(None), float))
        require(type(value) is dict)
        return value
    except RefreshUnavailable:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise RefreshUnavailable() from None


def pin_bytes(root, pins, api, name, *, private=False, maximum=262144, expected=None):
    path = root / name
    stream = pins.enter_context(api.pin(path, private=private))
    raw = stream.read(maximum + 1)
    require(type(raw) is bytes and len(raw) <= maximum)
    if expected is not None:
        require(type(expected) is str and HEX.fullmatch(expected) is not None and sha(raw) == expected)
    return raw


def binding(package, package_raw):
    require(package.get('schema') == 1 and package.get('native_eligible') is False
            and package.get('control_state_modified') is False
            and package.get('compiler_image') == COMPILER and package.get('main_library_sha256') == LIBRARY
            and package.get('directory') == CONTEXT)
    for key in ('lock_sha256', 'runtime_json_sha256', 'signature_generation'):
        require(type(package.get(key)) is str and HEX.fullmatch(package[key]) is not None
                and package[key] != '0' * 64)
    return {key: package[key] for key in ('compiler_image', 'main_library_sha256', 'lock_sha256',
            'runtime_json_sha256', 'signature_generation')} | {'package_sha256': sha(package_raw)}


def context_files(files):
    require(type(files) is dict and 1 <= len(files) <= 128 and 'Dockerfile' in files)
    total = 0
    for name, row in files.items():
        require(type(name) is str and 1 <= len(name) <= 256 and '\\' not in name)
        rel = PurePosixPath(name)
        require(not rel.is_absolute() and rel.as_posix() == name and all(part not in ('', '.', '..') for part in rel.parts))
        allowed = name in {'Dockerfile', 'runtime.json', 'signature-files.json', 'closure/inventory.json',
            'wheels/requirements.txt', 'clamav/lib/libclamav.so.12.0.3', 'clamav/lib/libclamav.so.12',
            'clamav/lib/libclammspack.so.0'} or re.fullmatch(
                r'(?:closure/lib/[A-Za-z0-9_.+-]+|signatures/(?:main|daily|bytecode)\.cvd|'
                r'kapit_evidence/(?:__init__|evidence_native_worker|evidence_scan_protocol|evidence_protocol|'
                r'evidence_policy|evidence_decoder|evidence_linux)\.py|'
                r'wheels/pillow-13\.0\.0-cp314-cp314-manylinux_2_27_x86_64\.manylinux_2_28_x86_64\.whl)', name)
        require(bool(allowed) and type(row) is dict and set(row) == {'bytes', 'sha256'}
                and type(row['bytes']) is int and 0 <= row['bytes'] <= 256 * 1024**2
                and type(row['sha256']) is str and HEX.fullmatch(row['sha256']) is not None)
        total += row['bytes']
    require(total <= 256 * 1024**2)


def reviewed_constants():
    require(type(COMPILER) is str and ID.fullmatch(COMPILER) is not None
        and type(LIBRARY) is str and HEX.fullmatch(LIBRARY) is not None
        and type(PREPARATION_SHA256) is str and HEX.fullmatch(PREPARATION_SHA256) is not None,
        'ACTUAL_COMPILER_SOURCE_NOT_REVIEWED')


def load_package(root, pins, api):
    """The preparation verifier holds and revalidates every upstream byte and age."""
    reviewed_constants()
    pin_bytes(root, pins, api, 'infra/evidence_interpreter_prepare.py', expected=PREPARATION_SHA256)
    from infra import evidence_interpreter_prepare as preparation
    package = preparation.verified_package(root, pins, api)
    raw = pin_bytes(root, pins, api, PACKAGE)
    require(document(raw) == package)
    chain = binding(package, raw)
    context_files(package.get('files'))
    for name, expected in SOURCE_PINS.items():
        pin_bytes(root, pins, api, name, expected=expected)
    for name, row in package['files'].items():
        data = pin_bytes(root, pins, api, CONTEXT + '/' + name, private=True,
                         maximum=256 * 1024**2, expected=row['sha256'])
        require(len(data) == row['bytes'])
    return package, chain


class Receipt:
    """Exclusive reservation; updates use only the original owned file handle."""
    def __init__(self, path, initial):
        self.path = path
        self.stream = path.open('xb')
        self.save(initial)

    def save(self, result):
        raw = json.dumps(result, sort_keys=True, indent=2, allow_nan=False).encode('utf-8')
        require(len(raw) <= 262144)
        self.stream.seek(0); self.stream.write(raw); self.stream.truncate()
        self.stream.flush(); os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()


def tools(root, pins, api):
    from infra.live_recovery_drill import PrivateDirectory
    stage = root / STAGE_REL
    client = stage / 'build-client'
    docker = root / '.cache/m1-runtime/container-tools/docker.exe'
    config = client / 'runtime-config1'
    for path in (stage, client, config, client / 'buildx-state', docker.parent):
        pins.enter_context(PrivateDirectory().pin(path, private=True, directory=True))
    pin_bytes(root, pins, api, str(docker.relative_to(root)), maximum=128 * 1024**2, expected=DOCKER_SHA256)
    exe = client / 'docker-buildx.exe'
    pin_bytes(root, pins, api, str(exe.relative_to(root)), private=True, maximum=128 * 1024**2, expected=BUILDX_SHA256)
    raw = pin_bytes(root, pins, api, str((config / 'config.json').relative_to(root)), private=True, maximum=128)
    require(raw == b'{"auths":{}}\n')
    env = {key: value for key, value in os.environ.items() if key.upper() in {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}}
    env.update(DOCKER_CONFIG=str(config), BUILDX_CONFIG=str(client / 'buildx-state'), DOCKER_HOST=HOST,
               BUILDX_GIT_INFO='0', BUILDX_NO_DEFAULT_ATTESTATIONS='1')
    return docker, exe, config, env


def call(docker, config, *args):
    from infra import evidence_container as commands
    return commands._bounded_command([str(docker), '--host', HOST, '--config', str(config), *args],
                                     timeout=15, maximum=65536)


def stop_owned(process, tracked):
    """Only the retained direct CLI handle is stopped. Every cleanup is attempted."""
    uncertain = False; stopped = process is None; joined = True; closed = process is None
    if process is not None:
        for _ in range(2):
            try:
                if process.poll() is None:
                    process.kill()
                code = process.wait(timeout=10)
                stopped = type(code) is int and process.poll() is not None
                if stopped:
                    break
            except BaseException:
                uncertain = True
    for thread in tracked:
        try:
            if thread.ident is not None:
                thread.join(timeout=5)
            joined = joined and not thread.is_alive()
        except BaseException:
            joined = False; uncertain = True
    if process is not None and stopped and joined:
        closed = True
        for pipe in (process.stdout, process.stderr):
            try:
                pipe.close()
            except BaseException:
                closed = False; uncertain = True
    return stopped, joined, closed, uncertain or not stopped or not joined or not closed


def final_reason(reason, *, elapsed, free, iid, failed, overflow, cleanup):
    if failed:
        reason = 'IO_FAILURE'
    if overflow:
        reason = 'OUTPUT_LIMIT'
    if reason == 'EXIT' and elapsed >= WALL:
        reason = 'WALL_LIMIT'
    if reason == 'EXIT' and (type(free) is not int or free < FLOOR):
        reason = 'LOW_SPACE' if type(free) is int else 'BUILD_OUTPUT_UNCONFIRMED'
    if reason == 'EXIT' and (type(iid) is not str or ID.fullmatch(iid) is None):
        reason = 'BUILD_OUTPUT_UNCONFIRMED'
    if cleanup:
        reason = 'CLI_CLEANUP_UNCONFIRMED'
    return reason


def build(root, pins, api, package, chain, result):
    docker, exe, config, env = tools(root, pins, api)
    require(shutil.disk_usage(root).free >= INITIAL, 'LOW_SPACE')
    token = uuid.uuid4().hex; tag = 'kapit-public-native-runtime:' + token
    iid = root / STAGE_REL / ('runtime-interpreter-' + token + '.iid')
    require(not iid.exists() and not iid.is_symlink())
    code, _, err, reason = call(docker, config, 'image', 'inspect', tag)
    require(type(code) is int and code == 1 and reason == 'EXIT' and b'No such image' in err)
    result.update(chain, reservation=token, tag=tag, context=CONTEXT)
    process = None; threads = []; buffers = [bytearray(), bytearray()]
    failed = threading.Event(); overflow = threading.Event(); started = time.monotonic()
    reason = 'PRIMARY_EXECUTION_FAILED'; identity = None; status = 'UNAVAILABLE'
    def reader(pipe, target):
        try:
            while True:
                block = pipe.read1(8192)
                if not block:
                    break
                if len(target) + len(block) > OUTPUT_LIMIT:
                    overflow.set(); break
                target.extend(block)
        except BaseException:
            failed.set()
        finally:
            try:
                pipe.close()
            except BaseException:
                failed.set()
    try:
        args = [str(exe), 'build', '--network', 'none', '--pull=false', '--progress', 'plain',
            '--iidfile', str(iid), '--tag', tag, '--label', 'org.kapit.owner=' + OWNER,
            '--label', 'org.kapit.reservation=' + token, str(root / CONTEXT)]
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, shell=False, close_fds=True, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        for pipe, target in zip((process.stdout, process.stderr), buffers):
            thread = threading.Thread(target=reader, args=(pipe, target), daemon=True)
            threads.append(thread); thread.start()
        reason = 'EXIT'; heartbeat = started
        while process.poll() is None:
            elapsed = time.monotonic() - started
            reason = final_reason('EXIT', elapsed=elapsed, free=shutil.disk_usage(root).free,
                iid='sha256:' + '1' * 64, failed=failed.is_set(), overflow=overflow.is_set(), cleanup=False)
            if reason != 'EXIT':
                break
            if time.monotonic() - heartbeat >= 25:
                print(json.dumps({'phase': 'PUBLIC_RUNTIME_BUILD', 'seconds': round(elapsed)}), flush=True)
                heartbeat = time.monotonic()
            time.sleep(.1)
    except BaseException as error:
        result['exception_class'] = type(error).__name__
        reason = 'PRIMARY_EXECUTION_FAILED'
    finally:
        stopped = process is None; joined = not threads; closed = process is None; cleanup = False
        try:
            stopped, joined, closed, cleanup = stop_owned(process, threads)
        except BaseException:
            cleanup = True
            try:
                stopped, joined, closed, _ = stop_owned(process, threads)
            except BaseException:
                pass
        try:
            raw = pin_bytes(root, pins, api, str(iid.relative_to(root)), maximum=128)
            if re.fullmatch(rb'sha256:[0-9a-f]{64}(?:\r?\n)?', raw) is not None:
                identity = raw.decode('ascii').rstrip('\r\n'); status = 'VERIFIED_FORMAT'
            else:
                status = 'MALFORMED'
        except BaseException:
            status = 'UNAVAILABLE'
        try:
            free = shutil.disk_usage(root).free
        except BaseException:
            free = None
        elapsed = time.monotonic() - started
        reason = final_reason(reason, elapsed=elapsed, free=free, iid=identity,
            failed=failed.is_set(), overflow=overflow.is_set(), cleanup=cleanup)
        result.update(reason=reason, seconds=round(elapsed, 3), exit=None if process is None else process.returncode,
            cli_started=process is not None, cli_reaped=stopped, threads_joined=joined, pipes_closed=closed,
            config_digest=identity, iidfile_status=status, free_bytes=free,
            output_bytes=[len(raw) for raw in buffers])
        result['runtime_image_built'] = reason == 'EXIT' and type(result['exit']) is int and result['exit'] == 0
        if process is not None and not result['runtime_image_built']:
            result['daemon_build_cancellation'] = 'UNCONFIRMED_NO_GLOBAL_CLEANUP'


def validate_build(build_receipt, chain):
    require(build_receipt.get('schema') == 1 and build_receipt.get('status') == 'VERIFIED'
        and build_receipt.get('scope') == 'PUBLIC_FRESH_RUNTIME_BUILD_NOT_NATIVE_PROOF'
        and build_receipt.get('runtime_image_built') is True and build_receipt.get('reason') == 'EXIT'
        and type(build_receipt.get('exit')) is int and build_receipt['exit'] == 0
        and all(build_receipt.get(key) is True for key in ('cli_started', 'cli_reaped', 'threads_joined', 'pipes_closed'))
        and build_receipt.get('native_eligible') is False and build_receipt.get('private_input_allowed') is False
        and build_receipt.get('control_state_modified') is False and build_receipt.get('pins_closed') is True
        and 'exception_class' not in build_receipt and 'failure_code' not in build_receipt
        and type(build_receipt.get('total_seconds')) in (int, float) and 0 <= build_receipt['total_seconds'] < WALL
        and build_receipt.get('context') == CONTEXT and 'daemon_build_cancellation' not in build_receipt
        and type(build_receipt.get('config_digest')) is str and ID.fullmatch(build_receipt['config_digest']) is not None
        and type(build_receipt.get('reservation')) is str and TOKEN.fullmatch(build_receipt['reservation']) is not None
        and build_receipt.get('tag') == 'kapit-public-native-runtime:' + build_receipt['reservation'])
    require(all(build_receipt.get(key) == value for key, value in chain.items()))


def image_document(actual, build_receipt, chain):
    from infra import evidence_native_runtime as runtime
    identity = actual.get('Id')
    runtime.verify_image(actual, runtime.Candidate(identity, chain['signature_generation']))
    require(actual.get('RepoTags') == [build_receipt['tag']]
        and actual['Config']['Labels'] == {'org.kapit.owner': OWNER, 'org.kapit.reservation': build_receipt['reservation']})
    descriptor = actual.get('Descriptor')
    require(type(descriptor) is dict and descriptor.get('digest') == identity
        and type(descriptor.get('annotations')) is dict
        and descriptor['annotations'].get('config.digest') == build_receipt['config_digest'])
    return identity


def identity(root, pins, api, chain, result, *, expected=None):
    docker, _, config, _ = tools(root, pins, api)
    raw = pin_bytes(root, pins, api, BUILD)
    built = document(raw); validate_build(built, chain)
    selector = built['tag'] if expected is None else expected
    require(expected is None or type(expected) is str and ID.fullmatch(expected) is not None)
    code, out, err, reason = call(docker, config, 'image', 'inspect', selector)
    require(type(code) is int and code == 0 and reason == 'EXIT' and not err)
    # The envelope is a single image. Parsing uses the same bounded duplicate check.
    actual = document(b'{"images":' + out + b'}').get('images')
    require(type(actual) is list and len(actual) == 1 and type(actual[0]) is dict)
    actual = actual[0]; image_id = image_document(actual, built, chain)
    require(expected is None or image_id == expected)
    result.update(chain, image_id=image_id, config_digest=built['config_digest'],
        compiler_image_id=chain['compiler_image'],
        build_sha256=sha(raw), reservation=built['reservation'], tag=built['tag'],
        descriptor=actual['Descriptor'], config=actual['Config'], rootfs=actual['RootFS'])


def verified_image(root, pins, api):
    """Fresh package/currentness and live daemon identity; saved JSON is evidence only."""
    _, chain = load_package(root, pins, api)
    saved = document(pin_bytes(root, pins, api, IMAGE))
    require(saved.get('schema') == 1 and saved.get('scope') == 'PUBLIC_FRESH_RUNTIME_IDENTITY_NOT_NATIVE_PROOF'
        and saved.get('status') == 'VERIFIED' and saved.get('pins_closed') is True
        and saved.get('native_eligible') is False and saved.get('private_input_allowed') is False
        and saved.get('control_state_modified') is False and 'failure_code' not in saved)
    require(all(saved.get(key) == value for key, value in chain.items())
        and saved.get('compiler_image_id') == COMPILER)
    live = {}
    identity(root, pins, api, chain, live, expected=saved.get('image_id'))
    require(all(saved.get(key) == value for key, value in live.items()))
    return saved


def prior_suites(root, pins, api, *, current=None):
    """An interrupted current-chain public case is never cleared by a new UUID."""
    paths = list((root / 'ai/state').glob('private-scanner-interpreter-suite-*.json'))
    require(len(paths) <= 64, 'PRIOR_SUITE_UNCONFIRMED')
    for path in paths:
        require(re.fullmatch(r'private-scanner-interpreter-suite-(?:confinement|strict|pcre|fixtures)\.json',
                             path.name) is not None, 'PRIOR_SUITE_UNCONFIRMED')
        if current is not None and path == current:
            continue  # The original exclusive owned writer is still open.
        saved = document(pin_bytes(root, pins, api, str(path.relative_to(root))))
        require('active_case' not in saved, 'PRIOR_SUITE_UNCONFIRMED')
        stage = path.stem.removeprefix('private-scanner-interpreter-suite-')
        require(saved.get('stage') == stage and saved.get('status') == 'VERIFIED'
            and saved.get('pins_closed') is True and saved.get('native_eligible') is False
            and saved.get('private_input_allowed') is False and 'failure_code' not in saved
            and 'exception_class' not in saved
            and type(saved.get('results')) is list
            and len(saved['results']) == {'confinement':10,'strict':1,'pcre':1,'fixtures':6}[stage]
            and all(type(row) is dict and type(row.get('receipt')) is dict and row['receipt'].get('cleanup') in
                ('OWNED_CONTAINER_ABSENT_VERIFIED', 'ALL_OWNED_CONTAINERS_ABSENT_VERIFIED')
                for row in saved['results']), 'PRIOR_SUITE_UNCONFIRMED')
        from infra import evidence_native_attestation as probes
        expected = ([(case,mode) for mode in ('scan','decode') for case in sorted(probes.SCENARIOS)]
            if stage == 'confinement' else [('strict','scan')] if stage == 'strict' else [('pcre','scan')]
            if stage == 'pcre' else [(case,'pipeline') for case in
                ('png_clean','png_metadata','jpeg_clean','jpeg_metadata','png_malformed','png_eicar')])
        require([(row.get('name'),row.get('mode')) for row in saved['results']] == expected
            and saved.get('compiler_image') == COMPILER and saved.get('main_library_sha256') == LIBRARY
            and type(saved.get('image_id')) is str and ID.fullmatch(saved['image_id']) is not None
            and type(saved.get('signature_generation')) is str and HEX.fullmatch(saved['signature_generation']) is not None
            and all(row.get('image_id') == saved['image_id'] and
                row.get('signature_generation') == saved['signature_generation'] for row in saved['results']),
                'PRIOR_SUITE_UNCONFIRMED')


def suite(root, pins, api, package, chain, name, result, receipt, original_call):
    from infra import evidence_native_attestation as probes
    from infra import evidence_native_runtime as runtime
    from infra import evidence_container as base
    from infra import evidence_container_native as public
    prior_suites(root, pins, api, current=receipt.path)
    actual_image = verified_image(root, pins, api)
    require(all(actual_image.get(key) == value for key, value in chain.items()))
    identity(root, pins, api, chain, result, expected=actual_image.get('image_id'))
    require(result['build_sha256'] == actual_image.get('build_sha256')
        and result['config_digest'] == actual_image.get('config_digest'))
    profile = root / STAGE_REL / 'abi3-startup-profile.json'
    raw = pin_bytes(root, pins, api, str(profile.relative_to(root)), expected=PROFILE_SHA256)
    require(raw == base.canonical(public.startup_profile()))
    for path, expected in probes.PINS:
        pin_bytes(root, pins, api, str(Path(path).relative_to(root)), expected=expected)
    candidate = runtime.Candidate(result['image_id'], chain['signature_generation'])
    cases = ([(scenario, mode) for mode in ('scan', 'decode') for scenario in sorted(probes.SCENARIOS)]
        if name == 'confinement' else [('strict', 'scan')] if name == 'strict' else [('pcre', 'scan')]
        if name == 'pcre' else [(value, 'pipeline') for value in
            ('png_clean', 'png_metadata', 'jpeg_clean', 'jpeg_metadata', 'png_malformed', 'png_eicar')])
    result['results'] = []
    for case, mode in cases:
        require(shutil.disk_usage(root).free >= FLOOR, 'LOW_SPACE')
        _, current = load_package(root, pins, api)
        require(current == chain)
        # Re-observe exact defaults/descriptor; each existing controller also
        # performs its own live cgroup/resource/ownership/inspection checks.
        checked = {}; identity(root, pins, api, chain, checked, expected=candidate.image_id)
        require(checked.get('image_id') == candidate.image_id
            and checked.get('build_sha256') == actual_image['build_sha256']
            and all(checked.get(key) == value for key, value in chain.items()))
        result['active_case'] = {'name': case, 'mode': mode}; receipt.save(result)
        observe_case_originals(original_call)
        print(json.dumps({'event': 'START_PUBLIC_CASE', 'suite': name, 'name': case, 'mode': mode}), flush=True)
        started = time.monotonic()
        docker = root / '.cache/m1-runtime/container-tools/docker.exe'
        if name == 'confinement':
            observed = probes.run_public_probe(candidate, case, resource_mode=mode, docker_path=docker, profile_path=profile)
        elif name == 'strict':
            observed = probes.run_strict_probe(candidate, docker_path=docker, profile_path=profile)
        elif name == 'pcre':
            observed = probes.run_pcre_probe(candidate, docker_path=docker, profile_path=profile)
        else:
            observed = runtime.run_fixture_pipeline(candidate, case, docker_path=docker, profile_path=profile)
        require(type(observed) is dict and observed.get('cleanup') in
            ('OWNED_CONTAINER_ABSENT_VERIFIED', 'ALL_OWNED_CONTAINERS_ABSENT_VERIFIED'))
        if name != 'fixtures':
            require(observed.get('candidate_image_id') == candidate.image_id
                and observed.get('declared_signature_generation') == candidate.signature_generation)
        result['results'].append({'name': case, 'mode': mode, 'seconds': round(time.monotonic() - started, 3),
            'image_id': candidate.image_id, 'signature_generation': candidate.signature_generation, 'receipt': observed})
        receipt.save(result)
    result.pop('active_case', None)


def observe_case_originals(original_call):
    from infra.evidence_interpreter_compile import live_originals
    from infra.evidence_postcompile_diagnostic import Commands
    # Each finite case gets its own 64-query budget using the same held clients.
    # Any uncertainty throws and stops the suite; no failed budget is reused.
    require(type(original_call) is Commands and not original_call.uncertain)
    live_originals(Commands(original_call.docker, original_call.config)).consume()


def execute(stage):
    root = ROOT
    reviewed_constants()  # Unfilled actual pins cannot consume a receipt.
    require(Path.cwd().resolve() == ROOT, 'PROJECT_ROOT_REQUIRED')
    require(os.name == 'nt', 'WINDOWS_ROOT_ONLY')
    require(stage in ('build', 'identity', 'confinement', 'strict', 'pcre', 'fixtures'))
    from infra.evidence_tools import Windows
    path = root / (BUILD if stage == 'build' else IMAGE if stage == 'identity' else
        'ai/state/private-scanner-interpreter-suite-' + stage + '.json')
    result = {'schema': 1, 'scope': 'PUBLIC_FRESH_RUNTIME_' + ('BUILD' if stage == 'build' else
        'IDENTITY' if stage == 'identity' else 'SUITE') + '_NOT_NATIVE_PROOF',
        'stage': stage, 'status': 'REFUSED', 'native_eligible': False, 'private_input_allowed': False,
        'control_state_modified': False, 'pins_closed': False, 'runtime_image_built': False}
    receipt = Receipt(path, result)
    pins = ExitStack(); started = time.monotonic(); failure = None
    try:
        # The compiler facade retains exact source/input/ancestor pins, both
        # existing legacy and new interpreter locks, and historical journals.
        from infra.evidence_interpreter_compile import checked_inputs, live_originals
        api, _, original_call, _ = pins.enter_context(checked_inputs())
        for name, expected in SOURCE_PINS.items():
            pin_bytes(root,pins,api,name,expected=expected)
        prior_suites(root,pins,api,current=receipt.path)
        package, chain = load_package(root, pins, api)
        live_originals(original_call).consume()
        result.update(chain)
        if stage == 'build':
            build(root, pins, api, package, chain, result)
            require(result['runtime_image_built'], result.get('reason', 'BUILD_FAILED'))
        elif stage == 'identity':
            identity(root, pins, api, chain, result)
        else:
            suite(root, pins, api, package, chain, stage, result, receipt, original_call)
    except BaseException as error:
        failure = error
        result['failure_code'] = getattr(error, 'code', 'FRESH_RUNTIME_UNAVAILABLE')
        result['exception_class'] = type(error).__name__
        diagnostic = getattr(error, 'diagnostic', None)
        if type(diagnostic) is dict:
            result['diagnostic'] = diagnostic
    finally:
        try:
            pins.close(); result['pins_closed'] = True
        except BaseException as error:
            failure = error
            result['failure_code'] = 'PIN_CLOSE_UNCONFIRMED'
            result['runtime_image_built'] = False
            if stage == 'build':
                result['reason'] = 'CLI_CLEANUP_UNCONFIRMED'
                result['daemon_build_cancellation'] = 'UNCONFIRMED_NO_GLOBAL_CLEANUP'
        if stage == 'build' and time.monotonic() - started >= WALL:
            failure = failure or RefreshUnavailable('WALL_LIMIT')
            result['runtime_image_built'] = False
            if result.get('reason') != 'CLI_CLEANUP_UNCONFIRMED':
                result['reason'] = 'WALL_LIMIT'
            if result.get('cli_started'):
                result['daemon_build_cancellation'] = 'UNCONFIRMED_NO_GLOBAL_CLEANUP'
        result['status'] = 'VERIFIED' if failure is None else 'REFUSED'
        result['total_seconds'] = round(time.monotonic() - started, 3)
        try:
            receipt.save(result); receipt.close()
        except BaseException:
            result.update(status='REFUSED',runtime_image_built=False,
                failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            try:
                if not receipt.stream.closed: receipt.save(result)
            finally:
                receipt.close()
            raise RefreshUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
        print(json.dumps({'stage': stage, 'status': result['status'], 'receipt': str(path.relative_to(root)),
                          'native_eligible': False}), flush=True)
    if failure is not None:
        raise RefreshUnavailable(result.get('failure_code', 'FRESH_RUNTIME_UNAVAILABLE')) from failure
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('build', 'identity', 'confinement', 'strict', 'pcre', 'fixtures'))
    execute(parser.parse_args().stage)


if __name__ == '__main__':
    main()
