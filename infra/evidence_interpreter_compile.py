"""Fixed root-only interpreter compiler, identity and never-started export.

Import is inert. Old source and historical failures are never changed. A receipt
records a single attempt and cannot be used to retry a failed stage.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
STAGE = '.cache/m1-runtime/private-scanner-build'
PREFIX = 'ai/state/private-scanner-interpreter-'
BUILD = PREFIX + 'build.json'
IDENTITY = PREFIX + 'identity.json'
EXPORT = PREFIX + 'export.json'
DRIVER = 'ai/state/private-scanner-compile-engine-readback-pcre.py'
DRIVER_SHA = 'd9de8ed711da8b327a506288836a30b0f1737293d0ae2d1abfb056c947df3a49'
NEW_PINS = {
    'infra/evidence_interpreter_build.py': 'd2c8d7e6acd6f9cdb3740b18891c4673dffef9710a83c869fb51b49586faa8c7',
    'infra/native/Dockerfile.evidence-interpreter': '5215c1413e87b7440f544a1e97a3938bada812e315d2c04718bba012d4e5ed75',
    'infra/native/clamav_interpreter.patch': '1b1d289e9e23567d253b04fc4c17d647905dcd5f774247feaa132fbe54388223',
}
PIN_NAMES = ('infra/evidence_interpreter_build.py',
             'infra/native/Dockerfile.evidence-interpreter',
             'infra/native/clamav_interpreter.patch')
FROZEN = {
    DRIVER: DRIVER_SHA,
    'ai/state/private-scanner-resume-pcre.py': '5ed4100038497f90d57768fd08387394af5f8ceb58ed47c7201731c8538315bf',
    'ai/state/private-scanner-postflight-pcre.py': '31a29d62ed85f6be1d464f0c41b4a68dd61de12b3253ea282819b34a5816a36d',
    'ai/state/private-scanner-export.py': '3906ef598d57d0ea1341c0acff3ab916b2ddaef59081848f58384d6b73d12eab',
    'infra/evidence_postcompile_continuation.py': '43411a87c68935ecf3989017b2a541fac2b43bf56c4f578d3a602aee39723bac',
    'infra/evidence_postcompile_preflight.py': '4697680bbfcccf25956194d4fc374fd238e1d31a056bf3d5136f83d08ec2985c',
    'infra/evidence_postcompile_diagnostic.py': '5a24dbfa6de043730faa10c9ec3a8ba46fff8446d44fa82401977698dfda69ff',
    'infra/evidence_software_links.py': '785ef83ffc225520a9f181e80a78a6dbea4df68632d744c55d22c9a335f6e4b9',
}
DIAGNOSTIC = 'ai/state/private-scanner-continuation-diagnostic-pcre.json'
DIAGNOSTIC_SHA = 'd3f815e56ff5bc9af96b5b5b4737d4ba5a7d3ed5d7051798302c34f06a103c51'
OWNED = 'ai/state/private-scanner-continuation-owned-pcre.json'
OWNED_SHA = 'f3fa1629ad45637381a3fa151732c9479d0245e64b418ec2b2a1bcb76282e5fa'
TOKEN = '710f953f90544192b15d4c2906402175'
CID = '79a0091471136beb919c7d2c0608cd6eea8c997ced5faa13f5a1942610129a5e'
NAME = 'kapit-postcompile-public-' + TOKEN
EXPORT_PATHS = (
    '/out/opt/clamav/lib/libclamav.so.12.0.3', '/out/opt/clamav/lib/libclammspack.so.0',
    '/opt/kapit-builder-provenance/toolchain-packages.tsv',
    '/opt/kapit-builder-provenance/toolchain-versions.txt',
    '/opt/kapit-builder-provenance/toolchain-inventory.json',
    '/lib/x86_64-linux-gnu/libjson-c.so.5', '/lib/x86_64-linux-gnu/libxml2.so.2',
    '/lib/x86_64-linux-gnu/libicuuc.so.72', '/lib/x86_64-linux-gnu/libicudata.so.72',
    '/usr/include/pcre2.h')


class Refused(RuntimeError):
    pass


def require(value, code='INTERPRETER_COMPILE_REFUSED'):
    if value is not True:
        raise Refused(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def modules():
    from infra import evidence_native_refresh_runtime as refresh
    from infra import evidence_postcompile_diagnostic as old
    from infra import evidence_postcompile_preflight as preflight
    from infra import evidence_postcompile_continuation as continuation
    return refresh, old, preflight, continuation


def prepared_driver(raw, token):
    """Exact byte transform of one hash-pinned reviewed driver; no AST edits."""
    require(type(raw) is bytes and digest(raw) == DRIVER_SHA, 'DRIVER_CHANGED')
    require(type(token) is str and re.fullmatch('[0-9a-f]{32}', token) is not None,
            'RESERVATION_INVALID')
    require(set(NEW_PINS) == set(PIN_NAMES) and all(type(v) is str and
        re.fullmatch('[0-9a-f]{64}', v) is not None for v in NEW_PINS.values()), 'NEW_SOURCE_UNREVIEWED')
    source = raw.decode('utf-8')
    replacements = (
        ('from infra.evidence_native_build import source_build_inputs, MIN_BUILD_FREE_BYTES',
         'from infra.evidence_interpreter_build import source_build_inputs, MIN_BUILD_FREE_BYTES', 1),
        ("CTX=STAGE/'ctx6'; CLIENT=", "CTX=STAGE/'ctx-interpreter-" + token + "'; CLIENT=", 1),
        ('private-scanner-compile-engine-readback-pcre-', 'private-scanner-interpreter-compile-', 1),
        ('infra/native/Dockerfile.evidence', PIN_NAMES[1], 2),
        ('infra/evidence_native_build.py', PIN_NAMES[0], 1),
        ('infra/native/clamav_strict.patch', PIN_NAMES[2], 2),
        ('a50b0a5b3bdddf9cf4a3e17b7e61172a996ec2973002937d2e55677c1a2a7239', NEW_PINS[PIN_NAMES[1]], 1),
        ('2626b4e662e0f632ee52444e9bf68480b00d3a2d1ae9835294921798235b6702', NEW_PINS[PIN_NAMES[0]], 1),
        ('8e54280c6ad5c76c2748aae805a8cea85d69179ef9a57cbaf1af468a53db3eb4', NEW_PINS[PIN_NAMES[2]], 1))
    for before, after, count in replacements:
        require(source.count(before) == count, 'DRIVER_TRANSFORM_CHANGED')
        source = source.replace(before, after)
    compile(source, '<reviewed-interpreter-build>', 'exec')
    return source


def load_fixed(name, raw):
    """Only full immutable approved sources; never caller-selected source paths."""
    require(name in ('ai/state/private-scanner-resume-pcre.py',
                     'ai/state/private-scanner-export.py'), 'LOADER_REFUSED')
    require(type(raw) is bytes and digest(raw) == FROZEN[name], 'LOADER_SOURCE_CHANGED')
    namespace = {'__name__': 'kapit_fixed_public_source', '__file__': str(ROOT/name)}
    exec(compile(raw, str(ROOT/name), 'exec'), namespace)
    return namespace


def historical_bindings(pins, api):
    refresh, old, preflight, _ = modules()
    from infra.live_recovery_drill import PrivateDirectory
    preflight.preserved_refusals(pins, api)
    old.original_documents(ROOT, pins, api)
    raw = refresh.pin_bytes(ROOT, pins, api, DIAGNOSTIC, expected=DIAGNOSTIC_SHA)
    value = refresh.document(raw)
    require(value.get('completed') is True and value.get('status') == 'OBSERVED'
        and value.get('original_id') == CID and value.get('reservation') == TOKEN
        and value.get('pins_closed') is True and value.get('cli_cleanup_confirmed') is True
        and value.get('cleanup') == 'ORIGINAL_ID_ABSENT_VERIFIED'
        and value.get('native_eligible') is False and value.get('private_input_allowed') is False
        and value.get('measurement') == {'schema': 1, 'scope': 'PUBLIC_POSTCOMPILE_READBACK_DIAGNOSTIC_ONLY',
            'observation': 'FIRST_MISMATCH', 'field': '17', 'category': 'AUTO',
            'completed': True, 'native_eligible': False, 'private_input_allowed': False}, 'DIAGNOSTIC_CHANGED')
    raw = refresh.pin_bytes(ROOT, pins, api, OWNED, expected=OWNED_SHA)
    binding = refresh.document(raw)
    require(binding.get('receipt_sha256') == DIAGNOSTIC_SHA and binding.get('original_id') == CID
        and binding.get('reservation') == TOKEN and type(binding.get('files')) is dict
        and len(binding['files']) == 4, 'DIAGNOSTIC_BINDING_CHANGED')
    directory = ROOT/STAGE/('native-run-' + TOKEN)
    pins.enter_context(PrivateDirectory().pin(directory, private=True, directory=True))
    expected_names = {STAGE+'/native-run-'+TOKEN+'/'+name for name in
        ('reservation.json','create-attempt.json','ownership.json','result.json')}
    rows = {name.replace('\\', '/'): row for name, row in binding['files'].items()}
    require(set(rows) == expected_names, 'DIAGNOSTIC_BINDING_CHANGED')
    for name, row in rows.items():
        actual = refresh.pin_bytes(ROOT, pins, api, name, expected=row['sha256'], private=True)
        require(len(actual) == row['bytes'] and refresh.document(actual) == row['document'],
                'DIAGNOSTIC_JOURNAL_CHANGED')


def absent(call, selector):
    _, old, _, _ = modules()
    require(selector in (old.OLD_CID, old.OLD_NAME, CID, NAME), 'SELECTOR_REFUSED')
    code, out, err, reason = call('container', 'inspect', selector)
    require(type(code) is int and code == 1 and reason == 'EXIT' and out in (b'[]', b'[]\n', b'[]\r\n')
        and err in tuple(('Error response from daemon: No such container: '+selector+end).encode('ascii')
                        for end in ('','\n','\r\n')), 'ORIGINAL_ABSENCE_UNCONFIRMED')


def live_originals(call):
    _, old, _, _ = modules()
    started = time.monotonic()
    old.engine(call)
    for selector in (old.OLD_CID, old.OLD_NAME, CID, NAME):
        absent(call, selector)
    old.engine(call)
    require(not call.uncertain and time.monotonic()-started < 90, 'LIVE_ORIGINALS_UNCONFIRMED')
    return old.Observation(old._LIVE_SEAL, time.monotonic())


@contextmanager
def checked_inputs():
    refresh, old, _, continuation = modules()
    from infra.evidence_tools import Windows
    from infra.live_recovery_drill import PrivateDirectory
    require(Path.cwd().resolve() == ROOT, 'PROJECT_ROOT_REQUIRED')
    require(os.name == 'nt', 'WINDOWS_ROOT_ONLY')
    with ExitStack() as pins:
        api = Windows()
        path = ROOT
        pins.enter_context(api.pin(path, directory=True))
        for part in Path(STAGE).parts:
            path /= part
            pins.enter_context(api.pin(path, directory=True))
        pins.enter_context(PrivateDirectory().pin(ROOT/STAGE, private=True, directory=True))
        raws = {}
        for name, expected in {**old.SOURCE_PINS, **FROZEN, **NEW_PINS}.items():
            raws[name] = refresh.pin_bytes(ROOT, pins, api, name, expected=expected)
        # Build transform validates complete NEW_PINS, even for identity/export.
        prepared_driver(raws[DRIVER], '0'*32)
        docker, _, config, _ = refresh.tools(ROOT, pins, api)
        call = old.Commands(docker, config)
        with old.legacy_lock(api):
            with continuation.atomic_private_lock(ROOT/STAGE/'interpreter.lock', api):
                historical_bindings(pins, api)
                yield api, pins, call, raws
        require(not call.uncertain, 'FINAL_CLI_UNCONFIRMED')


def validate_build(value):
    require(type(value) is dict and value.get('compiler_success') is True
        and value.get('reason') == 'EXIT' and type(value.get('exit')) is int and value['exit'] == 0
        and all(value.get(k) is True for k in ('cli_reaped','threads_joined','streams_closed'))
        and value.get('cleanup_uncertain') is False and value.get('iidfile_status') == 'VERIFIED_FORMAT'
        and re.fullmatch('sha256:[0-9a-f]{64}', value.get('iidfile') or '') is not None,
        'BUILD_DID_NOT_PASS')
    token = value.get('reservation')
    require(type(token) is str and re.fullmatch('[0-9a-f]{32}', token) is not None
        and value.get('tag') == 'kapit-public-strict-build:'+token
        and type(value.get('context')) is str and
        re.fullmatch(re.escape(STAGE).replace('/', r'[/\\]')+r'[/\\]ctx-interpreter-[0-9a-f]{32}', value['context']) is not None,
        'BUILD_BINDING_CHANGED')
    require(type(value.get('context_files')) is dict and len(value['context_files']) == 29,
            'CONTEXT_BINDING_CHANGED')
    return value


def revalidate_context(api, pins, value):
    """Replay authenticated pure inputs and retain every actual context byte."""
    refresh, *_ = modules()
    from infra.evidence_interpreter_build import source_build_inputs, MIN_BUILD_FREE_BYTES
    from infra.live_recovery_drill import PrivateDirectory
    raws = [refresh.pin_bytes(ROOT, pins, api, STAGE+'/'+name, maximum=256*1024*1024)
        for name in ('clamav-1.4.6.tar.gz','clamav-1.4.6.tar.gz.sig',
                     'builder-packages.json','builder-debs.tar')]
    patch = refresh.pin_bytes(ROOT,pins,api,PIN_NAMES[2],expected=NEW_PINS[PIN_NAMES[2]])
    recipe = refresh.pin_bytes(ROOT,pins,api,PIN_NAMES[1],expected=NEW_PINS[PIN_NAMES[1]])
    # This is deterministic input reconstruction, not a claim about disk now.
    prepared = source_build_inputs(raws[0],raws[1],patch,raws[2],raws[3],recipe,
                                   free_bytes=MIN_BUILD_FREE_BYTES)
    rows = {name:{'bytes':len(raw),'sha256':digest(raw)} for name,raw in prepared.files.items()}
    require(value['context_files'] == rows, 'CONTEXT_ROWS_CHANGED')
    relative = value['context'].replace('\\','/')
    pins.enter_context(PrivateDirectory().pin(ROOT/relative,private=True,directory=True))
    for name, expected in rows.items():
        from infra.evidence_native_refresh import Reader
        Reader(ROOT,pins,api).parents(relative+'/'+name,private=True)
        raw = refresh.pin_bytes(ROOT,pins,api,relative+'/'+name,private=True,
                                expected=expected['sha256'],maximum=256*1024*1024)
        require(len(raw) == expected['bytes'], 'CONTEXT_BYTES_CHANGED')


def prior_build(pins, api):
    refresh, *_ = modules()
    raw = refresh.pin_bytes(ROOT, pins, api, BUILD)
    parent = refresh.document(raw)
    require(parent.get('completed') is True and parent.get('status') == 'COMPLETE'
        and parent.get('pins_closed') is True and parent.get('stage') == 'build', 'BUILD_PARENT_REFUSED')
    name = parent.get('driver_receipt')
    require(type(name) is str and re.fullmatch(r'ai/state/private-scanner-interpreter-compile-[0-9a-f]{32}\.json', name) is not None)
    driver_raw = refresh.pin_bytes(ROOT, pins, api, name, expected=parent['driver_receipt_sha256'])
    value = validate_build(refresh.document(driver_raw))
    revalidate_context(api,pins,value)
    return value, name, digest(driver_raw)


def inspect_image(call, build):
    from infra.evidence_native_refresh import document
    code, out, err, reason = call('image','inspect',build['tag'])
    require(type(code) is int and code == 0 and reason == 'EXIT' and err == b'')
    docs = document(out)
    require(type(docs) is list and len(docs) == 1 and type(docs[0]) is dict)
    doc = docs[0]; descriptor = doc.get('Descriptor')
    require(type(descriptor) is dict and descriptor.get('digest') == doc.get('Id')
        and re.fullmatch('sha256:[0-9a-f]{64}', doc.get('Id') or '') is not None
        and descriptor.get('annotations',{}).get('config.digest') == build['iidfile']
        and descriptor.get('mediaType') == 'application/vnd.docker.distribution.manifest.v2+json'
        and type(descriptor.get('size')) is int and 0 < descriptor['size'] <= 65536
        and doc.get('Os') == 'linux' and doc.get('Architecture') == 'amd64'
        and doc.get('RepoTags') == [build['tag']] and doc.get('Config',{}).get('Labels') == {
            'org.kapit.owner':'kapit-public-strict-build-v1',
            'org.kapit.reservation':build['reservation'],
            'org.opencontainers.image.source':'https://github.com/rust-lang/docker-rust'}, 'IMAGE_BINDING_CHANGED')
    rootfs = doc.get('RootFS')
    require(type(rootfs) is dict and rootfs.get('Type') == 'layers' and type(rootfs.get('Layers')) is list
        and 1 <= len(rootfs['Layers']) <= 32 and all(type(v) is str and re.fullmatch('sha256:[0-9a-f]{64}',v)
            is not None for v in rootfs['Layers']), 'ROOTFS_CHANGED')
    return doc


def build_stage(api, pins, call, raws, result):
    refresh, *_ = modules()
    resume = load_fixed('ai/state/private-scanner-resume-pcre.py', raws['ai/state/private-scanner-resume-pcre.py'])
    source = prepared_driver(raws[DRIVER], uuid.uuid4().hex)
    postflight = resume['live_postflight_module'](api, pins)
    with postflight['observe']() as observed:
        result['builder_engine_sha256'] = observed.result['engine_sha256']
        _, old, _, _ = modules()
        require(observed.result['engine_sha256'] == old.ENGINE, 'BUILDER_ENGINE_CHANGED')
        original = live_originals(call)
        original.consume()
        observed.consume()
        namespace = {'__name__':'__main__','__file__':str(ROOT/DRIVER)}
        exec(compile(source, '<reviewed-interpreter-build>', 'exec'), namespace)
        path = namespace.get('receipt')
        require(isinstance(path, Path) and path.parent == ROOT/'ai/state'
            and re.fullmatch(r'private-scanner-interpreter-compile-[0-9a-f]{32}\.json',path.name) is not None)
        raw = refresh.pin_bytes(ROOT, pins, api, path.relative_to(ROOT).as_posix())
        value = validate_build(refresh.document(raw))
        revalidate_context(api,pins,value)
        result.update(driver_receipt=path.relative_to(ROOT).as_posix(), driver_receipt_sha256=digest(raw))
    live_originals(call).consume()


def identity_stage(api, pins, call, raws, result):
    build, name, sha = prior_build(pins, api)
    live_originals(call).consume()
    doc = inspect_image(call, build)
    result.update(image_id=doc['Id'], config_digest=build['iidfile'], descriptor=doc['Descriptor'],
        rootfs=doc['RootFS'], reservation=build['reservation'], tag=build['tag'],
        build_receipt=name, build_receipt_sha256=sha, source_pins=dict(NEW_PINS),
        context_files=build['context_files'], container_created=False)


def export_stage(api, pins, call, raws, result):
    refresh, *_ = modules()
    build, name, sha = prior_build(pins, api)
    raw = refresh.pin_bytes(ROOT, pins, api, IDENTITY)
    identity = refresh.document(raw)
    require(identity.get('completed') is True and identity.get('pins_closed') is True
        and identity.get('build_receipt') == name and identity.get('build_receipt_sha256') == sha
        and identity.get('source_pins') == NEW_PINS, 'IDENTITY_REFUSED')
    live_originals(call).consume()
    doc = inspect_image(call, build)
    require(doc['Id'] == identity['image_id'] and doc['Descriptor'] == identity['descriptor']
        and doc['RootFS'] == identity['rootfs'], 'IMAGE_CHANGED')
    exporter = load_fixed('ai/state/private-scanner-export.py', raws['ai/state/private-scanner-export.py'])['Exporter']
    export = exporter(doc['Id'], 'compiler')
    result.update(image_id=doc['Id'], config_digest=build['iidfile'], identity_sha256=digest(raw),
        export_receipt=export.receipt.relative_to(ROOT).as_posix(), directory=export.directory.relative_to(ROOT).as_posix())
    with export:
        for path in EXPORT_PATHS:
            require(export.copy(path) is not None, 'EXPORT_MISSING')
    require(export.cleaned is True and export.cli_uncertain is False and len(export.rows) == 10,
            'EXPORT_CLEANUP_UNCONFIRMED')
    result.update(files=export.rows, original_id=export.cid, never_started=True,
                  original_id_absent_verified=True)
    live_originals(call).consume()


def execute(stage):
    require(stage in ('build','identity','export'), 'STAGE_REFUSED')
    refresh, *_ = modules()
    result = {'schema':1, 'scope':'PUBLIC_INTERPRETER_COMPILER_NOT_NATIVE_PROOF',
        'stage':stage, 'status':'REFUSED', 'completed':False, 'pins_closed':False,
        'native_eligible':False, 'private_input_allowed':False, 'control_state_modified':False}
    receipt = refresh.Receipt(ROOT/{'build':BUILD,'identity':IDENTITY,'export':EXPORT}[stage], result)
    started = time.monotonic(); failure = None
    try:
        with checked_inputs() as (api, pins, call, raws):
            {'build':build_stage,'identity':identity_stage,'export':export_stage}[stage](api,pins,call,raws,result)
        result['pins_closed'] = True
        require(time.monotonic()-started < (1200 if stage == 'build' else 780), 'FINAL_DEADLINE')
        result.update(status='COMPLETE', completed=True)
    except BaseException as error:
        failure = error
        result.update(status='REFUSED', completed=False, failure_code='INTERPRETER_COMPILE_REFUSED')
    finally:
        result['total_seconds'] = round(time.monotonic()-started,3)
        try:
            receipt.save(result); receipt.close()
        except BaseException:
            result.update(status='REFUSED',completed=False,failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            try:
                if not receipt.stream.closed: receipt.save(result)
            finally:
                receipt.close()
            raise Refused('RECEIPT_CLOSE_UNCONFIRMED') from None
    require(failure is None)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('build','identity','export'))
    args = parser.parse_args(argv)
    result = execute(args.stage)
    print(json.dumps({'stage':args.stage,'status':result['status'],'native_eligible':False}), flush=True)


if __name__ == '__main__':
    main()
