"""Root fixed public image acquisition. No container, extraction or native run."""
from contextlib import ExitStack
from pathlib import Path, PurePosixPath
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid

from infra.evidence_tools import Windows
from infra.live_recovery_drill import PrivateDirectory
from infra import evidence_container as commands

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / '.cache/m1-runtime/private-scanner-build'
DOCKER = ROOT / '.cache/m1-runtime/container-tools/docker.exe'
CONFIG = STAGE / 'build-client/runtime-config1'
MAXIMUM = 512 * 1024**2


def inventory(path):
    """Bounded raw tar walk, without extraction or automatic PAX processing."""
    rows = {}; total = 0; zeroes = 0
    def text_field(raw):
        first, separator, padding = raw.partition(b'\0')
        assert not any(padding)
        return first.decode('ascii')
    with path.open('rb') as stream:
        while True:
            raw = stream.read(512)
            assert len(raw) == 512
            if not any(raw):
                zeroes += 1
                if zeroes == 2:
                    while block := stream.read(65536):
                        assert not any(block)
                    break
                continue
            assert zeroes == 0 and len(rows) < 256
            assert raw[156:157] in (b'0', b'\0', b'5')
            assert raw[257:265] == b'ustar\x0000' and not any(raw[500:512])
            assert int(raw[148:156].strip(b'\0 '), 8) == sum(raw[:148]) + 8*32 + sum(raw[156:])
            name = text_field(raw[:100])
            prefix = text_field(raw[345:500])
            if prefix: name = prefix + '/' + name
            directory = raw[156:157] == b'5'
            identity = name[:-1] if directory and name.endswith('/') else name
            relative = PurePosixPath(identity)
            assert name and not relative.is_absolute() and '\\' not in name
            assert all(p not in ('', '.', '..') for p in identity.split('/'))
            assert relative.as_posix() == identity and re.fullmatch(r'[A-Za-z0-9_./+-]{1,511}', identity)
            assert identity not in rows and not any(raw[157:257])
            assert directory or not name.endswith('/')
            size = int(raw[124:136].strip(b'\0 '), 8)
            assert 0 <= size <= MAXIMUM and total + size <= MAXIMUM
            assert raw[156:157] != b'5' or size == 0
            offset = stream.tell(); digest = hashlib.sha256(); remaining = size
            while remaining:
                block = stream.read(min(65536, remaining)); assert block
                remaining -= len(block); digest.update(block)
            padding = (-size) % 512; assert stream.read(padding) == b'\0' * padding
            rows[identity] = {'bytes': size, 'offset': offset, 'sha256': digest.hexdigest(), 'directory': directory}
            total += size
    return rows


def acquire_archive(result, token, destination, actual_identity):
    api = Windows(); private = PrivateDirectory()
    process = None; threads = []; failed = threading.Event(); stderr = bytearray()
    completed = False; archive = destination / 'image.tar'
    with ExitStack() as pins:
        pins.enter_context(private.pin(STAGE, private=True, directory=True))
        pins.enter_context(private.pin(DOCKER.parent, private=True, directory=True))
        source = pins.enter_context(api.pin(DOCKER))
        assert hashlib.sha256(source.read()).hexdigest() == '0d24d78cfc6262aefc82e175123d0f0d81d416882b12893002383168a8ca6935'
        source = pins.enter_context(api.pin(CONFIG / 'config.json', private=True))
        assert source.read(129) == b'{"auths":{}}\n'
        source = pins.enter_context(api.pin(ROOT / 'ai/state/private-scanner-runtime-build.py'))
        raw = source.read(); assert hashlib.sha256(raw).hexdigest() == '954ec7caba97e7260ef2c1abc753a280428f82812c994b6bd16bd98fb93b2a18'
        function = next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == 'stop_owned')
        namespace = {}; exec(compile(ast.Module(body=[function], type_ignores=[]), '<reviewed-owned-cleanup>', 'exec'), namespace)
        stop_owned = namespace['stop_owned']
        argv = [str(DOCKER), '--host', commands.ENDPOINT, '--config', str(CONFIG)]
        code, out, err, reason = commands._bounded_command([*argv, 'image', 'inspect', actual_identity['image_id']], timeout=15, maximum=65536)
        assert code == 0 and reason == 'EXIT' and not err
        docs = json.loads(out); assert type(docs) is list and len(docs) == 1
        actual = docs[0]
        assert actual['Id'] == actual_identity['image_id'] and actual['Os'] == 'linux' and actual['Architecture'] == 'amd64'
        expected = json.loads((ROOT / 'ai/state/private-scanner-interpreter-runtime-image.json').read_text(encoding='utf-8'))
        assert expected == actual_identity
        assert actual['Descriptor'] == expected['descriptor'] and actual['RootFS'] == expected['rootfs']
        assert actual['Config'] == expected['config'] and shutil.disk_usage(ROOT).free >= 3*1024**3
        private.create(destination)
        pins.enter_context(private.pin(destination, private=True, directory=True))
        with archive.open('xb'): pass
        api.protect(archive)
        with archive.open('r+b') as target:
            def reader(pipe, save):
                try:
                    count = 0
                    while block := pipe.read1(65536):
                        count += len(block)
                        assert count <= (MAXIMUM if save else 65536)
                        if save: target.write(block)
                        else: stderr.extend(block)
                except BaseException: failed.set()
            started = time.monotonic()
            result['stage'] = 'CLI_ACQUISITION'
            try:
                process = subprocess.Popen([*argv, 'image', 'save', '--platform=linux/amd64', actual_identity['image_id']], stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','TEMP','TMP'}})
                for pipe, save in ((process.stdout, True), (process.stderr, False)):
                    thread = threading.Thread(target=reader, args=(pipe, save), daemon=True)
                    threads.append(thread); thread.start()
                while process.poll() is None:
                    assert not failed.is_set() and time.monotonic()-started < 180
                    assert shutil.disk_usage(ROOT).free >= 2*1024**3
                    time.sleep(.05)
                assert process.wait(timeout=5) == 0 and time.monotonic()-started < 180
                completed = True
            finally:
                stopped, joined, closed, uncertain = stop_owned(process, threads)
                result.update(cli_reaped=stopped, threads_joined=joined, streams_closed=closed, cli_uncertain=uncertain)
                assert stopped and joined and closed and not uncertain
                assert not failed.is_set()
            assert completed and not stderr
            target.flush(); os.fsync(target.fileno())
        source = pins.enter_context(api.pin(archive, private=True))
        raw_hash = hashlib.sha256(); size = 0
        while block := source.read(65536): raw_hash.update(block); size += len(block)
        assert 0 < size <= MAXIMUM
        result.update(stage='ARCHIVE_INVENTORY', archive_bytes=size, archive_sha256=raw_hash.hexdigest())
        result.update(status='ACQUIRED_NOT_YET_PROVENANCE_VERIFIED', members=inventory(archive),
                      seconds=round(time.monotonic()-started, 3))
        result['stage'] = 'PIN_RELEASE'


import zlib
HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")

def document(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result
            result[key] = value
        return result
    assert type(raw) is bytes and 0 < len(raw) <= 131072
    result = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                        parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    assert type(result) is dict
    return result


def gzip_digest(stream, size, *, deadline, maximum=512*1024**2):
    decoder = zlib.decompressobj(31)
    digest = hashlib.sha256()
    count = 0
    assert type(size) is int and 0 < size <= 512*1024**2
    remaining = size
    while remaining:
        assert time.monotonic() < deadline and not decoder.eof
        block = stream.read(min(65536, remaining))
        assert block
        remaining -= len(block)
        while block:
            assert time.monotonic() < deadline
            output = decoder.decompress(block, 65536)
            count += len(output)
            assert count <= maximum
            digest.update(output)
            assert not decoder.unused_data
            block = decoder.unconsumed_tail
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    return 'sha256:' + digest.hexdigest(), count


def checked_layout(manifest, config, actual):
    assert set(manifest) == {'schemaVersion', 'mediaType', 'config', 'layers'}
    assert type(manifest['schemaVersion']) is int and manifest['schemaVersion'] == 2
    assert manifest['mediaType'] == actual['descriptor']['mediaType'] == 'application/vnd.docker.distribution.manifest.v2+json'
    assert manifest['config']['mediaType'] == 'application/vnd.docker.container.image.v1+json'
    assert manifest['config']['digest'] == actual['config_digest']
    assert config['os'] == 'linux' and config['architecture'] == 'amd64'
    assert config['config'] == actual['config']
    assert config['rootfs'] == {'type': 'layers', 'diff_ids': actual['rootfs']['Layers']}
    assert type(manifest['layers']) is list and len(manifest['layers']) == len(actual['rootfs']['Layers']) == 13


def verify_archive(source, path, rows, actual, archive, *, deadline):
    digest = hashlib.sha256()
    size = 0
    while block := source.read(65536):
        assert time.monotonic() < deadline
        size += len(block)
        assert size <= 512*1024**2
        digest.update(block)
    assert size == archive['archive_bytes'] and digest.hexdigest() == archive['archive_sha256']

    def blob(descriptor, maximum):
        assert type(descriptor) is dict and set(descriptor) == {'mediaType', 'digest', 'size'}
        identity, length = descriptor['digest'], descriptor['size']
        assert type(identity) is str and HASH.fullmatch(identity)
        assert type(length) is int and 0 < length <= maximum
        row = rows['blobs/sha256/' + identity[7:]]
        assert not row['directory'] and row['bytes'] == length and row['sha256'] == identity[7:]
        return row

    descriptor = {key: actual['descriptor'][key] for key in ('mediaType', 'digest', 'size')}
    assert descriptor['digest'] == actual['image_id']
    row = blob(descriptor, 65536)
    source.seek(row['offset'])
    manifest = document(source.read(row['bytes']))
    row = blob(manifest['config'], 65536)
    source.seek(row['offset'])
    config = document(source.read(row['bytes']))
    checked_layout(manifest, config, actual)
    results, total = [], 0
    for index, layer in enumerate(manifest['layers']):
        assert layer['mediaType'] == 'application/vnd.docker.image.rootfs.diff.tar.gzip'
        row = blob(layer, 512*1024**2)
        source.seek(row['offset'])
        identity, count = gzip_digest(source, row['bytes'], deadline=deadline,
                                      maximum=min(512*1024**2, 1024**3-total))
        assert identity == config['rootfs']['diff_ids'][index]
        total += count
        assert total <= 1024**3
        results.append({'position': index, 'compressed_digest': layer['digest'],
                        'compressed_bytes': row['bytes'], 'diff_id': identity, 'uncompressed_bytes': count})
    assert time.monotonic() < deadline
    return {'scope': 'ACTUAL_FRESH_SAVED_OCI_MANIFEST_CONFIG_ORDERED_LAYER_BYTES', 'status': 'PASS',
            'image_id': actual['image_id'], 'config_digest': actual['config_digest'],
            'archive_sha256': archive['archive_sha256'], 'layers': results, 'uncompressed_bytes': total,
            'native_eligible': False, 'filesystem_or_notices_audited': False, 'container_created': False}


ACQUISITION = ROOT/'ai/state/private-scanner-interpreter-oci-acquisition.json'
VERIFIED = ROOT/'ai/state/private-scanner-interpreter-oci-verified.json'
RUNTIME_SHA256 = 'bc7b15fd9b1d202e07a43b07c626b131a1fdc029bd367ed6baa974a5378951b0'


def execute():
    from infra import evidence_interpreter_runtime as runtime
    from infra.evidence_interpreter_compile import checked_inputs, live_originals
    runtime.reviewed_constants()
    runtime.require(type(RUNTIME_SHA256) is str and re.fullmatch('[0-9a-f]{64}',RUNTIME_SHA256) is not None,
                    'RUNTIME_SOURCE_NOT_REVIEWED')
    runtime.require(Path.cwd().resolve() == ROOT, 'PROJECT_ROOT_REQUIRED')
    destination = STAGE/('oci-interpreter-'+uuid.uuid4().hex)
    result = {'scope':'PUBLIC_INTERPRETER_OCI_ACQUISITION_NOT_NATIVE_PROOF',
        'status':'REFUSED','native_eligible':False,'container_created':False,
        'directory':destination.relative_to(ROOT).as_posix(),'pins_closed':False}
    proof = {'scope':'PUBLIC_INTERPRETER_OCI_BYTES_NOT_NATIVE_PROOF',
        'status':'REFUSED','native_eligible':False,'container_created':False,'pins_closed':False}
    # Both fixed receipts are consumed before any protected/daemon operation.
    acquisition = runtime.Receipt(ACQUISITION,result)
    verification = None; failure = None; started = time.monotonic()
    try:
        verification = runtime.Receipt(VERIFIED,proof)
        with ExitStack() as pins:
            api,_,original_call,_ = pins.enter_context(checked_inputs())
            runtime.pin_bytes(ROOT,pins,api,'infra/evidence_interpreter_runtime.py',expected=RUNTIME_SHA256)
            actual = runtime.verified_image(ROOT,pins,api)
            live_originals(original_call).consume()
            result['image_id'] = actual['image_id']
            raw = runtime.pin_bytes(ROOT,pins,api,runtime.IMAGE)
            assert document(raw) == actual
            acquire_archive(result,uuid.uuid4().hex,destination,actual)
            pins.enter_context(PrivateDirectory().pin(destination,private=True,directory=True))
            source = pins.enter_context(api.pin(destination/'image.tar',private=True))
            observed = verify_archive(source,destination/'image.tar',inventory(destination/'image.tar'),
                                      actual,result,deadline=time.monotonic()+120)
            live_originals(original_call).consume()
        assert time.monotonic()-started < 600
        result.update(status='ACQUIRED_AND_OCI_BYTES_VERIFIED',pins_closed=True)
        proof.update(observed,pins_closed=True)
    except BaseException as error:
        failure = error
        result.update(status='REFUSED',failure_code='OCI_OR_CHECKED_CLEANUP_UNCONFIRMED')
        proof.update(status='REFUSED',failure_code='OCI_OR_CHECKED_CLEANUP_UNCONFIRMED')
    finally:
        result['total_seconds'] = round(time.monotonic()-started,3)
        try:
            acquisition.save(result)
            if verification is not None:verification.save(proof)
            acquisition.close()
            if verification is not None:verification.close()
        except BaseException:
            result.update(status='REFUSED',failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            proof.update(status='REFUSED',failure_code='RECEIPT_CLOSE_UNCONFIRMED')
            for receipt,value in ((acquisition,result),(verification,proof)):
                if receipt is not None:
                    try:
                        if not receipt.stream.closed:receipt.save(value)
                    except BaseException:pass
                    finally:
                        try:receipt.close()
                        except BaseException:pass
            raise runtime.RefreshUnavailable('RECEIPT_CLOSE_UNCONFIRMED') from None
    runtime.require(failure is None,'OCI_OR_CHECKED_CLEANUP_UNCONFIRMED')
    return proof


def main():
    import argparse
    argparse.ArgumentParser(description=__doc__).parse_args()
    result=execute()
    print(json.dumps({key:value for key,value in result.items() if key != 'layers'}),flush=True)


if __name__ == '__main__':main()

