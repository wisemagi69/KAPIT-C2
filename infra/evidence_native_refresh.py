"""Root-only public runtime preparation. Importing performs no IO or activation.

Receipts bind public software bytes, not native eligibility. Actual CLI execution
is reserved to the orchestrator after independent review; tests use fake IO.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import zipfile

COMPILER = 'sha256:b712bfbd9e15a3e0a973b3a6d9ca3574caa3c4c9cdfb3742b04c2bbd136f08d3'
CONFIG = 'sha256:57a93047cf4fab8220df108187a97a6b3712d011a63cc271383c7de1bac21997'
MAIN_SHA = '6aaf6b32a818527d889590619a7e1dc710eafe125eca1e0b8bdf3a5f29d83aab'
BASE = 'sha256:9bbb8720ae0a24a6ca8dd678bfdf57818fe70caf54c52a53ec01d8db43405056'
STAGE = '.cache/m1-runtime/private-scanner-build'
BUILD = 'ai/state/private-scanner-compile-engine-readback-pcre-aa845a31d7e0466392defe3718a67cee.json'
IDENTITY = 'ai/state/private-scanner-compiler-image-readback-pcre.json'
EXPORT = 'ai/state/private-scanner-export-6cdede6a190b4c40acfc8177399ebe77.json'
BASE_EXPORT = 'ai/state/private-scanner-export-c8312402bab04cf7a125fc93555491ca.json'
SIGNATURE = 'ai/reports/devops-m4-signature-updater-recheck.json'
SIGNATURE_SHA = '8adf551490602fe11f881f9e588653d33fb238a558fc362911107aa5ca7aebfc'
CLOSURE = 'ai/state/private-scanner-refresh-closure-pcre.json'
INPUTS = 'ai/state/private-scanner-refresh-inputs-pcre.json'
PACKAGE = 'ai/state/private-scanner-refresh-package-pcre.json'
CLOSURE_DIR = STAGE+'/runtime-closure-readback'
INPUTS_DIR = STAGE+'/runtime-inputs-readback'
CONTEXT = STAGE+'/ctx-runtime-readback'
LOCK = STAGE+'/final-package-lock-readback-pcre.json'
RECEIPT_PINS = {
    BUILD: '0d8dd204234979f03b7fea0650b7f65afeb446080d08541a1d76122bdd8025a5',
    IDENTITY: 'ead4e0cbb082156a5994943aaed777a9600e96377da8bb0a4df9aeea2755d905',
    EXPORT: '960e66975c8400ee16e671ab7cad762f9dcf97109259f020a2f29eb636c98770',
    BASE_EXPORT: 'b32404d47545d70e826af14ac9381e46071be272e37cd773ba0330cf4e390529',
}
SOURCE_PINS = {
    'infra/evidence_native_package.py': '102a6ef2758ebb83fb66fa6a15080b0351cd6ecd528bd0b9a014baf949e61bcf',
    'infra/evidence_native_build.py': '2626b4e662e0f632ee52444e9bf68480b00d3a2d1ae9835294921798235b6702',
    'infra/evidence_elf.py': '03bc99b6d61eca34a682c90188fadd2179dc0fc8403955ba350a91538dd6b23e',
    'infra/evidence_tools.py': 'b3d57248598364fabb208ea303a00139e27c5db1dc3746c95e32eda240f7202c',
    'infra/live_recovery_drill.py': 'cd6d9608399f0995b865da142611432b0c8a95ea1a9501b143dabebdc004388c',
    'infra/native/Dockerfile.evidence-runtime': '0ce8da5d07069c92602849d81a4cad7c141fde9c203de01ecdb1996da713b85e',
    'infra/native/Dockerfile.evidence': 'a50b0a5b3bdddf9cf4a3e17b7e61172a996ec2973002937d2e55677c1a2a7239',
    'infra/native/clamav_strict.patch': '8e54280c6ad5c76c2748aae805a8cea85d69179ef9a57cbaf1af468a53db3eb4',
}
SHA = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9_.][A-Za-z0-9._+~-]{0,254}\Z')
MAX_FILE = 512*1024*1024


class RefreshUnavailable(ValueError):
    def __str__(self): return 'PUBLIC_RUNTIME_REFRESH_UNAVAILABLE'


def require(value):
    if value is not True: raise RefreshUnavailable()


def digest(raw): return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def document(raw):
    require(type(raw) is bytes and 1 <= len(raw) <= 262144)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result); result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                           parse_constant=lambda _: require(False))
        pending = [(value, 0)]; count = 0
        while pending:
            node, depth = pending.pop(); count += 1
            require(depth <= 16 and count <= 20000)
            if type(node) is dict: pending.extend((x, depth+1) for x in node.values())
            elif type(node) is list: pending.extend((x, depth+1) for x in node)
        return value
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise RefreshUnavailable() from None


def safe_name(name):
    require(type(name) is str and name.isascii() and 1 <= len(name) <= 512)
    require(str(PurePosixPath(name)) == name and not name.startswith('/') and
            all(NAME.fullmatch(part) is not None and part not in ('.', '..') for part in name.split('/')))
    reserved = {'CON','PRN','AUX','NUL'}|{'COM'+str(i) for i in range(1,10)}|{'LPT'+str(i) for i in range(1,10)}
    require(all(not part.endswith('.') and part.split('.',1)[0].upper() not in reserved for part in name.split('/')))
    return name


def checked_row(raw, row):
    require(type(row) is dict and type(row.get('bytes')) is int and 0 <= row['bytes'] <= MAX_FILE)
    require(type(row.get('sha256')) is str and SHA.fullmatch(row['sha256']) is not None)
    require(type(raw) is bytes and len(raw) == row['bytes'] and digest(raw) == row['sha256'])
    return raw


class Reader:
    def __init__(self, root, pins, api):
        self.root, self.pins, self.api = Path(root), pins, api
        # Existing native staging directories use PrivateDirectory's exact
        # three-principal DACL; regular protected files use Windows' two ACEs.
        if type(api).__module__ == 'infra.evidence_tools':
            from infra.live_recovery_drill import PrivateDirectory
            self.directory_api = PrivateDirectory()
        else:
            self.directory_api = api  # Pure fake IO only.

    def parents(self, relative, private=False):
        safe_name(relative)
        path = self.root
        self.pins.enter_context(self.api.pin(path, directory=True))
        for part in PurePosixPath(relative).parts[:-1]:
            path /= part
            protected = path.is_relative_to(self.root/STAGE)
            self.pins.enter_context((self.directory_api if protected else self.api).pin(path, directory=True, private=protected))

    def read(self, relative, row=None, *, private=False, limit=MAX_FILE):
        safe_name(relative); self.parents(relative, private)
        handle = self.pins.enter_context(self.api.pin(self.root/relative, private=private))
        raw = handle.read(limit+1); require(len(raw) <= limit)
        if row is not None: checked_row(raw, row)
        return raw

    def doc(self, relative, expected=None):
        raw = self.read(relative, limit=262144)
        if expected is not None: require(digest(raw) == expected)
        return document(raw), raw


def baseline(reader):
    for name, expected in SOURCE_PINS.items(): require(digest(reader.read(name)) == expected)
    docs = {name:reader.doc(name, expected)[0] for name, expected in RECEIPT_PINS.items()}
    build, identity, exported, base = [docs[name] for name in (BUILD, IDENTITY, EXPORT, BASE_EXPORT)]
    require(build['compiler_success'] is True and build['reason'] == 'EXIT' and build['exit'] == 0 and
            all(build[key] is True for key in ('cli_reaped','threads_joined','streams_closed')) and
            build['cleanup_uncertain'] is False and build['iidfile'] == CONFIG)
    require(identity['image_id'] == COMPILER and identity['config_digest'] == CONFIG and
            identity['build_receipt_sha256'] == RECEIPT_PINS[BUILD] and
            identity['reservation'] == build['reservation'] and identity['tag'] == build['tag'] and
            identity['descriptor']['digest'] == COMPILER and identity['descriptor']['annotations']['config.digest'] == CONFIG)
    for name, receipt, kind, image in ((EXPORT, exported, 'compiler', COMPILER), (BASE_EXPORT, base, 'python-base', BASE)):
        reservation = name.rsplit('-',1)[1].removesuffix('.json')
        require(receipt['kind'] == kind and receipt['scope'] == 'PUBLIC_ARTIFACT_EXPORT' and receipt['image'] == image and
                receipt['reservation'] == reservation and receipt['never_started'] is True and receipt['original_id_absent_verified'] is True and
                receipt['cleanup_status'] == 'ORIGINAL_ID_ABSENT_VERIFIED' and receipt['cli_cleanup_unconfirmed'] is False and
                receipt['directory'].replace('\\','/') == STAGE+'/export-'+reservation and receipt['native_eligible'] is False)
        require(type(receipt['files']) is dict and len(receipt['files']) == (10 if kind == 'compiler' else 12))
        require(len({row['local_name'] for row in receipt['files'].values()}) == len(receipt['files']))
        for row in receipt['files'].values():
            require(re.fullmatch(r'artifact-[0-9]{1,2}', row['local_name']) is not None)
    return exported, base


def export_bytes(reader, receipt, path):
    row = receipt['files'][path]
    return reader.read(receipt['directory'].replace('\\','/')+'/'+row['local_name'], row, private=True, limit=256*1024*1024)


def signatures(reader, now):
    from infra.evidence_native_build import CVDS, signature_generation
    receipt, raw = reader.doc(SIGNATURE, SIGNATURE_SHA)
    require(receipt['native_exit'] == 0 and receipt['code'] == 'UPDATER_COMPLETED' and receipt['activation'] == 'INACTIVE' and
            receipt['native_validation'] == 'DISABLED' and receipt['all_cvd_signatures_verified'] is True)
    checked = datetime.fromisoformat(receipt['executed_at_utc'])
    require(checked.utcoffset() is not None and checked.utcoffset().total_seconds() == 0 and 0 <= (now-checked).total_seconds() < 24*3600)
    rows = receipt['definition_files']
    require(type(rows) is list and len(rows) == 3 and {r['name'] for r in rows} == CVDS)
    files, metadata = {}, []
    for row in sorted(rows, key=lambda r:r['name']):
        require(row['signature_verification'] == 'VERIFIED' and row['verification_exit'] == 0)
        signed = datetime.fromisoformat(row['built_utc'])
        require(signed.utcoffset() is not None and signed.utcoffset().total_seconds() == 0 and signed <= now)
        if row['name'] == 'daily.cvd': require((now-signed).total_seconds() < 72*3600)
        files['signatures/'+row['name']] = reader.read('.cache/m1-runtime/evidence-tools/official-signatures-stage/'+row['name'], row, limit=256*1024*1024)
        metadata.append({'name':row['name'],'sha256':row['sha256'],'version':row['version'],'signed_at':row['built_utc'],'verification_receipt_sha256':digest(raw)})
    files['signature-files.json'] = canonical(metadata); files['signature-verification.json'] = raw
    generation = signature_generation(files['signature-files.json'], {n:files['signatures/'+n] for n in CVDS}, now=now)
    return files, generation, digest(raw)


def inputs(reader, now):
    from infra.evidence_native_build import MODULE_PINS, PILLOW_FILENAME, PILLOW_SHA256, PILLOW_BYTES
    files, generation, signature_sha = signatures(reader, now)
    for name, expected in MODULE_PINS.items():
        raw = b'' if name == '__init__.py' else reader.read('backend/apps/operations/'+name, limit=1024*1024)
        require(digest(raw) == expected); files['kapit_evidence/'+name] = raw
    files['wheels/'+PILLOW_FILENAME] = reader.read(STAGE+'/'+PILLOW_FILENAME, {'bytes':PILLOW_BYTES,'sha256':PILLOW_SHA256}, limit=8*1024*1024)
    return files, generation, signature_sha


def closure_files(reader, exported, base):
    from infra.evidence_elf import Artifact, resolve_closure
    from infra.evidence_native_build import PILLOW_FILENAME, PILLOW_SHA256, PILLOW_BYTES
    roots, bases, candidates = [], [], []
    library = export_bytes(reader, exported, '/out/opt/clamav/lib/libclamav.so.12.0.3')
    require(digest(library) == MAIN_SHA)
    roots.append(Artifact('/opt/clamav/lib/libclamav.so.12.0.3', library))
    wheel = reader.read(STAGE+'/'+PILLOW_FILENAME, {'bytes':PILLOW_BYTES,'sha256':PILLOW_SHA256}, limit=8*1024*1024)
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        entries = archive.infolist(); require(len(entries) <= 512 and len({e.filename for e in entries}) == len(entries))
        total = 0
        for item in entries:
            if item.is_dir(): continue
            safe_name(item.filename); total += item.file_size
            require(item.file_size <= 256*1024*1024 and total <= 256*1024*1024 and (item.external_attr >> 16) & 0o170000 in (0,0o100000))
            with archive.open(item) as stream:
                prefix = stream.read(4)
                if prefix == b'\x7fELF':
                    raw = prefix+stream.read(item.file_size); require(len(raw) == item.file_size)
                    roots.append(Artifact('/usr/local/lib/python3.14/site-packages/'+item.filename, raw))
    for path in exported['files']:
        if path == '/out/opt/clamav/lib/libclammspack.so.0': roots.append(Artifact(path.removeprefix('/out'), export_bytes(reader, exported, path)))
        elif path.startswith('/lib/x86_64-linux-gnu/'): candidates.append(Artifact('/builder/'+path.rsplit('/',1)[1], export_bytes(reader, exported, path)))
    for path in base['files']: bases.append(Artifact(path, export_bytes(reader, base, path)))
    require(len(roots) == 28 and len(bases) == 12 and len(candidates) == 4)
    closure = resolve_closure(roots=tuple(roots), base=tuple(bases), candidates=tuple(candidates))
    inventory = {'schema':1,'scope':'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF',
                 'compiler_image':COMPILER,'runtime_base':BASE,'inventory':[asdict(x) for x in closure.inventory],
                 'edges':closure.edges,'cycles':closure.cycles,'export_receipts':[EXPORT,BASE_EXPORT],
                 'native_executed':False,'native_eligible':False}
    files = {'inventory.json':canonical(inventory)}
    for item in closure.copies:
        if item.destination.startswith('/opt/closure/lib/'):
            files[item.destination.removeprefix('/opt/closure/')] = item.data
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            safe_name(name); info = tarfile.TarInfo(name); info.size = len(raw); info.mode = 0o644
            info.uid = info.gid = info.mtime = 0; archive.addfile(info, io.BytesIO(raw))
    files['runtime-closure.tar'] = buf.getvalue()
    return files


def rows(files): return {name:{'bytes':len(raw),'sha256':digest(raw)} for name,raw in sorted(files.items())}


def read_staged(reader, receipt, expected_directory):
    common = {'schema','scope','compiler_image','main_library_sha256','source_pins','native_eligible',
              'control_state_modified','upstream_receipts','directory','files'}
    extra = {CLOSURE_DIR:set(), INPUTS_DIR:{'signature_generation','signature_verification_receipt_sha256','staged_at'},
             CONTEXT:{'signature_generation','lock_path','lock_sha256','runtime_json_sha256'}}
    require(type(receipt) is dict and set(receipt) == common|extra[expected_directory] and receipt['schema'] == 1 and type(receipt['schema']) is int)
    require(receipt['directory'] == expected_directory and receipt['compiler_image'] == COMPILER and receipt['main_library_sha256'] == MAIN_SHA and
            receipt['source_pins'] == SOURCE_PINS and receipt['native_eligible'] is False and receipt['control_state_modified'] is False)
    require(type(receipt['files']) is dict and 1 <= len(receipt['files']) <= 128)
    return {safe_name(name):reader.read(expected_directory+'/'+name, row, private=True) for name,row in receipt['files'].items()}


def package_files(reader, now, exported, base):
    from infra.evidence_native_build import PILLOW_FILENAME
    from infra.evidence_native_package import assemble_runtime
    closure_doc, closure_raw = reader.doc(CLOSURE)
    closure = read_staged(reader, closure_doc, CLOSURE_DIR)
    require(closure_doc['upstream_receipts'] == RECEIPT_PINS and closure_doc['scope'] == 'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF')
    require(closure == closure_files(reader, exported, base))
    input_doc, input_raw = reader.doc(INPUTS)
    staged = read_staged(reader, input_doc, INPUTS_DIR)
    current, generation, signature_sha = inputs(reader, now)
    require(staged == current and input_doc['scope'] == 'PUBLIC_SOFTWARE_BUILD_STAGING_NOT_PUBLISHED_GENERATION' and input_doc['signature_generation'] == generation and input_doc['upstream_receipts'] == RECEIPT_PINS and input_doc['signature_verification_receipt_sha256'] == signature_sha)
    artifacts = {}
    for name, raw in staged.items():
        artifacts['pillow.whl' if name == 'wheels/'+PILLOW_FILENAME else name.removeprefix('signatures/')] = raw
    for dest, source in {'source.tar.gz':'clamav-1.4.6.tar.gz','source.tar.gz.sig':'clamav-1.4.6.tar.gz.sig','builder-packages.json':'builder-packages.json','builder-debs.tar':'builder-debs.tar'}.items():
        artifacts[dest] = reader.read(STAGE+'/'+source)
    for name in ('toolchain-packages.tsv','toolchain-versions.txt','toolchain-inventory.json'):
        artifacts[name] = export_bytes(reader, exported, '/opt/kapit-builder-provenance/'+name)
    artifacts['runtime-closure.tar'] = closure['runtime-closure.tar']
    library = export_bytes(reader, exported, '/out/opt/clamav/lib/libclamav.so.12.0.3')
    companion = export_bytes(reader, exported, '/out/opt/clamav/lib/libclammspack.so.0')
    package = assemble_runtime(artifacts, library, reader.read('infra/native/clamav_strict.patch'), reader.read('infra/native/Dockerfile.evidence'),
                               clammspack_bytes=companion, runtime_recipe=reader.read('infra/native/Dockerfile.evidence-runtime'), now=now)
    require(package.runtime_eligible is False and sum(map(len,package.files.values())) <= 256*1024*1024)
    upstream = dict(RECEIPT_PINS); upstream.update({CLOSURE:digest(closure_raw),INPUTS:digest(input_raw)})
    return package, generation, upstream


def verified_package(root, pins, api, *, now=None):
    """Validate every fresh byte; caller holds pins through its owned operation.

    Repeated calls are allowed. This intentionally replays the pure graph and
    packaging validation; it never grants a native/private readiness flag.
    """
    now = datetime.now(timezone.utc) if now is None else now
    reader = Reader(root, pins, api); exported, base = baseline(reader)
    receipt, _ = reader.doc(PACKAGE)
    actual = read_staged(reader, receipt, CONTEXT)
    require(receipt['schema'] == 1 and receipt['scope'] == 'PUBLIC_FINAL_RUNTIME_BUILD_INPUTS_NOT_NATIVE_PROOF' and receipt['lock_path'] == LOCK)
    package, generation, upstream = package_files(reader, now, exported, base)
    require(actual == dict(package.files) and receipt['upstream_receipts'] == upstream and receipt['signature_generation'] == generation and
            receipt['runtime_json_sha256'] == digest(package.runtime_json) and receipt['lock_sha256'] == digest(package.lock_raw))
    lock = reader.read(LOCK, private=True, limit=16384); require(lock == package.lock_raw)
    return receipt


def write_exclusive(path, raw):
    with path.open('xb') as stream:
        require(stream.write(raw) == len(raw)); stream.flush(); os.fsync(stream.fileno())


def write_files(reader, directory, files, private):
    target = reader.root/directory; require(not target.exists() and not target.is_symlink())
    private.create(target)
    reader.pins.enter_context(private.pin(target, directory=True, private=True))
    for name, raw in sorted(files.items()):
        safe_name(name); dest = target/name
        parent = target
        for part in PurePosixPath(name).parts[:-1]:
            parent /= part
            if not parent.exists(): private.create(parent)
        # Protected ancestor inheritance is checked before each exclusive write.
        reader.parents(directory+'/'+name, private=True)
        write_exclusive(dest, raw)
        reader.api.protect(dest)
        require(reader.read(directory+'/'+name, rows({name:raw})[name], private=True) == raw)


def execute(stage, root, api, private, *, now=None):
    """No success summary is emitted until all checked source/output pins close."""
    require(stage in ('closure','inputs','package'))
    now = datetime.now(timezone.utc) if now is None else now; root = Path(root)
    output = {'closure':CLOSURE,'inputs':INPUTS,'package':PACKAGE}[stage]
    require(not (root/output).exists() and not (root/output).is_symlink())
    require(shutil.disk_usage(root).free >= 3*1024**3)
    with ExitStack() as pins:
        reader = Reader(root, pins, api); exported, base = baseline(reader)
        result = {'schema':1,'compiler_image':COMPILER,'main_library_sha256':MAIN_SHA,'source_pins':SOURCE_PINS,
                  'native_eligible':False,'control_state_modified':False,'upstream_receipts':dict(RECEIPT_PINS)}
        if stage == 'closure':
            files = closure_files(reader, exported, base); directory = CLOSURE_DIR
            result['scope'] = 'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF'
        elif stage == 'inputs':
            files, generation, signature_sha = inputs(reader, now); directory = INPUTS_DIR
            result.update(scope='PUBLIC_SOFTWARE_BUILD_STAGING_NOT_PUBLISHED_GENERATION',signature_generation=generation,
                          signature_verification_receipt_sha256=signature_sha,staged_at=now.isoformat())
        else:
            require(not (root/LOCK).exists() and not (root/LOCK).is_symlink())
            package, generation, upstream = package_files(reader, now, exported, base)
            files = dict(package.files); directory = CONTEXT
            write_exclusive(root/LOCK, package.lock_raw)
            api.protect(root/LOCK)
            require(reader.read(LOCK, private=True, limit=16384) == package.lock_raw)
            result.update(scope='PUBLIC_FINAL_RUNTIME_BUILD_INPUTS_NOT_NATIVE_PROOF',signature_generation=generation,
                          lock_path=LOCK,lock_sha256=digest(package.lock_raw),runtime_json_sha256=digest(package.runtime_json),upstream_receipts=upstream)
        write_files(reader, directory, files, private)
        result.update(directory=directory,files=rows(files))
    # An ExitStack close/check exception prevents the receipt below entirely.
    write_exclusive(root/output, canonical(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('stage', choices=('closure','inputs','package'))
    args = parser.parse_args(argv)
    from infra.evidence_tools import Windows
    from infra.live_recovery_drill import PrivateDirectory
    root = Path(__file__).resolve().parents[1]
    try:
        result = execute(args.stage, root, Windows(), PrivateDirectory())
        print(json.dumps({k:v for k,v in result.items() if k not in ('files','upstream_receipts','source_pins')})); return 0
    except Exception as exc:
        print(json.dumps({'scope':'PUBLIC_RUNTIME_REFRESH_REFUSED','stage':args.stage,'error_class':type(exc).__name__,'native_eligible':False})); return 1


if __name__ == '__main__': raise SystemExit(main())
