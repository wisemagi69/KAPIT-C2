"""Pure final runtime byte assembly; no files, Docker, native code or activation.

Bindings checked here are packaging identities, not provider authentication,
signature verification, ABI compatibility or a complete immutable-image proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import io
import json
from pathlib import PurePosixPath
import re
from types import MappingProxyType
import zipfile

from infra import evidence_native_build as build
from infra.evidence_elf import parse_elf, ElfUnavailable

COMPILER_IMAGE = 'sha256:b712bfbd9e15a3e0a973b3a6d9ca3574caa3c4c9cdfb3742b04c2bbd136f08d3'
RUNTIME_BASE = 'sha256:9bbb8720ae0a24a6ca8dd678bfdf57818fe70caf54c52a53ec01d8db43405056'
MAX_ARCHIVE = 512*1024*1024
NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._+\-]{0,254}\Z', re.ASCII)
RECEIPT = re.compile(r'ai/state/private-scanner-export-[0-9a-f]{32}\.json\Z')
BASE_DIRS = frozenset(('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/usr/local/lib', '/lib64'))
WHEEL_ROOT = '/usr/local/lib/python3.14/site-packages/'
LIBRARY_PATH = '/opt/clamav/lib/libclamav.so.12.0.3'
COMPANION_PATH = '/opt/clamav/lib/libclammspack.so.0'
RUNTIME_RECIPE_SHA256 = '0ce8da5d07069c92602849d81a4cad7c141fde9c203de01ecdb1996da713b85e'
_GLIBC = r'(?:c|m|mvec|pthread|dl|rt|resolv|util|anl|BrokenLocale|thread_db|memusage|pcprofile|SegFault|c_malloc_debug|nsl|nss_[A-Za-z0-9_]+)'
_PROTECTED = re.compile(r'(?:ld(?:-linux[A-Za-z0-9_-]*|-[0-9][A-Za-z0-9._+-]*)?\.so(?:\.[0-9]+)*|lib'+_GLIBC+r'(?:-[0-9][A-Za-z0-9._+-]*)?\.so(?:\.[0-9]+)*)\Z')


class PackageUnavailable(ValueError):
    def __str__(self): return 'NATIVE_PACKAGE_INPUTS_UNAVAILABLE'


def _require(value):
    if value is not True: raise PackageUnavailable()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result); result[key] = value
    return result


def _document(raw):
    _require(type(raw) is bytes and 1 <= len(raw) <= 262144)
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(PackageUnavailable()))
        pending = [(value, 0)]; count = 0
        while pending:
            node, depth = pending.pop(); count += 1
            _require(depth <= 16 and count <= 20000)
            if type(node) is dict: pending.extend((item, depth+1) for item in node.values())
            elif type(node) is list: pending.extend((item, depth+1) for item in node)
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise PackageUnavailable() from None


def _text(field):
    body, sep, padding = field.partition(b'\x00')
    _require(not sep or not any(padding))
    return body.decode('ascii')


def _octal(field):
    body = field.strip(b'\x00 ')
    _require(not body or all(char in b'01234567' for char in body))
    return int(body or b'0', 8)


def _closure_members(raw):
    _require(type(raw) is bytes and 1536 <= len(raw) <= MAX_ARCHIVE and len(raw) % 512 == 0)
    files = {}; folded = set(); pos = 0; total = 0
    try:
        while pos + 512 <= len(raw):
            header = raw[pos:pos+512]
            if not any(header):
                _require(len(raw)-pos >= 1024 and not any(raw[pos:])); break
            _require(len(files) < 128 and header[156:157] in (b'0', b'\x00') and header[257:265] == b'ustar\x0000')
            _require(not any(header[157:257]) and not any(header[345:512]))
            _require(_octal(header[148:156]) == sum(header[:148])+8*32+sum(header[156:]))
            name = _text(header[:100])
            _require(name == 'inventory.json' or (name.startswith('lib/') and NAME.fullmatch(name[4:]) is not None))
            _require(name.casefold() not in folded); folded.add(name.casefold())
            for start, end in ((100,108),(108,116),(116,124),(136,148),(329,337),(337,345)):
                _octal(header[start:end])
            size = _octal(header[124:136]); total += size
            _require(1 <= size <= 256*1024*1024 and total <= MAX_ARCHIVE)
            end = pos+512+size; padded = (end+511)//512*512
            _require(padded <= len(raw) and not any(raw[end:padded]))
            files[name] = raw[pos+512:end]; pos = padded
        else:
            raise PackageUnavailable()
        _require('inventory.json' in files)
        return files
    except (ValueError, UnicodeError, OverflowError):
        raise PackageUnavailable() from None


def _path(value):
    _require(type(value) is str and 1 <= len(value) <= 512 and value.isascii())
    path = PurePosixPath(value)
    _require(value.startswith('/') and not value.startswith('//') and str(path) == value and
             all(NAME.fullmatch(part) is not None and part not in ('.', '..') for part in path.parts[1:]))
    return path


def _inventory(raw, files, library_bytes):
    doc = _document(raw)
    keys = {'schema','scope','compiler_image','runtime_base','inventory','edges','cycles','export_receipts','native_executed','native_eligible'}
    _require(type(doc) is dict and set(doc) == keys and type(doc['schema']) is int and doc['schema'] == 1)
    _require(doc['scope'] == 'ACTUAL_PUBLIC_ELF_DEPENDENCY_CLOSURE_NOT_NATIVE_PROOF' and doc['compiler_image'] == COMPILER_IMAGE and doc['runtime_base'] == RUNTIME_BASE)
    _require(doc['native_executed'] is False and doc['native_eligible'] is False)
    receipts = doc['export_receipts']
    _require(type(receipts) is list and len(receipts) == 2 and all(type(item) is str and RECEIPT.fullmatch(item) is not None for item in receipts) and len(set(receipts)) == 2)
    entries = doc['inventory']; edges = doc['edges']; cycles = doc['cycles']
    _require(type(entries) is list and 1 <= len(entries) <= 128 and type(edges) is list and len(edges) <= 1024 and type(cycles) is list and len(cycles) <= 128)
    records = {}; expected = {}; total = 0; providers = {}
    for row in entries:
        _require(type(row) is dict and set(row) == {'path','origin','sha256','size','soname'})
        path = _path(row['path']); key = str(path)
        _require(key not in records and type(row['size']) is int and 1 <= row['size'] <= 256*1024*1024 and type(row['sha256']) is str and build.SHA.fullmatch(row['sha256']) is not None)
        _require(row['sha256'] != '0'*64 and (row['soname'] is None or (type(row['soname']) is str and NAME.fullmatch(row['soname']) is not None)))
        total += row['size']; _require(total <= MAX_ARCHIVE)
        origin = row['origin']; parent = str(path.parent)
        if origin == 'root': _require(parent in ('/opt/clamav/lib', WHEEL_ROOT+'PIL', WHEEL_ROOT+'pillow.libs'))
        elif origin == 'base': _require(parent in BASE_DIRS)
        elif origin == 'builder':
            _require(parent == '/builder' and row['soname'] is not None)
            member = 'lib/'+row['soname']; _require(member not in expected); expected[member] = row
        else: raise PackageUnavailable()
        if origin != 'base':
            _require(not any(_PROTECTED.fullmatch(name) for name in {path.name,row['soname']}-{None}))
        for name in {path.name, row['soname']} - {None}:
            _require(name not in providers); providers[name] = key
        records[key] = row
    _require(list(records) == sorted(records) and LIBRARY_PATH in records)
    lib = records[LIBRARY_PATH]
    _require(lib['origin'] == 'root' and lib['sha256'] == build.sha256(library_bytes) and lib['size'] == len(library_bytes))
    library_info = parse_elf(library_bytes)
    _require(library_info.soname == lib['soname'])
    _require(set(files) == {'inventory.json'} | set(expected))
    for name, row in expected.items():
        _require(len(files[name]) == row['size'] and build.sha256(files[name]) == row['sha256'])
        info = parse_elf(files[name])
        _require(info.soname == row['soname'])
    pairs = set(); seen_edges = set(); adjacency = {key: set() for key in records}
    for edge in edges:
        _require(type(edge) is list and len(edge) == 3 and all(type(item) is str for item in edge))
        source, name, provider = edge
        _require(source in records and provider in records and NAME.fullmatch(name) is not None and providers.get(name) == provider)
        triple = tuple(edge); _require(triple not in seen_edges); seen_edges.add(triple)
        pairs.add((source,provider)); adjacency[source].add(provider)
    _require(edges == sorted(edges))
    seen_cycles = set()
    for cycle in cycles:
        _require(type(cycle) is list and 2 <= len(cycle) <= 129 and all(type(item) is str and item in records for item in cycle))
        _require(cycle[0] == cycle[-1] and len(set(cycle[:-1])) == len(cycle)-1 and all((a,b) in pairs for a,b in zip(cycle,cycle[1:])))
        item = tuple(cycle); _require(item not in seen_cycles); seen_cycles.add(item)
    visited = set(); pending = [key for key,row in records.items() if row['origin'] == 'root']
    while pending:
        path = pending.pop()
        if path not in visited:
            visited.add(path); pending.extend(adjacency[path]-visited)
    _require(visited == set(records))
    # Compare actual DT_NEEDED sets for the bytes supplied here. Base and other
    # build-output providers still require the separate real-image audit.
    known = {LIBRARY_PATH: library_info}
    known.update({row['path']:parse_elf(files[name]) for name,row in expected.items()})
    for path,info in known.items():
        _require(set(info.needed) == {edge[1] for edge in edges if edge[0] == path})
    return records


def closure_context(raw, library_bytes):
    """Closed archive/graph byte binding only, not complete provider/ELF proof."""
    try:
        _require(type(library_bytes) is bytes and 1 <= len(library_bytes) <= 256*1024*1024)
        files = _closure_members(raw)
        _inventory(files['inventory.json'], files, library_bytes)
        return {'closure/'+name: value for name,value in files.items()}
    except (ElfUnavailable, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise PackageUnavailable() from None


def _wheel_rows(raw, records):
    # Parse only the exact reviewed wheel, never arbitrary compressed input.
    _require(type(raw) is bytes and len(raw) == build.PILLOW_BYTES and build.sha256(raw) == build.PILLOW_SHA256)
    wanted = {path[len(WHEEL_ROOT):]: row for path,row in records.items() if path.startswith(WHEEL_ROOT)}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist(); _require(len(entries) <= 512)
        names = [entry.filename for entry in entries]; _require(len(set(names)) == len(names))
        actual = {}; total = 0
        for entry in entries:
            if entry.is_dir(): continue
            _require((entry.external_attr >> 16) & 0o170000 in (0,0o100000))
            _require(0 <= entry.file_size <= 256*1024*1024)
            total += entry.file_size; _require(total <= 256*1024*1024)
            with archive.open(entry) as stream:
                magic = stream.read(4)
                if magic != b'\x7fELF': continue
                _require(entry.filename.startswith(('PIL/','pillow.libs/')) and '/' not in entry.filename.split('/',1)[1])
                data = magic+stream.read(entry.file_size)
                _require(len(data) == entry.file_size)
                actual[entry.filename] = parse_elf(data)
        _require(len(actual) == 26 and set(actual) == set(wanted))
        for name,info in actual.items():
            row = wanted[name]
            _require(info.sha256 == row['sha256'] and info.size == row['size'] and info.soname == row['soname'])
        return actual


def clamav_context(records, library_bytes, clammspack_bytes, edges):
    """Bind both real compiler exports; regular alias copies, never symlinks."""
    expected = {LIBRARY_PATH: ('libclamav.so.12',library_bytes),
                COMPANION_PATH: ('libclammspack.so.0',clammspack_bytes)}
    _require({path for path in records if path.startswith('/opt/clamav/lib/')} == set(expected))
    for path,(soname,data) in expected.items():
        _require(type(data) is bytes and 1 <= len(data) <= 256*1024*1024)
        row = records[path]; info = parse_elf(data)
        _require(row['origin'] == 'root' and row['sha256'] == info.sha256 and row['size'] == info.size and row['soname'] == soname == info.soname)
        _require(set(info.needed) == {edge[1] for edge in edges if edge[0] == path})
    return {'clamav/lib/libclamav.so.12.0.3':library_bytes,
            'clamav/lib/libclamav.so.12':library_bytes,
            'clamav/lib/libclammspack.so.0':clammspack_bytes}


def _runtime_recipe(raw):
    _require(type(raw) is bytes and build.sha256(raw) == RUNTIME_RECIPE_SHA256)
    return raw


def _runtime(artifacts, library_bytes, *, now):
    _require(type(library_bytes) is bytes and 1 <= len(library_bytes) <= 256*1024*1024)
    for name,digest in build.MODULE_PINS.items():
        _require(build.sha256(artifacts['kapit_evidence/'+name]) == digest)
    generation = build.signature_generation(artifacts['signature-files.json'], {name:artifacts[name] for name in build.CVDS}, now=now)
    # Bind metadata to actual receipt bytes; this does not authenticate its issuer.
    rows = json.loads(artifacts['signature-files.json'].decode('utf-8'))
    _require(all(row['verification_receipt_sha256'] == build.sha256(artifacts['signature-verification.json']) for row in rows))
    files = {name:build.sha256(artifacts['kapit_evidence/'+name]) for name in build.MODULE_PINS}
    files.update({name:build.sha256(artifacts[name]) for name in build.CVDS})
    files['clamav'] = build.sha256(library_bytes)
    return _json({'schema':1, 'policy_sha256':build.WORKER_POLICY_SHA256, 'signature_generation':generation, 'files':files}), generation


@dataclass(frozen=True)
class RuntimePackage:
    lock_raw: bytes
    runtime_json: bytes
    files: MappingProxyType

    @property
    def runtime_eligible(self): return False


def assemble_runtime(artifacts, library_bytes, patch, recipe, *, clammspack_bytes, runtime_recipe, now: datetime):
    """Actual byte inputs only. No filesystem write/free-space/readiness claim."""
    try:
        _require(type(artifacts) is dict and set(artifacts) == build.ARTIFACTS-{'runtime.json'})
        _require(all(type(value) is bytes and len(value) <= 1024**3 for value in artifacts.values()) and sum(map(len, artifacts.values())) <= 2*1024**3)
        _runtime_recipe(runtime_recipe)
        # A real output is constructed before the complete lock, never a zero
        # hash or placeholder artifact intended to satisfy a prebuild lock.
        runtime, generation = _runtime(artifacts, library_bytes, now=now)
        complete = dict(artifacts); complete['runtime.json'] = runtime
        lock = _json({'schema':1, 'derived_version':'1.4.6-kapit-strict1', 'builder_image':build.BUILDER_IMAGE,
                      'runtime_image':build.RUNTIME_IMAGE, 'source_sha256':build.SOURCE_SHA256, 'patch_sha256':build.PATCH_SHA256,
                      'policy_sha256':build.WORKER_POLICY_SHA256, 'signature_generation':generation,
                      'artifacts':{name:{'bytes':len(value),'sha256':build.sha256(value)} for name,value in complete.items()}})
        build.parse_lock(lock)
        build._verify_bytes({'bytes':801,'sha256':'f55ae2aa17482cf870f16578e56c2d77885c22ac748ebee9f6808c4dbba93bea'}, artifacts['source.tar.gz.sig'])
        patched = build.apply_exact_patch(build._source_members(artifacts['source.tar.gz']), patch)
        context = build.builder_deb_context(artifacts['builder-packages.json'], artifacts['builder-debs.tar'])
        build.verify_toolchain_inventory(artifacts['toolchain-inventory.json'], artifacts['toolchain-packages.tsv'], artifacts['toolchain-versions.txt'], artifacts['builder-packages.json'])
        context.update(closure_context(artifacts['runtime-closure.tar'], library_bytes))
        members = _closure_members(artifacts['runtime-closure.tar'])
        records = _inventory(members['inventory.json'], members, library_bytes)
        doc = _document(members['inventory.json'])
        context.update(clamav_context(records,library_bytes,clammspack_bytes,doc['edges']))
        wheel_info = _wheel_rows(artifacts['pillow.whl'], records)
        for name,info in wheel_info.items():
            _require(set(info.needed) == {edge[1] for edge in doc['edges'] if edge[0] == WHEEL_ROOT+name})
        build.render_recipe(lock, patch, recipe, artifacts=complete, library_bytes=library_bytes, now=now)
        selected = {name:artifacts[name] for name in build.PACKAGE_ARTIFACTS | build.CVDS | {'signature-files.json','pillow.whl'}}
        context.update(build.runtime_context_files(lock, selected, library_bytes, now=now))
        _require(context['runtime.json'] == runtime)
        # Preserve full source/patch/Deb/toolchain validation above but do not
        # send those build inputs into the runtime-only image context.
        context = {key:value for key,value in context.items() if not key.startswith('builder-debs/')}
        context.update({'Dockerfile':runtime_recipe})
        return RuntimePackage(lock, runtime, MappingProxyType(context))
    except (build.BuildUnavailable, ElfUnavailable, PackageUnavailable, ValueError, TypeError, KeyError, UnicodeError, RecursionError, zipfile.BadZipFile):
        raise PackageUnavailable() from None
