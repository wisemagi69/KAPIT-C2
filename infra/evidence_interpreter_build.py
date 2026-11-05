"""Offline, side-effect-free input preparation for the derived scanner build.

Hash binding is not signature authentication or authorization to run a build.
The operator independently verifies the source/signatures and reviews the lock.
This module never invokes Docker, a compiler, a scanner, or a package installer.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import MappingProxyType

SOURCE_SHA256 = '06dbc7adf96e2f6a27c548a841ce83c95360d1e121b106a6f7cf56f282a3c61b'
PATCH_SHA256 = '1b1d289e9e23567d253b04fc4c17d647905dcd5f774247feaa132fbe54388223'
RECIPE_SHA256 = '5215c1413e87b7440f544a1e97a3938bada812e315d2c04718bba012d4e5ed75'
MEMBERS = {
    'libclamav/scanners.c': '591abfd9c277089836150216fe33c45d2d92830d16e8f917b7996f11688dc1d1',
    'libclamav/clamav.h': '54f81b4d2f7cbbc832953cd4cd546f147b283664dcd17ecda67299ca489fbffd',
    'libclamav/png.c': '84387247363c75516e66a63beb07f121909e4f5618da513bd97a9aa69264eaa5',
    'libclamav/jpeg.c': 'a296d814986ef0d66bbdde0bcfabbc3ece37ef634468dd5c96a79ae3aaa1a661',
    'libclamav/matcher.c': '3cdbc1f230306239266de9265367c8f744eb8ad8fbe8c4b9fe67967f0b49b15b',
    'libclamav/libclamav.map': '737f7055ac79782e1265c890f4b1c6d51a0db73ffc78b841db776d0225cdb4cf',
    'libclamav/matcher-pcre.c': '6ad04c8f181379d411f83fb5a182edc51ac845e4a7a5b93d5dd0be2f4d68d3dc',
    'libclamav/others.c': 'ff9cb0cd2bfd3d4c891787364cf5e59860d3bf1e3164207bdb3b161bd859dce7',
    'libclamav/bytecode.c': '84421778f125853bb235c7c98fbe4f5e36b1a259ed960a6797d940b1ab9ea48b',
}
RUNTIME_IMAGE = 'docker.io/library/python@sha256:9bbb8720ae0a24a6ca8dd678bfdf57818fe70caf54c52a53ec01d8db43405056'
BUILDER_IMAGE = 'docker.io/library/rust@sha256:4727898c104ecd2e22d780925832502faee9fe4e70581b8572af081370b315a0'
BUILDER_MAP_SHA256 = '6c8b1cff196a3097312ac3186a3d241b8da77628b4d1dd034848ffbe1cfdc7b5'
BUILDER_MAP_BYTES = 6631
BUILDER_MAP_CANONICAL_SHA256 = 'df72486dcba1e17a8d1a6638494dad316097918547c54edf93c313a276d14759'
BUILDER_SUMS_SHA256 = '2ae7af1b9a1e9e26edadc63ed927184e1388158b32510dd74bcc36a7fcbf235d'
MIN_BUILD_FREE_BYTES = 6*1024**3
SOURCE_DATE_EPOCH = 1772496000
WORKER_POLICY_SHA256 = '1e2b71ab05a6905a3c9edfe056cf83ddb4df0170560f1f04a0e7978741358105'
MODULE_PINS = {
    'evidence_native_worker.py': '3cebed0fbccb579dc6890f28071b80936d194876c69957eb4820f2564713c991',
    'evidence_scan_protocol.py': 'a7b277e7697e59e41b95014499f56276cde55af710b8065cb213fca0e5295973',
    'evidence_protocol.py': 'c4df88f7f2c0da2fd9307ec1b1330f08e37454089f5e906f3073fdc3429f5d9d',
    'evidence_policy.py': '753d77708453eca0cfe9c4ea8eeccfdd9cc075c508db50521231f9bda478626b',
    'evidence_decoder.py': 'e14693494249d528c98478c9c260bbf3ba900a8a77dc9b4cc2baf30d87f7beda',
    'evidence_linux.py': 'de930340e056f64157e4ab82e6a528a2ff362477278a5e711d815606e96de0bb',
    '__init__.py': hashlib.sha256(b'').hexdigest(),
}
PACKAGE_ARTIFACTS = frozenset('kapit_evidence/'+name for name in MODULE_PINS)
CVDS = frozenset({'main.cvd', 'daily.cvd', 'bytecode.cvd'})
PILLOW_SHA256 = 'e91c2b1cbeae768c98752e67e717e283d68dae45717b41f2d91eaee648e37b7d'
PILLOW_BYTES = 7142574
PILLOW_FILENAME = 'pillow-13.0.0-cp314-cp314-manylinux_2_27_x86_64.manylinux_2_28_x86_64.whl'
ARTIFACTS = frozenset({
    'source.tar.gz', 'source.tar.gz.sig',
    'builder-packages.json', 'builder-debs.tar', 'runtime-closure.tar', 'pillow.whl',
    'toolchain-inventory.json', 'toolchain-packages.tsv', 'toolchain-versions.txt', 'runtime.json',
    'main.cvd', 'daily.cvd', 'bytecode.cvd', 'signature-verification.json',
    'signature-files.json',
}) | PACKAGE_ARTIFACTS
LOCK_FIELDS = frozenset({'schema', 'derived_version', 'builder_image', 'runtime_image',
                         'source_sha256', 'patch_sha256', 'artifacts',
                         'policy_sha256', 'signature_generation'})
SHA = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'docker\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}\Z')


class BuildUnavailable(Exception):
    def __init__(self):
        super().__init__('NATIVE_BUILD_INPUTS_UNAVAILABLE')


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildUnavailable()
        result[key] = value
    return result


def parse_lock(raw: bytes) -> dict:
    """Accept only a bounded complete pin set; no booleans confer trust."""
    try:
        if not isinstance(raw, bytes) or not 1 <= len(raw) <= 16384:
            raise BuildUnavailable()
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_closed_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(BuildUnavailable()))
        if not isinstance(value, dict) or set(value) != LOCK_FIELDS:
            raise BuildUnavailable()
        if type(value['schema']) is not int or value['schema'] != 1:
            raise BuildUnavailable()
        if value['derived_version'] != '1.4.6-kapit-strict2':
            raise BuildUnavailable()
        if value['runtime_image'] != RUNTIME_IMAGE or value['source_sha256'] != SOURCE_SHA256:
            raise BuildUnavailable()
        if value['builder_image'] != BUILDER_IMAGE:
            raise BuildUnavailable()
        if value['patch_sha256'] != PATCH_SHA256:
            raise BuildUnavailable()
        if value['policy_sha256'] != WORKER_POLICY_SHA256:
            raise BuildUnavailable()
        if type(value['signature_generation']) is not str or not SHA.fullmatch(value['signature_generation']) or value['signature_generation'] == '0'*64:
            raise BuildUnavailable()
        rows = value['artifacts']
        if not isinstance(rows, dict) or set(rows) != ARTIFACTS:
            raise BuildUnavailable()
        for name, row in rows.items():
            if not isinstance(row, dict) or set(row) != {'sha256', 'bytes'}:
                raise BuildUnavailable()
            if not isinstance(row['sha256'], str) or not SHA.fullmatch(row['sha256']) or row['sha256'] == '0'*64:
                raise BuildUnavailable()
            minimum = 0 if name == 'kapit_evidence/__init__.py' else 1
            if type(row['bytes']) is not int or not minimum <= row['bytes'] <= 1024**3:
                raise BuildUnavailable()
        if rows['source.tar.gz']['sha256'] != SOURCE_SHA256:
            raise BuildUnavailable()
        if rows['builder-packages.json'] != {'sha256': BUILDER_MAP_SHA256, 'bytes': BUILDER_MAP_BYTES}:
            raise BuildUnavailable()
        if rows['pillow.whl'] != {'sha256': PILLOW_SHA256, 'bytes': PILLOW_BYTES}:
            raise BuildUnavailable()
        for name, digest in MODULE_PINS.items():
            row = rows['kapit_evidence/'+name]
            if row['sha256'] != digest or (name == '__init__.py' and row['bytes'] != 0):
                raise BuildUnavailable()
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError, KeyError):
        raise BuildUnavailable() from None


def apply_exact_patch(members: dict[str, bytes], patch: bytes) -> dict[str, bytes]:
    """Apply the reviewed unified patch with exact positions/context, zero fuzz.

    No filesystem paths are opened. Only the pinned source members can change.
    All original files are hash checked before any output is produced.
    """
    try:
        if type(patch) is not bytes or set(members) != set(MEMBERS) or not 1 <= len(patch) <= 65536 or sha256(patch) != PATCH_SHA256:
            raise BuildUnavailable()
        for name, digest in MEMBERS.items():
            if type(members[name]) is not bytes or sha256(members[name]) != digest:
                raise BuildUnavailable()
        lines = patch.decode('utf-8').splitlines(keepends=True)
        output, i = {}, 0
        while i < len(lines):
            if not lines[i].startswith('--- a/') or i + 1 >= len(lines):
                raise BuildUnavailable()
            name = lines[i][6:].rstrip('\n')
            if name not in MEMBERS or name in output or lines[i+1] != '+++ b/' + name + '\n':
                raise BuildUnavailable()
            original = members[name].decode('utf-8').splitlines(keepends=True)
            result, cursor = [], 0
            i += 2
            while i < len(lines) and not lines[i].startswith('--- '):
                match = re.fullmatch(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@\n', lines[i])
                if not match:
                    raise BuildUnavailable()
                old_start, old_count, new_start, new_count = map(int, match.groups())
                if old_start - 1 < cursor or old_start - 1 > len(original):
                    raise BuildUnavailable()
                result.extend(original[cursor:old_start-1]); cursor = old_start-1
                if len(result) != new_start - 1:
                    raise BuildUnavailable()
                i += 1; before = after = 0
                while i < len(lines) and lines[i][:1] in {' ', '+', '-'} and not lines[i].startswith('--- '):
                    marker, body = lines[i][0], lines[i][1:]
                    if marker in {' ', '-'}:
                        if cursor >= len(original) or original[cursor] != body:
                            raise BuildUnavailable()
                        cursor += 1; before += 1
                    if marker in {' ', '+'}:
                        result.append(body); after += 1
                    i += 1
                if (before, after) != (old_count, new_count):
                    raise BuildUnavailable()
            result.extend(original[cursor:]); output[name] = ''.join(result).encode('utf-8')
        if set(output) != set(MEMBERS):
            raise BuildUnavailable()
        return output
    except (ValueError, TypeError, KeyError, UnicodeError, IndexError):
        raise BuildUnavailable() from None


def verify_artifacts(lock: dict, artifacts: dict[str, bytes]) -> None:
    """Pure byte verification; deliberately does not extract untrusted archives."""
    try:
        lock = parse_lock(json.dumps(lock, separators=(',', ':'), allow_nan=False).encode())
    except (ValueError, TypeError, RecursionError):
        raise BuildUnavailable() from None
    if set(artifacts) != ARTIFACTS:
        raise BuildUnavailable()
    for name, row in lock['artifacts'].items():
        _verify_bytes(row, artifacts[name])


def _verify_bytes(row: dict, raw: bytes) -> None:
    if type(raw) is not bytes or len(raw) != row['bytes'] or sha256(raw) != row['sha256']:
        raise BuildUnavailable()


def _fixed_recipe(template: bytes) -> bytes:
    if type(template) is not bytes or sha256(template) != RECIPE_SHA256 or b'@@' in template or BUILDER_IMAGE.encode() not in template:
        raise BuildUnavailable()
    return template


def render_recipe(lock_raw: bytes, patch: bytes, template: bytes, *, artifacts=None, library_bytes=None, now=None) -> bytes:
    """Final-runtime-only validator. Source builds use source_build_inputs."""
    lock = parse_lock(lock_raw)
    _fixed_recipe(template)
    if type(patch) is not bytes or sha256(patch) != lock['patch_sha256'] or type(artifacts) is not dict:
        raise BuildUnavailable()
    verify_artifacts(lock, artifacts)
    builder_deb_context(artifacts['builder-packages.json'], artifacts['builder-debs.tar'])
    verify_toolchain_inventory(artifacts['toolchain-inventory.json'], artifacts['toolchain-packages.tsv'], artifacts['toolchain-versions.txt'], artifacts['builder-packages.json'])
    selected = {name: artifacts[name] for name in PACKAGE_ARTIFACTS | CVDS | {'signature-files.json'}}
    generated = make_runtime_configuration(lock_raw, selected, library_bytes, now=now)
    if artifacts['runtime.json'] != generated or not artifacts['runtime-closure.tar']:
        raise BuildUnavailable()
    return template


def archive_member_allowed(name: str) -> bool:
    """Lexical prerequisite for a future reviewed context extractor, not extraction."""
    if not isinstance(name, str) or not 1 <= len(name) <= 240 or '\\' in name or ':' in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and all(p not in {'', '.', '..'} for p in name.split('/'))


def signature_generation(raw: bytes, cvd_bytes: dict[str, bytes], *, now: datetime) -> str:
    """Recompute common-manifest generation from exact verified metadata/bytes.

    This validates bindings, not official signatures. The protected operator
    supplies the metadata from an independently authenticated verification run.
    """
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 8192 or set(cvd_bytes) != CVDS:
            raise BuildUnavailable()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None or now.utcoffset().total_seconds() != 0:
            raise BuildUnavailable()
        rows = json.loads(raw.decode('utf-8'), object_pairs_hook=_closed_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(BuildUnavailable()))
        if type(rows) is not list or len(rows) != 3:
            raise BuildUnavailable()
        names = []
        for row in rows:
            if type(row) is not dict or set(row) != {'name', 'sha256', 'version', 'signed_at', 'verification_receipt_sha256'}:
                raise BuildUnavailable()
            name = row['name']
            if type(name) is not str or name not in CVDS or name in names:
                raise BuildUnavailable()
            names.append(name)
            if type(row['version']) is not int or not 1 <= row['version'] <= 2147483647:
                raise BuildUnavailable()
            for key in ('sha256', 'verification_receipt_sha256'):
                if type(row[key]) is not str or not SHA.fullmatch(row[key]) or row[key] == '0'*64:
                    raise BuildUnavailable()
            stamp = row['signed_at']
            if type(stamp) is not str or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', stamp):
                raise BuildUnavailable()
            if datetime.fromisoformat(stamp.replace('Z', '+00:00')) > now:
                raise BuildUnavailable()
            if type(cvd_bytes[name]) is not bytes or not 1 <= len(cvd_bytes[name]) <= 256*1024*1024 or sha256(cvd_bytes[name]) != row['sha256']:
                raise BuildUnavailable()
        if names != sorted(CVDS):
            raise BuildUnavailable()
        return sha256(json.dumps(rows, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii'))
    except (ValueError, UnicodeError, TypeError, RecursionError, KeyError):
        raise BuildUnavailable() from None


def make_runtime_configuration(lock_raw: bytes, artifacts: dict[str, bytes], library_bytes: bytes, *, now: datetime) -> bytes:
    """Postcompile pure packaging step. Does not attest native trust or readiness.

    First build the source-only Docker build stage; the operator then exports its
    exact compiled library. Its computed hash closes the runtime.json output
    without making a prebuild-lock/output-hash cycle. The final image hash-only
    check refuses any changed compiled output.
    """
    lock = parse_lock(lock_raw)
    expected = PACKAGE_ARTIFACTS | CVDS | {'signature-files.json'}
    if set(artifacts) != expected or type(library_bytes) is not bytes or not 1 <= len(library_bytes) <= 256*1024*1024:
        raise BuildUnavailable()
    for name in expected:
        _verify_bytes(lock['artifacts'][name], artifacts[name])
    generation = signature_generation(artifacts['signature-files.json'], {name: artifacts[name] for name in CVDS}, now=now)
    if generation != lock['signature_generation']:
        raise BuildUnavailable()
    files = {name: sha256(artifacts['kapit_evidence/'+name]) for name in MODULE_PINS}
    files.update({name: sha256(artifacts[name]) for name in CVDS})
    files['clamav'] = sha256(library_bytes)
    return json.dumps({'schema': 1, 'policy_sha256': WORKER_POLICY_SHA256,
                       'signature_generation': generation, 'files': files},
                      sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')


def pillow_requirements() -> bytes:
    return ('pillow==13.0.0 --hash=sha256:'+PILLOW_SHA256+'\n').encode('ascii')


def runtime_context_files(lock_raw: bytes, artifacts: dict[str, bytes], library_bytes: bytes, *, now: datetime) -> dict[str, bytes]:
    """Return fixed context names only; never create files or extract archives."""
    expected = PACKAGE_ARTIFACTS | CVDS | {'signature-files.json', 'pillow.whl'}
    if set(artifacts) != expected:
        raise BuildUnavailable()
    lock = parse_lock(lock_raw)
    _verify_bytes(lock['artifacts']['pillow.whl'], artifacts['pillow.whl'])
    runtime = make_runtime_configuration(lock_raw, {k: v for k, v in artifacts.items() if k != 'pillow.whl'}, library_bytes, now=now)
    result = {name: artifacts[name] for name in PACKAGE_ARTIFACTS}
    result.update({'signatures/'+name: artifacts[name] for name in CVDS})
    result.update({'runtime.json': runtime, 'signature-files.json': artifacts['signature-files.json'],
                   'wheels/requirements.txt': pillow_requirements(),
                   'wheels/'+PILLOW_FILENAME: artifacts['pillow.whl']})
    return result


def require_build_space(free_bytes: int) -> None:
    """Root supplies a fresh host free-space measurement before owned build.

    This pure guard cannot monitor the VM/host while compiling. The root-owned
    executor must keep monitoring and stop its owned build when space is low;
    no helper deletes anything to make room.
    """
    if type(free_bytes) is not int or free_bytes < MIN_BUILD_FREE_BYTES:
        raise BuildUnavailable()


def builder_packages(raw: bytes) -> dict:
    """Exact source-pinned seventeen-row map derived from the signed index.

    Neither a caller's index hash field nor a verified boolean confers trust.
    The full record bytes AND canonical structure are source pinned.
    """
    try:
        if type(raw) is not bytes or len(raw) != BUILDER_MAP_BYTES or sha256(raw) != BUILDER_MAP_SHA256:
            raise BuildUnavailable()
        doc = json.loads(raw.decode('utf-8'), object_pairs_hook=_closed_object,
                         parse_constant=lambda _: (_ for _ in ()).throw(BuildUnavailable()))
        canonical = json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
        if sha256(canonical) != BUILDER_MAP_CANONICAL_SHA256 or type(doc) is not dict or type(doc.get('packages')) is not list or len(doc['packages']) != 17:
            raise BuildUnavailable()
        expected = {}
        for row in doc['packages']:
            if type(row) is not dict or set(row) != {'package', 'version', 'architecture', 'filename', 'basename', 'bytes', 'sha256'}:
                raise BuildUnavailable()
            name = row['basename']
            if type(name) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+~%-]{0,99}\.deb', name) or name in expected:
                raise BuildUnavailable()
            if not archive_member_allowed(row['filename']) or PurePosixPath(row['filename']).name != name or not row['filename'].startswith('pool/main/'):
                raise BuildUnavailable()
            if type(row['bytes']) is not int or not 1 <= row['bytes'] <= 256*1024*1024 or type(row['sha256']) is not str or not SHA.fullmatch(row['sha256']):
                raise BuildUnavailable()
            expected[name] = {'bytes': row['bytes'], 'sha256': row['sha256']}
        return expected
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise BuildUnavailable() from None


def _octal(raw: bytes) -> int:
    text = raw.rstrip(b'\0 ').lstrip(b' ')
    if not re.fullmatch(b'[0-7]{1,12}', text):
        raise BuildUnavailable()
    return int(text, 8)


def _regular_tar_members(raw: bytes, expected: dict) -> dict[str, bytes]:
    """Minimal bounded USTAR reader, never extraction or a general tar parser.

    Reject extension/longname/sparse records before their payload is parsed.
    Every member is a fixed regular basename with exact size+hash; no hidden
    extra bytes in padding, end records, duplicate names, links or path prefixes.
    """
    try:
        if type(raw) is not bytes or not 1024 <= len(raw) <= 512*1024*1024 or len(raw) % 512 or not 1 <= len(expected) <= 128:
            raise BuildUnavailable()
        result, offset, ended = {}, 0, False
        while offset < len(raw):
            header = raw[offset:offset+512]
            if len(header) != 512:
                raise BuildUnavailable()
            if not any(header):
                if len(raw)-offset < 1024 or any(raw[offset:]):
                    raise BuildUnavailable()
                ended = True
                break
            if len(result) >= 128 or header[156:157] not in (b'0', b'\0') or header[257:265] != b'ustar\x0000' or any(header[345:500]):
                raise BuildUnavailable()
            if _octal(header[148:156]) != sum(header[:148])+8*32+sum(header[156:]):
                raise BuildUnavailable()
            field = header[:100]; name_raw = field.split(b'\0', 1)[0]
            if field[len(name_raw):] != b'\0'*(100-len(name_raw)):
                raise BuildUnavailable()
            name = name_raw.decode('ascii')
            if name not in expected or name in result or '/' in name or '\\' in name or not archive_member_allowed(name):
                raise BuildUnavailable()
            size = _octal(header[124:136]); row = expected[name]
            if size != row['bytes'] or not 1 <= size <= 256*1024*1024:
                raise BuildUnavailable()
            start = offset+512; end = start+size; next_offset = start+((size+511)//512)*512
            if next_offset > len(raw) or any(raw[end:next_offset]):
                raise BuildUnavailable()
            content = raw[start:end]
            _verify_bytes(row, content)
            result[name] = content; offset = next_offset
        if not ended or set(result) != set(expected):
            raise BuildUnavailable()
        return result
    except (ValueError, TypeError, UnicodeError, KeyError):
        raise BuildUnavailable() from None


def builder_deb_context(metadata_raw: bytes, archive_raw: bytes) -> dict[str, bytes]:
    """Pure fixed context mapping. Full real seventeen-deb closure required."""
    expected = builder_packages(metadata_raw)
    members = _regular_tar_members(archive_raw, expected)
    sums = ''.join(expected[name]['sha256']+'  '+name+'\n' for name in sorted(expected)).encode('ascii')
    if sha256(sums) != BUILDER_SUMS_SHA256:
        raise BuildUnavailable()
    return {'builder-debs/'+name: content for name, content in members.items()} | {'builder-debs/SHA256SUMS': sums}


def verify_toolchain_inventory(raw: bytes, packages: bytes, versions: bytes, metadata_raw: bytes) -> None:
    """Bind actual postinstall outputs, never a caller readiness boolean."""
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 4096 or type(packages) is not bytes or not 1 <= len(packages) <= 262144 or type(versions) is not bytes or not 1 <= len(versions) <= 16384:
            raise BuildUnavailable()
        doc = json.loads(raw.decode('ascii'), object_pairs_hook=_closed_object)
        keys = {'schema', 'purpose', 'base_image', 'builder_packages_sha256', 'baseline_status_sha256',
                'baseline_inventory_sha256', 'installed_inventory_sha256', 'tool_versions_sha256', 'installed_status_sha256'}
        if type(doc) is not dict or set(doc) != keys or type(doc['schema']) is not int or doc['schema'] != 1 or doc['purpose'] != 'offline-builder-toolchain-v1' or doc['base_image'] != BUILDER_IMAGE:
            raise BuildUnavailable()
        fixed = {'builder_packages_sha256': BUILDER_MAP_SHA256,
                 'baseline_status_sha256': '1d015cf7c0f25e096a890997e51b4a26376b6882fc351f5e4d814f9e38a11a8e',
                 'baseline_inventory_sha256': '8299ca428236ff8c647b6ece22ae2d873bb5885b50a1b00b81830e774950ecfc',
                 'installed_inventory_sha256': sha256(packages), 'tool_versions_sha256': sha256(versions)}
        if any(doc[key] != value for key, value in fixed.items()) or type(doc['installed_status_sha256']) is not str or not SHA.fullmatch(doc['installed_status_sha256']):
            raise BuildUnavailable()
        # The raw TSV must contain the exact resolved package versions. Actual
        # provenance of these outputs still comes from the owned build execution.
        rows = {}
        for line in packages.decode('ascii').splitlines():
            name, version, arch = line.split('\t')
            name = name.removesuffix(':amd64')
            if name in rows or arch not in ('amd64', 'all'):
                raise BuildUnavailable()
            rows[name] = (version, arch)
        builder_packages(metadata_raw)
        required = json.loads(metadata_raw.decode('utf-8'))['packages']
        if any(rows.get(row['package']) != (row['version'], row['architecture']) for row in required):
            raise BuildUnavailable()
    except (ValueError, TypeError, UnicodeError, KeyError):
        raise BuildUnavailable() from None


def _source_members(raw: bytes) -> dict[str, bytes]:
    if type(raw) is not bytes or len(raw) != 45990124 or sha256(raw) != SOURCE_SHA256:
        raise BuildUnavailable()
    selected, names, count, total = {}, set(), 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            for member in archive:
                count += 1
                if count > 16000 or not (member.isdir() or member.isreg()) or member.linkname or member.size > 16*1024*1024:
                    raise BuildUnavailable()
                name = member.name.rstrip('/')
                if len(name) > 240 or not archive_member_allowed(name) or name.casefold() in names:
                    raise BuildUnavailable()
                names.add(name.casefold())
                if name == 'clamav-1.4.6':
                    if not member.isdir(): raise BuildUnavailable()
                    continue
                if not name.startswith('clamav-1.4.6/'):
                    raise BuildUnavailable()
                relative = name[len('clamav-1.4.6/'):]
                # Every source path will be extracted only inside Linux. Also
                # reject Windows-special components to keep the context portable.
                if any(part.endswith(('.', ' ')) or ':' in part for part in relative.split('/')):
                    raise BuildUnavailable()
                if member.isreg():
                    total += member.size
                    if total > 256*1024*1024: raise BuildUnavailable()
                if relative in MEMBERS:
                    if not member.isreg(): raise BuildUnavailable()
                    stream = archive.extractfile(member)
                    if stream is None: raise BuildUnavailable()
                    with stream: selected[relative] = stream.read(1024*1024)
        if count != 12439 or total != 219199236 or set(selected) != set(MEMBERS):
            raise BuildUnavailable()
        return selected
    except (tarfile.TarError, OSError, EOFError, ValueError, UnicodeError, RecursionError):
        raise BuildUnavailable() from None


@dataclass(frozen=True)
class SourceBuildInputs:
    files: object

    @property
    def target(self): return 'build'

    @property
    def scope(self): return 'PUBLIC_SOURCE_BUILD_ONLY'

    @property
    def runtime_eligible(self): return False


def source_build_inputs(source_archive: bytes, source_signature: bytes, patch: bytes, metadata_raw: bytes,
                        deb_archive: bytes, template: bytes, *, free_bytes: int) -> SourceBuildInputs:
    """Authorized source-only bootstrap; no fake postbuild closure is needed.

    Validates the exact authenticated release and bounded member inventory but
    outputs the compressed release plus just nine patched overlays. No host
    extraction, native launch, filesystem mutation or activation takes place.
    """
    require_build_space(free_bytes)
    _fixed_recipe(template)
    _verify_bytes({'bytes': 801, 'sha256': 'f55ae2aa17482cf870f16578e56c2d77885c22ac748ebee9f6808c4dbba93bea'}, source_signature)
    patched = apply_exact_patch(_source_members(source_archive), patch)
    files = builder_deb_context(metadata_raw, deb_archive)
    files.update({'Dockerfile': template, 'source.tar.gz': source_archive})
    files.update({'patched/'+name: raw for name, raw in patched.items()})
    return SourceBuildInputs(MappingProxyType(files))


def main() -> int:
    # Default/import preparation does not open artifacts, keys, Docker or files.
    print(json.dumps({'status': 'NATIVE_BUILD_INPUTS_REQUIRED', 'native_enabled': False}, separators=(',', ':')))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
