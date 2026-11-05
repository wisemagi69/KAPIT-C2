"""Bounded, offline notice preparation from verified original package archives.

No package is imported or installed and no archive member is extracted to disk.
Declared licenses and preserved notices are evidence for review, not legal clearance.
"""
from __future__ import annotations

import argparse
import base64
import email.policy
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
import os
from pathlib import PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import zipfile

if __package__:
    from . import reproduce_python as replay
else:
    import reproduce_python as replay

ROOT = replay.ROOT
WEB_LOCK = ROOT / 'web/package-lock.json'
WEB_LOCK_SHA256 = '888dfe6b4c78c427bfae6e362c1f8b2bcb70aa0ff6b481ad77a1f2b6c6a1fb94'
WEB_PACKAGE = ROOT / 'web/package.json'
WEB_PACKAGE_SHA256 = 'cbb34c2c02644b9436068bf1ba524510b6f330a4a8a121b7e8a83f2e7d792d07'
CACHE = ROOT / '.cache/m1-runtime/npm-cache/_cacache/content-v2/sha512'
OUTPUT_JSON = ROOT / 'ai/reports/devops-m5-dependency-notices.json'
OUTPUT_TEXT = ROOT / 'ai/reports/devops-m5-dependency-notices-notice-text.md'
MAX_ARCHIVE = 40 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
MAX_MEMBER = 32 * 1024 * 1024
MAX_MEMBERS = 20000
MAX_TEXT = 2 * 1024 * 1024
MAX_NOTICES = 16 * 1024 * 1024
MAX_OUTPUT = 48 * 1024 * 1024


class NoticeError(RuntimeError):
    """Only fixed error codes may reach the CLI."""


def fail(code):
    raise NoticeError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')


def load_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail('DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        fail('JSON_REFUSED')


def safe_name(name):
    if (not isinstance(name, str) or not name or len(name.encode('utf-8')) > 1024
            or '\\' in name or ':' in name or name.startswith('/') or name.endswith('//')
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        fail('ARCHIVE_PATH_REFUSED')
    parts = name.rstrip('/').split('/')
    if any(p in ('', '.', '..') for p in parts):
        fail('ARCHIVE_PATH_REFUSED')
    # Also reject Windows device aliases and alternate ambiguous path spellings.
    for part in parts:
        if part.endswith((' ', '.')) or re.match(r'(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)', part):
            fail('ARCHIVE_PATH_REFUSED')
    return '/'.join(parts)


def notice_path(name):
    base = PurePosixPath(name).name.lower()
    return bool(re.match(r'^(?:licen[cs]e|copying|notice|copyright|authors)(?:$|[._-])', base))


def check_zip_directory(raw):
    """Walk real bounded records; never trust EOCD's advertised entry count."""
    end = raw.rfind(b'PK\x05\x06', max(0, len(raw) - 65557))
    if end < 0 or len(raw) - end < 22:
        fail('ARCHIVE_REFUSED')
    _, disk, central_disk, disk_count, expected_count, size, offset, comment = struct.unpack_from('<4s4H2LH', raw, end)
    if (disk or central_disk or disk_count != expected_count or expected_count > MAX_MEMBERS
            or expected_count == 65535 or offset + size != end or end + 22 + comment != len(raw)):
        fail('ARCHIVE_LIMIT')
    cursor, count, expanded = offset, 0, 0
    while cursor < end:
        if end - cursor < 46 or raw[cursor:cursor + 4] != b'PK\x01\x02':
            fail('ARCHIVE_REFUSED')
        fields = struct.unpack_from('<4s6H3L5H2L', raw, cursor)
        flags, method, compressed, uncompressed = fields[3], fields[4], fields[8], fields[9]
        name_size, extra_size, comment_size, start_disk, local_offset = fields[10], fields[11], fields[12], fields[13], fields[16]
        count += 1
        expanded += uncompressed
        next_record = cursor + 46 + name_size + extra_size + comment_size
        if (count > MAX_MEMBERS or not 0 < name_size <= 1024 or next_record > end
                or start_disk or local_offset >= offset or compressed == 0xffffffff
                or uncompressed > MAX_MEMBER or expanded > MAX_EXPANDED
                or flags & 1 or method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
            fail('ARCHIVE_LIMIT')
        cursor = next_record
    if cursor != end or count != expected_count:
        fail('ARCHIVE_LIMIT')


def archive_members(raw, kind):
    """Return selected metadata/notice bytes only; validate every member first."""
    if len(raw) > MAX_ARCHIVE:
        fail('ARCHIVE_LIMIT')
    chosen, seen, total, notice_total = {}, set(), 0, 0

    def accept(name, size, regular, directory, reader):
        nonlocal total, notice_total
        name = safe_name(name)
        folded = name.casefold()
        if folded in seen:
            fail('ARCHIVE_DUPLICATE')
        seen.add(folded)
        if len(seen) > MAX_MEMBERS or size < 0 or size > MAX_MEMBER:
            fail('ARCHIVE_LIMIT')
        if not regular and not directory:
            fail('ARCHIVE_TYPE_REFUSED')
        total += size
        if total > MAX_EXPANDED:
            fail('ARCHIVE_LIMIT')
        selected = (notice_path(name) or name.endswith('.dist-info/METADATA')
                    or (name.endswith('/package.json') and name.count('/') == 1))
        if regular and selected:
            limit = MAX_TEXT if notice_path(name) else 512 * 1024
            if size > limit:
                fail('NOTICE_LIMIT')
            data = reader(limit + 1)
            if len(data) != size:
                fail('ARCHIVE_SIZE_MISMATCH')
            notice_total += len(data)
            if notice_total > MAX_NOTICES:
                fail('NOTICE_LIMIT')
            chosen[name] = data

    try:
        if kind == 'wheel':
            # Bound actual central records before ZipFile builds ZipInfo objects.
            # This small-artifact workflow deliberately refuses ZIP64/multidisk.
            check_zip_directory(raw)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for member in archive.infolist():
                    mode = member.external_attr >> 16
                    regular = not member.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    directory = member.is_dir() and stat.S_IFMT(mode) in (0, stat.S_IFDIR)
                    if member.flag_bits & 1 or member.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                        fail('ARCHIVE_TYPE_REFUSED')
                    def read(limit, item=member):
                        with archive.open(item) as source:
                            return source.read(limit)
                    accept(member.filename, member.file_size, regular, directory, read)
        elif kind == 'npm':
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source:
                expanded = source.read(MAX_EXPANDED + 1)
            if len(expanded) > MAX_EXPANDED:
                fail('ARCHIVE_LIMIT')
            with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as archive:
                for member in archive:
                    def read(limit, item=member):
                        source = archive.extractfile(item)
                        if source is None:
                            fail('ARCHIVE_TYPE_REFUSED')
                        with source:
                            return source.read(limit)
                    accept(member.name, member.size, member.isfile(), member.isdir(), read)
        else:
            fail('ARCHIVE_TYPE_REFUSED')
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, RuntimeError) as exc:
        if isinstance(exc, NoticeError):
            raise
        fail('ARCHIVE_REFUSED')
    return chosen


def text_value(value):
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        fail('METADATA_REFUSED')
    return value


def describe(raw, kind, name, version, artifact_path, declared=None):
    files = archive_members(raw, kind)
    if kind == 'wheel':
        metadata = [(p, b) for p, b in files.items() if p.endswith('.dist-info/METADATA')]
        if len(metadata) != 1:
            fail('METADATA_REFUSED')
        meta = BytesParser(policy=email.policy.default).parsebytes(metadata[0][1])
        if (len(meta.get_all('Name', [])) != 1 or len(meta.get_all('Version', [])) != 1
                or replay.canonical(str(meta['Name'])) != replay.canonical(name) or str(meta['Version']) != version):
            fail('METADATA_IDENTITY_MISMATCH')
        declarations = [str(v) for key in ('License-Expression', 'License') for v in meta.get_all(key, [])]
        declarations += [str(v) for v in meta.get_all('Classifier', []) if str(v).startswith('License ::')]
        license_files = [str(v) for v in meta.get_all('License-File', [])]
    else:
        metadata = [(p, b) for p, b in files.items() if p.endswith('/package.json') and p.count('/') == 1]
        if len(metadata) != 1:
            fail('METADATA_REFUSED')
        meta = load_json(metadata[0][1])
        if not isinstance(meta, dict) or meta.get('name') != name or meta.get('version') != version:
            fail('METADATA_IDENTITY_MISMATCH')
        declaration = meta.get('license')
        declarations = [declaration] if isinstance(declaration, str) else []
        license_files = []
    declarations = sorted(set(text_value(v) for v in declarations))
    notices, gaps = [], []
    for path, data in sorted(files.items()):
        if not notice_path(path):
            continue
        record = {'path': path, 'sha256': sha(data), 'bytes': len(data)}
        try:
            text = data.decode('utf-8')
            if '\x00' in text:
                raise UnicodeError()
            record.update(encoding='UTF-8', text=text)
        except UnicodeError:
            record.update(encoding='UNSUPPORTED', text=None)
            gaps.append('NOTICE_ENCODING_UNSUPPORTED')
        notices.append(record)
    if not declarations:
        gaps.append('DECLARED_LICENSE_UNKNOWN')
    if not notices:
        gaps.append('NOTICE_TEXT_NOT_FOUND')
    for value in license_files:
        path = safe_name(value)
        if not any(p == path or p.endswith('/licenses/' + path) or p.endswith('.dist-info/' + path) for p in files):
            gaps.append('DECLARED_LICENSE_FILE_NOT_CAPTURED')
    return {'ecosystem': 'python' if kind == 'wheel' else 'web', 'name': name, 'version': version,
            'artifact_path': artifact_path, 'artifact_sha256': sha(raw), 'artifact_bytes': len(raw),
            'metadata_path': metadata[0][0], 'metadata_sha256': sha(metadata[0][1]),
            'declared_license': declarations, 'lock_declared_license': declared,
            'declared_license_files': sorted(license_files), 'notices': notices,
            'gaps': sorted(set(gaps)), 'legal_review': 'NOT_PERFORMED'}


def web_inputs(raw):
    lock = load_json(raw)
    if not isinstance(lock, dict) or lock.get('lockfileVersion') != 3 or not isinstance(lock.get('packages'), dict):
        fail('WEB_LOCK_REFUSED')
    packages = lock['packages']
    if '' not in packages or not 1 < len(packages) <= 501:
        fail('WEB_CLOSURE_REFUSED')
    rows = []
    for path, record in sorted(packages.items()):
        if path == '':
            continue
        match = re.fullmatch(r'node_modules/((?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+)', path)
        if not match or not isinstance(record, dict) or record.get('link'):
            fail('WEB_CLOSURE_REFUSED')
        name = match[1]
        version = text_value(record.get('version'))
        integrity = record.get('integrity')
        if not isinstance(integrity, str) or not re.fullmatch(r'sha512-[A-Za-z0-9+/]{86}==', integrity):
            fail('WEB_INTEGRITY_REFUSED')
        digest = base64.b64decode(integrity[7:], validate=True)
        if len(digest) != 64 or base64.b64encode(digest).decode() != integrity[7:]:
            fail('WEB_INTEGRITY_REFUSED')
        resolved = record.get('resolved')
        if not isinstance(resolved, str) or not resolved.startswith('https://registry.npmjs.org/'):
            fail('WEB_REGISTRY_REFUSED')
        declared = record.get('license')
        if declared is not None:
            declared = text_value(declared)
        rows.append((name, version, digest, integrity, declared))
    return rows


def build_inventory():
    rows = replay.manifest()
    replay.verify_inputs(rows)  # Pinned provenance + canonical full hash lock + exact original wheel closure.
    inventory = []
    for row in sorted(rows, key=lambda r: r['name'].lower()):
        path = replay.AREA / 'wheelhouse' / row['filename']
        raw = replay.read_fixed(path, MAX_ARCHIVE, row['sha256'])
        if len(raw) != row['bytes']:
            fail('ARCHIVE_SIZE_MISMATCH')
        entry = describe(raw, 'wheel', row['name'], row['version'], path.relative_to(ROOT).as_posix())
        entry['role'] = row['role']
        inventory.append(entry)
    lock = replay.read_fixed(WEB_LOCK, 2 * 1024 * 1024, WEB_LOCK_SHA256)
    package = replay.read_fixed(WEB_PACKAGE, 65536, WEB_PACKAGE_SHA256)
    metadata, root_entry = load_json(package), load_json(lock)['packages']['']
    if any(metadata.get(k) != root_entry.get(k) for k in ('name', 'version', 'dependencies', 'devDependencies')):
        fail('WEB_CLOSURE_REFUSED')
    for name, version, digest, integrity, declared in web_inputs(lock):
        h = digest.hex()
        path = CACHE / h[:2] / h[2:4] / h[4:]
        raw = replay.read_fixed(path, MAX_ARCHIVE)
        if hashlib.sha512(raw).digest() != digest:
            fail('WEB_INTEGRITY_MISMATCH')
        entry = describe(raw, 'npm', name, version, path.relative_to(ROOT).as_posix(), declared)
        entry['integrity'] = integrity
        inventory.append(entry)
    # Recheck fixed inputs after archive processing. No installed files are used.
    if (replay.read_fixed(WEB_LOCK, 2 * 1024 * 1024, WEB_LOCK_SHA256) != lock
            or replay.read_fixed(WEB_PACKAGE, 65536, WEB_PACKAGE_SHA256) != package):
        fail('INPUT_CHANGED')
    replay.verify_inputs(replay.manifest())
    return {'schema': 1, 'status': 'NOTICE_PREPARATION_INCOMPLETE',
            'inputs': {'python_provenance_sha256': replay.PROVENANCE_SHA256,
                       'python_lock_sha256': sha(replay.read_fixed(replay.LOCK, 16384)), 'web_lock_sha256': sha(lock),
                       'web_package_sha256': sha(package)},
            'packages': inventory, 'legal_review': 'NOT_PERFORMED', 'license_complete': False,
            'gaps': ['ANDROID_ARTIFACTS_NOT_INVENTORIED', 'NATIVE_TOOLS_AND_RUNTIME_NOT_INVENTORIED',
                     'OTHER_PLATFORM_OPTIONAL_PACKAGES_NOT_INVENTORIED',
                     'OPAQUE_BINARY_NOTICE_COVERAGE_NOT_PROVEN', 'SOURCE_OFFER_OBLIGATIONS_NOT_REVIEWED',
                     'BUNDLED_COMPONENT_CLOSURE_NOT_PROVEN', 'LICENSE_OBLIGATIONS_REQUIRE_HUMAN_REVIEW'],
            'scope': 'ORIGINAL_PYTHON_WHEELS_AND_WEB_LOCK_CACHE_ONLY'}


def render_notices(inventory):
    def fenced(text):
        runs = re.findall(r'`+', text)
        fence = '`' * max(3, max((len(r) + 1 for r in runs), default=3))
        return fence + 'text\n' + text + ('' if text.endswith('\n') else '\n') + fence + '\n\n'
    parts = ['# Dependency notice preparation\n\n',
             'Preserved package text for review. License completeness, legal clearance, native/Android coverage and clean-machine acceptance are not established.\n\n']
    for row in inventory['packages']:
        parts.append('## ' + json.dumps([row['ecosystem'], row['name'], row['version']]) + '\n\n')
        parts.append('Artifact SHA256: ' + row['artifact_sha256'] + '\n\n')
        parts.append('Artifact path:\n\n' + fenced(json.dumps(row['artifact_path'])))
        parts.append('Declared metadata (not legal review):\n\n' + fenced(json.dumps(row['declared_license'])))
        if row['gaps']:
            parts.append('Gaps: ' + ', '.join(row['gaps']) + '\n\n')
        for notice in row['notices']:
            parts.append('Member path:\n\n' + fenced(json.dumps(notice['path'])) + 'SHA256: ' + notice['sha256'] + '\n\n')
            if notice['text'] is None:
                parts.append('Unsupported text encoding; original bytes remain in the verified archive.\n\n')
                continue
            text = notice['text']
            parts.append(fenced(text))
    raw = ''.join(parts).encode('utf-8')
    if len(raw) > MAX_OUTPUT:
        fail('OUTPUT_LIMIT')
    return raw


def write_outputs(inventory):
    data, text = json_bytes(inventory), render_notices(inventory)
    if len(data) > MAX_OUTPUT:
        fail('OUTPUT_LIMIT')
    # Fixed destinations only. Existing links/hardlinks/nonregular files are refused
    # before either output is opened; no paths from package contents reach writes.
    for path in (OUTPUT_JSON, OUTPUT_TEXT):
        replay.checked(path)
        if path.exists():
            replay.read_fixed(path, MAX_OUTPUT)
        if not path.parent.is_dir():
            fail('OUTPUT_PARENT_REFUSED')
    for path, raw in ((OUTPUT_JSON, data), (OUTPUT_TEXT, text)):
        replay.checked(path)
        before = path.stat() if path.exists() else None
        flags = os.O_WRONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0)
        flags |= os.O_CREAT | os.O_EXCL if before is None else 0
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, 'wb') as target:
            opened = os.fstat(target.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                    or (before is not None and (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino))
                    or (replay.checked(path).stat().st_dev, path.stat().st_ino) != (opened.st_dev, opened.st_ino)):
                fail('OUTPUT_CHANGED')
            target.truncate(0)
            target.write(raw)
        if replay.read_fixed(path, MAX_OUTPUT) != raw:
            fail('OUTPUT_CHANGED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='write only the two fixed preparation reports')
    args = parser.parse_args(argv)
    try:
        inventory = build_inventory()
        if args.write:
            write_outputs(inventory)
        print(json.dumps({'status': 'WRITTEN_INCOMPLETE' if args.write else 'PREPARED_NOT_WRITTEN',
                          'packages': len(inventory['packages']), 'license_complete': False}, sort_keys=True))
        return 0 if args.write else 2
    except (NoticeError, replay.ReplayError) as exc:
        print(json.dumps({'status': 'UNAVAILABLE', 'code': str(exc)}, sort_keys=True))
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError):
        print('{"status":"UNAVAILABLE","code":"INPUT_REFUSED"}')
        return 2


if __name__ == '__main__':
    sys.exit(main())
