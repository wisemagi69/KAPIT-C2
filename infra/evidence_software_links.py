"""Pure single-symlink Docker USTAR metadata reader for public ELF software.

No extraction, filesystem access, Docker calls or readiness assertions. A
returned path is one lexical hop, not evidence of a regular/trusted ELF file.
"""
from __future__ import annotations

import re


SOFTWARE_DIRS = frozenset(('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu',
                          '/usr/local/lib', '/lib64', '/out/opt/clamav/lib'))
_COMPONENT = re.compile(r'[A-Za-z0-9_.+\-]{1,255}\Z', re.ASCII)


class SoftwareLinkUnavailable(ValueError):
    def __str__(self):
        return 'SOFTWARE_LINK_METADATA_UNAVAILABLE'


def _fail():
    raise SoftwareLinkUnavailable()


def _ascii(value):
    if type(value) is not str or not 1 <= len(value) <= 512 or not value.isascii():
        _fail()
    if '\\' in value or ':' in value or any(ord(char) < 33 or ord(char) > 126 for char in value):
        _fail()
    return value


def _original(value):
    _ascii(value)
    if not value.startswith('/') or value.startswith('//'):
        _fail()
    parent, sep, name = value.rpartition('/')
    if not sep or parent not in SOFTWARE_DIRS or not _COMPONENT.fullmatch(name) or name in ('.', '..'):
        _fail()
    return parent, name


def _target(parent, value):
    _ascii(value)
    absolute = value.startswith('/')
    if value.startswith('//') or value.endswith('/'):
        _fail()
    parts = [] if absolute else parent[1:].split('/')
    ordinary_seen = False
    for component in value.split('/')[1:] if absolute else value.split('/'):
        if component in ('.', '..'):
            # Only leading relative parent navigation is lexical: never cancel
            # an opaque intermediate named directory that may itself be a link.
            if absolute or ordinary_seen:
                _fail()
            if component == '..':
                if not parts:
                    _fail()
                parts.pop()
        else:
            if not _COMPONENT.fullmatch(component):
                _fail()
            ordinary_seen = True
            parts.append(component)
    target = '/' + '/'.join(parts)
    _original(target)  # Exact direct child only, no opaque intermediate tree.
    return target


def _field(value, *, required=False):
    body, separator, padding = value.partition(b'\x00')
    if (separator and any(padding)) or (required and not body):
        _fail()
    try:
        return body.decode('ascii')
    except UnicodeError:
        _fail()


def _octal(value):
    body = value.strip(b'\x00 ')
    if body and any(char not in b'01234567' for char in body):
        _fail()
    return int(body or b'0', 8)


def resolve_link_metadata(raw: bytes, original_container_path: str) -> str:
    """Validate one exact metadata record and return an allowlisted lexical hop.

    The caller must independently pin the immutable container, limit hop count,
    detect cycles, apply its shared deadline and verify/copy the final regular
    object. This API cannot authenticate a container, link target or ELF bytes.
    """
    parent, basename = _original(original_container_path)
    if type(raw) is not bytes or not 1536 <= len(raw) <= 65536 or len(raw) % 512:
        _fail()
    header = raw[:512]
    if header[156:157] != b'2' or header[257:265] != b'ustar\x0000':
        _fail()
    if any(header[345:512]) or any(raw[512:]):
        _fail()  # No prefix, hidden record, payload, extension or second archive.
    if _octal(header[148:156]) != sum(header[:148]) + 8*32 + sum(header[156:]):
        _fail()
    for start, end in ((100,108), (108,116), (116,124), (136,148), (329,337), (337,345)):
        _octal(header[start:end])
    if _octal(header[124:136]) != 0:
        _fail()
    if _field(header[:100], required=True) != basename:
        _fail()
    # Names are unused identity metadata, still reject malformed byte strings.
    _field(header[265:297]); _field(header[297:329])
    return _target(parent, _field(header[157:257], required=True))
