"""Bounded pure ELF/dependency inventory. No loading, execution or filesystem IO.

Computed byte identities and regular-copy plans are not ABI compatibility,
artifact provenance, complete-image audit or native runtime eligibility.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import PurePosixPath
import re
import struct

MAX_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_ARTIFACTS = 256
CLAMAV = '/opt/clamav/lib'
CLOSURE = '/opt/closure/lib'
WHEEL = '/usr/local/lib/python3.14/site-packages'
WHEEL_DIRS = (WHEEL + '/PIL', WHEEL + '/pillow.libs')
BASE_DIRS = ('/lib/x86_64-linux-gnu', '/usr/lib/x86_64-linux-gnu', '/usr/local/lib', '/lib64')
_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9._+-]{0,254}\Z')
_PATH = re.compile(r'/[A-Za-z0-9._+/-]{1,511}\Z')
_GLIBC_FAMILIES = r'(?:c|m|mvec|pthread|dl|rt|resolv|util|anl|BrokenLocale|thread_db|memusage|pcprofile|SegFault|c_malloc_debug|nsl|nss_[A-Za-z0-9_]+)'
_PROTECTED = re.compile(r'(?:ld(?:-linux[A-Za-z0-9_-]*|-[0-9][A-Za-z0-9._+-]*)?\.so(?:\.[0-9]+)*|'
    r'lib' + _GLIBC_FAMILIES + r'(?:-[0-9][A-Za-z0-9._+-]*)?\.so(?:\.[0-9]+)*)\Z')
_TAGS = frozenset(range(0, 31)) | frozenset(range(32, 38)) | frozenset({0x6ffffef5, 0x6ffffff0, 0x6ffffff9, 0x6ffffffa,
    0x6ffffffb, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff})


class ElfUnavailable(RuntimeError):
    def __init__(self):
        self.code = 'ELF_CLOSURE_UNAVAILABLE'
        super().__init__(self.code)


def require(value):
    if value is not True: raise ElfUnavailable()


def _span(offset, size, length):
    require(type(offset) is int and type(size) is int and 0 <= offset <= length and 0 <= size <= length - offset)


def _basename(value):
    require(type(value) is str and _NAME.fullmatch(value) is not None and value not in ('.', '..'))
    return value


@dataclass(frozen=True)
class ElfInfo:
    sha256: str
    size: int
    needed: tuple[str, ...]
    soname: str | None
    rpath: tuple[str, ...]
    runpath: tuple[str, ...]


def parse_elf(raw):
    """ELF64 little-endian AMD64 ET_DYN only; unknown loader tags refuse."""
    try:
        require(type(raw) is bytes and 64 <= len(raw) <= MAX_BYTES)
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', raw)
        ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
        require(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3) and ident[8:] == b'\x00' * 8
                and kind == 3 and machine == 62 and version == 1 and flags == 0 and ehsize == 64
                and phsize == 56 and 1 <= phnum <= 128 and phoff >= 64)
        _span(phoff, phsize * phnum, len(raw))
        if shnum:
            require(shsize == 64 and shoff >= 64 and shstr < shnum)
            _span(shoff, shsize * shnum, len(raw))
        else:
            require(shoff == 0 and shstr == 0 and shsize in (0, 64))  # No extended section numbering.
        loads, dynamic = [], []
        for index in range(phnum):
            ptype, pflags, offset, address, _, size, memory, align = struct.unpack_from('<IIQQQQQQ', raw, phoff + 56 * index)
            _span(offset, size, len(raw))
            require(pflags & ~7 == 0 and address + memory < 1 << 64
                    and (align in (0, 1) or (align <= 1 << 32 and align & (align - 1) == 0)))
            if ptype == 1:
                require(size <= memory and pflags & 4 != 0 and pflags & 3 != 3
                        and (align in (0, 1) or offset % align == address % align))
                loads.append((offset, address, size, memory, pflags))
            if ptype == 2: dynamic.append((offset, address, size))
        require(1 <= len(loads) <= 32 and len(dynamic) == 1)
        require([item[1] for item in loads] == sorted(item[1] for item in loads))
        # Any ambiguous virtual mapping is refused rather than guessed.
        for index, first in enumerate(loads):
            for other in loads[index + 1:]:
                require(not (first[3] and other[3] and max(first[1], other[1]) < min(first[1]+first[3], other[1]+other[3])))
                require(not (first[2] and other[2] and max(first[0], other[0]) < min(first[0]+first[2], other[0]+other[2])))
        def mapping(address, size):
            choices = [offset + address - start for offset, start, filesz, _, _ in loads
                       if start <= address and size <= filesz and address - start <= filesz - size]
            require(len(choices) == 1)
            _span(choices[0], size, len(raw))
            return choices[0]
        if entry: require(any(start <= entry < start + size and bits & 1 for _, start, size, _, bits in loads))
        offset, address, size = dynamic[0]
        require(16 <= size <= 65536 and size % 16 == 0 and mapping(address, size) == offset)
        values, names, ended = {}, [], False
        for position in range(offset, offset + size, 16):
            tag, value = struct.unpack_from('<qQ', raw, position)
            if ended:
                require(tag == value == 0)
                continue
            require(tag in _TAGS)
            if tag == 0:
                require(value == 0); ended = True
            elif tag == 1:
                names.append(value); require(len(names) <= 128)
            else:
                require(tag not in values); values[tag] = value
        require(ended and 5 in values and 10 in values and 1 <= values[10] <= 1048576)
        table = mapping(values[5], values[10]); table_end = table + values[10]
        require(raw[table] == 0 and raw[table_end - 1] == 0)
        def string(index):
            require(index < values[10])
            start = table + index
            stop = raw.find(b'\x00', start, min(table_end, start + 4097))
            require(stop > start)
            result = raw[start:stop].decode('ascii', errors='strict')
            require(all(32 <= ord(char) <= 126 for char in result))
            return result
        needed = tuple(_basename(string(index)) for index in names)
        require(len(set(needed)) == len(needed))
        soname = _basename(string(values[14])) if 14 in values else None
        def paths(tag):
            if tag not in values: return ()
            result = tuple(string(values[tag]).split(':'))
            require(1 <= len(result) <= 8 and all(result) and len(set(result)) == len(result))
            return result
        return ElfInfo(hashlib.sha256(raw).hexdigest(), len(raw), needed, soname, paths(15), paths(29))
    except Exception:
        raise ElfUnavailable() from None


@dataclass(frozen=True)
class Artifact:
    """Explicit source inventory bytes. Parent must prove real-file provenance."""
    path: str
    data: bytes


@dataclass(frozen=True)
class InventoryEntry:
    path: str
    origin: str
    sha256: str
    size: int
    soname: str | None


@dataclass(frozen=True)
class CopyFile:
    """Exact regular-file bytes, never an archive entry/link or a filesystem write."""
    destination: str
    sha256: str
    data: bytes


@dataclass(frozen=True)
class Closure:
    inventory: tuple[InventoryEntry, ...]
    edges: tuple[tuple[str, str, str], ...]
    copies: tuple[CopyFile, ...]
    cycles: tuple[tuple[str, ...], ...] = ()


def _path(value):
    require(type(value) is str and _PATH.fullmatch(value) is not None)
    path = PurePosixPath(value)
    require(str(path) == value and '..' not in path.parts and '.' not in path.parts)
    _basename(path.name)
    return path


def resolve_closure(*, roots, base, candidates):
    """Resolve explicit bytes; checked backedges are metadata, not ABI approval.

    Base glibc/loader libraries can never be copied or overridden. Added builder
    dependencies become regular SONAME copies only under /opt/closure/lib.
    """
    try:
        require(type(roots) is tuple and type(base) is tuple and type(candidates) is tuple
                and 1 <= len(roots) <= 64 and len(roots) + len(base) + len(candidates) <= MAX_ARTIFACTS)
        records, providers, total = {}, {}, 0
        for origin, artifacts in (('root', roots), ('base', base), ('builder', candidates)):
            for artifact in artifacts:
                require(type(artifact) is Artifact)
                path = _path(artifact.path)
                require(artifact.path not in records and type(artifact.data) is bytes)
                total += len(artifact.data); require(total <= MAX_TOTAL_BYTES)
                parent = str(path.parent)
                if origin == 'root': require(parent in (CLAMAV, *WHEEL_DIRS))
                elif origin == 'base': require(parent in BASE_DIRS)
                else: require(str(path).startswith('/builder/') and len(path.parts) >= 3)
                info = parse_elf(artifact.data)
                if origin == 'builder': require(info.soname is not None)
                names = {path.name} | ({info.soname} if info.soname else set())
                if origin != 'base': require(not any(_PROTECTED.fullmatch(name) for name in names))
                target = CLOSURE + '/' + info.soname if origin == 'builder' else artifact.path
                records[artifact.path] = (artifact, info, origin, target)
                for name in names: providers.setdefault(name, []).append(artifact.path)
        # Duplicate providers are refused even when bytes coincide. The parent
        # must export a canonical real-file inventory, not symlink aliases.
        require(all(len(paths) == 1 for paths in providers.values()))
        for _, info, origin, target in records.values():
            require(not (info.rpath and info.runpath))
            for search in info.rpath or info.runpath:
                if search in (CLAMAV, CLOSURE): continue
                parent = str(PurePosixPath(target).parent)
                if parent in WHEEL_DIRS and search in ('$ORIGIN', '$ORIGIN/../pillow.libs'): continue
                if origin == 'base' and search in BASE_DIRS: continue
                raise ElfUnavailable()
        active, visited, edges, stack, cycles = set(), set(), [], [], set()
        def visit(path, depth):
            require(depth <= 32)
            if path in active:
                # The caller has already validated and recorded this edge.
                # Only stop re-expansion; every other dependency still runs.
                ring = tuple(stack[stack.index(path):])
                rotation = min(ring[index:] + ring[:index] for index in range(len(ring)))
                cycles.add(rotation + (rotation[0],))
                return
            if path in visited: return
            require(len(visited) + len(active) < 128)
            active.add(path); stack.append(path)
            artifact, info, origin, target = records[path]
            search_dirs = {CLAMAV, CLOSURE, *BASE_DIRS}
            for search in info.rpath or info.runpath:
                parent = str(PurePosixPath(target).parent)
                search_dirs.add(parent if search == '$ORIGIN' else WHEEL_DIRS[1] if search == '$ORIGIN/../pillow.libs' else search)
            for name in info.needed:
                choices = providers.get(name, [])
                require(len(choices) == 1)
                provider = choices[0]
                _, dependency, provider_origin, provider_target = records[provider]
                require(str(PurePosixPath(provider_target).parent) in search_dirs)
                if _PROTECTED.fullmatch(name): require(provider_origin == 'base')
                if provider_origin != 'base': require(dependency.soname == name)
                edges.append((path, name, provider)); require(len(edges) <= 1024)
                visit(provider, depth + 1)
            stack.pop(); active.remove(path); visited.add(path)
        for artifact in roots: visit(artifact.path, 1)
        copies = {}
        for path in sorted(visited):
            artifact, info, origin, target = records[path]
            if origin == 'base': continue
            destinations = {target}
            if origin == 'root' and str(PurePosixPath(target).parent) == CLAMAV and info.soname:
                destinations.add(CLAMAV + '/' + info.soname)
            for destination in destinations:
                require(destination not in copies)
                copies[destination] = CopyFile(destination, info.sha256, artifact.data)
        inventory = tuple(InventoryEntry(path, origin, info.sha256, info.size, info.soname)
            for path, (_, info, origin, _) in sorted(records.items()))
        return Closure(inventory, tuple(sorted(edges)), tuple(copies[path] for path in sorted(copies)), tuple(sorted(cycles)))
    except Exception:
        raise ElfUnavailable() from None
