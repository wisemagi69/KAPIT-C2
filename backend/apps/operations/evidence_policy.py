"""Pure bounds/container checks. No ORM, native decoder, I/O or safe-release verdict."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import struct
from types import MappingProxyType
import zlib

MAX_BYTES = 5 * 1024 * 1024
CODES = frozenset({
    "DECODE_COMPLETE", "INVALID_IMAGE", "TYPE_MISMATCH", "PIXEL_LIMIT",
    "MULTIFRAME_UNSUPPORTED", "METADATA_INVALID", "DEPENDENCY_UNAVAILABLE",
    "PROVENANCE_UNAVAILABLE", "ISOLATION_UNAVAILABLE", "SCANNER_UNAVAILABLE",
    "SIGNATURES_STALE", "SCAN_NOT_CLEAN", "RESOURCE_LIMIT", "DECODE_UNAVAILABLE",
    "DERIVATIVE_LIMIT", "VALIDATION_STALE", "SCRATCH_CLEANUP_REQUIRED",
})
REJECT_CODES = frozenset({"INVALID_IMAGE", "TYPE_MISMATCH", "PIXEL_LIMIT",
                         "MULTIFRAME_UNSUPPORTED", "METADATA_INVALID"})


class EvidenceError(ValueError):
    """Only a known fixed code can cross a helper boundary."""
    def __init__(self, code="DECODE_UNAVAILABLE"):
        self.code = code if type(code) is str and code in CODES - {"DECODE_COMPLETE"} else "DECODE_UNAVAILABLE"
        super().__init__(self.code)


@dataclass(frozen=True)
class EvidencePolicy:
    max_bytes: int = MAX_BYTES
    max_output_bytes: int = MAX_BYTES
    max_width: int = 6000
    max_height: int = 6000
    max_pixels: int = 24000000
    metadata_bytes: int = 65536

    def __post_init__(self):
        ceilings = (MAX_BYTES, MAX_BYTES, 6000, 6000, 24000000, 65536)
        for value, ceiling in zip(self.__dict__.values(), ceilings):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise EvidenceError("PROVENANCE_UNAVAILABLE")


DEFAULT_POLICY = EvidencePolicy()


@dataclass(frozen=True)
class ContainerInfo:
    media_type: str
    width: int
    height: int
    metadata_bytes: int


def checked_policy(policy):
    if type(policy) is not EvidencePolicy:
        raise EvidenceError("PROVENANCE_UNAVAILABLE")
    policy.__post_init__()
    return policy


def dimensions(width, height, policy):
    if (type(width) is not int or type(height) is not int or width < 1 or height < 1
            or width > policy.max_width or height > policy.max_height
            or width * height > policy.max_pixels):
        raise EvidenceError("PIXEL_LIMIT")


def _exif(data):
    """Bounded TIFF/IFD framing only; never interpret vendor blobs or display tags."""
    if len(data) < 8 or data[:4] not in (b"II\x2a\x00", b"MM\x00\x2a"):
        raise EvidenceError("METADATA_INVALID")
    endian = "little" if data[:2] == b"II" else "big"
    def number(offset, size):
        if offset < 0 or offset + size > len(data):
            raise EvidenceError("METADATA_INVALID")
        return int.from_bytes(data[offset:offset + size], endian)
    first = number(4, 4)
    if first < 8:
        raise EvidenceError("METADATA_INVALID")
    pending, seen, entries = [first], set(), 0
    sizes = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4}
    while pending:
        offset = pending.pop()
        if offset == 0:
            continue
        if offset < 8 or offset % 2 or offset in seen or len(seen) >= 32:
            raise EvidenceError("METADATA_INVALID")
        seen.add(offset)
        count = number(offset, 2)
        entries += count
        if entries > 512 or offset + 2 + 12 * count + 4 > len(data):
            raise EvidenceError("METADATA_INVALID")
        tags = set()
        for index in range(count):
            entry = offset + 2 + 12 * index
            tag, kind, length = number(entry, 2), number(entry + 2, 2), number(entry + 4, 4)
            if tag in tags:
                raise EvidenceError("METADATA_INVALID")
            tags.add(tag)
            if kind not in sizes or length > 65536:
                raise EvidenceError("METADATA_INVALID")
            extent = sizes[kind] * length
            value_offset = entry + 8 if extent <= 4 else number(entry + 8, 4)
            if extent and (value_offset < 0 or value_offset + extent > len(data)):
                raise EvidenceError("METADATA_INVALID")
            if tag == 274 and (kind != 3 or length != 1 or not 1 <= number(value_offset, 2) <= 8):
                raise EvidenceError("METADATA_INVALID")
            if tag in (0x8769, 0x8825, 0xa005, 0x014a):
                if kind not in (4, 13) or not 1 <= length <= 32:
                    raise EvidenceError("METADATA_INVALID")
                pending.extend(number(value_offset + item * 4, 4) for item in range(length))
        pending.append(number(offset + 2 + 12 * count, 4))


def _png(data, policy, normalized):
    position, width, height, meta, palette = 8, 0, 0, 0, None
    chunks, seen, ended_idat, color = 0, set(), False, None
    while position < len(data):
        if len(data) - position < 12:
            raise EvidenceError("INVALID_IMAGE")
        length = int.from_bytes(data[position:position + 4], "big")
        kind = data[position + 4:position + 8]
        stop = position + 12 + length
        if stop > len(data) or any(not (65 <= c <= 90 or 97 <= c <= 122) for c in kind) or kind[2] & 32:
            raise EvidenceError("INVALID_IMAGE")
        body = data[position + 8:position + 8 + length]
        crc = int.from_bytes(data[position + 8 + length:stop], "big")
        if zlib.crc32(kind + body) & 0xffffffff != crc:
            raise EvidenceError("INVALID_IMAGE")
        if kind in {b"acTL", b"fcTL", b"fdAT"}:
            raise EvidenceError("MULTIFRAME_UNSUPPORTED")
        if normalized and kind not in {b"IHDR", b"IDAT", b"IEND"}:
            raise EvidenceError("METADATA_INVALID")
        if not kind[0] & 32 and kind not in {b"IHDR", b"PLTE", b"IDAT", b"IEND"}:
            raise EvidenceError("INVALID_IMAGE")
        if chunks == 0 and kind != b"IHDR":
            raise EvidenceError("INVALID_IMAGE")
        if kind == b"IHDR":
            if chunks or length != 13:
                raise EvidenceError("INVALID_IMAGE")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", body)
            dimensions(width, height, policy)
            allowed = {0: (1, 2, 4, 8), 2: (8,), 3: (1, 2, 4, 8), 4: (8,), 6: (8,)}
            if color not in allowed or depth not in allowed[color] or compression or filtering or interlace not in (0, 1):
                raise EvidenceError("INVALID_IMAGE")
            if normalized and (color not in (2, 6) or depth != 8 or interlace):
                raise EvidenceError("INVALID_IMAGE")
        elif kind == b"PLTE":
            if kind in seen or b"IDAT" in seen or color in (0, 4) or not 3 <= length <= 768 or length % 3:
                raise EvidenceError("INVALID_IMAGE")
            palette = length // 3
        elif kind == b"IDAT":
            if ended_idat or (color == 3 and palette is None):
                raise EvidenceError("INVALID_IMAGE")
        elif kind == b"IEND":
            if length or b"IDAT" not in seen or stop != len(data):
                raise EvidenceError("INVALID_IMAGE")
            return ContainerInfo("image/png", width, height, meta)
        else:
            meta += length + 12
            if meta > policy.metadata_bytes:
                raise EvidenceError("METADATA_INVALID")
            if kind == b"eXIf":
                if kind in seen or b"IDAT" in seen:
                    raise EvidenceError("METADATA_INVALID")
                _exif(body)
            if kind == b"tRNS":
                if kind in seen or b"IDAT" in seen or color in (4, 6):
                    raise EvidenceError("METADATA_INVALID")
                if ((color == 0 and length != 2) or (color == 2 and length != 6)
                        or (color == 3 and (palette is None or not 1 <= length <= palette))):
                    raise EvidenceError("METADATA_INVALID")
        if b"IDAT" in seen and kind != b"IDAT":
            ended_idat = True
        seen.add(kind)
        chunks += 1
        position = stop
    raise EvidenceError("INVALID_IMAGE")

# This parser validates a closed declaration only. Actual artifacts, issuer/key
# provenance, fence, OS isolation and signature authenticity belong to the
# trusted runtime adapter. A parsed manifest cannot enable a process.
MANIFEST_FIELDS = frozenset({
    "schema_version", "purpose", "policy_generation", "created_at", "valid_until",
    "contract_sha256", "helper_sha256", "python_version", "python_artifact_sha256",
    "pillow_version", "pillow_wheel_sha256", "decoder_tree_sha256", "codec_versions",
    "clamav_version", "clamav_archive_sha256", "scanner_tree_sha256",
    "signature_generation", "signature_files", "daily_signed_at",
    "last_successful_update_check_at", "signature_verification_receipt_sha256",
    "isolation_profile_sha256", "limits_sha256",
})
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[0-9][0-9A-Za-z.+_-]{0,63}\Z")
_CODEC_NAMES = frozenset({"jpeg", "zlib", "libtiff", "littlecms2", "webp", "openjpeg", "freetype", "avif"})
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")


def _manifest_error(code="PROVENANCE_UNAVAILABLE"):
    raise EvidenceError(code)


def _manifest_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _manifest_error()
        result[key] = value
    return result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _utc(value):
    if type(value) is not str or not _TIMESTAMP.fullmatch(value):
        _manifest_error()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _manifest_error()


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class ParsedManifest:
    manifest_hash: str
    signature_generation: str
    expires_at: datetime
    policy_generation: int
    _canonical_bytes: bytes

    @property
    def document(self):
        return _freeze(json.loads(self._canonical_bytes))

    def as_provenance(self):
        """Fresh detached declaration, not permission or verified provenance."""
        return json.loads(self._canonical_bytes)


def parse_manifest(raw, *, now):
    if (type(raw) is not bytes or not 1 <= len(raw) <= 65536 or type(now) is not datetime
            or now.tzinfo is None or now.utcoffset() != timedelta(0)):
        _manifest_error()
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_manifest_pairs,
                              parse_constant=lambda _: _manifest_error())
    except (ValueError, UnicodeError, RecursionError):
        _manifest_error()
    stack, nodes = [(document, 1)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 2048 or depth > 8:
            _manifest_error()
        if type(value) is dict:
            stack.extend((item, depth + 1) for item in value.values())
        elif type(value) is list:
            stack.extend((item, depth + 1) for item in value)
        elif type(value) not in (str, int) or type(value) is bool:
            _manifest_error()
    if (type(document) is not dict or set(document) != MANIFEST_FIELDS
            or type(document["schema_version"]) is not int or document["schema_version"] != 1
            or document["purpose"] != "private-evidence-validation-v1"
            or type(document["policy_generation"]) is not int
            or not 1 <= document["policy_generation"] <= 2147483647):
        _manifest_error()
    for key in MANIFEST_FIELDS:
        if key.endswith("_sha256") or key == "signature_generation":
            if type(document[key]) is not str or not _HEX.fullmatch(document[key]):
                _manifest_error()
    for key in ("python_version", "pillow_version", "clamav_version"):
        if type(document[key]) is not str or not _VERSION.fullmatch(document[key]):
            _manifest_error()
    if document["pillow_version"] != "13.0.0" or document["clamav_version"] != "1.4.6":
        _manifest_error()
    codecs = document["codec_versions"]
    if (type(codecs) is not dict or not {"jpeg", "zlib"} <= set(codecs)
            or not set(codecs) <= _CODEC_NAMES
            or any(type(value) is not str or not _VERSION.fullmatch(value) for value in codecs.values())):
        _manifest_error()
    files = document["signature_files"]
    if type(files) is not list or len(files) != 3:
        _manifest_error()
    names, bases, signed = [], set(), {}
    for item in files:
        if (type(item) is not dict or set(item) != {"name", "sha256", "version", "signed_at", "verification_receipt_sha256"}
                or type(item["name"]) is not str or not re.fullmatch(r"(main|daily|bytecode)\.(cvd|cld)", item["name"])
                or type(item["version"]) is not int or not 1 <= item["version"] <= 2147483647):
            _manifest_error()
        base = item["name"].split(".")[0]
        if base in bases:
            _manifest_error()
        for key in ("sha256", "verification_receipt_sha256"):
            if type(item[key]) is not str or not _HEX.fullmatch(item[key]):
                _manifest_error()
        names.append(item["name"])
        bases.add(base)
        signed[base] = _utc(item["signed_at"])
        if signed[base] > now:
            _manifest_error()
    if bases != {"main", "daily", "bytecode"} or names != sorted(names):
        _manifest_error()
    if hashlib.sha256(_canonical(files)).hexdigest() != document["signature_generation"]:
        _manifest_error()
    created = _utc(document["created_at"])
    expiry = _utc(document["valid_until"])
    checked = _utc(document["last_successful_update_check_at"])
    daily = _utc(document["daily_signed_at"])
    if (created > now or checked > created or daily > checked or daily != signed["daily"]
            or not created < expiry <= created + timedelta(days=7)):
        _manifest_error()
    if expiry <= now:
        _manifest_error("VALIDATION_STALE")
    freshness = min(checked + timedelta(days=1), daily + timedelta(days=3))
    if freshness <= now:
        _manifest_error("SIGNATURES_STALE")
    canonical = _canonical(document)
    return ParsedManifest(hashlib.sha256(canonical).hexdigest(), document["signature_generation"],
                          min(expiry, freshness), document["policy_generation"], canonical)


def _jpeg(data, policy):
    position, width, height, meta, in_scan, had_scan = 2, 0, 0, 0, False, False
    while position < len(data):
        if in_scan:
            marker_start = data.find(b"\xff", position)
            if marker_start < 0:
                raise EvidenceError("INVALID_IMAGE")
            position = marker_start
        if data[position] != 0xff:
            raise EvidenceError("INVALID_IMAGE")
        position += 1
        while position < len(data) and data[position] == 0xff:
            position += 1
        if position >= len(data):
            raise EvidenceError("INVALID_IMAGE")
        marker = data[position]
        position += 1
        if in_scan and (marker == 0 or 0xd0 <= marker <= 0xd7):
            continue
        if marker == 0xd9:
            if not had_scan or not width or position != len(data):
                raise EvidenceError("INVALID_IMAGE")
            return ContainerInfo("image/jpeg", width, height, meta)
        in_scan = False
        if marker in (0, 1, 0xd8) or 0xd0 <= marker <= 0xd7:
            raise EvidenceError("INVALID_IMAGE")
        if marker not in {0xc0, 0xc1, 0xc2, 0xc4, 0xdb, 0xdd, 0xda, 0xfe, *range(0xe0, 0xf0)}:
            raise EvidenceError("INVALID_IMAGE")
        if position + 2 > len(data):
            raise EvidenceError("INVALID_IMAGE")
        length = int.from_bytes(data[position:position + 2], "big")
        stop = position + length
        if length < 2 or stop > len(data):
            raise EvidenceError("INVALID_IMAGE")
        body = data[position + 2:stop]
        if 0xe0 <= marker <= 0xef or marker == 0xfe:
            meta += len(body) + 4
            if meta > policy.metadata_bytes:
                raise EvidenceError("METADATA_INVALID")
            if marker == 0xe2 and body.startswith(b"MPF\x00"):
                raise EvidenceError("MULTIFRAME_UNSUPPORTED")
            if marker == 0xe1 and body.startswith(b"Exif"):
                if not body.startswith(b"Exif\x00\x00"):
                    raise EvidenceError("METADATA_INVALID")
                _exif(body[6:])
        if marker in {0xc0, 0xc1, 0xc2}:
            if width or len(body) < 6:
                raise EvidenceError("INVALID_IMAGE")
            precision, height, width, components = struct.unpack(">BHHB", body[:6])
            if precision != 8 or components not in (1, 3) or len(body) != 6 + 3 * components:
                raise EvidenceError("INVALID_IMAGE")
            dimensions(width, height, policy)
        elif marker in {0xc3, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf}:
            raise EvidenceError("INVALID_IMAGE")
        if marker == 0xda:
            if not width or len(body) < 4 or body[0] not in (1, 2, 3) or len(body) != 4 + 2 * body[0]:
                raise EvidenceError("INVALID_IMAGE")
            had_scan, in_scan = True, True
        position = stop
    raise EvidenceError("INVALID_IMAGE")


def inspect_container(data, media_type, *, policy=DEFAULT_POLICY, normalized=False):
    policy = checked_policy(policy)
    if type(data) is not bytes or not 1 <= len(data) <= (policy.max_output_bytes if normalized else policy.max_bytes):
        raise EvidenceError("DERIVATIVE_LIMIT" if normalized else "INVALID_IMAGE")
    if type(media_type) is not str or media_type not in ("image/png", "image/jpeg") or type(normalized) is not bool:
        raise EvidenceError("TYPE_MISMATCH")
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if media_type != "image/png":
            raise EvidenceError("TYPE_MISMATCH")
        return _png(data, policy, normalized)
    if data.startswith(b"\xff\xd8"):
        if media_type != "image/jpeg" or normalized:
            raise EvidenceError("TYPE_MISMATCH")
        return _jpeg(data, policy)
    raise EvidenceError("INVALID_IMAGE")
