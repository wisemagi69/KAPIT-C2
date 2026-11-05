"""Closed length-prefixed decoder IPC only; never a validation/scanner verdict."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import struct

from .evidence_policy import CODES, DEFAULT_POLICY, EvidenceError, checked_policy, dimensions

HEADER_LIMIT = 4096
HASH = re.compile(r"[0-9a-f]{64}\Z")
REQUEST = "private-evidence-decode-v1"
RESULT = "private-evidence-decode-result-v1"


def _error():
    raise EvidenceError("DECODE_UNAVAILABLE")


def _pairs(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            _error()
        document[key] = value
    return document


def _read_exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.read(size - len(output))
        if type(part) is not bytes or not part or len(part) > size - len(output):
            _error()
        output.extend(part)
    return bytes(output)


def _header(stream):
    size = struct.unpack(">I", _read_exact(stream, 4))[0]
    if not 1 <= size <= HEADER_LIMIT:
        _error()
    try:
        value = json.loads(_read_exact(stream, size).decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: _error())
    except (ValueError, UnicodeError, RecursionError):
        _error()
    if type(value) is not dict:
        _error()
    return value


def _base(header, purpose, keys):
    if set(header) != keys or type(header.get("schema")) is not int or header["schema"] != 1 or header.get("purpose") != purpose:
        _error()


def _payload(stream, header, limit):
    size, checksum = header.get("size"), header.get("sha256")
    if type(size) is not int or not 0 <= size <= limit or type(checksum) is not str or not HASH.fullmatch(checksum):
        _error()
    data = _read_exact(stream, size)
    # Parent closes the dedicated pipe after exactly one frame. EOF read must have
    # the external runner's wall deadline; pure protocol never creates a thread.
    if stream.read(1) != b"" or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), checksum):
        _error()
    return data


def read_request(stream, *, policy=DEFAULT_POLICY):
    policy = checked_policy(policy)
    header = _header(stream)
    _base(header, REQUEST, {"schema", "purpose", "media_type", "size", "sha256"})
    if header["media_type"] not in ("image/png", "image/jpeg") or type(header["media_type"]) is not str or type(header["size"]) is not int or header["size"] < 1:
        _error()
    return header["media_type"], _payload(stream, header, policy.max_bytes)


def read_result(stream, *, policy=DEFAULT_POLICY):
    policy = checked_policy(policy)
    header = _header(stream)
    _base(header, RESULT, {"schema", "purpose", "code", "media_type", "width", "height", "frames", "size", "sha256"})
    if type(header["code"]) is not str or header["code"] not in CODES:
        _error()
    data = _payload(stream, header, policy.max_output_bytes)
    if header["code"] == "DECODE_COMPLETE":
        if header["media_type"] != "image/png" or type(header["frames"]) is not int or header["frames"] != 1 or not data:
            _error()
        dimensions(header["width"], header["height"], policy)
        from .evidence_policy import inspect_container
        info = inspect_container(data, "image/png", policy=policy, normalized=True)
        if (info.width, info.height) != (header["width"], header["height"]):
            _error()
    elif data or any(header[key] is not None for key in ("media_type", "width", "height", "frames")):
        _error()
    return header, data


def _write_all(stream, data):
    offset = 0
    while offset < len(data):
        written = stream.write(data[offset:])
        if type(written) is not int or not 1 <= written <= len(data) - offset:
            _error()
        offset += written


def _write(stream, header, data):
    raw = json.dumps(header, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("ascii")
    if len(raw) > HEADER_LIMIT:
        _error()
    _write_all(stream, struct.pack(">I", len(raw)) + raw)
    _write_all(stream, data)
    stream.flush()


def write_request(stream, data, media_type, *, policy=DEFAULT_POLICY):
    policy = checked_policy(policy)
    if type(data) is not bytes or not 1 <= len(data) <= policy.max_bytes or media_type not in ("image/png", "image/jpeg") or type(media_type) is not str:
        _error()
    _write(stream, {"schema": 1, "purpose": REQUEST, "media_type": media_type, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()}, data)


def write_result(stream, *, code, data=b"", width=None, height=None, policy=DEFAULT_POLICY):
    policy = checked_policy(policy)
    if type(code) is not str or code not in CODES or type(data) is not bytes or len(data) > policy.max_output_bytes:
        _error()
    success = code == "DECODE_COMPLETE"
    if success:
        from .evidence_policy import inspect_container
        info = inspect_container(data, "image/png", policy=policy, normalized=True)
        dimensions(width, height, policy)
        if (width, height) != (info.width, info.height):
            _error()
    elif data or width is not None or height is not None:
        _error()
    _write(stream, {"schema": 1, "purpose": RESULT, "code": code, "media_type": "image/png" if success else None,
                    "width": width, "height": height, "frames": 1 if success else None,
                    "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}, data)
