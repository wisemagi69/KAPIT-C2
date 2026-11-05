"""Private, pure evidence preflight. Never authorizes storage, download or release.

Limits are explicit caller configuration, not an activated retention/upload policy.
A supplied decoder is a trusted capability, not a claim that a decoder is installed.
Even decoded input remains quarantined: scanner and runtime authorization are separate.
"""
from dataclasses import dataclass
import hashlib
import hmac
import re
import struct
from typing import Callable
import zlib


@dataclass(frozen=True)
class EvidenceLimits:
    max_bytes: int
    max_width: int
    max_height: int
    max_pixels: int

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in
               (self.max_bytes, self.max_width, self.max_height, self.max_pixels)):
            raise ValueError("INVALID_LIMITS")


@dataclass(frozen=True)
class DecodedImage:
    media_type: str
    width: int
    height: int
    frames: int


@dataclass(frozen=True)
class EvidencePreflight:
    state: str
    code: str


Decoder = Callable[[bytes, str, EvidenceLimits], DecodedImage]
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                  *(f"LPT{i}" for i in range(1, 10))}


def safe_supplied_name(name):
    """Reject rather than repair untrusted filenames. Never used as a storage key."""
    return (isinstance(name, str) and len(name) <= 100
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*\.(?:png|jpg|jpeg)", name, re.ASCII | re.IGNORECASE) is not None
            and name.split(".")[0].upper() not in RESERVED_NAMES)


def _dimensions_allowed(width, height, limits):
    return (type(width) is int and type(height) is int and width > 0 and height > 0
            and width <= limits.max_width and height <= limits.max_height
            and width * height <= limits.max_pixels)


def _reject(code):
    return EvidencePreflight("REJECTED_PRIVATE", code)


def preflight(data, media_type, filename, limits, *, decoder: Decoder | None = None, expected_digest=None):
    """Bounded byte/header checks; returns fixed metadata codes only.

    Callers must bound streaming before materializing bytes. No file, image parser,
    network, credential, HTTP or storage access occurs here. The trusted decoder must
    enforce allocation/time limits while parsing; its returned dimensions alone cannot
    constrain decoder memory. Exceptions are never included in returned metadata.
    """
    if not isinstance(limits, EvidenceLimits):
        raise ValueError("INVALID_LIMITS")
    if type(data) is not bytes or not data:
        return _reject("INVALID_BYTES")
    if len(data) > limits.max_bytes:
        return _reject("BYTE_LIMIT")
    if not safe_supplied_name(filename):
        return _reject("INVALID_FILENAME")
    if media_type not in ("image/png", "image/jpeg"):
        return _reject("UNSUPPORTED_TYPE")
    suffix = filename.rsplit(".", 1)[1].lower()
    if (media_type == "image/png") != (suffix == "png"):
        return _reject("TYPE_MISMATCH")
    if expected_digest is not None:
        if not isinstance(expected_digest, str) or re.fullmatch(r"[a-f0-9]{64}", expected_digest) is None:
            return _reject("INVALID_DIGEST")
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_digest):
            return _reject("DIGEST_CONFLICT")
    if media_type == "image/png":
        if not data.startswith(PNG_SIGNATURE):
            return _reject("TYPE_MISMATCH")
        if len(data) < 33 or data[8:16] != b"\x00\x00\x00\rIHDR":
            return _reject("MALFORMED_HEADER")
        width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", data[16:29])
        depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8}, 4: {8, 16}, 6: {8, 16}}
        if (depth not in depths.get(color, set()) or compression != 0 or filtering != 0 or interlace not in (0, 1)
                or zlib.crc32(data[12:29]) != int.from_bytes(data[29:33], "big")):
            return _reject("MALFORMED_HEADER")
        if not _dimensions_allowed(width, height, limits):
            return _reject("PIXEL_LIMIT")
    elif len(data) < 4 or not data.startswith(b"\xff\xd8") or not data.endswith(b"\xff\xd9"):
        return _reject("MALFORMED_HEADER")
    if decoder is None:
        return EvidencePreflight("QUARANTINED", "DECODER_REQUIRED")
    try:
        decoded = decoder(data, media_type, limits)
        if type(decoded) is not DecodedImage:
            return _reject("INVALID_DECODE_RESULT")
        if decoded.media_type != media_type:
            return _reject("TYPE_MISMATCH")
        if type(decoded.frames) is not int or decoded.frames != 1:
            return _reject("MULTIFRAME_UNSUPPORTED")
        if not _dimensions_allowed(decoded.width, decoded.height, limits):
            return _reject("PIXEL_LIMIT")
        if media_type == "image/png" and (decoded.width != width or decoded.height != height):
            return _reject("DECODE_MISMATCH")
    except Exception:
        return EvidencePreflight("QUARANTINED", "DECODE_UNAVAILABLE")
    return EvidencePreflight("QUARANTINED", "SCANNER_POLICY_REQUIRED")
