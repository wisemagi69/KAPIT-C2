"""Source-fixed PUBLIC image fixtures only; no input/path or native dependency."""
from dataclasses import dataclass
import struct
import zlib

IDS = frozenset({'png_clean', 'png_metadata', 'jpeg_clean', 'jpeg_metadata', 'png_malformed', 'png_eicar'})
_MARKER = b'PUBLIC-METADATA-CANARY'


def _chunk(kind, payload):
    return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload) & 0xffffffff)


def _png(text=None):
    return (b'\x89PNG\r\n\x1a\n' + _chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
            + (_chunk(b'tEXt', b'Comment\x00' + text) if text is not None else b'')
            + _chunk(b'IDAT', zlib.compress(b'\x00\x01\x02\x03')) + _chunk(b'IEND', b''))


def _segment(number, data):
    return b'\xff' + bytes([number]) + struct.pack('>H', len(data) + 2) + data


def _jpeg(metadata=False):
    # Complete one-component baseline JPEG: unit quantization, DC category0 and
    # AC EOB single-code tables, one zero-coefficient MCU. Root native tests must
    # independently establish decoder/scanner behavior; framing alone cannot.
    table = b'\x01' + b'\x00' * 15 + b'\x00'
    return (b'\xff\xd8' + (_segment(0xfe, _MARKER) if metadata else b'')
            + _segment(0xdb, b'\x00' + b'\x01' * 64)
            + _segment(0xc0, struct.pack('>BHHB', 8, 1, 1, 1) + b'\x01\x11\x00')
            + _segment(0xc4, b'\x00' + table + b'\x10' + table)
            + _segment(0xda, b'\x01\x01\x00\x00\x3f\x00') + b'\x3f\xff\xd9')


@dataclass(frozen=True)
class PublicFixture:
    media_type: str
    data: bytes
    expected_original_code: str
    metadata: bool


def fixture(fixture_id):
    if type(fixture_id) is not str or fixture_id not in IDS:
        raise ValueError('PUBLIC_FIXTURE_UNAVAILABLE')
    if fixture_id == 'png_malformed':
        data = bytearray(_png()); data[-1] ^= 1
        return PublicFixture('image/png', bytes(data), 'SCANNER_UNAVAILABLE', False)
    if fixture_id == 'png_eicar':
        # Public standard antivirus test string, never actual malicious code.
        data = _png(b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        return PublicFixture('image/png', data, 'SCAN_NOT_CLEAN', False)
    if fixture_id.startswith('jpeg_'):
        metadata = fixture_id == 'jpeg_metadata'
        return PublicFixture('image/jpeg', _jpeg(metadata), 'SCAN_CLEAN', metadata)
    metadata = fixture_id == 'png_metadata'
    return PublicFixture('image/png', _png(_MARKER if metadata else None), 'SCAN_CLEAN', metadata)


def derivative_metadata_absent(data):
    """Called only after independent strict normalized PNG validation."""
    return type(data) is bytes and _MARKER not in data
