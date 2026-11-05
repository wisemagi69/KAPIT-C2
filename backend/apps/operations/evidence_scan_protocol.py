"""One-request native IPC. Framing is never a containment or trust receipt."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re

from .evidence_policy import EvidenceError, inspect_container, dimensions, DEFAULT_POLICY
from .evidence_protocol import _header, _payload, _write

HEX = re.compile(r'[0-9a-f]{64}\Z')
BINDING = {'mode', 'nonce', 'policy_sha256', 'signature_generation'}
BASE = {'schema', 'purpose'} | BINDING
READY = 'private-evidence-native-ready-v1'
REQUEST = 'private-evidence-native-request-v1'
RESULT = 'private-evidence-native-result-v1'
SCAN_CODES = frozenset({'SCAN_CLEAN', 'SCAN_NOT_CLEAN', 'SCANNER_UNAVAILABLE'})
DECODE_CODES = frozenset({'DECODE_COMPLETE', 'DECODE_UNAVAILABLE'})


def refuse():
    raise EvidenceError('SCANNER_UNAVAILABLE')


@dataclass(frozen=True)
class Binding:
    mode: str
    nonce: str
    policy_sha256: str
    signature_generation: str

    def __post_init__(self):
        if self.mode not in ('scan', 'decode') or type(self.mode) is not str:
            refuse()
        for value in (self.nonce, self.policy_sha256, self.signature_generation):
            if type(value) is not str or not HEX.fullmatch(value):
                refuse()

    def fields(self):
        return {name: getattr(self, name) for name in BINDING}


def _bound(header, expected, purpose, extra):
    if type(expected) is not Binding or set(header) != BASE | extra:
        refuse()
    if type(header['schema']) is not int or header['schema'] != 1 or header['purpose'] != purpose:
        refuse()
    for name, value in expected.fields().items():
        if type(header[name]) is not str or not header[name].isascii() or not hmac.compare_digest(header[name], value):
            refuse()


def _base(binding, purpose):
    if type(binding) is not Binding:
        refuse()
    return {'schema': 1, 'purpose': purpose, **binding.fields()}


def write_ready(stream, binding):
    _write(stream, _base(binding, READY), b'')


def read_ready(stream, binding):
    # This stream remains open for the result: deliberately do not read EOF here.
    _bound(_header(stream), binding, READY, set())


def write_request(stream, binding, data, media_type):
    if type(data) is not bytes or not 1 <= len(data) <= DEFAULT_POLICY.max_bytes:
        refuse()
    if type(media_type) is not str or media_type not in ('image/png', 'image/jpeg'):
        refuse()
    _write(stream, {**_base(binding, REQUEST), 'media_type': media_type,
                    'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}, data)


def read_request(stream, binding):
    header = _header(stream)
    _bound(header, binding, REQUEST, {'media_type', 'size', 'sha256'})
    if type(header['media_type']) is not str or header['media_type'] not in ('image/png', 'image/jpeg'):
        refuse()
    if type(header['size']) is not int or header['size'] < 1:
        refuse()
    return header['media_type'], _payload(stream, header, DEFAULT_POLICY.max_bytes)


def write_result(stream, binding, code, *, data=b'', width=None, height=None):
    if type(code) is not str or code not in (SCAN_CODES if binding.mode == 'scan' else DECODE_CODES):
        refuse()
    if type(data) is not bytes or len(data) > DEFAULT_POLICY.max_output_bytes:
        refuse()
    success = binding.mode == 'decode' and code == 'DECODE_COMPLETE'
    if success:
        dimensions(width, height, DEFAULT_POLICY)
        info = inspect_container(data, 'image/png', normalized=True)
        if (info.width, info.height) != (width, height):
            refuse()
    elif data or width is not None or height is not None:
        refuse()
    _write(stream, {**_base(binding, RESULT), 'code': code, 'size': len(data),
                    'sha256': hashlib.sha256(data).hexdigest(),
                    'media_type': 'image/png' if success else None,
                    'width': width, 'height': height, 'frames': 1 if success else None}, data)


def read_result(stream, binding):
    header = _header(stream)
    _bound(header, binding, RESULT, {'code', 'size', 'sha256', 'media_type', 'width', 'height', 'frames'})
    codes = SCAN_CODES if binding.mode == 'scan' else DECODE_CODES
    if type(header['code']) is not str or header['code'] not in codes:
        refuse()
    success = binding.mode == 'decode' and header['code'] == 'DECODE_COMPLETE'
    if not success and (type(header['size']) is not int or header['size'] != 0):
        refuse()
    data = _payload(stream, header, DEFAULT_POLICY.max_output_bytes)
    if success:
        if header['media_type'] != 'image/png' or type(header['frames']) is not int or header['frames'] != 1:
            refuse()
        dimensions(header['width'], header['height'], DEFAULT_POLICY)
        info = inspect_container(data, 'image/png', normalized=True)
        if (info.width, info.height) != (header['width'], header['height']):
            refuse()
    elif data or any(header[key] is not None for key in ('media_type', 'width', 'height', 'frames')):
        refuse()
    return header, data
