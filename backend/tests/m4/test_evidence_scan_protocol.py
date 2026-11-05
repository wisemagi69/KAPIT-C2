"""Pure framing and binding tests; no scanner, Pillow, kernel or database."""
import hashlib
import io
import json
import struct
import unittest
import zlib

from apps.operations import evidence_scan_protocol as p
from apps.operations.evidence_policy import EvidenceError


def png():
    def chunk(kind, value):
        return struct.pack('>I', len(value))+kind+value+struct.pack('>I', zlib.crc32(kind+value)&0xffffffff)
    return (b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
            +chunk(b'IDAT', zlib.compress(b'\x00\x01\x02\x03'))+chunk(b'IEND', b''))


def binding(mode='scan'):
    return p.Binding(mode, 'a'*64, 'b'*64, 'c'*64)


def framed(header, data=b''):
    raw = json.dumps(header, separators=(',', ':')).encode()
    return struct.pack('>I', len(raw))+raw+data


def split(raw):
    size = struct.unpack('>I', raw[:4])[0]
    return json.loads(raw[4:4+size]), raw[4+size:]


class NativeProtocolTests(unittest.TestCase):
    def test_ready_then_result_share_stream_without_consuming_result(self):
        out = io.BytesIO(); p.write_ready(out, binding()); p.write_result(out, binding(), 'SCAN_CLEAN')
        stream = io.BytesIO(out.getvalue()); p.read_ready(stream, binding())
        header, data = p.read_result(stream, binding())
        self.assertEqual((header['code'], data), ('SCAN_CLEAN', b''))

    def test_request_single_frame_exact_binding_and_bytes(self):
        out = io.BytesIO(); p.write_request(out, binding(), png(), 'image/png')
        self.assertEqual(p.read_request(io.BytesIO(out.getvalue()), binding()), ('image/png', png()))
        for tail in [b'x', out.getvalue()]:
            with self.assertRaises(EvidenceError): p.read_request(io.BytesIO(out.getvalue()+tail), binding())

    def test_every_binding_component_mismatch_refuses(self):
        out = io.BytesIO(); p.write_request(out, binding(), png(), 'image/png')
        header, data = split(out.getvalue())
        for name in ['mode', 'nonce', 'policy_sha256', 'signature_generation']:
            altered = dict(header); altered[name] = 'decode' if name == 'mode' else 'd'*64
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                p.read_request(io.BytesIO(framed(altered, data)), binding())
        header['nonce'] = '\u2603'*64
        with self.assertRaises(EvidenceError): p.read_request(io.BytesIO(framed(header, data)), binding())

    def test_header_unknown_duplicate_nonfinite_and_excessive_size_refuse(self):
        for raw in [b'{"schema":1,"schema":1}', b'{"schema":NaN}', b'\xff', b'{} '*1400]:
            with self.assertRaises(EvidenceError):
                p.read_ready(io.BytesIO(struct.pack('>I', len(raw))+raw), binding())
        out = io.BytesIO(); p.write_ready(out, binding())
        header, _ = split(out.getvalue()); header['caller_pass'] = True
        with self.assertRaises(EvidenceError): p.read_ready(io.BytesIO(framed(header)), binding())

    def test_length_bool_oversize_truncation_hash_and_mime_refuse(self):
        out = io.BytesIO(); p.write_request(out, binding(), png(), 'image/png')
        header, data = split(out.getvalue())
        for field, value in [('size', True), ('size', 5242881), ('size', 0), ('sha256', '0'*64),
                             ('media_type', 'application/octet-stream')]:
            altered = dict(header); altered[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(EvidenceError):
                p.read_request(io.BytesIO(framed(altered, data)), binding())
        with self.assertRaises(EvidenceError): p.read_request(io.BytesIO(out.getvalue()[:-1]), binding())

    def test_scan_result_never_carries_payload_or_decoder_success(self):
        for code in ['SCAN_CLEAN', 'SCAN_NOT_CLEAN', 'SCANNER_UNAVAILABLE']:
            out = io.BytesIO(); p.write_result(out, binding(), code)
            self.assertEqual(p.read_result(io.BytesIO(out.getvalue()), binding())[0]['code'], code)
        for code in ['DECODE_COMPLETE', 'UNKNOWN']:
            with self.assertRaises(EvidenceError): p.write_result(io.BytesIO(), binding(), code)
        with self.assertRaises(EvidenceError): p.write_result(io.BytesIO(), binding(), 'SCAN_CLEAN', data=png())

    def test_normalized_decode_result_is_rechecked_not_just_header(self):
        out = io.BytesIO(); p.write_result(out, binding('decode'), 'DECODE_COMPLETE', data=png(), width=1, height=1)
        header, data = p.read_result(io.BytesIO(out.getvalue()), binding('decode'))
        self.assertEqual((header['frames'], data), (1, png()))
        for key, value in [('frames', True), ('width', 2), ('media_type', 'image/jpeg'), ('code', 'SCAN_CLEAN')]:
            altered = dict(header); altered[key] = value
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                p.read_result(io.BytesIO(framed(altered, data)), binding('decode'))
        header['sha256'] = hashlib.sha256(b'notPNG').hexdigest(); header['size'] = 6
        with self.assertRaises(EvidenceError): p.read_result(io.BytesIO(framed(header, b'notPNG')), binding('decode'))

    def test_failure_result_must_have_no_image_metadata(self):
        out = io.BytesIO(); p.write_result(out, binding('decode'), 'DECODE_UNAVAILABLE')
        header, data = split(out.getvalue()); header['width'] = 1
        with self.assertRaises(EvidenceError): p.read_result(io.BytesIO(framed(header, data)), binding('decode'))


if __name__ == '__main__':
    unittest.main()
