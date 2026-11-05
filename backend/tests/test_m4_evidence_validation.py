"""Synthetic preflight cases; mocked decoders do not establish real image safety."""
from dataclasses import asdict
import hashlib
import json
import struct
import unittest
import zlib

try:
    from apps.operations.evidence_validation import DecodedImage, EvidenceLimits, preflight, PNG_SIGNATURE
except ModuleNotFoundError:
    from backend.apps.operations.evidence_validation import DecodedImage, EvidenceLimits, preflight, PNG_SIGNATURE


def png_header(width=2, height=3):
    header = b"IHDR" + struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIGNATURE + struct.pack(">I", 13) + header + struct.pack(">I", zlib.crc32(header))


class EvidencePreflightTests(unittest.TestCase):
    def setUp(self):
        self.data = png_header()
        self.limits = EvidenceLimits(max_bytes=100, max_width=20, max_height=20, max_pixels=100)

    def check(self, data=None, mime="image/png", name="synthetic.png", **kwargs):
        return preflight(self.data if data is None else data, mime, name, self.limits, **kwargs)

    def test_explicit_limits_are_required_and_validated(self):
        for value in (0, -1, True, "100", float("inf")):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "INVALID_LIMITS"):
                EvidenceLimits(value, 20, 20, 100)
        with self.assertRaisesRegex(ValueError, "INVALID_LIMITS"):
            preflight(self.data, "image/png", "synthetic.png", None)

    def test_no_decoder_keeps_header_only_and_jpeg_marker_inputs_quarantined(self):
        # Header-only PNG and empty JPEG marker pair are deliberately not real images.
        for result in (self.check(), self.check(b"\xff\xd8\xff\xd9", "image/jpeg", "synthetic.jpg")):
            self.assertEqual((result.state, result.code), ("QUARANTINED", "DECODER_REQUIRED"))

    def test_empty_wrong_type_and_oversize_reject_before_decoder(self):
        def forbidden(*args):
            self.fail("decoder must not run on rejected envelope")
        for data, expected in ((b"", "INVALID_BYTES"), (bytearray(self.data), "INVALID_BYTES"),
                               (b"x" * 101, "BYTE_LIMIT")):
            with self.subTest(expected=expected):
                result = self.check(data, decoder=forbidden)
                self.assertEqual((result.state, result.code), ("REJECTED_PRIVATE", expected))

    def test_paths_controls_windows_devices_and_injection_names_rejected(self):
        for name in ("../source.png", "C:\\source.png", "a/b.png", "a.png.exe", "CON.png", "com1.JPG",
                     "a\x00.png", "a\r\nX-Header.png", "<script>.png", "a .png", "а.png", "a" * 101 + ".png"):
            with self.subTest(name=repr(name)):
                self.assertEqual(self.check(name=name).code, "INVALID_FILENAME")

    def test_mime_signature_and_extension_agreement(self):
        for data, mime, name, code in ((self.data, "image/jpeg", "synthetic.jpg", "MALFORMED_HEADER"),
                                       (self.data, "image/png", "synthetic.jpg", "TYPE_MISMATCH"),
                                       (b"GIF89a", "image/gif", "synthetic.png", "UNSUPPORTED_TYPE"),
                                       (b"<script>secret</script>", "image/png", "synthetic.png", "TYPE_MISMATCH")):
            with self.subTest(mime=mime, name=name):
                self.assertEqual(self.check(data, mime, name).code, code)

    def test_header_corruption_and_advertised_bombs_rejected(self):
        for data in (self.data[:20], self.data[:29] + b"\x00" * 4, PNG_SIGNATURE + b"bad header"):
            self.assertEqual(self.check(data).code, "MALFORMED_HEADER")
        for width, height in ((0, 2), (21, 2), (20, 20), (2**32 - 1, 2**32 - 1)):
            self.assertEqual(self.check(png_header(width, height)).code, "PIXEL_LIMIT")

    def test_digest_retries_bind_exact_bytes_without_existence_lookup(self):
        digest = hashlib.sha256(self.data).hexdigest()
        self.assertEqual(self.check(expected_digest=digest).state, "QUARANTINED")
        self.assertEqual(self.check(expected_digest="0" * 64).code, "DIGEST_CONFLICT")
        for malformed in ("PRIVATE_CANARY", "0" * 63, True):
            self.assertEqual(self.check(expected_digest=malformed).code, "INVALID_DIGEST")

    def test_trusted_decoder_receives_explicit_limits_and_cannot_validate_evidence(self):
        seen = []
        def decoder(data, mime, limits):
            seen.append((data, mime, limits))
            return DecodedImage(mime, 2, 3, 1)
        result = self.check(decoder=decoder)
        self.assertEqual(seen, [(self.data, "image/png", self.limits)])
        self.assertEqual((result.state, result.code), ("QUARANTINED", "SCANNER_POLICY_REQUIRED"))

    def test_decoder_failures_malformed_results_animation_and_size_fail_closed(self):
        def raising(*args):
            raise RuntimeError("PRIVATE_CANARY parser details")
        result = self.check(decoder=raising)
        self.assertEqual((result.state, result.code), ("QUARANTINED", "DECODE_UNAVAILABLE"))
        self.assertNotIn("PRIVATE_CANARY", json.dumps(asdict(result)))
        for decoded, expected in (({}, "INVALID_DECODE_RESULT"), (DecodedImage("image/jpeg", 2, 3, 1), "TYPE_MISMATCH"),
                                  (DecodedImage("image/png", 2, 3, 2), "MULTIFRAME_UNSUPPORTED"),
                                  (DecodedImage("image/png", 2, 3, True), "MULTIFRAME_UNSUPPORTED"),
                                  (DecodedImage("image/png", 2, 1000, 1), "PIXEL_LIMIT"),
                                  (DecodedImage("image/png", 3, 2, 1), "DECODE_MISMATCH")):
            with self.subTest(expected=expected):
                self.assertEqual(self.check(decoder=lambda *args: decoded).code, expected)


if __name__ == "__main__":
    unittest.main()
