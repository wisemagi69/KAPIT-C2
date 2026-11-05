"""Pure fixtures and optional Pillow13 synthetic decode; no scanner/DB/OS-isolation claim."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import struct
import unittest
from unittest.mock import patch
import zlib

from apps.operations import evidence_decoder as decoder
from apps.operations import evidence_policy as policy
from apps.operations import evidence_protocol as protocol

try:
    import PIL
    NATIVE = PIL.__version__ == decoder.PILLOW_VERSION
except ImportError:
    NATIVE = False

NOW = datetime(2026, 10, 21, 12, tzinfo=timezone.utc)


def chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)


def png(width=1, height=1, *, extras=(), color=2, depth=8):
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, 0))
            + b"".join(extras) + chunk(b"IDAT", zlib.compress(b"\x00\x01\x02\x03")) + chunk(b"IEND", b""))


def segment(marker, data):
    return b"\xff" + bytes([marker]) + struct.pack(">H", len(data) + 2) + data


def jpeg(width=1, height=1, *, extras=b""):
    # Framing fixture intentionally has no quantization/Huffman tables; parser
    # success alone must not imply it decodes or is a valid private derivative.
    return (b"\xff\xd8" + extras + segment(0xc0, struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x00\x03\x11\x00")
            + segment(0xda, b"\x03\x01\x00\x02\x11\x03\x11\x00\x3f\x00") + b"\x10\xff\x00\x20\xff\xd0\x30\xff\xd9")


def manifest():
    def stamp(value): return value.isoformat()
    files = [{"name": base + ".cvd", "sha256": "a" * 64, "version": 1,
              "signed_at": stamp(NOW - timedelta(hours=1)), "verification_receipt_sha256": "b" * 64}
             for base in ("bytecode", "daily", "main")]
    doc = {key: "a" * 64 for key in policy.MANIFEST_FIELDS}
    doc.update(schema_version=1, purpose="private-evidence-validation-v1", policy_generation=1,
               created_at=stamp(NOW), valid_until=stamp(NOW + timedelta(days=1)), python_version="3.14.0",
               pillow_version="13.0.0", clamav_version="1.4.6",
               codec_versions={"jpeg": "8.0", "zlib": "1.3.1.zlib-ng"}, signature_files=files,
               daily_signed_at=files[1]["signed_at"],
               last_successful_update_check_at=stamp(NOW - timedelta(minutes=5)),
               signature_generation=hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
    return doc


def parse(doc, **kwargs):
    return policy.parse_manifest(json.dumps(doc, separators=(",", ":")).encode(), now=kwargs.get("now", NOW))


class ContainerTests(unittest.TestCase):
    def error(self, data, media="image/png", code=None, **kwargs):
        with self.assertRaises(policy.EvidenceError) as caught:
            policy.inspect_container(data, media, **kwargs)
        if code:
            self.assertEqual(caught.exception.code, code)

    def test_small_png_and_jpeg_framing(self):
        self.assertEqual(policy.inspect_container(png(), "image/png").width, 1)
        self.assertEqual(policy.inspect_container(jpeg(), "image/jpeg").height, 1)

    def test_type_trailing_truncation_crc_and_header_order(self):
        self.error(png(), "image/jpeg", "TYPE_MISMATCH")
        for data in (png() + b"PRIVATE_CANARY", png()[:-1], png()[:20], b"", bytearray(png()),
                     png().replace(b"IHDR", b"JHDR", 1), b"not an image"):
            self.error(data)
        self.error(jpeg() + b"trailer", "image/jpeg")
        self.error(jpeg()[:-2], "image/jpeg")
        self.error(jpeg().replace(b"\xff\xda", b"\xff\x02"), "image/jpeg")

    def test_dimensions_product_limits_exact_integer_policy(self):
        self.error(png(6001, 1), code="PIXEL_LIMIT")
        self.error(png(6000, 4001), code="PIXEL_LIMIT")
        self.error(jpeg(1, 6001), "image/jpeg", "PIXEL_LIMIT")
        for value in (True, 0, -1, 6001, "12", 1.5):
            with self.assertRaises(policy.EvidenceError):
                policy.EvidencePolicy(max_width=value)
        self.error(png(), policy={})

    def test_animation_mpo_metadata_budget_and_unsupported_modes(self):
        for kind in (b"acTL", b"fcTL", b"fdAT"):
            self.error(png(extras=[chunk(kind, b"")]), code="MULTIFRAME_UNSUPPORTED")
        self.error(jpeg(extras=segment(0xe2, b"MPF\x00private")), "image/jpeg", "MULTIFRAME_UNSUPPORTED")
        self.error(png(extras=[chunk(b"tEXt", b"x" * 65537)]), code="METADATA_INVALID")
        self.error(png(depth=16))
        self.error(png(color=1))

    def test_png_palette_and_idat_order_and_critical_chunks(self):
        self.error(png(color=3))
        self.error(png(extras=[chunk(b"ABCD", b"")]))
        source = png().replace(chunk(b"IEND", b""), chunk(b"tEXt", b"k\x00v") + chunk(b"IDAT", b"") + chunk(b"IEND", b""))
        self.error(source)
        self.error(png(extras=[chunk(b"tRNS", b"bad")]))

    def test_normalized_output_forbids_every_metadata_chunk(self):
        self.assertEqual(policy.inspect_container(png(), "image/png", normalized=True).metadata_bytes, 0)
        for kind in (b"tEXt", b"eXIf", b"iCCP", b"tIME"):
            self.error(png(extras=[chunk(kind, b"PRIVATE_CANARY")]), normalized=True)
        self.error(jpeg(), "image/jpeg", normalized=True)

    def test_missing_optional_decoder_is_fixed_unavailable(self):
        import sys
        with patch.dict(sys.modules, {"PIL": None}):
            with self.assertRaises(policy.EvidenceError) as caught:
                decoder.decode_image(png(), "image/png")
        self.assertEqual(caught.exception.code, "DEPENDENCY_UNAVAILABLE")

    def test_metadata_budget_accounts_empty_chunk_overhead(self):
        self.error(png(extras=[chunk(b"tEXt", b"")] * 5462), code="METADATA_INVALID")

    def test_exif_ifd_cycles_offsets_and_orientation_are_bounded(self):
        header = b"II\x2a\x00" + struct.pack("<I", 8)
        empty = header + b"\x00\x00" + struct.pack("<I", 0)
        self.assertEqual(policy.inspect_container(png(extras=[chunk(b"eXIf", empty)]), "image/png").width, 1)
        malformed = [b"bad", b"II\x2a\x00" + b"\x00" * 4,
                     header + b"\x00\x00" + struct.pack("<I", 8),
                     header + struct.pack("<H", 65535),
                     header + struct.pack("<H", 1) + struct.pack("<HHII", 274, 3, 1, 9) + b"\x00" * 4,
                     header + struct.pack("<H", 1) + struct.pack("<HHII", 270, 2, 65536, 99999) + b"\x00" * 4]
        for raw in malformed:
            self.error(png(extras=[chunk(b"eXIf", raw)]), code="METADATA_INVALID")
            self.error(jpeg(extras=segment(0xe1, b"Exif\x00\x00" + raw)), "image/jpeg", "METADATA_INVALID")


class ProtocolTests(unittest.TestCase):
    def envelope(self, header, data=b""):
        raw = json.dumps(header, separators=(",", ":")).encode()
        return io.BytesIO(struct.pack(">I", len(raw)) + raw + data)

    def test_request_and_result_roundtrip_and_no_validation_state(self):
        stream = io.BytesIO()
        protocol.write_request(stream, png(), "image/png")
        self.assertEqual(protocol.read_request(io.BytesIO(stream.getvalue())), ("image/png", png()))
        stream = io.BytesIO()
        protocol.write_result(stream, code="DECODE_COMPLETE", data=png(), width=1, height=1)
        header, data = protocol.read_result(io.BytesIO(stream.getvalue()))
        self.assertEqual(data, png())
        self.assertNotIn("state", header)
        self.assertNotIn("VALIDATED_PRIVATE", json.dumps(header))
        for code in policy.CODES - {"DECODE_COMPLETE"}:
            stream = io.BytesIO()
            protocol.write_result(stream, code=code)
            self.assertEqual(protocol.read_result(io.BytesIO(stream.getvalue()))[0]["code"], code)

    def test_duplicate_json_keys_boolean_version_and_unknown_fields(self):
        stream = io.BytesIO()
        protocol.write_request(stream, png(), "image/png")
        encoded = stream.getvalue()
        size = int.from_bytes(encoded[:4], "big")
        original = json.loads(encoded[4:4 + size])
        for key, value in (("schema", True), ("size", True), ("extra", "PRIVATE_CANARY"),
                           ("media_type", []), ("sha256", "A" * 64)):
            altered = {**original, key: value}
            with self.assertRaises(policy.EvidenceError):
                protocol.read_request(self.envelope(altered, png()))
        raw = b'{"schema":1,"schema":1}'
        with self.assertRaises(policy.EvidenceError):
            protocol.read_request(io.BytesIO(struct.pack(">I", len(raw)) + raw))

    def test_truncation_digest_oversize_and_trailing_refuse(self):
        stream = io.BytesIO()
        protocol.write_request(stream, png(), "image/png")
        frame = stream.getvalue()
        for data in (b"", frame[:-1], frame + b"x", b"\x00\x00\x10\x01", frame[:-5] + b"xxxxx"):
            with self.assertRaises(policy.EvidenceError):
                protocol.read_request(io.BytesIO(data))

    def test_unknown_and_forged_success_or_failure_are_not_safe(self):
        template = dict(schema=1, purpose=protocol.RESULT, code="DECODE_COMPLETE", media_type="image/png",
                        width=1, height=1, frames=1, size=len(png()), sha256=hashlib.sha256(png()).hexdigest())
        for changes in ({"code": "VALIDATED_PRIVATE"}, {"width": True}, {"height": 2}, {"frames": True},
                        {"code": "DECODE_UNAVAILABLE"}, {"media_type": "image/jpeg"}, {"code": []}):
            with self.assertRaises(policy.EvidenceError):
                protocol.read_result(self.envelope({**template, **changes}, png()))
        with self.assertRaises(policy.EvidenceError):
            protocol.write_result(io.BytesIO(), code="private exception canary")

    def test_partial_io_works_and_invalid_stream_capability_refuses(self):
        class Partial(io.BytesIO):
            def read(self, n=-1): return super().read(min(n, 3))
            def write(self, data): return super().write(data[:3])
        stream = Partial()
        protocol.write_request(stream, png(), "image/png")
        self.assertEqual(protocol.read_request(Partial(stream.getvalue()))[1], png())
        class Broken:
            def read(self, size): return "PRIVATE_CANARY"
        with self.assertRaises(policy.EvidenceError):
            protocol.read_request(Broken())

    def test_main_contains_errors_and_writes_only_fixed_envelope(self):
        output = io.BytesIO()
        self.assertEqual(decoder.main(io.BytesIO(b"PRIVATE_INPUT_CANARY"), output), 2)
        header, data = protocol.read_result(io.BytesIO(output.getvalue()))
        self.assertEqual(header["code"], "DECODE_UNAVAILABLE")
        self.assertNotIn(b"PRIVATE", output.getvalue())
        self.assertEqual(data, b"")
        request = io.BytesIO()
        protocol.write_request(request, png(), "image/png")
        with patch.object(decoder, "decode_image", side_effect=RuntimeError("PRIVATE_EXCEPTION_CANARY")):
            output = io.BytesIO()
            self.assertEqual(decoder.main(io.BytesIO(request.getvalue()), output), 2)
            self.assertNotIn(b"PRIVATE", output.getvalue())


class ManifestTests(unittest.TestCase):
    def test_future_expiry_valid_and_result_detached_frozen(self):
        parsed = parse(manifest())
        self.assertEqual(parsed.policy_generation, 1)
        self.assertEqual(len(parsed.manifest_hash), 64)
        self.assertEqual(parsed.expires_at, NOW + timedelta(hours=23, minutes=55))
        with self.assertRaises(TypeError):
            parsed.document["codec_versions"]["jpeg"] = "changed"
        detached = parsed.as_provenance()
        detached["codec_versions"]["jpeg"] = "changed"
        self.assertEqual(parsed.as_provenance()["codec_versions"]["jpeg"], "8.0")

    def test_future_observation_naive_time_and_excessive_expiry_refuse(self):
        for key in ("created_at", "daily_signed_at", "last_successful_update_check_at"):
            doc = manifest()
            doc[key] = (NOW + timedelta(seconds=1)).isoformat()
            with self.assertRaises(policy.EvidenceError): parse(doc)
        for value in (NOW.replace(tzinfo=None), True):
            with self.assertRaises(policy.EvidenceError): parse(manifest(), now=value)
        doc = manifest()
        doc["valid_until"] = (NOW + timedelta(days=7, seconds=1)).isoformat()
        with self.assertRaises(policy.EvidenceError): parse(doc)

    def test_expired_and_stale_checked_database_remain_closed(self):
        with self.assertRaises(policy.EvidenceError) as caught:
            parse(manifest(), now=NOW + timedelta(days=2))
        self.assertEqual(caught.exception.code, "VALIDATION_STALE")
        doc = manifest()
        doc["last_successful_update_check_at"] = (NOW - timedelta(days=2)).isoformat()
        # Also make daily metadata consistently older so check ordering is valid.
        for item in doc["signature_files"]: item["signed_at"] = (NOW - timedelta(days=2, hours=1)).isoformat()
        doc["daily_signed_at"] = doc["signature_files"][1]["signed_at"]
        doc["signature_generation"] = hashlib.sha256(json.dumps(doc["signature_files"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaises(policy.EvidenceError) as caught: parse(doc)
        self.assertEqual(caught.exception.code, "SIGNATURES_STALE")

    def test_hashes_versions_codecs_files_types_and_unknown_fields(self):
        for key, value in (("schema_version", True), ("policy_generation", True),
                           ("helper_sha256", "A" * 64), ("pillow_version", "12.3.0"),
                           ("clamav_version", "1.5.4"), ("codec_versions", {"jpeg": "8"}),
                           ("codec_versions", {"jpeg": "8", "zlib": "1", "path": "PRIVATE_CANARY"}),
                           ("extra", 1), ("signature_generation", "0" * 64)):
            doc = manifest()
            doc[key] = value
            with self.assertRaises(policy.EvidenceError): parse(doc)
        for mutate in ("order", "name", "version", "field"):
            doc = manifest()
            if mutate == "order": doc["signature_files"].reverse()
            if mutate == "name": doc["signature_files"][0]["name"] = "../main.cvd"
            if mutate == "version": doc["signature_files"][0]["version"] = True
            if mutate == "field": doc["signature_files"][0]["raw"] = "PRIVATE_CANARY"
            with self.assertRaises(policy.EvidenceError): parse(doc)

    def test_json_bounds_duplicates_nonfinite_and_depth(self):
        for raw in (b" " * 65537, b"[]", b'{"schema_version":1,"schema_version":1}', b'{"bad":NaN}',
                    b"[" * 20 + b"0" + b"]" * 20, b"\xff"):
            with self.assertRaises(policy.EvidenceError) as caught:
                policy.parse_manifest(raw, now=NOW)
            self.assertNotIn("PRIVATE", str(caught.exception))


@unittest.skipUnless(NATIVE, "Pillow13 tool environment unavailable; no native decode claim")
class NativeDecodeTests(unittest.TestCase):
    def image(self, format="PNG", mode="RGB", size=(3, 2), **options):
        from PIL import Image
        output = io.BytesIO()
        with Image.new(mode, size, 1 if mode in ("L", "P", "1") else 0) as image:
            image.save(output, format=format, **options)
        return output.getvalue()

    def test_real_valid_jpeg_png_palette_grayscale_and_alpha(self):
        from PIL import Image
        for format, mode in (("PNG", "RGB"), ("PNG", "RGBA"), ("PNG", "P"), ("PNG", "L"),
                             ("PNG", "LA"), ("PNG", "1"), ("JPEG", "RGB"), ("JPEG", "L")):
            result = decoder.decode_image(self.image(format, mode), "image/png" if format == "PNG" else "image/jpeg")
            self.assertEqual((result.width, result.height, result.frames), (3, 2, 1))
            policy.inspect_container(result.data, "image/png", normalized=True)
            with Image.open(io.BytesIO(result.data)) as image:
                image.load()
                self.assertIn(image.mode, ("RGB", "RGBA"))
                self.assertEqual(image.info, {})

    def test_metadata_canary_removed_and_exif_orientation_applied(self):
        from PIL import Image, PngImagePlugin
        info = PngImagePlugin.PngInfo()
        info.add_text("private", "SYNTHETIC_PRIVATE_METADATA_CANARY")
        result = decoder.decode_image(self.image(pnginfo=info), "image/png")
        self.assertNotIn(b"SYNTHETIC_PRIVATE_METADATA_CANARY", result.data)
        exif = Image.Exif()
        exif[274] = 6
        exif[270] = "SYNTHETIC_PRIVATE_METADATA_CANARY"
        result = decoder.decode_image(self.image("JPEG", size=(3, 2), exif=exif), "image/jpeg")
        self.assertEqual((result.width, result.height), (2, 3))
        self.assertNotIn(b"SYNTHETIC_PRIVATE_METADATA_CANARY", result.data)

    def test_compressed_text_budget_and_malformed_exif_fail(self):
        from PIL import PngImagePlugin
        info = PngImagePlugin.PngInfo()
        info.add_text("private", "x" * 70000, zip=True)
        with self.assertRaises(policy.EvidenceError):
            decoder.decode_image(self.image(pnginfo=info), "image/png")
        with self.assertRaises(policy.EvidenceError):
            decoder.decode_image(self.image("JPEG", exif=b"Exif\x00\x00bad"), "image/jpeg")

    def test_complete_decode_not_header_verdict_and_limits(self):
        for data, media in ((jpeg(), "image/jpeg"), (png(width=4), "image/png"),
                            (self.image("JPEG")[:-10], "image/jpeg")):
            with self.assertRaises(policy.EvidenceError): decoder.decode_image(data, media)
        with self.assertRaises(policy.EvidenceError) as caught:
            decoder.decode_image(self.image(size=(4, 3)), "image/png", policy=policy.EvidencePolicy(max_pixels=10))
        self.assertEqual(caught.exception.code, "PIXEL_LIMIT")
        with self.assertRaises(policy.EvidenceError) as caught:
            decoder.decode_image(self.image(), "image/png", policy=policy.EvidencePolicy(max_output_bytes=20))
        self.assertEqual(caught.exception.code, "DERIVATIVE_LIMIT")

    def test_cmyk_rejected_and_global_settings_restored(self):
        from PIL import Image, ImageFile, PngImagePlugin
        previous = (Image.MAX_IMAGE_PIXELS, ImageFile.LOAD_TRUNCATED_IMAGES, PngImagePlugin.MAX_TEXT_CHUNK, PngImagePlugin.MAX_TEXT_MEMORY)
        with self.assertRaises(policy.EvidenceError):
            decoder.decode_image(self.image("JPEG", mode="CMYK"), "image/jpeg")
        decoder.decode_image(self.image(), "image/png")
        self.assertEqual(previous, (Image.MAX_IMAGE_PIXELS, ImageFile.LOAD_TRUNCATED_IMAGES,
                                    PngImagePlugin.MAX_TEXT_CHUNK, PngImagePlugin.MAX_TEXT_MEMORY))

    def test_helper_main_success_remains_intermediate_decode(self):
        request, output = io.BytesIO(), io.BytesIO()
        protocol.write_request(request, self.image(), "image/png")
        self.assertEqual(decoder.main(io.BytesIO(request.getvalue()), output), 0)
        header, data = protocol.read_result(io.BytesIO(output.getvalue()))
        self.assertEqual(header["code"], "DECODE_COMPLETE")
        self.assertNotIn("VALIDATED", json.dumps(header))
        self.assertGreater(len(data), 0)

    def test_wrong_native_version_and_resource_failure_are_fixed(self):
        import PIL
        from PIL import Image
        source = self.image()
        with patch.object(PIL, "__version__", "12.3.0"):
            with self.assertRaises(policy.EvidenceError) as caught:
                decoder.decode_image(source, "image/png")
        self.assertEqual(caught.exception.code, "PROVENANCE_UNAVAILABLE")
        with patch.object(Image, "open", side_effect=MemoryError("PRIVATE_ALLOCATION_CANARY")):
            with self.assertRaises(policy.EvidenceError) as caught:
                decoder.decode_image(source, "image/png")
        self.assertEqual(caught.exception.code, "RESOURCE_LIMIT")
        self.assertNotIn("PRIVATE", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
