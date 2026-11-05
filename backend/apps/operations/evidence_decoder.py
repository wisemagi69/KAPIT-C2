"""Optional maintained native decoder. Synthetic decode success is NOT validation.

Production callers must enforce reviewed OS isolation/provenance and scan both
original and derivative. This module never launches processes, scans or publishes.
Invoke with isolated interpreter: -B -m apps.operations.evidence_decoder
"""
from __future__ import annotations

from dataclasses import dataclass
import io
import sys
import warnings

from .evidence_policy import DEFAULT_POLICY, EvidenceError, checked_policy, dimensions, inspect_container

PILLOW_VERSION = "13.0.0"


@dataclass(frozen=True)
class DecodedEvidence:
    media_type: str
    width: int
    height: int
    frames: int
    data: bytes


class _CappedOutput(io.BytesIO):
    def __init__(self, maximum):
        super().__init__()
        self.maximum = maximum

    def write(self, data):
        if self.tell() + len(data) > self.maximum:
            raise EvidenceError("DERIVATIVE_LIMIT")
        return super().write(data)


def decode_image(data, media_type, *, policy=DEFAULT_POLICY):
    policy = checked_policy(policy)
    original = inspect_container(data, media_type, policy=policy)
    try:
        import PIL
        from PIL import Image, ImageFile, ImageOps, PngImagePlugin
    except ImportError:
        raise EvidenceError("DEPENDENCY_UNAVAILABLE") from None
    if PIL.__version__ != PILLOW_VERSION:
        raise EvidenceError("PROVENANCE_UNAVAILABLE")
    # Fresh single-request helper only. Restore globals so synthetic library tests
    # do not silently change other code. Native production concurrency is one.
    previous = (Image.MAX_IMAGE_PIXELS, ImageFile.LOAD_TRUNCATED_IMAGES,
                PngImagePlugin.MAX_TEXT_CHUNK, PngImagePlugin.MAX_TEXT_MEMORY)
    images = []
    try:
        Image.MAX_IMAGE_PIXELS = policy.max_pixels
        ImageFile.LOAD_TRUNCATED_IMAGES = False
        PngImagePlugin.MAX_TEXT_CHUNK = policy.metadata_bytes
        PngImagePlugin.MAX_TEXT_MEMORY = policy.metadata_bytes
        expected = "PNG" if media_type == "image/png" else "JPEG"
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            def open_checked(raw, format_name):
                image = Image.open(io.BytesIO(raw), formats=[format_name])
                images.append(image)
                dimensions(image.width, image.height, policy)
                if image.format != format_name or (image.width, image.height) != (original.width, original.height):
                    raise EvidenceError("TYPE_MISMATCH")
                if type(getattr(image, "n_frames", 1)) is not int or getattr(image, "n_frames", 1) != 1:
                    raise EvidenceError("MULTIFRAME_UNSUPPORTED")
                if image.mode not in {"1", "L", "LA", "P", "RGB", "RGBA"}:
                    raise EvidenceError("INVALID_IMAGE")
                return image
            verified = open_checked(data, expected)
            verified.verify()
            verified.close()
            image = open_checked(data, expected)
            image.load()
            oriented = ImageOps.exif_transpose(image)
            images.append(oriented)
            dimensions(oriented.width, oriented.height, policy)
            has_alpha = oriented.mode in ("LA", "RGBA") or "transparency" in oriented.info
            pixels = oriented.convert("RGBA" if has_alpha else "RGB")
            images.append(pixels)
            # New pixel instance rather than info-preserving copy; no metadata
            # arguments, profiles, comments, EXIF or pnginfo enter the encoder.
            clean = Image.frombytes(pixels.mode, pixels.size, pixels.tobytes())
            images.append(clean)
            clean.info.clear()
            sink = _CappedOutput(policy.max_output_bytes)
            clean.save(sink, format="PNG", optimize=False, compress_level=6)
            normalized = sink.getvalue()
            info = inspect_container(normalized, "image/png", policy=policy, normalized=True)
            if (info.width, info.height) != clean.size:
                raise EvidenceError("TYPE_MISMATCH")
            with Image.open(io.BytesIO(normalized), formats=["PNG"]) as reloaded:
                if reloaded.mode not in ("RGB", "RGBA") or getattr(reloaded, "n_frames", 1) != 1:
                    raise EvidenceError("INVALID_IMAGE")
                dimensions(reloaded.width, reloaded.height, policy)
                reloaded.verify()
            with Image.open(io.BytesIO(normalized), formats=["PNG"]) as reloaded:
                reloaded.load()
                if reloaded.size != clean.size:
                    raise EvidenceError("TYPE_MISMATCH")
            return DecodedEvidence("image/png", clean.width, clean.height, 1, normalized)
    except EvidenceError:
        raise
    except MemoryError:
        raise EvidenceError("RESOURCE_LIMIT") from None
    except (Image.DecompressionBombWarning, Image.DecompressionBombError):
        raise EvidenceError("PIXEL_LIMIT") from None
    except Exception:
        raise EvidenceError("INVALID_IMAGE") from None
    finally:
        for image in images:
            try:
                image.close()
            except Exception:
                pass
        (Image.MAX_IMAGE_PIXELS, ImageFile.LOAD_TRUNCATED_IMAGES,
         PngImagePlugin.MAX_TEXT_CHUNK, PngImagePlugin.MAX_TEXT_MEMORY) = previous


def main(stdin=None, stdout=None):
    from .evidence_protocol import read_request, write_result
    stdin = sys.stdin.buffer if stdin is None else stdin
    stdout = sys.stdout.buffer if stdout is None else stdout
    try:
        media_type, data = read_request(stdin)
        result = decode_image(data, media_type)
        write_result(stdout, code="DECODE_COMPLETE", data=result.data, width=result.width, height=result.height)
        return 0
    except EvidenceError as error:
        code = error.code
    except Exception:
        code = "DECODE_UNAVAILABLE"
    # No exception text, traceback, bytes, file name or metadata is reflected.
    try:
        write_result(stdout, code=code)
    except Exception:
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
