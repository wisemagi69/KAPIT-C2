"""Bounded, optional local detector boundary. Findings never approve disclosure."""
import math
import re

MAX_TEXT_BYTES = 20 * 1024
MAX_SPANS = 256
ENTITIES = frozenset({"PERSON", "LOCATION", "IDENTIFIER"})
MANIFEST_KEYS = frozenset({"engine", "recognizer_version", "model_version"})
OUTCOMES = frozenset({"READY_FOR_HUMAN_REVIEW", "MANUAL_REQUIRED", "FAILED_PRIVATE"})
CODES = frozenset({"DETECTOR_COMPLETED", "DETECTOR_UNAVAILABLE", "UNSUPPORTED_LANGUAGE", "INVALID_INPUT", "DETECTOR_ERROR", "INVALID_RESULT"})


def valid_text(text):
    if not isinstance(text, str) or not text:
        return False
    try:
        return len(text.encode("utf-8")) <= MAX_TEXT_BYTES
    except UnicodeError:
        return False


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise ValueError("INVALID_ENGINE_MANIFEST")
    for value in manifest.values():
        if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}", value)
                or value.lower() in {"unknown", "latest", "none", "unversioned"}):
            raise ValueError("INVALID_ENGINE_MANIFEST")
    return dict(manifest)


def validate_spans(spans, text_length, *, scores=True):
    """Offsets use Python Unicode code points; exact duplicates are invalid; overlaps are allowed."""
    if not isinstance(spans, list) or len(spans) > MAX_SPANS:
        raise ValueError("INVALID_SPANS")
    checked, seen = [], set()
    keys = {"entity", "start", "end", "score"} if scores else {"entity", "start", "end"}
    for span in spans:
        if not isinstance(span, dict) or set(span) != keys:
            raise ValueError("INVALID_SPAN")
        start, end, entity = span["start"], span["end"], span["entity"]
        if (type(start) is not int or type(end) is not int or not 0 <= start < end <= text_length
                or not isinstance(entity, str) or entity not in ENTITIES):
            raise ValueError("INVALID_SPAN")
        identity = (entity, start, end)
        if identity in seen:
            raise ValueError("DUPLICATE_SPAN")
        seen.add(identity)
        if scores:
            score = span["score"]
            # Adapter contract: nullable recognizer confidence/rank normalized to [0,1].
            # No interpretation as probability of safe disclosure is permitted.
            if score is not None and (type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1):
                raise ValueError("INVALID_SCORE")
        checked.append(dict(span))
    return checked


def _result(outcome, code, manifest=None, spans=None):
    return {"outcome": outcome, "code": code, "manifest": manifest, "spans": spans or []}


def detect(text, language="en", *, adapter=None, manifest=None):
    """Trusted synchronous local adapter hook; no imports/downloads, persistence or publication.

    Runtime timeout/process isolation belongs to a later integration. Callers must not
    pass an untrusted or unbounded adapter; exceptions become fixed private codes.
    """
    if not valid_text(text):
        return _result("FAILED_PRIVATE", "INVALID_INPUT")
    if language != "en":
        return _result("MANUAL_REQUIRED", "UNSUPPORTED_LANGUAGE")
    if adapter is None:
        return _result("MANUAL_REQUIRED", "DETECTOR_UNAVAILABLE")
    try:
        frozen = validate_manifest(manifest)
    except (ValueError, TypeError):
        return _result("FAILED_PRIVATE", "INVALID_RESULT")
    try:
        raw = adapter(text, language)
    except Exception:
        return _result("FAILED_PRIVATE", "DETECTOR_ERROR", frozen)
    try:
        spans = validate_spans(raw, len(text))
    except (ValueError, TypeError):
        return _result("FAILED_PRIVATE", "INVALID_RESULT", frozen)
    return _result("READY_FOR_HUMAN_REVIEW", "DETECTOR_COMPLETED", frozen, spans)


def validate_result(result, text_length):
    """Revalidate observations on the evaluator boundary, including outcome/code agreement."""
    if not isinstance(result, dict) or set(result) != {"outcome", "code", "manifest", "spans"}:
        raise ValueError("INVALID_DETECTOR_RESULT")
    pairs = {("READY_FOR_HUMAN_REVIEW", "DETECTOR_COMPLETED"),
             ("MANUAL_REQUIRED", "DETECTOR_UNAVAILABLE"), ("MANUAL_REQUIRED", "UNSUPPORTED_LANGUAGE"),
             ("FAILED_PRIVATE", "INVALID_INPUT"), ("FAILED_PRIVATE", "DETECTOR_ERROR"),
             ("FAILED_PRIVATE", "INVALID_RESULT")}
    if (not isinstance(result["outcome"], str) or not isinstance(result["code"], str)
            or (result["outcome"], result["code"]) not in pairs):
        raise ValueError("INVALID_DETECTOR_RESULT")
    if result["manifest"] is not None:
        validate_manifest(result["manifest"])
    if result["outcome"] == "READY_FOR_HUMAN_REVIEW":
        validate_manifest(result["manifest"])
        validate_spans(result["spans"], text_length)
    elif result["spans"] != []:
        raise ValueError("PRIVATE_FAILURE_HAS_FINDINGS")
    return result
