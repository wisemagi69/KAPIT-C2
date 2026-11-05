"""Pure private capture metadata bounds. Device reports are never verified GPS."""
from datetime import datetime, timedelta
import json
import re


MAX_HEADER = 1024
PURPOSE = "private-evidence-capture-v1"
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,3})?Z\Z", re.ASCII)


class CaptureError(ValueError):
    def __init__(self):
        super().__init__("INVALID_EVIDENCE_CAPTURE")


def _require(value):
    if not value:
        raise CaptureError()


def _timestamp(value):
    _require(type(value) is str and _STAMP.fullmatch(value) is not None)
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise CaptureError() from None


def validate_capture(value, *, now):
    """Return a fresh closed object. Stored callers use original item.created_at."""
    _require(type(now) is datetime and now.tzinfo is not None and now.utcoffset() == timedelta(0))
    _require(type(value) is dict and set(value) == {"version", "captured_at", "location"})
    _require(type(value["version"]) is int and value["version"] == 1)
    captured = _timestamp(value["captured_at"])
    _require(captured <= now + timedelta(minutes=5))
    location = value["location"]
    result = {"version": 1, "captured_at": value["captured_at"], "location": None}
    if location is not None:
        _require(type(location) is dict and set(location) == {"latitude_e7", "longitude_e7", "accuracy_mm", "fix_at", "age_ms", "mock"})
        for name, lower, upper in (("latitude_e7", -900000000, 900000000),
                                   ("longitude_e7", -1800000000, 1800000000),
                                   ("accuracy_mm", 1, 100000000), ("age_ms", 0, 30000)):
            _require(type(location[name]) is int and lower <= location[name] <= upper)
        _require(type(location["mock"]) is bool)
        fix = _timestamp(location["fix_at"])
        difference = captured - fix
        elapsed_ms = difference.days * 86400000 + difference.seconds * 1000 + difference.microseconds // 1000
        _require(-1000 <= elapsed_ms <= 30000 and abs(elapsed_ms - location["age_ms"]) <= 1000)
        result["location"] = {name: location[name] for name in
            ("latitude_e7", "longitude_e7", "accuracy_mm", "fix_at", "age_ms", "mock")}
    try:
        encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    except (ValueError, UnicodeError):
        raise CaptureError() from None
    _require(len(encoded) <= MAX_HEADER)
    return result


def parse_capture_header(raw, *, now):
    """None alone means absent; explicit blank/null/duplicate fields are invalid."""
    if raw is None:
        return None
    _require(type(raw) is str)
    try:
        _require(len(raw.encode("ascii")) <= MAX_HEADER)
        value = strict_json(raw)
        return validate_capture(value, now=now)
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise CaptureError() from None


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            _require(key not in value)
            value[key] = item
        return value
    def nonfinite(_):
        raise CaptureError()
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def decrypt_original(ciphertext):
    """Same source Fernet primitive/key; strict JSON preserves capture ambiguity checks."""
    from cryptography.fernet import Fernet
    from django.conf import settings
    key = settings.KAPIT_SOURCE_KEY
    raw = Fernet(key.encode("ascii") if isinstance(key, str) else key).decrypt(bytes(ciphertext))
    return strict_json(raw.decode("utf-8"))
