import hashlib
import json


def canonical(value):
    """UTF-8, sorted object keys, compact JSON; spelling of strings is preserved."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
