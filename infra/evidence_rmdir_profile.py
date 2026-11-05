"""Pure versioned startup profile: exactly one added rmdir permission.

No file, Docker, native or policy-global mutation occurs. Normalization is an
inspection adapter only and never replaces independent full container checks.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from infra import evidence_container_native as historical

OLD_PROFILE_SHA256 = '389b9d083fc90982a51f999c9cfc1858cb660654d8d01dd5bc28da0a4e0523a7'
PROFILE_SHA256 = 'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733'
MAX_PROFILE_BYTES = 16384


class ProfileUnavailable(ValueError):
    def __str__(self): return 'RMDIR_STARTUP_PROFILE_UNAVAILABLE'


def _require(value):
    if value is not True: raise ProfileUnavailable()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def _profile_tree(value):
    """Exact profile primitives; in particular bool never aliases an integer."""
    pending = [(value, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        _require(depth <= 8 and count <= 512)
        if type(node) is dict:
            _require(len(node) <= 16 and all(type(key) is str for key in node))
            pending.extend((item, depth + 1) for item in node.values())
        elif type(node) is list:
            _require(len(node) <= 128)
            pending.extend((item, depth + 1) for item in node)
        elif type(node) is str:
            _require(node.isascii() and 1 <= len(node) <= 128)
        else:
            _require(type(node) is int and 0 <= node <= 0xffffffff)


def _old_profile():
    try:
        value = historical.startup_profile()
        _profile_tree(value)
        _require(hashlib.sha256(_canonical(value)).hexdigest() == OLD_PROFILE_SHA256)
        return deepcopy(value)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ProfileUnavailable() from None


def startup_profile():
    """Return a new independent profile; every historical rule is authenticated."""
    try:
        value = _old_profile()
        names = value['syscalls'][0]['names']
        _require(type(names) is list and names == sorted(set(names)) and 'rmdir' not in names)
        value['syscalls'][0]['names'] = sorted(names + ['rmdir'])
        _profile_tree(value)
        _require(hashlib.sha256(_canonical(value)).hexdigest() == PROFILE_SHA256)
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ProfileUnavailable() from None


def profile_bytes():
    return _canonical(startup_profile())


def profile_digest():
    # Reconstruct and authenticate, rather than returning a readiness flag.
    return hashlib.sha256(profile_bytes()).hexdigest()


def validate_effective_profile(raw):
    """Accept only the exact new JSON structure; paths/duplicates/types refuse."""
    def pairs(items):
        doc = {}
        for key, value in items:
            _require(key not in doc)
            doc[key] = value
        return doc
    try:
        _require(type(raw) is bytes and 1 <= len(raw) <= MAX_PROFILE_BYTES)
        value = json.loads(raw.decode('ascii'), object_pairs_hook=pairs,
                           parse_constant=lambda _: _require(False))
        _profile_tree(value)
        _require(_canonical(value) == profile_bytes())
        return value
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ProfileUnavailable() from None


def normalize_inspection(document):
    """Validate new effective seccomp first, then normalize only that field.

    Identity, labels, commands, resource limits, namespaces and every other
    inspection field are left to the unchanged independent validators.
    """
    try:
        _require(type(document) is dict and type(document.get('HostConfig')) is dict)
        options = document['HostConfig'].get('SecurityOpt')
        _require(type(options) is list and len(options) == 2 and
                 all(type(item) is str for item in options) and
                 options.count('no-new-privileges=true') == 1)
        policies = [index for index, item in enumerate(options) if item.startswith('seccomp=')]
        _require(len(policies) == 1)
        index = policies[0]
        validate_effective_profile(options[index][8:].encode('ascii'))
        normalized = deepcopy(document)
        normalized['HostConfig']['SecurityOpt'][index] = 'seccomp=' + _canonical(_old_profile()).decode('ascii')
        return normalized
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        raise ProfileUnavailable() from None
