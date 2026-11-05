"""Authenticated held-byte loader, synthetic qualification only.

Interpreter, stdlib, cryptography, this module and backend are an externally
admitted trusted base. This is neither a Python sandbox nor self-authentication.
Production remains closed; no native API is imported or invoked here.
"""
import builtins
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import sys
from types import MappingProxyType, ModuleType

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class Refused(ValueError):
    def __init__(self):
        super().__init__("RELEASE_BOOTSTRAP_REFUSED")


BUNDLE = (
    ("schemas", "infra/evidence_release_schemas.py"),
    ("bridge", "infra/evidence_release_bridge.py"),
    ("lifecycle", "infra/evidence_release_lifecycle.py"),
    ("reservations", "infra/evidence_release_reservations.py"),
)
MODULES = tuple(path[:-3].replace("/", ".") for _, path in BUNDLE)
EXTERNAL_NAMES = frozenset(("dataclasses", "datetime", "hashlib", "json", "re",
    "functools", "cryptography.hazmat.primitives.asymmetric.ed25519", "os",
    "pathlib", "time", "types", "math", "ctypes", "ctypes.wintypes", "ntpath"))
MAX_SOURCE = 1048576
MAX_MANIFEST = 8192
DOMAIN = b"KAPIT-C2/EXECUTABLE-BUNDLE/V1\x00"
_COMPILE, _EXEC = compile, exec


def _need(condition):
    if not condition:
        raise Refused()


def _hex(value, width):
    _need(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % width, value) is not None
          and value != "0" * width)


def _label(value):
    _need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is not None)


def _utc(value):
    _need(type(value) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is not None)
    try:
        result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        raise Refused() from None
    _need(result.strftime("%Y-%m-%dT%H:%M:%SZ") == value)
    return result


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


@dataclass(frozen=True)
class OfflineTrust:
    """Explicit externally admitted configuration, never obtained from manifest."""
    key_id: str
    public_key: bytes
    policy: str
    authority: str
    owner: str
    revoked_key_ids: tuple = ()


def verify_manifest(raw, signature, *, trust, now_utc, expected_nonce):
    """Authenticate the entire canonical ASCII byte string before backend access."""
    try:
        _need(type(trust) is OfflineTrust)
        for label in (trust.key_id, trust.policy, trust.authority):
            _label(label)
        _need(type(trust.owner) is str and 1 <= len(trust.owner) <= 184 and trust.owner.isascii())
        _need(type(trust.public_key) is bytes and len(trust.public_key) == 32)
        _need(type(trust.revoked_key_ids) is tuple)
        for revoked in trust.revoked_key_ids:
            _label(revoked)
        _need(trust.key_id not in trust.revoked_key_ids)
        _hex(expected_nonce, 32)
        now = _utc(now_utc)
        _need(type(raw) is bytes and 1 <= len(raw) <= MAX_MANIFEST and raw.isascii())
        _need(type(signature) is bytes and len(signature) == 64)
        Ed25519PublicKey.from_public_bytes(trust.public_key).verify(signature, DOMAIN + raw)
        value = json.loads(raw.decode("ascii"))
        _need(type(value) is dict and set(value) == {"scope", "version", "key_id", "policy",
            "authority", "nonce", "issued_utc", "expires_utc", "files"})
        _need(canonical(value) == raw)
        _need(value["scope"] == "PUBLIC_EXECUTABLE_BUNDLE_V1" and type(value["version"]) is int and value["version"] == 1)
        _need((value["key_id"], value["policy"], value["authority"], value["nonce"]) ==
              (trust.key_id, trust.policy, trust.authority, expected_nonce))
        issued, expires = _utc(value["issued_utc"]), _utc(value["expires_utc"])
        _need(issued <= now < expires and 0 < (expires - issued).total_seconds() <= 300)
        files = value["files"]
        _need(type(files) is list and len(files) == len(BUNDLE))
        for row, (logical, path) in zip(files, BUNDLE):
            _need(type(row) is dict and set(row) == {"id", "path", "sha256", "size"})
            _need((row["id"], row["path"]) == (logical, path))
            _hex(row["sha256"], 64)
            _need(type(row["size"]) is int and 1 <= row["size"] <= MAX_SOURCE)
        return value
    except BaseException:
        pass
    raise Refused()


def _identity(value, owner, directory=False):
    """Local pre-import check; no dependency on the files being authenticated."""
    _need(type(value) is dict and set(value) == {"volume", "file_id", "attributes", "links",
        "size", "disk", "private", "owner"})
    _need(type(value["volume"]) is int and 1 <= value["volume"] <= 2**64 - 1)
    _hex(value["file_id"], 32)
    attrs = value["attributes"]
    _need(type(attrs) is int and 0 <= attrs <= 2**32 - 1 and not attrs & (0x400 | 0x40))
    _need(bool(attrs & 0x10) is directory)
    _need(type(value["links"]) is int and value["links"] == 1)
    _need(type(value["size"]) is int and 0 <= value["size"] <= (2**63 - 1 if directory else MAX_SOURCE))
    _need(value["disk"] is True and type(value["private"]) is bool
          and type(value["owner"]) is str and value["owner"] == owner)
    return dict(value)


class _Held:
    def __init__(self, obj, owner, directory, close_original):
        # Capture close first so later capture/identity failures still close original.
        self.close_callback = close_original
        self.closed = False
        self.identity_callback = obj.identity
        self.read_callback = None if directory else obj.read
        self.owner, self.directory = owner, directory
        self.original = _identity(self.identity_callback(), owner, directory)

    def recheck(self):
        _need(_identity(self.identity_callback(), self.owner, self.directory) == self.original)

    def close(self):
        if not self.closed:
            self.closed = True
            _need(self.close_callback() is None)


class LoadedBundle:
    """Held synthetic modules; closure failure is sticky, never an authority token."""
    def __init__(self, modules, held):
        self.modules = MappingProxyType(dict(modules))
        self._held = tuple(held)
        self._closed = False
        self._failed = False

    def close(self):
        if not self._closed:
            self._closed = True
            for resource in reversed(self._held):
                try:
                    resource.recheck()
                except BaseException:
                    self._failed = True
                try:
                    resource.close()
                except BaseException:
                    self._failed = True
        _need(not self._failed)


def production_bootstrap(*args, **kwargs):
    """Unconditionally closed, including before access to supplied inputs/backend."""
    raise Refused()


def load_synthetic_bundle(backend, raw, signature, *, trust, now_utc, expected_nonce,
                          trusted_external):
    """Protocol test seam. Never use this function as production admission.

    Supplied external modules are separately admitted base dependencies. Authenticated
    Python code still has full interpreter privileges; restricted imports are not a
    sandbox. This seam is tested solely with benign synthetic fixture sources.
    """
    manifest = verify_manifest(raw, signature, trust=trust, now_utc=now_utc,
                               expected_nonce=expected_nonce)
    held, modules = [], {}
    compile_owned, exec_owned = _COMPILE, _EXEC
    try:
        _need(type(trusted_external) is dict and set(trusted_external) <= EXTERNAL_NAMES)
        external = dict(trusted_external)
        _need(all(type(obj) is ModuleType for obj in external.values()))
        # Refuse both dotted and bare-stem cached aliases, including case aliases.
        forbidden = {name.casefold() for name in MODULES}
        forbidden.update(name.rsplit(".", 1)[-1].casefold() for name in MODULES)
        _need(not any(type(name) is str and name.casefold() in forbidden for name in tuple(sys.modules)))
        pin, open_source = backend.pin_parent, backend.open_source
        # Capture every owned callback before any target can execute.
        for path in ("", "infra"):
            obj = pin(path)
            close_original = obj.close
            try:
                resource = _Held(obj, trust.owner, True, close_original)
            except BaseException:
                # _Held may have failed before insertion; original close is still owed.
                close_original()
                raise
            held.append(resource)
        sources = []
        for _, path in BUNDLE:
            obj = open_source(path)
            close_original = obj.close
            try:
                resource = _Held(obj, trust.owner, False, close_original)
            except BaseException:
                close_original()
                raise
            held.append(resource)
            sources.append(resource)
        identities = [(r.original["volume"], r.original["file_id"]) for r in held]
        _need(len(set(identities)) == len(identities))
        payloads = []
        for resource, row in zip(sources, manifest["files"]):
            resource.recheck()
            _need(resource.original["size"] == row["size"])
            payload = resource.read_callback(row["size"] + 1)
            _need(type(payload) is bytes and len(payload) == row["size"])
            resource.recheck()
            _need(hashlib.sha256(payload).hexdigest() == row["sha256"])
            payloads.append(payload)
        for resource in held:
            resource.recheck()
        # Compile all only after all sources have passed, execute in frozen order.
        codes = [compile_owned(data, path, "exec", dont_inherit=True)
                 for data, (_, path) in zip(payloads, BUNDLE)]
        package = ModuleType("infra")

        def importer(name, globals=None, locals=None, fromlist=(), level=0):
            _need(level == 0 and type(name) is str)
            if name == "infra":
                _need(bool(fromlist))
                for member in fromlist:
                    full = "infra." + member
                    _need(full in modules)
                return package
            if name in MODULES:
                _need(name in modules)
                return modules[name] if fromlist else package
            _need(name in external)
            return external[name]

        base_builtins = dict(vars(builtins))
        base_builtins["__import__"] = importer
        for name, code in zip(MODULES, codes):
            for resource in held:
                resource.recheck()
            module = ModuleType(name)
            module.__dict__.update(__builtins__=dict(base_builtins), __package__="infra")
            exec_owned(code, module.__dict__)
            modules[name] = module
            setattr(package, name.rsplit(".", 1)[-1], module)
        for resource in held:
            resource.recheck()
        return LoadedBundle(modules, held)
    except BaseException:
        for resource in reversed(held):
            try:
                resource.close()
            except BaseException:
                pass
    raise Refused()
