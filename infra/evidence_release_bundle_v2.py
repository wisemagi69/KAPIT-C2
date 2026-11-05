"""Versioned public-library loader; production unconditionally closed.

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
        super().__init__("RELEASE_BUNDLE_V2_REFUSED")


BUNDLE = (
    ("schemas", "infra/evidence_release_schemas.py"),
    ("bridge", "infra/evidence_release_bridge.py"),
    ("lifecycle", "infra/evidence_release_lifecycle.py"),
    ("reservations", "infra/evidence_release_reservations.py"),
    ("detection_controls", "infra/evidence_detection_controls.py"),
)
MODULES = tuple(path[:-3].replace("/", ".") for _, path in BUNDLE)
EXTERNAL_NAMES = frozenset(("dataclasses", "datetime", "hashlib", "json", "re",
    "functools", "cryptography.hazmat.primitives.asymmetric.ed25519", "os",
    "pathlib", "time", "types", "math", "ctypes", "ctypes.wintypes", "ntpath", "enum"))
MAX_SOURCE = 1048576
MAX_MANIFEST = 8192
DOMAIN = b"KAPIT-C2/PUBLIC-LIBRARY-BUNDLE/V2\x00"
NAMESPACE = "_kapit_release_bundle_v2"
OWNED_NAMES = (NAMESPACE,) + tuple(NAMESPACE + "." + name.rsplit(".", 1)[-1] for name in MODULES)
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
        _need(value["scope"] == "PUBLIC_LIBRARY_BUNDLE_V2" and type(value["version"]) is int and value["version"] == 2)
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


def _target_alias(name):
    if type(name) is not str:
        return False
    folded = name.casefold()
    return (folded == NAMESPACE.casefold() or folded.startswith(NAMESPACE.casefold() + ".")
            or folded in {n.casefold() for n in MODULES}
            or folded in {n.rsplit(".", 1)[-1].casefold() for n in MODULES})


class LoadedBundle:
    """Owned module registrations and source handles; never execution authority."""
    def __init__(self, modules, held, registry, registrations):
        self.modules = MappingProxyType(dict(modules))
        self._held = tuple(held)
        self._registry = registry
        self._registrations = dict(registrations)
        self._failed = self._closed = False

    def recheck(self):
        try:
            _need(not self._failed)
            self._check()
        except BaseException:
            self._failed = True
            raise Refused() from None

    def _check(self):
        _need(sys.modules is self._registry)
        actual = {k: v for k, v in tuple(self._registry.items()) if _target_alias(k)}
        _need(set(actual) == set(self._registrations))
        _need(all(actual[k] is v for k, v in self._registrations.items()))
        if self._registrations:
            package = self._registrations[NAMESPACE]
            _need(all(getattr(package, name.rsplit(".", 1)[-1], None) is module
                      for name, module in self._registrations.items() if name != NAMESPACE))
        for resource in self._held:
            resource.recheck()

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                self.recheck()
            except BaseException:
                self._failed = True
            # Never adopt, delete or restore another party's replacement.
            for name, original in reversed(tuple(self._registrations.items())):
                if self._registry.get(name) is original:
                    del self._registry[name]
                else:
                    self._failed = True
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
    raise Refused()


def load_synthetic_bundle(backend, raw, signature, *, trust, now_utc, expected_nonce,
                          trusted_external):
    """Authenticated library initialization, not a sandbox or platform qualification.

    All external dependencies, this loader, interpreter and backend are admitted
    trusted base. No default importer, sys.path search or cached target is used.
    """
    manifest = verify_manifest(raw, signature, trust=trust, now_utc=now_utc,
                               expected_nonce=expected_nonce)
    held, registrations, modules = [], {}, {}
    registry = sys.modules
    compile_owned, exec_owned = _COMPILE, _EXEC
    loaded = LoadedBundle(modules, held, registry, registrations)
    try:
        _need(type(registry) is dict)
        _need(not any(_target_alias(name) for name in tuple(registry)))
        _need(type(trusted_external) is dict and set(trusted_external) <= EXTERNAL_NAMES)
        external = dict(trusted_external)
        _need(all(type(obj) is ModuleType for obj in external.values()))
        pin, open_source = backend.pin_parent, backend.open_source
        for directory, paths in ((True, ("", "infra")), (False, tuple(p for _, p in BUNDLE))):
            for path in paths:
                obj = pin(path) if directory else open_source(path)
                original_close = obj.close
                try:
                    resource = _Held(obj, trust.owner, directory, original_close)
                except BaseException:
                    original_close()
                    raise
                held.append(resource)
        identities = [(r.original["volume"], r.original["file_id"]) for r in held]
        _need(len(set(identities)) == len(identities))
        payloads = []
        for resource, row in zip(held[2:], manifest["files"]):
            resource.recheck()
            _need(resource.original["size"] == row["size"])
            payload = resource.read_callback(row["size"] + 1)
            _need(type(payload) is bytes and len(payload) == row["size"])
            resource.recheck()
            _need(hashlib.sha256(payload).hexdigest() == row["sha256"])
            payloads.append(payload)
        for resource in held:
            resource.recheck()
        codes = [compile_owned(data, path, "exec", dont_inherit=True)
                 for data, (_, path) in zip(payloads, BUNDLE)]
        _need(sys.modules is registry and not any(_target_alias(n) for n in tuple(registry)))
        package = ModuleType(NAMESPACE)
        package.__package__, package.__path__ = NAMESPACE, []
        registrations[NAMESPACE] = package
        for old_name, owned_name in zip(MODULES, OWNED_NAMES[1:]):
            module = ModuleType(owned_name)
            module.__package__ = NAMESPACE
            registrations[owned_name] = module
            setattr(package, old_name.rsplit(".", 1)[-1], module)
        registry.update(registrations)
        loaded = LoadedBundle(modules, held, registry, registrations)

        def importer(name, globals=None, locals=None, fromlist=(), level=0):
            _need(not loaded._closed)
            loaded.recheck()
            _need(level == 0 and type(name) is str)
            if name == "infra":
                _need(bool(fromlist) and all("infra." + m in modules for m in fromlist))
                return package
            if name in MODULES:
                _need(name in modules)
                return modules[name] if fromlist else package
            _need(name in external)
            return external[name]

        base = dict(vars(builtins))
        base["__import__"] = importer
        for name, owned_name, code in zip(MODULES, OWNED_NAMES[1:], codes):
            loaded.recheck()
            module = registrations[owned_name]
            module.__dict__["__builtins__"] = dict(base)
            exec_owned(code, module.__dict__)
            modules[name] = module
        loaded.recheck()
        loaded.modules = MappingProxyType(dict(modules))
        return loaded
    except BaseException:
        # Include handles acquired before the namespace was installed.
        loaded._held = tuple(held)
        try:
            loaded.close()
        except BaseException:
            pass
    raise Refused()


class _SmokeSource:
    def __init__(self, path, directory, serial, owner):
        self.path, self.directory, self.serial, self.owner = path, directory, serial, owner
        _need(not path.is_symlink())
        self.stream = None if directory else path.open("rb")
        try:
            self.original = self._stat()
        except BaseException:
            if self.stream is not None:
                self.stream.close()
            raise

    def _stat(self):
        import os
        st = self.path.stat() if self.directory else os.fstat(self.stream.fileno())
        return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)

    def identity(self):
        _need(not self.path.is_symlink() and self._stat() == self.original)
        _need(self.path.stat().st_ino == self.original[1])
        return dict(volume=1, file_id=f"{self.serial:032x}",
                    attributes=16 if self.directory else 0, links=1,
                    size=0 if self.directory else self.original[2], disk=True,
                    private=False, owner=self.owner)

    def read(self, maximum):
        self.stream.seek(0)
        return self.stream.read(maximum)

    def close(self):
        if self.stream is not None:
            self.stream.close()


def _public_library_smoke():
    """Finite root-only actual public definitions check; NOT protected OS proof.

    Parent directories are stat snapshots, source files ordinary read-only Python
    handles. Identity fields are a portable smoke model, not Win32 admission.
    Ephemeral signing proves protocol compatibility, never external authority.
    """
    import importlib
    import os
    from pathlib import Path
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    root = Path(__file__).resolve().parent.parent
    owner = "public-smoke-model-owner"

    class Backend:
        def pin_parent(self, path):
            _need(path in ("", "infra"))
            return _SmokeSource(root / path, True, 1 if not path else 2, owner)

        def open_source(self, path):
            _need(path in tuple(p for _, p in BUNDLE))
            return _SmokeSource(root / path, False, 3 + tuple(p for _, p in BUNDLE).index(path), owner)

    external = {name: importlib.import_module(name) for name in EXTERNAL_NAMES}
    key = Ed25519PrivateKey.generate()
    trust = OfflineTrust("smoke-key", key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
                         "smoke-policy", "smoke-authority", owner)
    files = []
    for logical, path in BUNDLE:
        with (root / path).open("rb") as stream:
            payload = stream.read(MAX_SOURCE + 1)
        _need(1 <= len(payload) <= MAX_SOURCE)
        files.append(dict(id=logical, path=path, size=len(payload), sha256=hashlib.sha256(payload).hexdigest()))
    raw = canonical(dict(scope="PUBLIC_LIBRARY_BUNDLE_V2", version=2,
        key_id=trust.key_id, policy=trust.policy, authority=trust.authority, nonce="1" * 32,
        issued_utc="2026-10-24T00:00:00Z", expires_utc="2026-10-24T00:05:00Z", files=files))
    before = {n: v for n, v in tuple(sys.modules.items()) if _target_alias(n)}
    loaded = load_synthetic_bundle(Backend(), raw, key.sign(DOMAIN + raw), trust=trust,
        now_utc="2026-10-24T00:00:01Z", expected_nonce="1" * 32, trusted_external=external)
    try:
        schemas, bridge, lifecycle, reservations, parser = (loaded.modules[n] for n in MODULES)
        _need(bridge.Refused is schemas.Refused and lifecycle.Refused is schemas.Refused)
        _need(lifecycle.ModelAdmission is bridge.ModelAdmission)
        for module, symbol in ((schemas, "Refused"), (bridge, "ModelAdmission"),
                               (parser, "DetectionObservation"), (parser, "Comparison")):
            _need(getattr(module, symbol).__module__ == module.__name__)
            _need(sys.modules[module.__name__] is module)
        _need(callable(reservations.production_open))
        loaded.recheck()
    finally:
        loaded.close()
    _need({n: v for n, v in tuple(sys.modules.items()) if _target_alias(n)} == before)
    return {"status": "PUBLIC_LIBRARY_DEFINITIONS_ONLY_PASS", "modules": 5,
            "namespace_restored": True, "production_enabled": False,
            "platform_qualified": False, "runtime_functions_called": 0}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        _need(type(args) is list and args == ["--public-library-smoke"])
        result = _public_library_smoke()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except BaseException:
        print('{"status":"PUBLIC_LIBRARY_SMOKE_REFUSED"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


