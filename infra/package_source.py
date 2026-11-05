"""Deterministic clean source package for a clean-machine replay (M5).

Packages the source tree minus exclusions that mirror the project's ignore rules
(.gitignore and android/.gitignore, hand-copied below), local tool settings and copied
scanner work binaries. It refuses symlinks and files whose names look secret-shaped
instead of silently skipping them. Detection is a filename deny-list, so the manifest
still needs a human look before a package leaves this host.
Writes a fixed-timestamp zip plus a SHA-256 manifest; never modifies the tree.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / ".cache/m5-package"
# Directory names excluded anywhere (ignore files plus generated caches).
EXCLUDED_NAMES = {".cache", "__pycache__", ".venv", "node_modules", ".gradle", ".gradle-user-home",
                  ".android-user-home", ".tooling", ".kotlin", "build", ".git", ".claude", ".vscode"}
# Root-relative POSIX path patterns excluded.
EXCLUDED_PATHS = ("web/dist", "web/dist/*", "web/test-results", "web/test-results/*", "web/playwright-report", "web/playwright-report/*",
                  "web/debug.log", "ai/state/private-scanner-postflight-pcre-work-*", "android/local.properties")
EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".pyd")
# Secret-shaped files are a hard failure, never a silent skip.
SECRET_PATTERNS = ("secrets.json", "*.jks", "*.keystore", ".env", ".env.*", "*.env", "pgpass", "*.pgpass", "*.pass", "id_rsa*", "*.pem",
                   "*.p12", "*.key", "*.dump")
ALLOWED_SECRET_NAMES = {".env.example"}
FIXED_TIME = (1980, 1, 1, 0, 0, 0)
# Content-screened runtime-area evidence that task records cite; carried only at its pinned hash.
EVIDENCE_EXPORTS = "ai/reports/m5-evidence-exports.json"


class PackageError(RuntimeError):
    pass


def excluded(relative: str, is_dir: bool) -> bool:
    name = relative.rsplit("/", 1)[-1]
    if is_dir and name in EXCLUDED_NAMES:
        return True
    if any(fnmatch.fnmatchcase(relative, pattern) for pattern in EXCLUDED_PATHS):
        return True
    return not is_dir and name.endswith(EXCLUDED_SUFFIXES)


def secret_shaped(name: str) -> bool:
    return name not in ALLOWED_SECRET_NAMES and any(fnmatch.fnmatchcase(name.lower(), pattern) for pattern in SECRET_PATTERNS)


def collect(root: Path = ROOT) -> list[str]:
    files = []
    for current, directories, names in os.walk(root):
        base = Path(current)
        kept = []
        for directory in sorted(directories):
            path = base / directory
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or os.path.isjunction(path):
                raise PackageError(f"LINK_REFUSED {relative}")
            if not excluded(relative, True):
                kept.append(directory)
        directories[:] = kept
        for name in sorted(names):
            path = base / name
            relative = path.relative_to(root).as_posix()
            if excluded(relative, False):
                continue
            if path.is_symlink():
                raise PackageError(f"LINK_REFUSED {relative}")
            if secret_shaped(name):
                raise PackageError(f"SECRET_SHAPED_FILE {relative}")
            files.append(relative)
    return sorted(files)


def evidence_exports(root: Path) -> list[str]:
    listing = root / EVIDENCE_EXPORTS
    if not listing.is_file():
        return []
    exports = []
    for item in json.loads(listing.read_text(encoding="utf-8"))["files"]:
        relative = item["path"]
        path = root / relative
        inside = path.resolve().is_relative_to(root.resolve()) and path.resolve() == (root.resolve() / relative)
        if (not relative.startswith((".cache/", "android/.tooling/")) or "\\" in relative or ".." in relative.split("/")
                or not inside or path.is_symlink() or not path.is_file()):
            raise PackageError(f"EVIDENCE_EXPORT_UNAVAILABLE {relative}")
        if secret_shaped(path.name):
            raise PackageError(f"SECRET_SHAPED_FILE {relative}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise PackageError(f"EVIDENCE_EXPORT_CHANGED {relative}")
        exports.append(relative)
    return exports


def build(root: Path = ROOT, output: Path = OUTPUT) -> dict:
    files = sorted(set(collect(root)) | set(evidence_exports(root)))
    output.mkdir(parents=True, exist_ok=True)
    archive = output / "kapit-c2-source.zip"
    entries = []
    partial = archive.with_suffix(".zip.partial")
    with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for relative in files:
            data = (root / relative).read_bytes()
            info = zipfile.ZipInfo(relative, date_time=FIXED_TIME)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data)
            entries.append({"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    partial.replace(archive)
    manifest = {"schema": 1, "archive": archive.name, "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "file_count": len(entries), "total_bytes": sum(item["bytes"] for item in entries), "files": entries}
    (output / "kapit-c2-source.manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return manifest


def verify(archive: Path, manifest_path: Path, destination: Path) -> dict:
    """Extract into an empty directory and check every file against the manifest."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if hashlib.sha256(archive.read_bytes()).hexdigest() != manifest["archive_sha256"]:
        raise PackageError("ARCHIVE_HASH_MISMATCH")
    if destination.exists() and any(destination.iterdir()):
        raise PackageError("DESTINATION_NOT_EMPTY")
    destination.mkdir(parents=True, exist_ok=True)
    expected = {item["path"]: item["sha256"] for item in manifest["files"]}
    with zipfile.ZipFile(archive) as bundle:
        names = bundle.namelist()
        if sorted(names) != sorted(expected):
            raise PackageError("ARCHIVE_ENTRY_MISMATCH")
        for name in names:
            target = (destination / name).resolve()
            if not target.is_relative_to(destination.resolve()):
                raise PackageError("ENTRY_ESCAPES_DESTINATION")
            data = bundle.read(name)
            if hashlib.sha256(data).hexdigest() != expected[name]:
                raise PackageError("ENTRY_HASH_MISMATCH")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    return {"verified_files": len(names), "destination": str(destination)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-into", type=Path, help="extract the built package into this empty directory and verify it")
    args = parser.parse_args(argv)
    try:
        if args.verify_into:
            result = verify(OUTPUT / "kapit-c2-source.zip", OUTPUT / "kapit-c2-source.manifest.json", args.verify_into)
        else:
            manifest = build()
            result = {key: manifest[key] for key in ("archive", "archive_sha256", "file_count", "total_bytes")}
    except PackageError as error:
        print(json.dumps({"ok": False, "code": str(error)}))
        return 2
    print(json.dumps({"ok": True, **result}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
