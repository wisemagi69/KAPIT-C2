"""Fetch the pinned official Gradle distribution into this project's tool cache."""
from pathlib import Path
import hashlib
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "8.13"
SHA256 = "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78"
URL = f"https://services.gradle.org/distributions/gradle-{VERSION}-bin.zip"


def main():
    cache = ROOT / ".tooling"
    cache.mkdir(exist_ok=True)
    archive = cache / f"gradle-{VERSION}-bin.zip"
    if not archive.exists():
        partial = archive.with_suffix(".part")
        with urllib.request.urlopen(URL, timeout=60) as response, partial.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        if hashlib.file_digest(partial.open("rb"), "sha256").hexdigest() != SHA256:
            raise SystemExit("Official Gradle archive checksum mismatch; download preserved for inspection")
        partial.replace(archive)
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != SHA256:
            raise SystemExit("Pinned Gradle checksum mismatch")
    destination = cache / f"gradle-{VERSION}"
    if not (destination / "bin" / "gradle.bat").exists():
        with zipfile.ZipFile(archive) as bundle:
            for item in bundle.infolist():
                target = (cache / item.filename).resolve()
                if not target.is_relative_to(cache.resolve()) or (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SystemExit("Unsafe Gradle archive entry")
            bundle.extractall(cache)
    print(f"Verified Gradle {VERSION}; project-local distribution ready")


if __name__ == "__main__":
    main()

