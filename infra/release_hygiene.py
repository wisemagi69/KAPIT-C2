"""B3 release hygiene: offline SBOM from the committed locks, and a secret scan of shipped source.

Reads only lock files and source text. Prints counts and finding locations, never matched values.
A finding is evidence for review, not proof of exposure; licence fields are declared metadata,
not legal clearance.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
PYTHON_LOCK = ROOT / "backend/requirements-lock-cp314-win_amd64.txt"
WEB_LOCK = ROOT / "web/package-lock.json"
SHIPPED = ("backend", "web/src", "web/public", "web/index.html", "web/dist", "infra", "android/app/src", "android/app/build.gradle.kts",
           "android/build.gradle.kts", "android/settings.gradle.kts", "android/gradle.properties", "tools", "docs", "README.md")
SKIP_PARTS = {"__pycache__", "node_modules", ".tooling", ".gradle"}
TEXT_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".mjs", ".json", ".md", ".html", ".css", ".kt", ".kts", ".xml", ".txt", ".cmd", ".ps1", ".toml", ".yaml", ".yml", ".env",
                 ".properties", ".gradle", ".ini", ".cfg", ".pem", ".key", ".sh", ".bat", ".conf"}
PATTERNS = {
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b"),
    "generic_api_key": re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"),
    "supabase_service_jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
    "integration_key": re.compile(r"\bkapit_ic_[a-z0-9]{8}_[A-Za-z0-9_-]{43}\b"),
    # Also matches KAPIT_SECRET_KEY=..., JSON "KAPIT_DB_PASSWORD": "..." and unquoted .env values.
    "assigned_secret": re.compile(r"(?i)(?<![A-Za-z0-9])(?:secret_key|db_password|source_key|api_key|password|passwd)[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9_+/=-]{20,}"),
}
# Public synthetic fixture credentials that tests and docs intentionally contain.
KNOWN_FIXTURE = re.compile(r"DemoMaintenance!2026|([A-Za-z0-9])\1{30,}")


def python_components():
    rows = []
    for line in PYTHON_LOCK.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9_.\[\]-]+)==([^\s]+)\s+--hash=sha256:([0-9a-f]{64})", line)
        if match:
            name = re.sub(r"\[.*\]", "", match.group(1))
            rows.append({"type": "library", "name": name, "version": match.group(2), "purl": f"pkg:pypi/{name.lower()}@{match.group(2)}",
                         "hashes": [{"alg": "SHA-256", "content": match.group(3)}], "scope": "required"})
    return rows


def web_components():
    rows = []
    for key, value in json.loads(WEB_LOCK.read_text(encoding="utf-8"))["packages"].items():
        if not key:
            continue
        name = key.split("node_modules/")[-1]
        row = {"type": "library", "name": name, "version": value.get("version"), "purl": f"pkg:npm/{name}@{value.get('version')}",
               "scope": "excluded" if value.get("dev") else "required"}
        if value.get("license"):
            row["licenses"] = [{"license": {"id": value["license"]}}]
        if value.get("integrity"):
            alg, _, digest = value["integrity"].partition("-")
            row["hashes"] = [{"alg": alg.upper().replace("SHA", "SHA-"), "content": digest}]
        rows.append(row)
    return rows


def sbom():
    components = python_components() + web_components()
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                         "component": {"type": "application", "name": "KAPIT-C2"},
                         "properties": [{"name": "kapit:sources", "value": "backend/requirements-lock-cp314-win_amd64.txt; web/package-lock.json"},
                                        {"name": "kapit:not-covered", "value": "Android Gradle dependencies, PostgreSQL binaries, bundled map data; licence fields are declared metadata only"}]},
            "components": components}


def shipped_files(skipped):
    for entry in SHIPPED:
        path = ROOT / entry
        candidates = [path] if path.is_file() else path.rglob("*") if path.is_dir() else []
        for item in candidates:
            if not item.is_file() or set(item.relative_to(ROOT).parts) & SKIP_PARTS:
                continue
            if item.suffix.lower() not in TEXT_SUFFIXES and item.name != ".env":
                skipped["not_text"] += 1
            elif item.stat().st_size > 2_000_000:
                skipped["over_2mb"] += 1
            else:
                yield item


def secret_scan():
    findings, scanned, skipped = [], 0, {"not_text": 0, "over_2mb": 0, "undecodable": 0}
    for path in shipped_files(skipped):
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            skipped["undecodable"] += 1
            continue
        scanned += 1
        for number, line in enumerate(text.splitlines(), 1):
            for name, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    if KNOWN_FIXTURE.search(match.group(0)):
                        continue
                    relative = path.relative_to(ROOT)
                    findings.append({"file": relative.as_posix(), "line": number, "pattern": name,
                                     "in_test": "tests" in relative.parts or relative.name.startswith("test_"),
                                     "value_sha256_prefix": hashlib.sha256(match.group(0).encode()).hexdigest()[:12]})
    return {"files_scanned": scanned, "skipped": skipped, "findings": findings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", type=Path, help="write the CycloneDX SBOM to this new file")
    args = parser.parse_args(argv)
    result = {"secret_scan": secret_scan()}
    if args.sbom:
        if args.sbom.exists():
            raise SystemExit("Refusing to overwrite an existing SBOM file.")
        document = sbom()
        args.sbom.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        counts = {"python": sum(c["purl"].startswith("pkg:pypi") for c in document["components"]),
                  "web_required": sum(c["purl"].startswith("pkg:npm") and c["scope"] == "required" for c in document["components"]),
                  "web_development": sum(c["purl"].startswith("pkg:npm") and c["scope"] == "excluded" for c in document["components"])}
        result["sbom"] = {"file": args.sbom.as_posix(), "components": counts}
    print(json.dumps(result, indent=2))
    # Test-file findings are listed for human review but do not fail the gate; anything else does.
    return 1 if any(not row["in_test"] for row in result["secret_scan"]["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())
