"""Record cached Maven license declarations and checked-in artifact checksums."""
from pathlib import Path
import hashlib
import json
import os
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def main():
    cache = ROOT / ".gradle-user-home/caches/modules-2/files-2.1"
    if os.name == "nt":
        cache = Path("\\\\?\\" + str(cache.resolve()))
    poms = {}
    for path in cache.glob("*/*/*/*/*.pom"):
        coordinate = ":".join(path.parts[-5:-2])
        poms[coordinate] = (path, ET.parse(path).getroot())

    def field(element, name):
        child = element.find("{*}" + name)
        return child.text.strip() if child is not None and child.text else None

    def licenses(coordinate, seen=()):
        if coordinate in seen or coordinate not in poms:
            return [], None
        _, pom = poms[coordinate]
        declared = [{"name": field(item, "name"), "url": field(item, "url")}
            for item in pom.findall("{*}licenses/{*}license")]
        if declared:
            return declared, coordinate
        parent = pom.find("{*}parent")
        if parent is not None:
            parent_coordinate = ":".join(field(parent, key) or "" for key in ("groupId", "artifactId", "version"))
            return licenses(parent_coordinate, (*seen, coordinate))
        return [], None

    configurations = {}
    for line in (ROOT / "app/gradle.lockfile").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            coordinate, values = line.split("=", 1)
            configurations[coordinate] = values.split(",")
    metadata = ROOT / "gradle/verification-metadata.xml"
    components = []
    for component in ET.parse(metadata).getroot().findall("{*}components/{*}component"):
        coordinate = ":".join(component.attrib[key] for key in ("group", "name", "version"))
        declared, inherited_from = licenses(coordinate)
        artifacts = []
        for artifact in component.findall("{*}artifact"):
            hashes = [node.attrib["value"] for node in artifact.findall("{*}sha256")]
            artifacts.append({"name": artifact.attrib["name"], "sha256": hashes})
        entry = {"coordinate": coordinate, "licenses": declared,
            "license_metadata_coordinate": inherited_from,
            "license_status": "declared_in_cached_pom" if declared else "not_declared_in_cached_pom_chain",
            "demo_debug_runtime": "demoDebugRuntimeClasspath" in configurations.get(coordinate, []),
            "artifacts": artifacts}
        if coordinate in poms:
            entry["pom_sha256"] = hashlib.sha256(poms[coordinate][0].read_bytes()).hexdigest()
        components.append(entry)
    missing = [item["coordinate"] for item in components if not item["licenses"]]
    result = {"schema_version": 1,
        "scope": "Components from checked-in Gradle verification metadata; runtime marker comes from app dependency locks.",
        "provenance": "Declared Maven POM license metadata from Google Maven/Maven Central/plugin repositories; not an independent legal or source audit.",
        "checksum_basis": "SHA-256 values pinned after first resolution over official repository HTTPS; Gradle verifies subsequent builds. No PGP verification claimed.",
        "unresolved_license_metadata": missing,
        "components": sorted(components, key=lambda item: item["coordinate"])}
    output = ROOT / "dependency-inventory.json"
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"components": len(components), "unresolved_license_metadata": missing,
        "runtime_components": sum(item["demo_debug_runtime"] for item in components)}))


if __name__ == "__main__":
    main()
