"""Build the bundled offline area map from a one-time OpenStreetMap extract.

Input: .cache/maps/los-banos/raw.json (Overpass `out geom`, ODbL). Output:
web/src/map/los-banos-map.json. Geometry only: no external URLs, no report data.
Run: python tools/maps/build_area_map.py [--adjacency]
"""
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / ".cache/maps/los-banos/raw.json"
OUT = ROOT / "web/src/map/los-banos-map.json"
RAW_SHA256 = "75a930dc9a722d498dd02b26e08f9c8238135641933e04379dc0370c07fdc4ee"
WIDTH = 100.0
TOLERANCE = 0.12
# Demonstration assignment of the unchanged synthetic Area A/B/C contract to real barangays.
AREAS = {"area-a": "Batong Malake", "area-b": "Mayondon", "area-c": "Anos"}
ROAD_CLASSES = ("trunk", "primary", "secondary", "tertiary")


def rings(relation):
    """Join outer member ways end to end into closed rings."""
    pending = [[(p["lon"], p["lat"]) for p in m["geometry"]] for m in relation["members"]
               if m["type"] == "way" and m.get("role") in ("outer", "") and m.get("geometry")]
    result = []
    while pending:
        ring = pending.pop(0)
        while ring[0] != ring[-1]:
            for i, way in enumerate(pending):
                if way[0] == ring[-1]:
                    ring += way[1:]
                elif way[-1] == ring[-1]:
                    ring += way[::-1][1:]
                else:
                    continue
                pending.pop(i)
                break
            else:
                raise SystemExit("OPEN_RING " + relation["tags"].get("name", "?"))
        result.append(ring)
    return result


def simplify(points, tolerance):
    if len(points) < 3:
        return points
    (x1, y1), (x2, y2) = points[0], points[-1]
    dx, dy = x2 - x1, y2 - y1
    norm = math.hypot(dx, dy) or 1e-12
    index, distance = 0, -1.0
    for i in range(1, len(points) - 1):
        px, py = points[i]
        d = abs(dy * px - dx * py + x2 * y1 - y2 * x1) / norm if math.hypot(dx, dy) else math.hypot(px - x1, py - y1)
        if d > distance:
            index, distance = i, d
    if distance <= tolerance:
        return [points[0], points[-1]]
    return simplify(points[:index + 1], tolerance)[:-1] + simplify(points[index:], tolerance)


def path(points, closed):
    text = "M" + " L".join(f"{x:.1f} {y:.1f}" for x, y in points)
    return text + (" Z" if closed else "")


def centroid(ring):
    area = cx = cy = 0.0
    for (x1, y1), (x2, y2) in zip(ring, ring[1:]):
        cross = x1 * y2 - x2 * y1
        area += cross; cx += (x1 + x2) * cross; cy += (y1 + y2) * cross
    if abs(area) < 1e-12:
        return sum(p[0] for p in ring) / len(ring), sum(p[1] for p in ring) / len(ring)
    return cx / (3 * area), cy / (3 * area)


def main():
    raw = RAW.read_bytes()
    if hashlib.sha256(raw).hexdigest() != RAW_SHA256:
        raise SystemExit("RAW_EXTRACT_CHANGED")
    elements = json.loads(raw)["elements"]
    municipality = next(e for e in elements if e["type"] == "relation" and e["tags"].get("admin_level") == "6")
    barangays = sorted((e for e in elements if e["type"] == "relation" and e["tags"].get("admin_level") == "10"),
                       key=lambda e: e["tags"]["name"])
    outline = rings(municipality)
    # Frame the land barangays; the municipal boundary also covers open lake water.
    land = [p for b in barangays for r in rings(b) for p in r]
    pad = 0.004
    lons = [min(p[0] for p in land) - pad, max(p[0] for p in land) + pad]
    lats = [min(p[1] for p in land) - pad, max(p[1] for p in land) + pad]
    lat0 = (min(lats) + max(lats)) / 2
    kx = math.cos(math.radians(lat0))
    span_x = (max(lons) - min(lons)) * kx
    scale = WIDTH / span_x
    height = round((max(lats) - min(lats)) * scale, 1)

    def project(points):
        return [((lon - min(lons)) * kx * scale, (max(lats) - lat) * scale) for lon, lat in points]

    if "--adjacency" in sys.argv:
        vertices = {b["tags"]["name"]: {p for r in rings(b) for p in r} for b in barangays}
        for name, own in vertices.items():
            print(name, "->", sorted(other for other, theirs in vertices.items() if other != name and len(own & theirs) > 2))
        return

    out_barangays = []
    for b in barangays:
        projected = [project(r) for r in rings(b)]
        main_ring = max(projected, key=len)
        ax, ay = centroid(main_ring)
        out_barangays.append({"name": b["tags"]["name"],
                              "path": " ".join(path(simplify(r, TOLERANCE), True) for r in projected),
                              "anchor": {"x": round(ax, 1), "y": round(ay, 1)}})
    names = {b["name"] for b in out_barangays}
    if not set(AREAS.values()) <= names:
        raise SystemExit("AREA_BARANGAY_MISSING")
    roads = [{"class": e["tags"]["highway"], "path": path(simplify(project([(p["lon"], p["lat"]) for p in e["geometry"]]), TOLERANCE), False)}
             for e in elements if e["type"] == "way" and e["tags"].get("highway") in ROAD_CLASSES]
    rivers = [path(simplify(project([(p["lon"], p["lat"]) for p in e["geometry"]]), TOLERANCE), False)
              for e in elements if e["type"] == "way" and e["tags"].get("waterway") == "river"]
    document = {
        "place": "Los Baños, Laguna, Philippines",
        "source": "OpenStreetMap",
        "license": "ODbL 1.0",
        "attribution": "© OpenStreetMap contributors",
        "extract_sha256": RAW_SHA256,
        "approval": "ai/reports/event-map-area-approval.md",
        "viewBox": [WIDTH, height],
        "municipality": " ".join(path(simplify(r, TOLERANCE), True) for r in (project(r) for r in outline)),
        "barangays": out_barangays,
        "roads": sorted(roads, key=lambda r: ROAD_CLASSES.index(r["class"]), reverse=True),
        "rivers": rivers,
        "areas": [{"area_id": area_id, "label": "Area " + area_id[-1].upper(), "barangay": name} for area_id, name in AREAS.items()],
    }
    text = json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n"
    OUT.write_text(text, encoding="utf-8")
    print(f"{OUT.relative_to(ROOT)} {len(text.encode())} bytes, {len(out_barangays)} barangays, {len(roads)} roads, {len(rivers)} rivers")


if __name__ == "__main__":
    main()
