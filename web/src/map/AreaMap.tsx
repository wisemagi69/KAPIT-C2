import type { Area, MapCounts } from '../types';
import map from './los-banos-map.json';

// Bundled OpenStreetMap geometry (ODbL); the synthetic Area A/B/C contract is unchanged. No runtime network access.
export default function AreaMap({ counts, selected, onArea }: { counts: MapCounts; selected?: Area | 'ALL'; onArea: (area: Area) => void }) {
  const count = (id: string) => counts.areas.find(area => area.area_id === id)?.count ?? 0;
  const assigned = new Map(map.areas.map(area => [area.barangay, area]));
  const [width, height] = map.viewBox;
  return <section className="card area-map" aria-label="Area map"><h3>Maintenance areas · {map.place}</h3><p>Reporting areas on a real map. Counts cover the same current filters as the list and never show report locations.</p>
    <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Map of Los Baños showing Areas A, B and C"><title>Areas A, B and C in {map.place}</title>
      <path className="area-map-outline" d={map.municipality} />
      {map.barangays.map(barangay => {
        const area = assigned.get(barangay.name);
        return <path key={barangay.name} className={area ? 'area-map-area' + (selected === area.label ? ' map-selected' : '') : 'area-map-barangay'} d={barangay.path} />;
      })}
      {map.rivers.map((d, index) => <path key={'river-' + index} className="area-map-river" d={d} />)}
      {map.roads.map((road, index) => <path key={'road-' + index} className={'area-map-road area-map-' + road.class} d={road.path} />)}
      {map.barangays.filter(barangay => assigned.has(barangay.name)).map(barangay => {
        const area = assigned.get(barangay.name)!;
        return <g key={'label-' + area.area_id} className="area-map-label"><text x={barangay.anchor.x} y={barangay.anchor.y}>{area.label}</text><text x={barangay.anchor.x} y={barangay.anchor.y + 4.5}>{count(area.area_id)}</text></g>;
      })}
    </svg>
    <table><caption>Area counts and filters</caption><thead><tr><th>Area</th><th>Barangay</th><th>Matching publications</th></tr></thead><tbody>{map.areas.map(area => <tr key={area.area_id}><th><button className="text-button" aria-pressed={selected === area.label} onClick={() => onArea(area.label as Area)}>Filter {area.label}</button></th><td>{area.barangay}</td><td>{count(area.area_id)}</td></tr>)}</tbody></table><p>Without a map area: {counts.unmapped}</p>
    <p className="area-map-attribution">Map data {map.attribution}, {map.license}. Bundled offline.</p>
  </section>;
}
