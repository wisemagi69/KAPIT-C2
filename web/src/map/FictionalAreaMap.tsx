import type { Area, MapCounts } from '../types';
import areas from './fictional-areas.json';

export default function FictionalAreaMap({ counts, selected, onArea }: { counts: MapCounts; selected?: Area | 'ALL'; onArea: (area: Area) => void }) {
  const count = (id: string) => counts.areas.find(area => area.area_id === id)?.count ?? 0;
  return <section className="card fictional-map" aria-label="Fictional area map"><h3>Fictional maintenance areas</h3><p>Abstract demonstration geometry. Counts cover the same current filters as the list.</p>
    <svg viewBox="0 0 100 100" role="img" aria-label="Abstract diagram of Areas A, B and C"><title>Fictional areas, no real geography</title>{areas.map(area => <g key={area.area_id} className={selected === area.label ? 'map-selected' : ''}><path d={area.path} /><text x={area.anchor.x} y={area.anchor.y}>{area.label}</text><text x={area.anchor.x} y={area.anchor.y + 7}>{count(area.area_id)}</text></g>)}</svg>
    <table><caption>Area counts and filters</caption><thead><tr><th>Area</th><th>Matching publications</th></tr></thead><tbody>{areas.map(area => <tr key={area.area_id}><th><button className="text-button" aria-pressed={selected === area.label} onClick={() => onArea(area.label as Area)}>Filter {area.label}</button></th><td>{count(area.area_id)}</td></tr>)}</tbody></table><p>Without a map area: {counts.unmapped}</p>
  </section>;
}
