import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { accessSignature, allowedProfiles, mapMatchesCount, projectionObserved, publishedLabel, recipientGrants, validateFeedFilters } from '../src/domain.ts';

const fixture = name => JSON.parse(readFileSync(new URL(`../../contracts/m3/${name}`, import.meta.url), 'utf8'));
const channel = { id: 'channel-1', code: 'CH-DEMO-01', name: 'Fictional channel' };
const legacy = { id: 'person', role: 'recipient', username: 'recipient', display_name: 'Synthetic recipient', unit: null, channel, profile: 'DEMO-REDUCED' };

test('legacy optional contexts remain usable while explicit empty grants fail closed', () => {
  assert.deepEqual(recipientGrants(legacy), [{ channel, profile_ceiling: 'DEMO-REDUCED' }]);
  assert.deepEqual(recipientGrants({ ...legacy, grants: [] }), []);
  assert.deepEqual(recipientGrants({ ...legacy, grants: [{ channel, profile_ceiling: 'constructor' }] }), []);
});
test('offered profiles obey the frozen rank and never raise a ceiling', () => {
  const { rank } = fixture('profiles.json');
  for (const ceiling of Object.keys(rank)) assert.deepEqual(allowedProfiles(ceiling), Object.keys(rank).filter(profile => rank[profile] <= rank[ceiling]).sort((a, b) => rank[b] - rank[a]));
  for (const invalid of ['__proto__', 'UNKNOWN', null]) assert.deepEqual(allowedProfiles(invalid), []);
});
test('session comparison detects grant revocation and ceiling changes independent of ordering', () => {
  const expanded = { ...legacy, grants: [{ channel, profile_ceiling: 'DEMO-REDUCED' }, { channel: { ...channel, id: 'channel-2' }, profile_ceiling: 'DEMO-SUMMARY' }] };
  assert.equal(accessSignature(expanded), accessSignature({ ...expanded, grants: [...expanded.grants].reverse() }));
  assert.notEqual(accessSignature(expanded), accessSignature({ ...expanded, grants: [] }));
  assert.notEqual(accessSignature(expanded), accessSignature({ ...expanded, grants: [{ channel, profile_ceiling: 'DEMO-FULL' }] }));
});
test('each profile consumes its exact frozen observed precision', () => {
  const { expected } = fixture('profiles.json');
  for (const projections of Object.values(expected)) {
    assert.match(projectionObserved(projections['DEMO-SUMMARY']), /^\d{4}-W\d{2}$/);
    assert.ok(projectionObserved(projections['DEMO-FULL']));
    assert.ok(projectionObserved(projections['DEMO-REDUCED']));
  }
  assert.match(publishedLabel('2026-10-19T00:00:00Z', 'DEMO-SUMMARY'), /^Week of /);
});
test('local map geometry is byte-for-value identical to the frozen abstract assets', () => {
  const local = JSON.parse(readFileSync(new URL('../src/map/fictional-areas.json', import.meta.url), 'utf8'));
  assert.deepEqual(local, fixture('map-areas.json').areas);
  assert.ok(!JSON.stringify(local).includes('http'));
});
test('bundled real-area map keeps the Area A/B/C contract, OSM attribution and no external references', () => {
  const real = JSON.parse(readFileSync(new URL('../src/map/los-banos-map.json', import.meta.url), 'utf8'));
  assert.deepEqual(real.areas.map(area => [area.area_id, area.label]), fixture('map-areas.json').areas.map(area => [area.area_id, area.label]));
  assert.equal(real.attribution, '© OpenStreetMap contributors');
  for (const area of real.areas) assert.ok(real.barangays.some(barangay => barangay.name === area.barangay));
  assert.ok(!/https?:|\/\/|www\./.test(JSON.stringify(real)));
  assert.ok(!/lat|lon|coordinates/i.test(Object.keys(real).join(' ')));
});
test('map/list parity rejects hidden areas, duplicates, negatives, invalid counts and inconsistent totals', () => {
  assert.equal(mapMatchesCount(fixture('map-areas.json').map_response, 1), true);
  assert.equal(mapMatchesCount(fixture('map-areas.json').summary_profile_map_response, 1), true);
  for (const map of [{ areas: [{ area_id: 'hidden', count: 1 }], unmapped: 0 }, { areas: [{ area_id: 'area-a', count: -1 }], unmapped: 2 }, { areas: [{ area_id: 'area-a', count: 1 }, { area_id: 'area-a', count: 0 }], unmapped: 0 }, { areas: [], unmapped: NaN }, { areas: [], unmapped: 0 }]) assert.equal(mapMatchesCount(map, 1), false);
});
test('summary area filters and unknown profiles fail before request submission', () => {
  const base = { q: '', category: 'ALL', urgency: 'ALL' };
  assert.ok(validateFeedFilters({ ...base, profile: 'DEMO-SUMMARY', area: 'Area A' }));
  assert.ok(validateFeedFilters({ ...base, profile: 'UNKNOWN' }));
  assert.ok(validateFeedFilters({ ...base, area: 'Private place' }));
  assert.equal(validateFeedFilters({ ...base, profile: 'DEMO-SUMMARY' }), '');
});
