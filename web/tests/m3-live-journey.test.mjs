import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { assertGates, assertParity, assertSafeBody, CANARIES, GATES, JOURNEY_TIMEOUT_MS, safeFailure, validateInput } from './m3-live-journey.mjs';

const id = n => `11111111-1111-4111-8111-${String(n).padStart(12, '0')}`;
const valid = { url: 'http://127.0.0.1:43123', channel_ids: [id(1), id(2), id(3)], unit_ids: [id(4), id(5), id(6)], policy_ids: [id(7), id(8)] };
test('M3 input accepts only exact disposable loopback identity and copies its arrays', () => {
  const parsed = validateInput(valid); assert.deepEqual(parsed, valid); assert.notEqual(parsed.channel_ids, valid.channel_ids);
});
test('M3 input rejects remote hosts, credentials, paths, fragments and alternate URL spellings', () => {
  for (const url of ['https://127.0.0.1:43123', 'http://localhost:43123', 'http://127.0.0.1.evil:43123', 'http://example.org:43123', 'http://127.0.0.1:80', 'http://127.0.0.1', valid.url + '/', valid.url + '/workspace', valid.url + '?secret=canary', valid.url + '#canary', 'http://user:password@127.0.0.1:43123']) assert.throws(() => validateInput({ ...valid, url }));
});
test('M3 input rejects unknown fields, incomplete topology, duplicate and cross-kind IDs', () => {
  for (const value of [null, [], { ...valid, password: 'canary' }, { ...valid, unit_ids: [id(4)] }, { ...valid, policy_ids: [id(7), id(7)] }, { ...valid, channel_ids: [id(1), id(2), '../secret'] }, { ...valid, unit_ids: valid.channel_ids }]) assert.throws(() => validateInput(value));
});
test('seven gates have fixed order and an independent bounded deadline', () => {
  assertGates(['m3_review', 'm3_isolation', 'm3_recipients', 'm3_correction', 'm3_withdrawal', 'm3_policy', 'm3_integration']);
  assert.throws(() => assertGates([...GATES].reverse())); assert.throws(() => assertGates(GATES.slice(1)));
  assert.equal(JOURNEY_TIMEOUT_MS, 330000);
});
test('private reason/source canaries and nested private fields fail disclosure scan', () => {
  assertSafeBody({ results: [{ projection: { text: 'Fictional maintenance support.', profile: 'DEMO-SUMMARY' } }] });
  for (const canary of CANARIES) assert.throws(() => assertSafeBody({ nested: { value: canary } }));
  for (const field of ['correction_reason', 'payload_ciphertext', 'variant_id', 'report_id', 'revision_id', 'scope_context_hash', 'policy_epoch', 'reporter_label', 'site_label', 'narrative']) assert.throws(() => assertSafeBody({ nested: { [field]: 'withheld' } }));
});
test('map/count/summary parity rejects inconsistent counts and duplicate result IDs', () => {
  const feed = { count: 1, results: [{ id: id(1) }], summary: { by_category: { WATER_SUPPLY: 1 } } };
  assertParity(feed, { areas: [{ area_id: 'area-a', count: 1 }], unmapped: 0 });
  assert.throws(() => assertParity(feed, { areas: [], unmapped: 0 }));
  assert.throws(() => assertParity({ ...feed, summary: { by_category: {} } }, { areas: [], unmapped: 1 }));
  assert.throws(() => assertParity({ ...feed, count: 2, results: [feed.results[0], feed.results[0]], summary: { by_category: { WATER_SUPPLY: 2 } } }, { areas: [], unmapped: 2 }));
});
test('failure output is fixed stage metadata only', () => {
  assert.deepEqual(safeFailure('POLICY'), { ok: false, stage: 'POLICY' });
  assert.deepEqual(safeFailure('PRIVATE_KEY_CANARY'), { ok: false, stage: 'INPUT' });
});
test('CLI rejects argv override and oversized/malformed stdin before Chromium import', () => {
  const script = fileURLToPath(new URL('./m3-live-journey.mjs', import.meta.url));
  for (const [args, input] of [[[script, 'http://remote.invalid'], JSON.stringify(valid)], [[script], 'PRIVATE_INPUT_CANARY'], [[script], 'x'.repeat(4097)]]) {
    const child = spawnSync(process.execPath, args, { input, encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 1); assert.equal(child.stderr, ''); assert.deepEqual(JSON.parse(child.stdout), { ok: false, stage: 'INPUT' });
  }
});
test('live script has no response fixtures or authentication injection and delegates reference reader', () => {
  const source = readFileSync(new URL('./m3-live-journey.mjs', import.meta.url), 'utf8');
  assert.ok(!source.includes('.fulfill(')); assert.ok(!source.includes('force_authenticate')); assert.ok(!source.includes('storageState:'));
  assert.ok(source.includes("route.continue()")); assert.ok(source.includes("route.abort()"));
  assert.ok(source.includes('clients/kapit_feed.py')); assert.ok(source.includes("serviceWorkers: 'block'"));
});
