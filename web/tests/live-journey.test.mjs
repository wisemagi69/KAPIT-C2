import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { assertRecipientBody, assertRecipientIdentity, safeFailure, validateInput } from './live-journey.mjs';

const valid = { url: 'http://127.0.0.1:43123', channel_id: '11111111-1111-4111-8111-111111111111' };
test('exact loopback input is accepted', () => assert.deepEqual(validateInput(valid), valid));
test('remote, credentials, redirect paths and unexpected schemes are refused', () => {
  for (const url of ['https://127.0.0.1:43123', 'http://localhost:43123', 'http://example.org:43123', 'http://127.0.0.1', 'http://127.0.0.1:80', 'http://user:password@127.0.0.1:43123', valid.url + '/api', valid.url + '/?redirect=remote', valid.url + '/#secret']) assert.throws(() => validateInput({ ...valid, url }));
});
test('unexpected fields or arbitrary IDs are refused', () => {
  for (const value of [null, [], { ...valid, password: 'secret' }, { ...valid, channel_id: '../private' }, { url: valid.url }]) assert.throws(() => validateInput(value));
});
test('authenticated recipient must match the disposable fixture channel before mutations', () => {
  const identity = { user: { role: 'recipient', channel: { id: valid.channel_id } } };
  assert.doesNotThrow(() => assertRecipientIdentity(identity, valid.channel_id));
  for (const value of [null, {}, { user: { role: 'recipient', channel: null } }, { user: { role: 'reviewer', channel: { id: valid.channel_id } } }, { user: { role: 'recipient', channel: { id: '22222222-2222-4222-8222-222222222222' } } }]) assert.throws(() => assertRecipientIdentity(value, valid.channel_id));
});
test('recipient projection scan accepts only absence of private canaries and fields', () => {
  assertRecipientBody({ projection: { title: 'Water maintenance', text: 'Repair assistance requested.' } });
  for (const value of [{ projection: { text: 'PRIVATE_LIVE_NARRATIVE' } }, { reporter_label: 'private' }, { nested: { variant_id: 'hidden' } }, { report_id: 'hidden' }, { source_digest: 'hidden' }, { author_id: 'hidden' }, { submitted_by_id: 'hidden' }]) assert.throws(() => assertRecipientBody(value));
});
test('error output is restricted to known stage labels', () => {
  assert.deepEqual(safeFailure('PASSWORD'), { ok: false, stage: 'PASSWORD' });
  assert.deepEqual(safeFailure('private secret'), { ok: false, stage: 'INPUT' });
});
test('CLI rejects an inherited-style URL argument before browser launch', () => {
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('./live-journey.mjs', import.meta.url)), 'http://remote.invalid'], { input: JSON.stringify(valid), encoding: 'utf8', timeout: 5000 });
  assert.equal(child.status, 1); assert.deepEqual(JSON.parse(child.stdout), { ok: false, stage: 'INPUT' }); assert.equal(child.stderr, '');
});
test('CLI rejects malformed and oversized stdin without reflecting contents', () => {
  for (const input of ['private secret', 'private secret'.repeat(1000)]) {
    const child = spawnSync(process.execPath, [fileURLToPath(new URL('./live-journey.mjs', import.meta.url))], { input, encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 1); assert.deepEqual(JSON.parse(child.stdout), { ok: false, stage: 'INPUT' }); assert.equal(child.stderr, '');
  }
});
