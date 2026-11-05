import test from 'node:test';
import assert from 'node:assert/strict';
import { ageLabel, createOperation, dateLabel, eligibleChannels, roleLabel, sharingExplanation, STATUS_LABELS, validateAccount, validateCorrectionReason, validateFeedFilters, validatePasswordChange, validatePayload, validateReportFilters } from '../src/domain.ts';

const now = Date.parse('2026-10-13T04:00:00Z');
const valid = () => ({ observed_at: '2026-10-13T04:00:00Z', category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', site_label: 'Fictional Site C-14', reporter_label: 'Fictional Reporter A', narrative: 'Damaged fictional water pump.', assistance_requested: 'Repair assistance' });
test('accepted synthetic fields validate without deriving shared text from the narrative', () => {
  const payload = valid(); payload.narrative = '<script>release original</script>';
  assert.deepEqual(validatePayload(payload, now), {});
  assert.equal(payload.narrative, '<script>release original</script>');
});
test('required private fields flag their field names without echoing input', () => {
  const payload = valid(); payload.site_label = ' '; payload.reporter_label = ''; payload.narrative = ' ';
  assert.deepEqual(Object.keys(validatePayload(payload, now)).sort(), ['narrative', 'reporter_label', 'site_label']);
});
test('private string limits accept their boundaries and reject overflow', () => {
  const payload = valid(); payload.site_label = 'S'.repeat(100); payload.reporter_label = 'R'.repeat(100); payload.narrative = 'N'.repeat(2000);
  assert.deepEqual(validatePayload(payload, now), {});
  payload.site_label += 'S'; payload.reporter_label += 'R'; payload.narrative += 'N';
  assert.deepEqual(Object.keys(validatePayload(payload, now)).sort(), ['narrative', 'reporter_label', 'site_label']);
});
test('unsupported values are rejected for every enum', () => {
  const payload = valid(); payload.category = 'SECRET'; payload.urgency = 'CRITICAL'; payload.area_label = 'Real location'; payload.assistance_requested = 'Operational action';
  assert.deepEqual(Object.keys(validatePayload(payload, now)).sort(), ['area_label', 'assistance_requested', 'category', 'urgency']);
});
test('inherited object property names are not accepted categories', () => {
  for (const category of ['toString', '__proto__', 'constructor']) assert.ok(validatePayload({ ...valid(), category }, now).category);
});
test('timezone-free and malformed observation strings are rejected', () => {
  for (const value of ['2026-10-13T04:00:00', '', 'not a date']) {
    assert.ok(validatePayload({ ...valid(), observed_at: value }, now).observed_at);
  }
});
test('timezone-aware offset observation is accepted', () => {
  assert.deepEqual(validatePayload({ ...valid(), observed_at: '2026-10-13T12:00:00+08:00' }, now), {});
});
test('future observation boundary is exactly five minutes', () => {
  assert.deepEqual(validatePayload({ ...valid(), observed_at: '2026-10-13T04:05:00Z' }, now), {});
  assert.ok(validatePayload({ ...valid(), observed_at: '2026-10-13T04:05:00.001Z' }, now).observed_at);
});
test('retry envelope has two distinct operation/report IDs and owns a payload copy', () => {
  const payload = valid(); const operation = createOperation(payload);
  assert.match(operation.operation_id, /^[0-9a-f-]{36}$/); assert.match(operation.report_id, /^[0-9a-f-]{36}$/);
  assert.notEqual(operation.operation_id, operation.report_id);
  assert.equal(operation.expected_revision, 0); assert.equal(operation.template_version, 'demo-maintenance-v1');
  payload.narrative = 'Edited after the request was frozen';
  assert.equal(operation.payload.narrative, 'Damaged fictional water pump.');
  const wire = JSON.stringify(operation); assert.equal(JSON.stringify(operation), wire);
});
test('day precision dates do not shift across local time zones', () => {
  const prior = process.env.TZ;
  try { process.env.TZ = 'America/Los_Angeles'; assert.equal(dateLabel('2026-10-13'), 'Oct 13, 2026'); process.env.TZ = 'Asia/Manila'; assert.equal(dateLabel('2026-10-13'), 'Oct 13, 2026'); }
  finally { if (prior === undefined) delete process.env.TZ; else process.env.TZ = prior; }
});
test('missing and malformed dates show a safe placeholder', () => {
  assert.equal(dateLabel(''), '—'); assert.equal(dateLabel('not a date'), '—');
});
test('receipt and approval status labels remain different', () => {
  assert.match(STATUS_LABELS.PENDING, /Received/); assert.doesNotMatch(STATUS_LABELS.PENDING, /published/i);
  assert.match(STATUS_LABELS.APPROVED, /review approved/i); assert.doesNotMatch(STATUS_LABELS.APPROVED, /published/i); assert.match(STATUS_LABELS.AWAITING_REVIEW, /human review/i);
});
test('correction keeps report identity, freezes a new body, and advances from the expected revision', () => {
  const payload = valid(); const report_id = crypto.randomUUID();
  const correction = createOperation(payload, { report_id, expected_revision: 2, correction_reason: 'Clarified the fictional repair request.' });
  assert.equal(correction.correction_reason, 'Clarified the fictional repair request.');
  assert.equal(correction.report_id, report_id); assert.equal(correction.expected_revision, 2);
  assert.notEqual(correction.operation_id, report_id);
  const wire = JSON.stringify(correction);
  payload.narrative = 'Unsent edits';
  assert.equal(JSON.stringify(correction), wire);
  assert.notEqual(createOperation(valid(), { report_id, expected_revision: 2, correction_reason: 'Clarified the fictional repair request.' }).operation_id, correction.operation_id);
});
test('correction rejects missing, zero, negative and fractional expected revision context', () => {
  for (const expected_revision of [0, -1, 1.5, NaN, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => createOperation(valid(), { report_id: 'report', expected_revision, correction_reason: 'Clarified the fictional maintenance description.' }));
  assert.throws(() => createOperation(valid(), { report_id: '', expected_revision: 1, correction_reason: 'Clarified the fictional maintenance description.' }));
});
test('creation date filters allow inclusive single-day and open ranges but reject invalid dates', () => {
  for (const values of [['', ''], ['2026-10-13', ''], ['', '2026-10-13'], ['2026-10-13', '2026-10-13']]) assert.equal(validateReportFilters({ date_from: values[0], date_to: values[1] }), '');
  for (const date of ['2026-02-30', '2026-13-01', '10/13/2026', '0000-01-01']) assert.ok(validateReportFilters({ date_from: date, date_to: '' }));
  assert.ok(validateReportFilters({ date_from: '2026-10-14', date_to: '2026-10-13' }));
});
const context = () => ({ units: [{ id: 'unit', active: true }, { id: 'inactive-unit', active: false }], channels: [{ id: 'channel', active: true }, { id: 'other', active: true }, { id: 'inactive-channel', active: false }], channel_sources: [{ unit_id: 'unit', channel_id: 'channel', active: true }] });
const account = () => ({ display_name: 'Fictional Submitter', role: 'submitter', is_active: true, unit_id: 'unit', channel_id: 'channel' });
test('source assignments require one active eligible channel, including inactive-account edits', () => {
  assert.deepEqual(validateAccount(account(), context()), {});
  assert.deepEqual(validateAccount({ ...account(), is_active: false }, context()), {});
  const multiple = context(); multiple.channel_sources.push({ unit_id: 'unit', channel_id: 'other', active: true });
  assert.ok(validateAccount(account(), multiple).channel_id);
  assert.ok(validateAccount({ ...account(), unit_id: 'inactive-unit' }, context()).unit_id);
  const revoked = context(); revoked.channel_sources[0].active = false;
  assert.equal(eligibleChannels(revoked, 'unit').length, 0);
  assert.ok(validateAccount(account(), revoked).channel_id);
});
test('recipient assignments exclude source units and inactive channels', () => {
  assert.deepEqual(validateAccount({ ...account(), role: 'recipient', unit_id: null }, context()), {});
  assert.ok(validateAccount({ ...account(), role: 'recipient' }, context()).unit_id);
  assert.ok(validateAccount({ ...account(), role: 'recipient', unit_id: null, channel_id: 'inactive-channel' }, context()).channel_id);
});
test('administrator role has no report scope and unsupported roles fail closed', () => {
  assert.deepEqual(validateAccount({ ...account(), role: 'administrator', unit_id: null, channel_id: null }, context()), {});
  assert.ok(validateAccount({ ...account(), role: 'administrator' }, context()).role);
  assert.ok(validateAccount({ ...account(), role: 'superuser' }, context()).role);
  assert.equal(roleLabel('administrator'), 'Account administrator');
});
test('account display name is required and bounded without echoing input', () => {
  assert.ok(validateAccount({ ...account(), display_name: ' ' }, context()).display_name);
  assert.deepEqual(validateAccount({ ...account(), display_name: 'A'.repeat(120) }, context()), {});
  assert.ok(validateAccount({ ...account(), display_name: 'A'.repeat(121) }, context()).display_name);
});
test('password change preserves spaces, requires exact confirmation and rejects unchanged credentials', () => {
  assert.deepEqual(validatePasswordChange(' old ', ' new password ', ' new password '), {});
  assert.ok(validatePasswordChange(' old ', ' new password ', 'new password').confirmation);
  assert.ok(validatePasswordChange('same long password', 'same long password', 'same long password').new_password);
  assert.deepEqual(validatePasswordChange(' ', 'twelve chars', 'twelve chars'), {});
});
test('password bounds reject empty current and short or overlong new values without echoing input', () => {
  assert.ok(validatePasswordChange('', 'twelve chars', 'twelve chars').current_password);
  assert.deepEqual(validatePasswordChange('c'.repeat(128), 'n'.repeat(128), 'n'.repeat(128)), {});
  assert.ok(validatePasswordChange('c'.repeat(129), 'twelve chars', 'twelve chars').current_password);
  for (const size of [0, 11, 129]) assert.ok(validatePasswordChange('current', 'n'.repeat(size), 'n'.repeat(size)).new_password);
  assert.doesNotMatch(JSON.stringify(validatePasswordChange('private-example', 'tiny', 'different')), /private-example|tiny|different/);
});
test('recipient filter validation accepts trimmed search boundaries and every approved enum', () => {
  for (const category of ['ALL', 'INFRASTRUCTURE', 'WATER_SUPPLY', 'EQUIPMENT']) for (const urgency of ['ALL', 'ROUTINE', 'PRIORITY']) assert.equal(validateFeedFilters({ q: '  ' + 's'.repeat(120) + ' ', category, urgency }), '');
  assert.ok(validateFeedFilters({ q: 's'.repeat(121), category: 'ALL', urgency: 'ALL' }));
  for (const category of ['toString', '__proto__', 'constructor', 'PRIVATE']) assert.ok(validateFeedFilters({ q: '', category, urgency: 'ALL' }));
  assert.ok(validateFeedFilters({ q: '', category: 'ALL', urgency: 'SECRET' }));
});
test('sharing explains historical decisions separately from current publication availability', () => {
  assert.match(sharingExplanation('AVAILABLE'), /current channel grant/);
  assert.match(sharingExplanation('SUPERSEDED'), /does not authorize the new revision/);
  assert.match(sharingExplanation('WITHDRAWN'), /earlier approval remains/);
  assert.match(sharingExplanation('UNAVAILABLE'), /cannot currently be shared/);
  assert.match(sharingExplanation('NOT_SHARED'), /does not share/);
  assert.match(sharingExplanation('UNKNOWN'), /could not be confirmed/);
});
test('waiting age is coarse, never negative and tolerates unknown dates', () => {
  assert.equal(ageLabel('2026-10-13T03:30:00Z', now), 'Under 1 hour');
  assert.equal(ageLabel('2026-10-13T03:00:00Z', now), '1 hour');
  assert.equal(ageLabel('2026-10-12T04:00:00Z', now), '24 hours');
  assert.equal(ageLabel('2026-10-10T04:00:00Z', now), '3 days');
  assert.equal(ageLabel('2026-10-14T04:00:00Z', now), 'Under 1 hour');
  assert.equal(ageLabel('not a date', now), '—');
});

test('website correction reason is explicit bounded and private; initial body keys stay unchanged', () => {
  const payload = valid(); const context = { report_id: crypto.randomUUID(), expected_revision: 1 };
  for (const reason of [undefined, null, '', '   ', 'x'.repeat(501)]) {
    assert.ok(validateCorrectionReason(reason));
    assert.throws(() => createOperation(payload, { ...context, correction_reason: reason }));
  }
  assert.equal(validateCorrectionReason('x'.repeat(500)), '');
  assert.deepEqual(Object.keys(createOperation(payload)).sort(), ['expected_revision', 'operation_id', 'payload', 'report_id', 'template_version']);
  const correction = { ...context, correction_reason: '  Private synthetic clarification.  ' };
  const operation = createOperation(payload, correction); const frozen = JSON.stringify(operation);
  correction.correction_reason = 'Later unsent reason edit'; payload.narrative = 'Later unsent payload edit';
  assert.equal(JSON.stringify(operation), frozen);
  assert.equal(operation.correction_reason, '  Private synthetic clarification.  ');
});
