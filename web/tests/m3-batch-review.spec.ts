import { expect, test, type Page, type Route } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Synthetic fixture journeys. These do not establish real API authorization.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18091').toString();
const stamp = '2026-10-21T00:00:00Z';
const id = '11111111-1111-4111-8111-111111111111', revision = '22222222-2222-4222-8222-222222222222';
const channel = { id: '33333333-3333-4333-8333-333333333333', name: 'Synthetic sharing channel', code: 'CH-DEMO-02' };
const profiles = ['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY'];
const label = (profile: string) => ({ 'DEMO-FULL': 'Full', 'DEMO-REDUCED': 'Reduced', 'DEMO-SUMMARY': 'Summary' } as Record<string, string>)[profile];
const projected = JSON.parse(readFileSync(new URL('../../contracts/m3/profiles.json', import.meta.url), 'utf8')).expected['demo-policy-v1'];
const payload = { observed_at: stamp, category: 'WATER_SUPPLY', urgency: 'ROUTINE', area_label: 'Area B', site_label: 'Synthetic site', reporter_label: 'Synthetic author', narrative: 'Fictional maintenance issue.', assistance_requested: 'Inspection' };
const report = { id, reference: 'R-BATCH', category: 'WATER_SUPPLY', urgency: 'ROUTINE', area_label: 'Area B', created_at: stamp, observed_date: '2026-10-21', revision_no: 2, status: 'AWAITING_REVIEW', variant_id: '44444444-4444-4444-8444-444444444441', feedback: null };
const binding = { revision_id: revision, revision_no: 2, policy_version: 'demo-policy-v1', policy_hash: 'a'.repeat(64), scope_context_hash: 'b'.repeat(64), candidates: profiles.map((profile, index) => ({ variant_id: `44444444-4444-4444-8444-44444444444${index + 1}`, profile, candidate_hash: String(index + 1).repeat(64), channel_ids: [channel.id] })) };

async function setup(page: Page, mode = 'normal', legacy = false) {
  const user = { id: '77777777-7777-4777-8777-777777777777', username: 'reviewer', display_name: 'Synthetic reviewer', role: 'reviewer', unit: { id: 'u', code: 'UNIT-DEMO-01', name: 'Synthetic unit' }, channel, profile: 'DEMO-REDUCED', ...(!legacy ? { channels: [channel] } : {}) };
  const activeBinding = { ...binding, candidates: mode === 'summary-only' ? binding.candidates.slice(2) : mode === 'reduced-summary' ? binding.candidates.slice(1) : binding.candidates };
  const state = { authenticated: false, writes: [] as { path: string; body: any; key?: string }[], paths: [] as string[], withdrawn: false };
  const reply = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice('/api/v1'.length); state.paths.push(path);
    if (path === '/auth/csrf/') return reply(route, { csrf_token: 'synthetic-token' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, { user }); }
    if (path === '/auth/logout/') { state.authenticated = false; return reply(route, {}); }
    if (path === '/me/') return reply(route, state.authenticated ? { user } : { code: 'AUTH_REQUIRED' }, state.authenticated ? 200 : 403);
    if (path === '/review/queue/') return reply(route, { results: [report], count: 1, page: 1, page_size: 10, total_pages: 1 });
    if (request.method() === 'POST') {
      state.writes.push({ path, body: request.postDataJSON(), key: request.headers()['idempotency-key'] });
      const count = state.writes.length;
      if (mode === 'retry' && count === 1) return reply(route, { code: 'UNAVAILABLE', message: 'Result not confirmed.' }, 503);
      if (mode === 'retry' && count === 2) return reply(route, { code: 'CSRF_FAILED', message: 'Retry CSRF.' }, 403);
      if (mode === 'stale') return reply(route, { code: 'STALE_CONTEXT', message: 'Context changed.' }, 409);
      if (path.endsWith('/withdrawal/')) { state.withdrawn = true; return reply(route, { withdrawal_id: 'w', report_status: 'WITHDRAWN', publication_ids: ['p'] }); }
      const body = request.postDataJSON();
      return reply(route, { batch_id: 'batch', action: body.action, report_status: body.action === 'APPROVE' ? 'APPROVED' : body.action === 'RETURN' ? 'RETURNED' : 'REJECTED', publication_ids: body.action === 'APPROVE' ? ['p'] : [], approved_profiles: body.approve_profiles, withheld_profiles: body.action === 'APPROVE' ? activeBinding.candidates.map(row => row.profile).filter(profile => !body.approve_profiles.includes(profile)) : [], withheld_variant_ids: body.action === 'APPROVE' ? activeBinding.candidates.filter(row => !body.approve_profiles.includes(row.profile)).map(row => row.variant_id) : [] });
    }
    if (path.includes('/revisions/') && !path.includes('/candidates/')) {
      const n = Number(path.split('/').at(-2));
      return reply(route, { report: { ...report, revision_no: n }, payload, receipt: { operation_id: 'receipt', report_id: id, revision_id: revision, revision_no: n, delivery_status: 'RECEIVED', processing_status: 'PENDING', shared: false }, can_correct: false, correction_reason: 'Synthetic approved-source correction reason.', history: [{ revision_no: 2, received_at: stamp, status: 'AWAITING_REVIEW' }, { revision_no: 1, received_at: stamp, status: 'APPROVED' }], workflow: { revision_no: n, is_current: n === 2, received_at: stamp, processing: { state: 'DONE', attempts: 1 }, review: { state: 'AWAITING_REVIEW', prepared_at: stamp, decided_at: null }, sharing: { state: state.withdrawn ? 'WITHDRAWN' : 'NOT_SHARED', published_at: null } } });
    }
    if (path.endsWith('/candidates/')) return reply(route, { report, source: payload, candidates: activeBinding.candidates.map(row => ({ variant_id: row.variant_id, profile: row.profile, candidate: projected[row.profile], warnings: [`Synthetic ${row.profile} review warning.`], state: 'CANDIDATE' })), binding: mode === 'incomplete' ? { ...activeBinding, candidates: activeBinding.candidates.slice(1) } : mode === 'empty-channel' ? { ...activeBinding, candidates: activeBinding.candidates.map((row, index) => index === 0 ? { ...row, channel_ids: [] } : row) } : activeBinding, correction_reason: 'Synthetic approved-source correction reason.' });
    if (path.includes('/variants/')) return reply(route, { report, source: payload, candidate: projected['DEMO-REDUCED'], warnings: [], binding: { revision_id: revision, revision_no: 2, candidate_hash: 'a'.repeat(64), policy_version: 'demo-policy-v1', policy_hash: 'b'.repeat(64), profile: 'DEMO-REDUCED', channel_ids: [channel.id] } });
    return reply(route, { code: 'NOT_FOUND' }, 404);
  });
  await page.goto(BASE);
  await page.getByLabel('Username', { exact: true }).fill('reviewer');
  await page.getByLabel('Password', { exact: true }).fill('SyntheticPassword!2026');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await page.getByRole('button', { name: 'Start review of R-BATCH', exact: true }).click();
  return state;
}

async function approve(page: Page) {
  await page.getByRole('checkbox', { name: 'Approve Reduced', exact: true }).check();
  await page.getByRole('button', { name: 'Review & approve', exact: true }).click();
  await page.getByRole('checkbox', { name: 'I have checked every selected candidate, source revision, policy and sharing audience.', exact: true }).check();
  await page.getByRole('button', { name: 'Approve & share', exact: true }).click();
}

test('expanded reviewer uses receipt UUID and submits complete binding with selected subset', async ({ page }) => {
  const state = await setup(page);
  for (const profile of profiles) {
    await expect(page.getByRole('region', { name: `${label(profile)} candidate` })).toContainText(`Synthetic ${profile} review warning.`);
    await expect(page.getByRole('region', { name: `${label(profile)} candidate` })).toContainText(channel.code);
  }
  await expect(page.getByText('Synthetic approved-source correction reason.', { exact: false })).toBeVisible();
  await approve(page);
  await expect(page.getByText('Approval committed.', { exact: true })).toBeVisible();
  expect(state.paths).toContain(`/reports/${id}/revisions/2/`);
  expect(state.paths).toContain(`/revisions/${revision}/candidates/`);
  expect(state.paths.some(path => path.includes('/variants/'))).toBe(false);
  expect(state.writes[0].body).toMatchObject({ expected: binding, action: 'APPROVE', approve_profiles: ['DEMO-REDUCED'], reason: null });
  expect(state.writes[0].key).toBe(state.writes[0].body.operation_id);
});

for (const action of ['RETURN', 'REJECT']) test(`${action} covers the whole set with private reason and no approved subset`, async ({ page }) => {
  const state = await setup(page);
  await page.getByRole('checkbox', { name: 'Approve Full', exact: true }).check();
  await page.getByRole('button', { name: action === 'RETURN' ? 'Return for correction' : 'Reject', exact: true }).click();
  await page.getByLabel('Private reason', { exact: true }).fill('Synthetic whole-set private decision.');
  await page.getByRole('button', { name: action === 'RETURN' ? 'Return report' : 'Reject report', exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(1);
  expect(state.writes[0].body).toMatchObject({ action, approve_profiles: [], reason: 'Synthetic whole-set private decision.', expected: binding });
});

test('uncertain batch and CSRF retries freeze body, key and navigation', async ({ page }) => {
  const state = await setup(page, 'retry'); await approve(page);
  await expect(page.getByRole('button', { name: 'Account security', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeEnabled();
  await expect(page.getByRole('checkbox', { name: 'Approve Full', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same decision', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry same decision', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Retry same decision', exact: true }).click();
  await expect(page.getByText('Approval committed.', { exact: true })).toBeVisible();
  expect(state.writes).toHaveLength(3);
  expect(state.writes[1]).toEqual(state.writes[0]); expect(state.writes[2]).toEqual(state.writes[0]);
  await expect(page.getByRole('button', { name: 'Account security', exact: true })).toBeEnabled();
});

test('forced session clearing immediately removes uncertain private review', async ({ page }) => {
  await setup(page, 'retry'); await approve(page);
  await expect(page.getByRole('button', { name: 'Retry same decision', exact: true })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('kapit-session-expired')));
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  await expect(page.getByText(payload.narrative, { exact: true })).toHaveCount(0);
});

test('explicit sign out stays available inside an uncertain batch confirmation', async ({ page }) => {
  const state = await setup(page, 'retry'); await approve(page);
  await page.getByRole('button', { name: 'Sign out and clear workspace', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  expect(state.authenticated).toBe(false);
  await expect(page.getByText(payload.narrative, { exact: true })).toHaveCount(0);
});

test('stale decision clears candidates', async ({ page }) => {
  await setup(page, 'stale'); await approve(page);
  await expect(page.getByText('This review changed. Reload before deciding.', { exact: true })).toBeVisible();
  await expect(page.getByRole('checkbox', { name: 'Approve Full', exact: true })).toHaveCount(0);
});

test('incomplete binding refuses review', async ({ page }) => {
  const state = await setup(page, 'incomplete');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review & approve', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(0);
});

for (const mode of ['summary-only', 'reduced-summary']) test(`${mode} candidate union can be reviewed without inventing absent profiles`, async ({ page }) => {
  const state = await setup(page, mode);
  const expectedCandidates = mode === 'summary-only' ? binding.candidates.slice(2) : binding.candidates.slice(1);
  const selected = mode === 'summary-only' ? 'DEMO-SUMMARY' : 'DEMO-REDUCED';
  await expect(page.getByRole('region', { name: /(Full|Reduced|Summary) candidate/ })).toHaveCount(expectedCandidates.length);
  await expect(page.getByRole('checkbox', { name: 'Approve Full', exact: true })).toHaveCount(0);
  await page.getByRole('checkbox', { name: `Approve ${label(selected)}`, exact: true }).check();
  await page.getByRole('button', { name: 'Review & approve', exact: true }).click();
  await page.getByRole('checkbox', { name: 'I have checked every selected candidate, source revision, policy and sharing audience.', exact: true }).check();
  await page.getByRole('button', { name: 'Approve & share', exact: true }).click();
  await expect(page.getByText('Approval committed.', { exact: true })).toBeVisible();
  expect(state.writes[0].body).toMatchObject({ action: 'APPROVE', approve_profiles: [selected], expected: { ...binding, candidates: expectedCandidates } });
});

test('a generated candidate with an empty channel set refuses review', async ({ page }) => {
  const state = await setup(page, 'empty-channel');
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review & approve', exact: true })).toHaveCount(0);
  expect(state.writes).toHaveLength(0);
});

test('withdrawal is current-only and freezes expected revision, reason and key across retries', async ({ page }) => {
  const state = await setup(page, 'retry');
  await page.getByRole('button', { name: 'View revision history', exact: true }).click();
  await page.getByRole('button', { name: 'Revision 1', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Withdraw report', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Revision 2', exact: true }).click();
  await page.getByLabel('Private withdrawal reason', { exact: true }).fill('Synthetic report withdrawal.');
  await page.getByRole('button', { name: 'Withdraw report', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Account security', exact: true })).toBeDisabled();
  await expect(page.getByLabel('Private withdrawal reason', { exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Revision 1', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same withdrawal', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry same withdrawal', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Retry same withdrawal', exact: true }).click();
  await expect(page.getByText('Withdrawal committed.', { exact: true })).toBeVisible();
  await expect(page.getByText('Previously viewed copies cannot be recalled.', { exact: false }).first()).toBeVisible();
  expect(state.writes[0].body).toMatchObject({ expected_revision_no: 2, reason: 'Synthetic report withdrawal.' });
  expect(state.writes[0].key).toBe(state.writes[0].body.operation_id);
  expect(state.writes[1]).toEqual(state.writes[0]); expect(state.writes[2]).toEqual(state.writes[0]);
});

test('legacy reviewer keeps the original variant review path', async ({ page }) => {
  const state = await setup(page, 'normal', true);
  await expect(page.getByRole('heading', { name: 'Reduced candidate', exact: true })).toBeVisible();
  expect(state.paths).toContain(`/variants/${report.variant_id}/review/`);
  expect(state.paths.some(path => path.endsWith('/candidates/'))).toBe(false);
});
