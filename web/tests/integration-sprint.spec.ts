import { expect, test, type Page, type Route } from '@playwright/test';

// Built website in Chromium with controlled API responses. These cases never
// establish Django session enforcement or real database persistence.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const CHANNEL = { id: '11111111-1111-4111-8111-111111111111', code: 'CH-DEMO-01', name: 'Synthetic maintenance channel' };
const UNIT = { id: '22222222-2222-4222-8222-222222222222', code: 'SIM-UNIT-01', name: 'Synthetic source unit' };
const REPORT = '33333333-3333-4333-8333-333333333333';
const STAMP = '2026-10-14T00:00:00Z';
const CURRENT = 'DemoMaintenance!2026';
const REPLACEMENT = 'Fictional-New!2026';
type Role = 'submitter' | 'reviewer' | 'recipient' | 'administrator';
type Mode = 'normal' | 'wrong-password' | 'uncertain-password' | 'invalid-password-response' | 'feed-denied' | 'detail-denied';
const initialWorkflow = () => ({ revision_no: 1, is_current: true, received_at: STAMP, processing: { state: 'DONE', attempts: 2 }, review: { state: 'APPROVED', prepared_at: STAMP, decided_at: STAMP }, sharing: { state: 'AVAILABLE', published_at: STAMP } });

async function setup(page: Page, role: Role, mode: Mode = 'normal') {
  const state = { authenticated: false, mode, workflow: initialWorkflow(), queries: [] as { path: string; params: Record<string, string> }[], passwordWrites: [] as Record<string, unknown>[], logoutCalls: 0 };
  const user = { id: '77777777-7777-4777-8777-777777777777', username: role, display_name: `Demo ${role}`, role, unit: ['submitter', 'reviewer'].includes(role) ? UNIT : null, channel: role === 'administrator' ? null : CHANNEL, profile: 'DEMO-REDUCED' };
  const publications = Array.from({ length: 101 }, (_, index) => ({ id: `a0000000-0000-4000-8000-${String(index + 1).padStart(12, '0')}`, published_at: STAMP, channel: CHANNEL, projection: { title: `Synthetic maintenance update ${index + 1}`, text: index === 100 ? 'Earlier approved archived pump update.' : `Approved fictional maintenance detail ${index + 1}.`, category: index % 2 ? 'EQUIPMENT' : 'INFRASTRUCTURE', urgency: index % 3 ? 'ROUTINE' : 'PRIORITY', area_label: 'Area C', assistance_requested: 'Repair assistance', observed_date: '2026-10-14', verification: 'Human reviewed', profile: 'DEMO-REDUCED' } }));
  const summary = { id: REPORT, reference: 'R-WORKFLOW', category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', created_at: STAMP, observed_date: '2026-10-14', revision_no: 1, status: 'APPROVED', variant_id: null, feedback: null };
  const reply = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers: { 'Cache-Control': 'no-store' } });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.slice('/api/v1'.length);
    state.queries.push({ path, params: Object.fromEntries(url.searchParams) });
    if (path === '/auth/csrf/') return reply(route, 200, { csrf_token: 'synthetic-fixture-token' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, 200, { user }); }
    if (path === '/auth/logout/') { state.logoutCalls++; state.authenticated = false; return reply(route, 200, { logged_out: true }); }
    if (path === '/me/') return reply(route, state.authenticated ? 200 : 403, state.authenticated ? { user } : { code: 'AUTH_REQUIRED', message: 'Sign in to continue.' });
    if (path === '/auth/password/') {
      state.passwordWrites.push(request.postDataJSON());
      if (state.mode === 'wrong-password') return reply(route, 400, { code: 'INVALID_INPUT', message: 'The current password could not be verified.', errors: { current_password: ['The current password could not be verified.'] } });
      if (state.mode === 'uncertain-password') return reply(route, 503, { code: 'UNAVAILABLE', message: 'Change result could not be confirmed.' });
      if (state.mode === 'invalid-password-response') return reply(route, 200, {});
      state.authenticated = false; return reply(route, 200, { changed: true, reauthenticate: true });
    }
    if (path === '/reports/' || path === '/review/queue/') return reply(route, 200, { results: [summary], count: 1, page: 1, page_size: 10, total_pages: 1 });
    if (path === `/reports/${REPORT}/revisions/1/`) return reply(route, 200, { report: { ...summary, status: state.workflow.processing.state === 'FAILED' ? 'FAILED' : summary.status }, payload: { observed_at: STAMP, category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', site_label: 'Fictional site', reporter_label: 'Fictional author', narrative: 'Private fictional repair request.', assistance_requested: 'Repair assistance' }, receipt: { operation_id: '99999999-9999-4999-8999-999999999999', report_id: REPORT, revision_id: '66666666-6666-4666-8666-666666666666', revision_no: 1, delivery_status: 'RECEIVED', processing_status: 'PENDING', shared: false }, can_correct: false, history: [{ revision_no: 1, received_at: STAMP, status: summary.status }], workflow: state.workflow });
    if (path === '/administration/context/') return reply(route, 200, { units: [], channels: [], channel_sources: [] });
    if (path === '/administration/users/') return reply(route, 200, { results: [], count: 0, page: 1, page_size: 10, total_pages: 1 });
    if (path === `/channels/${CHANNEL.id}/feed/`) {
      if (state.mode === 'feed-denied') return reply(route, 403, { code: 'SCOPE_DENIED', message: 'Current channel access is unavailable.' });
      const params = url.searchParams, q = (params.get('q') || '').toLowerCase();
      const category = params.get('category') || 'ALL', urgency = params.get('urgency') || 'ALL';
      const rows = publications.filter(row => (!q || [row.projection.title, row.projection.text, row.projection.area_label, row.projection.assistance_requested].join(' ').toLowerCase().includes(q)) && (category === 'ALL' || row.projection.category === category) && (urgency === 'ALL' || row.projection.urgency === urgency));
      const number = Number(params.get('page') || 1), size = Number(params.get('page_size') || 10);
      return reply(route, 200, { results: rows.slice((number - 1) * size, number * size), count: rows.length, page: number, page_size: size, total_pages: Math.max(1, Math.ceil(rows.length / size)), refreshed_at: new Date().toISOString() });
    }
    if (path.startsWith('/publications/')) {
      if (state.mode === 'detail-denied') return reply(route, 404, { code: 'NOT_FOUND', message: 'This publication is no longer available.' });
      const item = publications.find(value => path === `/publications/${value.id}/`);
      return reply(route, item ? 200 : 404, item || { code: 'NOT_FOUND', message: 'Unavailable.' });
    }
    return reply(route, 404, { code: 'NOT_FOUND', message: 'Unavailable fixture route.' });
  });
  await page.goto(BASE);
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill(CURRENT);
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  return state;
}
async function account(page: Page) {
  await page.getByRole('button', { name: 'Account security', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Account security', exact: true })).toBeVisible();
}
async function passwordFields(page: Page) {
  await page.getByLabel(/^Current password/).fill(CURRENT);
  await page.getByLabel(/^New password/).fill(REPLACEMENT);
  await page.getByLabel(/^Confirm new password/).fill(REPLACEMENT);
}
async function source(page: Page) {
  await page.getByRole('button', { name: /R-WORKFLOW/ }).first().click();
  await expect(page.getByRole('heading', { name: 'Workflow progress', exact: true })).toBeVisible();
}

for (const role of ['submitter', 'reviewer', 'recipient', 'administrator'] as const) {
  test(`${role} confirms own password change and returns to sign-in without storing credentials`, async ({ page }) => {
    const state = await setup(page, role); await account(page); await passwordFields(page);
    await page.getByRole('button', { name: 'Review password change', exact: true }).click();
    await expect(page.getByRole('dialog')).toBeVisible(); expect(state.passwordWrites).toHaveLength(0);
    await expect(page.getByRole('dialog')).not.toContainText(REPLACEMENT);
    await page.getByRole('button', { name: 'Change password', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
    expect(state.passwordWrites).toEqual([{ current_password: CURRENT, new_password: REPLACEMENT }]);
    expect(state.queries.every(row => !JSON.stringify(row.params).includes(REPLACEMENT))).toBe(true);
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  });
}

test('password mismatch sends no request and wrong current password clears secret fields', async ({ page }) => {
  const state = await setup(page, 'administrator', 'wrong-password'); await account(page); await passwordFields(page);
  await page.getByLabel(/^Confirm new password/).fill('Different-Fictional!2026');
  await page.getByRole('button', { name: 'Review password change', exact: true }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0); expect(state.passwordWrites).toHaveLength(0);
  await page.getByLabel(/^Confirm new password/).fill(REPLACEMENT);
  await page.getByRole('button', { name: 'Review password change', exact: true }).click();
  await page.getByRole('button', { name: 'Change password', exact: true }).click();
  await expect(page.locator('body')).toContainText('password change was not accepted');
  for (const label of ['Current password', 'New password', 'Confirm new password']) await expect(page.getByLabel(new RegExp('^' + label))).toHaveValue('');
  expect(state.passwordWrites).toHaveLength(1);
});

test('uncertain password change clears the workspace and never automatically repeats the write', async ({ page }) => {
  const state = await setup(page, 'submitter', 'uncertain-password'); await account(page); await passwordFields(page);
  await page.getByRole('button', { name: 'Review password change', exact: true }).click();
  await page.getByRole('button', { name: 'Change password', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  expect(state.passwordWrites).toHaveLength(1);
  await expect(page.getByRole('button', { name: 'Your reports', exact: true })).toHaveCount(0);
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
});

test('malformed password acknowledgement requires reauthentication without claiming success', async ({ page }) => {
  const state = await setup(page, 'administrator', 'invalid-password-response'); await account(page); await passwordFields(page);
  await page.getByRole('button', { name: 'Review password change', exact: true }).click();
  await page.getByRole('button', { name: 'Change password', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.locator('body')).toContainText(/could not be confirmed|not confirmed|uncertain/i);
  expect(state.passwordWrites).toHaveLength(1);
});

test('private workflow separates the immutable receipt from current approval and sharing', async ({ page }) => {
  await setup(page, 'submitter'); await source(page);
  await expect(page.locator('body')).toContainText('Initial processing');
  await expect(page.locator('body')).toContainText('Shared at acceptance');
  await expect(page.locator('body')).toContainText('Human review');
  await expect(page.locator('body')).toContainText('Sharing');
  await page.screenshot({ path: '../.cache/m1-qa/integration-workflow-desktop.png', fullPage: true });
});

test('workflow refresh marks earlier approval unavailable after policy or channel change', async ({ page }) => {
  const state = await setup(page, 'submitter'); await source(page);
  state.workflow.sharing.state = 'UNAVAILABLE';
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.locator('body')).toContainText(/unavailable/i);
  await expect(page.locator('body')).toContainText(/approved/i);
});

test('failed processing remains private in workflow details', async ({ page }) => {
  const state = await setup(page, 'submitter');
  state.workflow.processing = { state: 'FAILED', attempts: 3 }; state.workflow.review = { state: 'NOT_READY', prepared_at: null as any, decided_at: null as any }; state.workflow.sharing = { state: 'NOT_SHARED', published_at: null as any };
  await source(page);
  await expect(page.locator('body')).toContainText(/failed|did not complete/i);
  await expect(page.locator('body')).toContainText(/not shared|private/i);
});

test('recipient reaches publication101 using server pages and can search the older approved content', async ({ page }) => {
  const state = await setup(page, 'recipient');
  await page.getByRole('combobox', { name: 'Per page', exact: true }).selectOption('50');
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Synthetic maintenance update 101', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();
  await page.getByRole('searchbox', { name: 'Search approved publications', exact: true }).fill('archived pump');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect.poll(() => state.queries.filter(row => row.path.endsWith('/feed/')).at(-1)?.params).toMatchObject({ q: 'archived pump', page: '1' });
  await expect(page.getByRole('button', { name: 'Synthetic maintenance update 101', exact: true })).toBeVisible();
  expect(state.queries.some(row => row.path.startsWith('/reports/') || row.path.startsWith('/review/'))).toBe(false);
});

test('recipient category and urgency filters are sent to the server', async ({ page }) => {
  const state = await setup(page, 'recipient');
  await page.getByRole('combobox', { name: 'Filter approved category', exact: true }).selectOption('EQUIPMENT');
  await page.getByRole('combobox', { name: 'Filter approved urgency', exact: true }).selectOption('PRIORITY');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect.poll(() => state.queries.filter(row => row.path.endsWith('/feed/')).at(-1)?.params).toMatchObject({ category: 'EQUIPMENT', urgency: 'PRIORITY', page: '1' });
  await expect(page.getByRole('button', { name: 'Synthetic maintenance update 4', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Synthetic maintenance update 1', exact: true })).toHaveCount(0);
});

test('selected publication is rechecked on refresh and removed after withdrawal', async ({ page }) => {
  const state = await setup(page, 'recipient');
  await page.getByRole('button', { name: 'Synthetic maintenance update 1', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Approved reduced representation', exact: true })).toBeVisible();
  state.mode = 'detail-denied'; await page.getByRole('button', { name: 'Refresh now', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Approved reduced representation', exact: true })).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText('Approved fictional maintenance detail 1.');
});

test('recipient scope loss during a page request clears earlier content', async ({ page }) => {
  const state = await setup(page, 'recipient');
  await expect(page.getByRole('button', { name: 'Next page', exact: true })).toBeEnabled();
  state.mode = 'feed-denied';
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('Synthetic maintenance update');
});

test('account security and recipient filters fit mobile screens', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); await setup(page, 'recipient');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Open navigation', exact: true }).click(); await account(page);
  await expect(page.getByRole('button', { name: 'Open navigation', exact: true })).toHaveAttribute('aria-expanded', 'false');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '../.cache/m1-qa/integration-account-mobile.png', fullPage: true, animations: 'disabled' });
});
