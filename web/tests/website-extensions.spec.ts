import { expect, test, type Page, type Route } from '@playwright/test';

// These tests run the real built website against controlled API responses.
// They verify browser behavior, not Django permissions or Supabase enforcement.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const UNIT = { id: '22222222-2222-4222-8222-222222222222', code: 'SIM-UNIT-01', name: 'Simulated Support Unit', active: true };
const CHANNEL = { id: '11111111-1111-4111-8111-111111111111', code: 'CH-DEMO-01', name: 'Maintenance Coordination', active: true };
const REPORT = '33333333-3333-4333-8333-333333333333';
const ACTOR = '77777777-7777-4777-8777-777777777777';
const TARGET = '88888888-8888-4888-8888-888888888888';
const STAMP = '2026-10-13T02:00:00Z';
const ORIGINAL = 'Fictional returned report original.';
const UPDATED = 'Fictional corrected maintenance description.';
const payload = { observed_at: STAMP, category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', site_label: 'Fictional Site C-14', reporter_label: 'Fictional Reporter A', narrative: ORIGINAL, assistance_requested: 'Repair assistance' };
const returned = { id: REPORT, reference: 'R-RETURNED', category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', created_at: STAMP, observed_date: '2026-10-13', revision_no: 1, status: 'RETURNED', variant_id: '44444444-4444-4444-8444-444444444444', feedback: 'Clarify the fictional repair request.' };
type Role = 'submitter' | 'reviewer' | 'recipient' | 'administrator';
const CORRECTION_REASON = 'Clarified the synthetic maintenance description after reviewer feedback.';
type Mode = 'normal' | 'correction-retry' | 'correction-conflict' | 'admin-conflict' | 'admin-denied' | 'admin-uncertain';
type AdminUser = { id: string; username: string; display_name: string; role: Role; is_active: boolean; permission_version: number; unit_id: string | null; channel_id: string | null };

async function setup(page: Page, role: Role, mode: Mode = 'normal', corrected = false) {
  const state = {
    authenticated: false, mode, corrected,
    queries: [] as { path: string; query: Record<string, string> }[],
    writes: [] as { path: string; method: string; body: Record<string, any>; key?: string }[],
    users: [
      { id: ACTOR, username: 'admin', display_name: 'Demo Administrator', role: 'administrator', is_active: true, permission_version: 0, unit_id: null, channel_id: null },
      { id: TARGET, username: 'alice', display_name: 'Fictional Alice', role: 'submitter', is_active: true, permission_version: 2, unit_id: UNIT.id, channel_id: CHANNEL.id },
    ] as AdminUser[],
  };
  const user = { id: ACTOR, username: role, display_name: 'Demo ' + role, role, unit: ['administrator', 'recipient'].includes(role) ? null : UNIT, channel: role === 'administrator' ? null : CHANNEL, profile: 'DEMO-REDUCED', permission_version: 0 };
  const reply = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers: { 'Cache-Control': 'no-store' } });
  const paginate = (rows: unknown[], params: URLSearchParams) => {
    const page = Number(params.get('page') || 1), size = Number(params.get('page_size') || 10);
    return { results: rows.slice((page - 1) * size, page * size), count: rows.length, page, page_size: size, total_pages: Math.max(1, Math.ceil(rows.length / size)) };
  };
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname.slice('/api/v1'.length), method = request.method();
    state.queries.push({ path, query: Object.fromEntries(url.searchParams) });
    if (path === '/auth/csrf/') return reply(route, 200, { csrf_token: 'synthetic-ui-fixture-token' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, 200, { user }); }
    if (path === '/auth/logout/') { state.authenticated = false; return reply(route, 200, { logged_out: true }); }
    if (path === '/me/') return reply(route, state.authenticated ? 200 : 403, state.authenticated ? { user } : { code: 'AUTH_REQUIRED', message: 'Sign in to continue.' });
    if (method !== 'GET') state.writes.push({ path, method, body: request.postDataJSON(), key: request.headers()['idempotency-key'] });
    if (path === '/reports/' || path === '/review/queue/') {
      const current = state.corrected ? { ...returned, revision_no: 2, status: 'PENDING', feedback: null, variant_id: null } : returned;
      let rows = [current, ...Array.from({ length: 13 }, (_, i) => ({ ...returned, id: `a0000000-0000-4000-8000-${String(i + 1).padStart(12, '0')}`, reference: `R-OTHER-${i + 1}`, status: i % 2 ? 'APPROVED' : 'AWAITING_REVIEW', feedback: null }))];
      const status = url.searchParams.get('status') || (path.includes('queue') ? 'AWAITING_REVIEW' : 'ALL');
      if (status !== 'ALL') rows = rows.filter(row => row.status === status);
      if (url.searchParams.get('date_from') && url.searchParams.get('date_from')! > '2026-10-13') rows = [];
      return reply(route, 200, paginate(rows, url.searchParams));
    }
    const revisionMatch = path.match(/^\/reports\/([^/]+)\/revisions\/(\d+)\/$/);
    if (revisionMatch) {
      const n = Number(revisionMatch[2]);
      const report = n === 2 ? { ...returned, revision_no: 2, status: 'PENDING', variant_id: null, feedback: null } : returned;
      return reply(route, 200, { report, payload: { ...payload, narrative: n === 2 ? UPDATED : ORIGINAL }, receipt: { operation_id: '99999999-9999-4999-8999-999999999999', report_id: REPORT, revision_id: `66666666-6666-4666-8666-66666666666${n}`, revision_no: n, delivery_status: 'RECEIVED', processing_status: 'PENDING', shared: false }, can_correct: n === 1 && !state.corrected && role === 'submitter', history: [...(state.corrected ? [{ revision_no: 2, received_at: STAMP, status: 'PENDING' }] : []), { revision_no: 1, received_at: STAMP, status: 'RETURNED' }], workflow: { revision_no: n, is_current: !state.corrected || n === 2, received_at: STAMP, processing: { state: n === 2 ? 'PENDING' : 'DONE', attempts: n === 2 ? 0 : 1 }, review: { state: n === 2 ? 'NOT_READY' : 'RETURNED', prepared_at: n === 2 ? null : STAMP, decided_at: n === 2 ? null : STAMP }, sharing: { state: 'NOT_SHARED', published_at: null } } });
    }
    if (path === '/sync/operations/') {
      const posts = state.writes.filter(item => item.path === path);
      if (state.mode === 'correction-retry' && posts.length === 1) return reply(route, 503, { code: 'UNAVAILABLE', message: 'Receipt not confirmed.' });
      if (state.mode === 'correction-retry' && posts.length === 2) return reply(route, 403, { code: 'CSRF_FAILED', message: 'Refresh the CSRF token and retry.' });
      if (state.mode === 'correction-conflict') return reply(route, 409, { code: 'REVISION_CONFLICT', message: 'This report has a newer revision. Reload before correcting.' });
      const body = request.postDataJSON(); state.corrected = true;
      return reply(route, 201, { operation_id: body.operation_id, report_id: REPORT, revision_id: '66666666-6666-4666-8666-666666666662', revision_no: 2, delivery_status: 'RECEIVED', processing_status: 'PENDING', shared: false });
    }
    if (path === '/administration/context/') return reply(route, 200, { units: [UNIT], channels: [CHANNEL], channel_sources: [{ unit_id: UNIT.id, channel_id: CHANNEL.id, active: true }] });
    if (path === '/administration/users/' && method === 'GET') {
      if (state.mode === 'admin-denied') return reply(route, 403, { code: 'ACCESS_DENIED', message: 'Current administration access is unavailable.' });
      let rows = state.users;
      const q = url.searchParams.get('q')?.toLowerCase(); if (q) rows = rows.filter(row => (row.username + row.display_name).toLowerCase().includes(q));
      const filterRole = url.searchParams.get('role'); if (filterRole && filterRole !== 'ALL') rows = rows.filter(row => row.role === filterRole);
      const active = url.searchParams.get('active'); if (active && active !== 'ALL') rows = rows.filter(row => row.is_active === (active === 'true'));
      return reply(route, 200, paginate(rows, url.searchParams));
    }
    if (path === '/administration/users/' && method === 'POST') {
      if (state.mode === 'admin-uncertain') return reply(route, 503, { code: 'UNAVAILABLE', message: 'Creation result could not be confirmed. Reload accounts before trying again.' });
      const body = request.postDataJSON();
      const created: AdminUser = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', username: body.username, display_name: body.display_name, role: body.role, is_active: body.is_active, permission_version: 0, unit_id: body.unit_id, channel_id: body.channel_id };
      state.users.push(created); return reply(route, 201, created);
    }
    if (path === `/administration/users/${TARGET}/` || path === `/administration/users/${TARGET}/password/`) {
      const body = request.postDataJSON(), target = state.users.find(row => row.id === TARGET)!;
      if (state.mode === 'admin-conflict') return reply(route, 409, { code: 'STALE_PERMISSIONS', message: 'This account changed. Reload before saving.' });
      if (body.expected_permission_version !== target.permission_version) return reply(route, 409, { code: 'STALE_PERMISSIONS', message: 'Reload this account.' });
      if (method === 'PATCH') Object.assign(target, { display_name: body.display_name, role: body.role, is_active: body.is_active, unit_id: body.unit_id, channel_id: body.channel_id });
      target.permission_version += 1; return reply(route, 200, target);
    }
    return reply(route, 404, { code: 'NOT_FOUND', message: 'Unavailable fixture route.' });
  });
  await page.goto(BASE);
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill('DemoMaintenance!2026');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  return state;
}

async function openReturned(page: Page) {
  await page.getByRole('button', { name: 'Your reports', exact: true }).first().click();
  await page.getByRole('button', { name: /R-RETURNED/ }).first().click();
  await expect(page.getByText(ORIGINAL, { exact: true })).toBeVisible();
}

test('report filters and pagination send scoped list parameters and reset page', async ({ page }) => {
  const state = await setup(page, 'submitter');
  await page.getByRole('button', { name: 'Your reports', exact: true }).first().click();
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect.poll(() => state.queries.filter(row => row.path === '/reports/').at(-1)?.query.page).toBe('2');
  await page.getByRole('combobox', { name: 'Report status', exact: true }).selectOption('RETURNED');
  await page.getByLabel('Created from (UTC)', { exact: true }).fill('2026-10-13');
  await page.getByLabel('Created to (UTC)', { exact: true }).fill('2026-10-13');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect.poll(() => state.queries.filter(row => row.path === '/reports/').at(-1)?.query).toMatchObject({ status: 'RETURNED', date_from: '2026-10-13', date_to: '2026-10-13', page: '1' });
  await expect(page.getByRole('button', { name: 'Next page', exact: true })).toBeDisabled();
  await expect(page.locator('body')).not.toContainText('R-OTHER-');
});

test('reviewer can find returned reports without offering an approval action', async ({ page }) => {
  await setup(page, 'reviewer');
  await page.getByRole('button', { name: 'Review queue', exact: true }).first().click();
  await page.getByRole('combobox', { name: 'Report status', exact: true }).selectOption('RETURNED');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await page.getByRole('button', { name: /R-RETURNED/ }).first().click();
  await expect(page.getByRole('button', { name: 'Review & approve', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Correct this report', exact: true })).toHaveCount(0);
  await expect(page.locator('body')).toContainText(ORIGINAL);
});

test('correction retains report/revision identity through uncertain and CSRF retries', async ({ page }) => {
  const state = await setup(page, 'submitter', 'correction-retry'); await openReturned(page);
  await page.getByRole('button', { name: 'Correct this report', exact: true }).click();
  await expect(page.getByLabel('Describe the issue')).toHaveValue(ORIGINAL);
  await page.getByLabel('Describe the issue').fill(UPDATED);
  await page.getByLabel('Private correction reason').fill(CORRECTION_REASON);
  await page.getByRole('button', { name: 'Submit correction', exact: true }).click();
  await page.getByRole('button', { name: 'Retry same submission', exact: true }).click();
  await expect(page.getByLabel('Describe the issue')).toBeDisabled();
  await expect(page.getByLabel('Private correction reason')).toBeDisabled();
  await expect(page.getByLabel('Private correction reason')).toHaveValue(CORRECTION_REASON);
  await page.getByRole('button', { name: 'Retry same submission', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your report was received.' })).toBeVisible();
  const writes = state.writes.filter(row => row.path === '/sync/operations/');
  expect(writes).toHaveLength(3); expect(new Set(writes.map(row => JSON.stringify(row.body))).size).toBe(1);
  expect(writes[0].body).toMatchObject({ report_id: REPORT, expected_revision: 1, correction_reason: CORRECTION_REASON, payload: { narrative: UPDATED } });
  expect(new Set(writes.map(row => row.key)).size).toBe(1); expect(writes[0].key).toBe(writes[0].body.operation_id);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

test('revision history opens retained original after a correction', async ({ page }) => {
  const state = await setup(page, 'submitter', 'normal', true);
  await page.getByRole('button', { name: 'Your reports', exact: true }).first().click();
  await page.getByRole('button', { name: /R-RETURNED/ }).first().click();
  await expect(page.locator('body')).toContainText(UPDATED);
  await page.getByRole('button', { name: 'Revision 1', exact: true }).click();
  await expect(page.locator('body')).toContainText(ORIGINAL);
  await expect(page.getByRole('button', { name: 'Correct this report', exact: true })).toHaveCount(0);
  expect(state.queries.some(row => row.path === `/reports/${REPORT}/revisions/1/`)).toBe(true);
  await page.screenshot({ path: '../.cache/m1-qa/expansion-history-desktop.png', fullPage: true });
});

test('stale correction cannot silently submit a newer revision', async ({ page }) => {
  const state = await setup(page, 'submitter', 'correction-conflict'); await openReturned(page);
  await page.getByRole('button', { name: 'Correct this report', exact: true }).click();
  await page.getByLabel('Describe the issue').fill(UPDATED);
  await page.getByLabel('Private correction reason').fill(CORRECTION_REASON);
  await page.getByRole('button', { name: 'Submit correction', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Reload report history', exact: true })).toBeVisible();
  expect(state.writes.filter(row => row.path === '/sync/operations/')).toHaveLength(1);
  await expect(page.getByRole('button', { name: 'Submit correction', exact: true })).toBeDisabled();
});

test('administrator searches accounts and has no report-review controls', async ({ page }) => {
  const state = await setup(page, 'administrator');
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'New report', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Review queue', exact: true })).toHaveCount(0);
  await page.getByLabel('Search accounts', { exact: true }).fill('alice');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Manage alice', exact: true })).toBeVisible();
  await expect.poll(() => state.queries.filter(row => row.path === '/administration/users/').at(-1)?.query.q).toBe('alice');
});

test('account creation confirms role and scope without storing the password', async ({ page }) => {
  const state = await setup(page, 'administrator');
  await page.getByRole('button', { name: 'Create account', exact: true }).first().click();
  await page.getByRole('textbox', { name: /^Username/ }).fill('fictional.new');
  await page.getByLabel('Display name', { exact: true }).fill('Fictional New User');
  await page.getByRole('combobox', { name: 'Role', exact: true }).selectOption('recipient');
  await page.getByRole('combobox', { name: 'Recipient channel', exact: true }).selectOption(CHANNEL.id);
  await page.getByLabel(/^Password/).fill('Fictional-Account!2026');
  await page.getByLabel('Confirm password', { exact: true }).fill('Fictional-Account!2026');
  await page.getByRole('button', { name: 'Create account', exact: true }).last().click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await page.getByRole('button', { name: 'Confirm account creation', exact: true }).click();
  await expect.poll(() => state.writes.filter(row => row.path === '/administration/users/' && row.method === 'POST').length).toBe(1);
  const write = state.writes.find(row => row.path === '/administration/users/' && row.method === 'POST')!;
  expect(write.body).toMatchObject({ username: 'fictional.new', role: 'recipient', unit_id: null, channel_id: CHANNEL.id });
  expect(state.queries.every(row => !JSON.stringify(row.query).includes('Fictional-Account'))).toBe(true);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
});

test('stale account edit preserves expected version and requires reload', async ({ page }) => {
  const state = await setup(page, 'administrator', 'admin-conflict');
  await page.getByRole('button', { name: 'Manage alice', exact: true }).click();
  await page.getByLabel('Display name', { exact: true }).fill('Fictional Alice Updated');
  await page.getByRole('button', { name: 'Review changes', exact: true }).click();
  await page.getByRole('button', { name: 'Save account changes', exact: true }).click();
  await expect(page.locator('body')).toContainText('Reload');
  const writes = state.writes.filter(row => row.method === 'PATCH');
  expect(writes).toHaveLength(1); expect(writes[0].body.expected_permission_version).toBe(2);
  await expect(page.getByRole('button', { name: 'Review changes', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Reload accounts', exact: true })).toBeVisible();
});

test('password reset sends the selected account version and clears password controls', async ({ page }) => {
  const state = await setup(page, 'administrator');
  await page.getByRole('button', { name: 'Reset password for alice', exact: true }).click();
  await page.getByLabel(/^Password/).fill('Fictional-Reset!2026');
  await page.getByLabel('Confirm password', { exact: true }).fill('Fictional-Reset!2026');
  await page.getByRole('button', { name: 'Review password reset', exact: true }).click();
  await page.getByRole('button', { name: 'Reset password', exact: true }).click();
  await expect.poll(() => state.writes.filter(row => row.path.endsWith('/password/')).length).toBe(1);
  expect(state.writes.find(row => row.path.endsWith('/password/'))!.body.expected_permission_version).toBe(2);
  await expect(page.locator('input[type="password"]')).toHaveCount(0);
});

test('lost administration authority clears account data from the workspace', async ({ page }) => {
  const state = await setup(page, 'administrator');
  await expect(page.getByRole('button', { name: 'Manage alice', exact: true })).toBeVisible();
  state.mode = 'admin-denied';
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('Fictional Alice');
});

test('administration form and account list fit a mobile viewport', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 }); await setup(page, 'administrator');
  await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole('button', { name: 'Create account', exact: true }).first().click();
  await expect(page.getByRole('textbox', { name: /^Username/ })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: '../.cache/m1-qa/expansion-administration-mobile.png', fullPage: true });
});

test('uncertain account creation clears passwords and requires reconciliation before another write', async ({ page }) => {
  const state = await setup(page, 'administrator', 'admin-uncertain');
  await page.getByRole('button', { name: 'Create account', exact: true }).first().click();
  await page.getByRole('textbox', { name: /^Username/ }).fill('fictional.pending');
  await page.getByLabel('Display name', { exact: true }).fill('Fictional Pending User');
  await page.getByRole('combobox', { name: 'Role', exact: true }).selectOption('administrator');
  await page.getByLabel(/^Password/).fill('Fictional-Pending!2026');
  await page.getByLabel('Confirm password', { exact: true }).fill('Fictional-Pending!2026');
  await page.getByRole('button', { name: 'Create account', exact: true }).last().click();
  await page.getByRole('button', { name: 'Confirm account creation', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Reload accounts', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create account', exact: true }).last()).toBeDisabled();
  await expect(page.getByLabel(/^Password/)).toHaveValue('');
  await expect(page.getByLabel('Confirm password', { exact: true })).toHaveValue('');
  expect(state.writes.filter(row => row.path === '/administration/users/' && row.method === 'POST')).toHaveLength(1);
  await page.getByRole('button', { name: 'Reload accounts', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Create account', exact: true }).first()).toBeVisible();
  expect(state.writes.filter(row => row.path === '/administration/users/' && row.method === 'POST')).toHaveLength(1);
});

test('correction requires an entered private reason and reset does not carry it to initial submission', async ({ page }) => {
  const state = await setup(page, 'submitter'); await openReturned(page);
  await page.getByRole('button', { name: 'Correct this report', exact: true }).click();
  await expect(page.getByLabel('Private correction reason')).toHaveValue('');
  await page.getByRole('button', { name: 'Submit correction', exact: true }).click();
  await expect(page.getByLabel('Private correction reason')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('Enter a private reason for this correction.', { exact: true })).toBeVisible();
  expect(state.writes.filter(row => row.path === '/sync/operations/')).toHaveLength(0);
  await page.getByLabel('Private correction reason').fill(CORRECTION_REASON);
  await page.getByRole('button', { name: 'Submit correction', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your report was received.' })).toBeVisible();
  const writes = state.writes.filter(row => row.path === '/sync/operations/');
  expect(writes).toHaveLength(1); expect(writes[0].body.correction_reason).toBe(CORRECTION_REASON);
  await page.getByRole('button', { name: 'Make another report', exact: true }).click();
  await expect(page.getByLabel('Private correction reason')).toHaveCount(0);
  await expect(page.getByLabel('Describe the issue')).toHaveValue('');
});
