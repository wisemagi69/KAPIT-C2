import { expect, test, type Page, type Route } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import path from 'node:path';

// Real Chromium + real built assets. The API fixtures below exercise UI states
// only. They are deliberately not evidence of Django/PostgreSQL enforcement.
const URL = new globalThis.URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const OUTPUT = path.resolve('..', '.cache', 'm1-qa');
const CHANNEL = { id: '11111111-1111-4111-8111-111111111111', code: 'CH-DEMO-01', name: 'Demo maintenance channel' };
const UNIT = { id: '22222222-2222-4222-8222-222222222222', code: 'SIM-UNIT-01', name: 'Simulated maintenance unit' };
const REPORT_ID = '33333333-3333-4333-8333-333333333333';
const VARIANT_ID = '44444444-4444-4444-8444-444444444444';
const PUBLICATION_ID = '55555555-5555-4555-8555-555555555555';
const REVISION_ID = '66666666-6666-4666-8666-666666666666';
const SOURCE_CANARY = 'PRIVATE-UI-CANARY-82';
const timestamp = '2026-10-13T02:00:00Z';
const payload = { observed_at: timestamp, category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', site_label: 'Fictional Site C-14', reporter_label: 'Fictional Reporter A', narrative: SOURCE_CANARY + ' <script>window.fixtureScriptExecuted=true</script>', assistance_requested: 'Repair assistance' };
const summary = { id: REPORT_ID, reference: 'KPT-QA-001', category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', created_at: timestamp, observed_date: '2026-10-13', revision_no: 1, status: 'AWAITING_REVIEW', variant_id: VARIANT_ID, feedback: null };
const projection = { title: 'Infrastructure maintenance', text: 'A support unit reports a maintenance issue in Area C; repair assistance requested.', category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', assistance_requested: 'Repair assistance', observed_date: '2026-10-13', verification: 'Human reviewed', profile: 'DEMO-REDUCED' };
const binding = { revision_id: REVISION_ID, revision_no: 1, candidate_hash: 'a'.repeat(64), policy_version: 'demo-policy-v1', policy_hash: 'b'.repeat(64), profile: 'DEMO-REDUCED', channel_ids: [CHANNEL.id] };
const publication = { id: PUBLICATION_ID, published_at: timestamp, channel: CHANNEL, projection };
type Mode = 'normal' | 'submit-retry' | 'submit-csrf-retry' | 'decision-retry' | 'decision-csrf-retry' | 'stale' | 'feed-denied' | 'feed-missing' | 'feed-failure' | 'logout-failure' | 'empty-feed';

async function fixture(page: Page, role: 'submitter' | 'reviewer' | 'recipient', mode: Mode = 'normal') {
  const state = { authenticated: false, contextChanged: false, mode, submitPosts: [] as string[], decisionPosts: [] as string[], keys: [] as string[], requests: [] as string[], reports: [] as Record<string, unknown>[] };
  const user = { id: '77777777-7777-4777-8777-777777777777', username: role, display_name: role === 'submitter' ? 'Demo Submitter' : role === 'reviewer' ? 'Demo Reviewer' : 'Demo Recipient', role, unit: role === 'recipient' ? null : UNIT, channel: CHANNEL, profile: 'DEMO-REDUCED' };
  const answer = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers: { 'Cache-Control': 'no-store' } });
  await page.route('**/api/v1/**', async route => {
    const request = route.request();
    const endpoint = new globalThis.URL(request.url()).pathname.slice('/api/v1'.length);
    state.requests.push(endpoint);
    if (endpoint === '/auth/csrf/') return answer(route, 200, { csrf_token: 'fixture-token-for-ui-only' });
    if (endpoint === '/auth/login/') {
      const body = request.postDataJSON();
      if (body.username !== role || body.password !== 'DemoMaintenance!2026') return answer(route, 403, { code: 'AUTH_REQUIRED', message: 'The account could not be verified.' });
      state.authenticated = true; return answer(route, 200, { user });
    }
    if (endpoint === '/me/') return answer(route, state.authenticated ? 200 : 403, state.authenticated ? { user: state.contextChanged ? { ...user, id: '99999999-9999-4999-8999-999999999999' } : user } : { code: 'AUTH_REQUIRED', message: 'Sign in to continue.' });
    if (endpoint === '/auth/logout/') {
      if (state.mode === 'logout-failure') return answer(route, 503, { code: 'UNAVAILABLE', message: 'Unavailable.' });
      state.authenticated = false; return answer(route, 200, { logged_out: true });
    }
    if (endpoint === '/reports/') return answer(route, 200, { results: state.reports, count: state.reports.length, page: 1, page_size: 10, total_pages: Math.max(1, Math.ceil(state.reports.length / 10)) });
    if (endpoint === '/sync/operations/') {
      state.submitPosts.push(request.postData()!); state.keys.push(request.headers()['idempotency-key']);
      if (['submit-retry', 'submit-csrf-retry'].includes(state.mode) && state.submitPosts.length === 1) return answer(route, 503, { code: 'UNAVAILABLE', message: 'Receipt could not be confirmed.' });
      if (state.mode === 'submit-csrf-retry' && state.submitPosts.length === 2) return answer(route, 403, { code: 'CSRF_FAILED', message: 'Refresh the CSRF token and retry.' });
      const body = request.postDataJSON();
      state.reports = [{ ...summary, id: body.report_id, status: 'PENDING', variant_id: null }];
      return answer(route, 201, { operation_id: body.operation_id, report_id: body.report_id, revision_id: REVISION_ID, revision_no: 1, delivery_status: 'RECEIVED', processing_status: 'PENDING', shared: false });
    }
    if (endpoint === '/review/queue/') return answer(route, 200, { results: [summary], count: 1, page: 1, page_size: 10, total_pages: 1 });
    if (endpoint === `/variants/${VARIANT_ID}/review/`) return answer(route, 200, { report: summary, source: payload, candidate: projection, warnings: ['Private labels and narrative are excluded from the reduced candidate.'], binding });
    if (endpoint === `/variants/${VARIANT_ID}/decisions/`) {
      state.decisionPosts.push(request.postData()!); state.keys.push(request.headers()['idempotency-key']);
      if (state.mode === 'stale') return answer(route, 409, { code: 'STALE_REVIEW', message: 'Reload before deciding.' });
      if (['decision-retry', 'decision-csrf-retry'].includes(state.mode) && state.decisionPosts.length === 1) return answer(route, 503, { code: 'UNAVAILABLE', message: 'Decision could not be confirmed.' });
      if (state.mode === 'decision-csrf-retry' && state.decisionPosts.length === 2) return answer(route, 403, { code: 'CSRF_FAILED', message: 'Refresh the CSRF token and retry.' });
      const body = request.postDataJSON();
      return answer(route, 200, { decision_id: '88888888-8888-4888-8888-888888888888', action: body.action, publication_ids: body.action === 'APPROVE' ? [PUBLICATION_ID] : [], report_status: body.action === 'APPROVE' ? 'APPROVED' : body.action === 'RETURN' ? 'RETURNED' : 'REJECTED' });
    }
    if (endpoint === `/channels/${CHANNEL.id}/feed/`) {
      if (state.mode === 'feed-denied') return answer(route, 403, { code: 'SCOPE_DENIED', message: 'Current channel access is unavailable.' });
      if (state.mode === 'feed-missing') return answer(route, 404, { code: 'NOT_FOUND', message: 'Unavailable.' });
      if (state.mode === 'feed-failure') return answer(route, 503, { code: 'UNAVAILABLE', message: 'Refresh is unavailable.' });
      const params = new globalThis.URL(request.url()).searchParams;
      const q = (params.get('q') || '').toLowerCase();
      const matches = !q || [projection.title, projection.text, projection.area_label, projection.assistance_requested].join(' ').toLowerCase().includes(q);
      const results = state.mode === 'empty-feed' || !matches ? [] : [publication];
      return answer(route, 200, { results, count: results.length, page: Number(params.get('page') || 1), page_size: Number(params.get('page_size') || 10), total_pages: 1, refreshed_at: new Date().toISOString() });
    }
    if (endpoint === `/publications/${PUBLICATION_ID}/`) return answer(route, 200, publication);
    return answer(route, 404, { code: 'UNAVAILABLE', message: 'Unavailable fixture route.' });
  });
  await page.goto(URL);
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill('DemoMaintenance!2026');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('heading', { name: `Welcome, ${user.display_name}.` })).toBeVisible();
  return state;
}
async function screenshot(page: Page, name: string) {
  await mkdir(OUTPUT, { recursive: true });
  await page.screenshot({ path: path.join(OUTPUT, name), fullPage: true, animations: 'disabled' });
}
async function openReview(page: Page) {
  await page.getByRole('button', { name: 'Review KPT-QA-001', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Original report' })).toBeVisible();
}
async function approve(page: Page) {
  await page.getByRole('button', { name: 'Review & approve' }).click();
  const confirm = page.getByRole('button', { name: 'Approve & share' });
  await expect(confirm).toBeDisabled();
  await expect(page.getByRole('dialog')).toContainText(CHANNEL.code);
  await page.getByRole('checkbox').check();
  await confirm.click();
}

test('built sign-in page accepts an anonymous API response and validates empty credentials', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/v1/me/', route => route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ code: 'AUTH_REQUIRED', message: 'Sign in to continue.' }) }));
  await page.goto(URL);
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByText('Enter your issued username and password.')).toBeVisible();
  expect(errors).toEqual([]);
});

test('source form rejects blank private fields and uncertain retry preserves body/key', async ({ page }) => {
  const state = await fixture(page, 'submitter', 'submit-retry');
  await page.getByRole('button', { name: 'New report', exact: true }).first().click();
  await page.getByRole('button', { name: 'Submit report', exact: true }).click();
  await expect(page.getByText('Check the highlighted fields before submitting.')).toBeVisible();
  expect(state.submitPosts).toHaveLength(0);
  await page.getByLabel('Reporter label').fill('Fictional Reporter A');
  await page.getByLabel('Site label').fill('Fictional Site C-14');
  await page.getByLabel('Describe the issue').fill(SOURCE_CANARY);
  await screenshot(page, 'report-form-desktop.png');
  await page.getByRole('button', { name: 'Submit report', exact: true }).click();
  await expect(page.getByText('Receipt not yet confirmed.', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Describe the issue')).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same submission' }).click();
  await expect(page.getByRole('heading', { name: 'Your report was received.' })).toBeVisible();
  expect(state.submitPosts).toHaveLength(2); expect(state.submitPosts[0]).toBe(state.submitPosts[1]);
  expect(JSON.parse(state.submitPosts[0])).not.toHaveProperty('correction_reason');
  expect(state.keys[0]).toBe(state.keys[1]); expect(state.keys[0]).toBe(JSON.parse(state.submitPosts[0]).operation_id);
  await expect(page.getByText('this receipt does not mean your report has been shared.', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }))).toEqual({ local: 0, session: 0 });
});

test('visiting account security preserves an uncertain submission and its exact retry identity', async ({ page }) => {
  const state = await fixture(page, 'submitter', 'submit-retry');
  await page.getByRole('button', { name: 'New report', exact: true }).first().click();
  await page.getByLabel('Reporter label').fill('Fictional Reporter A');
  await page.getByLabel('Site label').fill('Fictional Site C-14');
  await page.getByLabel('Describe the issue').fill(SOURCE_CANARY);
  await page.getByRole('button', { name: 'Submit report', exact: true }).click();
  await expect(page.getByText('Receipt not yet confirmed.', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Account security', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Account security', exact: true })).toBeVisible();
  await expect(page.getByLabel('Describe the issue')).not.toBeVisible();
  await page.getByRole('button', { name: 'New report', exact: true }).first().click();
  await expect(page.getByLabel('Describe the issue')).toHaveValue(SOURCE_CANARY);
  await expect(page.getByLabel('Describe the issue')).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same submission', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your report was received.' })).toBeVisible();
  expect(state.submitPosts).toHaveLength(2);
  expect(state.submitPosts[0]).toBe(state.submitPosts[1]);
  expect(state.keys[0]).toBe(state.keys[1]);
});

test('recipient requests only publication routes and searches the approved fixture dataset', async ({ page }) => {
  const state = await fixture(page, 'recipient');
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(SOURCE_CANARY);
  await expect(page.getByRole('button', { name: 'New report', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Review queue', exact: true })).toHaveCount(0);
  await screenshot(page, 'recipient-desktop.png');
  await page.getByRole('searchbox').fill('absent search term');
  await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No matching publications' })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await page.getByRole('button', { name: 'Read update' }).click();
  await expect(page.getByRole('heading', { name: 'Approved reduced representation' })).toBeVisible();
  expect(state.requests.some(endpoint => endpoint.includes('/reports') || endpoint.includes('/variants') || endpoint.includes('/review'))).toBe(false);
});

test('recipient channel403 clears the workspace immediately', async ({ page }) => {
  const state = await fixture(page, 'recipient');
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
  state.mode = 'feed-denied';
  await page.getByRole('button', { name: 'Refresh now' }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(projection.text);
});

test('recipient server failure dates retained approved content and marks failed refresh', async ({ page }) => {
  const state = await fixture(page, 'recipient');
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
  state.mode = 'feed-failure';
  await page.getByRole('button', { name: 'Refresh now' }).click();
  await expect(page.getByText('Refresh failed · previously authorized content')).toBeVisible();
  await expect(page.getByText(/Last successful refresh/)).toBeVisible();
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
});

test('review requires explicit whole-content confirmation and preserves exact binding', async ({ page }) => {
  const state = await fixture(page, 'reviewer'); await openReview(page);
  await expect(page.locator('body')).toContainText(SOURCE_CANARY);
  expect(await page.evaluate(() => (window as Window & { fixtureScriptExecuted?: boolean }).fixtureScriptExecuted)).toBeUndefined();
  await approve(page);
  await expect(page.getByText('Approval committed.', { exact: true })).toBeVisible();
  expect(state.decisionPosts).toHaveLength(1);
  const request = JSON.parse(state.decisionPosts[0]); expect(request.expected).toEqual(binding); expect(request.action).toBe('APPROVE'); expect(state.keys[0]).toBe(request.operation_id);
});

test('stale review409 requires reload and disables further decisions', async ({ page }) => {
  const state = await fixture(page, 'reviewer', 'stale'); await openReview(page); await approve(page);
  await expect(page.getByText('This review is no longer current. Reload before making any decision.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review & approve' })).toBeDisabled();
  expect(state.decisionPosts).toHaveLength(1);
});

test('uncertain decision retry retains the same operation, tuple and action', async ({ page }) => {
  const state = await fixture(page, 'reviewer', 'decision-retry'); await openReview(page); await approve(page);
  await expect(page.getByText('Decision result not yet confirmed.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same decision' }).click();
  await expect(page.getByText('Approval committed.', { exact: true })).toBeVisible();
  expect(state.decisionPosts).toHaveLength(2); expect(state.decisionPosts[0]).toBe(state.decisionPosts[1]); expect(state.keys[0]).toBe(state.keys[1]);
});

test('return requires private feedback and does not claim publication', async ({ page }) => {
  const state = await fixture(page, 'reviewer'); await openReview(page);
  await page.getByRole('button', { name: 'Return for correction', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Return report', exact: true })).toBeDisabled();
  await page.getByLabel('Private reason').fill('Use a complete fictional maintenance description.');
  await page.getByRole('button', { name: 'Return report', exact: true }).click();
  await expect(page.getByText('Report returned for correction.', { exact: true })).toBeVisible();
  expect(JSON.parse(state.decisionPosts[0]).action).toBe('RETURN');
  await expect(page.getByText('No publication was created.', { exact: false })).toBeVisible();
});

test('recipient empty state does not reveal pending totals', async ({ page }) => {
  await fixture(page, 'recipient', 'empty-feed');
  await expect(page.getByRole('heading', { name: 'No approved reports available' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(SOURCE_CANARY);
  await expect(page.locator('body')).not.toContainText('KPT-QA-001');
});

test('unconfirmed logout clears private workspace and blocks a new login', async ({ page }) => {
  await fixture(page, 'recipient', 'logout-failure');
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(projection.text);
  await expect(page.getByRole('button', { name: 'Sign in to workspace' })).toBeDisabled();
  await expect(page.getByRole('button', { name: /Complete server sign-out/ })).toBeVisible();
});

test('mobile workspace and report form fit screen and navigation works', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await fixture(page, 'submitter');
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await page.getByRole('button', { name: 'New report', exact: true }).first().click();
  await expect(page.getByRole('heading', { name: 'Make a maintenance report' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect.poll(() => page.locator('.sidebar').evaluate(element => element.getBoundingClientRect().right)).toBeLessThanOrEqual(0);
  await expect(page.locator('.skip-link')).not.toBeInViewport();
  await screenshot(page, 'report-form-mobile.png');
});

test('uncertain source operation survives a later CSRF failure without a new identity', async ({ page }) => {
  const state = await fixture(page, 'submitter', 'submit-csrf-retry');
  await page.getByRole('button', { name: 'New report', exact: true }).first().click();
  await page.getByLabel('Reporter label').fill('Fictional Reporter A');
  await page.getByLabel('Site label').fill('Fictional Site C-14');
  await page.getByLabel('Describe the issue').fill(SOURCE_CANARY);
  await page.getByRole('button', { name: 'Submit report', exact: true }).click();
  await page.getByRole('button', { name: 'Retry same submission' }).click();
  await expect(page.getByText('Refresh the CSRF token and retry.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retry same submission' })).toBeVisible();
  await expect(page.getByLabel('Describe the issue')).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same submission' }).click();
  await expect(page.getByRole('heading', { name: 'Your report was received.' })).toBeVisible();
  expect(state.submitPosts).toHaveLength(3); expect(new Set(state.submitPosts).size).toBe(1); expect(new Set(state.keys).size).toBe(1);
});

test('uncertain review decision survives a later CSRF failure without losing its tuple', async ({ page }) => {
  const state = await fixture(page, 'reviewer', 'decision-csrf-retry'); await openReview(page); await approve(page);
  await page.getByRole('button', { name: 'Retry same decision' }).click();
  await expect(page.getByText('Refresh the CSRF token and retry.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Retry same decision' })).toBeVisible();
  await page.getByRole('button', { name: 'Retry same decision' }).click();
  await expect(page.getByText('Approval committed.', { exact: true })).toBeVisible();
  expect(state.decisionPosts).toHaveLength(3); expect(new Set(state.decisionPosts).size).toBe(1); expect(new Set(state.keys).size).toBe(1);
});

test('mobile closed navigation does not place hidden controls in the keyboard path', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await fixture(page, 'submitter');
  await page.evaluate(() => (document.activeElement as HTMLElement)?.blur());
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to workspace' })).toBeFocused();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('button', { name: 'Open navigation' })).toBeFocused();
});

test('recipient grant404 removes earlier content and shows a safe access state', async ({ page }) => {
  const state = await fixture(page, 'recipient');
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
  state.mode = 'feed-missing';
  await page.getByRole('button', { name: 'Refresh now' }).click();
  await expect(page.getByRole('heading', { name: 'Channel access unavailable' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText(projection.text);
});

test('a changed account context from me clears earlier workspace memory', async ({ page }) => {
  const state = await fixture(page, 'recipient');
  await expect(page.getByRole('button', { name: projection.title, exact: true })).toBeVisible();
  state.contextChanged = true;
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.getByText('Your account context changed. Sign in again to reload current permissions.')).toBeVisible();
  await expect(page.locator('body')).not.toContainText(projection.text);
});
