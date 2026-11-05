import { expect, test, type Page, type Route } from '@playwright/test';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Actual compiled UI, controlled synthetic API failures. These checks do not
// establish database provisioning, real account login or backend authorization.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const UNAVAILABLE = 'Workspace server unavailable';
const CANARY = 'UNTRUSTED-UPSTREAM-BODY-RESPONSE';
const PRIVATE_REFERENCE = 'PRIVATE-RECOVERY-REPORT-82';
const USER = {
  id: '77777777-7777-4777-8777-777777777777', username: 'submitter', display_name: 'Demo Submitter', role: 'submitter',
  unit: { id: '22222222-2222-4222-8222-222222222222', code: 'SIM-UNIT-01', name: 'Simulated Support Unit' },
  channel: { id: '11111111-1111-4111-8111-111111111111', code: 'CH-DEMO-01', name: 'Maintenance Coordination' }, profile: 'DEMO-REDUCED',
};
type Failure = 'html-200' | 'html-404' | 'html-502' | 'json-503' | 'network' | 'malformed';
type EndpointMode = Failure | 'normal';
const failures: Failure[] = ['html-200', 'html-404', 'html-502', 'json-503', 'network', 'malformed'];
const json = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });

async function failureReply(route: Route, failure: Failure) {
  if (failure === 'network') return route.abort('connectionfailed');
  if (failure === 'json-503') return json(route, 503, { code: 'UNAVAILABLE', message: CANARY });
  if (failure === 'malformed') return json(route, 200, { unexpected: CANARY });
  return route.fulfill({ status: Number(failure.slice(5)), contentType: 'text/html', body: '<!doctype html><h1>' + CANARY + '</h1>' });
}

async function fixture(page: Page, me: EndpointMode = 'normal', anonymousStatus = 401) {
  const state = {
    authenticated: false, me, csrf: 'normal' as EndpointMode, login: 'normal' as EndpointMode, logout: 'normal' as EndpointMode,
    wrongPassword: false, privateReport: false, reportsDenied: 0, calls: [] as { path: string; method: string }[], errors: 0,
  };
  page.on('pageerror', () => state.errors++);
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice('/api/v1'.length);
    state.calls.push({ path, method: request.method() });
    if (path === '/me/') {
      if (state.me !== 'normal') return failureReply(route, state.me);
      return json(route, state.authenticated ? 200 : anonymousStatus, state.authenticated ? { user: USER } : { code: 'AUTH_REQUIRED', message: 'Sign in to continue.' });
    }
    if (path === '/auth/csrf/') {
      if (state.csrf !== 'normal') return failureReply(route, state.csrf);
      return json(route, 200, { csrf_token: 'synthetic-recovery-fixture-token' });
    }
    if (path === '/auth/login/') {
      if (state.login !== 'normal') return failureReply(route, state.login);
      if (state.wrongPassword) return json(route, 401, { code: 'LOGIN_FAILED', message: 'The username or password was not accepted.' });
      state.authenticated = true;
      return json(route, 200, { user: USER });
    }
    if (path === '/auth/logout/') {
      if (state.logout !== 'normal') return failureReply(route, state.logout);
      state.authenticated = false;
      return json(route, 200, { logged_out: true });
    }
    if (path === '/reports/') {
      if (state.reportsDenied) return route.fulfill({ status: state.reportsDenied, contentType: 'text/html', body: '<h1>' + CANARY + '</h1>' });
      const results = state.privateReport ? [{ id: '33333333-3333-4333-8333-333333333333', reference: PRIVATE_REFERENCE, category: 'INFRASTRUCTURE', urgency: 'ROUTINE', area_label: 'Area C', created_at: '2026-10-13T02:00:00Z', observed_date: '2026-10-13', revision_no: 1, status: 'PENDING', variant_id: null, feedback: null }] : [];
      return json(route, 200, { results, count: results.length, page: 1, page_size: 10, total_pages: 1 });
    }
    return json(route, 404, { code: 'NOT_FOUND', message: 'Unavailable fixture route.' });
  });
  await page.goto(BASE);
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  return state;
}

async function blocked(page: Page) {
  await expect(page.getByRole('heading', { name: UNAVAILABLE, exact: true })).toBeVisible();
  await expect(page.getByLabel('Username', { exact: true })).toBeDisabled();
  await expect(page.getByLabel('Password', { exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Check connection', exact: true })).toBeEnabled();
  await expect(page.locator('body')).not.toContainText(CANARY);
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toHaveCount(0);
}

async function enterCredentials(page: Page) {
  await page.getByLabel('Username', { exact: true }).fill('submitter');
  await page.getByLabel('Password', { exact: true }).fill('Synthetic fixture credential');
  await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
}

for (const failure of failures) {
  test(`initial ${failure} backend response blocks credentials without displaying its body`, async ({ page }) => {
    const state = await fixture(page, failure);
    await blocked(page);
    await page.getByText('Start from PowerShell instead', { exact: true }).click();
    await expect(page.getByText('python infra/start_local.py', { exact: true })).toBeVisible();
    expect(state.calls.every(call => call.method === 'GET')).toBe(true);
    expect(state.calls.some(call => call.path === '/auth/login/')).toBe(false);
    expect(state.errors).toBe(0);
  });
}

for (const status of [401, 403]) {
  test(`valid anonymous JSON ${status} permits genuine login`, async ({ page }) => {
    const state = await fixture(page, 'normal', status);
    await expect(page.getByRole('heading', { name: UNAVAILABLE, exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeEnabled();
    await enterCredentials(page);
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
    expect(state.calls.filter(call => call.path === '/auth/login/' && call.method === 'POST')).toHaveLength(1);
    expect(state.errors).toBe(0);
  });
}

test('connection retry uses only a fresh CSRF read and never adopts an existing session or submits credentials', async ({ page }) => {
  const state = await fixture(page, 'network');
  await blocked(page);
  state.me = 'normal'; state.authenticated = true;
  const callsBefore = state.calls.length;
  await page.getByRole('button', { name: 'Check connection', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeEnabled();
  await expect(page.getByRole('heading', { name: UNAVAILABLE, exact: true })).toHaveCount(0);
  expect(state.calls.slice(callsBefore)).toEqual([{ path: '/auth/csrf/', method: 'GET' }]);
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toHaveCount(0);
});

for (const failure of ['html-200', 'json-503', 'malformed'] as Failure[]) {
  test(`failed ${failure} connection retry keeps the form blocked and can recover later`, async ({ page }) => {
    const state = await fixture(page, 'network');
    await blocked(page); state.csrf = failure;
    await page.getByRole('button', { name: 'Check connection', exact: true }).click();
    await blocked(page);
    state.csrf = 'normal';
    await page.getByRole('button', { name: 'Check connection', exact: true }).click();
    await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeEnabled();
    expect(state.calls.filter(call => call.path === '/auth/login/')).toHaveLength(0);
    expect(state.errors).toBe(0);
  });
}

test('backend loss at CSRF between session check and sign-in does not transmit credentials', async ({ page }) => {
  const state = await fixture(page); state.csrf = 'network';
  await enterCredentials(page);
  await blocked(page);
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  expect(state.calls.filter(call => call.path === '/auth/login/')).toHaveLength(0);
});

test('wrong credentials stay a credential error with enabled retry and no setup claim', async ({ page }) => {
  const state = await fixture(page); state.wrongPassword = true;
  await enterCredentials(page);
  await expect(page.getByText('The username or password was not accepted.', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: UNAVAILABLE, exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeEnabled();
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  state.wrongPassword = false;
  await enterCredentials(page);
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  expect(state.errors).toBe(0);
});

for (const failure of ['html-200', 'json-503', 'malformed'] as Failure[]) {
  test(`unconfirmed ${failure} login response cannot open the workspace or retain password`, async ({ page }) => {
    const state = await fixture(page); state.login = failure;
    await enterCredentials(page);
    await blocked(page);
    await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
    expect(state.calls.filter(call => call.path === '/auth/login/')).toHaveLength(1);
    expect(state.errors).toBe(0);
  });
}

test('connection recovery cannot bypass unconfirmed server sign-out', async ({ page }) => {
  const state = await fixture(page);
  await enterCredentials(page);
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  state.logout = 'network';
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await blocked(page);
  await expect(page.getByRole('button', { name: /Complete server sign-out/ })).toBeVisible();
  const count = state.calls.filter(call => call.path === '/auth/login/').length;
  await page.getByRole('button', { name: 'Check connection', exact: true }).click();
  await expect(page.getByRole('heading', { name: UNAVAILABLE, exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeDisabled();
  await page.getByLabel('Username', { exact: true }).fill('submitter');
  await page.getByLabel('Password', { exact: true }).fill('Synthetic fixture credential');
  await page.locator('form').evaluate(node => (node as HTMLFormElement).requestSubmit());
  await page.waitForTimeout(200);
  expect(state.calls.filter(call => call.path === '/auth/login/')).toHaveLength(count);
  state.logout = 'normal';
  await page.getByRole('button', { name: /Complete server sign-out/ }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: /Complete server sign-out/ })).toHaveCount(0);
  expect(state.errors).toBe(0);
});

for (const status of [401, 403]) {
  test(`protected HTML ${status} clears earlier private workspace content`, async ({ page }) => {
    const state = await fixture(page); state.privateReport = true;
    await enterCredentials(page);
    await expect(page.locator('body')).toContainText(PRIVATE_REFERENCE);
    state.reportsDenied = status;
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
    await expect(page.locator('body')).not.toContainText(PRIVATE_REFERENCE);
    await expect(page.locator('body')).not.toContainText(CANARY);
    await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toHaveCount(0);
    expect(state.errors).toBe(0);
  });
}

for (const width of [1440, 390]) test(`real preview recovery panel ${width}px remains usable without credential writes`, async ({ page }) => {
  await page.setViewportSize({ width, height: width < 500 ? 844 : 1000 });
  let writes = 0, errors = 0;
  page.on('request', request => { if (!['GET', 'HEAD'].includes(request.method())) writes++; });
  page.on('pageerror', () => errors++);
  await page.goto(BASE);
  await blocked(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  const shots = new URL('../../.cache/login-recovery-qa/', import.meta.url);
  await mkdir(shots, { recursive: true });
  await page.screenshot({ path: fileURLToPath(new URL(`unavailable-${width}.png`, shots)), fullPage: true, animations: 'disabled' });
  await page.getByRole('link', { name: /Back to home/ }).click();
  await expect(page).toHaveURL(new URL('/', BASE).toString());
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Clarity in the field.');
  expect(writes).toBe(0); expect(errors).toBe(0);
});
