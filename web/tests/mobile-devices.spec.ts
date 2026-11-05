import { expect, test, type Page, type Route } from '@playwright/test';

// Controlled browser fixtures only. Real session/CSRF enforcement, database
// revocation and Android denial require the separate isolated live-server gate.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const ID = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const STAMP = '2026-10-17T04:00:00.000000Z';
const REVOKED = '2026-10-17T05:00:00.000000Z';
const CANARY = 'SYNTHETIC_PRIVATE_RESPONSE_CANARY';
type Role = 'submitter' | 'reviewer' | 'recipient' | 'administrator';
const device = (overrides = {}) => ({ id: ID, label: 'Synthetic mobile phone', created_at: STAMP, last_authenticated_at: STAMP, revoked_at: null, ...overrides });
const list = (rows = [device()]) => ({ results: rows, count: rows.length });
const gate = () => { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve; }); return { promise, release }; };

async function setup(page: Page, role: Role = 'submitter') {
  const state = {
    authenticated: false, role, account: 1, lists: 0, listBody: list() as unknown, listStatus: 200,
    listHold: null as ReturnType<typeof gate> | null, revokeHold: null as ReturnType<typeof gate> | null,
    revokeMode: 'normal' as 'normal' | 'uncertain' | 'mismatched' | 'denied',
    writes: [] as { path: string; body: unknown; csrf: string | undefined; authorization: string | undefined }[],
    requests: [] as string[],
  };
  const unit = { id: '33333333-3333-4333-8333-333333333333', code: 'SIM-UNIT-01', name: 'Synthetic unit' };
  const channel = { id: '44444444-4444-4444-8444-444444444444', code: 'CH-DEMO-01', name: 'Synthetic channel' };
  const user = () => ({ id: state.account === 1 ? '55555555-5555-4555-8555-555555555555' : '66666666-6666-4666-8666-666666666666', username: role, display_name: `Synthetic ${role}`, role, unit: ['submitter', 'reviewer'].includes(role) ? unit : null, channel: role === 'administrator' ? null : channel, profile: 'DEMO-REDUCED' });
  const reply = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers: { 'Cache-Control': 'no-store' } });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice('/api/v1'.length);
    state.requests.push(path);
    if (path === '/auth/csrf/') return reply(route, 200, { csrf_token: 'synthetic-csrf-fixture' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, 200, { user: user() }); }
    if (path === '/auth/logout/') { state.authenticated = false; return reply(route, 200, { logged_out: true }); }
    if (path === '/me/') return reply(route, state.authenticated ? 200 : 403, state.authenticated ? { user: user() } : { code: 'AUTH_REQUIRED', message: 'Sign in.' });
    if (path === '/account/devices/') {
      state.lists++;
      const body = state.listBody, status = state.listStatus, hold = state.listHold;
      state.listHold = null;
      if (hold) await hold.promise;
      return reply(route, status, body);
    }
    if (path === `/account/devices/${ID}/revoke/`) {
      state.writes.push({ path, body: request.postDataJSON(), csrf: request.headers()['x-csrftoken'], authorization: request.headers()['authorization'] });
      if (state.revokeHold) await state.revokeHold.promise;
      if (state.revokeMode === 'denied') return reply(route, 404, { code: 'NOT_FOUND', message: CANARY });
      state.listBody = list([device({ revoked_at: REVOKED }), device({ id: OTHER, label: 'Other synthetic enrollment' })]);
      if (state.revokeMode === 'uncertain') return reply(route, 503, { code: 'SERVER_ERROR', message: CANARY });
      return reply(route, 200, { id: state.revokeMode === 'mismatched' ? OTHER : ID, revoked: true, revoked_at: REVOKED });
    }
    if (path === '/reports/' || path === '/review/queue/' || path === '/administration/users/' || path.endsWith('/feed/')) return reply(route, 200, { results: [], count: 0, page: 1, page_size: 10, total_pages: 1, refreshed_at: STAMP });
    if (path === '/administration/context/') return reply(route, 200, { units: [], channels: [], channel_sources: [] });
    return reply(route, 404, { code: 'NOT_FOUND', message: 'Unavailable synthetic fixture.' });
  });
  await page.goto(BASE);
  await signIn(page, role);
  return state;
}
async function signIn(page: Page, role: Role) {
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill('Synthetic-Password!2026');
  await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
}
async function account(page: Page) {
  await page.getByRole('button', { name: 'Account security', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Your mobile devices', exact: true })).toBeVisible();
}
async function confirm(page: Page) {
  await page.getByRole('button', { name: 'Review revocation for Synthetic mobile phone', exact: true }).click();
  await expect(page.getByRole('dialog', { name: 'Revoke mobile enrollment?' })).toBeVisible();
  await page.getByRole('button', { name: 'Revoke enrollment', exact: true }).click();
}

for (const role of ['submitter', 'reviewer', 'recipient', 'administrator'] as const) {
  test(`${role} can review own enrollment history without role or admin device APIs`, async ({ page }) => {
    const state = await setup(page, role);
    state.listBody = list([device(), device({ id: OTHER, label: 'Historical synthetic phone', revoked_at: REVOKED })]);
    await account(page);
    await expect(page.getByRole('article', { name: 'Mobile enrollment Synthetic mobile phone', exact: true })).toContainText('Not revoked');
    await expect(page.getByRole('article', { name: 'Mobile enrollment Historical synthetic phone', exact: true })).toContainText('Revoked');
    await expect(page.getByRole('button', { name: 'Review revocation for Historical synthetic phone' })).toHaveCount(0);
    expect(state.writes).toHaveLength(0);
    expect(state.requests.filter(path => path.includes('devices'))).toEqual(['/account/devices/']);
  });
}

test('keyboard confirmation can be cancelled, then one CSRF POST revokes only the selected enrollment', async ({ page }) => {
  const state = await setup(page); await account(page);
  const review = page.getByRole('button', { name: 'Review revocation for Synthetic mobile phone', exact: true });
  await review.focus(); await page.keyboard.press('Enter');
  await expect(page.getByRole('dialog')).toContainText('does not erase a disconnected phone');
  await expect(page.getByLabel('Current password', { exact: true })).toBeDisabled();
  expect(state.writes).toHaveLength(0);
  await page.keyboard.press('Escape'); await expect(page.getByRole('dialog')).toHaveCount(0);
  await expect(review).toBeFocused();
  await confirm(page);
  await expect(page.getByRole('article', { name: 'Mobile enrollment Synthetic mobile phone', exact: true })).toContainText('Revoked');
  await expect(page.getByRole('button', { name: 'Review revocation for Other synthetic enrollment', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  expect(state.writes).toEqual([{ path: `/account/devices/${ID}/revoke/`, body: {}, csrf: 'synthetic-csrf-fixture', authorization: undefined }]);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});

test('an outstanding revocation disables duplicate dispatch and cancellation', async ({ page }) => {
  const state = await setup(page); await account(page);
  const hold = gate(); state.revokeHold = hold;
  await confirm(page); await expect.poll(() => state.writes.length).toBe(1);
  const button = page.getByRole('button', { name: 'Revoking enrollment…', exact: true });
  await expect(button).toBeDisabled(); await expect(page.getByRole('button', { name: 'Cancel', exact: true })).toBeDisabled();
  await button.evaluate(element => (element as HTMLButtonElement).click());
  await page.keyboard.press('Escape'); await expect(page.getByRole('dialog')).toBeVisible();
  expect(state.writes).toHaveLength(1); hold.release();
  await expect(page.getByRole('dialog')).toHaveCount(0); expect(state.writes).toHaveLength(1);
});

for (const mode of ['uncertain', 'mismatched'] as const) {
  test(`${mode} revocation requires explicit read reconciliation and never repeats the POST`, async ({ page }) => {
    const state = await setup(page); await account(page); state.revokeMode = mode;
    const reads = state.lists; await confirm(page);
    await expect(page.getByRole('status').filter({ hasText: 'The revocation result is unconfirmed.' })).toBeVisible();
    expect(state.writes).toHaveLength(1); expect(state.lists).toBe(reads);
    await expect(page.getByRole('article')).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText(CANARY);
    await page.getByRole('button', { name: 'Refresh devices', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'refreshed server list confirms' })).toBeVisible();
    await expect(page.getByRole('article', { name: 'Mobile enrollment Synthetic mobile phone', exact: true })).toContainText('Revoked');
    expect(state.writes).toHaveLength(1);
  });
}

test('uncertain revocation with a still-active server row requires a new human confirmation', async ({ page }) => {
  const state = await setup(page); await account(page); state.revokeMode = 'uncertain'; await confirm(page);
  await expect(page.locator('body')).toContainText('The revocation result is unconfirmed.');
  state.listBody = list(); state.revokeMode = 'normal';
  await page.getByRole('button', { name: 'Refresh devices', exact: true }).click();
  await expect(page.locator('body')).toContainText('server currently lists this enrollment as not revoked');
  expect(state.writes).toHaveLength(1);
  await page.getByRole('button', { name: 'Review revocation for Synthetic mobile phone', exact: true }).click();
  expect(state.writes).toHaveLength(1);
  await page.getByRole('button', { name: 'Revoke enrollment', exact: true }).click();
  await expect.poll(() => state.writes.length).toBe(2);
});

test('unavailable device routes preserve the password form and never claim an empty list', async ({ page }) => {
  const state = await setup(page); state.listStatus = 404; state.listBody = { message: CANARY };
  await account(page); await expect(page.getByRole('alert')).toContainText('device list is unavailable');
  await expect(page.getByRole('heading', { name: 'No mobile enrollments', exact: true })).toHaveCount(0);
  await expect(page.getByLabel('Current password', { exact: true })).toBeEnabled();
  await expect(page.locator('body')).not.toContainText(CANARY);
});

test('a delayed device-list failure preserves password modal focus and its restored trigger', async ({ page }) => {
  const state = await setup(page);
  const hold = gate(); state.listHold = hold; state.listStatus = 503; state.listBody = { message: CANARY };
  await account(page); await expect.poll(() => state.lists).toBe(1);
  await page.getByLabel('Current password', { exact: true }).fill('Synthetic-Password!2026');
  await page.getByLabel('New password', { exact: true }).fill('Different-Synthetic!2026');
  await page.getByLabel('Confirm new password', { exact: true }).fill('Different-Synthetic!2026');
  const review = page.getByRole('button', { name: 'Review password change', exact: true });
  await review.focus(); await page.keyboard.press('Enter');
  const modal = page.getByRole('dialog', { name: 'Confirm password change', exact: true });
  const close = modal.getByRole('button', { name: 'Close confirmation', exact: true });
  await expect(close).toBeFocused();
  hold.release();
  await expect(page.getByRole('alert')).toContainText('device list is unavailable');
  await expect(close).toBeFocused();
  await page.keyboard.press('Tab'); await expect(modal.getByRole('button', { name: 'Cancel', exact: true })).toBeFocused();
  await page.keyboard.press('Shift+Tab'); await expect(close).toBeFocused();
  await page.keyboard.press('Escape'); await expect(modal).toHaveCount(0);
  await expect(review).toBeFocused();
  await expect(page.getByLabel('Current password', { exact: true })).toHaveValue('Synthetic-Password!2026');
  await expect(page.locator('body')).not.toContainText(CANARY);
  expect(state.requests.filter(path => path === '/auth/password/')).toHaveLength(0);
  expect(state.writes).toHaveLength(0);
});

test('a rejected revocation clears prior rows and hides server details until explicit refresh', async ({ page }) => {
  const state = await setup(page); await account(page); state.revokeMode = 'denied'; await confirm(page);
  await expect(page.getByRole('alert')).toContainText('revocation request was not accepted');
  await expect(page.getByRole('article')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText(CANARY);
  expect(state.writes).toHaveLength(1);
  await page.getByRole('button', { name: 'Refresh devices', exact: true }).click();
  await expect(page.getByRole('article')).toContainText('Not revoked');
  expect(state.writes).toHaveLength(1);
});

test('failed refresh removes earlier device details without claiming no enrollments', async ({ page }) => {
  const state = await setup(page); await account(page); await expect(page.getByRole('article')).toHaveCount(1);
  state.listStatus = 503; state.listBody = { message: CANARY };
  await page.getByRole('button', { name: 'Refresh devices', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('device list is unavailable');
  await expect(page.getByRole('article')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'No mobile enrollments', exact: true })).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText('Synthetic mobile phone');
  await expect(page.locator('body')).not.toContainText(CANARY);
});

const invalidLists: [string, unknown][] = [
  ['extra private field', list([device({ fingerprint: CANARY })])],
  ['duplicate enrollment', list([device(), device()])],
  ['incorrect count', { results: [device()], count: 2 }],
  ['too many entries', list(Array.from({ length: 101 }, (_, n) => device({ id: `a0000000-0000-4000-8000-${String(n).padStart(12, '0')}` })))],
  ['invalid date', list([device({ created_at: '2026-02-30T04:00:00Z' })])],
  ['unknown revocation state', list([device({ revoked_at: false })])],
  ['control character label', list([device({ label: `Synthetic\u202e${CANARY}` })])],
  ['oversized body', { results: [], count: 0, extra: CANARY.repeat(6000) }],
];
for (const [name, body] of invalidLists) {
  test(`device list fails closed for ${name}`, async ({ page }) => {
    const state = await setup(page); state.listBody = body; await account(page);
    await expect(page.getByRole('alert')).toContainText('could not be verified');
    await expect(page.getByRole('article')).toHaveCount(0);
    await expect(page.getByRole('heading', { name: 'No mobile enrollments', exact: true })).toHaveCount(0);
    await expect(page.locator('body')).not.toContainText(CANARY); expect(state.writes).toHaveLength(0);
  });
}

test('refresh removes earlier rows immediately and an access denial clears the workspace', async ({ page }) => {
  const state = await setup(page); await account(page);
  await expect(page.getByRole('article')).toHaveCount(1);
  const hold = gate(); state.listHold = hold; state.listStatus = 403; state.listBody = { code: 'AUTH_REQUIRED', message: CANARY };
  await page.getByRole('button', { name: 'Refresh devices', exact: true }).click();
  await expect(page.getByRole('article')).toHaveCount(0);
  await expect(page.getByRole('status').filter({ hasText: 'Checking your mobile enrollments' })).toBeVisible();
  hold.release(); await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  await expect(page.locator('body')).not.toContainText('Synthetic mobile phone');
  await expect(page.locator('body')).not.toContainText(CANARY);
});

test('a late old-account list cannot reappear after sign-out and a new account sign-in', async ({ page }) => {
  const state = await setup(page); const hold = gate(); state.listHold = hold;
  await account(page); await expect.poll(() => state.lists).toBe(1);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
  state.account = 2; state.listBody = list([]);
  await signIn(page, 'submitter'); await account(page);
  await expect(page.getByRole('heading', { name: 'No mobile enrollments', exact: true })).toBeVisible();
  const oldResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/account/devices/');
  hold.release(); await oldResponse;
  await page.evaluate(() => new Promise<void>(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(page.getByRole('heading', { name: 'No mobile enrollments', exact: true })).toBeVisible();
  await expect(page.getByRole('article')).toHaveCount(0);
  await expect(page.locator('body')).not.toContainText('Synthetic mobile phone');
});

test('device labels stay escaped and the security page fits a narrow screen', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const state = await setup(page); state.listBody = list([device({ label: '<img src=x onerror=alert(1)>' })]);
  await page.getByRole('button', { name: 'Open navigation', exact: true }).click(); await account(page);
  await expect(page.getByRole('article')).toContainText('<img src=x onerror=alert(1)>');
  await expect(page.getByRole('article').locator('img')).toHaveCount(0);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});
