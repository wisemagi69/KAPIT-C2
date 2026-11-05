import { expect, test, type Page, type Route } from '@playwright/test';
import { parseReportActivity } from '../src/reportActivity';

// Synthetic browser responses establish UI behavior, not real authorization or
// database acceptance. The root runs browsers against the existing local preview.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const statuses = ['PENDING', 'PROCESSING', 'AWAITING_REVIEW', 'APPROVED', 'RETURNED', 'REJECTED', 'FAILED'];
const activity = () => ({ total: 78, by_status: Object.fromEntries(statuses.map((status, index) => [status, index + 8])), unclassified: 1 });

async function setup(page: Page, role: 'submitter' | 'reviewer' = 'submitter', metadata: unknown = activity()) {
  const state = { authenticated: false, metadata, failure: false, revoked: false, queries: [] as Record<string, string>[], hold: null as Promise<void> | null };
  const unit = { id: '22222222-2222-4222-8222-222222222222', code: 'SIM-UNIT-01', name: 'Synthetic unit' };
  const user = { id: '77777777-7777-4777-8777-777777777777', username: role, display_name: 'Synthetic user', role, unit, channel: null, profile: 'DEMO-REDUCED' };
  const reply = (route: Route, status: number, body: unknown) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname.slice('/api/v1'.length);
    if (path === '/auth/csrf/') return reply(route, 200, { csrf_token: 'synthetic-csrf' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, 200, { user }); }
    if (path === '/me/') return reply(route, state.authenticated ? 200 : 403, state.authenticated ? { user } : { code: 'AUTH_REQUIRED', message: 'Sign in to continue.' });
    if (path === '/reports/' || path === '/review/queue/') {
      const query = Object.fromEntries(url.searchParams); state.queries.push(query);
      const observedMetadata = state.metadata;
      if (state.hold) await state.hold;
      if (state.revoked) return reply(route, 403, { code: 'SCOPE_DENIED', message: 'Synthetic access revoked.' });
      if (state.failure) return reply(route, 503, { code: 'UNAVAILABLE', message: 'Synthetic list unavailable.' });
      const number = Number(query.page || 1), size = Number(query.page_size || 10);
      return reply(route, 200, { results: [], count: 78, page: number, page_size: size, total_pages: Math.ceil(78 / size), activity: observedMetadata });
    }
    return reply(route, 404, { code: 'NOT_FOUND', message: 'Unavailable fixture route.' });
  });
  await page.goto(BASE);
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill('Fictional-Password!2026');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  const panel = page.getByRole('region', { name: 'Report activity', exact: true });
  await expect(panel).toBeVisible();
  await expect(panel).toHaveAttribute('aria-busy', 'false');
  return { state, panel };
}

for (const role of ['submitter', 'reviewer'] as const) {
  test(`${role} sees all-pages activity and can select status without losing dates or page size`, async ({ page }) => {
    const { state, panel } = await setup(page, role);
    await expect(panel).toContainText('All pages and all statuses within your selected dates');
    await expect(panel.getByRole('button', { name: 'All reports 78 reports', exact: true })).toBeVisible();
    await expect(panel.getByRole('button', { pressed: true })).toHaveCount(1);
    await page.getByLabel('Created from (UTC)').fill('2026-10-01');
    await page.getByLabel('Created to (UTC)').fill('2026-10-24');
    await page.getByRole('button', { name: 'Apply filters', exact: true }).click();
    await expect(panel).toHaveAttribute('aria-busy', 'false');
    await page.getByLabel('Per page').selectOption('25');
    await expect.poll(() => state.queries.at(-1)?.page_size).toBe('25');
    await expect(panel).toHaveAttribute('aria-busy', 'false');
    await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect.poll(() => state.queries.at(-1)?.page).toBe('2');
    await expect(panel).toHaveAttribute('aria-busy', 'false');
    await panel.getByRole('button', { name: 'Returned for correction 12 reports', exact: true }).click();
    await expect.poll(() => state.queries.at(-1)).toMatchObject({ status: 'RETURNED', date_from: '2026-10-01', date_to: '2026-10-24', page_size: '25', page: '1' });
    await expect(panel.getByRole('button', { name: 'Returned for correction 12 reports', exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(panel).toContainText('1 reports have an unavailable status');
  });
}

for (const [name, metadata] of [
  ['missing', undefined], ['negative', { ...activity(), total: -1 }],
  ['inconsistent', { ...activity(), total: 79 }], ['partial', { total: 0, by_status: {}, unclassified: 0 }],
  ['unknown key', { ...activity(), by_status: { ...activity().by_status, SECRET_STATE: 8 } }],
  ['fraction', { ...activity(), unclassified: .5 }], ['string', { ...activity(), total: '78' }],
] as const) {
  test(`${name} metadata is unavailable rather than zero`, async ({ page }) => {
    // Explicit assignment allows undefined to model an older server response.
    const { state, panel } = await setup(page, 'submitter', metadata ?? null);
    state.metadata = metadata;
    await expect(panel).toContainText('Activity counts unavailable');
    await expect(panel.getByRole('button')).toHaveCount(8);
    await expect(panel.getByLabel('Count unavailable', { exact: true })).toHaveCount(8);
  });
}

test('loading hides previous counts, disables filters, then failure clears activity', async ({ page }) => {
  const { state, panel } = await setup(page);
  await expect(panel).toContainText('78');
  let release!: () => void;
  state.hold = new Promise<void>(resolve => { release = resolve; });
  state.failure = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(panel).toContainText('Updating report activity');
  await expect(panel.getByLabel('Count unavailable', { exact: true })).toHaveCount(8);
  for (const button of await panel.getByRole('button').all()) await expect(button).toBeDisabled();
  release();
  await expect(panel).toContainText('Activity counts unavailable');
  await expect(panel).not.toContainText('78');
});

test('revoked list access removes private activity with the existing session guard', async ({ page }) => {
  const { state, panel } = await setup(page);
  await expect(panel).toContainText('78');
  state.revoked = true;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(panel).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Welcome back.' })).toBeVisible();
});

test('late earlier refresh cannot replace activity from a newer poll', async ({ page }) => {
  await page.clock.install();
  const { state, panel } = await setup(page);
  await expect(panel).toContainText('78');
  let release!: () => void;
  state.hold = new Promise<void>(resolve => { release = resolve; });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect.poll(() => state.queries.length).toBe(2);
  state.hold = null;
  state.metadata = { total: 0, by_status: Object.fromEntries(statuses.map(status => [status, 0])), unclassified: 0 };
  await page.clock.runFor(10_000);
  await expect(panel.getByRole('button', { name: 'All reports 0 reports', exact: true })).toBeVisible();
  const earlierResponse = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/reports/'));
  release();
  const staleResponse = await earlierResponse;
  await staleResponse.finished();
  expect((await staleResponse.json()).activity.total).toBe(78);
  await page.clock.runFor(1);
  await expect(panel.getByRole('button', { name: 'All reports 0 reports', exact: true })).toBeVisible();
  await expect(panel).not.toContainText('78');
});

test('runtime validator handles zero, unsafe numbers, arrays and inherited status keys', () => {
  const zero = { total: 0, by_status: Object.fromEntries(statuses.map(status => [status, 0])), unclassified: 0 };
  expect(parseReportActivity(zero)).toEqual(zero);
  for (const value of [undefined, [], null, { ...zero, total: Number.MAX_SAFE_INTEGER + 1 }, { ...zero, by_status: [] }, { ...zero, unclassified: true }, { ...zero, extra: 1 }]) expect(parseReportActivity(value)).toBeNull();
  const inherited = Object.create({ PENDING: 0 });
  Object.assign(inherited, Object.fromEntries(statuses.filter(status => status !== 'PENDING').map(status => [status, 0])), { OTHER: 0 });
  expect(parseReportActivity({ ...zero, by_status: inherited })).toBeNull();
});

test('mobile activity fits the viewport and keyboard Enter selects a status', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const { state, panel } = await setup(page);
  const returned = panel.getByRole('button', { name: 'Returned for correction 12 reports', exact: true });
  await returned.focus();
  await expect(returned).toBeFocused();
  await page.keyboard.press('Enter');
  await expect.poll(() => state.queries.at(-1)?.status).toBe('RETURNED');
  await expect(returned).toHaveAttribute('aria-pressed', 'true');
  await expect(panel).toHaveAttribute('aria-busy', 'false');
  const layout = await page.evaluate(() => ({ width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  expect(layout.scroll).toBeLessThanOrEqual(layout.width);
  const bounds = await panel.boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
  await panel.screenshot({ path: '../.cache/report-activity-mobile.png' });
});
