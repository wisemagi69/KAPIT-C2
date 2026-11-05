import { expect, test, type Page, type Route } from '@playwright/test';

// Synthetic browser responses establish UI behavior, not real authorization or
// database acceptance. The root runs browsers against the existing local preview.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const ACTOR = '77777777-7777-4777-8777-777777777777';
const UNIT = { id: '22222222-2222-4222-8222-222222222222', code: 'SIM-UNIT-01', name: 'Simulated Support Unit', active: true };
const CHANNEL = { id: '11111111-1111-4111-8111-111111111111', code: 'CH-DEMO-01', name: 'Maintenance Coordination', active: true };
type Role = 'submitter' | 'reviewer' | 'recipient' | 'administrator';

const healthy = () => ({
  schema_version: 1, scope: 'ORGANIZATION', generated_utc: '2026-10-30T12:00:00Z',
  jobs: { by_status: { PENDING: 3, PROCESSING: 2, DONE: 40, FAILED: 3 }, unknown_status: 0, expired_leases: 1, missing_leases: 0,
    oldest_pending_available_age_seconds: 754, failures_by_code: { RULE_PROCESSING_FAILED: 0, ATTEMPTS_EXHAUSTED: 2, STALE_CONTEXT: 0 }, unclassified_failures: 1 },
  backup: { status: 'CURRENT', last_verified_utc: '2026-10-30T09:00:00Z', age_seconds: 10800, interval_hours: 20, rpo_hours: 24, basis: 'RECORDED_VERIFIED_AT_CREATION' },
});

async function setup(page: Page, role: Role = 'administrator', body: unknown = healthy(), status = 200) {
  const state = { authenticated: false, body, status, healthReads: 0 };
  const user = { id: ACTOR, username: role, display_name: 'Demo ' + role, role, unit: ['administrator', 'recipient'].includes(role) ? null : UNIT, channel: role === 'administrator' ? null : CHANNEL, profile: 'DEMO-REDUCED', permission_version: 0 };
  const reply = (route: Route, code: number, value: unknown) => route.fulfill({ status: code, contentType: 'application/json', body: JSON.stringify(value), headers: { 'Cache-Control': 'no-store' } });
  await page.route('**/api/v1/**', async route => {
    const path = new URL(route.request().url()).pathname.slice('/api/v1'.length);
    if (path === '/auth/csrf/') return reply(route, 200, { csrf_token: 'synthetic-ui-fixture-token' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, 200, { user }); }
    if (path === '/me/') return reply(route, state.authenticated ? 200 : 403, state.authenticated ? { user } : { code: 'AUTH_REQUIRED', message: 'Sign in to continue.' });
    if (path === '/administration/context/') return reply(route, 200, { units: [UNIT], channels: [CHANNEL], channel_sources: [{ unit_id: UNIT.id, channel_id: CHANNEL.id, active: true }] });
    if (path === '/administration/users/') return reply(route, 200, { results: [{ id: ACTOR, username: 'admin', display_name: 'Demo Administrator', role: 'administrator', is_active: true, permission_version: 0, unit_id: null, channel_id: null }], count: 1, page: 1, page_size: 10, total_pages: 1 });
    if (path === '/administration/health/') { state.healthReads++; return state.status === 200 ? reply(route, 200, state.body) : reply(route, state.status, { code: 'UNAVAILABLE', message: 'Synthetic failure.' }); }
    if (path === '/reports/' || path === '/review/queue/') return reply(route, 200, { results: [], count: 0, page: 1, page_size: 10, total_pages: 1 });
    return reply(route, 404, { code: 'NOT_FOUND', message: 'Unavailable fixture route.' });
  });
  await page.goto(BASE);
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill('Fictional-Password!2026');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  return state;
}

async function panel(page: Page) {
  const region = page.getByRole('region', { name: 'Operations health', exact: true });
  await expect(region).toBeVisible();
  await expect(region).toHaveAttribute('aria-busy', 'false');
  return region;
}

test('administrator sees job counts, oldest waiting job, lease warning and backup age', async ({ page }) => {
  await setup(page);
  const region = await panel(page);
  await expect(region).toContainText('Counts only, never report content');
  await expect(region.getByRole('definition').filter({ hasText: 'Oldest waiting 12 min' })).toContainText('3');
  await expect(region).toContainText('1 expired leases');
  await expect(region).toContainText('2 attempts exhausted · 1 other');
  await expect(region).toContainText('Backed up');
  await expect(region).toContainText('3 h 0 min ago. The next backup runs after 20 h.');
  await expect(region).toContainText('Verified when created 2026-10-30 09:00:00 UTC');
  await expect(region.getByRole('listitem')).toHaveCount(1);
  await expect(region.getByRole('listitem')).toContainText('1 processing jobs have an expired lease');
  // Account administration remains on the same page.
  await expect(page.getByRole('button', { name: 'Create account', exact: true })).toBeVisible();
});

test('overdue or missing backup is flagged with the recovery command', async ({ page }) => {
  const overdue = healthy();
  overdue.jobs.expired_leases = 0;
  overdue.backup = { ...overdue.backup, status: 'OVERDUE', age_seconds: 26 * 3600 };
  await setup(page, 'administrator', overdue);
  const region = await panel(page);
  await expect(region).toContainText('Backup overdue');
  await expect(region).toContainText('Older than the 24 h recovery point target.');
  await expect(region.getByRole('listitem')).toHaveText(['Create a backup now: run python infra/local.py native-backup, or restart the website with infra/Start KAPIT.cmd.']);
});

for (const [name, mutate] of [
  ['extra field', (value: any) => { value.jobs.report_ids = []; }],
  ['negative count', (value: any) => { value.jobs.by_status.DONE = -1; }],
  ['failure breakdown mismatch', (value: any) => { value.jobs.by_status.FAILED = 9; }],
  ['pending age without pending jobs', (value: any) => { value.jobs.by_status.PENDING = 0; }],
  ['more leases than processing jobs', (value: any) => { value.jobs.expired_leases = 3; }],
  ['unknown backup state', (value: any) => { value.backup.status = 'FINE'; }],
  ['missing backup time', (value: any) => { value.backup.last_verified_utc = null; }],
  ['wrong scope', (value: any) => { value.scope = 'SYSTEM'; }],
  ['fractional count', (value: any) => { value.jobs.unknown_status = 0.5; }],
] as const) {
  test(`${name} shows unavailable rather than zero`, async ({ page }) => {
    const body = healthy(); mutate(body);
    await setup(page, 'administrator', body);
    const region = await panel(page);
    await expect(region).toContainText('Operations health unavailable. Account administration still works.');
    await expect(region.locator('strong')).toHaveText(['—', '—', '—', '—', '—']);
    await expect(region.getByRole('listitem')).toHaveCount(0);
  });
}

test('server failure keeps accounts usable and refresh recovers', async ({ page }) => {
  const state = await setup(page, 'administrator', healthy(), 503);
  const region = await panel(page);
  await expect(region).toContainText('Operations health unavailable');
  await expect(page.getByRole('button', { name: 'Create account', exact: true })).toBeEnabled();
  state.status = 200;
  await region.getByRole('button', { name: 'Refresh health', exact: true }).click();
  await expect(region).toHaveAttribute('aria-busy', 'false');
  await expect(region).toContainText('Backed up');
  expect(state.healthReads).toBe(2);
});

for (const role of ['submitter', 'reviewer', 'recipient'] as const) {
  test(`${role} never requests or sees operations health`, async ({ page }) => {
    const state = await setup(page, role);
    await expect(page.getByRole('button', { name: 'Sign out', exact: true }).first()).toBeVisible();
    await expect(page.getByRole('region', { name: 'Operations health', exact: true })).toHaveCount(0);
    expect(state.healthReads).toBe(0);
  });
}
