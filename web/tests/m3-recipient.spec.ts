import { expect, test, type Page, type Route } from '@playwright/test';
import { readFileSync } from 'node:fs';

// Controlled fixture journeys only: not live database or authorization evidence.
const BASE = new URL('/workspace', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18091').toString();
const profiles = JSON.parse(readFileSync(new URL('../../contracts/m3/profiles.json', import.meta.url), 'utf8'));
const map = JSON.parse(readFileSync(new URL('../../contracts/m3/map-areas.json', import.meta.url), 'utf8'));
const tombstone = JSON.parse(readFileSync(new URL('../../contracts/m3/tombstone.json', import.meta.url), 'utf8'));
const fullChannel = { id: 'aaaaaaaa-0000-4000-8000-000000000002', code: 'CH-DEMO-02', name: 'Fictional full channel' };
const summaryChannel = { id: 'aaaaaaaa-0000-4000-8000-000000000003', code: 'CH-DEMO-03', name: 'Fictional summary channel' };
const user = { id: '77777777-7777-4777-8777-777777777777', username: 'recipient', display_name: 'Synthetic recipient', role: 'recipient', unit: null, channel: null, profile: null,
  channels: [fullChannel, summaryChannel], grants: [{ channel: fullChannel, profile_ceiling: 'DEMO-FULL' }, { channel: summaryChannel, profile_ceiling: 'DEMO-SUMMARY' }] };

async function setup(page: Page) {
  const state = { authenticated: false, queries: [] as URL[], holdDetail: false, detailRequested: false, releaseDetail: () => {}, external: [] as string[] };
  const reply = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  page.on('request', request => { if (new URL(request.url()).origin !== new URL(BASE).origin) state.external.push(request.url()); });
  await page.route('**/api/v1/**', async route => {
    const url = new URL(route.request().url()); state.queries.push(url);
    const path = url.pathname.slice('/api/v1'.length);
    if (path === '/auth/csrf/') return reply(route, { csrf_token: 'fixture-token' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, { user }); }
    if (path === '/me/') return state.authenticated ? reply(route, { user }) : reply(route, { code: 'AUTH_REQUIRED', message: 'Sign in.' }, 403);
    const channel = path.includes(summaryChannel.id) ? summaryChannel : fullChannel;
    const profile = channel.id === summaryChannel.id ? 'DEMO-SUMMARY' : url.searchParams.get('profile') ?? 'DEMO-FULL';
    const publication = { id: `44444444-4444-4444-8444-${channel.id === fullChannel.id ? '000000000002' : '000000000003'}`, channel, published_at: profile === 'DEMO-SUMMARY' ? '2026-10-19T00:00:00Z' : '2026-10-21T00:00:00Z', projection: profiles.expected['demo-policy-v1'][profile] };
    if (path.endsWith('/feed/')) return reply(route, { results: [publication], count: 1, page: 1, page_size: 10, total_pages: 1, refreshed_at: new Date().toISOString(), profile,
      summary: { by_category: { WATER_SUPPLY: 1 }, by_urgency: { ROUTINE: 1 }, by_area: profile === 'DEMO-SUMMARY' ? {} : { 'Area B': 1 }, unmapped: profile === 'DEMO-SUMMARY' ? 1 : 0 } });
    if (path.endsWith('/map/')) return reply(route, map.map_response);
    if (path.endsWith('/removed/')) return reply(route, { results: [tombstone.removed_entry] });
    if (path.startsWith('/publications/')) {
      state.detailRequested = true;
      if (state.holdDetail) await new Promise<void>(resolve => { state.releaseDetail = resolve; });
      return reply(route, { ...publication, projection: { ...publication.projection, text: 'Earlier channel detail must not appear after a switch.' } });
    }
    return reply(route, { code: 'NOT_FOUND', message: 'Fixture route unavailable.' }, 404);
  });
  await page.goto(BASE);
  await page.getByLabel('Username', { exact: true }).fill('recipient');
  await page.getByLabel('Password', { exact: true }).fill('DemoMaintenance!2026');
  await page.getByRole('button', { name: 'Sign in to workspace' }).click();
  await expect(page.getByRole('button', { name: 'Read update' })).toBeVisible();
  return state;
}

test('granted channels and profile ceilings use frozen fixtures; map filters share the feed query', async ({ page }) => {
  const state = await setup(page);
  await expect(page.getByLabel('Recipient channel')).toHaveValue(fullChannel.id);
  await expect(page.getByLabel('Disclosure profile', { exact: true }).locator('option')).toHaveText(['Full', 'Reduced', 'Summary']);
  const areaMap = page.getByRole('region', { name: 'Area map', exact: true });
  await expect(areaMap.getByRole('img', { name: 'Map of Los Baños showing Areas A, B and C' })).toBeVisible();
  await expect(areaMap).toContainText('© OpenStreetMap contributors');
  await expect(areaMap.getByRole('table', { name: 'Area counts and filters' })).toContainText('Mayondon');
  await page.getByRole('button', { name: 'Filter Area B', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Filter Area B', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect.poll(() => state.queries.filter(url => url.pathname.endsWith('/feed/') && url.searchParams.get('area') === 'Area B').length).toBeGreaterThan(0);
  await expect.poll(() => state.queries.filter(url => url.pathname.endsWith('/map/') && url.searchParams.get('area') === 'Area B').length).toBeGreaterThan(0);
  expect(state.external).toEqual([]);
});

test('SUMMARY hides area controls and geometry; tombstones show no cause or replacement link', async ({ page }) => {
  await setup(page);
  await page.getByLabel('Recipient channel').selectOption(summaryChannel.id);
  await expect(page.getByText('No map for this profile', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Disclosure profile', { exact: true }).locator('option')).toHaveText(['Summary']);
  await expect(page.getByLabel('Filter approved area')).toHaveCount(0);
  await expect(page.getByRole('img', { name: 'Map of Los Baños showing Areas A, B and C' })).toHaveCount(0);
  await expect(page.getByRole('region', { name: 'Previously delivered publications' })).toContainText('Viewed copies cannot be recalled');
  await expect(page.getByRole('region', { name: 'Previously delivered publications' })).not.toContainText(tombstone.removed_entry.publication_id);
});

test('channel switch clears pending detail and rejects the old channel response', async ({ page }) => {
  const state = await setup(page); state.holdDetail = true;
  await page.getByRole('button', { name: 'Read update' }).click();
  await expect.poll(() => state.detailRequested).toBe(true);
  await page.getByLabel('Recipient channel').selectOption(summaryChannel.id);
  state.releaseDetail();
  await expect(page.getByRole('button', { name: 'Back to publications' })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Read update' })).toBeVisible();
  await expect(page.getByText('Earlier channel detail must not appear after a switch.', { exact: true })).toHaveCount(0);
});
