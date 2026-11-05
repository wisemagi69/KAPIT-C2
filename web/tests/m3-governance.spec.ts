import { expect, test, type Page, type Route } from '@playwright/test';

const BASE = process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18091';

const USER = '11111111-1111-4111-8111-111111111111', OTHER = '22222222-2222-4222-8222-222222222222';
const CHANNEL = { id: '33333333-3333-4333-8333-333333333333', code: 'CH-FICTIONAL', name: 'Fictional maintenance', active: true };
const V1 = '44444444-4444-4444-8444-444444444441', V2 = '44444444-4444-4444-8444-444444444442';
const REQUEST = '55555555-5555-4555-8555-555555555555', CLIENT = '66666666-6666-4666-8666-666666666666';
const PROPOSAL = '77777777-7777-4777-8777-777777777777';
const NOW = '2026-10-21T00:00:00Z', FUTURE = '2030-10-21T00:00:00Z';
const KEY = 'kapit_ic_abcd1234_' + 'x'.repeat(43);
type Mode = 'normal' | 'retry' | 'denied' | 'full-own' | 'full-other';

async function setup(page: Page, authorities: string[] | undefined, mode: Mode = 'normal') {
  const user = { id: USER, username: 'admin', display_name: 'Fictional Administrator', role: 'administrator', unit: null, channel: null, profile: null };
  const state = { authenticated: false, authorities, breakClientBinding: '' as '' | 'channel_id' | 'profile_ceiling' | 'expires_at', breakRequestEcho: false, gets: [] as string[], writes: [] as { path: string; body: any; key?: string }[], active: V1, requests: [] as any[], clients: [] as any[], proposals: [] as any[] };
  const request = (requester = USER, profile = 'DEMO-REDUCED', approved = false) => ({ id: REQUEST, requester_id: requester, channel_id: CHANNEL.id, profile_ceiling: profile, label: 'Fictional local client', created_at: NOW, expires_at: FUTURE, collect_deadline: FUTURE, approved });
  const client = () => ({ id: CLIENT, request_id: REQUEST, channel_id: CHANNEL.id, profile_ceiling: state.requests[0]?.profile_ceiling ?? 'DEMO-REDUCED', label: 'Fictional local client', key_prefix: 'abcd1234', created_at: NOW, expires_at: state.requests[0]?.expires_at ?? FUTURE, revoked_at: null });
  const issuedResponse = () => {
    const response = { request: { ...state.requests[0] }, client: { ...state.clients[0] }, key: KEY };
    if (state.breakClientBinding) response.client[state.breakClientBinding] = ({ channel_id: OTHER, profile_ceiling: 'DEMO-SUMMARY', expires_at: '2031-01-01T00:00:00Z' })[state.breakClientBinding];
    if (state.breakRequestEcho) { response.request.channel_id = OTHER; response.client.channel_id = OTHER; }
    return response;
  };
  if (mode.startsWith('full-')) state.requests = [request(mode === 'full-own' ? USER : OTHER, 'DEMO-FULL', mode === 'full-own')];
  const proposal = { id: PROPOSAL, kind: 'ACTIVATE', target_policy_id: V2, target_rules_hash: 'b'.repeat(64), expected_active_policy_id: V1, proposer_id: OTHER, proposed_at: NOW, expires_at: FUTURE, applied: false };
  state.proposals = [proposal];
  const reply = (route: Route, body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  await page.route('**/api/v1/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname.slice('/api/v1'.length);
    if (req.method() === 'GET') state.gets.push(path);
    if (path === '/auth/csrf/') return reply(route, { csrf_token: 'synthetic-fixture-only' });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, { user }); }
    if (path === '/auth/logout/') { state.authenticated = false; return reply(route, { logged_out: true }); }
    if (path === '/me/') return reply(route, state.authenticated ? { user } : { code: 'AUTH_REQUIRED' }, state.authenticated ? 200 : 403);
    if (path === '/account/devices/') return reply(route, { results: [], count: 0 });
    if (path === '/administration/context/') return reply(route, { units: [], channels: [CHANNEL], channel_sources: [], ...(state.authorities === undefined ? {} : { authorities: state.authorities }) });
    if (path === '/administration/users/') return reply(route, { results: [{ ...user, is_active: true, permission_version: 0, unit_id: null, channel_id: null }], count: 1, page: 1, page_size: 10, total_pages: 1 });
    if (path.startsWith('/administration/policy') || path.startsWith('/administration/integration-clients')) {
      if (mode === 'denied') return reply(route, { code: 'ACCESS_DENIED', message: 'This action is unavailable.' }, 403);
      if (req.method() !== 'GET') state.writes.push({ path, body: req.postDataJSON(), key: req.headers()['idempotency-key'] });
      if (path === '/administration/policy/') return reply(route, { active_policy_id: state.active, policy_epoch: state.active === V1 ? 0 : 1, policies: [{ id: V1, version: 'demo-policy-v1', rules_hash: 'a'.repeat(64), active: state.active === V1, supported: true }, { id: V2, version: 'demo-policy-v2', rules_hash: 'b'.repeat(64), active: state.active === V2, supported: true }], proposals: state.proposals });
      if (path === '/administration/policy/proposals/') { const body = req.postDataJSON(); const value = { ...proposal, ...body, proposer_id: USER }; state.proposals = [value]; return reply(route, value, 201); }
      if (path.endsWith('/apply/')) { state.active = V2; state.proposals[0].applied = true; return reply(route, { activation_id: CLIENT, proposal_id: PROPOSAL, kind: 'ACTIVATE', target_policy_id: V2, activated_at: NOW }); }
      if (path === '/administration/integration-clients/' && req.method() === 'GET') return reply(route, { requests: state.requests, clients: state.clients, page: Number(url.searchParams.get('page') || 1), page_size: 25, client_count: state.clients.length, request_count: state.requests.length, clients_more: false, requests_more: false });
      if (path === '/administration/integration-clients/' && req.method() === 'POST') {
        const body = req.postDataJSON(); state.requests = [{ ...request(USER, body.profile_ceiling), expires_at: body.expires_at }];
        if (body.profile_ceiling === 'DEMO-FULL') return reply(route, { request: state.requests[0], client: null }, 201);
        state.clients = [client()];
        const count = state.writes.filter(row => row.path === path).length;
        if (mode === 'retry' && count === 1) return reply(route, { code: 'SERVER_ERROR', message: 'Result not confirmed.' }, 503);
        if (mode === 'retry' && count === 2) return reply(route, { code: 'CSRF_FAILED', message: 'Refresh and retry.' }, 403);
        const { key: ignoredKey, ...metadata } = issuedResponse();
        return reply(route, mode === 'retry' ? metadata : issuedResponse(), count === 1 ? 201 : 200);
      }
      if (path.endsWith('/approve/')) { state.requests[0].approved = true; return reply(route, { request_id: REQUEST, approval_id: CLIENT }); }
      if (path.endsWith('/collect/')) { state.clients = [client()]; return reply(route, issuedResponse()); }
      if (path.endsWith('/revoke/')) { state.clients[0].revoked_at = NOW; return reply(route, state.clients[0]); }
    }
    return reply(route, { code: 'NOT_FOUND' }, 404);
  });
  await page.goto(new URL('/workspace', BASE).href);
  await page.getByLabel('Username', { exact: true }).fill('admin');
  await page.getByLabel('Password', { exact: true }).fill('fictional-fixture-only');
  await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
  if (mode !== 'denied') await expect(page.getByRole('heading', { name: 'Administration', exact: true })).toBeVisible();
  return state;
}

async function requestKey(page: Page, profile = 'DEMO-REDUCED') {
  await page.getByLabel('Integration label', { exact: true }).fill('Fictional reader');
  await page.getByLabel('Integration channel', { exact: true }).selectOption(CHANNEL.id);
  await page.getByLabel('Integration profile', { exact: true }).selectOption(profile);
  await page.getByRole('checkbox', { name: 'I confirmed the channel, profile and expiry.', exact: true }).check();
  await page.getByRole('button', { name: 'Request integration key', exact: true }).click();
}

for (const authorities of [undefined, []]) test(`ordinary administrator never probes privileged endpoints (${authorities === undefined ? 'legacy' : 'empty'})`, async ({ page }) => {
  const state = await setup(page, authorities);
  await expect(page.getByRole('button', { name: 'Create account', exact: true })).toBeEnabled();
  await expect(page.getByRole('region', { name: 'Policy and integration administration' })).toHaveCount(0);
  expect(state.gets.filter(path => path.startsWith('/administration/policy') || path.startsWith('/administration/integration-clients'))).toEqual([]);
});

test('policy proposal binds exact target hash/pointer and cannot self apply', async ({ page }) => {
  const state = await setup(page, ['POLICY']);
  await page.getByLabel('Policy target', { exact: true }).selectOption(V2);
  await page.getByRole('checkbox', { name: 'I checked the policy hash and current active policy.', exact: true }).check();
  await page.getByRole('button', { name: 'Propose policy change', exact: true }).click();
  await expect(page.getByText('Proposal recorded. A different policy authority holder must apply it.', { exact: true })).toBeVisible();
  expect(state.writes[0].body).toMatchObject({ kind: 'ACTIVATE', target_policy_id: V2, target_rules_hash: 'b'.repeat(64), expected_active_policy_id: V1 });
  expect(state.writes[0].key).toBe(state.writes[0].body.operation_id);
  await expect(page.getByRole('button', { name: /^Apply proposal / })).toHaveCount(0);
  expect(state.gets.some(path => path.startsWith('/administration/integration-clients'))).toBe(false);
});

test('different policy authority applies the displayed proposal', async ({ page }) => {
  const state = await setup(page, ['POLICY']);
  await page.getByRole('button', { name: `Apply proposal ${PROPOSAL}`, exact: true }).click();
  await expect(page.getByText(/Policy change committed/)).toBeVisible();
  expect(state.writes[0]).toMatchObject({ path: `/administration/policy/proposals/${PROPOSAL}/apply/`, body: {} });
  await expect(page.getByText('Active policy: demo-policy-v2 · Epoch 1', { exact: true })).toBeVisible();
});

test('one-time key is memory only and clears on close and leaving administration', async ({ page }) => {
  await setup(page, ['INTEGRATION']);
  await requestKey(page);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveValue(KEY);
  expect(await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }))).not.toContain(KEY);
  await page.getByRole('button', { name: 'Close one-time key', exact: true }).click();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  await requestKey(page);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Account security', exact: true }).click();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Administration', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Integration keys', exact: true })).toBeVisible();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
});

test('uncertain key request and CSRF retry preserve exact body/UUID and acknowledge unrecoverable key', async ({ page }) => {
  const state = await setup(page, ['INTEGRATION'], 'retry');
  await requestKey(page);
  const retry = page.getByRole('button', { name: 'Retry same administration action', exact: true });
  await expect(retry).toBeVisible();
  await expect(page.getByRole('button', { name: 'Account security', exact: true })).toBeDisabled();
  await retry.click(); await expect(retry).toBeEnabled(); await retry.click();
  await expect(page.getByText(/one-time key cannot be recovered/)).toBeVisible();
  expect(state.writes).toHaveLength(3);
  expect(state.writes[1]).toEqual(state.writes[0]); expect(state.writes[2]).toEqual(state.writes[0]);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Revoke key abcd1234', exact: true }).click();
  await expect(page.getByText(/Key revocation committed/)).toBeVisible();
});

test('FULL request waits for a different authority with no immediate secret', async ({ page }) => {
  await setup(page, ['INTEGRATION']);
  await requestKey(page, 'DEMO-FULL');
  await expect(page.getByText(/FULL request recorded/)).toBeVisible();
  await expect(page.getByRole('button', { name: /^Approve FULL request / })).toHaveCount(0);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
});

test('different holder approves FULL but cannot collect for its requester', async ({ page }) => {
  const state = await setup(page, ['INTEGRATION'], 'full-other');
  await page.getByRole('button', { name: `Approve FULL request ${REQUEST}`, exact: true }).click();
  await expect(page.getByText('FULL request approved. Only its requester can collect the key.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /^Collect key / })).toHaveCount(0);
  expect(state.writes[0].path).toBe(`/administration/integration-clients/requests/${REQUEST}/approve/`);
});

test('FULL requester collects after approval and can revoke', async ({ page }) => {
  await setup(page, ['INTEGRATION'], 'full-own');
  await expect(page.getByRole('button', { name: /^Approve FULL request / })).toHaveCount(0);
  await page.getByRole('button', { name: `Collect key ${REQUEST}`, exact: true }).click();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveValue(KEY);
  await page.getByRole('button', { name: 'Revoke key abcd1234', exact: true }).click();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  await expect(page.getByText(/Key revocation committed/)).toBeVisible();
});

test('signout and forced session clearing remove keys immediately', async ({ page }) => {
  await setup(page, ['INTEGRATION']); await requestKey(page);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toBeVisible();
  await page.evaluate(() => window.dispatchEvent(new Event('kapit-session-expired')));
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
});

test('explicit signout remains available during an uncertain administration write', async ({ page }) => {
  await setup(page, ['INTEGRATION'], 'retry'); await requestKey(page);
  await expect(page.getByRole('button', { name: 'Retry same administration action', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Policy and integration administration' })).toHaveCount(0);
});

test('lost authority follows real session clearing instead of displaying privileged metadata', async ({ page }) => {
  await setup(page, ['POLICY'], 'denied');
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Policy control', exact: true })).toHaveCount(0);
});

for (const surface of ['request', 'collect'] as const) for (const field of ['channel_id', 'profile_ceiling', 'expires_at'] as const) test(`${surface} refuses a malformed success with mismatched client ${field}`, async ({ page }) => {
  const state = await setup(page, ['INTEGRATION'], surface === 'collect' ? 'full-own' : 'normal');
  state.breakClientBinding = field;
  if (surface === 'collect') await page.getByRole('button', { name: `Collect key ${REQUEST}`, exact: true }).click();
  else await requestKey(page);
  await expect(page.getByRole('button', { name: 'Retry same administration action', exact: true })).toBeVisible();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Key collected. Keep this one-time value private.', { exact: true })).toHaveCount(0);
});

test('matching forged request/client metadata cannot override the frozen request channel', async ({ page }) => {
  const state = await setup(page, ['INTEGRATION']); state.breakRequestEcho = true;
  await requestKey(page);
  await expect(page.getByRole('button', { name: 'Retry same administration action', exact: true })).toBeVisible();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
});

test('malformed metadata-only replay cannot confirm a different expiry after an uncertain request', async ({ page }) => {
  const state = await setup(page, ['INTEGRATION'], 'retry'); state.breakClientBinding = 'expires_at';
  await requestKey(page);
  const retry = page.getByRole('button', { name: 'Retry same administration action', exact: true });
  await expect(retry).toBeVisible(); await retry.click(); await expect(retry).toBeEnabled(); await retry.click();
  await expect(retry).toBeEnabled();
  expect(state.writes).toHaveLength(3);
  expect(state.writes[2]).toEqual(state.writes[0]);
  await expect(page.getByText(/one-time key cannot be recovered/)).toHaveCount(0);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
});

test('integration authority loss clears the key while POLICY governance remains mounted', async ({ page }) => {
  const state = await setup(page, ['POLICY', 'INTEGRATION']);
  await requestKey(page);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveValue(KEY);
  state.authorities = ['POLICY'];
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Policy control', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Integration keys', exact: true })).toHaveCount(0);
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  const count = state.gets.filter(path => path.startsWith('/administration/integration-clients')).length;
  await page.getByRole('button', { name: 'Reload governance', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Policy control', exact: true })).toBeVisible();
  expect(state.gets.filter(path => path.startsWith('/administration/integration-clients'))).toHaveLength(count);
});

test('late key response cannot restore a secret after integration authority disappears', async ({ page }) => {
  await setup(page, ['POLICY', 'INTEGRATION']);
  // Finish the initial context/load before intercepting the deliberate refresh.
  await expect(page.getByRole('heading', { name: 'Integration keys', exact: true })).toBeVisible();
  await expect(page.getByLabel('Integration label', { exact: true })).toBeEditable();
  let releaseContext: () => Promise<void> = async () => {};
  let releaseKey: () => Promise<void> = async () => {};
  let contextEntered!: () => void, keyEntered!: () => void;
  const contextStarted = new Promise<void>(resolve => { contextEntered = resolve; });
  const keyStarted = new Promise<void>(resolve => { keyEntered = resolve; });
  await page.route('**/api/v1/administration/context/', async route => {
    await new Promise<void>(resolve => {
      releaseContext = async () => { await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ units: [], channels: [CHANNEL], channel_sources: [], authorities: ['POLICY'] }) }); resolve(); };
      contextEntered();
    });
  });
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await contextStarted;
  await page.route('**/api/v1/administration/integration-clients/', async route => {
    if (route.request().method() !== 'POST') return route.fallback();
    const body = route.request().postDataJSON();
    await new Promise<void>(resolve => {
      releaseKey = async () => {
        const request = { id: REQUEST, requester_id: USER, channel_id: body.channel_id, profile_ceiling: body.profile_ceiling, expires_at: body.expires_at };
        const client = { id: CLIENT, request_id: REQUEST, channel_id: body.channel_id, profile_ceiling: body.profile_ceiling, expires_at: body.expires_at, label: body.label, created_at: NOW, revoked_at: null, key_prefix: 'abcd1234' };
        await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ request, client, key: KEY }) }); resolve();
      };
      keyEntered();
    });
  });
  await requestKey(page); await keyStarted;
  await releaseContext();
  await expect(page.getByRole('heading', { name: 'Integration keys', exact: true })).toHaveCount(0);
  await releaseKey();
  await expect(page.getByRole('button', { name: 'Retry same administration action', exact: true })).toBeDisabled();
  await expect(page.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Policy control', exact: true })).toBeVisible();
});
