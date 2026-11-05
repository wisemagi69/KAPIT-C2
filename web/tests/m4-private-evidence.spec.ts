import { expect, test, type Page, type Route } from '@playwright/test';

const BASE = process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18091';
const ACTOR = '11111111-1111-4111-8111-111111111111', UNIT = '22222222-2222-4222-8222-222222222222';
const REPORT = '33333333-3333-4333-8333-333333333333', VARIANT = '44444444-4444-4444-8444-444444444444';
const REV1 = '55555555-5555-4555-8555-555555555551', REV2 = '55555555-5555-4555-8555-555555555552';
const EVIDENCE = '66666666-6666-4666-8666-666666666666', OTHER = '77777777-7777-4777-8777-777777777777';
const STAMP = '2026-10-21T00:00:00Z';
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNgZGIGAAAOAAfpkuOmAAAAAElFTkSuQmCC', 'base64');
const PAYLOAD = { observed_at: STAMP, category: 'WATER_SUPPLY', urgency: 'ROUTINE', area_label: 'Area C',
  site_label: 'Fictional maintenance site', reporter_label: 'Fictional submitter', narrative: 'Synthetic water supply inspection.', assistance_requested: 'Inspection' };
type Mode = 'normal' | 'retry' | 'wrong-operation' | 'extra-receipt';
type DownloadMode = 'valid' | 'wrong-type' | 'wrong-bytes' | 'oversize' | 'missing-private-headers' | 'denied';

async function setup(page: Page, role: 'submitter' | 'reviewer' = 'submitter', mode: Mode = 'normal') {
  const state = {
    authenticated: false, uploads: [] as { body: string; key: string; filename: string; type: string; csrf: string }[],
    privateGets: [] as string[], statusCode: 'DECODER_REQUIRED', statusState: 'QUARANTINED', canDownload: false,
    statusEvidence: EVIDENCE, statusExtra: false, denyStatus: false, downloadMode: 'valid' as DownloadMode,
    sourceReport: REPORT,
    pauseStatus: false, statusStarted: false, releaseStatus: () => {},
  };
  const user = { id: ACTOR, username: role, display_name: 'Fictional source account', role,
    unit: { id: UNIT, code: 'SIM-UNIT-01', name: 'Synthetic unit' },
    channel: { id: OTHER, code: 'CH-DEMO-01', name: 'Synthetic maintenance' }, profile: 'DEMO-REDUCED' };
  const summary = { id: REPORT, reference: 'R-EVIDENCE', category: 'WATER_SUPPLY', urgency: 'ROUTINE', area_label: 'Area C',
    created_at: STAMP, observed_date: '2026-10-21', revision_no: 2, status: 'AWAITING_REVIEW', variant_id: VARIANT, feedback: null };
  const reply = (route: Route, body: unknown, status = 200) => route.fulfill({
    status, contentType: 'application/json', headers: { 'Cache-Control': 'no-store' }, body: JSON.stringify(body),
  });
  await page.addInitScript(() => {
    const counts = { created: 0, revoked: 0 };
    (window as any).__evidenceURLCounts = counts;
    const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = blob => { counts.created++; return create(blob); };
    URL.revokeObjectURL = url => { counts.revoked++; revoke(url); };
  });
  await page.route('**/api/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice('/api/v1'.length);
    if (path === '/auth/csrf/') return reply(route, { csrf_token: 'c'.repeat(64) });
    if (path === '/auth/login/') { state.authenticated = true; return reply(route, { user }); }
    if (path === '/auth/logout/') { state.authenticated = false; return reply(route, { logged_out: true }); }
    if (path === '/me/') return reply(route, state.authenticated ? { user } : { code: 'AUTH_REQUIRED', message: 'Sign in.' }, state.authenticated ? 200 : 403);
    if (path === '/account/devices/') return reply(route, { results: [], count: 0 });
    if (path === '/reports/' || path === '/review/queue/') return reply(route, { results: [summary], count: 1, page: 1, page_size: 10, total_pages: 1 });
    const source = path.match(/^\/reports\/[^/]+\/revisions\/(1|2)\/$/);
    if (source) {
      const number = Number(source[1]);
      return reply(route, { report: { ...summary, revision_no: number }, payload: PAYLOAD,
        receipt: { operation_id: OTHER, report_id: state.sourceReport, revision_id: number === 2 ? REV2 : REV1, revision_no: number,
          delivery_status: 'RECEIVED', processing_status: 'PENDING', shared: false }, can_correct: false,
        history: [{ revision_no: 2, received_at: STAMP, status: 'AWAITING_REVIEW' }, { revision_no: 1, received_at: STAMP, status: 'RETURNED' }],
        workflow: { revision_no: number, is_current: number === 2, received_at: STAMP, processing: { state: 'DONE', attempts: 1 },
          review: { state: 'AWAITING_REVIEW', prepared_at: STAMP, decided_at: null }, sharing: { state: 'NOT_SHARED', published_at: null } } });
    }
    if (path === `/variants/${VARIANT}/review/`) return reply(route, {
      report: summary, source: PAYLOAD, candidate: { observed_date: '2026-10-21', category: 'WATER_SUPPLY', urgency: 'ROUTINE',
        area_label: 'Area C', narrative: 'Synthetic inspection.', assistance_requested: 'Inspection', status: 'AWAITING_REVIEW' },
      warnings: [], binding: { revision_id: REV2, revision_no: 2, candidate_hash: 'a'.repeat(64),
        policy_version: 'demo-policy-v1', profile: 'DEMO-REDUCED', channel_ids: [OTHER] },
    });
    if (path === `/revisions/${REV2}/evidence/` && request.method() === 'POST') {
      const headers = request.headers();
      state.uploads.push({ body: request.postDataBuffer()!.toString('base64'), key: headers['idempotency-key'],
        filename: headers['x-evidence-filename'], type: headers['content-type'], csrf: headers['x-csrftoken'] });
      if (mode === 'retry' && state.uploads.length === 1) return reply(route, { code: 'SERVER_ERROR', message: 'Unconfirmed.' }, 503);
      if (mode === 'retry' && state.uploads.length === 2) return reply(route, { code: 'CSRF_FAILED', message: 'Refresh.' }, 403);
      return reply(route, { id: mode === 'normal' && state.uploads.length === 2 ? OTHER : EVIDENCE, operation_id: mode === 'wrong-operation' ? OTHER : headers['idempotency-key'],
        state: 'QUARANTINED', validation_code: 'DECODER_REQUIRED', created_at: STAMP,
        ...(mode === 'extra-receipt' ? { public_url: 'https://invalid.example/private' } : {}) }, 201);
    }
    if (path.startsWith('/evidence/')) {
      state.privateGets.push(path);
      if (path === `/evidence/${EVIDENCE}/validation/`) {
        state.statusStarted = true;
        if (state.pauseStatus) await new Promise<void>(resolve => { state.releaseStatus = resolve; });
        try {
          if (state.denyStatus) return await reply(route, { code: 'NOT_FOUND', message: 'Unavailable.' }, 404);
          return await reply(route, { evidence_id: state.statusEvidence, state: state.statusState, validation_code: state.statusCode,
            can_download: state.canDownload, ...(state.statusExtra ? { metadata: 'PRIVATE_METADATA_CANARY' } : {}) });
        } catch { return; } // expected only after the page aborts a delayed request on context loss
      }
      if (path === `/evidence/${EVIDENCE}/download/`) {
        if (state.downloadMode === 'denied') return reply(route, { code: 'NOT_FOUND', message: 'Unavailable.' }, 404);
        return route.fulfill({ status: 200,
          contentType: state.downloadMode === 'wrong-type' ? 'text/html' : 'image/png',
          headers: state.downloadMode === 'missing-private-headers' ? {} :
            { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Disposition': 'attachment; filename="evidence.png"' },
          body: state.downloadMode === 'wrong-bytes' ? Buffer.from('PRIVATE_NOT_A_PNG') :
            state.downloadMode === 'oversize' ? Buffer.alloc(5 * 1024 * 1024 + 2) : PNG });
      }
    }
    return reply(route, { code: 'NOT_FOUND', message: 'Unavailable fixture route.' }, 404);
  });
  await page.goto(new URL('/workspace', BASE).href);
  await page.getByLabel('Username', { exact: true }).fill(role);
  await page.getByLabel('Password', { exact: true }).fill('fictional-fixture-only');
  await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
  await page.getByRole('button', { name: role === 'submitter' ? 'Your reports' : 'Review queue', exact: true }).first().click();
  await page.getByRole('button', { name: /R-EVIDENCE/ }).first().click();
  if (role === 'reviewer') await page.getByRole('button', { name: 'View revision history', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Private source evidence', exact: true })).toBeVisible();
  return state;
}

async function upload(page: Page, name = 'synthetic.png', buffer = PNG, mimeType = 'image/png') {
  await page.getByLabel('Private evidence image', { exact: true }).setInputFiles({ name, buffer, mimeType });
  await page.getByRole('button', { name: 'Upload private image', exact: true }).click();
}
const panel = (page: Page) => page.getByRole('region', { name: 'Private source evidence', exact: true });
const refresh = (page: Page) => page.getByRole('button', { name: 'Refresh private image 1 status', exact: true });

test('private upload is separate, raw bounded CSRF and never auto probes status or previews', async ({ page }) => {
  const state = await setup(page);
  expect(state.privateGets).toEqual([]);
  await upload(page);
  await expect(panel(page).getByText(/Private upload received in quarantine/)).toBeVisible();
  expect(state.uploads).toHaveLength(1);
  expect(state.uploads[0]).toMatchObject({ body: PNG.toString('base64'), filename: 'evidence.png', type: 'image/png', csrf: 'c'.repeat(64) });
  expect(state.uploads[0].key).toMatch(/^[a-f0-9-]{36}$/);
  expect(state.privateGets).toEqual([]);
  await expect(panel(page).locator('img,canvas,iframe,video,a[href^="blob:"]')).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Delivery receipt', exact: true, level: 3 })).toBeVisible();
  await refresh(page).click();
  await expect(panel(page).getByText('Quarantined or validation not confirmed. No download is available.', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: /Download normalized private/ })).toHaveCount(0);
});

test('uncertain then CSRF retry retains immutable bytes, filename and UUID', async ({ page }) => {
  const state = await setup(page, 'submitter', 'retry');
  await upload(page);
  await expect(page.getByRole('button', { name: 'Retry same private upload', exact: true })).toBeEnabled();
  await expect(page.getByLabel('Private evidence image', { exact: true })).toBeDisabled();
  for (const name of ['Overview', 'New report', 'Your reports', 'Account security']) {
    await expect(page.getByRole('navigation', { name: 'Workspace navigation' }).getByRole('button', { name, exact: true })).toBeDisabled();
  }
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Retry same private upload', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Retry same private upload', exact: true })).toBeEnabled();
  await expect(page.getByLabel('Private evidence image', { exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Retry same private upload', exact: true }).click();
  await expect(panel(page).getByText(/Private upload received in quarantine/)).toBeVisible();
  expect(state.uploads).toHaveLength(3);
  expect(new Set(state.uploads.map(row => JSON.stringify(row))).size).toBe(1);
  await expect(panel(page).getByRole('region', { name: 'Private image 1', exact: true })).toBeVisible();
  for (const name of ['Overview', 'New report', 'Your reports', 'Account security']) {
    await expect(page.getByRole('navigation', { name: 'Workspace navigation' }).getByRole('button', { name, exact: true })).toBeEnabled();
  }
});

test('workspace lock is acquired before the first asynchronous file capture', async ({ page }) => {
  const state = await setup(page);
  await page.evaluate(() => {
    const original = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = function () {
      (window as any).__captureStarted = true;
      return new Promise<ArrayBuffer>(resolve => {
        (window as any).__releaseCapture = async () => resolve(await original.call(this));
      });
    };
  });
  await upload(page);
  await expect.poll(() => page.evaluate(() => (window as any).__captureStarted)).toBe(true);
  expect(state.uploads).toEqual([]);
  for (const name of ['Overview', 'New report', 'Your reports', 'Account security']) {
    await expect(page.getByRole('navigation', { name: 'Workspace navigation' }).getByRole('button', { name, exact: true })).toBeDisabled();
  }
  await page.evaluate(() => (window as any).__releaseCapture());
  await expect(refresh(page)).toBeVisible();
});

test('security signout immediately clears an uncertain upload while business navigation is locked', async ({ page }) => {
  await setup(page, 'submitter', 'retry');
  await upload(page);
  await expect(page.getByRole('button', { name: 'Retry same private upload', exact: true })).toBeEnabled();
  await expect(page.getByRole('navigation', { name: 'Workspace navigation' }).getByRole('button', { name: 'New report', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Retry same private upload', exact: true })).toHaveCount(0);
});

for (const mode of ['wrong-operation', 'extra-receipt'] as const) test(`malformed upload ${mode} cannot confirm or issue status query`, async ({ page }) => {
  const state = await setup(page, 'submitter', mode);
  await upload(page);
  await expect(page.getByRole('button', { name: 'Retry same private upload', exact: true })).toBeEnabled();
  await expect(refresh(page)).toHaveCount(0);
  expect(state.privateGets).toEqual([]);
});

for (const input of [
  { name: 'large.png', buffer: Buffer.alloc(5 * 1024 * 1024 + 1), mime: 'image/png' },
  { name: 'bad.png', buffer: Buffer.from('not an image'), mime: 'image/png' },
  { name: 'bad.gif', buffer: PNG, mime: 'image/gif' },
]) test(`invalid local selection ${input.name} sends no upload`, async ({ page }) => {
  const state = await setup(page);
  await upload(page, input.name, input.buffer, input.mime);
  await expect(panel(page).getByRole('alert')).toBeVisible();
  expect(state.uploads).toEqual([]);
});

test('Unicode original filename never enters HTTP headers or stored references', async ({ page }) => {
  const state = await setup(page);
  await upload(page, 'Fictional \u65e5\u672c\u8a9e image.png');
  await expect(refresh(page)).toBeVisible();
  expect(state.uploads).toHaveLength(1);
  expect(state.uploads[0].filename).toBe('evidence.png');
  expect(state.uploads[0].body).toBe(PNG.toString('base64'));
  expect(JSON.stringify(state.uploads)).not.toContain('Fictional');
});

test('two received references stop a third local upload without querying an image count', async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  await upload(page);
  await expect(panel(page).getByRole('region', { name: 'Private image 2', exact: true })).toBeVisible();
  await expect(page.getByLabel('Private evidence image', { exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Upload private image', exact: true })).toBeDisabled();
  expect(state.uploads).toHaveLength(2); expect(state.privateGets).toEqual([]);
});

for (const invalid of ['identity', 'state', 'flag', 'extra'] as const) test(`malformed status ${invalid} cannot enable private download`, async ({ page }) => {
  const state = await setup(page);
  await upload(page);
  await expect(refresh(page)).toBeVisible();
  state.statusState = 'VALIDATED_PRIVATE'; state.statusCode = 'VALIDATION_COMPLETE'; state.canDownload = true;
  if (invalid === 'identity') state.statusEvidence = OTHER;
  if (invalid === 'state') state.statusState = 'APPROVED';
  if (invalid === 'flag') state.statusState = 'QUARANTINED';
  if (invalid === 'extra') state.statusExtra = true;
  await refresh(page).click();
  await expect(panel(page).getByRole('alert')).toBeVisible();
  await expect(page.getByRole('button', { name: /Download normalized private/ })).toHaveCount(0);
});

test('status denial clears source references and disables actions without image presence probes', async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  state.denyStatus = true; await refresh(page).click();
  await expect(panel(page).getByText('Private evidence is unavailable in this source view. Refresh the source to continue.', { exact: true })).toBeVisible();
  await expect(refresh(page)).toHaveCount(0);
  await expect(page.getByLabel('Private evidence image', { exact: true })).toHaveCount(0);
  expect(state.privateGets).toEqual([`/evidence/${EVIDENCE}/validation/`]);
});

test('valid normalized download occurs on explicit click and object URL is revoked', async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  state.statusState = 'VALIDATED_PRIVATE'; state.statusCode = 'VALIDATION_COMPLETE'; state.canDownload = true;
  await refresh(page).click();
  const button = page.getByRole('button', { name: 'Download normalized private image 1', exact: true });
  await expect(button).toBeVisible();
  expect(state.privateGets).not.toContain(`/evidence/${EVIDENCE}/download/`);
  const downloaded = page.waitForEvent('download');
  await button.click(); const file = await downloaded;
  expect(file.suggestedFilename()).toBe('evidence.png');
  await file.delete();
  await expect.poll(() => page.evaluate(() => (window as any).__evidenceURLCounts)).toEqual({ created: 1, revoked: 1 });
  await expect(panel(page).locator('img,canvas,iframe,a[href^="blob:"]')).toHaveCount(0);
});

for (const mode of ['wrong-type', 'wrong-bytes', 'oversize', 'missing-private-headers', 'denied'] as const) test(`unsafe download ${mode} creates no Blob URL`, async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  state.statusState = 'VALIDATED_PRIVATE'; state.statusCode = 'VALIDATION_COMPLETE'; state.canDownload = true; state.downloadMode = mode;
  await refresh(page).click();
  await page.getByRole('button', { name: 'Download normalized private image 1', exact: true }).click();
  await expect(panel(page).getByRole('alert')).toBeVisible();
  expect(await page.evaluate(() => (window as any).__evidenceURLCounts)).toEqual({ created: 0, revoked: 0 });
  await expect(panel(page).locator('img,canvas,iframe,a[href^="blob:"]')).toHaveCount(0);
});

test('revision switch discards ephemeral references without listing or reading other evidence', async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  await page.getByRole('button', { name: 'Revision 1', exact: true }).click();
  await expect(page.getByText('Exact source revision 1', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Private evidence image', { exact: true })).toHaveCount(0);
  await expect(refresh(page)).toHaveCount(0);
  await page.getByRole('button', { name: 'Revision 2', exact: true }).click();
  await expect(page.getByLabel('Private evidence image', { exact: true })).toBeVisible();
  await expect(refresh(page)).toHaveCount(0);
  expect(state.privateGets).toEqual([]);
});

test('reviewer private original shows no upload/arbitrary reference and makes no evidence requests', async ({ page }) => {
  const state = await setup(page, 'reviewer');
  await expect(page.getByLabel('Private evidence image', { exact: true })).toHaveCount(0);
  await expect(panel(page).locator('input')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Download normalized private/ })).toHaveCount(0);
  expect(state.uploads).toEqual([]); expect(state.privateGets).toEqual([]);
});

test('misbound source receipt cannot supply an evidence context', async ({ page }) => {
  const state = await setup(page);
  state.sourceReport = OTHER;
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(panel(page)).toHaveCount(0);
  expect(state.uploads).toEqual([]); expect(state.privateGets).toEqual([]);
});

test('late status response after signout cannot restore private references or URLs', async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  state.pauseStatus = true; state.statusState = 'VALIDATED_PRIVATE'; state.statusCode = 'VALIDATION_COMPLETE'; state.canDownload = true;
  await refresh(page).click();
  await expect.poll(() => state.statusStarted).toBe(true);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  state.releaseStatus();
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Download normalized private/ })).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__evidenceURLCounts)).toEqual({ created: 0, revoked: 0 });
});

test('reauthentication starts with no file or saved evidence references', async ({ page }) => {
  const state = await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await page.getByLabel('Username', { exact: true }).fill('submitter');
  await page.getByLabel('Password', { exact: true }).fill('fictional-fixture-only');
  await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
  await page.getByRole('button', { name: 'Your reports', exact: true }).first().click();
  await page.getByRole('button', { name: /R-EVIDENCE/ }).first().click();
  await expect(panel(page)).toBeVisible();
  await expect(page.getByLabel('Private evidence image', { exact: true })).toHaveValue('');
  await expect(refresh(page)).toHaveCount(0);
  expect(state.privateGets).toEqual([]);
  expect(await page.evaluate(() => Object.keys(localStorage).some(key => /evidence/i.test(key)))).toBe(false);
});

test('aborted old denial body cannot expire a newly authenticated workspace', async ({ page }) => {
  await setup(page);
  await upload(page); await expect(refresh(page)).toBeVisible();
  await page.evaluate(({ evidence }) => {
    const original = window.fetch.bind(window);
    (window as any).__staleDenialEvents = 0;
    window.addEventListener('kapit-session-expired', () => { (window as any).__staleDenialEvents++; });
    window.fetch = async (input, init) => {
      const path = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (!path.endsWith(`/evidence/${evidence}/validation/`)) return original(input, init);
      let controller: ReadableStreamDefaultController<Uint8Array>;
      const stream = new ReadableStream<Uint8Array>({
        start(value) { controller = value; },
        pull() { (window as any).__denialBodyWaiting = true; },
      });
      // Deliberately ignore fetch's abort in this fixture transport: production
      // must still check the internal signal after body parsing, before its
      // global event. Other account requests use the normal fixture transport.
      (window as any).__releaseOldDenial = async () => {
        controller.enqueue(new TextEncoder().encode(JSON.stringify({ code: 'ACCESS_DENIED', message: 'Old context only.' })));
        controller.close();
        await new Promise(resolve => window.setTimeout(resolve, 0));
      };
      return new Response(stream, { status: 403, headers: { 'Content-Type': 'application/json' } });
    };
  }, { evidence: EVIDENCE });
  await refresh(page).click();
  await expect.poll(() => page.evaluate(() => (window as any).__denialBodyWaiting)).toBe(true);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toBeVisible();
  await page.getByLabel('Username', { exact: true }).fill('submitter');
  await page.getByLabel('Password', { exact: true }).fill('fictional-fixture-only');
  await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  await page.evaluate(() => (window as any).__releaseOldDenial());
  expect(await page.evaluate(() => (window as any).__staleDenialEvents)).toBe(0);
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in to workspace', exact: true })).toHaveCount(0);
});
