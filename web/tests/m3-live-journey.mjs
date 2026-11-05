// Genuine M3 Chromium/HTTP journey. Synthetic setup belongs to the guarded Python owner.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const MAX_INPUT = 4096;
export const JOURNEY_TIMEOUT_MS = 330_000;
export const GATES = ['m3_review', 'm3_isolation', 'm3_recipients', 'm3_correction', 'm3_withdrawal', 'm3_policy', 'm3_integration'];
const PROFILE_LABEL = { 'DEMO-FULL': 'Full', 'DEMO-REDUCED': 'Reduced', 'DEMO-SUMMARY': 'Summary' };
const STAGES = new Set(['INPUT', 'BROWSER', 'REVIEW', 'ISOLATION', 'RECIPIENTS', 'CORRECTION', 'WITHDRAWAL', 'POLICY', 'INTEGRATION', 'COMPLETE']);
const PASSWORD = 'DemoMaintenance!2026';
export const CANARIES = ['PRIVATE_M3_REPORTER', 'PRIVATE_M3_SITE', 'PRIVATE_M3_NARRATIVE', 'PRIVATE_M3_CORRECTION', 'PRIVATE_M3_DECISION', 'PRIVATE_M3_WITHDRAWAL'];
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);

export function validateInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'channel_ids,policy_ids,unit_ids,url') throw new Error('INPUT');
  const url = new URL(value.url);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || Number(url.port) < 1024 || Number(url.port) > 65535 || url.username || url.password || value.url !== url.origin) throw new Error('INPUT');
  for (const field of ['channel_ids', 'unit_ids', 'policy_ids']) {
    const expected = field === 'policy_ids' ? 2 : 3;
    if (!Array.isArray(value[field]) || value[field].length !== expected || !value[field].every(uuid) || new Set(value[field]).size !== expected) throw new Error('INPUT');
  }
  if (new Set([...value.channel_ids, ...value.unit_ids, ...value.policy_ids]).size !== 8) throw new Error('INPUT');
  return { url: url.origin, channel_ids: [...value.channel_ids], unit_ids: [...value.unit_ids], policy_ids: [...value.policy_ids] };
}
export function safeFailure(stage) { return { ok: false, stage: STAGES.has(stage) ? stage : 'INPUT' }; }
export function assertSafeBody(value) {
  const text = JSON.stringify(value);
  for (const canary of CANARIES) assert.ok(!text.includes(canary));
  for (const field of ['report_id', 'revision_id', 'variant_id', 'candidate_hash', 'policy_hash', 'scope_context_hash', 'policy_epoch', 'scope_epoch', 'payload_ciphertext', 'correction_reason', 'reporter_label', 'site_label', 'narrative']) assert.ok(!text.includes(`"${field}"`));
}
export function assertParity(feed, map) {
  assert.equal(feed.count, feed.results.length);
  assert.equal(new Set(feed.results.map(row => row.id)).size, feed.results.length);
  assert.equal(Object.values(feed.summary.by_category).reduce((a, b) => a + b, 0), feed.count);
  assert.equal(map.areas.reduce((sum, row) => sum + row.count, 0) + map.unmapped, feed.count);
  assertSafeBody(feed); assertSafeBody(map);
}
export function assertGates(value) { assert.deepEqual(value, GATES); }

async function readInput() {
  const chunks = []; let size = 0;
  for await (const chunk of process.stdin) { size += chunk.length; if (size > MAX_INPUT) throw new Error('INPUT'); chunks.push(chunk); }
  return validateInput(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}

async function referenceClient(base, key, expected) {
  const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'HOME']);
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => allowed.has(name.toUpperCase())));
  env.KAPIT_INTEGRATION_KEY = key;
  const script = fileURLToPath(new URL('../../backend/tests/m3/clients/kapit_feed.py', import.meta.url));
  await new Promise((resolve, reject) => {
    const child = spawn('python', ['-I', script, base + '/api/integration/v1/'], { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', count = 0, failed = false;
    const deadline = setTimeout(() => { failed = true; child.kill(); }, 20_000);
    for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => { count += chunk.length; if (count > 4096) { failed = true; child.kill(); } else if (stream === child.stdout) output += chunk.toString('utf8'); });
    child.on('error', () => { clearTimeout(deadline); reject(new Error('INTEGRATION')); });
    child.on('close', code => { clearTimeout(deadline); try { assert.equal(code, 0); assert.equal(failed, false); assert.deepEqual(JSON.parse(output), { received: expected }); resolve(); } catch { reject(new Error('INTEGRATION')); } });
  });
}

export async function journey(config) {
  let browser, stage = 'BROWSER', timer;
  const contexts = [], pending = [], scanFailures = [], external = [], gates = [];
  let scanned = 0;
  try {
    const execute = async () => {
      const { chromium } = await import('playwright');
      const { expect } = await import('@playwright/test');
      browser = await chromium.launch({ headless: true, timeout: 15_000 });
      const pageFor = async (name, recipient = false) => {
        const context = await browser.newContext({ viewport: { width: 1360, height: 1000 }, serviceWorkers: 'block' }); contexts.push(context);
        // Network policy only: every permitted request reaches the actual local server.
        await context.route('**/*', route => { const target = new URL(route.request().url()); if (target.origin === config.url) return route.continue(); external.push(true); return route.abort(); });
        const page = await context.newPage(); page.setDefaultTimeout(10_000);
        if (recipient) page.on('response', response => {
          const path = new URL(response.url()).pathname;
          if (path.startsWith('/api/v1/') && !['/api/v1/me/', '/api/v1/auth/login/', '/api/v1/auth/csrf/'].includes(path)) pending.push(response.json().then(body => { assertSafeBody(body); scanned++; }).catch(() => scanFailures.push(true)));
        });
        await page.goto(config.url + '/workspace', { waitUntil: 'domcontentloaded' });
        await page.getByLabel('Username', { exact: true }).fill(name); await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
        await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
        await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
        return page;
      };
      const get = async (page, path, status = 200, sharing = false) => {
        const response = await page.context().request.get(config.url + path, { maxRedirects: 0 }); assert.equal(response.status(), status);
        assert.ok(response.headers()['cache-control'].includes('no-store'));
        const body = await response.json(); if (sharing) { assertSafeBody(body); scanned++; } return body;
      };
      const responseFor = (page, suffix, method = 'GET') => page.waitForResponse(response => new URL(response.url()).pathname.endsWith(suffix) && response.request().method() === method);
      const clickResponse = async (page, name, suffix, method = 'POST') => { const response = responseFor(page, suffix, method); await page.getByRole('button', { name, exact: true }).click(); return response; };
      const keyboardCheck = async locator => { await locator.focus(); await locator.press('Space'); await expect(locator).toBeChecked(); };
      const submit = async (page, category = 'WATER_SUPPLY') => {
        await page.getByRole('button', { name: 'New report', exact: true }).first().click();
        const another = page.getByRole('button', { name: 'Make another report', exact: true }); if (await another.isVisible()) await another.click();
        await page.getByLabel('Reporter label').fill(CANARIES[0]); await page.getByLabel('Site label').fill(CANARIES[1]); await page.getByLabel('Describe the issue').fill(CANARIES[2] + '. Fictional maintenance.');
        await page.getByLabel('Category', { exact: true }).selectOption(category);
        const response = await clickResponse(page, 'Submit report', '/sync/operations/'); assert.equal(response.status(), 201);
        const receipt = await response.json(); assert.equal(receipt.shared, false); assert.equal(receipt.revision_no, 1);
        return { receipt, source: await get(page, `/api/v1/reports/${receipt.report_id}/revisions/1/`) };
      };
      const openReview = async (page, record, legacy = false) => {
        await page.goto(config.url + '/workspace');
        await page.getByRole('button', { name: 'Review queue', exact: true }).first().click();
        await expect(async () => { await page.getByRole('button', { name: 'Refresh queue', exact: true }).click(); await expect(page.getByRole('button', { name: `Review ${record.source.report.reference}`, exact: true })).toBeVisible({ timeout: 1000 }); }).toPass({ timeout: 20_000, intervals: [200, 500, 1000] });
        const response = page.waitForResponse(response => new URL(response.url()).pathname.endsWith(legacy ? '/review/' : '/candidates/'));
        await page.getByRole('button', { name: `Review ${record.source.report.reference}`, exact: true }).click();
        const loaded = await response; assert.equal(loaded.status(), 200); const detail = await loaded.json();
        if (!legacy) {
          assert.equal(detail.binding.revision_id, record.receipt.revision_id);
          for (const row of detail.candidates) {
            assertSafeBody(row.candidate);
            const panel = page.getByRole('region', { name: `${PROFILE_LABEL[row.profile]} candidate`, exact: true });
            await expect(panel).toContainText(row.candidate.text);
            for (const warning of row.warnings) await expect(panel).toContainText(warning);
            await expect(panel).toContainText(detail.binding.candidates.find(binding => binding.variant_id === row.variant_id).candidate_hash);
          }
        }
        return detail;
      };
      const decide = async (page, record, profiles, action = 'APPROVE', legacy = false) => {
        const detail = await openReview(page, record, legacy);
        if (!legacy && action === 'APPROVE') for (const profile of profiles) await keyboardCheck(page.getByRole('checkbox', { name: `Approve ${PROFILE_LABEL[profile]}`, exact: true }));
        await page.getByRole('button', { name: action === 'APPROVE' ? 'Review & approve' : action === 'RETURN' ? 'Return for correction' : 'Reject', exact: true }).click();
        if (action === 'APPROVE') await keyboardCheck(page.getByRole('checkbox', { name: legacy ? 'I have checked the complete candidate, source revision, policy and sharing audience.' : 'I have checked every selected candidate, source revision, policy and sharing audience.', exact: true }));
        else await page.getByLabel('Private reason', { exact: true }).fill(CANARIES[4]);
        const committing = page.waitForResponse(response => new URL(response.url()).pathname.endsWith('/decisions/') && response.request().method() === 'POST');
        const button = page.getByRole('button', { name: action === 'APPROVE' ? 'Approve & share' : action === 'RETURN' ? 'Return report' : 'Reject report', exact: true }); await button.focus(); await button.press('Enter');
        const committed = await committing; assert.equal(committed.status(), 200); const body = committed.request().postDataJSON();
        assert.deepEqual(body.expected, detail.binding); assert.equal(body.action, action); assert.equal(committed.request().headers()['idempotency-key'], body.operation_id); assert.ok(committed.request().headers()['x-csrftoken']);
        if (!legacy) assert.deepEqual(body.approve_profiles, action === 'APPROVE' ? profiles : []);
        return committed.json();
      };
      const feed = (page, channel, profile) => get(page, `/api/v1/channels/${channel}/feed/?profile=${profile}`, 200, true);
      const map = (page, channel, profile) => get(page, `/api/v1/channels/${channel}/map/?profile=${profile}`, 200, true);
      const gate = value => { assert.equal(value, GATES[gates.length]); gates.push(value); };

      stage = 'REVIEW';
      const author = await pageFor('submitter2'), reviewer = await pageFor('reviewer2');
      const identity = await get(author, '/api/v1/me/'); assert.equal(identity.user.unit.id, config.unit_ids[1]);
      const primary = await submit(author); const initial = await openReview(reviewer, primary);
      assert.deepEqual(initial.binding.candidates.map(row => row.profile), ['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY']);
      assert.deepEqual(initial.binding.candidates.map(row => row.channel_ids), [[config.channel_ids[1]], [config.channel_ids[1]], [config.channel_ids[1], config.channel_ids[2]].sort()]);
      await decide(reviewer, primary, ['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY']);
      const returned = await submit(author, 'INFRASTRUCTURE'); await decide(reviewer, returned, [], 'RETURN');
      const rejected = await submit(author, 'EQUIPMENT'); const rejectedResult = await decide(reviewer, rejected, [], 'REJECT'); assert.deepEqual(rejectedResult.publication_ids, []);
      gate('m3_review');

      stage = 'ISOLATION';
      const legacyAuthor = await pageFor('submitter'), legacyReviewer = await pageFor('reviewer');
      const thirdAuthor = await pageFor('submitter3'), thirdReviewer = await pageFor('reviewer3');
      const legacy = await submit(legacyAuthor); const legacyDetail = await openReview(legacyReviewer, legacy, true); assert.equal(legacyDetail.binding.profile, 'DEMO-REDUCED'); assert.equal(Object.hasOwn(legacyDetail.binding, 'scope_context_hash'), false);
      await decide(legacyReviewer, legacy, [], 'APPROVE', true);
      const third = await submit(thirdAuthor, 'EQUIPMENT'); const thirdDetail = await openReview(thirdReviewer, third); await decide(thirdReviewer, third, thirdDetail.binding.candidates.map(row => row.profile));
      for (const page of [legacyReviewer, thirdReviewer]) await get(page, `/api/v1/reports/${primary.receipt.report_id}/revisions/1/`, 404);
      gate('m3_isolation');

      stage = 'RECIPIENTS';
      const full = await pageFor('recipient-full', true), limited = await pageFor('recipient-limited', true), summary = await pageFor('recipient-summary', true), oldRecipient = await pageFor('recipient', true), multi = await pageFor('recipient-multi', true);
      const fullIdentity = await get(full, '/api/v1/me/'); assert.equal(fullIdentity.user.grants[0].channel.id, config.channel_ids[1]);
      const fullFeed = await feed(full, config.channel_ids[1], 'DEMO-FULL'), reducedFeed = await feed(limited, config.channel_ids[1], 'DEMO-REDUCED'), summaryFeed = await feed(summary, config.channel_ids[2], 'DEMO-SUMMARY');
      assert.equal(fullFeed.count, 1); assert.equal(reducedFeed.count, 1); assert.equal(summaryFeed.count, 2);
      assert.equal(fullFeed.results[0].projection.profile, 'DEMO-FULL'); assert.equal(reducedFeed.results[0].projection.profile, 'DEMO-REDUCED');
      for (const row of summaryFeed.results) { assert.equal(row.projection.profile, 'DEMO-SUMMARY'); assert.equal(Object.hasOwn(row.projection, 'area_label'), false); assert.match(row.projection.observed_week, /^\d{4}-W\d{2}$/); }
      assertParity(fullFeed, await map(full, config.channel_ids[1], 'DEMO-FULL')); assertParity(reducedFeed, await map(limited, config.channel_ids[1], 'DEMO-REDUCED'));
      for (const [page, profile] of [[full, 'DEMO-FULL'], [limited, 'DEMO-REDUCED']]) {
        const suffix = `profile=${profile}&category=WATER_SUPPLY&urgency=ROUTINE&q=maintenance`;
        const filtered = await get(page, `/api/v1/channels/${config.channel_ids[1]}/feed/?${suffix}`, 200, true);
        const filteredMap = await get(page, `/api/v1/channels/${config.channel_ids[1]}/map/?${suffix}`, 200, true);
        assertParity(filtered, filteredMap);
      }
      await expect(summary.getByRole('region', { name: 'Area map', exact: true })).toHaveCount(0);
      await get(oldRecipient, `/api/v1/publications/${fullFeed.results[0].id}/`, 404, true);
      const areaButton = full.getByRole('button', { name: 'Filter Area C', exact: true }); await areaButton.focus(); await expect(areaButton).toBeFocused(); await areaButton.press('Enter');
      await expect(full.getByRole('button', { name: 'Filter Area C', exact: true })).toHaveAttribute('aria-pressed', 'true');
      const switcher = multi.getByRole('combobox', { name: 'Recipient channel', exact: true });
      const switchByKeyboard = async value => {
        const values = await switcher.locator('option').evaluateAll(options => options.map(option => option.value));
        const index = values.indexOf(value); assert.ok(index >= 0); await switcher.focus(); await switcher.press('Home');
        for (let i = 0; i < index; i++) await switcher.press('ArrowDown'); await switcher.press('Enter'); await expect(switcher).toHaveValue(value);
      };
      await switchByKeyboard(config.channel_ids[0]); await switchByKeyboard(config.channel_ids[2]);
      await expect(switcher).toHaveValue(config.channel_ids[2]); await expect(multi.getByRole('region', { name: 'Area map', exact: true })).toHaveCount(0);
      const dom = await Promise.all([full, limited, summary, multi].map(page => page.locator('body').innerText())); for (const text of dom) for (const canary of CANARIES) assert.ok(!text.includes(canary));
      gate('m3_recipients');

      stage = 'CORRECTION';
      const correct = async record => {
        await author.goto(config.url + '/workspace'); await author.getByRole('button', { name: 'Your reports', exact: true }).first().click();
        await author.getByRole('button', { name: `Open ${record.source.report.reference}`, exact: true }).click(); await author.getByRole('button', { name: 'Correct this report', exact: true }).click();
        await author.getByLabel('Private correction reason').fill(CANARIES[3]);
        const response = await clickResponse(author, 'Submit correction', '/sync/operations/'); assert.equal(response.status(), 201); const body = response.request().postDataJSON(); assert.equal(body.expected_revision, 1); assert.equal(body.correction_reason, CANARIES[3]);
        const receipt = await response.json(); assert.equal(receipt.revision_no, 2); return { receipt, source: await get(author, `/api/v1/reports/${receipt.report_id}/revisions/2/`) };
      };
      const correctedPrimary = await correct(primary); assert.equal((await feed(full, config.channel_ids[1], 'DEMO-FULL')).count, 0);
      const correctedReturn = await correct(returned);
      await decide(reviewer, correctedPrimary, ['DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY']); await decide(reviewer, correctedReturn, ['DEMO-FULL', 'DEMO-REDUCED']);
      gate('m3_correction');

      stage = 'WITHDRAWAL';
      const beforeWithdrawal = await feed(full, config.channel_ids[1], 'DEMO-FULL');
      await reviewer.goto(config.url + '/workspace'); await reviewer.getByRole('button', { name: 'Review queue', exact: true }).first().click();
      await reviewer.getByRole('combobox', { name: 'Report status', exact: true }).selectOption('ALL'); await reviewer.getByRole('button', { name: 'Apply filters', exact: true }).click();
      await reviewer.getByRole('button', { name: `Review ${correctedPrimary.source.report.reference}`, exact: true }).click();
      // Approved history currently opens SourceRecord directly; a candidate opens
      // BatchReview, whose explicit history action reaches that same source view.
      const history = reviewer.getByRole('button', { name: 'View revision history', exact: true });
      if (await history.isVisible()) await history.click();
      await expect(reviewer.getByRole('heading', { name: 'Immutable original', exact: true })).toBeVisible();
      await expect(reviewer.getByLabel('Private withdrawal reason', { exact: true })).toBeVisible();
      await reviewer.getByLabel('Private withdrawal reason', { exact: true }).fill(CANARIES[5]); const withdrawn = await clickResponse(reviewer, 'Withdraw report', `/reports/${primary.receipt.report_id}/withdrawal/`); assert.equal(withdrawn.status(), 200);
      assert.equal(withdrawn.request().postDataJSON().expected_revision_no, 2);
      await expect(reviewer.getByText('Previously viewed copies cannot be recalled.', { exact: false }).first()).toBeVisible();
      const afterWithdrawal = await feed(full, config.channel_ids[1], 'DEMO-FULL'); assert.equal(afterWithdrawal.count, beforeWithdrawal.count - 1);
      const removals = await get(full, `/api/v1/channels/${config.channel_ids[1]}/removed/`, 200, true); assert.ok(removals.results.some(row => row.state === 'WITHDRAWN'));
      await get(reviewer, `/api/v1/revisions/${correctedPrimary.receipt.revision_id}/candidates/`, 409);
      await full.getByRole('button', { name: 'Refresh now', exact: true }).click();
      await expect(full.getByRole('region', { name: 'Previously delivered publications', exact: true })).toBeVisible();
      gate('m3_withdrawal');

      stage = 'POLICY';
      const admin = await pageFor('administrator'), second = await pageFor('administrator2');
      const changePolicy = async target => {
        await admin.goto(config.url + '/workspace'); await admin.getByLabel('Policy action', { exact: true }).selectOption('ACTIVATE'); await admin.getByLabel('Policy target', { exact: true }).selectOption(target);
        await keyboardCheck(admin.getByRole('checkbox', { name: 'I checked the policy hash and current active policy.', exact: true }));
        const proposed = await clickResponse(admin, 'Propose policy change', '/administration/policy/proposals/'); assert.equal(proposed.status(), 201); const proposal = await proposed.json();
        await second.goto(config.url + '/workspace'); const applied = await clickResponse(second, `Apply proposal ${proposal.id}`, `/administration/policy/proposals/${proposal.id}/apply/`); assert.equal(applied.status(), 201);
      };
      await changePolicy(config.policy_ids[1]); assert.equal((await feed(full, config.channel_ids[1], 'DEMO-FULL')).count, 0);
      await decide(reviewer, correctedReturn, ['DEMO-FULL', 'DEMO-REDUCED']); assert.equal((await feed(full, config.channel_ids[1], 'DEMO-FULL')).count, 1);
      await changePolicy(config.policy_ids[0]); assert.equal((await feed(full, config.channel_ids[1], 'DEMO-FULL')).count, 0);
      await decide(reviewer, correctedReturn, ['DEMO-FULL', 'DEMO-REDUCED']);
      const additional = await submit(author); await decide(reviewer, additional, ['DEMO-FULL', 'DEMO-REDUCED']);
      gate('m3_policy');

      stage = 'INTEGRATION';
      const requestKey = async profile => {
        await admin.goto(config.url + '/workspace'); await admin.getByLabel('Integration label', { exact: true }).fill('Synthetic M3 browser reader'); await admin.getByLabel('Integration channel', { exact: true }).selectOption(config.channel_ids[1]); await admin.getByLabel('Integration profile', { exact: true }).selectOption(profile);
        // Expiry is an explicit browser-local datetime, bounded to one day.
        const expiry = new Date(Date.now() + 86_400_000); const local = new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60_000).toISOString().slice(0, 16); await admin.getByLabel('Integration expiry', { exact: true }).fill(local);
        await keyboardCheck(admin.getByRole('checkbox', { name: 'I confirmed the channel, profile and expiry.', exact: true }));
        const response = await clickResponse(admin, 'Request integration key', '/administration/integration-clients/'); assert.equal(response.status(), 201); return response.json();
      };
      const issued = await requestKey('DEMO-REDUCED'); let key = await admin.getByLabel('One-time integration key', { exact: true }).inputValue(); assert.ok(key.startsWith('kapit_ic_'));
      await admin.getByRole('button', { name: 'Close one-time key', exact: true }).click(); await expect(admin.getByLabel('One-time integration key', { exact: true })).toHaveCount(0);
      const rows = []; let cursor = null;
      do {
        const response = await limited.context().request.get(config.url + '/api/integration/v1/publications/', { headers: { Authorization: 'Bearer ' + key }, params: { limit: 1, ...(cursor ? { cursor } : {}) }, maxRedirects: 0 }); assert.equal(response.status(), 200); const body = await response.json(); assertSafeBody(body); scanned++; rows.push(...body.results); cursor = body.next_cursor;
      } while (cursor && rows.length < 20);
      assert.equal(cursor, null); const recipientRows = (await feed(limited, config.channel_ids[1], 'DEMO-REDUCED')).results; assert.ok(rows.length >= 2); assert.deepEqual(rows, recipientRows);
      await referenceClient(config.url, key, rows.length);
      const revoked = await clickResponse(admin, `Revoke key ${issued.client.key_prefix}`, `/administration/integration-clients/${issued.client.id}/revoke/`); assert.equal(revoked.status(), 200);
      const denied = await limited.context().request.get(config.url + '/api/integration/v1/publications/', { headers: { Authorization: 'Bearer ' + key }, maxRedirects: 0 }); assert.equal(denied.status(), 401); assertSafeBody(await denied.json()); key = '';
      const requested = await requestKey('DEMO-FULL'); assert.equal(requested.client, null); assert.equal(Object.hasOwn(requested, 'key'), false);
      await second.goto(config.url + '/workspace'); const approved = await clickResponse(second, `Approve FULL request ${requested.request.id}`, `/administration/integration-clients/requests/${requested.request.id}/approve/`); assert.equal(approved.status(), 200);
      await admin.goto(config.url + '/workspace'); const collected = await clickResponse(admin, `Collect key ${requested.request.id}`, `/administration/integration-clients/requests/${requested.request.id}/collect/`); assert.equal(collected.status(), 200); await expect(admin.getByLabel('One-time integration key', { exact: true })).toBeVisible(); await admin.getByRole('button', { name: 'Close one-time key', exact: true }).click();
      gate('m3_integration');
      await Promise.all(pending); assert.equal(scanFailures.length, 0); assert.equal(external.length, 0); assert.ok(scanned >= 20); assertGates(gates); stage = 'COMPLETE';
      return { ok: true, stage, scanned_responses: scanned, gates };
    };
    return await Promise.race([execute(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('DEADLINE')), JOURNEY_TIMEOUT_MS); })]);
  } catch { return safeFailure(stage); }
  finally { clearTimeout(timer); for (const context of contexts) await context.close().catch(() => {}); if (browser) await browser.close().catch(() => {}); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let result;
  try { if (process.argv.length !== 2) throw new Error('INPUT'); result = await journey(await readInput()); }
  catch { result = safeFailure('INPUT'); }
  process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.ok ? 0 : 1;
}
