// Explicit real-Chromium review of a report that arrived from the user's phone (TASK-064 browser step).
// Never loaded by fixture Playwright tests. Input on stdin: {"url","channel_id","reference"}.
// Output: fixed booleans/ids only; no page text or report content.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { assertRecipientBody, assertRecipientIdentity } from './live-journey.mjs';

const PASSWORD = 'DemoMaintenance!2026';
const STAGES = new Set(['INPUT', 'BROWSER', 'LOGIN', 'REVIEW', 'PUBLICATION_FEED', 'PUBLICATION_READ', 'PUBLICATION_DETAIL', 'PUBLICATION_EQUAL', 'DENIAL', 'COMPLETE']);

export function validateInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'channel_id,reference,url') throw new Error('INPUT');
  const url = new URL(value.url);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/' || value.url !== url.origin) throw new Error('INPUT');
  if (!/^[0-9a-f-]{36}$/i.test(value.channel_id) || !/^[A-Za-z0-9-]{1,40}$/.test(value.reference)) throw new Error('INPUT');
  return value;
}

async function input() {
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) { length += chunk.length; if (length > 1024) throw new Error('INPUT'); chunks.push(chunk); }
  return validateInput(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}

export async function review(config) {
  let stage = 'BROWSER', browser;
  const contexts = [], scans = []; let scanFailures = 0;
  try {
    const { chromium } = await import('playwright');
    const { expect } = await import('@playwright/test');
    browser = await chromium.launch({ headless: true, timeout: 15000 });
    const newPage = async (recipient = false) => {
      const context = await browser.newContext({ viewport: { width: 1360, height: 900 }, serviceWorkers: 'block' });
      contexts.push(context);
      const page = await context.newPage();
      page.setDefaultTimeout(15000);
      if (recipient) page.on('response', response => {
        if (response.url().startsWith(config.url + '/api/v1/'))
          scans.push(response.json().then(assertRecipientBody).catch(() => { scanFailures++; }));
      });
      await page.goto(config.url + '/workspace', { waitUntil: 'domcontentloaded' });
      return page;
    };
    const login = async (page, username) => {
      await page.getByLabel('Username', { exact: true }).fill(username);
      await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
      await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
      await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
    };
    const get = async (page, suffix) => {
      const response = await page.context().request.get(config.url + '/api/v1' + suffix);
      return { status: response.status(), body: await response.json().catch(() => null) };
    };
    stage = 'LOGIN';
    const recipient = await newPage(true); await login(recipient, 'recipient');
    assertRecipientIdentity((await get(recipient, '/me/')).body, config.channel_id);
    const before = await get(recipient, `/channels/${config.channel_id}/feed/`);
    if (before.status !== 200 || before.body.count !== 0) throw new Error(stage);
    const reviewer = await newPage(); await login(reviewer, 'reviewer');

    stage = 'REVIEW';
    await expect(async () => {
      await reviewer.getByRole('button', { name: 'Refresh queue', exact: true }).click();
      await expect(reviewer.getByRole('button', { name: `Review ${config.reference}`, exact: true })).toBeVisible({ timeout: 1000 });
    }).toPass({ timeout: 30000, intervals: [300, 1000] });
    const reviewResponse = reviewer.waitForResponse(r => /\/variants\/[^/]+\/review\/$/.test(new URL(r.url()).pathname));
    await reviewer.getByRole('button', { name: `Review ${config.reference}`, exact: true }).click();
    const reviewed = await reviewResponse; if (reviewed.status() !== 200) throw new Error(stage);
    const candidate = (await reviewed.json()).candidate; assertRecipientBody(candidate);
    await expect(reviewer.getByRole('heading', { name: 'Original report', exact: true })).toBeVisible();
    await expect(reviewer.getByRole('heading', { name: 'Reduced candidate', exact: true })).toBeVisible();
    await reviewer.getByRole('button', { name: 'Review & approve', exact: true }).click();
    await expect(reviewer.getByRole('button', { name: 'Approve & share', exact: true })).toBeDisabled();
    await reviewer.getByRole('checkbox', { name: 'I have checked the complete candidate, source revision, policy and sharing audience.' }).check();
    const decisionResponse = reviewer.waitForResponse(r => /\/variants\/[^/]+\/decisions\/$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST');
    await reviewer.getByRole('button', { name: 'Approve & share', exact: true }).click();
    const decided = await decisionResponse; if (decided.status() !== 200) throw new Error(stage);
    const outcome = await decided.json();
    if (outcome.action !== 'APPROVE' || outcome.publication_ids?.length !== 1) throw new Error(stage);

    stage = 'PUBLICATION_FEED';
    await recipient.getByRole('button', { name: 'Refresh now', exact: true }).click();
    await expect(recipient.getByRole('button', { name: candidate.title, exact: true })).toBeVisible();
    stage = 'PUBLICATION_READ';
    await recipient.getByRole('button', { name: 'Read update', exact: true }).click();
    await expect(recipient.getByRole('heading', { name: 'Approved reduced representation', exact: true })).toBeVisible();
    stage = 'PUBLICATION_DETAIL';
    const publication = await get(recipient, `/publications/${outcome.publication_ids[0]}/`);
    if (publication.status !== 200) throw new Error(stage);
    assertRecipientBody(publication.body);
    stage = 'PUBLICATION_EQUAL';
    // Key-order-insensitive, as the M1 live journey (PostgreSQL jsonb does not preserve key order).
    assert.deepEqual(publication.body.projection, candidate);

    stage = 'DENIAL';
    const source = await get(recipient, new URL(reviewed.url()).pathname.slice('/api/v1'.length));
    if (![403, 404].includes(source.status)) throw new Error(stage);
    await Promise.all(scans);
    if (scanFailures !== 0 || scans.length < 3) throw new Error(stage);
    stage = 'COMPLETE';
    return { ok: true, stage, publication_id: outcome.publication_ids[0], recipient_responses_scanned: scans.length,
             projection_equals_approved_candidate: true, recipient_source_denied: true };
  } catch {
    return { ok: false, stage: STAGES.has(stage) ? stage : 'INPUT' };
  } finally {
    for (const context of contexts) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let result;
  try { result = await review(await input()); } catch { result = { ok: false, stage: 'INPUT' }; }
  process.stdout.write(JSON.stringify(result) + '\n');
  process.exitCode = result.ok ? 0 : 1;
}
