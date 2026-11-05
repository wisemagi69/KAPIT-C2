// Read-only verification of the retained compiled preview. No login or writes.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { expect } from '@playwright/test';

const BASE = 'http://127.0.0.1:18081';
const DIST = new URL('../dist/', import.meta.url);
const hash = value => createHash('sha256').update(value).digest('hex');
let browser, stage = 'BROWSER';
let result;
try {
  browser = await chromium.launch({ headless: true, timeout: 15000 });
  const context = await browser.newContext({ serviceWorkers: 'block', viewport: { width: 1360, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(12000);
  let pageErrors = 0, unsafeRequests = 0, apiRequests = 0;
  page.on('pageerror', () => { pageErrors++; });
  page.on('request', request => {
    if (!['GET', 'HEAD'].includes(request.method())) unsafeRequests++;
    if (new URL(request.url()).pathname.startsWith('/api/')) apiRequests++;
  });
  stage = 'INDEX';
  const response = await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  assert.equal(response.status(), 200);
  const localIndex = await readFile(new URL('index.html', DIST));
  assert.equal(hash(await response.body()), hash(localIndex));
  await expect(page.getByRole('main')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open workspace', exact: true }).first()).toBeVisible();
  const backendNotice = page.getByRole('heading', { name: 'Workspace server unavailable', exact: true });
  await expect(backendNotice).toHaveCount(0);
  await page.waitForLoadState('networkidle');
  assert.equal(apiRequests, 0);
  stage = 'ASSETS';
  const assetNames = [...localIndex.toString('utf8').matchAll(/(?:src|href)="\/assets\/([A-Za-z0-9_.-]+)"/g)].map(match => match[1]);
  assert.ok(assetNames.some(name => name.endsWith('.js')));
  assert.ok(assetNames.some(name => name.endsWith('.css')));
  const hero = page.locator('main img').first();
  await expect(hero).toBeVisible();
  const heroUrl = new URL(await hero.getAttribute('src'), BASE);
  assert.equal(heroUrl.origin, BASE);
  assert.match(heroUrl.pathname, /^\/assets\/[A-Za-z0-9_.-]+\.webp$/);
  assert.equal(await hero.evaluate(node => node.complete && node.naturalWidth > 0), true);
  assetNames.push(heroUrl.pathname.slice('/assets/'.length));
  for (const name of assetNames) {
    const asset = await context.request.get(BASE + '/assets/' + name);
    assert.equal(asset.status(), 200);
    assert.equal(hash(await asset.body()), hash(await readFile(new URL('assets/' + name, DIST))));
  }
  stage = 'WORKSPACE';
  await page.getByRole('link', { name: 'Open workspace', exact: true }).first().click();
  await expect(page).toHaveURL(BASE + '/workspace');
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  await expect(backendNotice).toBeVisible();
  await expect(page.getByLabel('Username', { exact: true })).toHaveValue('');
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  const workspace = await context.request.get(BASE + '/workspace');
  assert.equal(workspace.status(), 200);
  assert.equal(hash(await workspace.body()), hash(localIndex));
  stage = 'DEEP_LINK';
  await page.setViewportSize({ width: 390, height: 844 });
  const deep = await page.goto(BASE + '/reports', { waitUntil: 'domcontentloaded' });
  assert.equal(deep.status(), 200);
  assert.equal(hash(await deep.body()), hash(localIndex));
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  await expect(backendNotice).toBeVisible();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.equal(pageErrors, 0); assert.equal(unsafeRequests, 0);
  result = { ok: true, url: BASE, index_http: 200, workspace_http: 200, deep_link_http: 200, root_api_requests: 0, assets_verified: assetNames.length, page_errors: pageErrors, unsafe_requests: unsafeRequests, backend_unavailable_notice_in_workspace: true, index_sha256: hash(localIndex) };
} catch {
  result = { ok: false, stage };
} finally {
  if (browser) await browser.close().catch(() => {});
}
process.stdout.write(JSON.stringify(result) + '\n');
process.exitCode = result.ok ? 0 : 1;
