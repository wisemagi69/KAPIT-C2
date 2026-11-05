// Explicit live revocation acceptance (TASK-068 criterion 3). Never loaded by fixture Playwright tests.
// Input on stdin: {"url": "http://127.0.0.1:<port>", "revoke": "<label>", "keep": "<label>"}.
// Output: {"ok": true, ...fixed booleans} or {"ok": false, "stage": <fixed stage>}. No page text is echoed.
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const PASSWORD = 'DemoMaintenance!2026';
const STAGES = new Set(['INPUT', 'BROWSER', 'LOGIN', 'LIST', 'CONFIRM', 'REVOKED', 'COMPLETE']);
const LABEL = /^Synthetic live phone [A-Z]$/;

export function validateInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'keep,revoke,url') throw new Error('INPUT');
  const url = new URL(value.url);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.pathname !== '/' || value.url !== url.origin) throw new Error('INPUT');
  if (!LABEL.test(value.revoke) || !LABEL.test(value.keep) || value.revoke === value.keep) throw new Error('INPUT');
  return value;
}

async function input() {
  const chunks = []; let length = 0;
  for await (const chunk of process.stdin) {
    length += chunk.length;
    if (length > 1024) throw new Error('INPUT');
    chunks.push(chunk);
  }
  return validateInput(JSON.parse(Buffer.concat(chunks).toString('utf8')));
}

async function main() {
  let stage = 'INPUT';
  let browser;
  try {
    const value = await input();
    stage = 'BROWSER';
    browser = await chromium.launch();
    const page = await browser.newPage();
    const article = (label) => page.getByRole('article', { name: `Mobile enrollment ${label}`, exact: true });
    stage = 'LOGIN';
    await page.goto(`${value.url}/workspace`);
    await page.getByLabel('Username', { exact: true }).fill('submitter');
    await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
    await page.getByRole('button', { name: 'Sign in to workspace', exact: true }).click();
    await page.getByRole('button', { name: 'Sign out', exact: true }).waitFor();
    stage = 'LIST';
    await page.getByRole('button', { name: 'Account security', exact: true }).click();
    await page.getByRole('heading', { name: 'Your mobile devices', exact: true }).waitFor();
    for (const label of [value.revoke, value.keep]) {
      await article(label).waitFor();
      if (!(await article(label).innerText()).includes('Not revoked')) throw new Error(stage);
    }
    stage = 'CONFIRM';
    await page.getByRole('button', { name: `Review revocation for ${value.revoke}`, exact: true }).click();
    await page.getByRole('dialog', { name: 'Revoke mobile enrollment?' }).waitFor();
    await page.getByRole('button', { name: 'Revoke enrollment', exact: true }).click();
    stage = 'REVOKED';
    await page.getByRole('dialog', { name: 'Revoke mobile enrollment?' }).waitFor({ state: 'detached' });
    const deadline = Date.now() + 15000;
    for (;;) {
      const text = await article(value.revoke).innerText();
      if (text.includes('Revoked') && !text.includes('Not revoked')) break;
      if (Date.now() > deadline) throw new Error(stage);
      await page.waitForTimeout(250);
    }
    const revokedButtons = await page.getByRole('button', { name: `Review revocation for ${value.revoke}`, exact: true }).count();
    const keptText = await article(value.keep).innerText();
    const keepButtons = await page.getByRole('button', { name: `Review revocation for ${value.keep}`, exact: true }).count();
    if (revokedButtons !== 0 || !keptText.includes('Not revoked') || keepButtons !== 1) throw new Error(stage);
    stage = 'COMPLETE';
    process.stdout.write(JSON.stringify({ ok: true, revoked_shown: true, other_still_active_shown: true, revoke_control_removed: true }) + '\n');
  } catch {
    process.stdout.write(JSON.stringify({ ok: false, stage: STAGES.has(stage) ? stage : 'INPUT' }) + '\n');
    process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
