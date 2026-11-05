// One bounded read-only visual inspection of the user's public references.
import { mkdir } from 'node:fs/promises';
import { chromium } from 'playwright';
const folder = new URL('../../.cache/landing-qa/references/', import.meta.url);
await mkdir(folder, { recursive: true });
let browser;
try {
  browser = await chromium.launch({ headless: true, timeout: 15000 });
  const results = await Promise.all([
    ['anduril', 'https://www.anduril.com/'],
    ['shield-ai', 'https://shield.ai/'],
    ['palantir', 'https://www.palantir.com/'],
  ].map(async ([name, url]) => {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    try {
      const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 15000 });
      await page.screenshot({ path: new URL(name + '.png', folder).pathname.replace(/^\/(\w:)/, '$1') });
      return { name, reached: true, status: response?.status(), title: await page.title() };
    } catch { return { name, reached: false, code: 'PUBLIC_REFERENCE_UNAVAILABLE' }; }
    finally { await page.close(); }
  }));
  process.stdout.write(JSON.stringify(results) + '\n');
} finally { if (browser) await browser.close(); }
