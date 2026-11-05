import { expect, test, type Page } from '@playwright/test';
import { mkdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Actual compiled public page and existing unavailable-backend login shell.
// No API fixture interception or authentication is used by these checks.
const BASE = new URL('/', process.env.KAPIT_UI_QA_URL ?? 'http://127.0.0.1:18081').toString();
const SHOTS = new URL('../../.cache/landing-qa/', import.meta.url);
const BACKEND_NOTICE = 'Workspace server unavailable';

async function openHome(page: Page) {
  const errors: string[] = [], api: string[] = [], external: string[] = [];
  page.on('pageerror', () => errors.push('PAGE_ERROR'));
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.pathname.startsWith('/api/')) api.push(url.pathname);
    if (['http:', 'https:'].includes(url.protocol) && url.origin !== new URL(BASE).origin) external.push(url.origin);
  });
  const response = await page.goto(BASE, { waitUntil: 'networkidle' });
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('main')).toBeVisible();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.getByText(BACKEND_NOTICE, { exact: true })).toHaveCount(0);
  expect(api).toEqual([]); expect(external).toEqual([]); expect(errors).toEqual([]);
  return { errors, api, external };
}

async function screenshot(page: Page, name: string, fullPage = true) {
  await mkdir(SHOTS, { recursive: true });
  if (fullPage) {
    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    const step = Math.max(400, (page.viewportSize()?.height ?? 900) * 0.8);
    for (let y = 0; y < height; y += step) {
      await page.evaluate(top => window.scrollTo({ top, behavior: 'instant' }), y);
      await page.waitForTimeout(90);
    }
    await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'instant' }));
    await page.waitForTimeout(800);
  }
  await page.screenshot({ path: fileURLToPath(new URL(name + '.png', SHOTS)), fullPage, animations: 'disabled' });
}

for (const width of [1440, 1920, 390, 360]) {
  test(`public landing ${width}px loads local artwork without API calls or overflow`, async ({ page }) => {
    await page.setViewportSize({ width, height: width < 500 ? 844 : 1000 });
    const evidence = await openHome(page);
    const images = page.locator('main img');
    expect(await images.count()).toBeGreaterThan(0);
    expect(await images.evaluateAll(nodes => nodes.every(node => node instanceof HTMLImageElement && node.complete && node.naturalWidth > 0 && !!node.getAttribute('alt')?.trim()))).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await expect(page.getByRole('link', { name: 'Open workspace', exact: true }).first()).toBeVisible();
    await screenshot(page, `landing-${width}`);
    expect(evidence.errors).toEqual([]); expect(evidence.api).toEqual([]);
  });
}

test('public navigation links have real destinations and anchors move to their sections', async ({ page }) => {
  await openHome(page);
  const destinations = await page.locator('a').evaluateAll(nodes => nodes.map(node => node.getAttribute('href')));
  expect(destinations.length).toBeGreaterThan(3);
  for (const destination of destinations) {
    expect(destination).toBeTruthy(); expect(destination).not.toBe('#');
    const url = new URL(destination!, BASE);
    expect(url.origin).toBe(new URL(BASE).origin);
    expect(['/', '/workspace']).toContain(url.pathname);
    if (url.hash) expect(await page.locator(`[id=${JSON.stringify(decodeURIComponent(url.hash.slice(1)))}]`).count()).toBe(1);
  }
  const sectionLink = page.locator('header a[href^="#"]').first();
  const hash = await sectionLink.getAttribute('href');
  await sectionLink.click();
  await expect(page).toHaveURL(new RegExp(hash!.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$'));
  const target = page.locator(`[id=${JSON.stringify(hash!.slice(1))}]`);
  await expect(target).toBeInViewport();
});

test('workspace CTA opens the existing login and history/reload/home navigation work', async ({ page }) => {
  await openHome(page);
  await page.getByRole('link', { name: 'Open workspace', exact: true }).first().click();
  await expect(page).toHaveURL(new URL('workspace', BASE).toString());
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  await expect(page.getByText(BACKEND_NOTICE, { exact: true })).toBeVisible();
  await expect(page.getByLabel('Username', { exact: true })).toHaveValue('');
  await expect(page.getByLabel('Password', { exact: true })).toHaveValue('');
  await page.reload({ waitUntil: 'networkidle' });
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  await page.goBack({ waitUntil: 'networkidle' });
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.getByText(BACKEND_NOTICE, { exact: true })).toHaveCount(0);
  await page.goForward({ waitUntil: 'networkidle' });
  await expect(page.getByRole('heading', { name: 'Welcome back.', exact: true })).toBeVisible();
  await page.getByRole('link', { name: /back.*home|home/i }).first().click();
  await expect(page).toHaveURL(BASE);
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
});

for (const width of [390, 360]) {
  test(`mobile navigation ${width}px opens, closes on Escape and follows anchors`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await openHome(page);
    const toggle = page.getByRole('button', { name: 'Open navigation', exact: true });
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).not.toBeVisible();
    await toggle.click();
    const close = page.getByRole('button', { name: 'Close navigation', exact: true });
    await expect(close).toHaveAttribute('aria-expanded', 'true');
    await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible();
    await screenshot(page, `landing-menu-${width}`, false);
    await page.keyboard.press('Escape');
    await expect(toggle).toBeFocused();
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await toggle.click();
    await page.getByRole('link', { name: 'How it works', exact: true }).click();
    await expect(page).toHaveURL(BASE + '#workflow');
    await expect(toggle).toHaveAttribute('aria-expanded', 'false');
    await expect(page.getByRole('tablist', { name: 'Reporting workflow stages' })).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}

test('workflow tabs change the illustration and support keyboard selection without API requests', async ({ page }) => {
  const evidence = await openHome(page);
  const tabs = page.getByRole('tablist', { name: 'Reporting workflow stages' }).getByRole('tab');
  await expect(tabs).toHaveCount(3);
  await tabs.first().scrollIntoViewIfNeeded();
  await expect(tabs.first()).toHaveAttribute('aria-selected', 'true');
  const panel = page.getByRole('tabpanel');
  await expect(panel).toContainText('Private original');
  await tabs.nth(1).click();
  await expect(tabs.nth(1)).toHaveAttribute('aria-selected', 'true');
  await expect(panel).toContainText('Awaiting human decision');
  await expect(panel).toContainText('Not published');
  await page.keyboard.press('ArrowRight');
  await expect(tabs.nth(2)).toBeFocused();
  await expect(tabs.nth(2)).toHaveAttribute('aria-selected', 'true');
  await expect(panel).toContainText('Approved version');
  await expect(panel).toContainText('Sharing channel');
  await page.keyboard.press('Home');
  await expect(tabs.first()).toBeFocused();
  await expect(panel).toContainText('Private original');
  await page.keyboard.press('End');
  await expect(tabs.nth(2)).toBeFocused();
  expect(evidence.api).toEqual([]); expect(evidence.errors).toEqual([]);
  await screenshot(page, 'landing-workflow', false);
});

test('keyboard entry exposes a visible skip link and focused navigation', async ({ page }) => {
  await openHome(page);
  await page.keyboard.press('Tab');
  const skip = page.getByRole('link', { name: 'Skip to content', exact: true });
  await expect(skip).toBeFocused(); await expect(skip).toBeInViewport();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('main')).toBeFocused();
  const workspace = page.getByRole('link', { name: 'Open workspace', exact: true }).first();
  await workspace.focus();
  expect(await workspace.evaluate(node => { const style = getComputedStyle(node); return style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0 || style.boxShadow !== 'none'; })).toBe(true);
});

test('essential public content remains visible without IntersectionObserver', async ({ page }) => {
  await page.addInitScript(() => { delete (window as unknown as Record<string, unknown>).IntersectionObserver; });
  await openHome(page);
  const sections = page.locator('main section');
  expect(await sections.count()).toBeGreaterThan(2);
  for (const section of await sections.all()) {
    await section.scrollIntoViewIfNeeded();
    await expect(section).toBeVisible();
    expect(await section.evaluate(node => getComputedStyle(node).opacity)).not.toBe('0');
  }
});

test('reduced-motion preference stops decorative animation while content stays usable', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await openHome(page);
  expect(await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
  const endless = await page.evaluate(() => document.getAnimations().filter(animation => animation.playState === 'running' && animation.effect?.getTiming().iterations === Infinity).length);
  expect(endless).toBe(0);
  await page.locator('footer').scrollIntoViewIfNeeded();
  await expect(page.locator('footer')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open workspace', exact: true }).last()).toBeVisible();
});

test('homepage works under the exact backend CSP header in an explicit policy simulation', async ({ page }) => {
  const source = await readFile(new URL('../../backend/config/middleware.py', import.meta.url), 'utf8');
  const expression = source.match(/"Content-Security-Policy":\s*\(([\s\S]*?)\)/)?.[1];
  expect(expression).toBeTruthy();
  const policy = [...expression!.matchAll(/"([^"]*)"/g)].map(match => match[1]).join('');
  expect(policy).toContain("script-src 'self'");
  // Only the HTML header is overlaid on real compiled output; no API is mocked.
  await page.route(BASE, async route => {
    const response = await route.fetch();
    await route.fulfill({ response, headers: { ...response.headers(), 'Content-Security-Policy': policy } });
  });
  await page.addInitScript(() => {
    (window as unknown as Record<string, unknown>).__landingCspViolations = 0;
    document.addEventListener('securitypolicyviolation', () => { (window as unknown as Record<string, number>).__landingCspViolations++; });
  });
  await openHome(page);
  expect(await page.locator('main img').evaluateAll(nodes => nodes.every(node => node instanceof HTMLImageElement && node.complete && node.naturalWidth > 0))).toBe(true);
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).__landingCspViolations)).toBe(0);
  await screenshot(page, 'landing-csp', false);
});
