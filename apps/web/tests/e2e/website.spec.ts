import { expect, test } from '@playwright/test';
import { localeDefinitions } from '../../src/lib/locales';
import { marketingCopy } from '../../src/i18n/marketing';
import { docsCopy } from '../../src/i18n/docs';
import { documents } from '../../src/content/documents.generated';
import { releaseVersion } from '../../src/lib/releases';

for (const locale of localeDefinitions) {
  test(`${locale.id}: localized SSR pages and document reading`, async ({ page, request }) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const response = await page.goto(`/${locale.id}/`);
    expect(response?.status()).toBe(200);
    await expect(page.locator('html')).toHaveAttribute('lang', locale.tag);
    await expect(page.getByRole('heading', { level: 1 })).toContainText(marketingCopy[locale.id].hero.title);
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', `https://umbra.cat/${locale.id}/`);
    expect(await page.locator('link[rel="alternate"][hreflang]').count()).toBe(8);
    await expect(page.locator('link[rel="alternate"][hreflang="x-default"]')).toHaveAttribute('href', 'https://umbra.cat/en/');

    const article = documents.find((item) => item.locale === locale.id && item.id === 'reference/cli')!;
    const documentResponse = await page.goto(article.url);
    expect(documentResponse?.status()).toBe(200);
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(article.title);
    await expect(page.locator('pre').first()).toBeVisible();
    await expect(page.getByRole('link', { name: new RegExp(docsCopy[locale.id].edit) })).toBeVisible();
    expect(errors).toEqual([]);

    const index = await request.get(`/search/${locale.id}.json`);
    expect(index.ok()).toBe(true);
    const entries = await index.json() as { url: string; content: string }[];
    expect(entries).toHaveLength(18);
    expect(entries.every((entry) => entry.url.startsWith(`/${locale.id}/docs/`) && entry.content.length > 150)).toBe(true);
  });

  test(`${locale.id}: benefits lead to sourced comparisons on mobile`, async ({ page, request }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`/${locale.id}/`);
    await expect(page.locator('.facts-strip')).toContainText('SOCKS5');
    await expect(page.locator('main')).not.toContainText(/90\s*[%％]/);
    await page.locator('main').getByRole('link', { name: marketingCopy[locale.id].hero.explore, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/${locale.id}/protocol/$`));
    await expect(page.locator('.layer-row')).toHaveCount(6);
    await expect(page.locator('.layer-list')).toContainText('VMess');
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.locator('main').getByRole('link', { name: marketingCopy[locale.id].protocol.read, exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/${locale.id}/docs/reference/protocol/$`));
    const article = page.locator('article');
    await expect(article.locator('table tbody tr')).toHaveCount(6);
    for (const name of ['Umbra', 'Xray', 'VMess', 'Trojan', 'Shadowsocks', 'Hysteria']) {
      await expect(article.locator('table')).toContainText(name);
    }
    await expect(article).toContainText('1.0.0-alpha');
    await expect(article).not.toContainText('**');
    await expect(article.locator('a[href="https://shadowsocks.org/doc/sip022.html"]')).toBeVisible();

    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    const index = await request.get(`/search/${locale.id}.json`);
    const entries = await index.json() as { url: string; content: string }[];
    expect(entries.find((entry) => entry.url.endsWith('/docs/reference/protocol/'))?.content).toContain('VMess');
    await page.goto(`/${locale.id}/docs/concepts/security-model/`);
    await expect(page.locator('article')).toContainText('ML-KEM');
    await expect(page.locator('article')).toContainText('Chrome 150');
    await expect(page.locator('article')).toContainText('ring');
  });

  test(`${locale.id}: every published URL returns content`, async ({ request }) => {
    const urls = ['', 'download/', 'protocol/', 'security/', 'changelog/', 'docs/'].map((path) => `/${locale.id}/${path}`);
    urls.push(...documents.filter((item) => item.locale === locale.id).map((item) => item.url));
    urls.push(`/${locale.id}/changelog/${releaseVersion}/`);
    for (const url of urls) {
      const response = await request.get(url);
      expect(response.status(), url).toBe(200);
      const body = await response.text();
      expect(body, url).toContain('<h1');
      expect(body, url).not.toContain('Something went wrong');
    }
  });
}

test('canonical redirects, real 404 and public metadata endpoints', async ({ request }) => {
  const root = await request.get('/', { maxRedirects: 0 });
  expect(root.status()).toBe(307);
  expect(root.headers().location).toMatch(/\/en\/$/);
  const zhRoot = await request.get('/', {
    maxRedirects: 0,
    headers: { 'accept-language': 'zh-CN,zh;q=0.9' },
  });
  expect(zhRoot.status()).toBe(307);
  expect(zhRoot.headers().location).toMatch(/\/zh-hans\/$/);
  const slash = await request.get('/en/docs/reference/cli', { maxRedirects: 0 });
  expect(slash.status()).toBe(308);
  expect(slash.headers().location).toMatch(/\/en\/docs\/reference\/cli\/$/);
  for (const url of ['/xx/', '/en/missing/', '/en/docs/missing/', '/en/changelog/unknown/']) {
    const missing = await request.get(url);
    expect(missing.status(), url).toBe(404);
    expect(await missing.text()).toContain('404');
  }
  const sitemap = await request.get('/sitemap.xml');
  expect(sitemap.ok()).toBe(true);
  expect(await sitemap.text()).toContain('https://umbra.cat/ca/docs/reference/cli/');
  const robots = await request.get('/robots.txt');
  expect(await robots.text()).toContain('Sitemap: https://umbra.cat/sitemap.xml');
  const manifest = await request.get('/manifest.webmanifest');
  expect((await manifest.json()).name).toBe('Umbra');
});

test('documentation is readable without client JavaScript', async ({ browser, baseURL }) => {
  const context = await browser.newContext({ javaScriptEnabled: false, baseURL });
  const page = await context.newPage();
  await page.goto('/zh-hans/docs/getting-started/quick-start/');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await expect(page.locator('pre').first()).toBeVisible();
  expect((await page.locator('article').textContent())?.length).toBeGreaterThan(300);
  await context.close();
});

test('keyboard readers can skip documentation navigation', async ({ page }) => {
  await page.goto('/en/docs/getting-started/quick-start/');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: marketingCopy.en.ui.skip })).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#nd-page')).toBeFocused();
});

test('local search finds configuration terms and navigates to an article', async ({ page }) => {
  await page.goto('/en/docs/');
  await expect(page.locator('.umbra-docs-card').first()).toHaveAttribute('href', '/en/docs/getting-started/introduction/');
  await page.getByRole('button', { name: /Search/ }).first().click();
  const input = page.getByRole('textbox');
  await expect(input).toBeVisible();
  await input.fill('udp_transport');
  await expect(page.getByRole('dialog')).toContainText(/transport|configuration|client/i);
  await input.press('ArrowDown');
  await input.press('Enter');
  await expect(page).toHaveURL(/\/en\/docs\/.+/);
  await expect(page.getByRole('dialog')).not.toBeVisible();
});

test('language switching preserves the article and themes work', async ({ page }) => {
  await page.goto('/en/docs/reference/cli/');
  await page.getByRole('button', { name: docsCopy.en.chooseLanguage }).click();
  await page.getByRole('button', { name: 'Français', exact: true }).click();
  await expect(page).toHaveURL(/\/fr\/docs\/reference\/cli\/$/);
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  await page.goto('/en/');
  await expect(page.locator('html')).toHaveClass(/light/);
  await page.getByRole('button', { name: marketingCopy.en.ui.theme }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.reload();
  await expect(page.locator('html')).toHaveClass(/dark/);
});

test('mobile navigation and desktop layout fit their viewports', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/en/');
  await page.screenshot({ path: testInfo.outputPath('home-desktop.png'), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/zh-hans/');
  await page.getByLabel(marketingCopy['zh-hans'].ui.menu, { exact: true }).first().click();
  await expect(page.locator('.mobile-navigation').getByRole('link', { name: marketingCopy['zh-hans'].nav.docs })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('home-mobile.png'), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.goto('/ja/docs/reference/configuration/');
  await page.screenshot({ path: testInfo.outputPath('docs-mobile.png'), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
