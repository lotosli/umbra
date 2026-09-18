import { expect, test } from '@playwright/test';
import { localeDefinitions } from '../../src/lib/locales';

for (const locale of localeDefinitions) {
  test(`${locale.id}: full protocol reference renders without JavaScript on mobile`, async ({ browser, baseURL }) => {
    const context = await browser.newContext({ javaScriptEnabled: false, viewport: { width: 390, height: 844 }, baseURL });
    const page = await context.newPage();
    try {
      const response = await page.goto(`/${locale.id}/docs/reference/protocol-design/`);
      expect(response?.status()).toBe(200);
      const article = page.locator('article');
      await expect(article.locator('h2, h3')).toHaveCount(40);
      await expect(article.locator('.reference-diagram')).toHaveCount(3);
      for (const figure of await article.locator('.reference-diagram').all()) {
        const image = figure.locator('img');
        await image.scrollIntoViewIfNeeded();
        await expect.poll(() => image.evaluate((element: HTMLImageElement) => element.complete && element.naturalWidth > 0)).toBe(true);
        const captionBox = await figure.locator('figcaption').boundingBox();
        const imageBox = await image.boundingBox();
        expect(captionBox!.y).toBeGreaterThanOrEqual(imageBox!.y + imageBox!.height);
        const link = figure.locator('figcaption a');
        const asset = await context.request.get((await link.getAttribute('href'))!);
        expect(asset.ok()).toBe(true);
        expect(asset.headers()['content-type']).toContain('image/svg+xml');
        await figure.locator('summary').click();
        await expect(figure.locator('details')).toHaveAttribute('open', '');
        await expect(figure.locator('details code')).toBeVisible();
      }
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      const search = await context.request.get(`/search/${locale.id}.json`);
      expect(await search.json()).toEqual(expect.arrayContaining([expect.objectContaining({ url: `/${locale.id}/docs/reference/protocol-design/` })]));
      await page.screenshot({ path: `test-results/protocol-${locale.id}-mobile.png`, fullPage: false });
    } finally { await context.close(); }
  });
}
