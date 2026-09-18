import { expect, test } from '@playwright/test';
import { localeDefinitions } from '../../src/lib/locales';
import { marketingCopy } from '../../src/i18n/marketing';
import { releaseVersion } from '../../src/lib/releases';

for (const locale of localeDefinitions) {
  test(`${locale.id}: redesigned page templates fit all supported widths`, async ({ page }) => {
    test.setTimeout(180_000);
    for (const width of [320, 390, 768, 1280, 1440]) {
      await page.setViewportSize({ width, height: 1000 });
      for (const path of ['', 'download/', 'protocol/', 'security/', 'changelog/', `changelog/${releaseVersion}/`, 'docs/', 'docs/reference/cli/']) {
        await page.goto(`/${locale.id}/${path}`);
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - innerWidth);
        expect(overflow, `${locale.id}/${path} at ${width}px`).toBeLessThanOrEqual(1);
      }
    }
  });
}

test('desktop hero, neutral themes, readable contrast and reduced motion', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/en/');
  const copy = await page.locator('.hero-copy').boundingBox();
  const code = await page.locator('.hero-code').boundingBox();
  expect(copy!.x + copy!.width).toBeLessThan(code!.x);
  await expect(page.locator('.hero-code pre')).toContainText('cargo build --release');
  await expect(page.locator('.hero-code pre')).not.toContainText('gpui');
  await expect(page.locator('.hero h1')).toHaveCSS('font-weight', '700');
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: marketingCopy.en.ui.skip })).toBeFocused();
  await expect(page.getByRole('link', { name: marketingCopy.en.ui.skip })).toHaveCSS('outline-style', 'solid');
  for (const theme of ['light', 'dark']) {
    if (theme === 'dark') await page.getByRole('button', { name: marketingCopy.en.ui.theme }).click();
    await expect(page.locator('body')).toHaveCSS('background-color', theme === 'light' ? 'rgb(255, 255, 255)' : 'rgb(10, 10, 10)');
    const contrast = await page.locator('.hero-description').evaluate((el) => {
      const luminance = (rgb: string) => {
        const channels = rgb.match(/\d+/g)!.slice(0, 3).map(Number).map((v) => v / 255).map((v) => v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4);
        return channels[0]! * .2126 + channels[1]! * .7152 + channels[2]! * .0722;
      };
      const a = luminance(getComputedStyle(el).color);
      const b = luminance(getComputedStyle(document.body).backgroundColor);
      return (Math.max(a,b) + .05) / (Math.min(a,b) + .05);
    });
    expect(contrast).toBeGreaterThanOrEqual(4.5);
    await page.screenshot({ path: testInfo.outputPath(`home-${theme}.png`), fullPage: true });
  }
  await page.goto('/en/protocol/');
  await expect(page.locator('.diagram-packet').first()).toHaveCSS('animation-name', 'none');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(10, 10, 10)');
  await page.goto('/en/docs/');
  await expect(page.locator('body')).toHaveCSS('background-color', 'rgb(10, 10, 10)');
});
