import { writeFile } from 'node:fs/promises';
import { auditPage, sitemapLocations } from './discovery-lib';

const origin = process.env.AUDIT_ORIGIN ?? 'http://127.0.0.1:3000';
const output = process.env.AUDIT_OUTPUT ?? '/tmp/umbra-discovery-audit.json';
const sitemap = await fetch(`${origin}/sitemap.xml`);
if (!sitemap.ok) throw new Error(`Sitemap HTTP ${sitemap.status}`);
const urls = sitemapLocations(await sitemap.text());
const results: { url: string; errors: string[] }[] = [];
for (let start = 0; start < urls.length; start += 4) {
  results.push(...await Promise.all(urls.slice(start, start + 4).map(async ({ url, lastmod }) => {
    try {
      const response = await fetch(origin + new URL(url).pathname);
      const errors = auditPage(url, response.status, await response.text());
      if (/noindex|nosnippet/i.test(response.headers.get('x-robots-tag') ?? '') && origin === 'https://umbra.cat') errors.push('Production X-Robots-Tag restriction');
      if (new URL(url).pathname.split('/').length > 4 && url.includes('/docs/') && !lastmod) errors.push('Missing sitemap document lastmod');
      return { url, errors };
    } catch (error) { return { url, errors: [String(error)] }; }
  })));
}
await writeFile(output, JSON.stringify({ origin, checkedAt: new Date().toISOString(), pages: results.length, results }, null, 2));
const failed = results.filter(({ errors }) => errors.length);
console.log(`${results.length} pages audited; ${failed.length} failed. Evidence: ${output}`);
if (failed.length) { console.error(failed); process.exitCode = 1; }
