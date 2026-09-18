import { describe, expect, it, vi } from 'vitest';
import { pageHead } from './seo';
import { serializeStructuredData, structuredData } from './structured-data';
import { navigationMeasurement, observeNavigation } from './measurement';
import { auditPage, sitemapLocations } from '../../tooling/discovery-lib';
import { sitemapXml } from './sitemap';
import { locales, canonicalUrl } from './locales';
import { frontmatterSchema } from '../../tooling/content-lib';

function page(locale: typeof locales[number], path: string) {
  const head = pageHead(locale, path, 'Install Umbra', 'Install and configure Umbra.', { updatedAt: '2026-09-18', reviewedAt: '2026-09-18' });
  const language = locale === 'zh-hans' ? 'zh-Hans' : locale === 'zh-hant' ? 'zh-Hant' : locale;
  return `<html lang="${language}"><head><title>${head.meta[0]!.title}</title><meta name="description" content="Install Umbra">${head.links.map((l) => `<link rel="${l.rel}" href="${l.href}" ${'hrefLang' in l ? `hreflang="${l.hrefLang}"` : ''}>`).join('')}<script type="application/ld+json">${head.scripts[0]!.children}</script></head><body><h1>Install Umbra</h1><time datetime="2026-09-18">18 Sep 2026</time></body></html>`;
}

describe('discovery contract', () => {
  it('audits all locale identities and document dates in server HTML', () => {
    for (const locale of locales) for (const path of ['', 'download', 'docs/getting-started/installation']) expect(auditPage(canonicalUrl(locale, path), 200, page(locale, path))).toEqual([]);
  });
  it('emits actual software identity, platform facts and breadcrumbs without invented reviews', () => {
    const home = structuredData('en', '', 'Umbra', 'A self-hosted proxy');
    expect(home['@graph']).toContainEqual(expect.objectContaining({ '@type': 'SoftwareSourceCode', programmingLanguage: 'Rust', codeRepository: 'https://github.com/lotosli/umbra' }));
    expect(structuredData('en', 'download', 'Download', 'Download Umbra')['@graph']).toContainEqual(expect.objectContaining({ '@type': 'SoftwareApplication', operatingSystem: expect.arrayContaining(['Linux', 'Windows', 'macOS']) }));
    expect(JSON.stringify(home)).not.toMatch(/aggregateRating|reviewCount/);
    const docs = structuredData('fr', 'docs/reference/cli', 'CLI', 'CLI reference', { updatedAt: '2026-09-18', reviewedAt: '2026-09-18' });
    expect(docs['@graph']).toContainEqual(expect.objectContaining({ '@type': 'BreadcrumbList', itemListElement: expect.arrayContaining([expect.objectContaining({ position: 2, item: 'https://umbra.cat/fr/docs/' })]) }));
  });
  it('escapes script termination and Unicode separators while preserving JSON semantics', () => {
    const value = { text: '</script><script>alert(1)</script>\u2028\u2029' };
    const serialized = serializeStructuredData(value);
    expect(serialized).not.toContain('</script>');
    expect(JSON.parse(serialized)).toEqual(value);
  });
  it('reports broken status, language, canonical, alternatives, dates and restrictions', () => {
    expect(auditPage('https://umbra.cat/xx/', 200, '')).toEqual(['Unsupported locale']);
    const broken = auditPage('https://umbra.cat/en/docs/reference/cli/', 500, '<html><meta name="robots" content="noindex"><script type="application/ld+json">{"@graph":[]}</script></html>');
    for (const error of ['HTTP 500', 'Missing project title', 'Missing description', 'Canonical mismatch', 'HTML language mismatch', 'Alternate mismatch: en', 'Unexpected robots restriction', 'Structured page mismatch', 'Document date mismatch', 'Missing server-rendered heading']) expect(broken).toContain(error);
    expect(auditPage('https://umbra.cat/en/', 200, '<html/>')).toContain('Missing or invalid JSON-LD');
  });
  it('keeps sitemap dates stable across rebuilds and rejects invalid document dates', () => {
    const dates = { 'en/docs/reference/cli': '2026-09-18', 'fr/docs/reference/cli': 'bad' };
    const xml = sitemapXml(['reference/cli'], [], dates);
    expect(sitemapLocations(xml)).toContainEqual({ url: 'https://umbra.cat/en/docs/reference/cli/', lastmod: '2026-09-18' });
    expect(sitemapLocations(xml)).toContainEqual({ url: 'https://umbra.cat/fr/docs/reference/cli/', lastmod: undefined });
    expect(sitemapXml(['reference/cli'], [], dates)).toBe(xml);
    for (const invalid of ['2026-02-30', '2026-13-01', '2099-01-01', '', undefined]) expect(frontmatterSchema.shape.updatedAt.safeParse(invalid).success).toBe(false);
  });
});

describe('bounded local measurement interface', () => {
  it('emits useful categories and never includes arbitrary URL data', () => {
    expect(navigationMeasurement('/en/', '/en/docs/getting-started/quick-start/?secret=abc#key')).toMatchObject({ event: 'quickstart_open', source: 'home', destination: 'getting-started' });
    const value = navigationMeasurement('/en/download/', 'https://github.com/lotosli/umbra/releases?secret=abc', 'Linux');
    expect(value).toMatchObject({ event: 'download_click', platform: 'Linux' });
    expect(JSON.stringify(value)).not.toMatch(/secret|abc|https/);
    expect(navigationMeasurement('/fr/docs/reference/cli/', '/fr/docs/guides/client/')).toMatchObject({ event: 'docs_next_step', source: 'reference', destination: 'guides' });
    expect(navigationMeasurement('/en/unknown/', '/en/docs/')).toMatchObject({ source: 'other', destination: 'docs' });
    expect(navigationMeasurement('/en/', 'https://github.com/lotosli/umbra/releases', 'secret')).not.toHaveProperty('platform');
    for (const [from, to] of [['/xx/', '/en/docs/'], ['/en/', 'https://external.test/'], ['/en/', 'http://['], ['/en/docs/', '/en/docs/']]) expect(navigationMeasurement(from!, to!)).toBeUndefined();
  });
  it('dispatches locally, cleans up, respects modified clicks and tolerates collector failure', () => {
    window.history.replaceState({}, '', '/en/');
    document.body.innerHTML = '<article class="download-card"><h2>Linux</h2><a href="https://github.com/lotosli/umbra/releases"><span>Download</span></a></article><a id="docs" href="/en/docs/">Docs</a>';
    const dispatch = vi.spyOn(window, 'dispatchEvent').mockReturnValue(true);
    const cleanup = observeNavigation(document, window);
    document.querySelector('span')!.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    expect(dispatch).toHaveBeenCalledWith(expect.objectContaining({ type: 'umbra:measurement', detail: expect.objectContaining({ platform: 'Linux' }) }));
    dispatch.mockClear();
    document.querySelector('span')!.dispatchEvent(new MouseEvent('click', { bubbles: true, ctrlKey: true }));
    document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(dispatch).not.toHaveBeenCalled();
    dispatch.mockImplementation(() => { throw new Error('collector failed'); });
    expect(() => document.querySelector('#docs')!.dispatchEvent(new MouseEvent('click', { bubbles: true }))).not.toThrow();
    cleanup(); dispatch.mockClear();
    document.querySelector('span')!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(dispatch).not.toHaveBeenCalled(); dispatch.mockRestore();
  });
});
