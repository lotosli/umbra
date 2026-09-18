import { describe, expect, it } from 'vitest';
import {
  canonicalOrigin, canonicalUrl, defaultLocale, isLocale, languageTag, localeDefinitions,
  localePath, locales, negotiateLocale, repositoryUrl, switchLocale,
} from './locales';
import { pageHead } from './seo';
import { publicResponseHeaders, redirectTarget } from './routing';
import { sitemapXml } from './sitemap';
import { normalizeSearch, searchDocuments, validateSearchIndex, type SearchDocument } from './search';

describe('seven-language public URL contract', () => {
  it('separates lowercase route IDs from correct HTML language tags', () => {
    expect(locales).toEqual(['en', 'zh-hans', 'zh-hant', 'fr', 'es', 'ja', 'ca']);
    expect(defaultLocale).toBe('en');
    for (const locale of localeDefinitions) {
      expect(isLocale(locale.id)).toBe(true);
      expect(languageTag(locale.id)).toBe(locale.tag);
      expect(locale.name.length).toBeGreaterThan(1);
    }
    expect(languageTag('zh-hans')).toBe('zh-Hans');
    expect(languageTag('zh-hant')).toBe('zh-Hant');
    expect(isLocale('zh-CN')).toBe(false);
    expect(isLocale('unknown')).toBe(false);
  });

  it('normalizes edge slashes while keeping stable article IDs', () => {
    expect(localePath('en')).toBe('/en/');
    expect(localePath('en', '/docs/getting-started/installation///')).toBe('/en/docs/getting-started/installation/');
    expect(canonicalUrl('fr')).toBe('https://umbra.cat/fr/');
    expect(canonicalUrl('ca', 'docs/reference/cli')).toBe('https://umbra.cat/ca/docs/reference/cli/');
  });

  it('switches languages without losing a deep article, query or fragment', () => {
    expect(switchLocale('/en/docs/reference/cli/?source=nav#commands', 'ja')).toBe('/ja/docs/reference/cli/?source=nav#commands');
    expect(switchLocale('/', 'zh-hant')).toBe('/zh-hant/');
    expect(switchLocale('/docs/reference/cli', 'fr')).toBe('/fr/docs/reference/cli/');
    expect(switchLocale('https://umbra.cat/ca/download/#linux', 'es')).toBe('/es/download/#linux');
  });
});

describe('root Accept-Language negotiation', () => {
  it('ranks quality values and matches exact and regional tags', () => {
    expect(negotiateLocale('fr-CA,fr;q=0.9')).toBe('fr');
    expect(negotiateLocale('ja;q=0.8,en;q=0.9')).toBe('en');
    expect(negotiateLocale('es-MX')).toBe('es');
    expect(negotiateLocale('ca-ES,es;q=0.5')).toBe('ca');
  });

  it('maps Chinese variants to the supported script', () => {
    expect(negotiateLocale('zh-CN,zh;q=0.9')).toBe('zh-hans');
    expect(negotiateLocale('zh-TW')).toBe('zh-hant');
    expect(negotiateLocale('zh-HK')).toBe('zh-hant');
    expect(negotiateLocale('zh-Hant-TW')).toBe('zh-hant');
    expect(negotiateLocale('zh-SG')).toBe('zh-hans');
    expect(negotiateLocale('zh')).toBe('zh-hans');
  });

  it('falls back to the default locale for wildcards and unsupported languages', () => {
    expect(negotiateLocale('*')).toBe('en');
    expect(negotiateLocale('pt-BR;q=0.9')).toBe('en');
    expect(negotiateLocale('de;q=0,pt-BR')).toBe('en');
    expect(negotiateLocale('')).toBe('en');
  });
});

describe('search-visible localized metadata', () => {
  it('creates reciprocal alternatives, self canonical and default-language fallback for every locale', () => {
    for (const locale of locales) {
      const head = pageHead(locale, 'docs/reference/cli', 'CLI reference', 'Supported command-line options.');
      expect(head.meta).toContainEqual({ title: 'CLI reference · Umbra' });
      expect(head.meta).toContainEqual({ property: 'og:image', content: `https://umbra.cat/social/${locale}.png` });
      expect(head.links).toContainEqual({ rel: 'manifest', href: `/manifests/${locale}.webmanifest` });
      expect(head.meta).toContainEqual({ property: 'og:url', content: canonicalUrl(locale, 'docs/reference/cli') });
      expect(head.links).toContainEqual({ rel: 'canonical', href: canonicalUrl(locale, 'docs/reference/cli') });
      for (const alternate of localeDefinitions) {
        expect(head.links).toContainEqual({ rel: 'alternate', hrefLang: alternate.tag, href: canonicalUrl(alternate.id, 'docs/reference/cli') });
      }
      expect(head.links).toContainEqual({ rel: 'alternate', hrefLang: 'x-default', href: 'https://umbra.cat/en/docs/reference/cli/' });
    }
  });

  it('uses the project title and native-script locale metadata on the homepage', () => {
    const head = pageHead('zh-hant', '', 'Umbra', '保護連線隱私');
    expect(head.meta).toContainEqual({ title: 'Umbra — 你的連線， 由你掌控。' });
    expect(head.meta).toContainEqual({ property: 'og:locale', content: 'zh_Hant' });
    expect(head.meta).toContainEqual({ name: 'description', content: '保護連線隱私' });
  });

  it('emits only production URLs for every document/language and escapes XML data', () => {
    const xml = sitemapXml(['getting-started/installation', 'reference/cli'], ['1.0.0-alpha']);
    const parsed = new DOMParser().parseFromString(xml, 'application/xml');
    expect(parsed.querySelector('parsererror')).toBeNull();
    expect(parsed.getElementsByTagName('url')).toHaveLength(63);
    const locations = Array.from(parsed.getElementsByTagName('loc'), (node) => node.textContent);
    expect(locations).toContain('https://umbra.cat/ja/docs/reference/cli/');
    expect(locations).toContain('https://umbra.cat/ca/changelog/1.0.0-alpha/');
    expect(locations.every((url) => url?.startsWith(canonicalOrigin) && url.endsWith('/'))).toBe(true);
    expect(parsed.getElementsByTagNameNS('http://www.w3.org/1999/xhtml', 'link')).toHaveLength(441);
    expect(sitemapXml(['a&b<c"d'])).toContain('a&amp;b&lt;c&quot;d');
  });
});

describe('redirect-only aliases and deployment headers', () => {
  it.each([
    ['https://www.umbra.cat/en/docs/?a=1', 'https://umbra.cat/en/docs/?a=1'],
    ['https://git.umbra.cat/', repositoryUrl],
    ['https://docs.umbra.cat/', 'https://umbra.cat/en/docs/'],
    ['https://docs.umbra.cat/en/docs/reference/cli/?x=1', 'https://umbra.cat/en/docs/reference/cli/?x=1'],
    ['https://docs.umbra.cat/reference/cli', 'https://umbra.cat/en/docs/reference/cli/'],
    ['https://fr.umbra.cat/docs/reference/cli/?x=1', 'https://umbra.cat/fr/docs/reference/cli/?x=1'],
    ['https://ja.umbra.cat/', 'https://umbra.cat/ja/'],
    ['https://umbra.cat/en/docs?from=nav', 'https://umbra.cat/en/docs/?from=nav'],
    ['https://preview.workers.dev/ja/docs', 'https://preview.workers.dev/ja/docs/'],
  ])('maps %s to the declared canonical destination', (input, expected) => {
    expect(redirectTarget(new URL(input))).toBe(expected);
  });

  it.each(['https://umbra.cat/en/', 'https://umbra.cat/en/search.json', 'https://umbra.cat.evil.test/en/', 'https://unknown.umbra.cat/', 'https://git.umbra.cat/repository'])('does not invent a redirect for %s', (input) => {
    expect(redirectTarget(new URL(input))).toBeUndefined();
  });

  it('keeps HTML conservatively cached and preview hosts out of indexing', () => {
    const original = new Headers({ 'content-type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=3600' });
    const preview = publicResponseHeaders(new URL('https://preview.workers.dev/en/'), original);
    expect(preview.get('Cache-Control')).toBe('no-cache');
    expect(preview.get('X-Robots-Tag')).toBe('noindex, nofollow');
    expect(preview.get('X-Content-Type-Options')).toBe('nosniff');
    expect(preview.get('Referrer-Policy')).toBe('strict-origin-when-cross-origin');
    expect(original.get('Cache-Control')).toBe('public, max-age=3600');
    const production = publicResponseHeaders(new URL('https://umbra.cat/en/'), new Headers({ 'content-type': 'application/json', 'Cache-Control': 'public, max-age=300' }));
    expect(production.has('X-Robots-Tag')).toBe(false);
    expect(production.get('Cache-Control')).toBe('public, max-age=300');
    expect(publicResponseHeaders(new URL('https://umbra.cat/'), new Headers()).has('Cache-Control')).toBe(false);
  });
});

function document(id: string, fields: Partial<SearchDocument> = {}): SearchDocument {
  return { id, title: 'Reference', description: 'Command line reference', content: 'bind_addr = loopback', url: `/en/docs/${id}/`, ...fields };
}

describe('local multilingual document search', () => {
  it.each([
    ['sécurité', 'securite'], ['CONEXIÓN', 'conexion'], ['configuració', 'configuracio'],
    ['客户端配置', '客户端配置'], ['用戶端設定', '用戶端設定'], ['クライアント設定', 'クライアント設定'],
    ['BIND_ADDR', 'bind_addr'],
  ])('normalizes %s without losing its searchable form', (input, expected) => {
    expect(normalizeSearch(input)).toBe(expected);
  });

  it('ranks titles before descriptions and body matches and requires all query terms', () => {
    const body = document('body', { content: 'security bind_addr' });
    const summary = document('summary', { description: 'security bind_addr' });
    const title = document('title', { title: 'security bind_addr' });
    expect(searchDocuments([body, summary, title], 'SECURITY bind_addr').map(({ id }) => id)).toEqual(['title', 'summary', 'body']);
    expect(searchDocuments([body], 'security absent')).toEqual([]);
    expect(searchDocuments([body], ' \n ')).toEqual([]);
    expect(searchDocuments([body], 'unknown')).toEqual([]);
  });

  it('finds CJK phrases, accents and configuration keys without remote requests', () => {
    const docs = [
      document('zh', { title: '客户端配置 用戶端設定' }), document('ja', { content: 'クライアント設定' }),
      document('fr', { description: 'sécurité réseau' }), document('es', { title: 'conexión configuración' }),
      document('ca', { content: 'connexió configuració bind_addr' }),
    ];
    for (const [query, id] of [['客户端', 'zh'], ['用戶端', 'zh'], ['クライアント', 'ja'], ['securite reseau', 'fr'], ['conexion', 'es'], ['connexio configuracio', 'ca']]) {
      expect(searchDocuments(docs, query!)[0]?.id).toBe(id);
    }
    expect(searchDocuments(docs, 'bind_addr').some(({ id }) => id === 'ca')).toBe(true);
  });

  it('keeps source order for ties and bounds visible results', () => {
    const docs = Array.from({ length: 20 }, (_, index) => document(String(index)));
    expect(searchDocuments(docs, 'reference').map(({ id }) => id)).toEqual(Array.from({ length: 12 }, (_, index) => String(index)));
  });

  it('validates loaded JSON fields and rejects cross-language and escaping destinations', () => {
    expect(validateSearchIndex([document('reference/cli')], 'en')).toEqual([document('reference/cli')]);
    expect(() => validateSearchIndex({}, 'en')).toThrow('Invalid search index');
    for (const invalid of [null, 'text', 12]) expect(() => validateSearchIndex([invalid], 'en')).toThrow('Invalid search document');
    expect(() => validateSearchIndex([{ ...document('cli'), title: 2 }], 'en')).toThrow('Invalid search field: title');
    expect(() => validateSearchIndex([document('cli', { url: '/fr/docs/cli/' })], 'en')).toThrow('Invalid search destination');
    expect(() => validateSearchIndex([document('cli', { url: '/en/docs/../../fr/' })], 'en')).toThrow('Invalid search destination');
  });
});
