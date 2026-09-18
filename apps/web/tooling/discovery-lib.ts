import { JSDOM } from 'jsdom';
import { canonicalUrl, localeDefinitions, isLocale } from '../src/lib/locales';

export function auditPage(url: string, status: number, html: string): string[] {
  const errors: string[] = [];
  const parsed = new URL(url);
  const [, locale, ...parts] = parsed.pathname.split('/');
  if (!locale || !isLocale(locale)) return ['Unsupported locale'];
  const path = parts.filter(Boolean).join('/');
  const document = new JSDOM(html).window.document;
  if (status !== 200) errors.push(`HTTP ${status}`);
  if (!document.title.includes('Umbra')) errors.push('Missing project title');
  if (!document.querySelector('meta[name="description"]')?.getAttribute('content')) errors.push('Missing description');
  if (document.querySelector('link[rel="canonical"]')?.getAttribute('href') !== url) errors.push('Canonical mismatch');
  if (document.documentElement.lang !== localeDefinitions.find((item) => item.id === locale)!.tag) errors.push('HTML language mismatch');
  for (const item of [...localeDefinitions, { id: 'en' as const, tag: 'x-default' }]) {
    if (document.querySelector(`link[rel="alternate"][hreflang="${item.tag}"]`)?.getAttribute('href') !== canonicalUrl(item.id, path)) errors.push(`Alternate mismatch: ${item.tag}`);
  }
  if (/noindex|nosnippet/i.test(document.querySelector('meta[name="robots"]')?.getAttribute('content') ?? '')) errors.push('Unexpected robots restriction');
  const script = document.querySelector('script[type="application/ld+json"]');
  try {
    const data = JSON.parse(script?.textContent ?? '');
    const page = data['@graph']?.find((item: Record<string, unknown>) => item['@id'] === `${url}#page`);
    if (!page || page.url !== url) errors.push('Structured page mismatch');
    if (path.startsWith('docs/')) {
      const date = document.querySelector('time')?.getAttribute('datetime');
      if (!date || page?.dateModified !== date) errors.push('Document date mismatch');
    }
  } catch { errors.push('Missing or invalid JSON-LD'); }
  if (!document.querySelector('h1')?.textContent?.trim()) errors.push('Missing server-rendered heading');
  return errors;
}

export function sitemapLocations(xml: string): { url: string; lastmod?: string }[] {
  const document = new JSDOM(xml, { contentType: 'application/xml' }).window.document;
  return Array.from(document.querySelectorAll('url'), (node) => ({ url: node.querySelector('loc')!.textContent!, lastmod: node.querySelector('lastmod')?.textContent ?? undefined }));
}
