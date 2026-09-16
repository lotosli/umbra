import { canonicalOrigin, localeDefinitions, localePath } from './locales';

export function sitemapXml(documentIds: string[], releaseVersions: string[] = []): string {
  const paths = ['', 'download', 'protocol', 'security', 'changelog', 'docs', ...releaseVersions.map((version) => `changelog/${version}`), ...documentIds.map((id) => `docs/${id}`)];
  const escapeXml = (value: string) => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
  const urls = paths.flatMap((path) => localeDefinitions.map(({ id }) => {
    const alternate = localeDefinitions.map((locale) => `<xhtml:link rel="alternate" hreflang="${locale.tag}" href="${escapeXml(canonicalOrigin + localePath(locale.id, path))}"/>`).join('');
    return `<url><loc>${escapeXml(canonicalOrigin + localePath(id, path))}</loc>${alternate}</url>`;
  }));
  return `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">${urls.join('')}</urlset>`;
}
