import { canonicalOrigin, canonicalUrl, languageTag, repositoryUrl, type Locale } from './locales';
import { releaseVersion, releaseUrl, platforms } from './releases';
import { docsCopy } from '../i18n/docs';

export interface ContentDates { updatedAt: string; reviewedAt: string }

/** Identity and facts are shared with the visible release and documentation data. */
export function structuredData(locale: Locale, path: string, title: string, description: string, dates?: ContentDates) {
  const url = canonicalUrl(locale, path);
  const websiteId = `${canonicalOrigin}/#website`;
  const softwareId = `${canonicalOrigin}/#software`;
  const graph: Record<string, unknown>[] = [{
    '@type': path.startsWith('docs/') ? ['TechArticle', 'WebPage'] : 'WebPage', '@id': `${url}#page`,
    url, name: title, description, inLanguage: languageTag(locale),
    isPartOf: { '@id': websiteId },
    ...(dates ? { dateModified: dates.updatedAt, lastReviewed: dates.reviewedAt, version: releaseVersion } : {}),
  }, { '@type': 'WebSite', '@id': websiteId, url: canonicalOrigin, name: 'Umbra', sameAs: repositoryUrl }];
  if (path === '' || path === 'download') graph.push({
    '@type': path === 'download' ? 'SoftwareApplication' : 'SoftwareSourceCode',
    '@id': path === '' ? `${canonicalOrigin}/#source` : softwareId, name: 'Umbra', url: canonicalUrl(locale), description,
    license: `${repositoryUrl}/blob/main/LICENSE`,
    ...(path === '' ? { codeRepository: repositoryUrl, programmingLanguage: 'Rust', version: releaseVersion, targetProduct: { '@type': 'SoftwareApplication', '@id': softwareId, name: 'Umbra' } } : {
      softwareVersion: releaseVersion, operatingSystem: [...new Set(platforms.map(({ os }) => os))],
      applicationCategory: 'NetworkingApplication', downloadUrl: releaseUrl,
    }),
    sameAs: repositoryUrl,
  });
  if (path.startsWith('docs/')) graph.push({
    '@type': 'BreadcrumbList', '@id': `${url}#breadcrumb`,
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Umbra', item: canonicalUrl(locale) },
      { '@type': 'ListItem', position: 2, name: docsCopy[locale].title, item: canonicalUrl(locale, 'docs') },
      { '@type': 'ListItem', position: 3, name: title.replace(/ · Umbra$/, ''), item: url },
    ],
  });
  return { '@context': 'https://schema.org', '@graph': graph };
}

/** Prevent content from terminating the script element in SSR HTML. */
export function serializeStructuredData(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}
