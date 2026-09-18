import { marketingCopy } from '../i18n/marketing';
import { searchTitles } from '../i18n/seo';
import { structuredData, serializeStructuredData, type ContentDates } from './structured-data';
import { canonicalUrl, languageTag, localeDefinitions, defaultLocale } from './locales';
import type { Locale } from './locales';

export function pageHead(locale: Locale, path: string, title: string, description: string, dates?: ContentDates) {
  const fullTitle = searchTitles[locale][path] ?? (title.includes('Umbra') ? title : `${title} · Umbra`);
  const url = canonicalUrl(locale, path);
  return {
    scripts: [{ type: 'application/ld+json', children: serializeStructuredData(structuredData(locale, path, fullTitle, description, dates)) }],
    meta: [
      { title: fullTitle },
      { name: 'description', content: description },
      { property: 'og:title', content: fullTitle },
      { property: 'og:description', content: description },
      { property: 'og:type', content: 'website' },
      { property: 'og:url', content: url },
      { property: 'og:locale', content: languageTag(locale).replace('-', '_') },
      { property: 'og:site_name', content: 'Umbra' },
      { property: 'og:image', content: `https://umbra.cat/social/${locale}.png` },
      { property: 'og:image:alt', content: marketingCopy[locale].hero.description },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
    links: [
      { rel: 'canonical', href: url },
      { rel: 'manifest', href: `/manifests/${locale}.webmanifest` },
      ...localeDefinitions.map(({ id, tag }) => ({ rel: 'alternate', hrefLang: tag, href: canonicalUrl(id, path) })),
      { rel: 'alternate', hrefLang: 'x-default', href: canonicalUrl(defaultLocale, path) },
    ],
  };
}
