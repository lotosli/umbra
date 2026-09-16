import { canonicalUrl, languageTag, localeDefinitions, defaultLocale } from './locales';
import type { Locale } from './locales';

export function pageHead(locale: Locale, path: string, title: string, description: string) {
  const fullTitle = title === 'Umbra' ? 'Umbra — Privacy, in plain sight.' : `${title} · Umbra`;
  const url = canonicalUrl(locale, path);
  return {
    meta: [
      { title: fullTitle },
      { name: 'description', content: description },
      { property: 'og:title', content: fullTitle },
      { property: 'og:description', content: description },
      { property: 'og:type', content: 'website' },
      { property: 'og:url', content: url },
      { property: 'og:locale', content: languageTag(locale).replace('-', '_') },
      { property: 'og:site_name', content: 'Umbra' },
      { property: 'og:image', content: 'https://umbra.cat/social-card.png' },
      { name: 'twitter:card', content: 'summary_large_image' },
    ],
    links: [
      { rel: 'canonical', href: url },
      ...localeDefinitions.map(({ id, tag }) => ({ rel: 'alternate', hrefLang: tag, href: canonicalUrl(id, path) })),
      { rel: 'alternate', hrefLang: 'x-default', href: canonicalUrl(defaultLocale, path) },
    ],
  };
}
