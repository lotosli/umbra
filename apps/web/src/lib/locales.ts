export const localeDefinitions = [
  { id: 'en', tag: 'en', name: 'English' },
  { id: 'zh-hans', tag: 'zh-Hans', name: '简体中文' },
  { id: 'zh-hant', tag: 'zh-Hant', name: '繁體中文' },
  { id: 'fr', tag: 'fr', name: 'Français' },
  { id: 'es', tag: 'es', name: 'Español' },
  { id: 'ja', tag: 'ja', name: '日本語' },
  { id: 'ca', tag: 'ca', name: 'Català' },
] as const;

export type Locale = (typeof localeDefinitions)[number]['id'];
export const locales = localeDefinitions.map(({ id }) => id);
export const defaultLocale: Locale = 'en';
export const canonicalOrigin = 'https://umbra.cat';
export const repositoryUrl = 'https://github.com/lotosli/umbra';

export function isLocale(value: string): value is Locale {
  return localeDefinitions.some(({ id }) => id === value);
}

export function languageTag(locale: Locale): string {
  return localeDefinitions.find(({ id }) => id === locale)!.tag;
}

export function localePath(locale: Locale, path = ''): string {
  const clean = path.replace(/^\/+|\/+$/g, '');
  return `/${locale}/${clean ? `${clean}/` : ''}`;
}

export function switchLocale(path: string, locale: Locale): string {
  const url = new URL(path, canonicalOrigin);
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts[0] && isLocale(parts[0])) parts.shift();
  return localePath(locale, parts.join('/')) + url.search + url.hash;
}

export function canonicalUrl(locale: Locale, path = ''): string {
  return canonicalOrigin + localePath(locale, path);
}

export function negotiateLocale(acceptLanguage: string): Locale {
  const candidates = acceptLanguage
    .split(',')
    .map((part) => {
      const [rawTag, ...params] = part.trim().split(';');
      const q = params.map((param) => param.trim()).find((param) => param.startsWith('q='));
      const quality = q ? Number.parseFloat(q.slice(2)) : 1;
      return {
        tag: (rawTag ?? '').trim().toLowerCase(),
        quality: Number.isFinite(quality) ? quality : 0,
      };
    })
    .filter(({ tag, quality }) => tag !== '' && tag !== '*' && quality > 0)
    .sort((a, b) => b.quality - a.quality);

  for (const { tag } of candidates) {
    const exact = localeDefinitions.find(({ id }) => id === tag);
    if (exact) return exact.id;
    if (tag === 'zh' || tag.startsWith('zh-')) {
      return /hant|tw|hk|mo/.test(tag) ? 'zh-hant' : 'zh-hans';
    }
    const primary = tag.split('-')[0];
    const regional = localeDefinitions.find(({ id }) => id.split('-')[0] === primary);
    if (regional) return regional.id;
  }
  return defaultLocale;
}
