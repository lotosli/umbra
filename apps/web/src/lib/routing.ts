import { canonicalOrigin, defaultLocale, isLocale, localePath, repositoryUrl } from './locales';

export function redirectTarget(url: URL): string | undefined {
  if (url.hostname === 'www.umbra.cat') return canonicalOrigin + url.pathname + url.search;
  if (url.hostname === 'git.umbra.cat' && url.pathname === '/') return repositoryUrl;
  if (url.hostname === 'docs.umbra.cat') {
    const segments = url.pathname.split('/').filter(Boolean);
    const first = segments[0];
    const locale = first && isLocale(first) ? segments.shift()! : defaultLocale;
    if (segments[0] === 'docs') segments.shift();
    return `${canonicalOrigin}/${locale}/docs/${segments.length ? `${segments.join('/')}/` : ''}${url.search}`;
  }
  const language = url.hostname.endsWith('.umbra.cat') ? url.hostname.slice(0, -'.umbra.cat'.length) : '';
  if (isLocale(language)) return canonicalOrigin + localePath(language, url.pathname) + url.search;
  const first = url.pathname.split('/')[1];
  if (first && isLocale(first) && !url.pathname.endsWith('/') && !url.pathname.split('/').at(-1)?.includes('.')) {
    const normalized = new URL(url);
    normalized.pathname += '/';
    return normalized.toString();
  }
  return undefined;
}

export function publicResponseHeaders(url: URL, original: Headers): Headers {
  const headers = new Headers(original);
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (url.hostname !== 'umbra.cat') headers.set('X-Robots-Tag', 'noindex, nofollow');
  if (headers.get('content-type')?.includes('text/html')) headers.set('Cache-Control', 'no-cache');
  return headers;
}
