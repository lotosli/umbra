import { isLocale, canonicalOrigin, type Locale } from './locales';
import { releaseVersion, releaseUrl } from './releases';

const sections = ['getting-started', 'guides', 'configuration', 'concepts', 'reference', 'troubleshooting', 'contributing'] as const;
type Section = typeof sections[number];
type PageKind = Section | 'home' | 'download' | 'protocol' | 'security' | 'changelog' | 'docs' | 'other';
export interface NavigationMeasurement {
  event: 'download_click' | 'quickstart_open' | 'docs_next_step';
  locale: Locale;
  source: PageKind;
  destination: PageKind;
  version: string;
  platform?: 'macOS' | 'Linux' | 'Windows';
}
function pageKind(path: string): PageKind {
  const parts = path.split('/').filter(Boolean);
  if (!parts[1]) return 'home';
  if (parts[1] === 'docs' && sections.includes(parts[2] as Section)) return parts[2] as Section;
  return ['download', 'protocol', 'security', 'changelog', 'docs'].includes(parts[1]) ? parts[1] as PageKind : 'other';
}

/** Only predefined categories are emitted: never search terms, URLs, fragments or configuration. */
export function navigationMeasurement(fromPath: string, href: string, platform?: string): NavigationMeasurement | undefined {
  const locale = fromPath.split('/')[1];
  if (!locale || !isLocale(locale)) return;
  let target: URL;
  try { target = new URL(href, canonicalOrigin + fromPath); } catch { return; }
  const download = target.origin + target.pathname.replace(/\/$/, '') === releaseUrl;
  const quickstart = target.origin === canonicalOrigin && target.pathname === `/${locale}/docs/getting-started/quick-start/`;
  const next = target.origin === canonicalOrigin && target.pathname.startsWith(`/${locale}/docs/`) && pageKind(target.pathname) !== 'other' && target.pathname !== fromPath;
  if (!download && !quickstart && !next) return;
  return {
    event: download ? 'download_click' : quickstart ? 'quickstart_open' : 'docs_next_step',
    locale, source: pageKind(fromPath), destination: download ? 'download' : pageKind(target.pathname), version: releaseVersion,
    ...(download && ['macOS', 'Linux', 'Windows'].includes(platform ?? '') ? { platform: platform as NavigationMeasurement['platform'] } : {}),
  };
}

/** Local extension point only. No cookies, storage, fetch, beacon or collector is installed. */
export function observeNavigation(document: Document, window: Window): () => void {
  const listener = (event: MouseEvent) => {
    if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const anchor = event.target instanceof Element ? event.target.closest('a[href]') : null;
    if (!anchor) return;
    const detail = navigationMeasurement(window.location.pathname, anchor.getAttribute('href')!, anchor.closest('.download-card')?.querySelector('h2')?.textContent ?? undefined);
    if (!detail) return;
    try { window.dispatchEvent(new CustomEvent('umbra:measurement', { detail })); } catch { /* Measurement never prevents navigation. */ }
  };
  document.addEventListener('click', listener);
  return () => document.removeEventListener('click', listener);
}
