import type { ReactNode } from 'react';
import { useHydrated } from '@tanstack/react-router';
import {
  ArrowUpRight,
  ChevronDown,
  Languages,
  Menu,
  Moon,
  Sun,
} from 'lucide-react';
import { useTheme } from 'next-themes';
import { useTranslation } from 'react-i18next';
import {
  localeDefinitions,
  localePath,
  repositoryUrl,
  switchLocale,
  type Locale,
} from '../lib/locales';
import { marketingCopy } from '../i18n/marketing';

export type SiteLocale = Locale;

/** The original eclipse mark remains crisp in navigation and documentation. */
export function EclipseMark({
  className = '',
  centered = false,
}: {
  className?: string;
  centered?: boolean;
}) {
  return (
    <svg
      className={`eclipse-mark ${className}`}
      width="32"
      height="32"
      viewBox={centered ? '4.5 2.5 27 27' : '0 0 32 32'}
      fill="none"
      aria-hidden="true"
    >
      <path
        className="eclipse-moon"
        d="M25.8 5.6a13 13 0 1 0 .6 20.1A14.1 14.1 0 0 1 25.8 5.6Z"
        fill="currentColor"
      />
      <path
        d="M26.9 8.2a10 10 0 0 1 1.7 13.5"
        stroke="currentColor"
        strokeWidth="1.4"
        strokeLinecap="round"
        opacity=".45"
      />
      <circle cx="28" cy="5" r="1.5" fill="currentColor" />
    </svg>
  );
}

const languageMenuLocales = [...localeDefinitions].sort((a, b) =>
  a.id.localeCompare(b.id, 'en'),
);

export function LanguageSwitcher({
  locale,
  currentPath,
}: {
  locale: Locale;
  currentPath: string;
}) {
  const { t } = useTranslation('marketing', { lng: locale });
  const current = localeDefinitions.find(({ id }) => id === locale)!;
  return (
    <details className="language-picker">
      <summary
        aria-label={t('ui.language', {
          defaultValue: marketingCopy[locale].ui.language,
        })}
      >
        <Languages size={17} aria-hidden="true" />
        <span className="language-current">{current.name}</span>
        <ChevronDown size={12} aria-hidden="true" />
      </summary>
      <div className="language-options">
        {languageMenuLocales.map(({ id, name, tag }) => (
          <a
            key={id}
            href={switchLocale(currentPath, id)}
            hrefLang={tag}
            lang={tag}
            aria-current={id === locale ? 'true' : undefined}
            onClick={(event) => {
              event.currentTarget.href = switchLocale(
                window.location.pathname +
                  window.location.search +
                  window.location.hash,
                id,
              );
            }}
          >
            {name}
            <span aria-hidden="true">{id === locale ? '✓' : ''}</span>
          </a>
        ))}
      </div>
    </details>
  );
}

export function ThemeButton({ locale }: { locale: Locale }) {
  const ready = useHydrated();
  const { resolvedTheme, setTheme } = useTheme();
  const { t } = useTranslation('marketing', { lng: locale });
  return (
    <button
      className="theme-button icon-button"
      type="button"
      disabled={!ready}
      aria-label={t('ui.theme', {
        defaultValue: marketingCopy[locale].ui.theme,
      })}
      onClick={() => {
        setTheme(resolvedTheme === 'light' ? 'dark' : 'light');
      }}
    >
      <Sun className="theme-sun" size={18} aria-hidden="true" />
      <Moon className="theme-moon" size={18} aria-hidden="true" />
    </button>
  );
}

/** A progressively enhanced shell: all core navigation works before hydration. */
export function SiteShell({
  locale,
  children,
  currentPath = localePath(locale),
}: {
  locale: Locale;
  children: ReactNode;
  currentPath?: string;
}) {
  const copy = marketingCopy[locale];
  const links = [
    { path: 'docs', label: copy.nav.docs },
    { path: 'protocol', label: copy.nav.protocol },
    { path: 'download', label: copy.nav.download },
  ];
  return (
    <div className="umbra-site">
      <a href="#main-content" className="skip-link">
        {copy.ui.skip}
      </a>
      <header className="site-header">
        <div className="site-header-inner">
          <a className="wordmark" href={localePath(locale)} aria-label="Umbra">
            <EclipseMark />
            <span>
              umbra<span className="wordmark-dot">.</span>
            </span>
          </a>
          <nav className="desktop-nav" aria-label={copy.footer.project}>
            {links.map(({ path, label }) => (
              <a
                key={path}
                href={localePath(locale, path)}
                aria-current={
                  currentPath.startsWith(localePath(locale, path))
                    ? 'page'
                    : undefined
                }
              >
                {label}
              </a>
            ))}
          </nav>
          <div className="header-actions">
            <LanguageSwitcher locale={locale} currentPath={currentPath} />
            <span className="header-divider" />
            <ThemeButton locale={locale} />
            <a
              className="icon-button github-header"
              href={repositoryUrl}
              aria-label={copy.nav.github}
            >
              <svg width="19" height="19" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                {/* GitHub mark shared with fumadocs-ui (MIT, Copyright 2023 Fuma). */}
                <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
              </svg>
            </a>
            <details className="mobile-navigation">
              <summary className="icon-button" aria-label={copy.ui.menu}>
                <Menu size={21} aria-hidden="true" />
              </summary>
              <nav aria-label={copy.footer.resources}>
                {links.map(({ path, label }) => (
                  <a key={path} href={localePath(locale, path)}>
                    {label}
                  </a>
                ))}
                <a href={localePath(locale, 'security')}>{copy.nav.security}</a>
                <a href={localePath(locale, 'changelog')}>
                  {copy.nav.changelog}
                </a>
                <a href={repositoryUrl}>
                  {copy.nav.github}
                  <ArrowUpRight size={15} aria-hidden="true" />
                </a>
              </nav>
            </details>
          </div>
        </div>
      </header>
      <main id="main-content">{children}</main>
      <footer className="site-footer">
        <div className="container footer-main">
          <div className="footer-brand">
            <a className="wordmark" href={localePath(locale)}>
              <EclipseMark />
              <span>
                umbra<span className="wordmark-dot">.</span>
              </span>
            </a>
            <p>{copy.footer.description}</p>
          </div>
          <div className="footer-column">
            <h2>{copy.footer.project}</h2>
            <a href={localePath(locale, 'protocol')}>{copy.nav.protocol}</a>
            <a href={localePath(locale, 'download')}>{copy.nav.download}</a>
            <a href={localePath(locale, 'security')}>{copy.nav.security}</a>
          </div>
          <div className="footer-column">
            <h2>{copy.footer.resources}</h2>
            <a href={localePath(locale, 'docs')}>{copy.nav.docs}</a>
            <a href={localePath(locale, 'changelog')}>{copy.nav.changelog}</a>
            <a href={repositoryUrl}>
              {copy.nav.github}
              <ArrowUpRight size={13} aria-hidden="true" />
            </a>
          </div>
        </div>
        <div className="container footer-bottom">
          <span>
            © Umbra contributors ·{' '}
            <a href={`${repositoryUrl}/blob/main/LICENSE`}>
              {copy.footer.license}
            </a>
          </span>
          <span>{copy.footer.legal}</span>
        </div>
      </footer>
    </div>
  );
}
