import { render, screen } from '@testing-library/react';
import { useTranslation } from 'react-i18next';
import { describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { SiteProviders } from './providers';
import { marketingCopy } from '../i18n/marketing';
import { docsCopy } from '../i18n/docs';
import { locales } from '../lib/locales';

const captured = vi.hoisted(() => ({ props: {} as Record<string, unknown> }));
vi.mock('fumadocs-ui/provider/tanstack', () => ({ RootProvider: (props: { children: ReactNode }) => { captured.props = props; return <>{props.children}</>; } }));
vi.mock('./search-dialog', () => ({ SearchDialog: ({ locale }: { locale: string }) => <div>search:{locale}</div> }));

function TranslationProbe() {
  const { t } = useTranslation('marketing');
  return <p>{t('nav.docs')}</p>;
}

describe('request-scoped translations', () => {
  it.each(locales)('supplies matching UI, document and search translations for %s', (locale) => {
    render(<SiteProviders locale={locale}><TranslationProbe /></SiteProviders>);
    expect(screen.getByText(marketingCopy[locale].nav.docs)).toBeVisible();
    const i18n = captured.props.i18n as { locale: string; translations: Record<string, string>; locales: unknown[] };
    expect(i18n.locale).toBe(locale);
    expect(i18n.translations['On this page(table of contents)']).toBe(docsCopy[locale].toc);
    expect(i18n.locales).toHaveLength(7);
    expect(captured.props.theme).toEqual({ defaultTheme: 'light', enableSystem: false });
    const Search = (captured.props.search as { SearchDialog: (props: { open: boolean; onOpenChange: () => void }) => ReactNode }).SearchDialog;
    render(<>{Search({ open: true, onOpenChange: () => undefined })}</>);
    expect(screen.getByText(`search:${locale}`)).toBeVisible();
  });

  it('keeps simultaneous provider instances in their own languages', () => {
    render(<><SiteProviders locale="fr"><TranslationProbe /></SiteProviders><SiteProviders locale="ja"><TranslationProbe /></SiteProviders></>);
    expect(screen.getByText(marketingCopy.fr.nav.docs)).toBeVisible();
    expect(screen.getByText(marketingCopy.ja.nav.docs)).toBeVisible();
  });

  it('preserves document, query and fragment when changing language', () => {
    render(<SiteProviders locale="en"><TranslationProbe /></SiteProviders>);
    const assign = vi.fn();
    const original = window;
    vi.stubGlobal('window', { location: { pathname: '/en/docs/reference/cli/', search: '?q=server', hash: '#flags', assign } });
    const i18n = captured.props.i18n as { onLocaleChange: (locale: string) => void };
    i18n.onLocaleChange('fr');
    expect(assign).toHaveBeenCalledWith('/fr/docs/reference/cli/?q=server#flags');
    i18n.onLocaleChange('unknown');
    expect(assign).toHaveBeenCalledTimes(1);
    vi.stubGlobal('window', original);
  });
});
