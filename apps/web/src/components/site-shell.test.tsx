import { fireEvent, render, screen, within } from '@testing-library/react';
import { createInstance } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { marketingCopy, marketingResources } from '../i18n/marketing';
import { localeDefinitions, localePath, type Locale } from '../lib/locales';
import { SiteShell } from './site-shell';

const theme = vi.hoisted(() => ({ resolvedTheme: 'dark', setTheme: vi.fn() }));
vi.mock('next-themes', () => ({ useTheme: () => theme }));

async function renderShell(locale: Locale = 'en', currentPath?: string) {
  const i18n = createInstance();
  await i18n.init({
    lng: locale,
    lowerCaseLng: true,
    fallbackLng: 'en',
    resources: marketingResources,
    ns: ['marketing'],
    defaultNS: 'marketing',
    interpolation: { escapeValue: false },
  });
  return render(
    <I18nextProvider i18n={i18n}>
      <SiteShell locale={locale} currentPath={currentPath}>
        <h1>Example page</h1>
      </SiteShell>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  theme.resolvedTheme = 'dark';
  theme.setTheme.mockClear();
  window.history.replaceState({}, '', '/en/');
});

describe('Accessible localized navigation', () => {
  for (const { id } of localeDefinitions) {
    it(`provides localized landmarks, links and language controls in ${id}`, async () => {
      await renderShell(id, localePath(id, 'protocol'));
      const copy = marketingCopy[id];
      expect(screen.getByRole('main')).toHaveAttribute('id', 'main-content');
      expect(screen.getByRole('link', { name: copy.ui.skip })).toHaveAttribute(
        'href',
        '#main-content',
      );
      expect(screen.getByRole('banner')).toBeInTheDocument();
      expect(screen.getByRole('contentinfo')).toBeInTheDocument();
      expect(
        screen.getByRole('button', { name: copy.ui.theme }),
      ).toBeInTheDocument();
      expect(screen.getByLabelText(copy.ui.language).tagName).toBe('SUMMARY');
      const desktop = screen.getByRole('navigation', {
        name: copy.footer.project,
      });
      expect(
        within(desktop).getByRole('link', { name: copy.nav.protocol }),
      ).toHaveAttribute('aria-current', 'page');
      expect(
        within(desktop).getByRole('link', { name: copy.nav.docs }),
      ).toHaveAttribute('href', localePath(id, 'docs'));
    });
  }

  it('keeps the current document and fragment in every language link', async () => {
    const path = '/en/docs/getting-started/installation/#build-from-source';
    await renderShell('en', path);
    const languageControl = screen.getByLabelText('Language');
    const details = languageControl.closest('details')!;
    details.open = true;
    for (const { id, name, tag } of localeDefinitions) {
      const link = within(details).getByRole('link', { name });
      expect(link).toHaveAttribute(
        'href',
        `/${id}/docs/getting-started/installation/#build-from-source`,
      );
      expect(link).toHaveAttribute('hrefLang', tag);
    }
    expect(
      within(details).getByRole('link', { name: 'English' }),
    ).toHaveAttribute('aria-current', 'true');
  });

  it('preserves the live browser fragment when the visitor changes language', async () => {
    await renderShell('en', '/en/docs/reference/cli/');
    window.history.replaceState(
      {},
      '',
      '/en/docs/reference/cli/?view=full#client',
    );
    const details = screen.getByLabelText('Language').closest('details')!;
    details.open = true;
    const link = within(details).getByRole('link', { name: '日本語' });
    link.addEventListener('click', (event) => {
      event.preventDefault();
    });
    fireEvent.click(link);
    expect(link).toHaveAttribute(
      'href',
      '/ja/docs/reference/cli/?view=full#client',
    );
  });

  it('exposes all important routes in a native mobile menu', async () => {
    await renderShell();
    const details = screen
      .getByLabelText('Open navigation')
      .closest('details')!;
    details.open = true;
    const navigation = within(details).getByRole('navigation');
    expect(
      within(navigation).getByRole('link', { name: 'Security' }),
    ).toHaveAttribute('href', '/en/security/');
    expect(
      within(navigation).getByRole('link', { name: 'Changelog' }),
    ).toHaveAttribute('href', '/en/changelog/');
    expect(
      within(navigation).getByRole('link', { name: 'GitHub' }),
    ).toHaveAttribute('href', 'https://github.com/lotosli/umbra');
    expect(within(navigation).getAllByRole('link')).toHaveLength(6);
  });

  it('switches both theme directions through the shared theme provider', async () => {
    await renderShell();
    fireEvent.click(screen.getByRole('button', { name: 'Toggle color theme' }));
    expect(theme.setTheme).toHaveBeenLastCalledWith('light');
    theme.resolvedTheme = 'light';
    await renderShell('fr');
    fireEvent.click(screen.getByRole('button', { name: 'Changer de thème' }));
    expect(theme.setTheme).toHaveBeenLastCalledWith('dark');
  });
});
