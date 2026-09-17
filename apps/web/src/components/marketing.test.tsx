import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { marketingCopy, type MarketingPageName } from '../i18n/marketing';
import { locales, localePath } from '../lib/locales';
import { CommandBlock, MarketingPage } from './marketing';

vi.mock('../lib/releases', () => ({
  releaseVersion: '1.0.0-alpha',
  releaseUrl: 'https://github.com/lotosli/umbra/releases',
  platforms: [
    { os: 'macOS', architecture: 'Apple Silicon' },
    { os: 'macOS', architecture: 'Intel' },
    { os: 'Linux', architecture: 'x86_64' },
    { os: 'Linux', architecture: 'aarch64' },
    { os: 'Windows', architecture: 'x86_64' },
  ],
}));

describe('Seven-language presentation', () => {
  const pages: MarketingPageName[] = [
    'home',
    'download',
    'protocol',
    'security',
    'changelog',
  ];
  for (const locale of locales) {
    for (const page of pages) {
      it(`renders meaningful ${locale}/${page} content and public navigation`, () => {
        const copy = marketingCopy[locale];
        const { container } = render(
          <MarketingPage locale={locale} page={page} />,
        );
        const expected =
          page === 'home'
            ? copy.hero.title + copy.hero.accent
            : copy[page].title;
        expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(
          expected.replace('\n', ' '),
        );
        expect(
          screen.getByText(
            page === 'home' ? copy.hero.description : copy[page].description,
          ),
        ).toBeInTheDocument();
        const links = [
          ...container.querySelectorAll<HTMLAnchorElement>('a[href]'),
        ];
        expect(links.length).toBeGreaterThan(0);
        expect(
          links.some(
            (link) =>
              link
                .getAttribute('href')!
                .startsWith(localePath(locale, 'docs')) ||
              link.href === 'https://github.com/lotosli/umbra/releases',
          ),
        ).toBe(true);
        expect(
          links.every(
            (link) =>
              link.getAttribute('href')!.startsWith(`/${locale}/`) ||
              link.href.startsWith('https://github.com/lotosli/umbra'),
          ),
        ).toBe(true);
      });
    }
  }

  for (const locale of locales) {
    it(`presents user benefits and comparison navigation in ${locale}`, () => {
      const copy = marketingCopy[locale];
      const { container } = render(<MarketingPage locale={locale} page="home" />);
      const facts = [...container.querySelectorAll('.fact strong')].map(
        (element) => element.textContent,
      );
      expect(facts).toEqual(['REALITY', 'TCP + QUIC', 'SOCKS5', 'MIT']);
      expect(container.textContent).not.toMatch(/90\s*[%％]/);
      expect(screen.getByRole('link', { name: copy.hero.explore })).toHaveAttribute(
        'href',
        localePath(locale, 'protocol'),
      );
      expect(screen.getByRole('link', {
        name: (name) => name.includes(copy.docs.cards[2]!.title),
      })).toHaveAttribute(
        'href',
        localePath(locale, 'docs/reference/protocol'),
      );
      expect(screen.getAllByRole('link', { name: copy.hero.start })[0]).toHaveAttribute(
        'href',
        localePath(locale, 'docs/getting-started/quick-start'),
      );
      expect(screen.queryByRole('figure')).not.toBeInTheDocument();
    });

    it(`compares named deployments rather than conflating platforms and protocols in ${locale}`, () => {
      const { container } = render(<MarketingPage locale={locale} page="protocol" />);
      const comparisons = [...container.querySelectorAll('.layer-row h3')].map(
        (element) => element.textContent,
      );
      expect(comparisons).toHaveLength(6);
      for (const name of ['Umbra', 'Xray', 'VLESS', 'REALITY', 'VMess', 'Trojan', 'Shadowsocks', 'Hysteria']) {
        expect(comparisons.join(' ')).toContain(name);
      }
      expect(screen.getByRole('link', { name: marketingCopy[locale].nav.docs })).toHaveAttribute(
        'href',
        localePath(locale, 'docs/reference/protocol'),
      );
      expect(screen.getByRole('figure')).toHaveAccessibleName(
        marketingCopy[locale].diagram.caption,
      );
    });
  }

  it('groups all supported targets and links to verified release listings only', () => {
    render(<MarketingPage locale="en" page="download" />);
    expect(screen.getByRole('heading', { name: 'macOS' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Linux' })).toBeInTheDocument();
    expect(
      screen.getByRole('heading', { name: 'Windows' }),
    ).toBeInTheDocument();
    expect(screen.getByText('Apple Silicon · Intel')).toBeInTheDocument();
    expect(screen.getByText('x86_64 · aarch64')).toBeInTheDocument();
    expect(screen.getByText('v1.0.0-alpha')).toBeInTheDocument();
    for (const link of screen.getAllByRole('link', {
      name: /view release assets/i,
    }))
      expect(link).toHaveAttribute(
        'href',
        'https://github.com/lotosli/umbra/releases',
      );
    expect(
      screen.getByText(marketingCopy.en.download.verifyDescription),
    ).toBeInTheDocument();
  });

  it('distinguishes historical browser profiles and design goals from implementation', () => {
    render(<MarketingPage locale="en" page="protocol" />);
    expect(
      screen.getByText(
        /chrome-latest currently follows the historical Chrome 150 profile/,
      ),
    ).toHaveTextContent('does not establish full fingerprint equivalence');
    expect(screen.getByRole('link', { name: 'Documentation' })).toHaveAttribute(
      'href',
      '/en/docs/reference/protocol/',
    );
  });

  it('states alpha, unaudited and unauthenticated SOCKS5 boundaries explicitly', () => {
    render(<MarketingPage locale="en" page="security" />);
    expect(
      screen.getByText(/not a claim of an independent security audit/),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(/SOCKS5 listener has no authentication/).length,
    ).toBeGreaterThan(0);
    expect(
      screen.getByText(/Keep application HTTPS enabled/),
    ).toBeInTheDocument();
  });

  it('gives paired upgrade guidance for the alpha release', () => {
    render(<MarketingPage locale="en" page="changelog" />);
    expect(screen.getByText('Prerelease')).toBeInTheDocument();
    expect(screen.getByText(/Upgrade both endpoints/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Documentation' })).toHaveAttribute(
      'href',
      '/en/docs/guides/upgrade/',
    );
  });

  it('links the release summary to a localized detail page with all changes and sources', () => {
    const { rerender } = render(<MarketingPage locale="en" page="changelog" />);
    expect(
      screen.getByRole('link', { name: 'Read the release notes' }),
    ).toHaveAttribute('href', '/en/changelog/1.0.0-alpha/');
    expect(
      screen.queryByText(marketingCopy.en.changelog.changes[0]!),
    ).not.toBeInTheDocument();
    rerender(<MarketingPage locale="en" page="changelog" releaseDetail />);
    for (const change of marketingCopy.en.changelog.changes)
      expect(screen.getByText(change)).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Read the release notes' }),
    ).toHaveAttribute('href', 'https://github.com/lotosli/umbra/releases');
    expect(screen.getByRole('link', { name: 'README' })).toHaveAttribute(
      'href',
      'https://github.com/lotosli/umbra/blob/main/README.md',
    );
    expect(
      screen.getByRole('link', { name: 'docs/performance.md' }),
    ).toHaveAttribute(
      'href',
      'https://github.com/lotosli/umbra/blob/main/docs/performance.md',
    );
    expect(screen.getByRole('link', { name: 'Changelog' })).toHaveAttribute(
      'href',
      '/en/changelog/',
    );
  });
});

describe('Source command copying', () => {
  it('copies complete commands and announces confirmed success', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    });
    render(<CommandBlock locale="fr" />);
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    fireEvent.click(
      screen.getByRole('button', { name: marketingCopy.fr.ui.copy }),
    );
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(
        marketingCopy.fr.ui.copied,
      );
    });
    expect(writeText).toHaveBeenCalledWith(
      'git clone https://github.com/lotosli/umbra.git\ncd umbra\ncargo build --release\n./target/release/umbra keygen',
    );
  });

  it('keeps commands selectable and announces clipboard failure', async () => {
    Object.defineProperty(navigator, 'clipboard', {
      value: {
        writeText: vi
          .fn()
          .mockRejectedValue(new Error('Clipboard unavailable')),
      },
      configurable: true,
    });
    render(<CommandBlock locale="zh-hans" />);
    fireEvent.click(
      screen.getByRole('button', { name: marketingCopy['zh-hans'].ui.copy }),
    );
    await waitFor(() => {
      expect(screen.getByRole('status')).toHaveTextContent(
        marketingCopy['zh-hans'].ui.copyFailed,
      );
    });
    expect(screen.getByText('cargo build --release')).toBeInTheDocument();
    expect(screen.getByRole('status')).not.toHaveTextContent(
      marketingCopy['zh-hans'].ui.copied,
    );
  });
});
