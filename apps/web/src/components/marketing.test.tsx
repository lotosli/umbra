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
              link.href.startsWith('https://github.com/lotosli/umbra') ||
              ['xtls.github.io', 'www.v2fly.org', 'trojan-gfw.github.io', 'shadowsocks.org', 'v2.hysteria.network'].includes(new URL(link.href).hostname),
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
      expect(screen.getAllByRole('link', { name: copy.hero.start }).at(-1)!).toHaveAttribute(
        'href',
        localePath(locale, 'docs/getting-started/quick-start'),
      );
      expect(container.querySelector('.hero-code pre')).toHaveTextContent('cargo build --release');
      expect(container.querySelector('.hero-code')).toHaveTextContent('macOS · Linux · Windows');
      expect(screen.getByRole('button', { name: copy.ui.copy })).toBeInTheDocument();
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
      expect(screen.getByRole('link', { name: marketingCopy[locale].protocol.read })).toHaveAttribute(
        'href',
        localePath(locale, 'docs/reference/protocol'),
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
      name: marketingCopy.en.download.releases,
    }))
      expect(link).toHaveAttribute(
        'href',
        'https://github.com/lotosli/umbra/releases',
      );
    expect(
      screen.getByText(marketingCopy.en.download.verifyDescription),
    ).toBeInTheDocument();
  });

  it('keeps setup guidance on the overview and links to detailed documentation', () => {
    render(<MarketingPage locale="en" page="protocol" />);
    expect(screen.getByText(marketingCopy.en.protocol.caveat)).toHaveTextContent('configuration');
    expect(screen.getByRole('link', { name: marketingCopy.en.protocol.read })).toHaveAttribute('href', '/en/docs/reference/protocol/');
  });

  it('explains alpha status, local access and application HTTPS on the security page', () => {
    render(<MarketingPage locale="en" page="security" />);
    expect(screen.getByText(/no published evidence of a completed independent security audit/)).toBeInTheDocument();
    expect(screen.getByText(/127.0.0.1:1080/)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Continue using HTTPS' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: marketingCopy.en.security.source })).toHaveAttribute('href', 'https://github.com/lotosli/umbra/security');
  });

  it('gives paired upgrade guidance for the alpha release', () => {
    render(<MarketingPage locale="en" page="changelog" />);
    expect(screen.getByText('Prerelease')).toBeInTheDocument();
    expect(screen.getByText(/Update both ends/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: marketingCopy.en.changelog.upgradeRead })).toHaveAttribute(
      'href',
      '/en/docs/guides/upgrade/',
    );
  });

  it('links the release summary to a localized detail page with all changes and sources', () => {
    const { rerender } = render(<MarketingPage locale="en" page="changelog" />);
    expect(
      screen.getByRole('link', { name: marketingCopy.en.changelog.read }),
    ).toHaveAttribute('href', '/en/changelog/1.0.0-alpha/');
    expect(
      screen.queryByText(marketingCopy.en.changelog.changes[0]!),
    ).not.toBeInTheDocument();
    rerender(<MarketingPage locale="en" page="changelog" releaseDetail />);
    for (const change of marketingCopy.en.changelog.changes)
      expect(screen.getByText(change)).toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: marketingCopy.en.changelog.externalRead }),
    ).toHaveAttribute('href', 'https://github.com/lotosli/umbra/releases');
    expect(screen.getByRole('link', { name: marketingCopy.en.changelog.sourceRead })).toHaveAttribute(
      'href',
      'https://github.com/lotosli/umbra/blob/main/README.md',
    );
    expect(
      screen.getByRole('link', { name: marketingCopy.en.changelog.performanceRead }),
    ).toHaveAttribute(
      'href',
      'https://github.com/lotosli/umbra/blob/main/docs/performance.md',
    );
    expect(screen.getByRole('link', { name: marketingCopy.en.changelog.back })).toHaveAttribute(
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
