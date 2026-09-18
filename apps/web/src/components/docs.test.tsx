import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { ReactNode } from 'react';
import { Suspense } from 'react';
import { locales } from '../lib/locales';
import { docsCopy } from '../i18n/docs';
import { NotFoundPage } from './not-found';
import { DocumentationArticle } from './docs-content';
import { DocumentationLayout } from './docs-layout';

const mocks = vi.hoisted(() => ({ getPage: vi.fn() }));
vi.mock('../lib/source', () => ({ docs: { getPage: mocks.getPage } }));
vi.mock('fumadocs-ui/layouts/docs/page', () => ({
  DocsPage: ({ children }: { children: ReactNode }) => <article>{children}</article>,
  DocsBody: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DocsTitle: ({ children }: { children: ReactNode }) => <h1>{children}</h1>,
  DocsDescription: ({ children }: { children: ReactNode }) => <p>{children}</p>,
}));
vi.mock('fumadocs-ui/mdx', () => ({ default: {} }));
vi.mock('fumadocs-ui/layouts/docs', () => ({
  DocsLayout: ({ children, nav, links, githubUrl }: { children: ReactNode; nav: { title: ReactNode; url: string }; links: { text: string; url: string }[]; githubUrl: string }) => <div><nav><a href={nav.url}>{nav.title}</a>{links.map((link) => <a key={link.url} href={link.url}>{link.text}</a>)}<a href={githubUrl}>GitHub</a></nav>{children}</div>,
}));

describe('public document reading', () => {
  it('moves keyboard focus from the skip link into the article', () => {
    render(<DocumentationLayout locale="en" tree={{ name: 'Docs', children: [] }}><article id="nd-page" tabIndex={-1}>Content</article></DocumentationLayout>);
    const article = screen.getByText('Content');
    article.scrollIntoView = vi.fn();
    fireEvent.click(screen.getByRole('link', { name: 'Skip to content' }));
    expect(article).toHaveFocus();
    expect(article.scrollIntoView).toHaveBeenCalledWith({ block: 'start' });
  });
  it.each(locales)('provides localized error recovery and document navigation in %s', (locale) => {
    const { unmount } = render(<NotFoundPage locale={locale} />);
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(docsCopy[locale].notFound);
    expect(screen.getByRole('link', { name: docsCopy[locale].returnHome })).toHaveAttribute('href', `/${locale}/`);
    unmount();
    render(<DocumentationLayout locale={locale} tree={{ name: 'Docs', children: [] }}><p>Article body</p></DocumentationLayout>);
    expect(screen.getByRole('navigation')).toHaveTextContent(docsCopy[locale].title);
    expect(screen.getByRole('link', { name: 'GitHub' })).toHaveAttribute('href', 'https://github.com/lotosli/umbra');
    expect(screen.getByText('Article body')).toBeVisible();
  });

  it('renders the actual loaded body with version and reviewed source/edit links', async () => {
    const data = { toc: [{ title: 'Install', url: '#install', depth: 2 }] };
    const loaded = Object.assign(Promise.resolve(data), { status: 'fulfilled', value: data });
    mocks.getPage.mockReturnValue({ load: () => loaded, body: () => <><h2 id="install">Install</h2><pre>cargo build --release</pre></> });
    render(<Suspense><DocumentationArticle locale="en" path="en/getting-started/installation.mdx" metadata={{ id: 'getting-started/installation', locale: 'en', title: 'Install Umbra', description: 'Build and install.', version: '1.0.0-alpha', source: ['README.md', 'Cargo.toml'], translation: 'complete', updatedAt: '2026-09-18', reviewedAt: '2026-09-18' }} /></Suspense>);
    expect(await screen.findByRole('heading', { name: 'Install Umbra' })).toBeVisible();
    expect(screen.getByText('cargo build --release')).toBeVisible();
    expect(screen.getByText(/Applies to 1.0.0-alpha/)).toBeVisible();
    expect(screen.getByRole('link', { name: 'README.md' })).toHaveAttribute('href', 'https://github.com/lotosli/umbra/blob/main/README.md');
    expect(screen.getByRole('link', { name: /Edit this page/ })).toHaveAttribute('href', 'https://github.com/lotosli/umbra/edit/main/docs/site/en/getting-started/installation.mdx');
  });

  it('fails explicitly when a compiled document module is missing', () => {
    mocks.getPage.mockReturnValue(undefined);
    expect(() => render(<DocumentationArticle locale="en" path="missing" metadata={{ id: 'missing', locale: 'en', title: '', description: '', version: '', source: [], translation: 'complete', updatedAt: '2026-09-18', reviewedAt: '2026-09-18' }} />)).toThrow('Document module is unavailable');
  });
});
