import type { ComponentType, ReactNode } from 'react';
import type * as RouterModule from '@tanstack/react-router';
import { renderToStaticMarkup } from 'react-dom/server';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { localeDefinitions, type Locale } from '../lib/locales';
import { releaseVersion } from '../lib/releases';

const state = vi.hoisted(() => ({
  locale: 'en', pathname: '/en/',
  data: { path: 'en/reference/cli.mdx', pageTree: { name: 'English', children: [] }, metadata: {
    id: 'reference/cli', locale: 'en', title: 'CLI reference', description: 'Public command reference', url: '/en/docs/reference/cli/',
  } },
  getPage: vi.fn(), preload: vi.fn(), loadDocPage: vi.fn(), loadDocsTree: vi.fn(),
}));

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const original = await importOriginal<typeof RouterModule>();
  function route(options: unknown) {
    return { options, useRouteContext: () => ({ locale: state.locale }), useLoaderData: () => state.data };
  }
  return {
    ...original,
    createFileRoute: () => route,
    createRootRoute: route,
    useRouterState: ({ select }: { select: (input: { location: { pathname: string } }) => unknown }) => select({ location: { pathname: state.pathname } }),
    Outlet: () => <main>Nested route content</main>,
    HeadContent: () => <meta name="test-head" content="SSR" />,
    Scripts: () => <script src="/assets/application.js" />,
  };
});
vi.mock('../components/marketing', () => ({
  MarketingPage: ({ locale, page, releaseDetail }: { locale: string; page: string; releaseDetail?: boolean }) => <main data-locale={locale} data-release-detail={releaseDetail}>{page}</main>,
}));
vi.mock('../components/site-shell', () => ({
  SiteShell: ({ locale, currentPath, children }: { locale: string; currentPath: string; children: ReactNode }) => <div data-locale={locale} data-path={currentPath}>{children}</div>,
}));
vi.mock('../components/providers', () => ({
  SiteProviders: ({ locale, children }: { locale: string; children: ReactNode }) => <div data-provider-locale={locale}>{children}</div>,
}));
vi.mock('../components/not-found', () => ({
  NotFoundPage: ({ locale }: { locale: string }) => <main>Not found: {locale}</main>,
}));
vi.mock('../components/docs-content', () => ({
  DocumentationArticle: ({ locale, path, metadata }: { locale: string; path: string; metadata: { title: string } }) => <article lang={locale} data-path={path}>{metadata.title}</article>,
}));
vi.mock('../components/docs-layout', () => ({
  DocumentationLayout: ({ locale, children }: { locale: string; children: ReactNode }) => <div data-docs-locale={locale}>{children}</div>,
}));
vi.mock('fumadocs-ui/layouts/docs/page', () => ({
  DocsPage: ({ children }: { children: ReactNode }) => <article>{children}</article>,
  DocsTitle: ({ children }: { children: ReactNode }) => <h1>{children}</h1>,
  DocsDescription: ({ children }: { children: ReactNode }) => <p>{children}</p>,
}));
vi.mock('fumadocs-core/source/client', () => ({ useFumadocsLoader: (input: unknown) => input }));
vi.mock('../lib/source', () => ({ docs: { getPage: state.getPage } }));
vi.mock('../lib/docs-loader', () => ({ loadDocPage: state.loadDocPage, loadDocsTree: state.loadDocsTree }));
vi.mock('../content/documents.generated', () => ({ documents: [
  { id: 'reference/cli', locale: 'en', title: 'English CLI article', description: 'Supported English commands', url: '/en/docs/reference/cli/' },
  { id: 'reference/cli', locale: 'fr', title: 'French CLI article', description: 'Commandes françaises', url: '/fr/docs/reference/cli/' },
] }));

import { Route as rootRoute } from './__root';
import { Route as indexRoute } from './index';
import { Route as localeRoute } from './$locale';
import { Route as marketingLayout } from './$locale._site';
import { Route as homeRoute } from './$locale._site.index';
import { Route as downloadRoute } from './$locale._site.download';
import { Route as protocolRoute } from './$locale._site.protocol';
import { Route as securityRoute } from './$locale._site.security';
import { Route as changelogRoute } from './$locale._site.changelog';
import { Route as releaseRoute } from './$locale._site.changelog_.$slug';
import { Route as docsLayout } from './$locale.docs';
import { Route as docsIndex } from './$locale.docs.index';
import { Route as docsArticle } from './$locale.docs.$';
import { Route as sitemapRoute } from './sitemap[.]xml';

interface TestedRoute {
  options: {
    beforeLoad?: (input: Record<string, unknown>) => unknown;
    head?: (input: Record<string, unknown>) => { meta?: unknown[]; links?: unknown[] };
    loader?: (input: Record<string, unknown>) => Promise<unknown>;
    component?: ComponentType;
    notFoundComponent?: ComponentType;
    server?: { handlers: { GET: () => Response } };
  };
}

function options(route: unknown): TestedRoute['options'] {
  return (route as TestedRoute).options;
}

function markup(route: unknown): string {
  const Component = options(route).component;
  if (!Component) throw new Error('The route has no content component');
  return renderToStaticMarkup(<Component />);
}

beforeEach(() => {
  vi.clearAllMocks();
  state.locale = 'en';
  state.pathname = '/en/';
  state.getPage.mockReturnValue({ preload: state.preload });
  state.preload.mockResolvedValue(undefined);
  state.loadDocPage.mockResolvedValue(state.data);
  state.loadDocsTree.mockResolvedValue({ pageTree: state.data.pageTree });
});

describe('file-route locale and canonical request boundaries', () => {
  it('redirects only non-file paths needing a slash and preserves query/fragment', () => {
    const before = options(rootRoute).beforeLoad!;
    expect(() => before({ location: { pathname: '/en/docs', searchStr: '?from=nav', hash: 'install' } })).toThrow();
    try { before({ location: { pathname: '/en/docs', searchStr: '?from=nav', hash: 'install' } }); }
    catch (response) { expect(response).toMatchObject({ options: { href: '/en/docs/?from=nav#install', statusCode: 308 } }); }
    try { before({ location: { pathname: '/en/docs', searchStr: '', hash: '' } }); }
    catch (response) { expect(response).toMatchObject({ options: { href: '/en/docs/', statusCode: 308 } }); }
    for (const pathname of ['/', '/en/docs/', '/sitemap.xml', '/manifest.webmanifest']) {
      expect(before({ location: { pathname, searchStr: '', hash: '' } })).toBeUndefined();
    }
  });

  it('redirects the unlocalized entry and rejects unknown locales before rendering', () => {
    expect(() => options(indexRoute).beforeLoad!({})).toThrow();
    try { options(indexRoute).beforeLoad!({}); }
    catch (response) { expect(response).toMatchObject({ options: { to: '/$locale/', params: { locale: 'en' }, statusCode: 307 } }); }
    for (const locale of localeDefinitions) {
      expect(options(localeRoute).beforeLoad!({ params: { locale: locale.id } })).toEqual({ locale: locale.id });
    }
    expect(() => options(localeRoute).beforeLoad!({ params: { locale: 'de' } })).toThrow();
    try { options(localeRoute).beforeLoad!({ params: { locale: 'de' } }); }
    catch (response) { expect(response).toMatchObject({ isNotFound: true }); }
    expect(markup(localeRoute)).toContain('Nested route content');
  });

  it('renders the HTML language and request locale in the server-visible document', () => {
    for (const locale of localeDefinitions) {
      state.pathname = `/${locale.id}/docs/`;
      const html = markup(rootRoute);
      expect(html).toContain(`<html lang="${locale.tag}"`);
      expect(html).toContain(`data-provider-locale="${locale.id}"`);
      expect(html).toContain('Nested route content');
    }
    state.pathname = '/unknown/path/';
    expect(markup(rootRoute)).toContain('<html lang="en"');
    state.pathname = '/';
    expect(markup(rootRoute)).toContain('<html lang="en"');
    const head = options(rootRoute).head!({});
    expect(head.links).toContainEqual({ rel: 'manifest', href: '/manifest.webmanifest' });
    expect(head.meta).toContainEqual({ charSet: 'utf-8' });
  });

  it('uses the requested locale for not-found content', () => {
    const NotFound = options(rootRoute).notFoundComponent!;
    state.pathname = '/fr/docs/missing/';
    expect(renderToStaticMarkup(<NotFound />)).toContain('Not found: fr');
    state.pathname = '/unknown/';
    expect(renderToStaticMarkup(<NotFound />)).toContain('Not found: en');
  });
});

describe('localized presentation route metadata and layout', () => {
  const pages = [
    [homeRoute, 'home', ''], [downloadRoute, 'download', 'download/'],
    [protocolRoute, 'protocol', 'protocol/'], [securityRoute, 'security', 'security/'],
    [changelogRoute, 'changelog', 'changelog/'],
  ] as const;

  it.each(pages)('renders each localized page with matching canonical metadata', (route, page, path) => {
    for (const locale of localeDefinitions) {
      state.locale = locale.id;
      const html = markup(route);
      expect(html).toContain(`data-locale="${locale.id}"`);
      expect(html).toContain(`>${page}</main>`);
      const head = options(route).head!({ match: { context: { locale: locale.id } } });
      expect(head.links).toContainEqual({ rel: 'canonical', href: `https://umbra.cat/${locale.id}/${path}` });
      expect(head.meta?.length).toBeGreaterThan(5);
    }
  });

  it('supplies the active locale and path to the shared navigation shell', () => {
    state.locale = 'ja';
    state.pathname = '/ja/security/';
    const html = markup(marketingLayout);
    expect(html).toContain('data-locale="ja"');
    expect(html).toContain('data-path="/ja/security/"');
    expect(html).toContain('Nested route content');
  });

  it('publishes only the source-backed release detail and rejects invented versions', () => {
    expect(options(releaseRoute).beforeLoad!({ params: { slug: releaseVersion } })).toBeUndefined();
    expect(() => options(releaseRoute).beforeLoad!({ params: { slug: '99.0.0' } })).toThrow();
    try { options(releaseRoute).beforeLoad!({ params: { slug: '99.0.0' } }); }
    catch (response) { expect(response).toMatchObject({ isNotFound: true }); }
    for (const locale of localeDefinitions) {
      state.locale = locale.id;
      expect(markup(releaseRoute)).toContain('data-release-detail="true"');
      const head = options(releaseRoute).head!({ match: { context: { locale: locale.id } } });
      expect(head.links).toContainEqual({ rel: 'canonical', href: `https://umbra.cat/${locale.id}/changelog/${releaseVersion}/` });
      expect(head.meta?.some((item) => typeof item === 'object' && item !== null && 'title' in item && String(item.title).includes(releaseVersion))).toBe(true);
    }
  });
});

describe('documentation route loading and SSR', () => {
  it('loads the locale-specific tree before rendering the documentation shell', async () => {
    expect(await options(docsLayout).loader!({ context: { locale: 'ca' } })).toEqual({ pageTree: state.data.pageTree });
    expect(state.loadDocsTree).toHaveBeenCalledWith({ data: { locale: 'ca' } });
    state.locale = 'ca';
    expect(markup(docsLayout)).toContain('data-docs-locale="ca"');
    expect(markup(docsLayout)).toContain('Nested route content');
  });

  it('lists only the selected language documents and emits docs metadata', () => {
    const english = markup(docsIndex);
    expect(english).toContain('English CLI article');
    expect(english).toContain('href="/en/docs/reference/cli/"');
    expect(english).not.toContain('French CLI article');
    state.locale = 'fr';
    expect(markup(docsIndex)).toContain('French CLI article');
    const head = options(docsIndex).head!({ match: { context: { locale: 'fr' } } });
    expect(head.links).toContainEqual({ rel: 'canonical', href: 'https://umbra.cat/fr/docs/' });
  });

  it('preloads the requested compiled document before rendering its body', async () => {
    const result = await options(docsArticle).loader!({ params: { _splat: 'reference/cli' }, context: { locale: 'en' } });
    expect(state.loadDocPage).toHaveBeenCalledWith({ data: { locale: 'en', slug: 'reference/cli' } });
    expect(state.getPage).toHaveBeenCalledWith('en/reference/cli.mdx');
    expect(state.preload).toHaveBeenCalledOnce();
    expect(result).toBe(state.data);
    const html = markup(docsArticle);
    expect(html).toContain('CLI reference');
    expect(html).toContain('data-path="en/reference/cli.mdx"');
  });

  it('handles an absent splat and source preload without masking loader failures', async () => {
    state.getPage.mockReturnValue(undefined);
    await options(docsArticle).loader!({ params: {}, context: { locale: 'en' } });
    expect(state.loadDocPage).toHaveBeenCalledWith({ data: { locale: 'en', slug: '' } });
    expect(state.preload).not.toHaveBeenCalled();
    state.loadDocPage.mockRejectedValue(new Error('Missing article'));
    await expect(options(docsArticle).loader!({ params: {}, context: { locale: 'en' } })).rejects.toThrow('Missing article');
  });

  it('derives article metadata from the verified loader result and tolerates no result', () => {
    const head = options(docsArticle).head!({ loaderData: state.data, match: { context: { locale: 'en' as Locale } } });
    expect(head.meta).toContainEqual({ title: 'CLI reference · Umbra' });
    expect(head.links).toContainEqual({ rel: 'canonical', href: 'https://umbra.cat/en/docs/reference/cli/' });
    expect(options(docsArticle).head!({ loaderData: undefined })).toEqual({});
  });

  it('serves a cacheable sitemap with deduplicated stable article IDs', async () => {
    const response = options(sitemapRoute).server!.handlers.GET();
    expect(response.headers.get('content-type')).toBe('application/xml; charset=utf-8');
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    const xml = await response.text();
    expect((xml.match(/<loc>https:\/\/umbra.cat\/en\/docs\/reference\/cli\/<\/loc>/g) ?? [])).toHaveLength(1);
    expect(xml).toContain('https://umbra.cat/ca/docs/reference/cli/');
    expect(xml).toContain(`https://umbra.cat/ca/changelog/${releaseVersion}/`);
    expect((xml.match(/<url>/g) ?? [])).toHaveLength(56);
  });
});
