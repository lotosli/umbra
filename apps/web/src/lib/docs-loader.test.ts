import { beforeEach, describe, expect, it, vi } from 'vitest';

const source = vi.hoisted(() => ({
  getPage: vi.fn(), getPageTree: vi.fn(), serializePageTree: vi.fn(),
}));

vi.mock('./source', () => ({ source }));
vi.mock('../content/documents.generated', () => ({ documents: [
  { id: 'reference/cli', locale: 'en', title: 'CLI reference', description: 'Public command reference', url: '/en/docs/reference/cli/' },
  { id: 'reference/cli', locale: 'fr', title: 'Référence CLI', description: 'Commandes disponibles', url: '/fr/docs/reference/cli/' },
] }));
vi.mock('@tanstack/react-start', () => ({
  createServerFn: () => ({
    validator: (schema: { parse: (input: unknown) => unknown }) => ({
      handler: (callback: (context: { data: unknown }) => Promise<unknown>) => async (options: { data: unknown }) => callback({ data: schema.parse(options.data) }),
    }),
  }),
}));

import { loadDocPage, loadDocsTree } from './docs-loader';

beforeEach(() => { vi.clearAllMocks(); });

describe('server documentation loaders', () => {
  it('serializes the requested language tree rather than sharing mutable request state', async () => {
    source.getPageTree.mockImplementation((locale: string) => ({ locale, children: [] }));
    source.serializePageTree.mockImplementation((tree: unknown) => Promise.resolve({ tree }));
    const [english, french] = await Promise.all([
      loadDocsTree({ data: { locale: 'en' } }), loadDocsTree({ data: { locale: 'fr' } }),
    ]);
    expect(english).toEqual({ pageTree: { tree: { locale: 'en', children: [] } } });
    expect(french).toEqual({ pageTree: { tree: { locale: 'fr', children: [] } } });
    expect(source.getPageTree).toHaveBeenNthCalledWith(1, 'en');
    expect(source.getPageTree).toHaveBeenNthCalledWith(2, 'fr');
  });

  it('validates locale and input length before content access', async () => {
    await expect(loadDocsTree({ data: { locale: 'de' } })).rejects.toThrow();
    await expect(loadDocPage({ data: { locale: 'en', slug: 'x'.repeat(201) } })).rejects.toThrow();
    expect(source.getPage).not.toHaveBeenCalled();
  });

  it('looks up and returns the published metadata for the selected locale', async () => {
    source.getPage.mockReturnValue({ path: 'fr/reference/cli.mdx' });
    const result = await loadDocPage({ data: { locale: 'fr', slug: '//reference/cli///' } });
    expect(source.getPage).toHaveBeenCalledWith(['reference', 'cli'], 'fr');
    expect(result).toMatchObject({ path: 'fr/reference/cli.mdx', metadata: { title: 'Référence CLI', locale: 'fr' } });
  });

  it('returns not-found when content or reviewed publication metadata is absent', async () => {
    source.getPage.mockReturnValue(undefined);
    await expect(loadDocPage({ data: { locale: 'en', slug: 'reference/cli' } })).rejects.toMatchObject({ isNotFound: true });
    source.getPage.mockReturnValue({ path: 'en/unreviewed.mdx' });
    await expect(loadDocPage({ data: { locale: 'en', slug: 'unreviewed' } })).rejects.toMatchObject({ isNotFound: true });
  });
});
