import { beforeEach, describe, expect, it, vi } from 'vitest';

const framework = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('@tanstack/react-start/server-entry', () => ({
  default: framework,
  createServerEntry: (entry: unknown) => entry,
}));
import server from './server';

beforeEach(() => { vi.clearAllMocks(); });

describe('Cloudflare request boundary', () => {
  it('negotiates the site language from Accept-Language at the root path', async () => {
    const zh = await server.fetch(new Request('https://umbra.cat/', { headers: { 'accept-language': 'zh-CN,zh;q=0.9' } }));
    expect(zh.status).toBe(307);
    expect(zh.headers.get('location')).toBe('https://umbra.cat/zh-hans/');
    const hant = await server.fetch(new Request('https://umbra.cat/', { headers: { 'accept-language': 'zh-TW' } }));
    expect(hant.headers.get('location')).toBe('https://umbra.cat/zh-hant/');
    const fallback = await server.fetch(new Request('https://umbra.cat/'));
    expect(fallback.headers.get('location')).toBe('https://umbra.cat/en/');
    const query = await server.fetch(new Request('https://umbra.cat/?from=nav', { headers: { 'accept-language': 'fr-CA' } }));
    expect(query.headers.get('location')).toBe('https://umbra.cat/fr/?from=nav');
    expect(framework.fetch).not.toHaveBeenCalled();
  });

  it('redirects aliases with HTTP 308 before rendering application content', async () => {
    const response = await server.fetch(new Request('https://docs.umbra.cat/en/reference/cli/'));
    expect(response.status).toBe(308);
    expect(response.headers.get('location')).toBe('https://umbra.cat/en/docs/reference/cli/');
    expect(framework.fetch).not.toHaveBeenCalled();
  });

  it('preserves real not-found status and body while applying preview headers', async () => {
    framework.fetch.mockResolvedValue(new Response('<h1>Page not found</h1>', {
      status: 404, statusText: 'Not Found', headers: { 'content-type': 'text/html; charset=utf-8' },
    }));
    const request = new Request('https://preview.workers.dev/en/docs/missing/');
    const response = await server.fetch(request);
    expect(framework.fetch).toHaveBeenCalledWith(request);
    expect(response.status).toBe(404);
    expect(response.statusText).toBe('Not Found');
    expect(await response.text()).toContain('Page not found');
    expect(response.headers.get('X-Robots-Tag')).toBe('noindex, nofollow');
    expect(response.headers.get('Cache-Control')).toBe('no-cache');
  });

  it('retains non-HTML content headers on the production domain', async () => {
    framework.fetch.mockResolvedValue(new Response('<urlset/>', {
      headers: { 'content-type': 'application/xml; charset=utf-8', 'cache-control': 'public, max-age=300' },
    }));
    const response = await server.fetch(new Request('https://umbra.cat/sitemap.xml'));
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    expect(response.headers.has('X-Robots-Tag')).toBe(false);
    expect(await response.text()).toBe('<urlset/>');
  });
});
