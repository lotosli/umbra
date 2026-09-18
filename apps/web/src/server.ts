import handler, { createServerEntry } from '@tanstack/react-start/server-entry';
import { localePath, negotiateLocale } from './lib/locales';
import { publicResponseHeaders, redirectTarget } from './lib/routing';

export default createServerEntry({
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/') {
      // The bundled '/' route cannot read request headers, so language negotiation happens here.
      const locale = negotiateLocale(request.headers.get('accept-language') ?? '');
      return new Response(null, { status: 307, headers: {
        Location: (url.hostname === 'www.umbra.cat' ? 'https://umbra.cat' : url.origin) + localePath(locale) + url.search,
        Vary: 'Accept-Language', 'Cache-Control': 'no-store',
      } });
    }
    const target = redirectTarget(url);
    if (target) return Response.redirect(target, 308);
    const response = await handler.fetch(request);
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: publicResponseHeaders(url, response.headers),
    });
  },
});
