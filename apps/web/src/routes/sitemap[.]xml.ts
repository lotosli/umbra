import { createFileRoute } from '@tanstack/react-router';
import { documents } from '../content/documents.generated';
import { sitemapXml } from '../lib/sitemap';
import { releaseVersion } from '../lib/releases';

export const Route = createFileRoute('/sitemap.xml')({
  server: { handlers: { GET: () => new Response(sitemapXml([...new Set(documents.map(({ id }) => id))], [releaseVersion]), { headers: { 'Content-Type': 'application/xml; charset=utf-8', 'Cache-Control': 'public, max-age=300' } }) } },
});
