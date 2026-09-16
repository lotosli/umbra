import { createFileRoute, Outlet } from '@tanstack/react-router';
import { useFumadocsLoader } from 'fumadocs-core/source/client';
import { loadDocsTree } from '../lib/docs-loader';
import { DocumentationLayout } from '../components/docs-layout';

export const Route = createFileRoute('/$locale/docs')({
  loader: ({ context }) => loadDocsTree({ data: { locale: context.locale } }),
  component: DocsRoute,
});

function DocsRoute() {
  const { locale } = Route.useRouteContext();
  const { pageTree } = useFumadocsLoader(Route.useLoaderData());
  return <DocumentationLayout locale={locale} tree={pageTree}><Outlet /></DocumentationLayout>;
}
