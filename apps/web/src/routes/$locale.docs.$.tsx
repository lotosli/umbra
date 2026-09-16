import { createFileRoute } from '@tanstack/react-router';
import { Suspense } from 'react';
import { docs } from '../lib/source';
import { loadDocPage } from '../lib/docs-loader';
import { DocumentationArticle } from '../components/docs-content';
import { pageHead } from '../lib/seo';

export const Route = createFileRoute('/$locale/docs/$')({
  loader: async ({ params, context }) => {
    const result = await loadDocPage({ data: { locale: context.locale, slug: params._splat ?? '' } });
    await docs.getPage(result.path)?.preload();
    return result;
  },
  head: ({ loaderData, match }) => loaderData ? pageHead(match.context.locale, `docs/${loaderData.metadata.id}`, loaderData.metadata.title, loaderData.metadata.description) : {},
  component: Article,
});

function Article() {
  const { locale } = Route.useRouteContext();
  const data = Route.useLoaderData();
  return <Suspense><DocumentationArticle locale={locale} path={data.path} metadata={data.metadata} /></Suspense>;
}
