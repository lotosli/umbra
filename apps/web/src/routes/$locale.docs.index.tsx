import { createFileRoute } from '@tanstack/react-router';
import { DocsDescription, DocsPage, DocsTitle } from 'fumadocs-ui/layouts/docs/page';
import { documents } from '../content/documents.generated';
import { docsCopy } from '../i18n/docs';
import { pageHead } from '../lib/seo';

export const Route = createFileRoute('/$locale/docs/')({
  head: ({ match }) => {
    const locale = match.context.locale;
    return pageHead(locale, 'docs', docsCopy[locale].title, docsCopy[locale].description);
  },
  component: DocsIndex,
});

function DocsIndex() {
  const { locale } = Route.useRouteContext();
  const copy = docsCopy[locale];
  const entries = documents.filter((document) => document.locale === locale).sort((a, b) => a.order - b.order);
  return <DocsPage toc={[]} tabIndex={-1}>
    <DocsTitle>{copy.title}</DocsTitle><DocsDescription>{copy.description}</DocsDescription>
    <div className="umbra-docs-grid">
      {entries.map((document) => <a key={document.id} href={document.url} className="umbra-docs-card"><h2>{document.title} <span aria-hidden>↗</span></h2><p>{document.description}</p></a>)}
    </div>
  </DocsPage>;
}
