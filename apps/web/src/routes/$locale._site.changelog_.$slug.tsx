import { createFileRoute, notFound } from '@tanstack/react-router';
import { MarketingPage } from '../components/marketing';
import { marketingCopy } from '../i18n/marketing';
import { releaseVersion } from '../lib/releases';
import { pageHead } from '../lib/seo';

export const Route = createFileRoute('/$locale/_site/changelog_/$slug')({
  beforeLoad: ({ params }) => { if (params.slug !== releaseVersion) throw notFound(); },
  head: ({ match }) => {
    const locale = match.context.locale;
    const copy = marketingCopy[locale].changelog;
    return pageHead(locale, `changelog/${releaseVersion}`, `${releaseVersion} — ${copy.heading}`, copy.summary);
  },
  component: ReleasePage,
});

function ReleasePage() {
  const { locale } = Route.useRouteContext();
  return <MarketingPage locale={locale} page="changelog" releaseDetail />;
}
