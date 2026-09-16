import { createFileRoute } from '@tanstack/react-router';
import { MarketingPage } from '../components/marketing';
import { marketingCopy } from '../i18n/marketing';
import { pageHead } from '../lib/seo';

export const Route = createFileRoute('/$locale/_site/changelog')({
  head: ({ match }) => {
    const locale = match.context.locale;
    const copy = marketingCopy[locale].pages.changelog;
    return pageHead(locale, 'changelog', copy.title, copy.description);
  },
  component: Page,
});

function Page() {
  const { locale } = Route.useRouteContext();
  return <MarketingPage locale={locale} page="changelog" />;
}
