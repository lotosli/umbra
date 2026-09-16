import { createFileRoute, Outlet, useRouterState } from '@tanstack/react-router';
import { SiteShell } from '../components/site-shell';

export const Route = createFileRoute('/$locale/_site')({ component: MarketingLayout });

function MarketingLayout() {
  const { locale } = Route.useRouteContext();
  const currentPath = useRouterState({ select: (state) => state.location.pathname });
  return <SiteShell locale={locale} currentPath={currentPath}><Outlet /></SiteShell>;
}
