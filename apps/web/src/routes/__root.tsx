import { createRootRoute, HeadContent, Outlet, Scripts, useRouterState, redirect } from '@tanstack/react-router';
import { SiteProviders } from '../components/providers';
import { NotFoundPage } from '../components/not-found';
import { defaultLocale, isLocale, languageTag } from '../lib/locales';
import appCss from '../styles/app.css?url';

export const Route = createRootRoute({
  beforeLoad: ({ location }) => {
    if (location.pathname !== '/' && !location.pathname.endsWith('/') && !location.pathname.split('/').at(-1)?.includes('.')) {
      throw redirect({ to: './', href: `${location.pathname}/${location.searchStr}${location.hash ? `#${location.hash}` : ''}`, statusCode: 308 });
    }
  },
  head: () => ({
    meta: [{ charSet: 'utf-8' }, { name: 'viewport', content: 'width=device-width, initial-scale=1' }, { name: 'theme-color', content: '#ffffff' }],
    links: [{ rel: 'stylesheet', href: appCss }, { rel: 'icon', href: '/favicon.svg', type: 'image/svg+xml' }, { rel: 'manifest', href: '/manifest.webmanifest' }],
  }),
  component: RootDocument,
  notFoundComponent: RootNotFound,
});

function useCurrentLocale() {
  const segment = useRouterState({ select: (state) => state.location.pathname.split('/')[1] });
  return segment && isLocale(segment) ? segment : defaultLocale;
}

function RootNotFound() { return <NotFoundPage locale={useCurrentLocale()} />; }

function RootDocument() {
  const locale = useCurrentLocale();
  return <html lang={languageTag(locale)} suppressHydrationWarning>
    <head><HeadContent /></head>
    <body><SiteProviders locale={locale}><Outlet /></SiteProviders><Scripts /></body>
  </html>;
}
