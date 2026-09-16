import { createRouter } from '@tanstack/react-router';
import { routeTree } from './routeTree.gen';

export function getRouter() {
  return createRouter({
    routeTree,
    scrollRestoration: true,
    trailingSlash: 'always',
    defaultPreload: 'intent',
    defaultPreloadStaleTime: 60_000,
  });
}

declare module '@tanstack/react-router' {
  interface Register { router: ReturnType<typeof getRouter> }
}
