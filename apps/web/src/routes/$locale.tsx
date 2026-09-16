import { createFileRoute, notFound, Outlet } from '@tanstack/react-router';
import { isLocale } from '../lib/locales';

export const Route = createFileRoute('/$locale')({
  beforeLoad: ({ params }) => {
    if (!isLocale(params.locale)) throw notFound();
    return { locale: params.locale };
  },
  component: Outlet,
});
