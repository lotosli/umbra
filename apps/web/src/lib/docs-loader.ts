import { createServerFn } from '@tanstack/react-start';
import { notFound } from '@tanstack/react-router';
import { z } from 'zod';
import { source } from './source';
import { isLocale } from './locales';
import { documents } from '../content/documents.generated';

const localeInput = z.string().refine(isLocale);

export const loadDocsTree = createServerFn({ method: 'GET' })
  .validator(z.object({ locale: localeInput }))
  .handler(async ({ data }) => ({ pageTree: await source.serializePageTree(source.getPageTree(data.locale)) }));

export const loadDocPage = createServerFn({ method: 'GET' })
  .validator(z.object({ locale: localeInput, slug: z.string().max(200) }))
  .handler(async ({ data }) => {
    const slug = data.slug.replace(/^\/+|\/+$/g, '');
    const page = source.getPage(slug.split('/'), data.locale);
    const metadata = documents.find((item) => item.locale === data.locale && item.id === slug);
    if (!page || !metadata) throw notFound();
    return { path: page.path, metadata };
  });
