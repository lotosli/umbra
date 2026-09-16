import { defineDocs } from 'fumadocs-mdx/macro';
import { loader } from 'fumadocs-core/source';
import { docsI18n } from './docs-i18n';

export const docs = defineDocs({
  dir: '../../docs/site',
  docs: { async: true },
});

export const source = loader({
  baseUrl: '/docs',
  source: docs.toFumadocsSource(),
  i18n: docsI18n,
});
