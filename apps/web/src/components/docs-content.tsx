import { use } from 'react';
import { DocsBody, DocsDescription, DocsPage, DocsTitle } from 'fumadocs-ui/layouts/docs/page';
import { docs } from '../lib/source';
import { repositoryUrl } from '../lib/locales';
import type { Locale } from '../lib/locales';
import { docsCopy } from '../i18n/docs';
import { mdxComponents } from './mdx';

export interface ArticleMetadata {
  title: string; description: string; version: string; source: readonly string[];
  id: string; locale: string; translation: string;
}

export function DocumentationArticle({ path, locale, metadata }: { path: string; locale: Locale; metadata: ArticleMetadata }) {
  const page = docs.getPage(path);
  if (!page) throw new Error('Document module is unavailable');
  const { toc } = use(page.load());
  const MDX = page.body;
  const copy = docsCopy[locale];
  return <DocsPage toc={toc} tabIndex={-1}>
    <DocsTitle>{metadata.title}</DocsTitle>
    <DocsDescription>{metadata.description}</DocsDescription>
    <div className="umbra-docs-meta"><span>{copy.version} {metadata.version}</span><span>{copy.translated}</span></div>
    <DocsBody><MDX components={mdxComponents} /></DocsBody>
    <div className="umbra-docs-sources">
      <p>{copy.source}</p>
      <ul>{metadata.source.map((file) => <li key={file}><a href={`${repositoryUrl}/blob/main/${file}`} target="_blank" rel="noreferrer">{file}</a></li>)}</ul>
      <a href={`${repositoryUrl}/edit/main/docs/site/${path}`} target="_blank" rel="noreferrer">{copy.edit} ↗</a>
    </div>
  </DocsPage>;
}
