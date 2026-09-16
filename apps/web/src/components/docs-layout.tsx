import type { ReactNode } from 'react';
import type { Root } from 'fumadocs-core/page-tree';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { localePath, repositoryUrl } from '../lib/locales';
import type { Locale } from '../lib/locales';
import { docsCopy } from '../i18n/docs';
import { marketingCopy } from '../i18n/marketing';
import { docsI18n } from '../lib/docs-i18n';
import { EclipseMark } from './site-shell';
import { docsInteractionSlots } from './hydrated-controls';

export function DocumentationLayout({ locale, tree, children }: { locale: Locale; tree: Root; children: ReactNode }) {
  const copy = docsCopy[locale];
  return <><a href="#nd-page" className="skip-link" onClick={(event) => {
    const article = document.getElementById('nd-page');
    if (article) {
      event.preventDefault();
      article.focus();
      article.scrollIntoView({ block: 'start' });
    }
  }}>{marketingCopy[locale].ui.skip}</a><DocsLayout
    tree={tree}
    slots={docsInteractionSlots}
    i18n={docsI18n}
    nav={{ title: <span className="umbra-docs-logo"><EclipseMark /> umbra <small>{copy.title}</small></span>, url: localePath(locale) }}
    githubUrl={repositoryUrl}
    links={[{ text: marketingCopy[locale].nav.download, url: localePath(locale, 'download') }, { text: marketingCopy[locale].nav.protocol, url: localePath(locale, 'protocol') }]}
  >{children}</DocsLayout></>;
}
