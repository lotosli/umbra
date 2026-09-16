import type { Locale } from '../lib/locales';
import { localePath } from '../lib/locales';
import { docsCopy } from '../i18n/docs';

export function NotFoundPage({ locale }: { locale: Locale }) {
  const copy = docsCopy[locale];
  return <main className="umbra-not-found" id="main-content">
    <a href={localePath(locale)} className="umbra-wordmark">umbra</a>
    <span className="umbra-eyebrow">404 / UMBRA</span>
    <h1>{copy.notFound}</h1><p>{copy.notFoundDescription}</p>
    <div><a href={localePath(locale)} className="umbra-button-primary">{copy.returnHome} <span aria-hidden>↗</span></a><a href={localePath(locale, 'docs')}>{copy.title} <span aria-hidden>→</span></a></div>
  </main>;
}
