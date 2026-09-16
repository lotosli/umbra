import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { createInstance } from 'i18next';
import { I18nextProvider } from 'react-i18next';
import { RootProvider } from 'fumadocs-ui/provider/tanstack';
import { marketingResources } from '../i18n/marketing';
import { fumadocsTranslations } from '../i18n/fumadocs';
import type { Locale } from '../lib/locales';
import { localeDefinitions, isLocale, switchLocale } from '../lib/locales';
import { SearchDialog } from './search-dialog';

export function SiteProviders({ locale, children }: { locale: Locale; children: ReactNode }) {
  const i18n = useMemo(() => {
    const instance = createInstance();
    void instance.init({
      lng: locale,
      lowerCaseLng: true,
      fallbackLng: false,
      resources: marketingResources,
      ns: ['marketing'],
      defaultNS: 'marketing',
      initAsync: false,
      interpolation: { escapeValue: false },
    });
    return instance;
  }, [locale]);
  return (
    <I18nextProvider i18n={i18n}>
      <RootProvider
        theme={{ defaultTheme: 'light', enableSystem: false }}
        i18n={{
          locale,
          onLocaleChange: (next) => { if (isLocale(next)) window.location.assign(switchLocale(window.location.pathname + window.location.search + window.location.hash, next)); },
          locales: localeDefinitions.map(({ id, name }) => ({ locale: id, name })),
          translations: fumadocsTranslations(locale),
        }}
        search={{ SearchDialog: (props) => <SearchDialog {...props} locale={locale} /> }}
      >
        {children}
      </RootProvider>
    </I18nextProvider>
  );
}
