import { defineI18n } from 'fumadocs-core/i18n';
import { locales, defaultLocale } from './locales';

export const docsI18n = defineI18n({
  languages: [...locales],
  defaultLanguage: defaultLocale,
  parser: 'dir',
  hideLocale: 'never',
  fallbackLanguage: null,
});
