import { useHydrated } from '@tanstack/react-router';
import type { ComponentProps } from 'react';
import { FullSearchTrigger, SearchTrigger } from 'fumadocs-ui/layouts/shared/slots/search-trigger';
import { LanguageSelect, LanguageSelectText } from 'fumadocs-ui/layouts/shared/slots/language-select';
import { ThemeSwitch } from 'fumadocs-ui/layouts/shared/slots/theme-switch';

/** SSR buttons are unavailable until React can handle their first click. */
export function ReadySearchTrigger(props: ComponentProps<typeof SearchTrigger>) {
  const ready = useHydrated();
  return <SearchTrigger {...props} disabled={!ready || props.disabled} />;
}

export function ReadyFullSearchTrigger(props: ComponentProps<typeof FullSearchTrigger>) {
  const ready = useHydrated();
  return <FullSearchTrigger {...props} disabled={!ready || props.disabled} />;
}

export function ReadyLanguageSelect(props: ComponentProps<typeof LanguageSelect>) {
  const ready = useHydrated();
  return <LanguageSelect {...props} disabled={!ready || props.disabled} />;
}

export function ReadyThemeSwitch(props: ComponentProps<typeof ThemeSwitch>) {
  const ready = useHydrated();
  return <div inert={!ready}><ThemeSwitch {...props} /></div>;
}

export const docsInteractionSlots = {
  searchTrigger: { sm: ReadySearchTrigger, full: ReadyFullSearchTrigger },
  languageSelect: { root: ReadyLanguageSelect, text: LanguageSelectText },
  themeSwitch: ReadyThemeSwitch,
};
