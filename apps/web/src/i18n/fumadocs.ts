import type { Locale } from '../lib/locales';
import { docsCopy } from './docs';
import { marketingCopy } from './marketing';

const labels: Record<Locale, readonly [string, string, string, string, string, string]> = {
  'zh-hans': ['深色', '浅色', '跟随系统', '展开文档目录', '收起文档目录', '本页没有小节'],
  'zh-hant': ['深色', '淺色', '跟隨系統', '展開文件目錄', '收起文件目錄', '本頁沒有小節'],
  en: ['Dark', 'Light', 'System', 'Open sidebar', 'Close sidebar', 'No headings'],
  fr: ['Sombre', 'Clair', 'Système', 'Ouvrir le menu latéral', 'Fermer le menu latéral', 'Aucune section'],
  es: ['Oscuro', 'Claro', 'Sistema', 'Abrir la barra lateral', 'Cerrar la barra lateral', 'Sin secciones'],
  ja: ['ダーク', 'ライト', 'システム', 'サイドバーを開く', 'サイドバーを閉じる', '見出しがありません'],
  ca: ['Fosc', 'Clar', 'Sistema', 'Obre la barra lateral', 'Tanca la barra lateral', 'Sense seccions'],
};

export function fumadocsTranslations(locale: Locale): Record<string, string> {
  const copy = docsCopy[locale];
  const ui = marketingCopy[locale].ui;
  const [dark, light, system, openSidebar, closeSidebar, noHeadings] = labels[locale];
  return {
    'Search(search dialog)': copy.search,
    'Search(search trigger)': copy.search,
    'Open Search(search trigger)(aria-label)': copy.search,
    'Close Search(search dialog)(aria-label)': copy.close,
    'No results found(search dialog)': copy.noResults,
    'On this page(table of contents)': copy.toc,
    'Table of Contents(inline table of contents)': copy.tocPopover,
    'No Headings(table of contents)': noHeadings,
    'Next Page(pagination)': copy.next,
    'Previous Page(pagination)': copy.previous,
    'Last updated on(page footer)': copy.lastUpdate,
    'Edit on GitHub(edit page)': copy.edit,
    'Choose a language(language switcher)': copy.chooseLanguage,
    'Choose a language(language switcher)(aria-label)': copy.chooseLanguage,
    'Toggle Theme(theme switcher)(aria-label)': ui.theme,
    'Toggle Menu(mobile menu)(aria-label)': ui.menu,
    'Dark(theme switcher)(aria-label)': dark,
    'Light(theme switcher)(aria-label)': light,
    'System(theme switcher)(aria-label)': system,
    'Open Sidebar(sidebar)(aria-label)': openSidebar,
    'Close Sidebar(sidebar)(aria-label)': closeSidebar,
    'Close Sidebar(aria-label)': closeSidebar,
    'Collapse Sidebar(sidebar)(aria-label)': closeSidebar,
    'Hide Sidebar(sidebar)': closeSidebar,
    'Show Sidebar(sidebar)': openSidebar,
    'Copied Text(code block)(aria-label)': ui.copied,
    'Copy Text(code block)(aria-label)': ui.copyCode,
    'Copy Anchor Link(heading anchor)(aria-label)': ui.copyLink,
    'Copy Link(accordion)(aria-label)': ui.copyLink,
  };
}
