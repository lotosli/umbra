import { renderToString } from 'react-dom/server';
import { fireEvent, render, screen } from '@testing-library/react';
import type { ComponentProps, ReactNode } from 'react';
import { describe, expect, it, vi } from 'vitest';
import { ReadySearchTrigger, ReadyFullSearchTrigger, ReadyLanguageSelect, ReadyThemeSwitch } from './hydrated-controls';
import { CodeActions, mdxComponents } from './mdx';
import { CommandBlock } from './marketing';
import { ThemeButton } from './site-shell';

vi.mock('fumadocs-ui/layouts/shared/slots/search-trigger', () => ({
  SearchTrigger: (props: ComponentProps<'button'>) => <button {...props}>Search</button>,
  FullSearchTrigger: (props: ComponentProps<'button'>) => <button {...props}>Search</button>,
}));
vi.mock('fumadocs-ui/layouts/shared/slots/language-select', () => ({
  LanguageSelect: (props: ComponentProps<'button'>) => <button {...props}>Language</button>,
  LanguageSelectText: () => <span>English</span>,
}));
vi.mock('fumadocs-ui/layouts/shared/slots/theme-switch', () => ({ ThemeSwitch: () => <button>Theme</button> }));
vi.mock('fumadocs-ui/mdx', () => ({ default: { pre: ({ children }: { children: ReactNode }) => <pre>{children}</pre> } }));
vi.mock('fumadocs-ui/components/codeblock', () => ({
  CodeBlock: ({ children, Actions }: { children: ReactNode; Actions: (props: { children: ReactNode }) => ReactNode }) => <figure><Actions><button>Copy</button></Actions>{children}</figure>,
  Pre: ({ children }: { children: ReactNode }) => <pre>{children}</pre>,
}));
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (_key: string, options: { defaultValue: string }) => options.defaultValue }) }));
vi.mock('next-themes', () => ({ useTheme: () => ({ resolvedTheme: 'light', setTheme: vi.fn() }) }));

describe('first interaction while a page initializes', () => {
  it.each([ReadySearchTrigger, ReadyFullSearchTrigger, ReadyLanguageSelect])('disables SSR controls and handles the first hydrated click', (Control) => {
    const onClick = vi.fn();
    expect(renderToString(<Control onClick={onClick} />)).toContain('disabled=""');
    const { rerender } = render(<Control onClick={onClick} />);
    expect(screen.getByRole('button')).toBeEnabled();
    fireEvent.click(screen.getByRole('button'));
    expect(onClick).toHaveBeenCalledTimes(1);
    rerender(<Control disabled onClick={onClick} />);
    expect(screen.getByRole('button')).toBeDisabled();
  });

  it('keeps document theme and code actions inert only before hydration', () => {
    expect(renderToString(<ReadyThemeSwitch />)).toContain('inert=""');
    expect(renderToString(<CodeActions><button>Copy</button></CodeActions>)).toContain('inert=""');
    render(<><ReadyThemeSwitch /><CodeActions><button>Copy</button></CodeActions></>);
    expect(screen.getByRole('button', { name: 'Theme' }).parentElement).not.toHaveAttribute('inert');
    expect(screen.getByRole('button', { name: 'Copy' }).parentElement).not.toHaveAttribute('inert');
  });

  it('retains readable MDX code while its copy control is unavailable on the server', () => {
    const Pre = mdxComponents.pre;
    const markup = renderToString(<Pre><code>umbra keygen</code></Pre>);
    expect(markup).toContain('inert=""');
    expect(markup).toContain('<pre><code>umbra keygen</code></pre>');
  });

  it('disables marketing theme and command-copy buttons in SSR output', () => {
    expect(renderToString(<ThemeButton locale="en" />)).toContain('disabled=""');
    expect(renderToString(<CommandBlock locale="en" />)).toContain('disabled=""');
  });
});
