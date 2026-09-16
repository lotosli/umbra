import defaultMdxComponents from 'fumadocs-ui/mdx';
import { useHydrated } from '@tanstack/react-router';
import type { ComponentProps, ReactNode } from 'react';
import { CodeBlock, Pre } from 'fumadocs-ui/components/codeblock';

export function CodeActions({ children, ...props }: { children?: ReactNode; className?: string }) {
  const ready = useHydrated();
  return <div {...props} inert={!ready}>{children}</div>;
}

function ReadyPre(props: ComponentProps<typeof defaultMdxComponents.pre>) {
  return <CodeBlock {...props} Actions={CodeActions}><Pre>{props.children}</Pre></CodeBlock>;
}

export const mdxComponents = { ...defaultMdxComponents, pre: ReadyPre };
