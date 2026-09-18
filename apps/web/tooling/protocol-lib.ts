import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import matter from 'gray-matter';
import { locales } from './content-lib';

export const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const fences = (value: string) => [...value.matchAll(/^```([^\n]*)\n([\s\S]*?)^```/gm)]
  .filter((match) => match[1] !== 'mermaid').map((match) => match[2]!);
const headings = (value: string) => value.replace(/^```[^\n]*\n[\s\S]*?^```/gm, '').match(/^#{2,3} /gm)?.length ?? 0;

/** Compare program tokens while permitting translated comments and placeholder descriptions. */
export function codeSignature(value: string): string {
  if (value.startsWith('MuxFrame')) {
    return value.split('\n')[0] + (value.match(/0x[0-9a-f]+|u32/g) ?? []).join(',');
  }
  return value.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\n]*|#[^\n]*/g, '')
    .replace(/BASE64\([^)]*\)/g, 'BASE64(placeholder)').replace(/\s/g, '');
}

export function validateProtocolEdition(source: string, article: string, locale: string): void {
  const { data, content } = matter(article);
  if (data.sourceRevision !== digest(source)) throw new Error(`${locale}: stale protocol source revision`);
  const body = source.slice(source.indexOf('## 0.'));
  if (headings(body) !== headings(content)) throw new Error(`${locale}: incomplete protocol sections`);
  const expected = fences(body).map(codeSignature);
  const actual = fences(content).map(codeSignature);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${locale}: protocol code differs from source`);
  for (const name of ['architecture', 'server', 'client']) {
    if (content.split(`<ProtocolDiagram locale="${locale}" name="${name}" />`).length !== 2) {
      throw new Error(`${locale}: missing or duplicated ${name} diagram`);
    }
  }
  if (/@@BLOCK_|```mermaid/.test(content)) throw new Error(`${locale}: unrendered protocol content`);
}

/** Reject modified, missing or stale translations and assets before producing the site. */
export async function validateProtocolPublication(root: string): Promise<void> {
  const read = (path: string) => readFile(join(root, path), 'utf8');
  const source = await read('docs/protocol-design.md');
  const manifest: { sourceRevision: string; editions: Record<string, string>; assets: Record<string, { source: string; svg: string }> } = JSON.parse(await read('docs/protocol-diagrams/manifest.json'));
  const labels: Record<string, { source: string; path: string; caption: string; width: number; height: number }> = JSON.parse(await read('docs/protocol-diagrams/labels.json'));
  if (manifest.sourceRevision !== digest(source)) throw new Error('Protocol manifest source is stale');
  for (const locale of locales) {
    const article = await read(`docs/site/${locale}/reference/protocol-design.mdx`);
    validateProtocolEdition(source, article, locale);
    if (manifest.editions[locale] !== digest(article)) throw new Error(`${locale}: protocol edition needs review`);
    for (const name of ['architecture', 'server', 'client']) {
      const key = `${locale}/${name}`;
      const definition = await read(`docs/protocol-diagrams/${key}.mmd`);
      const svg = await read(`apps/web/public/diagrams/protocol-design/${key}.svg`);
      const label = labels[key];
      if (manifest.assets[key]?.source !== digest(definition) || manifest.assets[key]?.svg !== digest(svg)) throw new Error(`${key}: stale diagram asset`);
      if (!label || label.source !== definition || label.path !== `/diagrams/protocol-design/${key}.svg`
        || !label.caption || !(label.width > 0) || !(label.height > 0)) throw new Error(`${key}: invalid diagram metadata`);
      if (!svg.includes('<svg') || /<script|<foreignObject|(?:href|src)="https?:/i.test(svg)) throw new Error(`${key}: non-static diagram`);
    }
  }
  const sourceDiagrams = [...source.matchAll(/^```mermaid\n([\s\S]*?)^```/gm)].map((match) => match[1]!.trim());
  const names = ['architecture', 'server', 'client'];
  if (sourceDiagrams.length !== 3 || sourceDiagrams.some((value, index) => labels[`zh-hans/${names[index]}`]?.source.trim() !== value)) throw new Error('Chinese diagrams differ from the canonical source');
}
