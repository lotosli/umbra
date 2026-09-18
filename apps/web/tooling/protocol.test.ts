import { describe, expect, it } from 'vitest';
import { readFile, mkdtemp, cp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { codeSignature, validateProtocolEdition, validateProtocolPublication } from './protocol-lib';
import { locales } from './content-lib';

const root = resolve(process.cwd(), '../..');
const read = (path: string) => readFile(join(root, path), 'utf8');
describe('complete protocol publication', () => {
  it('publishes all sections, program tokens and three static diagrams in seven languages', async () => {
    await validateProtocolPublication(root);
    const source = await read('docs/protocol-design.md');
    for (const locale of locales) validateProtocolEdition(source, await read(`docs/site/${locale}/reference/protocol-design.mdx`), locale);
  });
  it('rejects stale, shortened, changed and unrendered editions', async () => {
    const source = await read('docs/protocol-design.md');
    const article = await read('docs/site/en/reference/protocol-design.mdx');
    expect(() => validateProtocolEdition(source + '\n', article, 'en')).toThrow('stale');
    expect(() => validateProtocolEdition(source, article.replace(/^## .+\n/m, ''), 'en')).toThrow('sections');
    expect(() => validateProtocolEdition(source, article.replace('pub fn seal_session_id', 'pub fn other'), 'en')).toThrow('code');
    expect(() => validateProtocolEdition(source, article.replace('<ProtocolDiagram locale="en" name="server" />', ''), 'en')).toThrow('diagram');
    expect(() => validateProtocolEdition(source, article + '\n@@BLOCK_0@@', 'en')).toThrow('unrendered');
  });
  it('permits localized comments but protects executable tokens and wire commands', () => {
    expect(codeSignature('let key = "BASE64(私钥)"; // 注释')).toBe(codeSignature('let key = "BASE64(private key)"; // comment'));
    expect(codeSignature('pub fn a(); /* comment */')).toBe('pubfna();');
    expect(codeSignature('MuxFrame = ver(1)\n0x01 u32')).not.toBe(codeSignature('MuxFrame = ver(1)\n0x02 u32'));
    expect(codeSignature('MuxFrame = ver(1)')).toBe('MuxFrame = ver(1)');
  });
  it('fails closed on unreviewed translations, stale SVGs, invalid labels and missing files', async () => {
    const fixture = await mkdtemp(join(tmpdir(), 'protocol-check-'));
    try {
      for (const path of ['docs/protocol-design.md', 'docs/protocol-diagrams', 'docs/site', 'apps/web/public/diagrams']) {
        await cp(join(root, path), join(fixture, path), { recursive: true });
      }
      const mutate = async (path: string, update: (value: string) => string, error: string) => {
        const target = join(fixture, path); const original = await readFile(target, 'utf8');
        await writeFile(target, update(original));
        await expect(validateProtocolPublication(fixture)).rejects.toThrow(error);
        await writeFile(target, original);
      };
      await mutate('docs/protocol-diagrams/manifest.json', (text) => text.replace(/"sourceRevision": "[^"]+"/, '"sourceRevision": "stale"'), 'manifest');
      await mutate('docs/site/zh-hans/reference/protocol-design.mdx', (text) => text + '\nEdited prose.\n', 'review');
      await mutate('apps/web/public/diagrams/protocol-design/zh-hans/server.svg', (text) => text + ' ', 'stale diagram');
      await mutate('docs/protocol-diagrams/labels.json', (text) => text.replace('"caption": "总体架构"', '"caption": ""'), 'metadata');
      await rm(join(fixture, 'docs/protocol-diagrams/en/client.mmd'));
      await expect(validateProtocolPublication(fixture)).rejects.toThrow('ENOENT');
    } finally { await rm(fixture, { recursive: true, force: true }); }
  });
});
