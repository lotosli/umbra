/** Regenerate reviewed static diagrams. Requires a local Chromium executable. */
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, copyFileSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const work = mkdtempSync(join(tmpdir(), 'umbra-diagrams-'));
const hash = (value) => createHash('sha256').update(value).digest('hex');
const labels = JSON.parse(readFileSync(join(root, 'docs/protocol-diagrams/labels.json'), 'utf8'));
const entries = Object.entries(labels);
const config = { theme: 'neutral', htmlLabels: false, securityLevel: 'strict', deterministicIds: true, deterministicIDSeed: 'umbra-protocol', themeVariables: { fontFamily: 'Arial, sans-serif', fontSize: '16px' }, flowchart: { htmlLabels: false, curve: 'linear' } };
writeFileSync(join(work, 'config.json'), JSON.stringify(config));
const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;
if (!executablePath) throw new Error('Set PUPPETEER_EXECUTABLE_PATH to your installed Chromium/Chrome executable.');
writeFileSync(join(work, 'puppeteer.json'), JSON.stringify({ executablePath, args: ['--no-sandbox'] }));
writeFileSync(join(work, 'input.md'), entries.map(([key]) => '```mermaid\n' + readFileSync(join(root, `docs/protocol-diagrams/${key}.mmd`), 'utf8') + '\n```').join('\n\n'));
try {
  execFileSync('pnpm', ['exec', 'mmdc', '-i', join(work, 'input.md'), '-o', join(work, 'diagram.md'), '-c', join(work, 'config.json'), '-p', join(work, 'puppeteer.json')], { cwd: join(root, 'apps/web'), stdio: 'inherit' });
  const assets = {};
  entries.forEach(([key, label], index) => {
    const source = readFileSync(join(root, `docs/protocol-diagrams/${key}.mmd`), 'utf8');
    const svg = readFileSync(join(work, `diagram-${index + 1}.svg`), 'utf8');
    const viewBox = svg.match(/viewBox="([^"]+)"/)[1].split(' ').map(Number);
    const target = resolve(root, 'apps/web/public' + label.path);
    mkdirSync(resolve(target, '..'), { recursive: true });
    copyFileSync(join(work, `diagram-${index + 1}.svg`), target);
    label.source = source; label.width = viewBox[2]; label.height = viewBox[3];
    assets[key] = { source: hash(source), svg: hash(svg) };
  });
  const sourceRevision = hash(readFileSync(join(root, 'docs/protocol-design.md')));
  const editions = Object.fromEntries([...new Set(entries.map(([key]) => key.split('/')[0]))].map((locale) => [locale, hash(readFileSync(join(root, `docs/site/${locale}/reference/protocol-design.mdx`)))]));
  writeFileSync(join(root, 'docs/protocol-diagrams/manifest.json'), JSON.stringify({ sourceRevision, editions, assets }, null, 2) + '\n');
  writeFileSync(join(root, 'docs/protocol-diagrams/labels.json'), JSON.stringify(labels, null, 2) + '\n');
} finally { rmSync(work, { recursive: true, force: true }); }
