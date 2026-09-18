import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  articleUrl, cargoVersion, generateContent, isAllowedSource, locales, parseArticle,
  releasePlatforms, requiredDocumentIds, searchEntries, validateArticles, validateLinks,
  type Article, type ContentLocale,
} from './content-lib';

const version = '1.0.0-alpha';
const directories: string[] = [];
const body = `## Configuration

Umbra serves a local SOCKS5 listener. Bind that listener to loopback and keep application HTTPS enabled. This public guide describes the released configuration and does not claim independent security auditing or complete browser fingerprint equivalence.

## Transport

The server and client must agree on the selected transport. Read the configuration reference before changing defaults. Test each change on both endpoints before switching existing applications.
`;

function raw(id = 'getting-started/introduction', extra = body): string {
  return `---\nid: ${id}\ntitle: Introduction\ndescription: Read the public Umbra introduction and configuration guide.\nsection: getting-started\norder: 1\nversion: ${version}\nsource:\n  - README.md\ntranslation: complete\nupdatedAt: "2026-09-18"\nreviewedAt: "2026-09-18"\n---\n${extra}`;
}

function article(locale: ContentLocale = 'en', id = 'getting-started/introduction'): Article {
  return parseArticle(locale, `${locale}/${id}.mdx`, raw(id));
}

function collection(): Article[] {
  return locales.flatMap((locale) => requiredDocumentIds.map((id) => article(locale, id)));
}

async function fixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'umbra-content-'));
  directories.push(root);
  await mkdir(join(root, '.github/workflows'), { recursive: true });
  await writeFile(join(root, 'README.md'), 'Public README');
  await writeFile(join(root, 'Cargo.toml'), `[workspace.package]\nversion = "${version}"\n`);
  await writeFile(join(root, '.github/workflows/dist.yml'), 'jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          - targets: aarch64-apple-darwin,x86_64-unknown-linux-gnu\n');
  for (const locale of locales) {
    for (const id of requiredDocumentIds) {
      const segments = id.split('/');
      const directory = join(root, 'docs/site', locale, ...segments.slice(0, -1));
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, `${segments.at(-1)}.mdx`), raw(id));
    }
  }
  await writeFile(join(root, 'docs/site/en/meta.json'), '{"pages": ["getting-started"]}');
  return root;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('reviewed public content', () => {
  it('requires every chapter in all seven locales', () => {
    const articles = collection();
    expect(articles).toHaveLength(126);
    expect(() => validateArticles(articles, version)).not.toThrow();
    expect(() => validateArticles(articles.slice(1), version)).toThrow('Missing translation: zh-hans/');
    expect(() => validateArticles([...articles, articles[0]!], version)).toThrow('duplicate document ID');
  });

  it('rejects incomplete, missing and invalid frontmatter', () => {
    expect(() => parseArticle('en', 'en/page.mdx', raw().replace('translation: complete', 'translation: pending'))).toThrow('invalid frontmatter');
    expect(() => parseArticle('en', 'en/page.mdx', raw().replace('source:\n  - README.md', 'source: []'))).toThrow('invalid frontmatter');
    expect(() => parseArticle('en', 'en/page.mdx', raw('page', '## Title\nToo short'))).toThrow('180 content characters and two headings');
  });

  it('checks stable IDs, paths, applicable version and source allowlist', () => {
    const invalid = article();
    invalid.metadata.id = 'unreviewed-page';
    expect(() => validateArticles([invalid], version)).toThrow('reviewed publication manifest');
    const wrongPath = article();
    wrongPath.file = 'en/wrong.mdx';
    expect(() => validateArticles([wrongPath], version)).toThrow('expected content path');
    expect(() => validateArticles([article()], '2.0.0')).toThrow('version must match Cargo');
    const privateSource = article();
    privateSource.metadata.source = ['openspec/changes/private/spec.md'];
    expect(() => validateArticles([privateSource], version)).toThrow('disallowed source');
    const articles = collection();
    for (const item of articles.filter((item) => item.metadata.id === 'contributing')) {
      item.file = `${item.locale}/contributing/index.mdx`;
    }
    expect(() => validateArticles(articles, version)).not.toThrow();
  });

  it('permits only named public documents and Rust sources without traversal', () => {
    for (const path of ['README.md', 'docs/usage.md', '.github/workflows/dist.yml', 'crates/umbra/src/main.rs', 'crates/umbra-core/src/config/client.rs']) {
      expect(isAllowedSource(path), path).toBe(true);
    }
    for (const path of ['../README.md', '/README.md', 'crates/umbra/src/../../secret.rs', 'docs/private.md', '.env', 'openspec/spec.md']) {
      expect(isAllowedSource(path), path).toBe(false);
    }
  });

  it('parses reference links, inline heading text and duplicate heading anchors', () => {
    const parsed = parseArticle('en', 'en/getting-started/introduction.mdx', raw(undefined,
      `${body}\n## A **clear** heading\n\n## A clear heading\n\n[Guide][guide]\n\n![Diagram](https://example.com/diagram.svg)\n\n[guide]: /en/docs/getting-started/introduction/#a-clear-heading-1\n\n\`\`\`text\n[Not a link](/broken/)\n\`\`\``));
    expect(parsed.headings).toContain('a-clear-heading');
    expect(parsed.headings).toContain('a-clear-heading-1');
    expect(parsed.links).toEqual(['/en/docs/getting-started/introduction/#a-clear-heading-1', 'https://example.com/diagram.svg']);
    expect(parsed.content).toContain('Diagram');
    expect(() => validateLinks([parsed])).not.toThrow();
  });
});

describe('public URL and heading integrity', () => {
  it('accepts canonical, relative, source-file, marketing and valid fragment links', () => {
    const page = article();
    page.links = ['#configuration', './#transport', 'introduction.mdx#configuration',
      '/en/docs/getting-started/introduction/', 'https://umbra.cat/en/docs/getting-started/introduction/',
      '/zh-hans/download/', '/en/docs/', '/', 'https://github.com/lotosli/umbra', 'mailto:example@example.com'];
    expect(articleUrl(page)).toBe('/en/docs/getting-started/introduction/');
    expect(() => validateLinks([page])).not.toThrow();
  });

  it.each(['/en/docs/missing/', '/unknown/docs/', '/en/download/#missing'])('rejects absent internal target %s', (target) => {
    const page = article();
    page.links = [target];
    expect(() => validateLinks([page])).toThrow('broken internal link');
  });

  it('rejects missing headings, unsafe schemes and protocol-relative destinations', () => {
    const page = article();
    page.links = ['#absent'];
    expect(() => validateLinks([page])).toThrow('missing heading');
    page.links = ['javascript:alert(1)'];
    expect(() => validateLinks([page])).toThrow('unsupported link protocol');
    page.links = ['//example.com/unknown'];
    expect(() => validateLinks([page])).toThrow('unsupported link');
    page.links = ['https://umbra.cat:invalid/path'];
    expect(() => validateLinks([page])).toThrow('invalid link');
  });
});

describe('release and local search artifacts', () => {
  it('reads only the workspace package version, including reordered keys', () => {
    expect(cargoVersion('[workspace.package]\nlicense = "MIT"\nversion = "1.0.0-alpha"\n[dependencies]\nversion = "9.0.0"')).toBe(version);
    expect(() => cargoVersion('[package]\nversion = "9.0.0"')).toThrow('workspace.package.version');
    expect(() => cargoVersion('[workspace.package]\nversion = "latest"')).toThrow('invalid');
  });

  it('derives platforms from the actual distribution matrix and links to the release list', () => {
    const platforms = releasePlatforms('jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          - targets: aarch64-apple-darwin,x86_64-apple-darwin,x86_64-unknown-linux-gnu,aarch64-unknown-linux-gnu,x86_64-pc-windows-msvc\n');
    expect(platforms).toHaveLength(5);
    expect(platforms.every((platform) => platform.href === 'https://github.com/lotosli/umbra/releases')).toBe(true);
    expect(platforms.map((platform) => platform.os)).toEqual(['macOS', 'macOS', 'Linux', 'Linux', 'Windows']);
    expect(() => releasePlatforms('jobs:\n  build:\n    strategy:\n      matrix:\n        include:\n          - targets: invented-target\n')).toThrow('Unreviewed distribution target');
    expect(() => releasePlatforms('jobs: {}')).toThrow();
  });

  it('keeps search language-specific and preserves CJK, accented terms and identifiers', () => {
    const examples: Record<ContentLocale, string> = {
      'zh-hans': '客户端配置 bind_addr', 'zh-hant': '用戶端設定 bind_addr', en: 'configuration bind_addr',
      fr: 'sécurité réseau bind_addr', es: 'conexión configuración bind_addr', ja: 'クライアント設定 bind_addr',
      ca: 'connexió configuració bind_addr',
    };
    const articles = locales.map((locale) => ({ ...article(locale), content: examples[locale] }));
    for (const locale of locales) {
      const entries = searchEntries(articles, locale);
      expect(entries).toHaveLength(1);
      expect(entries[0]?.content).toBe(examples[locale]);
      expect(entries[0]?.url.startsWith(`/${locale}/docs/`)).toBe(true);
    }
    expect(searchEntries([article('en', 'guides/server'), article('en')], 'en')[0]?.id).toBe('getting-started/introduction');
  });

  it('generates seven independent indexes and a source-derived release module', async () => {
    const root = await fixture();
    await mkdir(join(root, 'openspec/private'), { recursive: true });
    await writeFile(join(root, 'openspec/private/secret.mdx'), 'DO_NOT_PUBLISH');
    expect(await generateContent(root)).toEqual({ articles: 126, version });
    for (const locale of locales) {
      const output = await readFile(join(root, `apps/web/public/search/${locale}.json`), 'utf8');
      const parsed = JSON.parse(output) as { url: string }[];
      expect(parsed).toHaveLength(18);
      expect(parsed.every((item) => item.url.startsWith(`/${locale}/docs/`))).toBe(true);
      expect(output).not.toContain('DO_NOT_PUBLISH');
    }
    const release = await readFile(join(root, 'apps/web/src/content/releases.generated.ts'), 'utf8');
    expect(release).toContain('export const releaseVersion = "1.0.0-alpha"');
    expect(release).toContain('Apple Silicon');
    expect(release).not.toContain('/releases/download/');
    const manifest = await readFile(join(root, 'apps/web/src/content/documents.generated.ts'), 'utf8');
    expect(manifest).toContain('export const documents: GeneratedDocument[]');
    expect(manifest).toContain('"locale": "zh-hans"');
    expect(manifest).not.toContain('Umbra serves a local SOCKS5 listener');
  });

  it('rejects unrecognized locales and missing or escaping sources before output', async () => {
    const root = await fixture();
    await mkdir(join(root, 'docs/site/de'), { recursive: true });
    await writeFile(join(root, 'docs/site/de/unknown.mdx'), raw());
    await expect(generateContent(root)).rejects.toThrow('unknown content locale');
    await rm(join(root, 'docs/site/de'), { recursive: true });
    await rm(join(root, 'README.md'));
    await expect(generateContent(root)).rejects.toThrow();
    const external = await mkdtemp(join(tmpdir(), 'umbra-external-'));
    directories.push(external);
    await writeFile(join(external, 'README.md'), 'outside repository');
    await symlink(join(external, 'README.md'), join(root, 'README.md'));
    await expect(generateContent(root)).rejects.toThrow('Source escapes repository');
  });
});
