import { readFile, readdir, mkdir, writeFile, realpath } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import matter from 'gray-matter';
import GithubSlugger from 'github-slugger';
import { unified } from 'unified';
import remarkParse from 'remark-parse';
import remarkGfm from 'remark-gfm';
import type { Root, RootContent } from 'mdast';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

export const locales = ['zh-hans', 'zh-hant', 'en', 'fr', 'es', 'ja', 'ca'] as const;
export type ContentLocale = (typeof locales)[number];
export const canonicalOrigin = 'https://umbra.cat';
export const releaseUrl = 'https://github.com/lotosli/umbra/releases';

export const requiredDocumentIds = [
  'getting-started/introduction', 'getting-started/installation', 'getting-started/quick-start',
  'guides/server', 'guides/client', 'guides/deployment', 'guides/upgrade',
  'configuration/server', 'configuration/client', 'configuration/examples',
  'concepts/architecture', 'concepts/transports', 'concepts/security-model',
  'reference/cli', 'reference/configuration', 'reference/protocol',
  'troubleshooting', 'contributing',
] as const;

const contentDate = z.string().regex(/^\d{4}-\d{2}-\d{2}$/).refine((value) => {
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value && date.getTime() <= Date.now();
}, 'Date must be a real, non-future calendar date');

export const frontmatterSchema = z.object({
  id: z.string().regex(/^[a-z0-9-]+(?:\/[a-z0-9-]+)*$/),
  title: z.string().trim().min(2),
  description: z.string().trim().min(12),
  section: z.string().trim().min(2),
  order: z.number().int().nonnegative(),
  version: z.string().regex(/^\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/i),
  source: z.array(z.string().min(1)).nonempty(),
  translation: z.literal('complete'),
  updatedAt: contentDate,
  reviewedAt: contentDate,
});

export interface Article {
  locale: ContentLocale;
  file: string;
  metadata: z.infer<typeof frontmatterSchema>;
  content: string;
  headings: string[];
  links: string[];
}

export interface SearchEntry {
  id: string;
  title: string;
  description: string;
  url: string;
  content: string;
}

const allowedPublicSources = new Set([
  'README.md', 'README.zh-CN.md', 'Cargo.toml', 'CONTRIBUTING.md', 'LICENSE',
  'docs/usage.md', 'docs/usage.zh-CN.md', 'docs/performance.md',
  'docs/architecture.md', 'docs/protocol-design.md', 'docs/vision-runtime-wire-v2.md',
  '.github/workflows/dist.yml',
]);

/** Source paths identify reviewed input; their contents are never copied into the public output. */
export function isAllowedSource(source: string): boolean {
  return allowedPublicSources.has(source)
    || /^crates\/umbra(?:-[a-z]+)?\/src\/(?:[a-z0-9_-]+\/)*[a-z0-9_-]+\.rs$/.test(source);
}

type MarkdownNode = Root | RootContent;
function nodeText(node: MarkdownNode): string {
  if ('value' in node) return node.value;
  if ('alt' in node) return node.alt ?? '';
  if ('children' in node) return node.children.map((child) => nodeText(child)).join('');
  return '';
}

function walk(node: MarkdownNode, visit: (node: MarkdownNode) => void): void {
  visit(node);
  if ('children' in node) for (const child of node.children) walk(child, visit);
}

/** Parse only Markdown body nodes: URLs inside fenced examples are not treated as links. */
export function parseArticle(locale: ContentLocale, file: string, raw: string): Article {
  const { data, content } = matter(raw);
  const result = frontmatterSchema.safeParse(data);
  if (!result.success) throw new Error(`${file}: invalid frontmatter: ${result.error.message}`);
  const tree = unified().use(remarkParse).use(remarkGfm).parse(content);
  const slugger = new GithubSlugger();
  const headings: string[] = [];
  const links: string[] = [];
  const definitions = new Map<string, string>();
  walk(tree, (node) => {
    if (node.type === 'definition') definitions.set(node.identifier, node.url);
  });
  walk(tree, (node) => {
    if (node.type === 'heading') headings.push(slugger.slug(nodeText(node)));
    if (node.type === 'link' || node.type === 'image') links.push(node.url);
    if (node.type === 'linkReference' || node.type === 'imageReference') {
      const target = definitions.get(node.identifier);
      if (!target) throw new Error(`${file}: missing link definition ${node.identifier}`);
      links.push(target);
    }
  });
  const plainText = tree.children.map(nodeText).filter(Boolean).join('\n\n');
  if (plainText.trim().length < 180 || headings.length < 2) {
    throw new Error(`${file}: article needs at least 180 content characters and two headings`);
  }
  return { locale, file, metadata: result.data, content: plainText, headings, links };
}

export function articleUrl(article: Pick<Article, 'locale' | 'metadata'>): string {
  return `/${article.locale}/docs/${article.metadata.id}/`;
}

const marketingPaths = new Set(['', 'docs', 'download', 'protocol', 'security', 'changelog']);

/** Internal links must point at an actual published article or a known presentation page. */
export function validateLinks(articles: Article[]): void {
  const byUrl = new Map(articles.map((article) => [articleUrl(article), article]));
  for (const article of articles) {
    for (const target of article.links) {
      if (/^(?:https?:|mailto:)/i.test(target) && !target.startsWith(canonicalOrigin)) continue;
      if (/^[a-z][a-z\d+.-]*:/i.test(target) && !target.startsWith(canonicalOrigin)) {
        throw new Error(`${article.file}: unsupported link protocol: ${target}`);
      }
      let url: URL;
      try {
        // Markdown source references resolve relative to the article's file, ordinary links to its URL.
        const base = /\.mdx?(?:#|$)/.test(target)
          ? `${canonicalOrigin}/${article.locale}/docs/${article.metadata.id}.mdx`
          : `${canonicalOrigin}${articleUrl(article)}`;
        url = new URL(target, base);
      } catch {
        throw new Error(`${article.file}: invalid link: ${target}`);
      }
      if (url.origin !== canonicalOrigin) throw new Error(`${article.file}: unsupported link: ${target}`);
      const pathname = decodeURIComponent(url.pathname).replace(/\.mdx?$/, '').replace(/\/$/, '');
      const match = byUrl.get(`${pathname}/`);
      if (match) {
        if (url.hash && !match.headings.includes(decodeURIComponent(url.hash.slice(1)))) {
          throw new Error(`${article.file}: missing heading in link: ${target}`);
        }
        continue;
      }
      const [, locale, ...segments] = pathname.split('/');
      if ((pathname === '' || (locales.includes(locale as ContentLocale) && marketingPaths.has(segments.join('/')))) && !url.hash) continue;
      throw new Error(`${article.file}: broken internal link: ${target}`);
    }
  }
}

/** Enforce translation parity before producing any deployable search or release files. */
export function validateArticles(articles: Article[], version: string): void {
  const identities = new Set<string>();
  for (const article of articles) {
    const { id, source } = article.metadata;
    const identity = `${article.locale}/${id}`;
    if (identities.has(identity)) throw new Error(`${article.file}: duplicate document ID: ${identity}`);
    identities.add(identity);
    if (!requiredDocumentIds.includes(id as (typeof requiredDocumentIds)[number])) {
      throw new Error(`${article.file}: document ID is not in the reviewed publication manifest: ${id}`);
    }
    const expected = `${article.locale}/${id}.mdx`;
    if (article.file !== expected && article.file !== `${article.locale}/${id}/index.mdx`) {
      throw new Error(`${article.file}: expected content path ${expected} or its index.mdx equivalent`);
    }
    if (article.metadata.version !== version) throw new Error(`${article.file}: version must match Cargo ${version}`);
    for (const path of source) if (!isAllowedSource(path)) throw new Error(`${article.file}: disallowed source: ${path}`);
  }
  for (const locale of locales) {
    for (const id of requiredDocumentIds) {
      if (!identities.has(`${locale}/${id}`)) throw new Error(`Missing translation: ${locale}/${id}`);
    }
  }
  validateLinks(articles);
}

export function searchEntries(articles: Article[], locale: ContentLocale): SearchEntry[] {
  return articles.filter((article) => article.locale === locale)
    .sort((a, b) => a.metadata.order - b.metadata.order || a.metadata.id.localeCompare(b.metadata.id))
    .map((article) => ({
      id: article.metadata.id, title: article.metadata.title,
      description: article.metadata.description, url: articleUrl(article), content: article.content,
    }));
}

export function cargoVersion(cargo: string): string {
  const section = cargo.match(/^\[workspace\.package\][^\n]*\n([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1];
  const version = section?.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
  if (!version || !frontmatterSchema.shape.version.safeParse(version).success) {
    throw new Error('Cargo.toml: missing or invalid workspace.package.version');
  }
  return version;
}

const targetInfo: Record<string, { os: string; architecture: string }> = {
  'aarch64-apple-darwin': { os: 'macOS', architecture: 'Apple Silicon' },
  'x86_64-apple-darwin': { os: 'macOS', architecture: 'Intel' },
  'x86_64-unknown-linux-gnu': { os: 'Linux', architecture: 'x86_64' },
  'aarch64-unknown-linux-gnu': { os: 'Linux', architecture: 'ARM64' },
  'x86_64-pc-windows-msvc': { os: 'Windows', architecture: 'x86_64' },
};

const distributionSchema = z.object({
  jobs: z.object({ build: z.object({ strategy: z.object({ matrix: z.object({
    include: z.array(z.object({ targets: z.string().min(1) })).nonempty(),
  }) }) }) }),
});

export function releasePlatforms(workflow: string) {
  const matrix = distributionSchema.parse(parseYaml(workflow)).jobs.build.strategy.matrix.include;
  const targets = [...new Set(matrix.flatMap((row) => row.targets.split(',').map((target) => target.trim())))];
  return targets.map((target) => {
    const info = targetInfo[target];
    if (!info) throw new Error(`Unreviewed distribution target: ${target}`);
    return { id: target, target, ...info, href: releaseUrl };
  });
}

async function mdxFiles(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const paths = await Promise.all(entries.map(async (entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return mdxFiles(path);
    return entry.isFile() && entry.name.endsWith('.mdx') ? [path] : [];
  }));
  return paths.flat().sort();
}

/** Build output only from the explicit docs/site collection; never recursively scan the repository. */
export async function generateContent(repositoryRoot: string): Promise<{ articles: number; version: string }> {
  const root = resolve(repositoryRoot);
  const contentRoot = join(root, 'docs/site');
  const version = cargoVersion(await readFile(join(root, 'Cargo.toml'), 'utf8'));
  const articles = await Promise.all((await mdxFiles(contentRoot)).map(async (path) => {
    const file = relative(contentRoot, path).split(sep).join('/');
    const locale = file.split('/')[0];
    if (!locales.includes(locale as ContentLocale)) throw new Error(`${file}: unknown content locale`);
    return parseArticle(locale as ContentLocale, file, await readFile(path, 'utf8'));
  }));
  validateArticles(articles, version);
  const sources = new Set(articles.flatMap((article) => article.metadata.source));
  const physicalRoot = await realpath(root);
  for (const source of sources) {
    const sourcePath = await realpath(join(root, source));
    if (!sourcePath.startsWith(`${physicalRoot}${sep}`)) throw new Error(`Source escapes repository: ${source}`);
  }
  const platforms = releasePlatforms(await readFile(join(root, '.github/workflows/dist.yml'), 'utf8'));
  const outputRoot = join(root, 'apps/web');
  await mkdir(join(outputRoot, 'public/search'), { recursive: true });
  for (const locale of locales) {
    await writeFile(join(outputRoot, `public/search/${locale}.json`), `${JSON.stringify(searchEntries(articles, locale))}\n`);
  }
  const generated = join(outputRoot, 'src/content/releases.generated.ts');
  await mkdir(dirname(generated), { recursive: true });
  await writeFile(generated, [
    '// Generated by pnpm content from Cargo.toml and .github/workflows/dist.yml. Do not edit.',
    `export const releaseVersion = ${JSON.stringify(version)};`,
    `export const releaseUrl = ${JSON.stringify(releaseUrl)};`,
    `export const platforms = ${JSON.stringify(platforms, null, 2)} as const;`,
    '',
  ].join('\n'));
  await writeFile(join(outputRoot, 'src/content/documents.generated.ts'), [
    '// Generated by pnpm content from the reviewed docs/site collection. Do not edit.',
    'export interface GeneratedDocument {',
    '  id: string; locale: string; title: string; description: string;',
    '  section: string; order: number; version: string; source: string[];',
    "  translation: 'complete'; url: string; updatedAt: string; reviewedAt: string;",
    '}',
    `export const documents: GeneratedDocument[] = ${JSON.stringify(articles.map((article) => ({
      ...article.metadata, locale: article.locale, url: articleUrl(article),
    })), null, 2)};`,
    '',
  ].join('\n'));
  return { articles: articles.length, version };
}
