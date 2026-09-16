# Umbra website

The seven-language public website and documentation run as one React / TanStack Start application on Cloudflare Workers. Public content lives in `../../docs/site`; the application does not require a database, Rust server, account system or production credentials for local development.

## Local development

Use Node **24.18.1** and the repository's pinned **pnpm 9.11.0**. Run from the repository root:

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

The local address is printed by Vite. `/` redirects to `/zh-hans/`. All language and document URLs are directly addressable, for example `/en/docs/getting-started/installation/`.

## Verification

```sh
pnpm build
pnpm --filter @umbra/web run licenses
pnpm check
pnpm test
pnpm --filter @umbra/web exec playwright install chromium
pnpm test:e2e
pnpm preview
```

Build first on a fresh checkout: it generates the file route tree and the reviewed content artifacts. `check` validates content, TypeScript strict mode and ESLint. `test` enforces **90% line coverage** for maintained website code and tooling. Browser tests exercise the locally built Workers application. Rust retains its separate CI, dependency and coverage gates.

## Content and generated files

`pnpm content` validates all 126 articles, seven-language parity, metadata, source paths and internal links/headings. It then writes:

- `public/search/{locale}.json`: independent browser search indexes, including article body text.
- `src/content/documents.generated.ts`: public article metadata for navigation, sitemap and source links.
- `src/content/releases.generated.ts`: workspace version and the distribution workflow's target platforms.

Generated files are not edited or committed. The tool scans only the explicit `docs/site` collection; source metadata identifies reviewed inputs without publishing those source files. Existing usage and architecture documents remain in place.

Download cards link to the GitHub Releases listing. The build does not assume that a Cargo version has already been published, invent an asset name or claim a checksum/signature has been verified.

## Deployment

The app includes Wrangler configuration and an explicit **Deploy website** GitHub Actions workflow. To enable it, configure `CLOUDFLARE_API_TOKEN` as a production environment secret and `CLOUDFLARE_ACCOUNT_ID` as a production environment variable. Trigger the workflow only when publishing the selected revision is intended. All website checks run before deployment.

To publish manually after verification:

```sh
pnpm --filter @umbra/web deploy
```

This command performs a real deployment and requires Cloudflare authentication. Normal development/build/test commands do not deploy or create DNS records. Domain activation and redirect aliases are separate Cloudflare configuration steps.

See [website development and operations](../../docs/website-development.md) for content conventions, language/SEO rules, domain configuration and rollback.
