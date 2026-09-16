# Verification — multilingual Umbra website

Date: 2026-09-16. Branch: `feat/multilingual-website`.

## Delivered behavior

- Cargo remains in place; an independently locked pnpm workspace contains `apps/web`.
- React 19.2.8, Vite 8.3.0, Tailwind 4.3.3, TanStack Start/Router, Fumadocs and Cloudflare Workers SSR build successfully.
- The website defaults to **light theme**, as requested in the user's follow-up. Explicit dark-mode preferences persist only in the browser.
- Seven URL locales: `zh-hans`, `zh-hant`, `en`, `fr`, `es`, `ja`, `ca`; standard HTML language tags distinguish Simplified/Traditional Chinese.
- 126 reviewed-source documentation articles (18 per language), 56 navigation metadata files, localized marketing pages and versioned release details. Together with document indexes, the sitemap contains 175 canonical pages.
- Per-language read-only browser search; canonical/hreflang metadata, sitemap, manifest, root/slash redirects, alias handling and real missing-page HTTP 404s.
- Docs include sidebar, TOC, copyable code, previous/next, source/edit links, mobile navigation and a working keyboard skip link.
- Cloudflare configuration, an explicit manual deployment workflow, dependency-license gate and maintenance/rollback instructions are supplied.

## Executed checks

| Check | Result |
| --- | --- |
| `pnpm install --frozen-lockfile --offline` after initial installation | Passed; locked workspace is reproducible from the installed cache |
| `pnpm build` | Passed; client assets and Workers SSR bundle generated |
| `pnpm check` | Passed; all 126 content files, sources, links, heading targets, TypeScript strict and ESLint |
| `pnpm test` | **164 tests, 12 suites passed** |
| Frontend line coverage | **97.65% (417/427)**; threshold remains 90%, including maintained application and tooling code |
| `pnpm test:e2e` | **20 Chromium tests passed**, including requests to all 175 published URLs |
| `pnpm --filter @umbra/web run licenses` | Passed; 557 dependency packages / 578 installed versions |
| `pnpm --filter @umbra/web exec wrangler deploy --dry-run --outdir /tmp/umbra-web-worker-dry-run` | Passed; 203 static assets, Worker upload gzip 804.54 KiB, no storage bindings; nothing published |
| `npx --yes @fission-ai/openspec@latest validate --all --strict` | 11 items passed, 0 failed |
| `git diff --check` | Passed |

The existing `version-local-chrome-profile` change produces an informational archive warning about its missing base fingerprint spec; strict validation still passes. This website change does not modify that unrelated change.

Builds emit a Fumadocs upstream browser-externalization warning for its optional raw-source filesystem helper. Public content is compiled into modules; browser and Workers runtime tests pass without filesystem reads or browser exceptions. No Rust source, Cargo dependency/lockfile, Rust CI threshold, dist workflow or running proxy service was changed; unrelated Rust runtime tests were not rerun.

## Scenario-to-test mapping

| Spec scenario | Verification |
| --- | --- |
| Seven-language presentation | `marketing.test.tsx`, seven localized Playwright presentation/document cases |
| Canonical routes and missing pages | `core.test.ts`, `-routes.test.tsx`, Playwright canonical redirects/404/endpoints |
| Switch an article language | `providers.test.tsx`, `core.test.ts`, Playwright language switching |
| Inspect metadata without JavaScript | `core.test.ts` head/sitemap checks; Playwright metadata and no-script reading |
| Keyboard and mobile reading | `site-shell.test.tsx`, docs keyboard-focus test, Playwright skip/navigation/theme/mobile tests |
| Review download and security pages | `marketing.test.tsx`, content release-matrix tests and source audit |
| Build and serve without storage bindings | `server.test.ts`, alias/header tests, Workers preview and deployment dry-run |
| Validate translation coverage | content collection tests and real `pnpm content` across 126 articles |
| Reject invalid publication metadata | `tooling/content.test.ts` invalid/missing/duplicate metadata and source boundary cases |
| Read and navigate a reference article | `docs.test.tsx`, seven Playwright reference-document checks and screenshot review |
| Search across language-specific examples | Unicode/accent/config-key tests in `core.test.ts` and content index tests; browser search/navigation |
| Detect a broken internal reference | Markdown AST reference/heading tests in `tooling/content.test.ts` |
| Read a deep document without scripts | Playwright JavaScript-disabled quick-start reading |
| Install and build the website | frozen installation, production build, unchanged Cargo paths |
| Enforce independent quality gates | full frontend check/coverage run and `tooling/workflows.test.ts` preserving Rust gate |
| Review deployment configuration | workflow structure tests, dry-run and documented credential-free local verification |

## Content review

Content was derived from README, usage, public CLI/configuration code and the actual dist matrix. Seven-language configuration and CLI field sets were cross-checked against Rust definitions. Examples use placeholder keys/IDs, loopback/wildcard bindings and the documentation-only address `198.51.100.10`. The current alpha version, Chrome 150 profile versus Chrome 153 evidence, no-auth SOCKS boundary, application HTTPS requirement and unsupported/experimental capabilities remain explicit. Existing long usage documents stay reachable; source links in the website footer identify the original material.

## Visual review

Default-light home/download/docs layouts were checked for all seven languages at desktop 1440px and mobile 375px: 42 pages returned HTTP 200 with no horizontal overflow. French and Catalan long text, Chinese/Japanese pages, language menus, mobile navigation, tables and code scrolling were inspected. Auxiliary text contrast was increased and mobile diagram/footer labels enlarged. Final Playwright screenshots are under `apps/web/test-results`; additional review screenshots were created under `/tmp/umbra-design-review/light`.

## Publication boundary

The initial implementation did not publish or change DNS. The user subsequently authorized Cloudflare deployment and Cloudflare-side domain setup, with external registrar changes performed by the user. The deployment is now published as recorded below. Preview responses remain noindex; production metadata identifies the canonical origin.

Assisted-by: OpenAI Codex — specifications, website implementation, seven-language content, tests and verification.

## Follow-up: GitHub navigation mark

At the user's request, replaced the upper-right generic code icon with the GitHub mark already used by the installed MIT-licensed Fumadocs navigation. Existing repository link, accessible label, size and theme color are retained. The 11 shell tests, component ESLint and production build pass; the local preview was rebuilt.


## Authorized deployment and final handoff

- English is now the default locale: root redirects to `/en/`, unknown-locale errors use English, and SEO x-default and the optional docs alias use English. Default light theme is retained.
- The verified website is published to Cloudflare Workers. The live Workers endpoint was provided in the task; no account IDs, tokens or private credentials are recorded here.
- `umbra.cat` and `www.umbra.cat` Custom Domains are attached to `umbra-web` and declared in Wrangler configuration. Cloudflare created their proxied DNS records. The application redirects www to the apex; Always Use HTTPS is enabled.
- The user confirmed domain email is unused and changed registrar nameservers themselves. Registry RDAP, public DNS and Cloudflare confirmed the transition; the zone is **Active** on the Free Website plan.
- Real-network testing found clicks arriving before hydration. Search/language/theme/copy controls now remain disabled or inert until ready. Server-rendering and first-enabled-click regressions are tested; normal links and article text remain available without scripts.
- Build, TypeScript, ESLint and 126-article content validation pass. **170 tests / 13 suites pass**, with **97.73% line coverage (431/441)**. The license gate passes for 557 packages / 578 versions.
- The complete **20-test Playwright suite passes against the deployed Workers endpoint**, including all 175 canonical page paths, seven languages, search, language switching, theme persistence, keyboard/mobile behavior, metadata, redirects and real 404s.
- Custom-domain certificates remained **pending_validation** at handoff. Custom-domain HTTPS is **not** reported as passing. Universal SSL is enabled and automatic validation is in progress; no TLS-validation bypass or manual certificate purchase was used.
- The user explicitly requested ending after configuration confirmation and handling propagation verification themselves. Certificate waiting and eventual apex/www HTTPS verification are therefore handed back to the user.

After certificate activation, the remote suite can be rerun with `PLAYWRIGHT_BASE_URL=https://umbra.cat pnpm test:e2e`.
