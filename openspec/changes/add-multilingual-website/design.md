## Context

The existing Cargo workspace and release workflow remain authoritative for Rust. Public README and usage documents describe the current `1.0.0-alpha`; protocol-design and architecture also contain future goals. No HTTP management API exists. See proposal.md for the user-approved scope and authorization.

## Goals / Non-Goals

**Goals:** ship a polished, accessible, responsive content website with accurate seven-language documentation; preserve existing Rust paths and workflows; make development, testing and Workers deployment reproducible.

**Non-Goals:** databases, accounts, analytics tracking, contact submissions, remote CMS, WebSocket services, API clients, protocol changes, external registrar/DNS mutations, paid plan purchases, self-hosted Git, offline caching or a service worker. Cloudflare deployment configuration and a manually triggered workflow are deliverables. The subsequent explicit deployment request authorizes production activation and Cloudflare-side domain setup; the user will apply external DNS/nameserver changes.

## Decisions

### Workspace and dependencies

Keep Cargo.toml, Cargo.lock, crates, xtask, fuzz and packaging in place. Add a private pnpm workspace with apps/web and a single pnpm lockfile. Pin Node 24 and pnpm; use a root dependency catalog. Avoid adding empty shared packages or a task orchestrator. Add web-only checks without reducing existing Rust coverage or security gates. Build scripts live in apps/web/tooling because root scripts is intentionally ignored for local operations.

React and React DOM remain on 19.2.x, Vite on 8.x, Tailwind on 4.3.x. Use matched Fumadocs Core/UI plus its MDX Vite plugin, TanStack Start/Router, react-i18next, Zod, and the Cloudflare Vite plugin. Radix is used only where a real interaction warrants it. No Query, form framework, global state library or OpenAPI client is needed.

### URL, locale and metadata contract

Canonical origin is https://umbra.cat. URL locales are zh-hans, zh-hant, en, fr, es, ja, ca; HTML language tags are zh-Hans, zh-Hant, en, fr, es, ja, ca; content folders use the lowercase URL locale IDs. Root redirects to /en/. All content URLs consistently end with a slash. Homepage, download, protocol, security, changelog and docs live beneath the locale. The changelog lists versioned detail pages at /{locale}/changelog/{version}/; only source-backed versions are accepted. Stable document IDs use language-independent slugs. Locale switching maps an existing document ID and preserves the fragment; absent translations link explicitly to a source-language version rather than silently substituting text.

Each page renders its own localized title/description, canonical, html lang and reciprocal hreflang links. x-default selects the actual default-language equivalent. Sitemap includes only published canonical pages. robots and manifest are static/public endpoints. Manifest is metadata only and makes no offline claim. Unknown locales/documents return localized error content and HTTP 404 before streaming success headers.

Optional aliases are redirect-only, not duplicate content: www to apex, docs root to default-language docs, en/fr/es/ja/ca language aliases to matching directories; the git root can point to the canonical GitHub repository. Exact alias rules and DNS setup are documented and do not create resources automatically. No wildcard redirect forwards arbitrary attacker-provided destinations. Public URLs remain independent of possible future application splitting.

### Routing and rendering

Use TanStack Start SSR with file routes. Root owns the HTML document and request-scoped providers; $locale validates the locale; a pathless _site layout wraps marketing pages; docs has its own layout with a splat document route. Router/source adapters validate documents against a generated content manifest. Plain anchor navigation and server-rendered article content preserve basic use without JavaScript. Cloudflare Workers renders HTML from bundled content; Static Assets serves CSS, JS, SVG and search files. Node filesystem/MDX compilation runs during build, never for public requests.

Full-site SSG is not required. Future prerendering must enumerate real locale/document pairs. Hashed assets use long caching; SSR HTML starts conservatively with explicit headers, and any later edge cache must define invalidation and locale-aware keys. Preview URLs are noindex and canonical metadata continues to use the production origin.

### Content and information architecture

Use docs/site/{url-locale} for 18 substantive public chapters per language: introduction, installation, quick-start; server, client, deployment, upgrade; server/client configuration and examples; architecture, transports, security-model; CLI/configuration/protocol reference; troubleshooting; contributing. Existing long usage documents stay reachable and are linked as reviewed source references; the new pages reorganize/summarize these sources instead of automatically publishing engineering notes. Use standard Markdown with MDX only for approved components.

Frontmatter includes stable id, title, description, section, order, version, source paths and translation state. Explicit source allowlists exclude openspec, capture/raw audit records, private configs and local scripts. Validate locale completeness, unique IDs, metadata, cross-links, heading anchors and known public source paths. Release metadata derives version from Cargo and supported targets from checked release definitions; do not invent published asset filenames, checksums, signing status or audit claims. Until a release manifest proves an asset exists, download cards link to the project release listing.

Source precedence is current code and README state over aspirational protocol prose. State alpha status; historical Chrome 150 profile versus Chrome 153 evidence; no full fingerprint equivalence or audit claims; SOCKS no-auth and loopback binding; application HTTPS and endpoint trust boundaries. CLI/TOML examples contain placeholders only.

### Design and documentation experience

Use an original eclipse mark, warm off-white backgrounds, ink text, restrained lavender accents, clear technical diagrams and expressive typography with system/CJK fallbacks. Per the user’s follow-up, first visits default to light theme; retain dark mode and persist an explicit local preference. Support light/dark themes, reduced motion, visible focus, semantic landmarks, keyboard controls, skip links and mobile navigation. Marketing and docs share visual tokens while docs prioritize comfortable line length, sidebar, TOC, breadcrumbs, previous/next, source/edit links, code copying and version/translation status.

Use Fumadocs Core/UI/MDX as the document foundation. Document body and titles are localized; react-i18next owns shared UI and Fumadocs receives the same locale/translations. Each SSR request has its own i18next instance and initial language resources. Avoid global mutable language state and use no browser storage during server rendering.

Search is read-only and locale-specific. Prefer generated static content indexes with browser querying; use the Fumadocs search integration where appropriate. Index title/headings/body with stable canonical results, load only the current language and test CJK queries, accented text and configuration keys. No database or external search service. A local search endpoint serving a bundled index is permitted if framework integration requires it; no user query persistence.

### Verification and deployment

Vitest and Testing Library test locale/URL/SEO/content rules and meaningful UI behavior; coverage includes hand-maintained web logic/components and tooling, excluding generated route/content outputs, test files and framework configuration only. Fail below 90% lines without mixing Rust and frontend figures. Playwright checks all language routes, SSR/no-JS content, real 404s, language/theme/search/mobile interactions, and screenshots for visual review. Each spec scenario maps to a test or explicit structural CI assertion. Content validation runs before build. Existing Rust CI remains unchanged except additional independent web jobs/workflows.

Provide pnpm dev/build/check/test/test:e2e/deploy commands, Wrangler configuration, CI and a manually triggered deployment workflow that needs Cloudflare account/token secrets. Deploy only after checks; existing services are unaffected. Document local commands, content editing, translations, alias rules and rollback.

## Risks / Trade-offs

- SSR HTML can precede hydration over a real network → use the router's hydration state to disable JavaScript-only search/language/theme/copy controls until handlers are ready; preserve native links and HTML disclosure navigation. Live tests must exercise the first enabled click without artificial sleeps.

- Seven languages multiply review effort → complete matching core pages, source metadata, exact locale checks and visible translation status; technical terms stay consistent.
- Fumadocs/Start/Workers integration evolves → pin exact compatible versions and exercise a production build and local Workers preview.
- Large docs/search bundles → split content and indexes by language; load search on demand; inspect output sizes.
- SSR theme/locale mismatch → deterministic URL-derived locale, request-scoped translations and tested initial theme behavior.
- Current release information can drift → read Cargo version, check source paths and document release-listing fallback honestly.

## Migration Plan

1. Record approved scope and these artifacts before implementation, including the later authorization to deploy and use English by default.
2. Add workspace, framework, content, UI and routes without moving Rust or existing public documents.
3. Run content validation, typecheck, lint, coverage, build, browser checks and OpenSpec validation; record results in verification.md.
4. Publish the verified build to Cloudflare as subsequently requested; test the deployed workers.dev endpoint and prepare Cloudflare-side umbra.cat binding. Report the exact external DNS/nameserver changes the user must apply. Domain activation may remain pending that manual change.
5. Roll back a future deployment through Cloudflare versions; source rollback removes the independent web app without a Rust migration.
