## Why

Umbra needs a public website that explains the current implementation, helps users install and configure it, and provides professional documentation in seven languages. The existing Cargo monorepo has no web application; public information is spread across READMEs and long usage documents.

## What Changes

- Extend the repository with a pnpm workspace and one React 19.2 / TypeScript strict / Vite 8 application at `apps/web`, retaining the Rust workspace in place.
- Use TanStack Start and file-based TanStack Router routing for a Cloudflare Workers SSR website, with Tailwind CSS 4.3, CSS variables, and Fumadocs Core/UI/MDX.
- Provide localized home, download, protocol, security, changelog and professional documentation pages in Simplified Chinese, Traditional Chinese, English, French, Spanish, Japanese and Catalan.
- Publish canonical content under `https://umbra.cat/{locale}/`; use language directories and optional redirect-only aliases, not duplicate language or documentation sites.
- Derive public documentation and release metadata from reviewed README, usage, Cargo, CLI and configuration sources; clearly distinguish supported behavior from protocol goals.
- Add content validation, accessible navigation, language/theme controls, local document search, SEO metadata, manifests, CI, coverage and Cloudflare deployment configuration.
- No breaking Rust API, wire protocol, CLI or existing document link changes.

## Capabilities

### New Capabilities
- `public-website`: localized presentation, routing, design system, downloads, metadata, accessibility and hosting.
- `multilingual-documentation`: reviewed content collections, seven-language documentation, navigation, search and translation integrity.
- `web-workspace`: frontend package management, builds, tests, coverage and deployment automation alongside Cargo.

### Modified Capabilities
None.

## Impact

Adds root JavaScript workspace configuration, `apps/web`, public content under `docs/site`, web CI/deployment workflows and developer documentation. Existing Rust source, Cargo dependencies, private configuration, active services and packaging artifacts remain outside the website change. New npm dependencies require pinned lockfile versions and license review; Rust CI gates retain their existing thresholds.

## Authorization

The user reviewed the complete website, seven-language, SSR hosting and canonical-domain plan in this conversation, then explicitly requested: “新建spec，实现完整的方案包括细节，然后按照这个方案实现官网”. This change records that approved scope before implementation. Routine implementation details are authorized by that request. The user subsequently explicitly requested deploying the website to Cloudflare, completing Cloudflare-side domain setup and online tests, while leaving external registrar/DNS changes to them. This authorizes publishing the existing website and configuring its Cloudflare resources. It does not authorize changing external DNS, transferring registration, purchasing a plan, or modifying unrelated sites. The user also confirmed English as the default language; light remains the default theme.
