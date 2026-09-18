# Design

## Context

See proposal.md. The approved Chinese research plan includes a live baseline of 175 canonical URLs and 126 articles. The existing typed dictionaries, generated article metadata and SSR head helpers provide reusable integration points.

## Goals / Non-Goals

Implement the approved first publication batch and an operational measurement workflow. Keep the visual identity, article IDs, examples, proxy runtime and training permissions unchanged. No paid services, fabricated benchmarks, automatic broad WAF bypass or guaranteed ranking targets.

## Decisions

- Extend existing localized page metadata independently of visual headlines; generate JSON-LD from canonical URLs, release data and document metadata. Use software source identity on the homepage, application identity on downloads, WebPage and BreadcrumbList on documents. Avoid invented review rich results.
- Store explicit ISO date strings in article metadata. Seed update dates from the last actual editorial commit, then record reviews performed in this change. Dates are validated before build; no build-time freshness.
- Keep current canonical/hreflang URLs. Root language negotiation targets the canonical host directly for www, varies by Accept-Language and forbids caching.
- Rewrite comparison copy and extend existing guides; do not manufacture keyword landing pages. Provide specific per-option setup links and preserve examples.
- Dispatch a bounded browser CustomEvent interface with no persistence or outbound collector by default. External analytics integration remains dependent on the user's platform/privacy configuration. Include a documented schema and tests.
- Add a CLI audit and operational evidence templates, including fixed bilingual GEO tasks and unavailable account state. IndexNow is optional only after platform setup; no speculative submission credentials.

## Risks / Trade-offs

External browser connection unavailable → record access limitation and request platform state asynchronously while continuing engineering. Translation drift → preserve commands and compare core requirements. New metadata may enlarge bundles → keep helpers small and verify browser behavior. Sparse analytics → report unavailable metrics, not zero.

## Migration Plan

Build, types, content validation, unit coverage >=90%, browser tests, discovery audit and CI precede merge. Deploy with existing Wrangler authorization, retain rollback version, run production checks, then archive. Outcome reviews at 30/60/90 days are documented future operations, not fabricated current results.
