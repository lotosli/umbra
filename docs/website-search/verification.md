# Search discovery publication verification

Date: 2026-09-18. Change: `improve-website-search-discovery`.

## Local checks

- Build, 126-article content validation, TypeScript and ESLint: passed.
- Unit tests: 194 passed; line coverage 94.64% (513/542), above the independent website 90% gate.
- Browser tests: 35 passed, covering seven locales, responsive widths, navigation, search, no-JavaScript reading, metadata, dates and canonical redirects.
- Discovery audit: all 175 canonical URLs passed; seven locales, reciprocal alternatives, structured metadata, SSR content and article dates.
- License audit: 561 packages / 583 versions validated. New dependency `@types/jsdom` is development-only and MIT licensed.
- All fenced command/configuration examples in the 126 public documents are unchanged from the approved baseline. No proxy process or user network configuration was changed or exercised.
- Visual review: Chinese quick-start desktop layout, dates and readable task outcomes checked. Removed the default section breadcrumb to avoid duplicating the new complete trail.
- Structured source/application properties checked against https://schema.org/SoftwareSourceCode and https://schema.org/TechArticle. Source and downloadable application have separate stable IDs; document nodes express both article and webpage semantics.

## External account state

Google domain ownership is verified (user confirmation and property observed). The sitemap submission reached the submitting state; final receipt has not yet been read. Bing verification and real-bot security-log review are pending. External browser control repeatedly failed or lost the target tab; no successful platform step is inferred from a click.

## Publication

Implementation PR #14 merged as `eda45fc8d445cbbdc8fec2677abaa244d4067c7e` after Website checks #17 and Rust CI #70 both passed. Cloudflare version `58a83d85-1e79-4d7f-9418-c56c37be181f` was deployed and passed all 175 URL audits and all 35 browser tests on the production domain. The www root returned one 307 directly to the negotiated canonical language, with Vary and no-store. Rollback worker version before publication: `1e4bda6f-2ea4-4b2c-a37d-86661f7531b0`.

Performance results distinguish local preview (uncompressed, intentional noindex) from production and do not establish field Core Web Vitals. Search clicks, indexing and AI citations remain unavailable while account data is being processed; no outcome improvement is claimed from engineering checks alone.

## Lab baseline and follow-ups

`performance-lab.json` records three production mobile simulations before and after publication (Lighthouse 13.4.1). Median LCP was 3,208 ms before and 3,177 ms after; all CLS and TBT samples were zero. SEO lab score was 100 in all six samples. These small, host-dependent samples do not demonstrate a speed improvement or field CWV compliance. Prioritize the render-blocking stylesheet and unused first-page JavaScript in a separately measured performance change.

The GitHub About homepage field is currently empty; README links are now present. Updating About, final Google sitemap receipt, Bing ownership and verified-bot security review need a working authenticated browser connection. No broad bot bypass, training-policy change or analytics collector was enabled.

Post-publication user correction: shorten the English documentation search button from “Search documentation” to “Search” to avoid redundant wording and wrapping. The existing search behavior, shortcut and localized labels remain intact. This editorial correction is tracked in the publication follow-up.
