## 1. Specification and workspace

- [x] 1.1 Record the user-approved plan, detailed design and scenario specifications before implementation; verify OpenSpec validation succeeds.
- [x] 1.2 Add the private pnpm workspace, pinned catalog, TypeScript/lint/test configuration and ignore rules; verify locked installation and Cargo paths.
- [x] 1.3 Integrate Start, Router, Fumadocs and Workers; verify a production build and direct page rendering.

## 2. Public content and localization

- [x] 2.1 Create 18 substantive source-backed documentation chapters in each of seven languages; verify all 126 articles and source metadata.
- [x] 2.2 Add content validation, locale-aware navigation, stable headings and search indexes; verify malformed metadata, broken links and multilingual search tests.
- [x] 2.3 Implement locale helpers and seven-language UI resources with request-scoped translations; verify route and language-switch tests.

## 3. Website and documentation experience

- [x] 3.1 Build responsive original marketing layouts and five localized presentation pages; verify rendering and content assertions for all languages.
- [x] 3.2 Integrate professional docs layouts, TOC, code copying, previous/next and source links; verify browser reading/navigation scenarios.
- [x] 3.3 Implement language/theme/mobile/search interactions and accessible states; verify keyboard, narrow viewport and interaction tests.
- [x] 3.4 Add source-derived version/platform data and truthful download/security content; verify no invented asset URLs or security claims.

## 4. Routing, metadata and delivery

- [x] 4.1 Implement canonical routing, root/slash redirects, real 404s, metadata, sitemap, robots and manifest; verify HTTP and metadata tests.
- [x] 4.2 Add web CI, manual Cloudflare deployment configuration, domain alias guidance and rollback instructions; verify structural workflow checks and build without credentials.
- [x] 4.3 Document workspace commands, content maintenance and translations; verify instructions correspond to available commands.

## 5. 测试与覆盖率 >= 90%

- [x] 5.1 Run meaningful Vitest/Testing Library tests with >=90% line coverage of maintained web code; preserve the independent Rust gate.
- [x] 5.2 Run strict typecheck, lint, content/source/link validation and production build; resolve all failures.
- [x] 5.3 Run Playwright across seven languages, SSR/no-JS/deep links/404/search/theme/mobile flows and inspect screenshots; resolve visual and functional issues.
- [x] 5.4 Validate all OpenSpec artifacts and record scenario-to-test mapping, final commands, results and deployment limitations in verification.md.

## 6. Authorized production deployment and English default

- [x] 6.1 Make English the root/default/fallback locale and update tests/documentation; verify build/check/coverage and browser routing.
- [x] 6.2 Inspect Cloudflare Worker/domain state and publish the verified website without affecting unrelated resources; record the deployment URL/version.
- [x] 6.3 Complete available Cloudflare-side domain setup and produce exact manual external DNS instructions; verify authoritative DNS and pending/active status.
- [x] 6.4 Test the deployed website, seven-language content, metadata, search, theme, redirects and error responses; record live results and any DNS-dependent limitations.

Final handoff: all live tests passed on the deployed Workers endpoint. Domain DNS is Active; custom-domain SSL remains pending validation. Per the user’s final instruction, certificate waiting and eventual apex/www HTTPS verification are left to the user.
