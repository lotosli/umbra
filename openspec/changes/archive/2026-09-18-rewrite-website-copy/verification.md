# Verification

User approved implementation, translation and production publication on 2026-09-18.

- Reworked seven marketing editions and all 18 public articles per locale (126 total), following the reviewed Chinese master.
- Preserved article IDs, original command/configuration code blocks and technical usage conditions.
- Localized navigation, search, clipboard labels, metadata, manifests and social cards.
- Build and TypeScript/content checks passed; 126 articles validated.
- Unit tests: 187 passed; line coverage 97.81% (447/457).
- Browser acceptance: 35 passed across seven locales and widths 320, 390, 768, 1280, 1440.
- Manually inspected Chinese desktop, French mobile and localized sharing card.
- License check: 559 packages / 580 versions passed.
- OpenSpec strict validation: 13 passed. Git whitespace check passed.

## Publication — 2026-09-18

- PR #12: https://github.com/lotosli/umbra/pull/12
- Reviewed source commit: fd66e8cc9132a426ac91ba38530eee1e020dbc0e.
- Merge commit: 389e811b79aacfe0f0d0ea5cb2423e5e686e64c3; local build tree matched the merged source.
- Remote CI 35305752413 and Website checks 35305752492 passed, including Rust gates and website browser acceptance.
- Cloudflare local Wrangler deployment succeeded for umbra.cat and www.umbra.cat.
- Production version: 1e4bda6f-2ea4-4b2c-a37d-86661f7531b0.
- Previous version / rollback target: b0291722-974f-4cb4-9aad-e67bfd7d26f8.
- Production acceptance against https://umbra.cat: 35 browser tests passed (25.0 seconds), including all published URLs, seven languages, responsive pages, search, article language switching and navigation.
- Additional manual inspection: Japanese mobile protocol page.
- Archived after merge and production acceptance; editorial maintenance has no delta capability specs.
