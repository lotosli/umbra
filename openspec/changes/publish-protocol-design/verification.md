# Verification — complete protocol publication

Date: 2026-09-18. Approved scope: full seven-language editions, native diagrams, source repair, production publication.

## Local checks

- Seven complete editions: 40 section/subsection headings, 14 fenced examples and three localized diagrams each.
- 21 static SVGs generated successfully with Mermaid CLI 11.17.0; no runtime Mermaid, scripts, external resources or foreignObject.
- Canonical source revision and reviewed edition/diagram hashes recorded in `docs/protocol-diagrams/manifest.json`.
- `pnpm build`, `pnpm check`, dependency license gate: passed. 133 public articles validated; 721 dependency packages / 757 versions reviewed on macOS.
- `pnpm test`: 204 tests passed; line coverage 94.90% (559/589), threshold remains 90%.
- `PLAYWRIGHT_BASE_URL=http://127.0.0.1:3001 pnpm test:e2e`: 42 tests passed. Includes all seven protocol editions on 390px viewports with JavaScript disabled, image decoding, direct SVG access, native source disclosure, layout and search entries.
- Discovery audit: all 182 canonical pages passed, including canonical/hreflang, SSR article text and structured metadata.
- Browser inspection caught and fixed a class-name collision with the homepage diagram. Documentation figures now use isolated `.reference-diagram` styles; caption-below-image assertions prevent overlap.
- Existing unrelated runtime work remained outside this isolated worktree.

## Release

Remote CI, merge, Cloudflare version and production verification are recorded after publication.
