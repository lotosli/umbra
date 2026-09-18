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

- Implementation commit: `3128f3f84ac865f1b0a0a7fee737a2d92db7720f`.
- [PR #16](https://github.com/lotosli/umbra/pull/16) merged as `d3f273f2fcd37a9c2be9515d53bea006c120e62c` after [Website checks #23](https://github.com/lotosli/umbra/actions/runs/35327077735) and [Rust CI #76](https://github.com/lotosli/umbra/actions/runs/35327077739) both completed successfully.
- Cloudflare Worker `umbra-web` published to `umbra.cat` and `www.umbra.cat`: version `4c537fe4-8bed-480c-b4ec-a2092e9aa1e0`.
- Previous worker version retained for rollback: `d71fb9a3-0bae-48e8-84ff-1afcbadb1f3e`.
- Production `https://umbra.cat`: all 182 canonical page audits passed and all 42 browser tests passed, including all seven complete protocol pages, 21 SVG requests, mobile/no-JavaScript reading and existing site behavior.
- Worker upload compressed size: 1286.56 KiB; reported startup: 8 ms.
- Public entry: https://umbra.cat/zh-hans/docs/reference/protocol-design/ (same reference identity across all seven languages).
- Synced three requirements and four scenarios into `openspec/specs/protocol-design-publication/spec.md`; archived the completed change on 2026-09-18.
- Production source was deployed from an isolated worktree. Concurrent uncommitted Rust/runtime changes in the original checkout were neither staged nor altered.
