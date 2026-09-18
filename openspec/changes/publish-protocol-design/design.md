# Design

## Context
The existing site publishes a reviewed seven-language MDX collection. The 735-line design source mixes target architecture with later implementation notes. Its three Mermaid fences are currently code-only outside GitHub, and the architecture uses ambiguous edge/subgraph syntax.

## Goals / Non-Goals
Publish the full reference, readable on desktop/mobile and without JavaScript. Preserve formulas, code semantics and section correspondence. Do not change the proxy protocol or test live user connections; do not present design targets as measured properties.

## Decisions
- Use the existing technical-reference section and one complete long-form article per language; retain headings and appendices rather than replacing them with a summary. Fumadocs supplies the reading outline and highlighted examples.
- Fix source Mermaid with stable ASCII identifiers, quoted labels and explicit edge syntax. Render the three localized diagrams to checked-in SVG assets with a pinned dev-only CLI. Vector assets load without a client Mermaid bundle or runtime rendering delay.
- Provide captions, a full-size link and expandable Mermaid source. Keep SVGs externally referenced as images, with static metadata, avoiding arbitrary inline SVG/script execution.
- Record source digest and section/code parity for every edition; require reviewed changes instead of silently updating translation timestamps. Keep sample byte values and code tokens unchanged; translate prose and comments.
- Add an explicit reading-status introduction: this is the complete design reference, including historical/target material. Link current setup and architecture guides; annotate target-only QUIC/0-RTT and historical layout/dependency examples.

## Risks / Trade-offs
Translation omission → check section correspondence, critical literals and code token parity; review full editions. Wide diagrams/tables → contained scrolling and full-size SVG links. Mermaid/browser toolchain size → dev only, checked-in assets validated by hashes at build time. Concurrent proxy work → isolated worktree and scoped commits.

## Migration Plan
Create content and assets, run strict content/link validation, unit line coverage >=90%, browser/no-JavaScript/mobile checks, remote CI; merge, deploy Cloudflare and verify all localized URLs. Preserve the prior worker version for rollback. Archive after production acceptance.
