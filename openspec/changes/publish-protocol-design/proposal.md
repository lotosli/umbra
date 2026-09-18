# Proposal

## Why
The protocol design is only linked from GitHub, where its architecture Mermaid diagram fails to render. Users need the complete technical reference inside the website, with readable diagrams and full language coverage.

## What Changes
- Repair all three source diagrams and source navigation links.
- Publish the entire protocol design in seven languages, retaining components A–K, wire layouts, examples and references.
- Render diagrams to vector assets with accessible text and enlarge/source controls; retain no-JavaScript readability.
- Add documentation navigation, search and contextual links, source/review metadata and honest design-versus-runtime context.
- Validate section/code completeness, rendered assets, localization and browser behavior before Cloudflare publication.

User authorization: explicit requests on 2026-09-18 to repair the page, render the full document natively on the website, and provide complete seven-language editions.

## Capabilities
### New Capabilities
- `protocol-design-publication`: complete localized technical reference with verified diagram rendering and source parity.
### Modified Capabilities
None. Existing search identity and website visual requirements remain applicable.

## Impact
`docs/protocol-design.md`, seven public MDX editions, public content manifest/navigation, diagram rendering/validation tooling, small MDX presentation component, dev-only Mermaid CLI dependency and tests. No proxy runtime, network configuration or cryptographic behavior changes.
