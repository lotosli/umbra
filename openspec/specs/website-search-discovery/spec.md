# Website search discovery

## Purpose

Make Umbra's public website discoverable and accurately interpretable by search systems while helping users choose, install and configure the actual software.

## Requirements

### Requirement: Localized search identity
Every public page SHALL expose a descriptive localized search title, self canonical URL, reciprocal language alternatives and source-backed structured data in server-rendered HTML. Structured data MUST NOT invent ratings, authors or capabilities.

#### Scenario: Seven-language metadata
- **WHEN** any published page is fetched without JavaScript
- **THEN** its localized title, canonical, language alternatives and parseable structured data match the visible page and actual project facts.

### Requirement: Honest content freshness
Documents SHALL show the applicable version and actual update and review dates. Invalid dates SHALL fail publication, and sitemap modification dates MUST come from content metadata rather than build time.

#### Scenario: Stable publication dates
- **WHEN** content is rebuilt without edits
- **THEN** displayed dates and sitemap lastmod remain unchanged, while invalid or missing document dates fail validation.

### Requirement: Crawlable canonical routing
Language negotiation SHALL apply only to the root, with explicit non-shared caching. The www root SHALL reach the chosen language on the canonical host in one redirect. Unknown pages SHALL retain HTTP 404.

#### Scenario: Root and deep requests
- **WHEN** root, www root, localized deep paths and nonexistent paths are requested
- **THEN** roots negotiate with Vary and no-store, localized URLs retain their language, canonical aliases redirect and missing pages remain 404.

### Requirement: Actionable comparisons and guides
Comparisons SHALL explain the intended use and concrete prerequisites for each option with links to relevant setup information. Core guides SHALL explain how users recognize a successful step and where to go next in all seven languages.

#### Scenario: User decision path
- **WHEN** users read the protocol comparison and core getting-started guides
- **THEN** they can identify setup requirements and navigate to a relevant guide, and executable examples and version conditions remain intact.

### Requirement: Bounded measurement
The website SHALL provide a local event interface for enumerated download, onboarding and documentation navigation actions. It MUST NOT transmit telemetry without a separately configured collector, include user secrets or full URLs, or block navigation when collection fails.

#### Scenario: Privacy and delivery failure
- **WHEN** a user activates a measured action with no collector or a failing collector
- **THEN** navigation remains functional and the event contains only the approved event name and enumerated contextual values without network collection by default.

### Requirement: Repeatable discovery audit
Operators SHALL be able to audit all published canonical pages, language alternatives, structured metadata and freshness, and retain a baseline that distinguishes unavailable external metrics from zero values.

#### Scenario: Audit detects a broken contract
- **WHEN** an audit encounters missing structured data, canonical mismatch, an invalid alternate or a non-200 published page
- **THEN** it records the URL and failed rule and exits unsuccessfully without claiming indexation or AI citation success.
