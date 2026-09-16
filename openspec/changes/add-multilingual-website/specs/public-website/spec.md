## Purpose

Provide an accessible multilingual public website that accurately introduces Umbra, guides installation and exposes stable canonical pages without storing visitor data.

## ADDED Requirements

### Requirement: Localized presentation pages
The website SHALL provide home, download, protocol, security and changelog pages in zh-Hans, zh-Hant, en, fr, es, ja and ca with localized titles, navigation and substantive content. The changelog SHALL link to versioned detail pages for documented releases and reject unknown versions.

#### Scenario: Seven-language presentation
- **WHEN** a visitor opens each supported language's presentation pages
- **THEN** the response contains localized page content and working links to documentation and releases.

### Requirement: Canonical directory routing
The website SHALL use https://umbra.cat/{locale}/ with URL locales zh-hans, zh-hant, en, fr, es, ja and ca, redirect root to English, normalize trailing slashes and reject unknown paths with HTTP 404.

#### Scenario: Canonical routes and missing pages
- **WHEN** root, a valid deep route, a slashless route or an unknown locale/document is requested directly
- **THEN** the response respectively redirects to the default language, renders the page, redirects to its canonical path or returns HTTP 404.

### Requirement: Language switching
The website SHALL switch to the equivalent page in the selected language and preserve an existing fragment where possible, with explicit handling of missing translations.

#### Scenario: Switch an article language
- **WHEN** a reader changes language on a documentation article
- **THEN** navigation retains the document identity rather than returning to the homepage.

### Requirement: Discoverable metadata
Published pages SHALL contain server-rendered localized metadata, correct html language, self canonical and reciprocal alternate-language links; the sitemap SHALL list only canonical public pages.

#### Scenario: Inspect metadata without JavaScript
- **WHEN** a crawler reads a localized page and the sitemap without executing JavaScript
- **THEN** it receives meaningful content, localized metadata and the matching published language alternatives.

### Requirement: Responsive accessible navigation
The website SHALL support mobile and desktop reading, keyboard navigation, visible focus, semantic controls, reduced-motion preference, a skip link and light/dark themes. First visits SHALL default to the light theme, while an explicit visitor preference SHALL persist locally.

#### Scenario: Keyboard and mobile reading
- **WHEN** a visitor uses a narrow viewport or keyboard to navigate and change theme
- **THEN** content remains readable, navigation is operable and the selected theme is applied.

#### Scenario: First interaction during page initialization
- **WHEN** a server-rendered page is visible before its interaction handlers are ready
- **THEN** JavaScript-dependent search, language, theme and copy controls remain disabled until ready, so the first enabled click is handled while ordinary links remain usable without scripts.

### Requirement: Accurate release and security information
Release and capability information MUST be based on repository sources and MUST distinguish alpha status and implementation limits from design goals. Download links MUST NOT invent unverified assets or checksums.

#### Scenario: Review download and security pages
- **WHEN** a visitor views downloads, protocol or security information
- **THEN** supported targets, source-backed version information and relevant limitations are visible with valid release/source links.

### Requirement: Stateless content hosting
The website SHALL render on the configured hosting runtime using bundled content and static assets without a database, visitor writes or external search service. Optional aliases SHALL redirect to canonical destinations rather than serve duplicate content.

#### Scenario: Build and serve without storage bindings
- **WHEN** the production bundle runs with no database or storage credentials
- **THEN** public pages, documentation and search remain usable and configured alias redirects have fixed canonical targets.
