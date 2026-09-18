# Spec Delta

## Purpose
Make Umbra's complete protocol design available as a readable, localized and source-traceable website reference with correctly rendered diagrams.

## ADDED Requirements

### Requirement: Complete localized reference
The website SHALL publish the full protocol design in all seven supported languages, retaining every technical section, appendix, formula and example. It SHALL distinguish design targets and historical examples from current deployment instructions.

#### Scenario: Read a complete edition
- **WHEN** a reader opens any language edition
- **THEN** components A–K, numbered sections 0–3 and 15–21 and appendices A–C are available, code semantics match the source, and current-use guidance is linked.

### Requirement: Native diagram reading
All three protocol diagrams SHALL render as scalable diagrams without client JavaScript. Readers SHALL have accessible captions, a full-size view and the underlying Mermaid text. The repository source diagrams SHALL parse successfully.

#### Scenario: Read diagrams without JavaScript
- **WHEN** a reader opens a protocol design page with JavaScript disabled or on a narrow screen
- **THEN** three valid diagram images and their captions are readable, full-size links and source disclosure remain available, and the page does not overflow horizontally.

### Requirement: Discoverable and maintained content
The reference SHALL appear in documentation navigation, search, sitemap and reciprocal language links. Publication SHALL reject missing editions, stale source/diagram provenance and structural omissions.

#### Scenario: Reject incomplete publication
- **WHEN** an edition, required section or matching diagram asset is missing or stale
- **THEN** validation fails rather than silently publishing an incomplete or misleading edition.

#### Scenario: Find and switch reference languages
- **WHEN** a reader searches for a protocol term or switches language on the reference
- **THEN** the complete matching article can be found and language switching preserves the article identity.
