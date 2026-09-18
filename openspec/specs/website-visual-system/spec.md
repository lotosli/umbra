# website-visual-system Specification

## Purpose
Provide Umbra with a spacious, coherent website presentation based on the user-selected GPUI Kit reference while preserving readable multilingual content, accessible interactions and source-backed product information.

## Requirements

### Requirement: Coherent neutral presentation
The website SHALL present marketing pages, documentation, navigation and search in one black, white and neutral-gray visual system with bold headings, readable descriptions and consistent controls. Light SHALL remain the first-visit default, and an explicitly selected dark theme SHALL persist.

#### Scenario: Consistent themes across page types
- **WHEN** a visitor opens home, download, protocol, security, changelog, release detail, documentation and search in either theme
- **THEN** surfaces, text, borders and controls use the same theme hierarchy, and changing page retains the selected theme.

### Requirement: Spacious product introduction
The homepage SHALL use a wide two-column introduction on desktop with a bold product heading, primary and secondary actions and a prominent code window. The code window MUST show source-backed Umbra commands, and the following sections SHALL provide product capabilities, onboarding and documentation entry points.

#### Scenario: Desktop homepage and copy action
- **WHEN** a visitor opens the homepage at a 1440px viewport and copies the displayed commands
- **THEN** the introduction displays text and code side by side, primary actions remain visible, and clipboard feedback accurately reflects the copy result.

### Requirement: Multilingual responsive readability
All seven supported languages SHALL retain readable headings, body text, navigation and page actions at widths from 320px through desktop. Narrow layouts SHALL stack hero content and adapt card grids without clipping text or creating page-level horizontal scrolling. Long code MAY scroll inside its own panel.

#### Scenario: Narrow and long-text layouts
- **WHEN** presentation and documentation pages are opened in each supported language at 320px, 390px, 768px, 1280px and 1440px widths
- **THEN** important content and controls remain readable and reachable with no page-level horizontal overflow, including long translated labels.

### Requirement: Accessible visual hierarchy
The redesigned presentation SHALL retain semantic heading order, keyboard-operable controls, visible focus, reduced-motion support and readable contrast. Normal text MUST meet at least 4.5:1 contrast and large text at least 3:1 against its surface.

#### Scenario: Keyboard and reduced-motion use
- **WHEN** a keyboard user with reduced motion enabled visits the redesigned site in light or dark mode
- **THEN** they can reach navigation, search, language, theme and copy controls with visible focus, and decorative movement is suppressed without hiding content.

### Requirement: Product and routing fidelity
The redesign MUST preserve Umbra identity, alpha status, factual capability limits, real release destinations, localized routes, canonical metadata and server-rendered content. Reference-site product claims or statistics MUST NOT be presented as Umbra facts.

#### Scenario: Direct navigation and product facts
- **WHEN** a visitor directly opens localized homepage, download, security and documentation URLs or an unknown URL without JavaScript
- **THEN** valid routes retain substantive source-backed Umbra content and canonical metadata, download destinations remain real, and the unknown URL returns HTTP 404.
