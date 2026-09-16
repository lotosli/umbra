## Purpose

Enable reproducible website development, verification and deployment alongside the existing Rust workspace without weakening repository quality gates.

## ADDED Requirements

### Requirement: Independent reproducible frontend workspace
The repository SHALL provide a locked frontend workspace with documented development, check, test and production build commands while preserving existing Cargo workspace paths.

#### Scenario: Install and build the website
- **WHEN** a developer installs the locked dependencies and runs the documented build
- **THEN** the website builds independently of a Rust release build and Cargo workspace membership is preserved.

### Requirement: Tests and coverage gate
The website SHALL enforce at least 90 percent line coverage of hand-maintained web application logic and components, type checking, content validation and browser tests. Existing Rust coverage thresholds MUST NOT be reduced or mixed with frontend figures.

#### Scenario: Enforce independent quality gates
- **WHEN** web checks run locally or in CI
- **THEN** failing tests, invalid types/content or coverage below 90 percent fail the checks and Rust retains its existing gate.

### Requirement: Deployment readiness without implicit publication
The repository SHALL include hosting configuration and documented preview/deployment/rollback procedures. Production deployment SHALL require explicit user authorization or a manual workflow trigger and configured credentials. External registrar/DNS changes SHALL be left to the user unless separately authorized.

#### Scenario: Review deployment configuration
- **WHEN** a contributor reviews or builds the website without Cloudflare credentials
- **THEN** local verification works and no public deployment or DNS mutation is attempted.
