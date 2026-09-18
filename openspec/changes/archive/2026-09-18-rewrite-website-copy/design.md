# Design

## Context

See proposal.md. The existing typed locale dictionaries and MDX article IDs provide a stable publication boundary.

## Goals / Non-Goals

Use the approved Chinese master as the semantic source. Keep all executable examples and configuration requirements. Do not change protocol, routes, runtime deployment topology or visual theme.

## Decisions

Write benefits first on introduction pages, actionable steps in guides and detailed limitations in the security/reference sections. Translate complete articles with local sentence structure instead of sentence-by-sentence substitutions. Keep typed dictionaries and native MDX rather than adding a translation service. Separate labels for different destinations and clipboard actions. Preserve source metadata and validate seven-language coverage.

## Risks / Trade-offs

Longer translations can overflow → run the seven-language responsive browser suite. Technical meaning can drift → compare examples, field names and required conditions with the master. Moving caveats can remove useful instructions → retain local SOCKS access control, matched versions and QUIC prerequisites in relevant steps.

## Migration Plan

Build, check, unit coverage and browser tests precede CI and merge. Deploy the verified build with authenticated local Wrangler, retain the previous deployment version, and run production acceptance.
