## Purpose

Provide a self-contained private migration package that installs the existing Umbra client on another Mac and preserves selected Clash connection configurations for manual import.

## ADDED Requirements

### Requirement: Destination-local installation
The bundle SHALL support macOS 11 or later on Apple Silicon and Intel without additional language runtimes, and SHALL install the included client configuration and login service for the invoking user.

#### Scenario: Install an extracted bundle
- **WHEN** a standard logged-in user runs the installation script from an extracted directory
- **THEN** the correct client architecture and bundled configuration SHALL be installed under that user's home and a per-user service SHALL be registered

### Requirement: Reversible service ownership
Installation SHALL back up existing Umbra-owned files, restore prior state on failure, and provide start, stop, status and uninstall controls without terminating unrelated processes.

#### Scenario: Existing destination state
- **WHEN** an existing Umbra configuration or launch agent is replaced
- **THEN** the previous files SHALL remain recoverable and an installation failure SHALL restore the previous registration

### Requirement: Complete private configuration export
The delivery SHALL contain the existing client configuration and both selected Clash profiles with their required credentials intact; these private files SHALL remain outside repository and public artifacts.

#### Scenario: Manual Clash import
- **WHEN** the user selects either exported YAML file for import into a compatible Clash client
- **THEN** that file SHALL contain the same connection credentials and standalone profile content as the selected local profile
