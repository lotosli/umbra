## Why

The user requests a desktop migration package for another Mac: the installed Umbra client and the two selected Clash profiles. They subsequently explicitly requested including all required connection tokens and installing by running a script after extraction. This request authorizes packaging existing release binaries, exporting those local configurations and providing installation/start instructions; it does not authorize publishing credentials or changing the current running services.

## What Changes

- Create a self-contained local macOS migration archive with a double-click installation script and a universal client using the existing 1.0.0-alpha arm64/x86_64 binaries.
- Install the bundled client configuration automatically, with per-user launch-agent start/stop/status scripts and no Rust, Homebrew or Python dependency on the destination.
- Export the current client configuration and the two screenshot-selected Clash profiles beside the installer, including their connection credentials as explicitly requested, with portable resources and private permissions.
- Deliver the installation scripts, Clash manual-import configurations and concise Chinese instructions in a desktop folder and transfer archive. Clash itself remains the user's chosen host for importing the profiles.

## Capabilities

### New Capabilities
- `macos-client-migration`: local universal installation, manual configuration import, per-user service ownership and portable private exports.

### Modified Capabilities
None.

## Impact

Packaging scripts/application resources and OpenSpec records only. No Rust implementation or network protocol changes. Configuration material remains outside git and public release assets. The user's instruction to stop additional throughput testing remains in force; only package construction/static integrity checks are in scope.

## Authorization

Approved by the user's explicit request to create an installer and place it on the desktop. Routine packaging choices are covered by that request. Existing services on this Mac must remain running with their current configuration.
