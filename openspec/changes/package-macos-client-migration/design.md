## Context

The existing 1.0.0-alpha Mac binaries are already built and validated. The selected profiles are self-contained local YAML files. The user explicitly permits bundling their connection credentials and prefers unzip-and-run installation on another Mac.

## Goals / Non-Goals

Goals: one universal binary, bundled client config, two manually importable Clash profiles, destination-user paths, login startup and simple reversible controls. No new Rust code, protocol changes, current-service restarts, public credential upload, additional throughput testing or forced Clash-global configuration changes.

## Decisions

Combine the two existing Mac binaries into an ad-hoc signed universal executable. Package it with stock-zsh installation/start/stop/status/uninstall scripts, the three private configuration exports and a Chinese guide. A script bundle directly fulfills the user's preference without a privileged pkg installer or new GUI application. Require macOS 11 or later; no development environment is needed.

Installation resolves the destination user's home, copies immutable versioned program files and client configuration with restrictive permissions, creates a launch agent using structured plist edits, and enables it for the current graphical login. Existing executable/config/agent files are backed up before replacement. A failed installation restores prior state; an unrelated listener on the requested SOCKS port is not killed. The scripts refuse root installation to avoid binding the service to the wrong user.

Clash files are copied intact, including credentials. The user imports them into their existing compatible Clash application; no global Clash settings or unrelated profiles are exported. The private desktop directory/archive never enters git or public release assets. Existing code-signing identities are not required; local ad-hoc signing is documented accurately.

## Risks / Trade-offs

- Private archive contains working credentials -> retain local-only storage and owner-only permissions; never publish it.
- Existing destination service/config -> back up and restore on installation failure; retain explicit stop/uninstall controls.
- Gatekeeper on a transferred local script -> provide the normal Terminal invocation using stock zsh if Finder cannot open it.
- No access to the destination Mac -> state that package structure and script syntax were checked but no remote-Mac installation was performed.
