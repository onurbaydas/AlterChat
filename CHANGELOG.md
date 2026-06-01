# Changelog

All notable changes to AlterChat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Fixed: Tauri CSP was null, now enforces strict policy (no unsafe-eval)
- Deprecated: Legacy `PrivateMessage` and `RatchetPrivateMessage` DM paths; canonical path is X3DH + ML-KEM-768 + Double Ratchet

### Added

- Atomic database migration framework with versioned schema (`CURRENT_DB_VERSION = 1`)
- Onboarding wizard with password-protected profile creation and backup warning
- Network status indicator (online/connecting/offline)
- Message delivery status indicators (sending/sent/failed)
- Peer list persistence across restarts (`~/.alterchat/known_peers.json`)
- `ALTERCHAT_BOOTSTRAP` env var for custom bootstrap nodes
- X3DH unit tests and migration idempotency tests
- CI matrix expanded to ubuntu-22.04, windows-latest, macos-latest
- `cargo audit` and `npm audit` in CI
