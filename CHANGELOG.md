# Changelog

All notable changes to AlterChat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Profile storage redesigned (breaking).** The SQLCipher key used to be a
  bare SHA-256 of the password, and profile filenames contained a prefix of
  that hash. That allowed an offline dictionary attack against the filename
  alone. Profiles now live in `profiles/<random-id>/` under the OS app-data
  directory. The database key is Argon2id(password, random per-profile salt),
  passed to SQLCipher as a raw key. Profiles from earlier builds are not
  migrated.
- Login now distinguishes *create* from *unlock*: a mistyped password no longer
  silently creates a new empty profile.
- Path traversal fixed in the incoming `FileChunk` handler: a peer-supplied
  `transfer_id` is now restricted to `[A-Za-z0-9_-]{1,128}`.
- The legacy symmetric ratchet now caps skipped steps (1000), rejects replays,
  and only commits state after AEAD verification. Before this, a single
  message with `counter = u64::MAX` could freeze the event loop.
- Invite revocations are now Ed25519-signed and verified, and only the
  invite's issuer may revoke it. Before this, any peer could revoke any invite.
- I2P / SOCKS5 modes now refuse to start instead of silently connecting
  directly. mDNS is always off in Tor mode. The relay server only runs when
  "volunteer relay" is enabled.
- `panic_wipe` requires an explicit confirmation argument.
- Malformed CRDT room data from the network can no longer panic the event loop.
- Fixed: Tauri CSP was null, now enforces strict policy (no unsafe-eval)
- Deprecated: Legacy `PrivateMessage` and `RatchetPrivateMessage` DM paths

### Fixed

- The Tauri backend did not compile (`tracing` macro without the dependency,
  and an unbound variable).
- `AppState.db_key` was never set, so nearly every settings, storage, plugin,
  governance and vault command failed with "Not logged in".
- Governance commands read the encrypted keypair file with the unencrypted
  parser, so signing invites and roles always failed. They now use the
  in-memory session keypair.
- Double Ratchet roles were inverted on the receive path, so the first direct
  message never decrypted.
- Joining a room with a wrong password replaced and later overwrote the stored
  history. It now emits `room-join-failed`.
- Incoming room merges persisted the sender's document instead of the merged
  local document.
- Session startup no longer panics on database or network errors. The UI
  receives a `session-error` event instead.
- QUIC mode now also keeps TCP, so TCP-only bootstrap nodes are reachable.
- The frontend did not type-check (`npm run build` failed). Fixed the type
  errors and added the missing listener cleanup.
- The Tauri updater plugin was configured without a `pubkey`, which crashes at
  startup. The updater is removed until signed update infrastructure exists.
- The opener plugin was declared but never registered.
- The UI now reports `dm-requires-pubkey` and `private-message-blocked`
  instead of failing silently.
- The UI security capability flags now report X3DH/ML-KEM and zero-config
  bootstrap accurately (both `false` for now).

### Changed

- Bootstrap node: persistent identity (`ALTERCHAT_DATA_DIR`), configurable port
  (`ALTERCHAT_BOOTSTRAP_PORT`), TCP + QUIC listeners, ping, graceful shutdown,
  and a Dockerfile.
- SQLCipher is built with vendored OpenSSL for portable builds on all platforms.
- Removed unused UI components (`ChatPanel`, `CallManager`, `LoginScreen`,
  `UpdateChecker`).
- LICENSE now contains the complete AGPL-3.0 text (it was truncated after the
  preamble).
- CI: frontend job, frontend bundle built before Rust checks, `rustsec/audit-check`,
  concurrency control. Release: optional code signing, bootstrap binary and
  `SHA256SUMS` attached to the draft release.
- Added `rust-toolchain.toml`, `.editorconfig`, `.gitattributes` and Dependabot
  configuration.

### Added

- **File transfer works end to end.** The sender encrypts the file into
  256 KiB AES-256-GCM chunks with a random per-file key, seals the key to the
  friend's X25519 `offline_pubkey` and sends a `FileOffer`. The recipient
  validates every field (id, size, chunk size/count, hash, sealed key;
  filenames are sanitised against path separators, reserved Windows names,
  bidi tricks and length), checks block list, `min_trust_file`, storage quota,
  a max file size (default 100 MiB) and max concurrent transfers (default 3),
  then asks the user (`file-offer` event, `accept_file_offer` /
  `reject_file_offer` commands). Accepted transfers pull chunks with
  `FileChunkRequest` (4 in flight, 4 attempts per chunk), verify each chunk,
  reassemble, check the SHA-256 and save to the Downloads folder (fallback:
  profile storage) without overwriting. Stalled, expired or failed transfers
  are cleaned up. Progress and results are shown in the UI (`file-progress`,
  `file-received`, `file-sent`, `file-transfer-failed`); received files open
  via `open_received_file` (executables are only revealed in their folder).
  New wire messages: `FileOffer`, `FileChunkRequest`, `FileFinished` and
  their responses. The legacy whole-file `File` request is now refused.
  `send_file` takes the file as a raw IPC body instead of a JSON array.
- Atomic database migration framework with versioned schema
  (`CURRENT_DB_VERSION = 1`)
- Onboarding wizard with password-protected profile creation and backup warning
- Network status indicator (online/connecting/offline)
- Message delivery status indicators (sending/sent/failed)
- Peer list persistence across restarts (`~/.alterchat/known_peers.json`)
- `ALTERCHAT_BOOTSTRAP` env var for custom bootstrap nodes
- X3DH unit tests and migration idempotency tests
- CI matrix expanded to ubuntu-22.04, windows-latest, macos-latest
- `cargo audit` and `npm audit` in CI
