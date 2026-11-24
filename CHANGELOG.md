# Changelog

All notable changes to AlterChat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Direct messages now use X3DH + ML-KEM-768 and the Double Ratchet
  (breaking wire change).** Before this, sessions started from a static
  X25519 DH, and prekey secrets were thrown away.
  - Whoever sends first fetches the peer's prekey bundle (new
    `GetPrekeyBundle` request, DHT record as fallback) and runs the handshake.
  - Bundle signatures are verified against the Ed25519 key embedded in the
    peer id, and the signatures now also cover the X3DH identity key and a
    timestamp.
  - Signed-prekey and ML-KEM decapsulation secrets are stored in the SQLCipher
    DB (schema v3). The newest three are kept, with weekly rotation.
  - Either side can send first. Simultaneous initiation is resolved by keeping
    the lower peer id's session; the other side re-encrypts its pending
    messages on it.
  - Every DM stays in an encrypted outbox until the recipient acknowledges it.
    If it never is, a `dm-delivery-failed` event fires after 7 days.
  - The X3DH identity key is derived from the Ed25519 seed with HKDF (domain
    separated) instead of reusing the seed as an X25519 scalar.
  - Ratchet headers are now authenticated, and a forged message can no longer
    desynchronise a session.
  - Legacy static-DH `dr:` sessions are dropped by the migration.
- **Offline mailbox rebuilt.** Mailbox entries are now Double Ratchet messages
  (forward secrecy preserved), stored in one record per (recipient, sender),
  signed with the sender's Ed25519 identity. They are accepted only from
  non-blocked friends and deduplicated by message id in the DB. AlterChat DHT
  server nodes reject forged overwrites and rollbacks of mailbox records.
  Before this, records were encrypted to the static key, the sender id was
  unauthenticated, dedup never matched, and anyone could overwrite the single
  per-recipient record.
- Onion-routed DMs were silently dropped at the final hop (only the legacy
  `RatchetPrivateMessage` was handled). The final hop now dispatches
  `X3dhDm` through the normal DM path. Routes use up to two randomly chosen
  relay friends instead of one chosen by `timestamp % n`.
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
