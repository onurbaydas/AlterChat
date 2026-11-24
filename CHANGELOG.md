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
- **Signed room messages (breaking wire format).** Each group-room message now
  carries the author's protobuf-encoded libp2p Ed25519 public key and a
  signature over `(room_id, msg_id, peer_id, nick, text, timestamp, ttl)`.
  The receiver checks the signature against the current CRDT values and
  requires `peer_id == PeerId(pubkey)`; failing messages are shown with an
  "UNVERIFIED" marker instead of being trusted. Gossipsub stays anonymous.
- **Incremental room sync.** Only the new Automerge change is published per
  message (encrypted with the room key, padded), instead of the whole
  document, which broke past gossipsub's 64 KiB limit. New
  `RoomSyncRequest { room_tag, heads }` / `RoomSyncResponse { payload, more }`
  request-response messages let new or out-of-date peers catch up in chunks
  of at most 512 KiB (sent every 30 s, on connect, on join, and when a gossip
  change arrives with missing dependencies). Inputs are size-bounded
  (16 KiB text, 48 KiB per change, 64 heads) and malformed data is rejected
  without touching the stored document. Old whole-document payloads are no
  longer accepted on the wire; old local room files still load and their
  messages are shown as unverified. Each message is one Automerge op (a
  bincode record under `m/<msg_id>`), because Automerge 0.9's per-op cost
  grows with document size.

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
