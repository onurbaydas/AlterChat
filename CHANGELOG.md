# Changelog

All notable changes to AlterChat will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (supply chain)

- SPDX software bill of materials attached to every release and covered by
  `SHA256SUMS` and the build-provenance attestation.
- Weekly libFuzzer runs of the network parsers (`fuzz.yml`), line coverage
  report (`coverage.yml`) and dependency review on pull requests.

### Changed (supply chain)

- All GitHub Actions pinned to commit SHAs and Docker base images pinned to
  digests (Dependabot keeps them current); workflow tokens are read-only by
  default.

### Changed (dependencies)

- libp2p 0.56 -> 0.57.1 (gossipsub 0.50, kad 0.49, identity 0.3,
  hickory-dns 0.26) in the core and the bootstrap node (issue #34).
- arti-client / tor-rtcompat 0.24 -> 0.48 in the vendored Tor transport; the
  transport installs the aws-lc-rs rustls provider if none is set. rusqlite
  0.32 -> 0.40 (SQLCipher bundled), the newest version arti allows
  (issue #35).
- ed25519-dalek / x25519-dalek 2 -> 3 (curve25519-dalek 5, rand_core 0.10)
  (issue #36).

### Security (dependencies)

- Fixed by the upgrades above: hickory-proto/-resolver DNS advisories,
  RUSTSEC-2026-0534 (gossipsub PRUNE backoff), RUSTSEC-2025-0009 (ring 0.16).
  Still ignored with reasons in `.cargo/audit.toml`: RUSTSEC-2026-0459,
  RUSTSEC-2023-0071, RUSTSEC-2026-0387.

## [0.1.0] - 2026-11-25

First public release.

### Added (project infrastructure)

- Browser live demo on GitHub Pages: the real interface running against a
  simulated in-browser network.
- CodeQL (Rust, TypeScript, Actions) and OpenSSF Scorecard scans; working
  `cargo audit` job.
- Bootstrap node Docker image on `ghcr.io/onurbaydas/alterchat-bootstrap`
  (`:edge` from main, `:X.Y.Z`/`:latest` from releases).
- Release workflow refuses tags that do not match the app version.
- Issue forms (Turkish/English), CODEOWNERS, SUPPORT.md, grouped Dependabot
  updates, stale-issue automation, categorised release notes.
- Universal macOS build, SHA256SUMS for every release asset, signed build
  provenance, `scripts/bump_version.py`.

### Fixed (0.1.0)

- Room messages were filed under the room that was open at login; they now go
  to the currently joined room.
- Trust graph showed no edges (it expected JSON strings, the backend returns
  objects).
- Debug builds no longer generate full debug info for dependencies
  (`target/debug` went from ~38 GB to a few GB); release binaries are stripped.

### Security (0.1.0)

- Lockfile refresh fixes 27 RustSec advisories (h2, tokio, zstd-safe, cookie,
  crossbeam-epoch, anyhow, rustix, …). Remaining advisories need the libp2p
  0.57 and arti upgrades and are listed with reasons in `.cargo/audit.toml`
  (issues #34, #35).

### Added (distribution)

- In-app auto-update: the app checks GitHub Releases on startup and offers
  signed updates (Turkish/English prompt). Updates are verified against the
  public key in `tauri.conf.json`. The release workflow signs updater
  artifacts and publishes `latest.json`. See RELEASING.md.
- Per-user Windows installer (no admin), Turkish/English, embedded WebView2
  bootstrapper; AlterChat icon; "rat bunker" theme; Turkish/English
  onboarding with nickname, invite link and temporary-session button.
- Network badge shows direct vs relayed connectivity.
- `bootstrap/install.sh`: one-command systemd install; detects the server's
  public IP and sets `ALTERCHAT_EXTERNAL_ADDRS` so the relay works behind
  cloud 1:1 NAT.

### Added

- **Internet connectivity behind NAT through circuit relay v2.**
  - With `relay_fallback_enabled` on (now the default for new profiles),
    clients reserve circuits on up to two relays, bootstrap nodes first.
  - Relayed addresses are published in a signed `PeerRecord` DHT record
    (`/alterchat/addr/1/<peer id>`), validated by DHT record filtering.
  - Friends that are not connected are looked up and dialed on their direct
    and relayed addresses at the same time. DCUtR results are logged.
  - Kademlia now stays in client mode unless DHT server mode is enabled, so
    a relayed address no longer flips a node into DHT server mode.
- Tor mode: relay circuits through Tor, so two Tor users can reach each other
  through a relay. Tor and SOCKS5 users reserve a circuit on the bootstrap
  relay so they are reachable. Hole punching is off in proxy modes.
- `network-reachability` UI event (`direct` / `relayed` / `unreachable`).
  `network-status` now follows the actual connection state
  (`online` / `connecting` / `offline`).
- Bootstrap node: `ALTERCHAT_EXTERNAL_ADDRS`. It also confirms public listen
  addresses and addresses that two peers observed, because relay reservations
  without a relay address are rejected by clients.

### Fixed

- In SOCKS5/I2P mode, a dial that fails because the proxy is down now raises
  `session-error`, throttled to once every 5 minutes, instead of failing
  silently. Tor mode reports repeated dial failures the same way. When every
  connection is lost, bootstrap nodes are re-dialed every 30 seconds.
- The Tor transport no longer accepts relay circuit addresses: it used to dial
  them as plain connections to the relay.
- At session start, known peers are dialed from the profile that is being
  opened, not from the previous one.

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

- SOCKS5 proxy transport (`alterchat-core/src/socks5.rs`). In SOCKS5 mode,
  TCP multiaddrs (`/ip4`, `/ip6`, `/dns*`, `/onion3`) are dialed through the
  configured proxy with remote DNS (host names are sent to the proxy, never
  resolved locally) and optional `user:pass@host:port` authentication. The
  mode is outbound only: no direct TCP, QUIC, listeners, mDNS, relay server,
  or hole punching. Relay-client circuits still work on top of it. A missing,
  invalid, or unreachable proxy fails session start with a clear error, and
  there is no direct fallback.
- Experimental I2P mode: the SOCKS5 transport pointed at the I2P router's SOCKS
  proxy (default `127.0.0.1:4447`). It only dials `.i2p` host names; see the
  README for its limitations.

- **Sandboxed WASM plugin execution.** `PluginHost::run_plugin` now runs
  plugins in a `wasmi` interpreter. Each run verifies the manifest signature
  and WASM hash first. Limits: a fuel budget (10M instructions by default) and
  a memory cap (16 pages by default, enforced on growth). There is no WASI and
  no start function. Host functions are linked only for capabilities that are
  both requested in the signed manifest and granted by the user. Any other
  import is refused before instantiation. Every guest pointer and length is
  bounds-checked and size-capped. A new `Notify` capability was added. The new
  Tauri command `run_plugin` executes on a blocking thread, using the
  enabled flag and grants stored in the DB. See `docs/PLUGINS.md`.
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
