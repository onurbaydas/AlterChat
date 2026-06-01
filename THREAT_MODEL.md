# AlterChat Threat Model

AlterChat is a security-sensitive peer-to-peer communication project. This
document describes the assets, adversaries, implemented mitigations, current
limitations, and recommended hardening work.

It is written for contributors and auditors. It does not claim the project is
production-ready or independently audited.

## Security Goals

AlterChat aims to protect:

- message content
- long-term identity keys
- local profile data
- room state integrity
- direct-message session state
- peer trust decisions
- invite and role authority
- file contents and chunk integrity
- basic metadata such as peer relationships, timing, and requested resources

AlterChat does not currently claim to fully defeat a global passive adversary,
malware on the local device, or physical forensics against a compromised host.

## Assets

| Asset | Stored In | Why It Matters |
| --- | --- | --- |
| libp2p Ed25519 keypair | encrypted keypair file or memory | peer identity and governance signing |
| offline X25519 secret | encrypted local file or memory | DM bootstrap, safety number, sealed envelope paths |
| SQLCipher profile database | `alterchat_<hash>.db` | messages, settings, room state, trust, plugin registry |
| CRDT room blobs | SQLite `rooms` table | shared room state |
| ratchet state blobs | SQLite `ratchet_states` table | forward secrecy and message ordering |
| room invites and grants | SQLite governance tables | room admission and permissions |
| file chunks | `alterchat_storage/<profile>` | encrypted local file data |
| vault exports | user-supplied export blob | portable profile metadata |
| DHT records | libp2p Kademlia | bootstrap data, prekeys, revocations, offline paths |

## Adversaries

### Local Network Observer

Can observe traffic on the same LAN, block packets, and attempt local discovery
attacks. mDNS intentionally exposes local peer presence for zero-config
discovery.

### Internet Service Provider or Censor

Can observe IP addresses, timing, packet sizes, and protocol fingerprints. Can
block obvious P2P traffic or known bootstrap nodes.

### Malicious Peer

Can send malformed protocol messages, spam rooms, attempt file-transfer abuse,
forge invites, replay old messages, or probe trust/rate-limit behavior.

### Sybil Operator

Can create many peer identities and attempt to pollute DHT routing, overwhelm
rooms, or surround a target with dishonest peers.

### Compromised Bootstrap Node

Can provide poor routing information, disappear, log inbound connection
attempts, or bias discovery. A bootstrap node should not be treated as an
authority.

### Malware on the User's Device

Can read process memory, intercept keystrokes, steal unlocked database contents,
or tamper with the UI. AlterChat cannot fully protect against active malware on
the host.

### Physical Attacker

Can copy disk data, attempt password guessing, inspect crash dumps, and recover
deleted data from storage layers. Panic wipe is best-effort and not guaranteed
forensic erasure.

## Implemented Mitigations

### Transport Encryption

libp2p Noise is used for transport-level encryption and peer authentication.
Yamux multiplexes streams over TCP paths. QUIC support is available through the
configured transport preference path.

Residual risk:

- transport encryption does not hide IP metadata by itself
- Identify can reveal peer information
- traffic timing and volume remain observable without additional privacy layers

### Local Profile Encryption

The Tauri backend opens SQLite databases with SQLCipher support by setting a
database key pragma. Keypair and vault helper functions use Argon2id plus
AES-256-GCM.

Residual risk:

- password strength is critical
- memory is not protected from a local privileged attacker
- operating-system caches, backups, and snapshots can retain data
- database migrations need explicit security tests

### Identity and Signatures

Ed25519 identities are used for libp2p peer identity and governance signatures.
Invite tokens, permission grants, trust edges, and revocation announcements are
signed and verified.

Residual risk:

- social verification of peer identity remains a user responsibility
- compromised signing keys can issue valid malicious governance artifacts
- revocation propagation depends on peers receiving and honoring records

### Direct Message Encryption

The repository contains:

- X25519 encrypt/decrypt helpers
- sealed-sender style envelopes
- symmetric ratchet state
- full Double Ratchet module
- X3DH + ML-KEM-768 shared secret path

Residual risk:

- multiple DM paths exist; canonical protocol selection is still needed
- state migration and versioning are not complete
- X3DH lifecycle and one-time prekey consumption need deeper integration
- all cryptographic protocol code requires external audit

### Room State Integrity

Rooms use Automerge CRDT state. State merges are deterministic, and room
governance checks are applied in the backend for key actions.

Residual risk:

- CRDT payloads from peers must be treated as untrusted input
- large room states can become a resource-exhaustion vector
- room membership is not the same as cryptographic confidentiality
- retention/TTL behavior is local and cannot force deletion on other peers

### Trust and Abuse Controls

The local database tracks:

- peer trust levels
- block/mute flags
- per-peer rate limits
- PoW requirement flags
- minimum trust thresholds for DMs, files, and invites

PoW primitives exist for tokens and challenge solutions.

Residual risk:

- local trust is not global reputation
- Sybil resistance is partial without network-wide admission policy
- proof-of-work difficulty must be tuned to device class and abuse patterns

### File Safety

File preparation chunks data into 256 KiB blocks, encrypts chunks with
AES-256-GCM, stores per-chunk hashes, and enforces local storage quotas.

Residual risk:

- filenames, sizes, and manifests can leak metadata
- file content scanning is not implemented
- malicious files can still be dangerous after the user opens them
- content retention is local and cannot force peers to delete received data

### Onion and Traffic Privacy Experiments

`onion.rs`, `traffic.rs`, and `pluggable.rs` provide:

- fixed-size onion packets
- chaff payload generation
- padding helpers
- random send delays
- obfs4-style obfuscation helpers
- snowflake-style framing helpers

Residual risk:

- these are not a complete anonymity network
- traffic-analysis resistance requires deployment, route selection, and
  measurement
- Tor usage through libp2p requires careful avoidance of identifying behavior
- I2P/SOCKS5 routing is not fully implemented

### Panic Wipe

The panic wipe path overwrites files with zeroes where possible, removes profile
paths, and exits the process.

Residual risk:

- SSD wear leveling can retain data
- journaling filesystems can retain old blocks
- backups and cloud sync can retain copies
- open file handles and memory pages are outside the guarantee

## Threats by Area

### Malformed Peer Messages

Threat:

A malicious peer sends malformed CBOR/bincode payloads, oversized packets, or
unexpected protocol variants to crash the node.

Mitigations:

- Rust type safety
- request-response enums for protocol messages
- many deserialization paths return errors and ignore bad input

Hardening needed:

- size limits for every inbound message type
- fuzz tests for `P2pRequest`, CRDT merge data, onion packets, and ratchet
  envelopes
- removal of panic-prone `unwrap()` paths from production message handling

### DHT Poisoning

Threat:

An attacker publishes false records, floods DHT keys, or attempts to hide valid
records.

Mitigations:

- record keys are deterministic and scoped
- signed governance records can be verified
- content payloads can be encrypted and hashed

Hardening needed:

- signatures on all security-critical DHT records
- sequence numbers and freshness windows where applicable
- DHT quorum and provider strategy review
- peer scoring or S/Kademlia-style routing-table hardening

### Invite Forgery and Replay

Threat:

An attacker forges an invite, replays an old invite, or continues using a
revoked invite.

Mitigations:

- invite tokens are signed
- expiry and max-use fields exist
- local invite state tracks revoked/use count
- distributed revocation command path exists

Hardening needed:

- robust global revocation synchronization
- replay tests across peers
- clearer UI state for revoked and expired invites

### Direct Message Key Compromise

Threat:

An attacker steals current ratchet state or long-term keys.

Mitigations:

- Double Ratchet design supports forward secrecy and post-compromise recovery
- old chain keys are advanced
- skipped-message keys are bounded by `MAX_SKIP`

Hardening needed:

- secure deletion of old serialized state
- canonical migration from the simple ratchet to the Double Ratchet
- X3DH prekey lifecycle
- session versioning and transcript tests

### Metadata Correlation

Threat:

A passive observer correlates timing, packet sizes, and endpoint addresses.

Mitigations:

- optional Tor transport path
- padding and chaff primitives
- random delay helpers
- onion packet experiments

Hardening needed:

- measured network privacy profiles
- route selection and relay admission policy
- avoiding Identify leaks in privacy modes
- production guidance for Tor/I2P use

### UI Injection

Threat:

Remote text or file metadata injects script/content into the Tauri webview.

Mitigations:

- React escapes text by default in normal rendering
- privileged actions go through Tauri commands

Hardening needed:

- production CSP; current Tauri config has `csp: null`
- review all uses of raw HTML or file rendering
- strict allowlist for Tauri commands and capabilities
- tests for untrusted message rendering

### Supply Chain Compromise

Threat:

Malicious Rust crate, npm package, build action, or vendored dependency affects
the release.

Mitigations:

- lockfiles are present
- vendored Tor adapter is included in the repository
- CI workflow exists

Hardening needed:

- dependency review policy
- `cargo audit` / `cargo deny`
- npm lockfile review
- reproducible release notes and signed builds

## Security Boundaries

### Trusted

- the local OS and user session
- Rust standard library and selected dependencies
- Tauri backend command definitions
- user-entered password while the session is active

### Untrusted

- all peer messages
- DHT records
- Gossipsub room bytes
- file metadata from peers
- plugin manifests and events
- WebRTC signaling payloads
- bootstrap-node responses
- UI text received from other users

## Audit Priorities

1. Key derivation and profile unlock path.
2. X3DH + ML-KEM integration and prekey lifecycle.
3. Double Ratchet serialization, skipped-key handling, and migration.
4. Tauri IPC command surface and CSP.
5. Inbound request-response deserialization and size limits.
6. SQLite schema migrations and SQLCipher settings.
7. Panic wipe semantics and user-facing wording.
8. WebRTC media E2EE degradation behavior.
9. Tor transport usage and identity leakage.
10. Plugin execution model.

## Recommended Security Tests

- Two-node local integration test for room merge.
- Two-node DM test with first message, reply, offline state, and restart.
- Ratchet replay and out-of-order message tests against serialized state.
- Fuzzing for onion packet deserialization.
- Fuzzing for CRDT merge input.
- Invite expiry, max-use, and revocation tests.
- SQLCipher profile open with wrong password.
- Panic wipe path tests in a temporary directory.
- CSP regression test for production Tauri builds.

## Disclosure

Please do not open public issues for vulnerabilities. Use the process in
[SECURITY.md](SECURITY.md).
