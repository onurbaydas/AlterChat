# AlterChat Security Audit Preparation

## Scope

List the exact modules/files an auditor should focus on:

- `alterchat-core/src/x3dh.rs` (X3DH implementation)
- `alterchat-core/src/double_ratchet.rs` (Double Ratchet)
- `alterchat-core/src/crypto.rs` (X25519, safety numbers)
- `alterchat-core/src/onion.rs` (onion packet format)
- `alterchat-ui/src-tauri/src/db.rs` (SQLCipher encryption, migrations)
- `alterchat-core/src/governance.rs` (invite tokens, role system)

## Known Issues (Pre-Audit)

List what we already know needs attention:

- X3DH prekey lifecycle: OPK tracking implemented in DB migration 2 but not enforced at call sites
- Gossipsub rooms: no per-room E2EE (documented)
- Pluggable transports: not wired to transport layer
- Panic wipe: best-effort only on SSDs

Additional known gaps identified in the threat model:

- Multiple DM encryption paths exist simultaneously; canonical protocol selection is not yet finalized
- Double Ratchet state migration and versioning are incomplete
- Production CSP is absent (`csp: null` in current Tauri config)
- `unwrap()` calls remain in production message-handling paths
- DHT security-critical records are not all signed or freshness-bounded
- Invite revocation synchronization across peers is not robust
- Tauri command allowlist and capabilities have not been formally reviewed
- Tor/I2P routing is not fully implemented despite being referenced in privacy modes

## Questions for Auditor

- Is the X3DH + ML-KEM-768 hybrid construction sound? Are the KDF inputs correct?
- Is the Double Ratchet header encryption sufficient?
- Are there any side-channel attacks in the crypto operations?
- Is the SQLCipher key derivation (Argon2id + AES-256-GCM) correctly implemented?
- Is the onion packet format resistant to traffic analysis?
- Are skipped-message key bounds (`MAX_SKIP`) appropriate, and is key deletion after use verified?
- Does the sealed-sender envelope scheme prevent sender correlation by the server or relay?
- Are invite tokens fully resistant to replay and forgery under the current signing scheme?
- Is the Tauri IPC surface free of privilege-escalation or TOCTOU vulnerabilities?
- Are any `unwrap()` or `expect()` calls in network-facing deserialization paths reachable by a remote adversary?

## Audit Deliverables Requested

- Cryptographic design review
- Code-level vulnerability assessment
- Threat model validation
- Remediation recommendations

## How to Build and Run Tests

```
cargo test --all-features
cargo +nightly fuzz run fuzz_p2p_request -- -max_total_time=300
```

Additional recommended test coverage noted in the threat model:

```
# Two-node DM integration test (first message, reply, offline state, restart)
# Ratchet replay and out-of-order message tests against serialized state
# Invite expiry, max-use, and revocation tests
# SQLCipher profile open with wrong password
# Panic wipe path test in a temporary directory
```

## Threat Model Reference

The full threat model is in `THREAT_MODEL.md`. The audit priorities listed there are:

1. Key derivation and profile unlock path
2. X3DH + ML-KEM integration and prekey lifecycle
3. Double Ratchet serialization, skipped-key handling, and migration
4. Tauri IPC command surface and CSP
5. Inbound request-response deserialization and size limits
6. SQLite schema migrations and SQLCipher settings
7. Panic wipe semantics and user-facing wording
8. WebRTC media E2EE degradation behavior
9. Tor transport usage and identity leakage
10. Plugin execution model

## Security Boundaries Summary

Trusted within scope of this audit:

- Local OS and user session
- Rust standard library and selected dependencies
- Tauri backend command definitions
- User-entered password while the session is active

Untrusted (all must be treated as adversarial input):

- All peer messages
- DHT records
- Gossipsub room bytes
- File metadata from peers
- Plugin manifests and events
- WebRTC signaling payloads
- Bootstrap-node responses
- UI text received from other users

## Disclosure

Report vulnerabilities privately per the process in `SECURITY.md`. Do not open public issues for security findings.
