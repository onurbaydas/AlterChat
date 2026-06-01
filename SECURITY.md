# Security Policy

AlterChat handles cryptography, local encrypted profiles, peer-to-peer network
messages, and desktop IPC. Please report security issues privately and give the
maintainers time to investigate before public disclosure.

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` branch | Yes |
| tagged pre-releases | Best effort |
| old commits or forks | No |

The project is currently alpha-stage software and has not completed an
independent security audit.

## What to Report Privately

Please use private reporting for:

- key extraction or profile decryption bugs
- SQLCipher/database unlock bypass
- message decryption, ratchet, X3DH, or sealed-sender failures
- signature verification bypasses
- invite, role, or trust-edge forgery
- remote crash or denial-of-service from malformed peer input
- Tauri IPC privilege escalation
- XSS or webview-to-native command abuse
- panic-wipe bypasses that leave expected files intact
- dependency or build-chain compromise

## Reporting Process

Use GitHub private vulnerability reporting if enabled for the repository. If it
is not available, contact the maintainer directly and avoid posting exploit
details in a public issue.

Please include:

- affected branch or commit
- operating system
- exact steps to reproduce
- expected impact
- proof-of-concept input if safe to share
- logs or screenshots with secrets removed
- whether the issue is actively exploited or only theoretical

## Handling Expectations

The maintainers will try to:

- acknowledge the report as soon as possible
- reproduce and classify the issue
- prepare a fix or mitigation
- credit the reporter if desired
- publish a security note after users have a reasonable update window

## Changelog — Security-Relevant Changes

- **v0.1.1 (DB migration 2):** OPK consumption tracking added. One-time prekeys
  (OPKs) are now recorded in the `used_opk_ids` table upon first use. Any
  subsequent X3DH handshake that presents the same OPK ID is rejected as a
  replay attack. See `db::mark_opk_used` and `db::is_opk_used` for the
  implementation, and the `// IMPORTANT` comment above `receive_x3dh` in
  `alterchat-core/src/x3dh.rs` for the required call-site checks.

## DM Protocol Canonical Path (v0.1.0+)

The canonical DM encryption path is **X3DH + ML-KEM-768 + Double Ratchet**
(variant: `X3dhHybridMessage` or equivalent in `P2pRequest`).

Legacy paths (`RatchetMessage`, `DoubleRatchetMessage`) are deprecated as of
v0.2.0 and will be removed in v0.3.0. New sessions MUST use the X3DH hybrid
path.

## Research Rules

Please do not:

- attack public bootstrap nodes or other users
- publish private keys, messages, databases, or tokens
- run destructive tests against someone else's machine
- use GitHub issues for exploitable details before a fix exists

Local testing against your own clone, temporary profiles, and isolated peers is
welcome.
