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

## Research Rules

Please do not:

- attack public bootstrap nodes or other users
- publish private keys, messages, databases, or tokens
- run destructive tests against someone else's machine
- use GitHub issues for exploitable details before a fix exists

Local testing against your own clone, temporary profiles, and isolated peers is
welcome.
