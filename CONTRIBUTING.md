# Contributing to AlterChat

Thank you for helping improve AlterChat. This repository is small enough to move
quickly, but security-sensitive enough that every change needs clear reasoning.

## Ground Rules

- Keep AlterChat local-first and peer-to-peer.
- Do not introduce a required central service.
- Treat every peer payload as hostile input.
- Put security enforcement in Rust, not only in the React UI.
- Update documentation when behavior, commands, storage, or threat assumptions
  change.
- Keep pull requests focused and reviewable.

## Development Setup

Requirements:

- Rust 1.95+
- Node.js 20+
- npm
- Tauri v2 platform prerequisites

Install and check:

```bash
git clone https://github.com/onurbaydas/AlterChat.git
cd AlterChat
rustup update stable
cargo check --workspace
```

Run the desktop app:

```bash
cd alterchat-ui
npm install
npm run tauri dev
```

## Branch Workflow

```bash
git checkout -b feature/short-description
```

Before opening a PR:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

Frontend:

```bash
cd alterchat-ui
npm install
npm run build
```

If a check cannot be run, explain why in the PR.

## PR Expectations

Every PR should include:

- what changed
- why it changed
- how it was tested
- risk level
- screenshots for UI changes
- migration notes for database or serialized-state changes
- threat-model notes for crypto, networking, storage, or IPC changes

## Security-Sensitive Areas

Request extra review for changes touching:

- `alterchat-core/src/crypto.rs`
- `alterchat-core/src/double_ratchet.rs`
- `alterchat-core/src/x3dh.rs`
- `alterchat-core/src/secure_storage.rs`
- `alterchat-core/src/network.rs`
- `alterchat-core/src/onion.rs`
- `alterchat-core/src/governance.rs`
- `alterchat-ui/src-tauri/src/db.rs`
- `alterchat-ui/src-tauri/src/lib.rs`
- `alterchat-ui/src-tauri/src/commands/`
- Tauri config or capabilities
- GitHub workflows

## Testing Guidance

For narrow changes, unit tests are enough. For shared behavior, add integration
coverage. For protocol changes, include round-trip tests and failure tests.

Useful test shapes:

- wrong password fails to open encrypted material
- malformed peer payload is rejected
- old ratchet state can still be loaded or migrated
- invite expiry and revocation are enforced
- room permission checks reject unauthorized actions
- file chunk tampering is detected
- UI commands fail cleanly when not logged in

## Documentation Changes

Update Markdown files when:

- a command changes
- a setting is added or removed
- a security claim changes
- a database table or serialized format changes
- a feature moves from experimental to supported
- a threat or limitation becomes known

## Commit Style

Use short, direct commit messages:

```text
docs: clarify x3dh limitations
core: add ratchet replay test
ui: expose safety number error state
```

## Reporting Vulnerabilities

Do not open public issues for exploitable vulnerabilities. Follow
[SECURITY.md](SECURITY.md).
