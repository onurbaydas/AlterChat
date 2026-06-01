## Summary

<!-- What changed? Keep it concrete. -->

## Motivation

<!-- Why is this needed? What user, security, or maintenance problem does it solve? -->

## Type of Change

- [ ] Documentation only
- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] Security hardening
- [ ] Build, CI, or release

## Security Impact

<!-- Mention crypto, storage, IPC, networking, governance, or privacy impact. Write "None" only if you checked. -->

## Testing

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] `npm run build` from `alterchat-ui`
- [ ] Manual desktop test

Notes:

<!-- Include commands, OS, screenshots, logs, or why a check was not run. -->

## Documentation

- [ ] README or architecture docs updated
- [ ] Threat model updated
- [ ] Security notes updated
- [ ] Not needed

## Checklist

- [ ] I did not introduce a required central service.
- [ ] Peer input is validated or safely rejected.
- [ ] Rust backend enforces security-critical behavior.
- [ ] Database or serialized-state changes include migration notes.
- [ ] Secrets, tokens, database files, and private keys are not included.
