# Releasing AlterChat

Releases are built by GitHub Actions (`.github/workflows/release.yml`) when a
version tag is pushed. Nothing has to be compiled locally.

## One-time setup

1. **Updater signing key.** Installed apps only accept updates signed with the
   key whose public half is in `alterchat-ui/src-tauri/tauri.conf.json`
   (`plugins.updater.pubkey`). Store the private key and its password as
   repository secrets:

   ```bash
   gh secret set TAURI_SIGNING_PRIVATE_KEY < ~/.tauri/alterchat-updater.key
   gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD < ~/.tauri/alterchat-updater.password
   ```

   Keep an offline backup of both files. If the private key is lost, existing
   installs can no longer be updated automatically and users must reinstall
   manually once with a build that carries a new public key.

2. **Public releases.** The updater downloads
   `https://github.com/onurbaydas/AlterChat/releases/latest/download/latest.json`.
   Release assets of a private repository are not publicly downloadable, so
   the repository must be public for auto-update to work.

3. **Code signing (optional).** Without an Authenticode certificate Windows
   SmartScreen shows "unknown publisher". See [SIGNING.md](SIGNING.md).

## Cutting a release

1. Set the version everywhere at once (package.json, package-lock.json,
   tauri.conf.json, src-tauri/Cargo.toml, and a new CHANGELOG section):

   ```bash
   python scripts/bump_version.py 0.1.1
   ```

   Edit the new CHANGELOG section if needed.
2. Commit, then tag and push:

   ```bash
   git commit -am "Release v0.1.1"
   git tag v0.1.1
   git push origin main v0.1.1
   ```

   The release workflow first checks that the tag matches all version fields
   and stops if they differ.
3. The workflow builds Windows (NSIS/MSI), a universal macOS DMG and Linux
   (AppImage/deb/rpm) bundles, signs the updater artifacts, publishes the
   release with `latest.json`, attaches the bootstrap binary, pushes
   `ghcr.io/onurbaydas/alterchat-bootstrap:<version>` and `:latest`, and
   finally uploads `SHA256SUMS` for every asset plus a signed build-provenance
   attestation (`gh attestation verify <file> -R onurbaydas/AlterChat`).
4. Running apps see the update on their next start and offer to install it.

## Building an installer locally

Because update artifacts are signed, a local `tauri build` needs the key:

```powershell
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content -Raw ~/.tauri/alterchat-updater.key
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = Get-Content -Raw ~/.tauri/alterchat-updater.password
cd alterchat-ui
npm run tauri build -- --bundles nsis
```

The installer is written to `target/release/bundle/nsis/`.
