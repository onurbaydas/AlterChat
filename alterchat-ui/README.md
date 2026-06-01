# AlterChat UI

AlterChat UI is the desktop client for AlterChat. It combines a React frontend
with a Tauri v2 Rust backend that owns profile storage, libp2p networking,
governance checks, file preparation, and security-sensitive IPC commands.

For the full project overview, see the [root README](../README.md).

## Stack

| Layer | Technology |
| --- | --- |
| Desktop shell | Tauri v2 |
| Frontend | React 19, TypeScript, Vite 7 |
| Backend | Rust 2021 crate under `src-tauri` |
| Local database | `rusqlite` with bundled SQLCipher |
| P2P core | `alterchat-core` |
| Media | Browser WebRTC APIs with optional insertable-stream E2EE path |

## Directory Map

```text
alterchat-ui/
├─ src/
│  ├─ App.tsx                 main application shell
│  ├─ types.ts                shared UI types
│  ├─ webrtc.ts               media key derivation and transforms
│  ├─ components/
│  │  ├─ LoginScreen.tsx
│  │  ├─ PanicModal.tsx
│  │  ├─ SafetyNumbers.tsx
│  │  ├─ TrustGraph.tsx
│  │  └─ VaultExport.tsx
│  └─ index.css
├─ src-tauri/
│  ├─ src/lib.rs              backend event loop and app state
│  ├─ src/db.rs               SQLite schema and query helpers
│  ├─ src/commands/           Tauri command modules
│  ├─ capabilities/           Tauri capability config
│  └─ tauri.conf.json
└─ package.json
```

## Development

Requirements:

- Rust 1.95+
- Node.js 20+
- npm
- Tauri v2 system dependencies

Install dependencies:

```bash
npm install
```

Run the desktop app:

```bash
npm run tauri dev
```

Build only the web assets:

```bash
npm run build
```

Build a Tauri bundle:

```bash
npm run tauri build
```

## Backend Command Surface

The frontend communicates with Rust through explicit Tauri commands. Important
command groups:

- `auth`: login, amnesic mode, panic wipe, PoW solving
- `messaging`: send room messages, join channels, search
- `social`: friends, private messages, peer settings, saved groups
- `settings`: network/privacy/storage/media settings, safety numbers, vaults
- `governance`: invites, roles, permission grants, trust edges
- `media`: file send, file preparation, WebRTC signaling
- `storage`: file manifests, stored chunks, peer capabilities
- `plugin`: plugin manifest registry
- `system`: network and crypto capability summaries

Do not enforce critical policy only in React. The Rust command or backend event
loop must reject unauthorized actions.

## Local Data

Normal login creates profile-specific files derived from the password hash:

```text
alterchat_<prefix>.db
keypair_<prefix>.bin
alterchat_storage/<profile>/
```

Amnesic mode uses in-memory paths. Panic wipe removes active or all local
profiles on a best-effort basis.

## UI Security Notes

- Remote message text should be rendered as text, never trusted HTML.
- File names, peer names, group names, and invite JSON are untrusted input.
- The current Tauri config has `csp: null`; production packaging should define a
  strict CSP before release.
- WebRTC insertable streams may not be available in every runtime. The UI must
  make degraded media security states visible before high-risk use.

## Useful Checks

```bash
npm run build
cd ..
cargo check --workspace
cargo test --workspace
```

If Rust reports that `sysinfo` requires a newer compiler, update to Rust 1.95+
with `rustup update stable`.
