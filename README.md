<div align="center">
  <h1>بِسْمِ اللَّهِ الرَّحْمَنِ الرَّحِيمِ</h1>
  <h2>AlterChat</h2>
  <p><b>The Sovereign, Decentralized, Zero-Trust Communication Infrastructure</b></p>
  
  [![Rust](https://img.shields.io/badge/rust-v1.85.0-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
  [![Tauri](https://img.shields.io/badge/Tauri-v2-blue?style=flat-square&logo=tauri)](https://tauri.app/)
  [![React](https://img.shields.io/badge/React-v18-cyan?style=flat-square&logo=react)](https://reactjs.org/)
  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg?style=flat-square)](LICENSE)
</div>

---

## 📖 Comprehensive Overview

AlterChat is not just another messaging application; it is a **sovereign, peer-to-peer communication protocol** engineered from the ground up to eliminate central points of failure, metadata harvesting, and cryptographic obsolescence. Built with a monolithic yet highly concurrent Rust backend and a lightweight Tauri/React frontend, AlterChat ensures that your cryptographic keys, social graph, and message history never leave your local device unless explicitly encrypted and routed through an anonymizing network.

By completely stripping away the concept of "servers" and "accounts", AlterChat shifts the paradigm of digital communication back to its cypherpunk roots.

### 🌌 Core Philosophy
1. **Zero Trust, Zero Servers:** There is no central database. If the creators of AlterChat disappear tomorrow, the network will continue to operate flawlessly as long as two peers exist.
2. **Metadata is the Message:** In modern surveillance, who you talk to is as important as what you say. AlterChat utilizes Tor (Onion routing) and I2P integrations to obfuscate the origin, destination, and timing of packets.
3. **Cryptographic Supremacy:** We do not rely on standard TLS. We employ a custom Double Ratchet implementation coupled with X3DH (Extended Triple Diffie-Hellman) for perfect forward secrecy and post-compromise security.

---

## 🚀 Deep Technical Architecture

The architecture of AlterChat is split into two primary domains, bridged by highly optimized IPC (Inter-Process Communication).

### 1. The Headless Rust Core (`alterchat-core`)
The heart of the system is driven by a massive `tokio::select!` asynchronous event loop that handles thousands of concurrent multiplexed streams.

- **Libp2p Network Stack:** Uses Kademlia DHT for decentralized peer discovery, Gossipsub for pub/sub mechanisms (used in group chats and governance), and WebRTC/TCP transports.
- **Double Ratchet & X3DH:** Every single message rotates its cryptographic key. If an attacker compromises your device today, they cannot decrypt the messages you sent yesterday (Forward Secrecy), nor can they decrypt the messages you will send tomorrow once the ratchet turns (Post-Compromise Security).
- **Onion Routing & Pluggable Transports:** To bypass Deep Packet Inspection (DPI) and state-level firewalls, AlterChat implements Obfs4 and Snowflake pluggable transports natively.

### 2. The Tauri Presentation Layer (`alterchat-ui`)
A blazingly fast, memory-safe frontend that executes OS-level commands via strictly defined capability gates.
- **Strict Content Security Policy (CSP):** The React frontend is completely sandboxed. It cannot make outbound HTTP requests. All network IO is forced through the Rust core via `invoke()` IPC calls.
- **Local-First SQLite:** Your messages are stored locally in an encrypted SQLite database (using SQLCipher). The decryption key is derived from your master password using Argon2id.

```mermaid
graph TD
    subgraph UI [Tauri Webview (React/TS)]
        React[React Components] --> IPC[Tauri IPC Bridge]
    end

    subgraph Core [Rust Backend (tokio)]
        IPC --> FFI[Command Handler]
        FFI --> EventLoop[Main Event Loop]
        EventLoop --> DHT[Kademlia DHT]
        EventLoop --> Crypto[Double Ratchet Engine]
        EventLoop --> Storage[(Encrypted SQLite)]
    end

    subgraph Network [Global P2P Network]
        DHT <--> |Obfs4/Tor| Node2[Peer Node]
        DHT <--> |Noise Protocol| Node3[Peer Node]
    end
```

---

## 💻 Installation & Compilation Guide

Because AlterChat is deeply integrated with the OS for secure storage and network operations, compiling from source is the recommended approach for developers and security auditors.

### System Prerequisites
Ensure you have the following toolchains installed:
1. **Rust (latest stable):** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
2. **Node.js (v20+):** Required for the React frontend build pipeline.
3. **OS-Specific Dependencies:**
   - **Debian/Ubuntu:** `sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file libssl-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev`
   - **macOS:** Xcode Command Line Tools (`xcode-select --install`)
   - **Windows:** Visual Studio C++ Build Tools.

### Build Instructions

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/onurbaydas/AlterChat.git
   cd AlterChat
   ```

2. **Initialize the Frontend:**
   Navigate into the UI directory and install the TypeScript dependencies.
   ```bash
   cd alterchat-ui
   npm install
   ```

3. **Development Mode (Hot-Reloading):**
   To run the app with live-reloading (React + Rust), use the Tauri CLI:
   ```bash
   npm run tauri dev
   ```
   *Note: In development mode, the SQLite database is stored in a temporary `./.dev_data` folder and the Kademlia DHT will connect to local bootstrap nodes if available.*

4. **Production Build:**
   To compile a highly optimized, stripped binary for release:
   ```bash
   npm run tauri build
   ```
   The compiled `.exe`, `.dmg`, or `.AppImage` will be located in `src-tauri/target/release/bundle/`.

---

## 🛠 Usage & Operational Guide

### Bootstrapping the Node
When you first launch AlterChat, you do not "create an account". Instead, the application generates a cryptographic Ed25519 keypair. The public key becomes your "Identity" (your Address), and the private key is encrypted at rest.

The node will automatically attempt to join the global DHT via community-hosted bootstrap nodes. If standard internet is censored, navigate to **Settings -> Network** and enable **Obfs4 Bridge Mode**.

### Establishing a Secure Session
1. Share your Public Identity Hash (e.g., `alter1q8...`) with a peer out-of-band.
2. When you initiate a chat, AlterChat performs an asynchronous X3DH handshake using the DHT.
3. Once the PreKeys are exchanged, the session is established. Both nodes will begin advancing their local Double Ratchet chains.

### Advanced: Running a Bootstrap Node
To help the network survive, you can run the headless `alterchat-bootstrap` daemon on a VPS:
```bash
cd alterchat-bootstrap
cargo run --release -- --port 4001 --announce-ip <YOUR_PUBLIC_IP>
```

---

## 🤝 Development & Contribution Workflow

We strictly adhere to a **Security-First** contribution model. Please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for granular rules on PR submissions.

### Code Organization
- `alterchat-core/`: The headless Rust library. Contains all cryptography, P2P networking, and database logic.
- `alterchat-ui/`: The Tauri application. Contains `src-tauri` (the host) and `src` (the React webview).
- `alterchat-bootstrap/`: A lightweight discovery daemon for network resilience.

### Testing the Cryptography
All cryptographic state machines (Ratchet, X3DH) are covered by rigorous unit tests. Before submitting a PR, you MUST ensure tests pass:
```bash
cargo test --package alterchat-core --lib crypto
cargo clippy --all-targets --all-features -- -D warnings
```

---

## 🔐 Threat Model & Security Audits

For a terrifyingly detailed breakdown of how we mitigate Sybil attacks, Eclipse attacks, Metadata Analysis, and Quantum threats, please read the exhaustive [THREAT_MODEL.md](THREAT_MODEL.md) document.

---

## 🖤 Support & Donate
If you believe in decentralized, censorship-resistant communication and want to support the ongoing development of AlterChat, consider donating. Your support helps keep the network sovereign, private, and independent.

- **Monero (XMR):** `43bMdGQAkByAkbiGkgsuGbWf5afr2RBa42swxuqe7M8ohUSVbzaFAQabDivDtLcXJwQDNztZyhMSoiFkSvsCNouV2jACZyA` _(Privacy focused)_
- **Bitcoin (BTC):** `bc1q66wc9qq5w5k219ayv9mgm9jc3dkan757a7ufst`
- **Ethereum (ETH / ERC-20):** `0xC47BDDc11F70eb48f3c261186BdAA5A16E4448D0`
