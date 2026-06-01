# AlterChat Architecture & Protocol Specification

## 1. Introduction
This document serves as the absolute source of truth for the AlterChat protocol architecture. It details the intricate mechanisms by which AlterChat achieves zero-trust, metadata-resistant, perfectly forward-secret communication across a hostile global network.

## 2. The Monolithic Event Loop (`tokio::select!`)
Unlike traditional multi-threaded web servers that spawn a thread per request, an AlterChat node is a single unified asynchronous entity. The core of `alterchat-core` is driven by a massive `tokio::select!` loop inside `lib.rs`.

### Why a Single Loop?
In a P2P context, state mutation is extremely volatile. A network packet might arrive simultaneously as a user clicks "Send", both attempting to mutate the Double Ratchet state. By funneling all events (UI commands, DHT events, Swarm events, Timer events) into a single MPSC (Multi-Producer Single-Consumer) channel and processing them in one sequential `select!` block, we completely eliminate Race Conditions, Deadlocks, and the need for expensive `Arc<Mutex<T>>` locking across threads.

## 3. Cryptographic Pipeline

### 3.1. Identity Generation
Identities are not usernames. They are Ed25519 cryptographic keypairs.
- `Identity Key (IK)`: Long-term Ed25519 keypair. The public key IS your address.
- `Signed PreKey (SPK)`: Medium-term X25519 keypair, rotated every 7 days.
- `One-Time PreKeys (OPK)`: A pool of 100 ephemeral X25519 keys published to the DHT for asynchronous session initialization.

### 3.2. Extended Triple Diffie-Hellman (X3DH)
When Alice wants to message Bob, and Bob is offline:
1. Alice queries the Kademlia DHT for Bob's Identity Key.
2. Alice retrieves Bob's SPK and one OPK.
3. Alice performs 4 parallel Diffie-Hellman calculations (DH1, DH2, DH3, DH4) combining her keys with Bob's keys.
4. The output is fed into an HKDF (HMAC-based Extract-and-Expand Key Derivation Function) to produce a `SharedSecret`.
5. Alice sends an Initial Message containing her Ephemeral Key and the ciphertext to Bob's DHT address.

### 3.3. The Double Ratchet Algorithm
Once X3DH establishes the `SharedSecret`, the Double Ratchet takes over.
- **KDF Chain Ratchet:** Every single message sent or received hashes the previous key to create a new key. An attacker who steals your key right now cannot derive the previous keys (Forward Secrecy).
- **Diffie-Hellman Ratchet:** With every message, a new public key is attached. When the recipient replies, a new DH agreement is calculated, injecting new entropy into the KDF chain. If an attacker steals your key right now, the moment you exchange a new message, the attacker is locked out again (Post-Compromise Security).

## 4. Network Transport & Pluggable Obfuscation

AlterChat does not assume a neutral internet. It assumes the internet is hostile and monitored.

### 4.1. Base Transport (Noise + Yamux over TCP/WebRTC)
All connections are encrypted at the transport layer using the `Noise` protocol framework before any application data is sent. The stream is then multiplexed using `Yamux`, allowing thousands of logical streams over a single TCP connection.

### 4.2. Deep Packet Inspection (DPI) Resistance
State-level firewalls (like the Great Firewall) detect and block standard P2P traffic. AlterChat implements Pluggable Transports natively:
- **Obfs4:** Encrypts and scrambles the packet size and timing signatures, making the traffic look like pure white noise.
- **Snowflake:** Uses WebRTC to bounce traffic through temporary browser proxies volunteered by regular internet users, making it impossible to block without blocking the entire internet.

## 5. Storage & IPC Integration (Tauri)
Tauri serves purely as a "dumb terminal" presentation layer.
- The UI requests data via `invoke("send_message", { payload })`.
- Tauri serializes this to Rust. Rust pushes it to the MPSC channel.
- The `tokio` loop encrypts it, routes it via `libp2p`, and saves the ciphertext to SQLite.
- When an ACK is received, Rust triggers a `Window::emit` to push an event back to the React UI.
