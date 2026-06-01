# Comprehensive Threat Model & Security Posture

AlterChat operates under the assumption that the network infrastructure (ISPs, routers, cloud providers) is completely compromised and actively hostile. We assume adversaries have global passive observation capabilities and can actively inject, drop, or delay packets.

## 1. Network Level Attacks

### 1.1. Sybil Attacks
**The Threat:** An attacker spins up thousands of malicious nodes on the Kademlia DHT to surround a target node, intercepting all search queries and blocking discovery.
**Mitigation:** AlterChat requires Proof-of-Work (Hashcash-style) to participate in the DHT routing table. To generate a valid Node ID, the client must compute a cryptographic puzzle that takes ~5 seconds on a modern CPU. Spinning up 10,000 nodes would require immense computational cost, making large-scale Sybil attacks economically unviable.

### 1.2. Eclipse Attacks
**The Threat:** An attacker controls all inbound and outbound connections to a specific user, completely isolating them from the honest network.
**Mitigation:** AlterChat nodes maintain persistent connections to highly trusted, hardcoded "Bootstrap Relays" (community run, non-logging). Even if the local ISP blocks all P2P discovery, the node will tunnel through the bootstrap relays using Tor Obfs4 bridges to re-enter the network.

### 1.3. Global Passive Observation (Metadata Harvesting)
**The Threat:** Agencies like the NSA/GCHQ monitor all internet backbones. Even if messages are encrypted, they can see *who* is talking to *whom* by correlating packet sizes and timing (Metadata).
**Mitigation:** 
1. **Traffic Padding:** AlterChat pads all outgoing packets to standard block sizes (e.g., 512 bytes, 1KB).
2. **Covert Traffic Emission:** The node constantly sends fake "cover traffic" to random DHT nodes. An observer cannot mathematically distinguish between a real message and a cover packet.
3. **Onion Routing Integration:** SOCKS5 integration with local Tor/I2P daemons allows AlterChat to route all WebRTC/TCP traffic through 3 hops of encryption, completely blinding the passive observer to the destination IP.

## 2. Cryptographic Attacks

### 2.1. Key Compromise (Device Theft)
**The Threat:** An adversary physically seizes the user's unlocked device or uses malware to extract the SQLite database and current cryptographic keys from memory.
**Mitigation (Forward Secrecy):** Because the Double Ratchet deletes old keys the millisecond they are used, the adversary cannot decrypt any past messages stored on the network or intercepted previously.
**Mitigation (Post-Compromise Security):** If the device is stolen but later recovered, the moment the user sends a new message to a contact, the Diffie-Hellman ratchet rotates the master key. The adversary's stolen keys instantly become useless for future messages.

### 2.2. Quantum Computing Threat (Shor's Algorithm)
**The Threat:** In 10-15 years, a Cryptographically Relevant Quantum Computer (CRQC) could break Ed25519 and X25519 using Shor's algorithm, allowing retroactive decryption of intercepted traffic.
**Mitigation (Current):** We currently use symmetric encryption (ChaCha20-Poly1305) for the message payload, which is heavily quantum-resistant (requires Grover's algorithm, effectively needing 256-bit keys which we already use).
**Mitigation (Roadmap):** The AlterChat v2.0 roadmap includes hybrid key exchange mechanisms (combining X25519 with Kyber-768 / FIPS 203) to ensure total quantum immunity.

## 3. Application Security (Tauri & OS)

### 3.1. Cross-Site Scripting (XSS) & RCE
**The Threat:** A malicious user sends a specially crafted message containing JavaScript that executes in the recipient's Tauri Webview, potentially reading local files.
**Mitigation:**
- Strict Content Security Policy (CSP): `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:;`
- Context Isolation is enforced. The React frontend has ZERO access to the `fs` (File System) or `net` modules. It can only call explicit `invoke("command_name")` endpoints exposed by Rust.

### 3.2. Local Database Extraction
**The Threat:** Malware on the host OS attempts to read the SQLite database containing message history.
**Mitigation:** The database is encrypted at rest using `SQLCipher` (AES-256-GCM). The key is derived using `Argon2id` from the user's master password, which is never stored on disk and only held in volatile RAM using Rust's `secrecy::SecretString` wrapper to prevent memory swapping to disk.
