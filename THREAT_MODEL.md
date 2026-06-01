# AlterChat Threat Model & Mitigation Strategy

AlterChat prioritizes metadata resistance and perfect forward secrecy. Since there is no central server, traditional client-server attack vectors do not apply.

## 1. Network Level Threats

### 1.1 Traffic Analysis (ISP / DPI)
**Threat:** An ISP monitors traffic patterns to deduce when a user is active or communicating with a specific IP.
**Mitigation:** 
- **Chaff Traffic:** Generates dummy messages at randomized intervals. The payloads are padded to a constant length (e.g., 512 bytes) so that an observer cannot distinguish a chat message from background noise.
- **Onion Routing (Multi-Hop):** To prevent an ISP from knowing the final destination, traffic can be routed through an intermediary node (Manifesto VI).

### 1.2 Sybil & Eclipse Attacks
**Threat:** Attackers flood the DHT with malicious nodes to prevent offline message retrieval.
**Mitigation:**
- Messages are replicated to the `k` closest peers.
- PoW integration ensures that spawning thousands of DHT nodes is computationally infeasible.

## 2. Cryptographic Threats

### 2.1 Key Compromise (Device Seizure)
**Threat:** An adversary gains physical access to the device and extracts the private key.
**Mitigation:**
- **Double Ratchet Algorithm:** ensures that even if a key is compromised today, past messages cannot be decrypted (Perfect Forward Secrecy), and future messages will be secure once the ratchet advances (Post-Compromise Security).
- **Amnesic Mode:** For extreme threat models, AlterChat can run completely in RAM without writing to disk.

### 2.2 Quantum Cryptanalysis
**Threat:** A future quantum computer breaks X25519 or Ed25519 keys via Shor's algorithm (Harvest Now, Decrypt Later).
**Mitigation:**
- Currently not mitigated (Layer 1 relies on classic elliptic curves). Future transitions to ML-KEM (Kyber) are planned.

## 3. Social & Spam Threats

### 3.1 Network Spam
**Threat:** A malicious user sends millions of direct messages to random peers.
**Mitigation:**
- **Proof-of-Work (PoW):** If the sender is not in the receiver's local trust list, the receiver drops the message unless it contains a valid Argon2id hash demonstrating 5 seconds of CPU work. 
- **Auto-Ban:** 3 invalid PoW attempts result in a permanent network-level IP/PeerID ban.
