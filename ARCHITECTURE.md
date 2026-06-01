# AlterChat Architecture & Topology

AlterChat is designed as a hybrid messaging and P2P communication platform.

## 1. Network Topology (Layer 1)
- **Direct Peering:** AlterChat attempts to establish direct TCP/QUIC connections using ICE/STUN for NAT traversal.
- **Relay Fallback:** If direct connection fails (symmetric NATs), communication is routed through community relay nodes.

## 2. Cryptographic Topology (Layer 2)
- **Identity:** An AlterChat identity is an Ed25519 keypair. The public key is hashed to create the Peer ID.
- **Asynchronous Messaging:** 
  - Messages for offline peers are stored in the Kademlia DHT using the peer's public key as the routing key.
  - Senders encrypt the message using the receiver's X3DH Pre-Key Bundle fetched from the DHT.

## 3. Application Topology (Layer 3)
- **Desktop Client:** A React/TypeScript frontend running inside a Tauri Webview.
- **Core Engine:** A Rust backend running a dedicated Tokio async runtime, managing SQLite state, and Kademlia routing.
- **WebRTC Signaling:** WebRTC offers are encrypted and sent as standard AlterChat messages via libp2p. Once received, the peers establish an RTCPeerConnection for low-latency A/V streams.
