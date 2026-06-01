# AlterChat Bootstrap Node

A bootstrap node acts as the first contact point for new peers joining the AlterChat network.
It does not store messages or user data — it only answers DHT queries, helping new nodes
discover other peers. Anyone can run one.

---

## How to Run an AlterChat Bootstrap Node

The `alterchat-bootstrap` crate is a standalone binary that listens on a configurable port,
participates in Kademlia DHT, and reports its multiaddr so you can share it with the community.

### Build from source

```bash
git clone https://github.com/your-org/alterchat
cd alterchat
cargo build --release --package alterchat-bootstrap
./target/release/alterchat-bootstrap
```

On first start the node generates a persistent Ed25519 keypair and writes it to
`$ALTERCHAT_DATA_DIR/peer_id` (defaults to `/var/lib/alterchat-bootstrap`).
The peer ID is stable across restarts.

After startup the node prints its full multiaddr, for example:

```
INFO  alterchat_bootstrap: Listening on /ip4/0.0.0.0/tcp/4001/p2p/12D3KooWExamplePeerIdXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Copy that multiaddr — you will need it when submitting your node to the community list.

---

## Docker Run

```bash
docker run -d \
  --name alterchat-bootstrap \
  --restart unless-stopped \
  -p 4001:4001/tcp \
  -p 4001:4001/udp \
  -v /var/lib/alterchat-bootstrap:/data \
  -e RUST_LOG=info \
  -e ALTERCHAT_DATA_DIR=/data \
  ghcr.io/your-org/alterchat-bootstrap:latest
```

To see the assigned peer ID and multiaddr:

```bash
docker logs alterchat-bootstrap 2>&1 | grep "Listening on"
```

---

## systemd Service

Create `/etc/systemd/system/alterchat-bootstrap.service`:

```ini
[Unit]
Description=AlterChat Bootstrap Node
After=network.target

[Service]
Type=simple
User=alterchat
Group=alterchat
Environment=RUST_LOG=info
Environment=ALTERCHAT_DATA_DIR=/var/lib/alterchat-bootstrap
Environment=ALTERCHAT_BOOTSTRAP_PORT=4001
ExecStart=/usr/local/bin/alterchat-bootstrap
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

Then enable and start it:

```bash
# Create a dedicated system user
sudo useradd -r -s /usr/sbin/nologin -d /var/lib/alterchat-bootstrap alterchat
sudo mkdir -p /var/lib/alterchat-bootstrap
sudo chown alterchat:alterchat /var/lib/alterchat-bootstrap

sudo systemctl daemon-reload
sudo systemctl enable --now alterchat-bootstrap
sudo journalctl -u alterchat-bootstrap -f
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `ALTERCHAT_BOOTSTRAP_PORT` | `4001` | TCP/UDP port the node listens on |
| `ALTERCHAT_DATA_DIR` | `/var/lib/alterchat-bootstrap` | Directory for the persistent keypair and state |
| `RUST_LOG` | `info` | Log verbosity (`error`, `warn`, `info`, `debug`, `trace`) |
| `ALTERCHAT_BOOTSTRAP` | _(empty)_ | Comma-separated multiaddrs to dial on startup (peer with known nodes) |

The port can also be passed as the first positional argument:

```bash
alterchat-bootstrap 4001
```

---

## Submitting Your Node to the Community List

Bootstrap nodes are listed in
`alterchat-core/src/network.rs` inside the `COMMUNITY_BOOTSTRAP_ADDRS` constant:

```rust
pub const COMMUNITY_BOOTSTRAP_ADDRS: &[&str] = &[
    "/ip4/<YOUR_IP>/tcp/4001/p2p/<YOUR_PEER_ID>",
    // ...
];
```

To add your node:

1. Make sure your node has been running stably for at least 48 hours.
2. Ensure port 4001 is reachable from the public internet (check with
   `nc -zv <YOUR_IP> 4001` from an external host).
3. Fork the repository and open a pull request that adds your multiaddr to
   `COMMUNITY_BOOTSTRAP_ADDRS` in `alterchat-core/src/network.rs`.
4. In the PR description include:
   - Your multiaddr (e.g. `/ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...`)
   - The region/country where the node is hosted
   - Expected uptime commitment
5. A maintainer will verify reachability before merging.

---

## Security Considerations

**Network exposure**

- Open port 4001 in your firewall for TCP and UDP only. Do not expose any management
  interfaces to the internet.
- If you run the node behind NAT, configure port forwarding for both TCP and UDP on 4001
  so external peers can dial you directly.

**Process isolation**

- Run the binary as a dedicated unprivileged user (`alterchat`) with no login shell, as
  shown in the systemd example above.
- The process does not need filesystem access outside `ALTERCHAT_DATA_DIR`.

**Data stored on disk**

- The only file written to disk is the Ed25519 keypair (`peer_id`). This file controls
  your stable peer identity — back it up and keep it readable only by the service user:
  ```bash
  chmod 600 /var/lib/alterchat-bootstrap/peer_id
  ```
- No user messages or content are stored by a bootstrap node.

**Denial-of-service**

- Consider rate-limiting inbound connections at the firewall or with a tool such as
  `ufw limit 4001/tcp` to reduce the impact of connection floods.
- The Kademlia implementation enforces a per-peer connection limit; you do not need to
  tune this manually under normal load.

**Software updates**

- Subscribe to security advisories for the repository.
- Keep the binary up to date; update procedures are the same as the initial install
  (rebuild from source or pull a new Docker image tag).

**No trusted authority**

- Bootstrap nodes carry no special authority per Manifesto I. Compromising a bootstrap
  node does not let an attacker read messages, impersonate users, or modify content.
  The worst outcome is that new peers have difficulty finding their first contacts, which
  is recoverable once the node is taken offline and the community list is updated.
