# libp2p Community Tor Transport

This directory contains the vendored `libp2p-community-tor` transport used by
AlterChat to experiment with Tor-backed libp2p connections.

The crate originates from the community `libp2p-tor` work and is built on top of
Arti. It allows libp2p to dial TCP listeners through the Tor network.

## Why It Is Vendored Here

AlterChat needs a reviewable Tor transport path while its networking model is
still evolving. Vendoring the crate makes it easier to audit changes together
with the rest of the repository and to keep protocol experiments reproducible.

## Important Misuse Warning

Tor transport does not automatically make a libp2p application anonymous.

Privacy can still be lost through:

- libp2p Identify data
- stable peer IDs
- DHT records
- application-level metadata
- bootstrap choices
- timing and traffic volume
- direct transports enabled at the same time

Use this transport only after reviewing what the application reveals above the
transport layer.

## Minimal Example

```rust
use libp2p::core::Transport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let address = "/dns/www.torproject.org/tcp/443".parse()?;
    let mut transport = libp2p_community_tor::TorTransport::bootstrapped().await?;
    let _conn = transport.dial(address)?.await?;
    Ok(())
}
```

## Runtime Notes

- Uses Tokio.
- Uses rustls-compatible Arti runtime components.
- Tor bootstrap can be slow and should be surfaced clearly in UI/CLI flows.
- A Tor path should be paired with careful application-layer privacy review.

## AlterChat Integration Notes

`alterchat-core/src/network.rs` creates a Tor transport when
`NetworkPrivacyConfig.proxy_mode` is `Tor`. The transport is upgraded through
libp2p and authenticated with Noise before Yamux multiplexing.

Before treating Tor mode as a strong privacy guarantee, audit:

- whether Identify should be disabled or minimized
- which DHT records are published
- whether direct listeners remain enabled
- how bootstrap nodes are selected
- whether peer IDs should be rotated for specific use cases

## License

This vendored crate keeps its original MIT license. AlterChat as a whole is
licensed under AGPL-3.0; see the repository root for details.
