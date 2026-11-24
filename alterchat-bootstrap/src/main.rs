//! AlterChat bootstrap node.
//!
//! A small, headless libp2p node that runs Kademlia in server mode so new
//! AlterChat peers can find their first contacts. It carries no special
//! authority: it never sees message contents and can be run by anyone.
//!
//! Configuration (environment variables):
//! - `ALTERCHAT_DATA_DIR`        directory for the persistent node key (default: `./bootstrap-data`)
//! - `ALTERCHAT_BOOTSTRAP_PORT`  TCP and UDP/QUIC listen port (default: `4001`)
//! - `ALTERCHAT_LISTEN_IP`       listen IPv4 address (default: `0.0.0.0`)
//! - `ALTERCHAT_RELAY`           `0` disables the circuit relay service (default: enabled)
//!
//! The node also acts as a libp2p circuit relay (v2) so peers behind NAT can
//! reach each other and upgrade to a direct connection via DCUtR. Relayed
//! traffic is end-to-end encrypted (Noise between the two peers); the relay
//! only sees encrypted bytes and connection metadata. Circuits are limited
//! in duration and volume to keep operator costs predictable.

use libp2p::identity::Keypair;
use libp2p::{
    PeerId, SwarmBuilder,
    futures::StreamExt,
    identify, kad, noise, ping, relay,
    swarm::{NetworkBehaviour, SwarmEvent, behaviour::toggle::Toggle},
    tcp, yamux,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(NetworkBehaviour)]
struct BootstrapBehaviour {
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    relay: Toggle<relay::Behaviour>,
}

const KEY_FILE: &str = "bootstrap_ed25519.key";

/// Load the node identity from disk, or create and persist a new one.
///
/// A stable identity is required: clients reference bootstrap nodes by
/// `/ip4/.../tcp/.../p2p/<PEER_ID>`, so the peer id must survive restarts.
fn load_or_create_keypair(dir: &Path) -> Result<Keypair, Box<dyn std::error::Error>> {
    let path = dir.join(KEY_FILE);
    if path.exists() {
        let bytes = std::fs::read(&path)?;
        return Ok(Keypair::from_protobuf_encoding(&bytes)?);
    }
    std::fs::create_dir_all(dir)?;
    let keypair = Keypair::generate_ed25519();
    std::fs::write(&path, keypair.to_protobuf_encoding()?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("Generated new node identity at {}", path.display());
    Ok(keypair)
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(env_or("ALTERCHAT_DATA_DIR", "./bootstrap-data"));
    let port: u16 = env_or("ALTERCHAT_BOOTSTRAP_PORT", "4001").parse()?;
    let listen_ip = env_or("ALTERCHAT_LISTEN_IP", "0.0.0.0");

    println!("Starting AlterChat bootstrap node...");
    let keypair = load_or_create_keypair(&data_dir)?;
    let local_peer_id = PeerId::from(keypair.public());
    println!("Bootstrap node id: {local_peer_id}");

    let mut cfg = kad::Config::new(kad::PROTOCOL_NAME);
    cfg.set_query_timeout(Duration::from_secs(5 * 60));
    let store = kad::store::MemoryStore::new(local_peer_id);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, cfg);
    kademlia.set_mode(Some(kad::Mode::Server));

    let identify = identify::Behaviour::new(identify::Config::new(
        "/alterchat/1.0.0".to_string(),
        keypair.public(),
    ));

    let relay_enabled = env_or("ALTERCHAT_RELAY", "1") != "0";
    let relay = relay_enabled.then(|| {
        let cfg = relay::Config {
            max_reservations: 512,
            max_reservations_per_peer: 2,
            reservation_duration: Duration::from_secs(60 * 60),
            max_circuits: 128,
            max_circuits_per_peer: 8,
            // Chat traffic is small; generous enough for messages and the
            // DCUtR hole-punch upgrade, small enough to deter bulk transfer.
            max_circuit_duration: Duration::from_secs(10 * 60),
            max_circuit_bytes: 2 * 1024 * 1024,
            ..relay::Config::default()
        };
        relay::Behaviour::new(local_peer_id, cfg)
    });

    let behaviour = BootstrapBehaviour {
        kademlia,
        identify,
        ping: ping::Behaviour::default(),
        relay: Toggle::from(relay),
    };

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    swarm.listen_on(format!("/ip4/{listen_ip}/tcp/{port}").parse()?)?;
    swarm.listen_on(format!("/ip4/{listen_ip}/udp/{port}/quic-v1").parse()?)?;

    println!(
        "Circuit relay: {}",
        if relay_enabled { "enabled" } else { "disabled" }
    );
    println!("Clients can use any of the listen addresses below as a bootstrap node.");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("Shutting down.");
                return Ok(());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on: {address}/p2p/{local_peer_id}");
                }
                SwarmEvent::Behaviour(BootstrapBehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    println!("Peer connected: {peer_id}");
                }
                _ => {}
            }
        }
    }
}
