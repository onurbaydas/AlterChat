use libp2p::{
    futures::StreamExt, identify, kad, noise, swarm::{NetworkBehaviour, SwarmEvent}, tcp, yamux, PeerId, SwarmBuilder,
};
use libp2p::identity::Keypair;
use std::time::Duration;

#[derive(NetworkBehaviour)]
struct BootstrapBehaviour {
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    identify: identify::Behaviour,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting AlterChat Bootstrap Node...");

    // Generate a fixed keypair for the bootstrap node (in production, load from file)
    let keypair = Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(keypair.public());
    
    println!("Bootstrap Node ID: {}", local_peer_id);

    let mut cfg = kad::Config::default();
    cfg.set_query_timeout(Duration::from_secs(5 * 60));

    let store = kad::store::MemoryStore::new(local_peer_id);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, cfg);
    kademlia.set_mode(Some(kad::Mode::Server));

    let identify_config = identify::Config::new("/alterchat/1.0.0".to_string(), keypair.public());
    let identify = identify::Behaviour::new(identify_config);

    let behaviour = BootstrapBehaviour {
        kademlia,
        identify,
    };

    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let port = 4001;
    let addr: libp2p::Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", port).parse()?;
    swarm.listen_on(addr.clone())?;
    
    println!("Listening on port {}. Multiaddr: {}/p2p/{}", port, addr, local_peer_id);
    println!("Clients should use this Multiaddr to connect and discover peers globally.");

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on: {}/p2p/{}", address, local_peer_id);
            }
            SwarmEvent::Behaviour(BootstrapBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                println!("Identified peer: {}", peer_id);
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }
            _ => {}
        }
    }
}
