use alterchat_core::{crdt, identity, network};
use libp2p::{futures::StreamExt, gossipsub, mdns, swarm::SwarmEvent};
use std::error::Error;
use tokio::io::{self, AsyncBufReadExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let keypair = identity::load_or_generate_keypair("local_keypair.bin")?;
    let local_peer_id = libp2p::PeerId::from(keypair.public());
    let mut swarm =
        network::create_swarm(keypair, network::NetworkPrivacyConfig::default()).await?;

    // CRDT Room initialization
    let mut room = crdt::Room::new("alterchat-global".to_string(), None);

    let topic = gossipsub::IdentTopic::new("alterchat-global");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("AlterChat Core Node starting...");
    println!("Type a message and press Enter to broadcast via CRDT.");

    let mut stdin = io::BufReader::new(io::stdin()).lines();

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                if let Ok(Some(line)) = line {
                    // Add message to local CRDT room
                    match room.add_message(&local_peer_id.to_string(), &local_peer_id.to_string(), &line, None) {
                        Ok(bytes) => {
                            // Broadcast the updated CRDT state
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                                println!("Publish error: {e:?}");
                            } else {
                                println!("Message added to CRDT and broadcasted.");
                            }
                        }
                        Err(e) => println!("CRDT Error: {:?}", e),
                    }
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {:?}", address);
                }
                SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: _id,
                    message,
                })) => {
                    // Merge incoming CRDT state
                    if let Err(e) = room.merge(&message.data) {
                        println!("Failed to merge CRDT state from {peer_id}: {e:?}");
                    } else {
                        println!("Merged CRDT state from {peer_id}. Last 3 messages in room:");
                        if let Ok(msgs) = room.get_messages() {
                            for msg in msgs.iter().skip(msgs.len().saturating_sub(3)) {
                                println!("[{}] {}: {}", msg.timestamp, msg.sender, msg.text);
                            }
                        }
                    }
                }
                SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    let mut new_addrs: Vec<String> = Vec::new();
                    for (peer_id, multiaddr) in list {
                        println!("mDNS discovered a new peer: {} at {}", peer_id, multiaddr);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        new_addrs.push(multiaddr.to_string());
                    }
                    if !new_addrs.is_empty() {
                        let peers_path = network::default_known_peers_path();
                        let mut existing = network::load_known_peers(&peers_path);
                        for addr in new_addrs {
                            if !existing.contains(&addr) {
                                existing.push(addr);
                            }
                        }
                        let _ = network::save_known_peers(&existing, &peers_path);
                    }
                }
                SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, multiaddr) in list {
                        println!("mDNS discover peer has expired: {} at {}", peer_id, multiaddr);
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                }
                _ => {}
            }
        }
    }
}
