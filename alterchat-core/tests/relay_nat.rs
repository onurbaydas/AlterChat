//! NAT traversal end to end: a relay server (configured like
//! `alterchat-bootstrap`) and two clients that have no listener of their own,
//! so they cannot dial each other directly. Client B reserves a circuit on
//! the relay, publishes its relayed address in a signed address record,
//! client A dials B through the relay from that record and the AlterChat
//! request-response protocol works over the circuit.
use alterchat_core::file_transfer::{P2pRequest, P2pResponse};
use alterchat_core::nat::{self, NatTraversal, Reachability};
use alterchat_core::network::{
    AlterChatBehaviour, AlterChatBehaviourEvent, NetworkPrivacyConfig, create_swarm,
};
use libp2p::futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use libp2p::{Multiaddr, Swarm, identify, kad, noise, ping, relay, request_response, tcp, yamux};
use std::time::{Duration, Instant};

#[derive(NetworkBehaviour)]
struct RelayNode {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

async fn spawn_relay() -> Multiaddr {
    let mut relay = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .unwrap()
        .with_behaviour(|key| RelayNode {
            relay: relay::Behaviour::new(key.public().to_peer_id(), relay::Config::default()),
            identify: identify::Behaviour::new(identify::Config::new(
                "/alterchat/1.0.0".into(),
                key.public(),
            )),
            ping: ping::Behaviour::default(),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    relay
        .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .unwrap();
    let addr = loop {
        if let SwarmEvent::NewListenAddr { address, .. } = relay.select_next_some().await {
            break address;
        }
    };
    // Like the bootstrap node: reservations need a confirmed external address.
    relay.add_external_address(addr.clone());
    let full = addr.with(Protocol::P2p(*relay.local_peer_id()));
    tokio::spawn(async move {
        loop {
            relay.select_next_some().await;
        }
    });
    full
}

fn client_config() -> NetworkPrivacyConfig {
    NetworkPrivacyConfig {
        mdns_enabled: false,
        relay_fallback_enabled: true,
        ..NetworkPrivacyConfig::default()
    }
}

/// Runs the NAT state machine and answers `WebRtcSignal` requests.
fn drive(
    swarm: &mut Swarm<AlterChatBehaviour>,
    nat: &mut NatTraversal,
    event: SwarmEvent<AlterChatBehaviourEvent>,
) -> Option<SwarmEvent<AlterChatBehaviourEvent>> {
    nat.on_swarm_event(swarm, &event, Instant::now());
    if let SwarmEvent::Behaviour(AlterChatBehaviourEvent::RequestResponse(
        request_response::Event::Message {
            message:
                request_response::Message::Request {
                    request: P2pRequest::WebRtcSignal { signal },
                    channel,
                    ..
                },
            ..
        },
    )) = event
    {
        assert_eq!(signal, "hello through the relay");
        let _ = swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, P2pResponse::WebRtcAck { success: true });
        return None;
    }
    Some(event)
}

#[tokio::test]
async fn clients_behind_nat_reach_each_other_through_relay() {
    let relay_addr = spawn_relay().await;
    let bootstrap = vec![relay_addr.to_string()];
    let cfg = client_config();

    // Client B: no listener, only the relay circuit.
    let key_b = Keypair::generate_ed25519();
    let mut b = create_swarm(key_b.clone(), cfg.clone()).await.unwrap();
    let b_id = *b.local_peer_id();
    let mut nat_b = NatTraversal::new(key_b.clone(), &cfg, &bootstrap);
    nat_b.start();
    b.dial(relay_addr.clone()).unwrap();

    tokio::time::timeout(Duration::from_secs(10), async {
        while nat_b.reachability() != Reachability::Relayed
            || NatTraversal::advertised_addrs(&b).is_empty()
        {
            let ev = b.select_next_some().await;
            drive(&mut b, &mut nat_b, ev);
        }
    })
    .await
    .expect("B reserves a circuit on the relay");

    let advertised = NatTraversal::advertised_addrs(&b);
    assert!(advertised.iter().all(nat::is_relayed), "{advertised:?}");
    assert!(nat_b.reserved_relays().count() == 1);

    // B's signed address record, as a friend would fetch it from the DHT.
    let record = kad::Record {
        key: nat::addr_record_key(&b_id),
        value: nat::seal_addr_record(&key_b, &advertised).unwrap(),
        publisher: None,
        expires: None,
    };

    // Client A: no listener either; dials B only from the record.
    let key_a = Keypair::generate_ed25519();
    let mut a = create_swarm(key_a.clone(), cfg.clone()).await.unwrap();
    let mut nat_a = NatTraversal::new(key_a, &cfg, &bootstrap);
    nat_a.start();
    assert!(nat_a.on_record(&mut a, &record), "valid address record");
    a.behaviour_mut().request_response.send_request(
        &b_id,
        P2pRequest::WebRtcSignal {
            signal: "hello through the relay".into(),
        },
    );

    let mut relayed_connection = false;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                ev = a.select_next_some() => {
                    match drive(&mut a, &mut nat_a, ev) {
                        Some(SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }) if peer_id == b_id => {
                            assert!(endpoint.is_relayed(), "A must reach B through the relay: {endpoint:?}");
                            relayed_connection = true;
                        }
                        Some(SwarmEvent::Behaviour(AlterChatBehaviourEvent::RequestResponse(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Response { response, .. },
                                ..
                            },
                        ))) if peer == b_id => {
                            assert!(matches!(response, P2pResponse::WebRtcAck { success: true }));
                            break;
                        }
                        Some(SwarmEvent::Behaviour(AlterChatBehaviourEvent::RequestResponse(
                            request_response::Event::OutboundFailure { error, .. },
                        ))) => panic!("request failed: {error}"),
                        _ => {}
                    }
                }
                ev = b.select_next_some() => { drive(&mut b, &mut nat_b, ev); }
            }
        }
    })
    .await
    .expect("request-response round trip through the relay");
    assert!(relayed_connection);
}
