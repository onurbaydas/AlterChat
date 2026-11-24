use crate::socks5::{Socks5Config, Socks5Transport};
use libp2p::StreamProtocol;
use libp2p::core::Transport;
use libp2p::identity::Keypair;
use libp2p::request_response::ProtocolSupport;
use libp2p::{
    PeerId, Swarm, dcutr, gossipsub, identify, kad, mdns, noise, relay, request_response,
    swarm::{NetworkBehaviour, behaviour::toggle::Toggle},
    tcp, yamux,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Known-peer persistence
// ---------------------------------------------------------------------------

/// Returns the default path for the known-peers file:
/// `$HOME/.alterchat/known_peers.json` (falls back to `$USERPROFILE` on Windows).
pub fn default_known_peers_path() -> PathBuf {
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".alterchat")
        .join("known_peers.json")
}

/// Persists a list of multiaddr strings as a JSON array to `path`.
/// Creates parent directories if they do not exist.
pub fn save_known_peers(peers: &[String], path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string(peers)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Reads a JSON array of multiaddr strings from `path`.
/// Returns an empty `Vec` on any error (missing file, parse error, etc.).
pub fn load_known_peers(path: &Path) -> Vec<String> {
    let data = match std::fs::read_to_string(path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    serde_json::from_str::<Vec<String>>(&data).unwrap_or_default()
}

// ---------------------------------------------------------------------------

/// Community bootstrap nodes for peer discovery.
/// Override with ALTERCHAT_BOOTSTRAP env var (comma-separated multiaddrs).
/// Format: /ip4/<IP>/tcp/<PORT>/p2p/<PEER_ID>
///
/// These entries are used for initial DHT bootstrap; they carry no special
/// authority. Any community member can run `alterchat-bootstrap`
/// and submit a PR to add their multiaddr to this list.
pub const COMMUNITY_BOOTSTRAP_ADDRS: &[&str] = &[
    // Placeholder: replace with real community nodes before public release
    // "/ip4/bootstrap1.alterchat.example/tcp/4001/p2p/12D3KooW..."
    //
    // Candidates waiting for deployment confirmation:
    // "/ip4/95.216.8.12/tcp/4001/p2p/12D3KooWRkGLz4YbVmrsWK75VhydFu5Ncy1XHCkUBqLDinYBYEGR",
    // "/ip4/167.235.132.45/tcp/4001/p2p/12D3KooWQnwEGNqcM2nAcPtRR9rAX8Hrg4k9kJLCHoTR5chJjKD6",
    // "/ip4/49.13.56.189/tcp/4001/p2p/12D3KooWHdiAxVd8uMQR1hGWXccidmfCwLqcMpGwR6QcTP6QRMuD",
];

/// DNS TXT record domain for bootstrap node discovery.
/// Fallback mekanizması: hardcoded adresler erişilemezse DNS seed kullanılır.
/// TXT kaydı formatı: "multiaddr=<ADDR>" — birden fazla kayıt olabilir.
pub const DNS_SEED_DOMAIN: &str = "_alterchat-bootstrap.alterchat.org";

/// DNS seed'den bootstrap adreslerini çözümle.
/// Ağ erişimi gerektirir; başarısız olursa boş döner.
pub fn resolve_dns_seeds() -> Vec<String> {
    // DNS TXT record lookup — standart kütüphane ile basit implementasyon.
    // Üretimde `trust-dns-resolver` veya `hickory-dns` kullanılabilir.
    // Şimdilik hardcoded listeye fallback.
    COMMUNITY_BOOTSTRAP_ADDRS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Kullanıcı bootstrap + topluluk bootstrap + DNS seed birleşimi.
/// ALTERCHAT_BOOTSTRAP env var (comma-separated multiaddrs) also contributes.
pub fn effective_bootstrap_addrs(user_addrs: &[String]) -> Vec<String> {
    let mut addrs: Vec<String> = user_addrs.to_vec();

    // Env var override: ALTERCHAT_BOOTSTRAP=<multiaddr1>,<multiaddr2>,...
    let env_bootstrap: Vec<String> = std::env::var("ALTERCHAT_BOOTSTRAP")
        .unwrap_or_default()
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string())
        .collect();
    for addr in env_bootstrap {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }

    for addr in COMMUNITY_BOOTSTRAP_ADDRS {
        let s = addr.to_string();
        if !addrs.contains(&s) {
            addrs.push(s);
        }
    }
    if addrs.is_empty() {
        addrs.extend(resolve_dns_seeds());
    }
    addrs
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Default)]
pub enum ProxyMode {
    #[default]
    Direct,
    Tor,
    Socks5,
    I2p,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, Default)]
pub enum TransportPreference {
    #[default]
    Tcp,
    Quic,
    Tor,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct NetworkPrivacyConfig {
    pub proxy_mode: ProxyMode,
    pub transport_preference: TransportPreference,
    pub proxy_addr: Option<String>,
    pub bootstrap_addrs: Vec<String>,
    pub mdns_enabled: bool,
    pub dht_server_mode: bool,
    pub relay_enabled: bool,
    pub relay_fallback_enabled: bool,
    pub publish_capabilities: bool,
    pub protocol_versions: Vec<String>,
}

impl Default for NetworkPrivacyConfig {
    fn default() -> Self {
        Self {
            proxy_mode: ProxyMode::Direct,
            transport_preference: TransportPreference::Tcp,
            proxy_addr: None,
            bootstrap_addrs: Vec::new(),
            mdns_enabled: true,
            dht_server_mode: false,
            relay_enabled: false,
            relay_fallback_enabled: false,
            publish_capabilities: true,
            protocol_versions: vec!["/alterchat/p2p/1.0.0".to_string()],
        }
    }
}

#[derive(NetworkBehaviour)]
pub struct AlterChatBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    /// Disabled when `mdns_enabled` is false and always in Tor/SOCKS5/I2P mode (mDNS
    /// broadcasts presence on the local network).
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub request_response: request_response::cbor::Behaviour<
        crate::file_transfer::P2pRequest,
        crate::file_transfer::P2pResponse,
    >,
    // NAT traversal: relay sunucu (başkaları için) + relay istemci (NAT arkası) + dcutr hole punching
    /// Only active when the user volunteers as a relay (`relay_enabled`).
    pub relay_server: Toggle<relay::Behaviour>,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

pub async fn create_swarm(
    keypair: Keypair,
    config: NetworkPrivacyConfig,
) -> Result<Swarm<AlterChatBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(keypair.public());

    // Fail closed: in SOCKS5 / I2P mode an invalid, missing or unreachable
    // proxy is an error; we never fall back to direct connections.
    let socks_config = match config.proxy_mode {
        ProxyMode::Socks5 => Some(Socks5Config::socks5_from_setting(
            config.proxy_addr.as_deref(),
        )?),
        ProxyMode::I2p => Some(Socks5Config::i2p_from_setting(
            config.proxy_addr.as_deref(),
        )?),
        ProxyMode::Direct | ProxyMode::Tor => None,
    };
    if let Some(socks) = &socks_config {
        crate::socks5::probe_proxy(socks, Duration::from_secs(10))
            .await
            .map_err(|e| format!("{e}; refusing to connect directly"))?;
    }
    let tor_mode = matches!(config.proxy_mode, ProxyMode::Tor);
    // Any anonymising mode: no mDNS, no relay server, no public listeners.
    let anonymised = tor_mode || socks_config.is_some();

    // Gossipsub configuration for message broadcast
    let message_id_fn = |message: &gossipsub::Message| {
        let mut s = DefaultHasher::new();
        message.data.hash(&mut s);
        gossipsub::MessageId::from(s.finish().to_string())
    };

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        // Anonymous mod imzalamaz; Permissive hem imzalı hem imzasız mesajları kabul eder.
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .message_id_fn(message_id_fn)
        .build()
        .map_err(std::io::Error::other)?;

    // Anonymous mod: gönderenin PeerId'si mesajlara eklenmez.
    // Sealed Sender zaten gönderici kimliğini şifreli zarfa koyuyor; açık imza gizliliği ihlal eder.
    let gossipsub =
        gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Anonymous, gossipsub_config)?;

    // Kademlia configuration for DHT (peer discovery and content routing)
    let mut cfg = kad::Config::new(kad::PROTOCOL_NAME);
    cfg.set_query_timeout(Duration::from_secs(5 * 60));
    let store = kad::store::MemoryStore::new(local_peer_id);
    let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, cfg);
    // Proxy modes are outbound-only, so advertising DHT server mode is useless.
    if config.dht_server_mode && socks_config.is_none() {
        kademlia.set_mode(Some(kad::Mode::Server));
    }

    // mDNS configuration for local network discovery
    let mdns = if config.mdns_enabled && !anonymised {
        Some(mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        )?)
    } else {
        None
    };
    let mdns = Toggle::from(mdns);

    // Identify configuration for protocol negotiation and exchanging peer information
    let identify_config = identify::Config::new("/alterchat/1.0.0".to_string(), keypair.public());
    let identify = identify::Behaviour::new(identify_config);

    let request_response = request_response::cbor::Behaviour::new(
        [(
            StreamProtocol::new("/alterchat/p2p/1.0.0"),
            ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    );

    // NAT traversal: relay sunucu (her node başkaları için relay yapabilir) + relay istemci + dcutr
    let relay_server = Toggle::from(
        (config.relay_enabled && !anonymised)
            .then(|| relay::Behaviour::new(local_peer_id, relay::Config::default())),
    );
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let dcutr = dcutr::Behaviour::new(local_peer_id);

    let behaviour = AlterChatBehaviour {
        gossipsub,
        mdns,
        kademlia,
        identify,
        request_response,
        relay_server,
        relay_client,
        dcutr,
    };

    if let Some(socks) = socks_config {
        // SOCKS5 / I2P: the only transports are the SOCKS5 dialer and relay
        // circuits on top of it. No TCP listener, no QUIC, no DNS transport
        // (host names are resolved by the proxy).
        let socks_transport = Socks5Transport::new(socks);
        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(
                |key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                    Ok(socks_transport
                        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                        .authenticate(noise::Config::new(key)?)
                        .multiplex(yamux::Config::default()))
                },
            )?
            .with_other_transport(
                |key| -> Result<_, Box<dyn std::error::Error + Send + Sync>> {
                    Ok(relay_transport
                        .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                        .authenticate(noise::Config::new(key)?)
                        .multiplex(yamux::Config::default()))
                },
            )?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        Ok(swarm)
    } else if tor_mode {
        let tor_transport = libp2p_community_tor::TorTransport::bootstrapped().await?;

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_other_transport(|key| {
                let noise_config = noise::Config::new(key).unwrap();
                let yamux_config = yamux::Config::default();

                tor_transport
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise_config)
                    .multiplex(yamux_config)
            })?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        Ok(swarm)
    } else if matches!(config.transport_preference, TransportPreference::Quic) {
        // QUIC preferred, TCP kept so TCP-only bootstrap nodes stay reachable.
        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_quic()
            .with_other_transport(|key| {
                relay_transport
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
            })?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        Ok(swarm)
    } else {
        // Direct transport
        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            // Relay transport: relay üzerinden geçen bağlantılar için noise+yamux
            .with_other_transport(|key| {
                relay_transport
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
            })?
            .with_behaviour(|_| behaviour)?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        // Bootstrap node'larına bağlan (topluluk + kullanıcı + DNS seed)
        for addr_str in effective_bootstrap_addrs(&config.bootstrap_addrs) {
            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                swarm.dial(addr).ok();
            }
        }

        // Dial previously discovered peers that survived restart.
        let peers_path = default_known_peers_path();
        let persisted = load_known_peers(&peers_path);
        for addr_str in &persisted {
            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                swarm.dial(addr).ok();
            }
        }
        // Re-save so the file is refreshed / created if it was missing.
        let _ = save_known_peers(&persisted, &peers_path);

        Ok(swarm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_known_peers() {
        let dir = std::env::temp_dir().join("alterchat_test_peers");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_peers.json");

        let peers = vec![
            "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWFakeAddr1111111111111111111111111111111111111111"
                .to_string(),
            "/ip4/5.6.7.8/tcp/4001/p2p/12D3KooWFakeAddr2222222222222222222222222222222222222222"
                .to_string(),
        ];

        save_known_peers(&peers, &path).expect("save should succeed");
        let loaded = load_known_peers(&path);
        assert_eq!(loaded.len(), 2, "expected 2 peers, got {}", loaded.len());
        assert_eq!(loaded[0], peers[0]);
        assert_eq!(loaded[1], peers[1]);

        // Clean up
        let _ = std::fs::remove_file(&path);
    }

    use crate::socks5::tests::spawn_mock_proxy;
    use libp2p::futures::StreamExt;
    use libp2p::swarm::SwarmEvent;
    use libp2p::{Multiaddr, ping};

    #[derive(NetworkBehaviour)]
    struct PingIdentify {
        ping: ping::Behaviour,
        identify: identify::Behaviour,
    }

    fn ping_identify(key: &Keypair) -> PingIdentify {
        PingIdentify {
            ping: ping::Behaviour::new(
                ping::Config::new().with_interval(Duration::from_millis(200)),
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                "/alterchat-test/1.0.0".into(),
                key.public(),
            )),
        }
    }

    fn proxy_config(addr: Option<String>, mode: ProxyMode) -> NetworkPrivacyConfig {
        NetworkPrivacyConfig {
            proxy_mode: mode,
            proxy_addr: addr,
            mdns_enabled: true,
            relay_enabled: true,
            ..NetworkPrivacyConfig::default()
        }
    }

    #[tokio::test]
    async fn ping_and_identify_over_socks5_proxy() {
        // Peer B: plain TCP listener on loopback.
        let mut b = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(ping_identify)
            .unwrap()
            .build();
        b.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let b_port = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = b.select_next_some().await {
                break address
                    .iter()
                    .find_map(|p| match p {
                        libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
                        _ => None,
                    })
                    .unwrap();
            }
        };
        let b_id = *b.local_peer_id();

        // Peer A: SOCKS5 transport only, pointed at the mock proxy which maps
        // an unresolvable host name to 127.0.0.1.
        let (proxy, seen) = spawn_mock_proxy(None, &["peer-b.alterchat.invalid"]).await;
        let socks =
            Socks5Config::socks5_from_setting(Some(&proxy.to_string())).expect("valid proxy");
        let mut a = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_other_transport(|key| {
                Socks5Transport::new(socks)
                    .upgrade(libp2p::core::upgrade::Version::V1Lazy)
                    .authenticate(noise::Config::new(key).unwrap())
                    .multiplex(yamux::Config::default())
            })
            .unwrap()
            .with_behaviour(ping_identify)
            .unwrap()
            .build();
        assert!(
            a.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .is_err(),
            "proxied swarm must not listen"
        );
        let target: Multiaddr = format!("/dns4/peer-b.alterchat.invalid/tcp/{b_port}/p2p/{b_id}")
            .parse()
            .unwrap();
        a.dial(target).unwrap();

        let (mut pinged, mut identified) = (false, false);
        tokio::time::timeout(Duration::from_secs(30), async {
            while !(pinged && identified) {
                tokio::select! {
                    ev = a.select_next_some() => match ev {
                        SwarmEvent::Behaviour(PingIdentifyEvent::Ping(ping::Event { peer, result: Ok(_), .. })) if peer == b_id => pinged = true,
                        SwarmEvent::Behaviour(PingIdentifyEvent::Identify(identify::Event::Received { peer_id, .. })) if peer_id == b_id => identified = true,
                        SwarmEvent::OutgoingConnectionError { error, .. } => panic!("dial failed: {error}"),
                        _ => {}
                    },
                    _ = b.select_next_some() => {}
                }
            }
        })
        .await
        .expect("ping + identify over the SOCKS5 proxy");

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].atyp, 0x03, "CONNECT must carry the host name");
        assert_eq!(seen[0].host, "peer-b.alterchat.invalid");
        assert_eq!(seen[0].port, b_port);
    }

    #[tokio::test]
    async fn create_swarm_socks5_mode_is_outbound_only() {
        let (proxy, _seen) = spawn_mock_proxy(None, &[]).await;
        let mut swarm = create_swarm(
            Keypair::generate_ed25519(),
            proxy_config(Some(proxy.to_string()), ProxyMode::Socks5),
        )
        .await
        .expect("swarm with reachable proxy");
        assert!(!swarm.behaviour().mdns.is_enabled());
        assert!(!swarm.behaviour().relay_server.is_enabled());
        assert!(
            swarm
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .is_err()
        );
        assert!(
            swarm
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .is_err()
        );
    }

    #[tokio::test]
    async fn create_swarm_rejects_missing_invalid_or_down_proxy() {
        let err = create_swarm(
            Keypair::generate_ed25519(),
            proxy_config(None, ProxyMode::Socks5),
        )
        .await
        .err()
        .expect("missing proxy must fail")
        .to_string();
        assert!(err.contains("requires a proxy address"), "{err}");

        let err = create_swarm(
            Keypair::generate_ed25519(),
            proxy_config(Some("not a proxy".into()), ProxyMode::Socks5),
        )
        .await
        .err()
        .expect("invalid proxy must fail")
        .to_string();
        assert!(err.contains("refusing to connect directly"), "{err}");

        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        for mode in [ProxyMode::Socks5, ProxyMode::I2p] {
            let err = create_swarm(
                Keypair::generate_ed25519(),
                proxy_config(Some(dead_addr.to_string()), mode),
            )
            .await
            .err()
            .expect("unreachable proxy must fail")
            .to_string();
            assert!(err.contains("unreachable"), "{err}");
            assert!(err.contains("refusing to connect directly"), "{err}");
        }
    }

    #[test]
    fn test_load_known_peers_missing_file() {
        let path = std::env::temp_dir().join("alterchat_nonexistent_peers.json");
        let loaded = load_known_peers(&path);
        assert!(loaded.is_empty(), "missing file should return empty vec");
    }
}
