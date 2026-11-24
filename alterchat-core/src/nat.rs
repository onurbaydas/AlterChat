//! NAT traversal, reachability and connectivity tracking for the client swarm.
//!
//! Most home users sit behind NAT and cannot accept inbound connections, and
//! Tor / SOCKS5 / I2P users have no listener at all. To stay reachable a
//! client reserves a circuit-relay-v2 slot on up to [`MAX_RELAYS`] relays
//! (bootstrap nodes first, then any peer advertising the relay hop protocol)
//! by listening on `<relay_addr>/p2p/<relay>/p2p-circuit`. The relay client
//! then reports `<relay_addr>/p2p/<relay>/p2p-circuit` as a confirmed external
//! address, identify advertises it, and [`NatTraversal`] publishes the
//! external addresses in a signed peer record in the DHT
//! (`ADDR_RECORD_PREFIX || peer_id`) so friends can dial
//! `/p2p/<relay>/p2p-circuit/p2p/<peer>`. DCUtR upgrades relayed connections
//! to direct ones where hole punching works (direct mode only).
//!
//! Reservations are made whenever `relay_fallback_enabled` is set, without
//! waiting for an AutoNAT verdict: the bootstrap nodes do not run an AutoNAT
//! server, AutoNAT cannot work through Tor / SOCKS5 at all, and a reservation
//! only costs one small stream on a connection we already hold. A cheap
//! heuristic still reports `direct` reachability when a peer observes us on
//! a public IP that is assigned to one of our own interfaces (no NAT in
//! between) or a peer connects to us directly from a public IP.
use crate::network::{
    AlterChatBehaviour, AlterChatBehaviourEvent, NetworkPrivacyConfig, ProxyMode,
};
use libp2p::core::transport::ListenerId;
use libp2p::core::{ConnectedPoint, PeerRecord, SignedEnvelope, transport::TransportError};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{ConnectionId, DialError, SwarmEvent, dial_opts::DialOpts};
use libp2p::{Multiaddr, PeerId, Swarm, dcutr, identify, kad, relay};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// DHT key prefix of signed address records.
pub const ADDR_RECORD_PREFIX: &[u8] = b"/alterchat/addr/1/";
/// Maximum number of relays we hold a reservation on at the same time.
pub const MAX_RELAYS: usize = 2;
/// Address records older than this are ignored (reservations last 1 h and
/// are re-published every [`REPUBLISH_INTERVAL`]).
pub const ADDR_RECORD_MAX_AGE_SECS: u64 = 24 * 60 * 60;
const MAX_ADDR_RECORD_BYTES: usize = 4096;
const MAX_RECORD_ADDRS: usize = 16;
const MAX_CLOCK_SKEW_SECS: u64 = 10 * 60;
const RESERVATION_RETRY: Duration = Duration::from_secs(60);
const MAX_RELAY_FAILURES: u32 = 3;
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(10 * 60);
const LOOKUP_INTERVAL: Duration = Duration::from_secs(2 * 60);
/// At most one proxy error message per this interval.
pub const PROXY_ERROR_THROTTLE: Duration = Duration::from_secs(5 * 60);
/// Consecutive failed dials (no success in between) before Tor is reported
/// as unusable.
const TOR_FAILURE_THRESHOLD: u32 = 4;

// ---------------------------------------------------------------------------
// Signed address records
// ---------------------------------------------------------------------------

pub fn addr_record_key(peer: &PeerId) -> kad::RecordKey {
    let mut key = ADDR_RECORD_PREFIX.to_vec();
    key.extend_from_slice(&peer.to_bytes());
    kad::RecordKey::new(&key)
}

pub fn is_addr_record_key(key: &[u8]) -> bool {
    key.starts_with(ADDR_RECORD_PREFIX)
}

/// Builds a signed (libp2p `PeerRecord` envelope) address record value.
pub fn seal_addr_record(keypair: &Keypair, addrs: &[Multiaddr]) -> Option<Vec<u8>> {
    let addrs: Vec<Multiaddr> = addrs.iter().take(MAX_RECORD_ADDRS).cloned().collect();
    let value = PeerRecord::new(keypair, addrs)
        .ok()?
        .into_signed_envelope()
        .into_protobuf_encoding();
    (value.len() <= MAX_ADDR_RECORD_BYTES).then_some(value)
}

/// Verifies an address record: signature, key binding to the signer, size
/// and freshness (`now_secs` is UNIX time in seconds).
pub fn open_addr_record(key: &[u8], value: &[u8], now_secs: u64) -> Option<PeerRecord> {
    if value.len() > MAX_ADDR_RECORD_BYTES || !is_addr_record_key(key) {
        return None;
    }
    let envelope = SignedEnvelope::from_protobuf_encoding(value).ok()?;
    let record = PeerRecord::from_signed_envelope(envelope).ok()?;
    if addr_record_key(&record.peer_id()).as_ref() != key
        || record.addresses().len() > MAX_RECORD_ADDRS
        || record.seq() > now_secs.saturating_add(MAX_CLOCK_SKEW_SECS)
        || record.seq().saturating_add(ADDR_RECORD_MAX_AGE_SECS) < now_secs
    {
        return None;
    }
    Some(record)
}

/// Storage-side filter for inbound PUTs under [`ADDR_RECORD_PREFIX`]: valid,
/// fresh and not older than the stored record (no rollback).
pub fn accept_addr_record(
    key: &[u8],
    value: &[u8],
    existing: Option<&[u8]>,
    now_secs: u64,
) -> bool {
    let Some(new) = open_addr_record(key, value, now_secs) else {
        return false;
    };
    match existing.and_then(|old| open_addr_record(key, old, now_secs)) {
        Some(old) => new.seq() >= old.seq(),
        None => true,
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

pub fn is_relayed(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::P2pCircuit))
}

/// `<relay_addr>/p2p/<relay>/p2p-circuit` (any trailing `/p2p` is replaced).
pub fn circuit_listen_addr(relay_addr: &Multiaddr, relay: PeerId) -> Multiaddr {
    let mut addr = relay_addr.clone();
    while matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.pop();
    }
    addr.with(Protocol::P2p(relay)).with(Protocol::P2pCircuit)
}

/// Peer id carried by the last `/p2p` component (before any circuit).
pub fn peer_id_of(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}

fn ip_of(addr: &Multiaddr) -> Option<IpAddr> {
    addr.iter().find_map(|p| match p {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                // 100.64.0.0/10 carrier-grade NAT
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// True when a dial failed because the local SOCKS5 / I2P proxy itself is
/// down (as opposed to the destination being unreachable through it).
pub fn is_proxy_failure(error: &DialError) -> bool {
    let DialError::Transport(errors) = error else {
        return false;
    };
    errors.iter().any(|(_, e)| match e {
        TransportError::Other(e) => {
            let text = error_chain(e).to_lowercase();
            text.contains("socks5 proxy")
                && (text.contains(" is unreachable") || text.contains("did not respond"))
        }
        TransportError::MultiaddrNotSupported(_) => false,
    })
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatus {
    Online,
    Connecting,
    Offline,
}

impl NetworkStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Connecting => "connecting",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// Peers can dial one of our public addresses.
    Direct,
    /// Reachable through at least one relay circuit.
    Relayed,
    Unreachable,
}

impl Reachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relayed => "relayed",
            Self::Unreachable => "unreachable",
        }
    }
}

/// What the UI should be told; the caller maps these to Tauri events
/// (`network-status`, `network-reachability`, `session-error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatNotice {
    Status(NetworkStatus),
    Reachability(Reachability),
    ProxyError(String),
}

pub struct NatTraversal {
    keypair: Keypair,
    local_peer_id: PeerId,
    use_relays: bool,
    proxy: Option<ProxyMode>,
    bootstrap: Vec<Multiaddr>,
    bootstrap_peers: HashSet<PeerId>,
    /// Non-relayed address we dialed each connected peer on.
    dialed: HashMap<PeerId, Multiaddr>,
    /// Peers advertising the relay hop protocol, bootstrap nodes first.
    relay_candidates: Vec<PeerId>,
    /// Address each relay candidate is dialed on (kept across disconnects:
    /// the relay client re-dials the relay when we listen on it again).
    relay_addrs: HashMap<PeerId, Multiaddr>,
    /// Reservation attempts that ended without an accepted reservation.
    relay_failures: HashMap<PeerId, u32>,
    circuits: HashMap<ListenerId, PeerId>,
    reserved: HashSet<PeerId>,
    last_attempt: HashMap<PeerId, Instant>,
    local_ips: HashSet<IpAddr>,
    public_listen_addrs: Vec<Multiaddr>,
    direct: bool,
    connections: usize,
    pending_dials: HashSet<ConnectionId>,
    /// Set once a dial attempt has finished (or a maintenance tick ran), so
    /// "no connection and nothing pending" means offline rather than
    /// "still starting up".
    settled: bool,
    last_status: Option<NetworkStatus>,
    last_reachability: Option<Reachability>,
    last_proxy_error: Option<Instant>,
    consecutive_failures: u32,
    published: Option<(Vec<Multiaddr>, Instant)>,
    last_lookup: HashMap<PeerId, Instant>,
}

impl NatTraversal {
    /// `bootstrap` should be the same list the caller dials at startup.
    pub fn new(keypair: Keypair, config: &NetworkPrivacyConfig, bootstrap: &[String]) -> Self {
        let bootstrap: Vec<Multiaddr> = bootstrap.iter().filter_map(|s| s.parse().ok()).collect();
        Self {
            local_peer_id: keypair.public().to_peer_id(),
            keypair,
            use_relays: config.relay_fallback_enabled,
            proxy: match config.proxy_mode {
                ProxyMode::Direct => None,
                ref m => Some(m.clone()),
            },
            bootstrap_peers: bootstrap.iter().filter_map(peer_id_of).collect(),
            bootstrap,
            dialed: HashMap::new(),
            relay_candidates: Vec::new(),
            relay_addrs: HashMap::new(),
            relay_failures: HashMap::new(),
            circuits: HashMap::new(),
            reserved: HashSet::new(),
            last_attempt: HashMap::new(),
            local_ips: HashSet::new(),
            public_listen_addrs: Vec::new(),
            direct: false,
            connections: 0,
            pending_dials: HashSet::new(),
            settled: false,
            last_status: None,
            last_reachability: None,
            last_proxy_error: None,
            consecutive_failures: 0,
            published: None,
            last_lookup: HashMap::new(),
        }
    }

    pub fn reachability(&self) -> Reachability {
        if self.direct {
            Reachability::Direct
        } else if !self.reserved.is_empty() {
            Reachability::Relayed
        } else {
            Reachability::Unreachable
        }
    }

    pub fn status(&self) -> NetworkStatus {
        if self.connections > 0 {
            NetworkStatus::Online
        } else if !self.pending_dials.is_empty() || !self.settled {
            NetworkStatus::Connecting
        } else {
            NetworkStatus::Offline
        }
    }

    /// Relays we currently hold a confirmed reservation on.
    pub fn reserved_relays(&self) -> impl Iterator<Item = &PeerId> {
        self.reserved.iter()
    }

    /// Call once the swarm has been built and the initial dials issued.
    pub fn start(&mut self) -> Vec<NatNotice> {
        let out = vec![
            NatNotice::Status(NetworkStatus::Connecting),
            NatNotice::Reachability(Reachability::Unreachable),
        ];
        self.last_status = Some(NetworkStatus::Connecting);
        self.last_reachability = Some(Reachability::Unreachable);
        out
    }

    fn changes(&mut self, out: &mut Vec<NatNotice>) {
        let status = self.status();
        if self.last_status != Some(status) {
            self.last_status = Some(status);
            out.push(NatNotice::Status(status));
        }
        let reach = self.reachability();
        if self.last_reachability != Some(reach) {
            self.last_reachability = Some(reach);
            out.push(NatNotice::Reachability(reach));
        }
    }

    fn proxy_error(&mut self, now: Instant, message: String, out: &mut Vec<NatNotice>) {
        if self
            .last_proxy_error
            .is_some_and(|t| now.duration_since(t) < PROXY_ERROR_THROTTLE)
        {
            return;
        }
        self.last_proxy_error = Some(now);
        out.push(NatNotice::ProxyError(message));
    }

    /// Feed every swarm event through here (before the caller consumes it).
    pub fn on_swarm_event(
        &mut self,
        swarm: &mut Swarm<AlterChatBehaviour>,
        event: &SwarmEvent<AlterChatBehaviourEvent>,
        now: Instant,
    ) -> Vec<NatNotice> {
        let mut out = Vec::new();
        match event {
            SwarmEvent::Dialing { connection_id, .. } => {
                self.pending_dials.insert(*connection_id);
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                endpoint,
                ..
            } => {
                self.pending_dials.remove(connection_id);
                self.connections += 1;
                self.consecutive_failures = 0;
                match endpoint {
                    ConnectedPoint::Dialer { address, .. } if !is_relayed(address) => {
                        self.dialed.insert(*peer_id, address.clone());
                    }
                    ConnectedPoint::Listener { send_back_addr, .. }
                        if !endpoint.is_relayed()
                            && ip_of(send_back_addr).is_some_and(is_public_ip) =>
                    {
                        // Someone reached our listener from the internet.
                        self.mark_direct(swarm);
                    }
                    _ => {}
                }
                if endpoint.is_relayed() {
                    tracing::info!(peer = %peer_id, "relayed connection established");
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                self.connections = self.connections.saturating_sub(1);
                self.settled = true;
                if *num_established == 0 {
                    self.dialed.remove(peer_id);
                }
            }
            SwarmEvent::OutgoingConnectionError {
                connection_id,
                error,
                peer_id,
            } => {
                self.pending_dials.remove(connection_id);
                self.settled = true;
                if !matches!(
                    error,
                    DialError::DialPeerConditionFalse(_) | DialError::Aborted
                ) {
                    self.consecutive_failures += 1;
                }
                self.on_dial_error(*peer_id, error, now, &mut out);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                if let Some(ip) = ip_of(address).filter(|_| !is_relayed(address)) {
                    self.local_ips.insert(ip);
                    if is_public_ip(ip) && !self.public_listen_addrs.contains(address) {
                        self.public_listen_addrs.push(address.clone());
                        if self.direct {
                            swarm.add_external_address(address.clone());
                        }
                    }
                }
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                reason,
                ..
            } => {
                if let Some(relay) = self.circuits.remove(listener_id) {
                    tracing::info!(%relay, ?reason, "relay circuit listener closed");
                    if !self.reserved.remove(&relay) {
                        // Never accepted: give up on relays that keep refusing.
                        let failures = self.relay_failures.entry(relay).or_default();
                        *failures += 1;
                        if *failures >= MAX_RELAY_FAILURES {
                            self.relay_candidates.retain(|p| *p != relay);
                        }
                    }
                    self.try_reserve(swarm, now);
                }
            }
            SwarmEvent::Behaviour(AlterChatBehaviourEvent::Identify(
                identify::Event::Received { peer_id, info, .. },
            )) => {
                if ip_of(&info.observed_addr)
                    .is_some_and(|ip| is_public_ip(ip) && self.local_ips.contains(&ip))
                {
                    // Our interface owns the public IP peers see: no NAT.
                    self.mark_direct(swarm);
                }
                if info.protocols.contains(&relay::HOP_PROTOCOL_NAME)
                    && !self.relay_candidates.contains(peer_id)
                    && self.relay_failures.get(peer_id).copied().unwrap_or(0) < MAX_RELAY_FAILURES
                {
                    let addr = self.dialed.get(peer_id).cloned().or_else(|| {
                        // Inbound connection: fall back to an advertised public address.
                        self.proxy.is_none().then(|| {
                            info.listen_addrs
                                .iter()
                                .find(|a| !is_relayed(a) && ip_of(a).is_some_and(is_public_ip))
                                .cloned()
                        })?
                    });
                    let Some(addr) = addr else {
                        self.changes(&mut out);
                        return out;
                    };
                    self.relay_addrs.insert(*peer_id, addr);
                    self.relay_candidates.push(*peer_id);
                    let boot = &self.bootstrap_peers;
                    // Stable sort: bootstrap relays first, then discovery order.
                    self.relay_candidates.sort_by_key(|p| !boot.contains(p));
                    self.try_reserve(swarm, now);
                }
            }
            SwarmEvent::Behaviour(AlterChatBehaviourEvent::RelayClient(ev)) => match ev {
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    ..
                } => {
                    if !renewal {
                        tracing::info!(relay = %relay_peer_id, "relay reservation accepted");
                    }
                    self.reserved.insert(*relay_peer_id);
                    self.relay_failures.remove(relay_peer_id);
                }
                relay::client::Event::OutboundCircuitEstablished { relay_peer_id, .. } => {
                    tracing::debug!(relay = %relay_peer_id, "outbound relay circuit established");
                }
                relay::client::Event::InboundCircuitEstablished { src_peer_id, .. } => {
                    tracing::debug!(peer = %src_peer_id, "inbound relay circuit established");
                }
            },
            SwarmEvent::Behaviour(AlterChatBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            })) => match result {
                Ok(_) => {
                    tracing::info!(peer = %remote_peer_id, "DCUtR: upgraded relayed connection to direct")
                }
                Err(e) => {
                    tracing::debug!(peer = %remote_peer_id, error = %e, "DCUtR: hole punch failed, staying relayed")
                }
            },
            SwarmEvent::ExternalAddrConfirmed { .. } | SwarmEvent::ExternalAddrExpired { .. } => {
                self.publish(swarm, now, false);
            }
            _ => {}
        }
        self.changes(&mut out);
        out
    }

    fn on_dial_error(
        &mut self,
        peer: Option<PeerId>,
        error: &DialError,
        now: Instant,
        out: &mut Vec<NatNotice>,
    ) {
        match &self.proxy {
            Some(ProxyMode::Socks5) | Some(ProxyMode::I2p) if is_proxy_failure(error) => {
                let kind = if matches!(self.proxy, Some(ProxyMode::I2p)) {
                    "I2P SOCKS proxy"
                } else {
                    "SOCKS5 proxy"
                };
                self.proxy_error(
                    now,
                    format!(
                        "The {kind} is not reachable, so AlterChat cannot connect to anyone \
                         (it never falls back to direct connections). Start the proxy again; \
                         AlterChat reconnects automatically."
                    ),
                    out,
                );
            }
            Some(ProxyMode::Tor)
                if self.connections == 0 && self.consecutive_failures >= TOR_FAILURE_THRESHOLD =>
            {
                self.proxy_error(
                    now,
                    "No peer could be reached through Tor. The Tor network may be blocked or \
                     unreachable from this network; AlterChat keeps retrying."
                        .to_string(),
                    out,
                );
            }
            _ => {
                tracing::debug!(?peer, error = %error, "outgoing connection failed");
            }
        }
    }

    fn mark_direct(&mut self, swarm: &mut Swarm<AlterChatBehaviour>) {
        if self.direct || self.proxy.is_some() {
            return;
        }
        self.direct = true;
        tracing::info!("publicly reachable without NAT");
        for addr in self.public_listen_addrs.clone() {
            swarm.add_external_address(addr);
        }
    }

    fn try_reserve(&mut self, swarm: &mut Swarm<AlterChatBehaviour>, now: Instant) {
        if !self.use_relays {
            return;
        }
        let mut active: HashSet<PeerId> = self.circuits.values().copied().collect();
        for relay in self.relay_candidates.clone() {
            if active.len() >= MAX_RELAYS {
                break;
            }
            if active.contains(&relay) || relay == self.local_peer_id {
                continue;
            }
            if self
                .last_attempt
                .get(&relay)
                .is_some_and(|t| now.duration_since(*t) < RESERVATION_RETRY)
            {
                continue;
            }
            let Some(addr) = self.relay_addrs.get(&relay) else {
                continue;
            };
            let circuit = circuit_listen_addr(addr, relay);
            self.last_attempt.insert(relay, now);
            match swarm.listen_on(circuit.clone()) {
                Ok(id) => {
                    tracing::info!(%circuit, "requesting relay reservation");
                    self.circuits.insert(id, relay);
                    active.insert(relay);
                }
                Err(e) => tracing::warn!(%circuit, error = %e, "relay listen failed"),
            }
        }
    }

    /// The addresses we publish: confirmed external addresses (relay
    /// circuits, plus public listen addresses when reachable directly).
    /// LAN addresses are never published.
    pub fn advertised_addrs(swarm: &Swarm<AlterChatBehaviour>) -> Vec<Multiaddr> {
        let mut addrs: Vec<Multiaddr> = swarm
            .external_addresses()
            .filter(|a| is_relayed(a) || ip_of(a).is_none_or(is_public_ip))
            .cloned()
            .collect();
        // Direct addresses first so dialers try them before relays.
        addrs.sort_by_key(is_relayed);
        addrs.dedup();
        addrs
    }

    fn publish(&mut self, swarm: &mut Swarm<AlterChatBehaviour>, now: Instant, periodic: bool) {
        let addrs = Self::advertised_addrs(swarm);
        if addrs.is_empty() {
            return;
        }
        if let Some((last, at)) = &self.published {
            let stale = now.duration_since(*at) >= REPUBLISH_INTERVAL;
            if *last == addrs && !(periodic && stale) {
                return;
            }
        }
        let Some(value) = seal_addr_record(&self.keypair, &addrs) else {
            return;
        };
        let record = kad::Record {
            key: addr_record_key(&self.local_peer_id),
            value,
            publisher: None,
            expires: None,
        };
        let _ = swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One);
        self.published = Some((addrs, now));
    }

    /// Periodic maintenance: retry reservations, re-dial bootstrap nodes
    /// when we lost every connection (e.g. the proxy came back), re-publish
    /// our address record.
    pub fn tick(&mut self, swarm: &mut Swarm<AlterChatBehaviour>, now: Instant) -> Vec<NatNotice> {
        let mut out = Vec::new();
        self.settled = true;
        self.try_reserve(swarm, now);
        if self.connections == 0 && self.pending_dials.is_empty() {
            for addr in self.bootstrap.clone() {
                let _ = swarm.dial(addr);
            }
        }
        self.publish(swarm, now, true);
        self.changes(&mut out);
        out
    }

    /// Looks up the signed address records of `peers` that are not
    /// connected (rate limited per peer).
    pub fn lookup_peers(
        &mut self,
        swarm: &mut Swarm<AlterChatBehaviour>,
        peers: impl IntoIterator<Item = PeerId>,
        now: Instant,
    ) {
        for peer in peers {
            if peer == self.local_peer_id || swarm.is_connected(&peer) {
                continue;
            }
            if self
                .last_lookup
                .get(&peer)
                .is_some_and(|t| now.duration_since(*t) < LOOKUP_INTERVAL)
            {
                continue;
            }
            self.last_lookup.insert(peer, now);
            swarm
                .behaviour_mut()
                .kademlia
                .get_record(addr_record_key(&peer));
        }
    }

    /// Handles a DHT record; returns true if it was a valid address record.
    /// Its addresses are added to the swarm's address book (used by
    /// request-response) and the peer is dialed on all of them at once,
    /// direct and relayed.
    pub fn on_record(
        &mut self,
        swarm: &mut Swarm<AlterChatBehaviour>,
        record: &kad::Record,
    ) -> bool {
        let Some(peer_record) = open_addr_record(record.key.as_ref(), &record.value, now_secs())
        else {
            return false;
        };
        let peer = peer_record.peer_id();
        if peer == self.local_peer_id {
            return true;
        }
        let addrs = self.dialable(peer_record.addresses());
        for addr in &addrs {
            swarm.add_peer_address(peer, addr.clone());
        }
        if !addrs.is_empty() && !swarm.is_connected(&peer) {
            let opts = DialOpts::peer_id(peer)
                .addresses(addrs)
                .extend_addresses_through_behaviour()
                .build();
            if let Err(e) = swarm.dial(opts) {
                tracing::debug!(%peer, error = %e, "dial from address record failed");
            }
        }
        true
    }

    /// In proxy modes only relay circuits and (for SOCKS5) TCP addresses can
    /// be dialed; drop the rest so no direct traffic is attempted.
    fn dialable(&self, addrs: &[Multiaddr]) -> Vec<Multiaddr> {
        addrs
            .iter()
            .filter(|a| {
                self.proxy.is_none()
                    || is_relayed(a)
                    || !a
                        .iter()
                        .any(|p| matches!(p, Protocol::QuicV1 | Protocol::Udp(_)))
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_record_roundtrip_and_binding() {
        let kp = Keypair::generate_ed25519();
        let peer = kp.public().to_peer_id();
        let relay = PeerId::random();
        let addr: Multiaddr = format!("/ip4/1.2.3.4/tcp/4001/p2p/{relay}/p2p-circuit")
            .parse()
            .unwrap();
        let value = seal_addr_record(&kp, std::slice::from_ref(&addr)).unwrap();
        let key = addr_record_key(&peer);
        let now = now_secs();
        let rec = open_addr_record(key.as_ref(), &value, now).expect("valid record");
        assert_eq!(rec.peer_id(), peer);
        assert_eq!(rec.addresses(), &[addr]);

        // Bound to the signer's key.
        let other = addr_record_key(&PeerId::random());
        assert!(open_addr_record(other.as_ref(), &value, now).is_none());
        // Stale or from the future.
        assert!(
            open_addr_record(key.as_ref(), &value, now + ADDR_RECORD_MAX_AGE_SECS + 5).is_none()
        );
        assert!(open_addr_record(key.as_ref(), &value, now - 3600).is_none());
        // Tampered.
        let mut bad = value.clone();
        let n = bad.len();
        bad[n - 1] ^= 1;
        assert!(open_addr_record(key.as_ref(), &bad, now).is_none());

        assert!(accept_addr_record(key.as_ref(), &value, None, now));
        assert!(accept_addr_record(key.as_ref(), &value, Some(&value), now));
        assert!(!accept_addr_record(key.as_ref(), &bad, None, now));
    }

    #[test]
    fn circuit_addr_and_ip_helpers() {
        let relay = PeerId::random();
        let base: Multiaddr = format!("/dns4/boot.example/tcp/4001/p2p/{relay}")
            .parse()
            .unwrap();
        let c = circuit_listen_addr(&base, relay);
        assert_eq!(
            c.to_string(),
            format!("/dns4/boot.example/tcp/4001/p2p/{relay}/p2p-circuit")
        );
        assert!(is_relayed(&c));
        assert_eq!(peer_id_of(&c), Some(relay));
        assert!(!is_public_ip("192.168.1.2".parse().unwrap()));
        assert!(!is_public_ip("100.64.3.4".parse().unwrap()));
        assert!(!is_public_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip("fd00::1".parse().unwrap()));
        assert!(is_public_ip("8.8.8.8".parse().unwrap()));
        assert!(is_public_ip("2001:4860::8888".parse().unwrap()));
    }

    #[test]
    fn proxy_failure_classification() {
        let addr: Multiaddr = "/ip4/1.2.3.4/tcp/1".parse().unwrap();
        let down = DialError::Transport(vec![(
            addr.clone(),
            TransportError::Other(std::io::Error::other(
                "SOCKS5 proxy 127.0.0.1:9050 is unreachable: connection refused",
            )),
        )]);
        assert!(is_proxy_failure(&down));
        let dest = DialError::Transport(vec![(
            addr,
            TransportError::Other(std::io::Error::other(
                "SOCKS5 proxy could not connect to the destination: host unreachable",
            )),
        )]);
        assert!(!is_proxy_failure(&dest));
        assert!(!is_proxy_failure(&DialError::Aborted));
    }

    #[test]
    fn proxy_errors_are_throttled() {
        let cfg = NetworkPrivacyConfig {
            proxy_mode: ProxyMode::Socks5,
            ..NetworkPrivacyConfig::default()
        };
        let mut nat = NatTraversal::new(Keypair::generate_ed25519(), &cfg, &[]);
        let t0 = Instant::now();
        let mut out = Vec::new();
        nat.proxy_error(t0, "a".into(), &mut out);
        nat.proxy_error(t0 + Duration::from_secs(10), "b".into(), &mut out);
        nat.proxy_error(t0 + PROXY_ERROR_THROTTLE, "c".into(), &mut out);
        assert_eq!(
            out,
            vec![
                NatNotice::ProxyError("a".into()),
                NatNotice::ProxyError("c".into())
            ]
        );
    }
}
