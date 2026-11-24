//! Direct-message runtime: glues the protocol logic in `alterchat_core::dm`
//! and `alterchat_core::mailbox` to the database and the swarm.
//!
//! Delivery model:
//! - Every outgoing DM is written to the `dm_outbox` table first and stays
//!   there until the recipient acknowledges it directly (`X3dhDmAck`), the
//!   onion relay accepts it (onion mode, best effort), or it expires after
//!   [`OUTBOX_TTL_MS`] (the UI is told via `dm-delivery-failed`).
//! - No session yet: fetch the peer's prekey bundle (request-response
//!   `GetPrekeyBundle`, DHT record as fallback), run X3DH, then send.
//! - Peer unreachable: the pending messages (already Double Ratchet
//!   encrypted on the current session) are published as one signed mailbox
//!   record under the (recipient, sender) DHT key. Recipients poll the keys
//!   of their friends; duplicates are dropped by message id.
//! - Whenever the session changes (tie-break loss, peer reset), pending
//!   messages are re-encrypted on the new session and re-sent.
use crate::db;
use alterchat_core::dm::{self, DmMessage, DmPlaintext, Incoming, RejectReason};
use alterchat_core::file_transfer::{P2pRequest, P2pResponse};
use alterchat_core::libp2p::{kad, request_response::OutboundRequestId, PeerId, Swarm};
use alterchat_core::network::AlterChatBehaviour;
use alterchat_core::{crypto, mailbox, onion, x3dh};
use rusqlite::Connection;
use std::collections::HashMap;
use tauri::{AppHandle, Emitter};

pub const OUTBOX_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const RETRY_MIN_INTERVAL_MS: i64 = 60_000;
const BUNDLE_RETRY_MS: i64 = 30_000;
const MAILBOX_REPUBLISH_MS: i64 = 30_000;
const MAX_FLUSH: usize = 200;
const MAX_TRACKED: usize = 4096;
const MAX_POLLED_FRIENDS: usize = 256;
const SPK_ROTATE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const SPK_KEEP: usize = 3;
const RECEIVED_ID_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Ticks are 30 s apart (DHT check interval).
const MAILBOX_POLL_EVERY_TICKS: u64 = 4;
const ROTATION_CHECK_EVERY_TICKS: u64 = 120;

#[derive(Clone, serde::Serialize)]
pub struct PmPayload {
    pub peer_id: String,
    pub sender_nick: String,
    pub text: String,
    pub timestamp: i64,
    pub ttl: Option<i64>,
}

#[derive(Clone, serde::Serialize)]
pub struct DeliveryFailed {
    pub peer_id: String,
    pub reason: String,
}

enum Tracked {
    Dm {
        peer: String,
        msg_id: String,
        session_id: [u8; 32],
    },
    Bundle {
        peer: String,
    },
    Onion {
        msg_id: String,
    },
}

/// Result of processing one incoming DM.
pub struct Processed {
    pub ack: bool,
    pub reset: bool,
    pub flush: bool,
}

impl Processed {
    fn rejected(reset: bool) -> Self {
        Self {
            ack: false,
            reset,
            flush: false,
        }
    }

    pub fn response(&self) -> P2pResponse {
        P2pResponse::X3dhDmAck {
            success: self.ack,
            reset_session: self.reset,
        }
    }
}

pub struct DmCtx<'a> {
    pub app: &'a AppHandle,
    /// Static X25519 secret used by sealed sender / onion layers.
    pub offline_secret: &'a [u8; 32],
}

#[derive(Default)]
pub struct DmRuntime {
    me: Option<dm::LocalIdentity>,
    tracked: HashMap<OutboundRequestId, Tracked>,
    bundle_queries: HashMap<kad::QueryId, String>,
    bundle_requested_at: HashMap<String, i64>,
    mailbox_published_at: HashMap<String, i64>,
    tick: u64,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn parse_msg_id(hex_id: &str) -> Option<dm::MsgId> {
    hex::decode(hex_id).ok()?.try_into().ok()
}

fn load_session(conn: &Connection, peer: &str) -> Option<dm::DmSession> {
    db::load_dm_session(conn, peer)
        .ok()
        .flatten()
        .and_then(|b| dm::DmSession::from_bytes(&b))
}

fn save_session(conn: &Connection, peer: &str, session: &dm::DmSession) {
    if let Some(blob) = session.to_bytes() {
        let _ = db::save_dm_session(conn, peer, &blob);
    }
}

/// Incoming DMs are accepted only from non-blocked friends.
pub fn sender_allowed(conn: &Connection, peer: &str) -> bool {
    let blocked = db::get_peer_settings(conn, peer)
        .map(|s| s.blocked)
        .unwrap_or(false);
    !blocked
        && db::get_friends(conn)
            .map(|fs| fs.iter().any(|f| f.peer_id == peer && !f.blocked))
            .unwrap_or(false)
}

impl DmRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    fn track(&mut self, id: OutboundRequestId, t: Tracked) {
        if self.tracked.len() >= MAX_TRACKED {
            self.tracked.clear();
        }
        self.tracked.insert(id, t);
    }

    /// Called at login, before the swarm is stored.
    pub fn start(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        my_peer_id: &str,
        ed25519_seed: &[u8; 32],
    ) {
        self.me = Some(dm::LocalIdentity::from_ed25519_seed(
            my_peer_id,
            ed25519_seed,
        ));
        self.tracked.clear();
        self.bundle_queries.clear();
        self.bundle_requested_at.clear();
        self.mailbox_published_at.clear();
        let _ = db::prune_dm_received(conn, RECEIVED_ID_RETENTION_MS);
        self.maybe_rotate(conn, swarm, true);
        self.poll_mailboxes(conn, swarm);
    }

    /// Generates a new signed prekey when none exists or the newest is older
    /// than a week, then (re)publishes the newest bundle to the DHT.
    pub fn maybe_rotate(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        publish: bool,
    ) {
        let Some(me) = &self.me else { return };
        let latest = db::latest_signed_prekey(conn).ok().flatten();
        let stale = latest
            .as_ref()
            .map(|(_, created)| now_ms() - created > SPK_ROTATE_MS)
            .unwrap_or(true);
        if stale {
            let (bundle, secrets) = me.generate_signed_prekey();
            let Ok(json) = serde_json::to_string(&bundle) else {
                return;
            };
            if db::save_signed_prekey(
                conn,
                &bundle.signed_prekey,
                &secrets.spk_secret,
                &secrets.ml_kem_seed,
                &json,
                bundle.created_at as i64,
            )
            .is_err()
            {
                // Never publish a bundle whose secrets were not persisted.
                return;
            }
            let _ = db::prune_signed_prekeys(conn, SPK_KEEP);
            tracing::info!("X3DH signed prekey rotated");
        }
        if stale || publish {
            self.publish_bundle(conn, swarm);
        }
    }

    fn publish_bundle(&self, conn: &Connection, swarm: &mut Swarm<AlterChatBehaviour>) {
        let Some(me) = &self.me else { return };
        if let Ok(Some((json, _))) = db::latest_signed_prekey(conn) {
            let record = kad::Record {
                key: crypto::get_dht_prekey_bundle_key(me.peer_id()),
                value: json.into_bytes(),
                publisher: None,
                expires: None,
            };
            let _ = swarm
                .behaviour_mut()
                .kademlia
                .put_record(record, kad::Quorum::One);
        }
    }

    /// Answer to `GetPrekeyBundle`.
    pub fn bundle_response(&self, conn: &Connection) -> P2pResponse {
        P2pResponse::PrekeyBundle {
            bundle: db::latest_signed_prekey(conn)
                .ok()
                .flatten()
                .map(|(json, _)| json.into_bytes()),
        }
    }

    /// Queues a DM and tries to deliver it. Returns false if it was refused.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        peer: &str,
        plaintext: DmPlaintext,
        use_onion: bool,
    ) -> bool {
        if self.me.is_none() || dm::ed25519_public_from_peer_id(peer).is_none() {
            return false;
        }
        if plaintext.text.len() > dm::MAX_DM_TEXT_BYTES {
            let _ = ctx.app.emit(
                "dm-delivery-failed",
                DeliveryFailed {
                    peer_id: peer.to_string(),
                    reason: "message too large".into(),
                },
            );
            return false;
        }
        let Some(payload) = plaintext.to_bytes() else {
            return false;
        };
        let msg_id = hex::encode(dm::new_msg_id());
        if db::insert_dm_outbox(conn, &msg_id, peer, &payload, use_onion).is_err() {
            return false;
        }
        self.flush_peer(conn, swarm, ctx, peer, true);
        true
    }

    fn request_bundle(&mut self, swarm: &mut Swarm<AlterChatBehaviour>, peer: &str) {
        let now = now_ms();
        if self
            .bundle_requested_at
            .get(peer)
            .is_some_and(|t| now - t < BUNDLE_RETRY_MS)
        {
            return;
        }
        let Ok(pid) = peer.parse::<PeerId>() else {
            return;
        };
        if self.bundle_requested_at.len() >= MAX_TRACKED {
            self.bundle_requested_at.clear();
        }
        self.bundle_requested_at.insert(peer.to_string(), now);
        // Request-response first (dials if needed), DHT record as fallback.
        let rid = swarm
            .behaviour_mut()
            .request_response
            .send_request(&pid, P2pRequest::GetPrekeyBundle);
        self.track(
            rid,
            Tracked::Bundle {
                peer: peer.to_string(),
            },
        );
        let qid = swarm
            .behaviour_mut()
            .kademlia
            .get_record(crypto::get_dht_prekey_bundle_key(peer));
        if self.bundle_queries.len() >= MAX_TRACKED {
            self.bundle_queries.clear();
        }
        self.bundle_queries.insert(qid, peer.to_string());
    }

    fn on_bundle(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        peer: &str,
        bytes: &[u8],
    ) -> bool {
        let Ok(bundle) = dm::parse_and_verify_bundle(peer, bytes, now_ms() as u64) else {
            return false;
        };
        let Ok(json) = serde_json::to_string(&bundle) else {
            return false;
        };
        let _ = db::save_prekey_bundle(conn, peer, &json);
        self.bundle_requested_at.remove(peer);
        self.flush_peer(conn, swarm, ctx, peer, true);
        true
    }

    fn cached_bundle(conn: &Connection, peer: &str) -> Option<x3dh::PreKeyBundle> {
        let json = db::load_prekey_bundle(conn, peer).ok().flatten()?;
        match dm::parse_and_verify_bundle(peer, json.as_bytes(), now_ms() as u64) {
            Ok(b) => Some(b),
            Err(_) => {
                let _ = db::delete_prekey_bundle(conn, peer);
                None
            }
        }
    }

    /// Encrypts pending messages for `peer` on the current session (starting
    /// one if needed) and sends them. `force` ignores the retry back-off.
    pub fn flush_peer(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        peer: &str,
        force: bool,
    ) {
        let Some(me) = &self.me else { return };
        let Ok(pid) = peer.parse::<PeerId>() else {
            return;
        };
        let entries = db::list_dm_outbox(conn, peer, MAX_FLUSH).unwrap_or_default();
        if entries.is_empty() {
            return;
        }
        let mut session = match load_session(conn, peer) {
            Some(s) => s,
            None => {
                let started = Self::cached_bundle(conn, peer)
                    .and_then(|b| dm::start_session(me, peer, &b, now_ms() as u64).ok());
                match started {
                    Some(s) => s,
                    None => {
                        let _ = db::delete_prekey_bundle(conn, peer);
                        self.request_bundle(swarm, peer);
                        return;
                    }
                }
            }
        };
        let sid_hex = hex::encode(session.session_id);
        let now = now_ms();
        let mut to_send: Vec<(String, Vec<u8>, bool)> = Vec::new();
        for e in entries {
            let mut fresh = false;
            let wire = match (&e.wire, &e.session_id) {
                (Some(w), Some(sid)) if *sid == sid_hex => w.clone(),
                _ => {
                    let (Some(pt), Some(msg_id)) =
                        (DmPlaintext::from_bytes(&e.payload), parse_msg_id(&e.msg_id))
                    else {
                        let _ = db::delete_dm_outbox(conn, &e.msg_id);
                        continue;
                    };
                    match dm::encrypt_message(&mut session, msg_id, &pt)
                        .ok()
                        .and_then(|m| m.to_bytes())
                    {
                        Some(w) => {
                            let _ = db::set_dm_outbox_wire(conn, &e.msg_id, &w, &sid_hex);
                            fresh = true;
                            w
                        }
                        None => {
                            let _ = db::delete_dm_outbox(conn, &e.msg_id);
                            let _ = ctx.app.emit(
                                "dm-delivery-failed",
                                DeliveryFailed {
                                    peer_id: peer.to_string(),
                                    reason: "encryption failed".into(),
                                },
                            );
                            continue;
                        }
                    }
                }
            };
            // Newly (re-)encrypted messages go out at once; others back off.
            if force || fresh || now - e.last_attempt >= RETRY_MIN_INTERVAL_MS {
                to_send.push((e.msg_id, wire, e.use_onion));
            }
        }
        // Persist the ratchet before anything leaves the process.
        save_session(conn, peer, &session);

        let connected = swarm.is_connected(&pid);
        for (msg_id, wire, use_onion) in to_send {
            let _ = db::mark_dm_outbox_attempt(conn, &msg_id);
            if use_onion && self.send_onion(conn, swarm, ctx, peer, &msg_id, &wire) {
                continue;
            }
            let rid = swarm
                .behaviour_mut()
                .request_response
                .send_request(&pid, P2pRequest::X3dhDm { message: wire });
            self.track(
                rid,
                Tracked::Dm {
                    peer: peer.to_string(),
                    msg_id,
                    session_id: session.session_id,
                },
            );
        }
        if !connected {
            self.publish_mailbox(conn, swarm, peer);
        }
    }

    /// Onion route: up to two random relay friends, then the recipient.
    fn send_onion(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        peer: &str,
        msg_id: &str,
        wire: &[u8],
    ) -> bool {
        let Some(me) = &self.me else { return false };
        let friends = db::get_friends(conn).unwrap_or_default();
        let decode = |hex_key: &Option<String>| -> Option<[u8; 32]> {
            hex::decode(hex_key.as_deref()?).ok()?.try_into().ok()
        };
        let Some(target_pk) = friends
            .iter()
            .find(|f| f.peer_id == peer)
            .and_then(|f| decode(&f.offline_pubkey))
        else {
            return false;
        };
        let candidates: Vec<(String, [u8; 32])> = friends
            .iter()
            .filter(|f| f.peer_id != peer && f.peer_id != me.peer_id() && !f.blocked)
            .filter_map(|f| Some((f.peer_id.clone(), decode(&f.offline_pubkey)?)))
            .collect();
        let relays = onion::pick_relays(&candidates, 2);
        let Some(first) = relays.first().and_then(|(p, _)| p.parse::<PeerId>().ok()) else {
            return false;
        };
        let Ok(req_bytes) = bincode::serialize(&P2pRequest::X3dhDm {
            message: wire.to_vec(),
        }) else {
            return false;
        };
        let Ok(sealed) = crypto::sealed_send(
            ctx.offline_secret,
            me.peer_id().to_string(),
            &target_pk,
            &req_bytes,
        ) else {
            return false;
        };
        let Ok(sealed_bytes) = bincode::serialize(&sealed) else {
            return false;
        };
        let mut route = relays;
        route.push((peer.to_string(), target_pk));
        let Some(packet) = onion::wrap_onion(&route, sealed_bytes)
            .ok()
            .and_then(|p| bincode::serialize(&p).ok())
        else {
            return false;
        };
        let rid = swarm
            .behaviour_mut()
            .request_response
            .send_request(&first, P2pRequest::OnionForward { packet });
        self.track(
            rid,
            Tracked::Onion {
                msg_id: msg_id.to_string(),
            },
        );
        true
    }

    /// Publishes pending messages for an unreachable peer as one signed
    /// mailbox record (debounced per peer).
    fn publish_mailbox(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        peer: &str,
    ) {
        let Some(me) = &self.me else { return };
        let now = now_ms();
        if self
            .mailbox_published_at
            .get(peer)
            .is_some_and(|t| now - t < MAILBOX_REPUBLISH_MS)
        {
            return;
        }
        let Some(session) = load_session(conn, peer) else {
            return;
        };
        let sid_hex = hex::encode(session.session_id);
        let entries: Vec<Vec<u8>> = db::list_dm_outbox(conn, peer, MAX_FLUSH)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| e.session_id.as_deref() == Some(sid_hex.as_str()))
            .filter_map(|e| e.wire)
            .collect();
        if entries.is_empty() {
            return;
        }
        let Ok(value) =
            mailbox::seal_mailbox(me.ed25519_seed(), me.peer_id(), peer, &entries, now as u64)
        else {
            return;
        };
        let record = kad::Record {
            key: kad::RecordKey::new(&mailbox::mailbox_key(peer, me.peer_id())),
            value,
            publisher: None,
            expires: Some(
                std::time::Instant::now()
                    + std::time::Duration::from_millis(mailbox::MAILBOX_TTL_MS),
            ),
        };
        if swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
            .is_ok()
        {
            let _ = db::mark_dm_outbox_mailboxed(conn, peer);
            if self.mailbox_published_at.len() >= MAX_TRACKED {
                self.mailbox_published_at.clear();
            }
            self.mailbox_published_at.insert(peer.to_string(), now);
        }
    }

    /// Processes one DM from an authenticated sender (transport peer,
    /// verified mailbox signer or verified sealed sender).
    pub fn process(
        &mut self,
        conn: &Connection,
        ctx: &DmCtx,
        peer: &str,
        msg: &DmMessage,
    ) -> Processed {
        let Some(me) = &self.me else {
            return Processed::rejected(false);
        };
        if !sender_allowed(conn, peer) {
            return Processed::rejected(false);
        }
        let id_hex = hex::encode(msg.msg_id);
        if db::is_dm_received(conn, peer, &id_hex).unwrap_or(false) {
            return Processed {
                ack: true,
                reset: false,
                flush: false,
            };
        }
        let current = load_session(conn, peer);
        let lookup = |spk: &[u8; 32]| {
            db::load_signed_prekey(conn, spk)
                .ok()
                .flatten()
                .map(|(spk_secret, ml_kem_seed)| x3dh::SignedPreKeySecrets {
                    spk_secret,
                    ml_kem_seed,
                })
        };
        let seen = |sid: &dm::SessionId| {
            db::is_dm_session_seen(conn, peer, &hex::encode(sid)).unwrap_or(false)
        };
        match dm::handle_incoming(me, peer, current.as_ref(), msg, &lookup, &seen) {
            Incoming::Delivered {
                plaintext,
                session,
                new_session,
                ..
            } => {
                save_session(conn, peer, &session);
                if new_session {
                    let _ = db::mark_dm_session_seen(conn, peer, &hex::encode(session.session_id));
                }
                let _ = db::record_dm_received(conn, peer, &id_hex);
                if !plaintext.control {
                    let _ = db::save_private_message(
                        conn,
                        peer,
                        false,
                        &plaintext.text,
                        plaintext.timestamp,
                        plaintext.ttl,
                    );
                    let _ = ctx.app.emit(
                        "new-private-message",
                        PmPayload {
                            peer_id: peer.to_string(),
                            sender_nick: plaintext.sender_nick,
                            text: plaintext.text,
                            timestamp: plaintext.timestamp,
                            ttl: plaintext.ttl,
                        },
                    );
                }
                // Re-encrypt pending messages if the session changed, and
                // deliver anything waiting for this peer.
                Processed {
                    ack: true,
                    reset: false,
                    flush: true,
                }
            }
            Incoming::Rejected(RejectReason::LostTieBreak) => {
                let sid_hex = hex::encode(msg.session_id);
                let first = !db::is_dm_session_seen(conn, peer, &sid_hex).unwrap_or(true);
                if first {
                    let _ = db::mark_dm_session_seen(conn, peer, &sid_hex);
                    if let Some(mut cur) = current {
                        // Our session was already confirmed: make sure the
                        // peer learns it (it may have lost its state).
                        if cur.reannounce() {
                            save_session(conn, peer, &cur);
                            if let Some(payload) =
                                DmPlaintext::session_announce(now_ms()).to_bytes()
                            {
                                let _ = db::insert_dm_outbox(
                                    conn,
                                    &hex::encode(dm::new_msg_id()),
                                    peer,
                                    &payload,
                                    false,
                                );
                            }
                        }
                    }
                }
                Processed {
                    ack: false,
                    reset: false,
                    flush: first,
                }
            }
            Incoming::Rejected(reason) => {
                tracing::debug!("DM from {peer} rejected: {reason:?}");
                Processed::rejected(reason.sender_should_reset())
            }
        }
    }

    /// Handles an inbound `X3dhDm` request; returns the response to send and
    /// whether the outbox for the peer should be flushed afterwards.
    pub fn on_dm_request(
        &mut self,
        conn: &Connection,
        ctx: &DmCtx,
        peer: &str,
        message: &[u8],
    ) -> Processed {
        match DmMessage::from_bytes(message) {
            Some(msg) => self.process(conn, ctx, peer, &msg),
            None => Processed::rejected(false),
        }
    }

    pub fn on_response(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        request_id: OutboundRequestId,
        response: P2pResponse,
    ) {
        let Some(tracked) = self.tracked.remove(&request_id) else {
            return;
        };
        match (tracked, response) {
            (
                Tracked::Dm {
                    peer,
                    msg_id,
                    session_id,
                },
                P2pResponse::X3dhDmAck {
                    success,
                    reset_session,
                },
            ) => {
                let current = load_session(conn, &peer);
                if success {
                    let _ = db::delete_dm_outbox(conn, &msg_id);
                    if let Some(mut s) = current.filter(|s| s.session_id == session_id) {
                        if s.is_pending_initiator() {
                            s.confirm();
                            save_session(conn, &peer, &s);
                        }
                    }
                } else if reset_session {
                    if current.is_some_and(|s| s.session_id == session_id) {
                        tracing::info!("DM session with {peer} reset by peer");
                        let _ = db::delete_dm_session(conn, &peer);
                        let _ = db::delete_prekey_bundle(conn, &peer);
                    }
                    self.flush_peer(conn, swarm, ctx, &peer, true);
                }
            }
            (Tracked::Bundle { peer }, P2pResponse::PrekeyBundle { bundle: Some(b) }) => {
                self.on_bundle(conn, swarm, ctx, &peer, &b);
            }
            (Tracked::Onion { msg_id }, P2pResponse::OnionAck { success: true }) => {
                // Best effort: the first relay accepted the packet; there is
                // no end-to-end acknowledgement on the onion path.
                let _ = db::delete_dm_outbox(conn, &msg_id);
            }
            _ => {}
        }
    }

    pub fn on_outbound_failure(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        request_id: OutboundRequestId,
    ) {
        if let Some(Tracked::Dm { peer, .. }) = self.tracked.remove(&request_id) {
            self.publish_mailbox(conn, swarm, &peer);
        }
    }

    pub fn on_connected(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        peer: &PeerId,
    ) {
        let peer = peer.to_string();
        if !db::list_dm_outbox(conn, &peer, 1)
            .unwrap_or_default()
            .is_empty()
        {
            self.flush_peer(conn, swarm, ctx, &peer, true);
        }
    }

    /// Periodic work (every 30 s): expiry, retries, mailbox polling and
    /// prekey rotation.
    pub fn on_tick(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
    ) {
        if self.me.is_none() {
            return;
        }
        self.tick = self.tick.wrapping_add(1);
        for (peer, _msg_id, mailboxed) in
            db::expire_dm_outbox(conn, OUTBOX_TTL_MS).unwrap_or_default()
        {
            let _ = ctx.app.emit(
                "dm-delivery-failed",
                DeliveryFailed {
                    peer_id: peer,
                    reason: if mailboxed {
                        "not confirmed by the recipient within 7 days (was left in the offline mailbox)".into()
                    } else {
                        "recipient unreachable for 7 days".into()
                    },
                },
            );
        }
        for peer in db::list_dm_outbox_peers(conn).unwrap_or_default() {
            self.flush_peer(conn, swarm, ctx, &peer, false);
        }
        if self.tick.is_multiple_of(MAILBOX_POLL_EVERY_TICKS) {
            self.poll_mailboxes(conn, swarm);
        }
        if self.tick.is_multiple_of(ROTATION_CHECK_EVERY_TICKS) {
            self.maybe_rotate(conn, swarm, true);
        }
    }

    pub fn poll_mailboxes(&mut self, conn: &Connection, swarm: &mut Swarm<AlterChatBehaviour>) {
        let Some(me) = &self.me else { return };
        let friends = db::get_friends(conn).unwrap_or_default();
        for f in friends
            .iter()
            .filter(|f| !f.blocked)
            .take(MAX_POLLED_FRIENDS)
        {
            swarm
                .behaviour_mut()
                .kademlia
                .get_record(kad::RecordKey::new(&mailbox::mailbox_key(
                    me.peer_id(),
                    &f.peer_id,
                )));
        }
    }

    /// Handles a record found by a DHT query (prekey bundle or mailbox).
    pub fn on_record(
        &mut self,
        conn: &Connection,
        swarm: &mut Swarm<AlterChatBehaviour>,
        ctx: &DmCtx,
        query: kad::QueryId,
        record: &kad::Record,
    ) {
        let Some(me) = &self.me else { return };
        if let Some(peer) = self.bundle_queries.get(&query).cloned() {
            if self.on_bundle(conn, swarm, ctx, &peer, &record.value) {
                self.bundle_queries.remove(&query);
            }
            return;
        }
        let key = record.key.to_vec();
        if !mailbox::is_mailbox_key(&key) {
            return;
        }
        let me_id = me.peer_id().to_string();
        let allowed = |p: &str| sender_allowed(conn, p);
        let Ok(opened) =
            mailbox::open_mailbox(&key, &record.value, &me_id, now_ms() as u64, &allowed)
        else {
            return;
        };
        for msg in &opened.messages {
            self.process(conn, ctx, &opened.sender, msg);
        }
        self.flush_peer(conn, swarm, ctx, &opened.sender, false);
    }
}

/// Final onion hop: dispatches a sealed `X3dhDm` through the same DM path.
/// The sealed-sender X25519 key must equal the claimed friend's stored key.
pub fn onion_final_hop(
    rt: &mut DmRuntime,
    conn: &Connection,
    swarm: &mut Swarm<AlterChatBehaviour>,
    ctx: &DmCtx,
    sender_pubkey: [u8; 32],
    sender_peer_id: &str,
    message: &[u8],
) -> bool {
    let key_matches = db::get_friends(conn)
        .unwrap_or_default()
        .iter()
        .find(|f| f.peer_id == sender_peer_id && !f.blocked)
        .and_then(|f| f.offline_pubkey.as_deref())
        .and_then(|h| hex::decode(h).ok())
        .is_some_and(|pk| pk.as_slice() == sender_pubkey.as_slice());
    if !key_matches {
        return false;
    }
    let Some(msg) = DmMessage::from_bytes(message) else {
        return false;
    };
    let processed = rt.process(conn, ctx, sender_peer_id, &msg);
    if processed.flush {
        rt.flush_peer(conn, swarm, ctx, sender_peer_id, false);
    }
    processed.ack
}
