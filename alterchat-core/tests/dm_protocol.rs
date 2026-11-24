//! End-to-end tests for the DM protocol: X3DH + ML-KEM handshake, Double
//! Ratchet sessions, either-side-first, simultaneous initiation, the signed
//! DHT mailbox and onion final-hop delivery.
use alterchat_core::crypto;
use alterchat_core::dm::{
    self, DmMessage, DmPlaintext, DmSession, Incoming, LocalIdentity, MsgId, RejectReason,
    SessionId,
};
use alterchat_core::file_transfer::P2pRequest;
use alterchat_core::mailbox;
use alterchat_core::onion;
use alterchat_core::x3dh::{PreKeyBundle, SignedPreKeySecrets};
use std::collections::HashSet;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Minimal model of one client: what the Tauri backend persists in the DB.
struct Peer {
    id: String,
    me: LocalIdentity,
    bundle: PreKeyBundle,
    spk: SignedPreKeySecrets,
    session: Option<DmSession>,
    seen_sessions: HashSet<SessionId>,
    received_ids: HashSet<MsgId>,
    inbox: Vec<String>,
    /// Outbox: (msg_id, plaintext, session id it was last encrypted on).
    outbox: Vec<(MsgId, DmPlaintext, Option<SessionId>)>,
}

impl Peer {
    fn new() -> Self {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let id = kp.public().to_peer_id().to_string();
        let ed = kp.try_into_ed25519().unwrap();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(ed.secret().as_ref());
        let me = LocalIdentity::from_ed25519_seed(&id, &seed);
        let (bundle, spk) = me.generate_signed_prekey();
        Peer {
            id,
            me,
            bundle,
            spk,
            session: None,
            seen_sessions: HashSet::new(),
            received_ids: HashSet::new(),
            inbox: Vec::new(),
            outbox: Vec::new(),
        }
    }

    fn bundle_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.bundle).unwrap()
    }

    /// Queue + encrypt a message; starts an initiator session if needed.
    fn send(&mut self, to: &Peer, text: &str) -> DmMessage {
        let pt = DmPlaintext {
            sender_nick: self.id.clone(),
            text: text.to_string(),
            timestamp: 1,
            ttl: None,
            control: false,
        };
        self.queue(to, pt)
    }

    fn queue(&mut self, to: &Peer, pt: DmPlaintext) -> DmMessage {
        let msg_id = dm::new_msg_id();
        self.outbox.push((msg_id, pt, None));
        self.encrypt_pending(to).pop().unwrap()
    }

    /// Encrypts every outbox entry that is not encrypted on the current
    /// session (what the backend does after a session change).
    fn encrypt_pending(&mut self, to: &Peer) -> Vec<DmMessage> {
        if self.session.is_none() {
            let bundle = dm::parse_and_verify_bundle(&to.id, &to.bundle_json(), now()).unwrap();
            self.session = Some(dm::start_session(&self.me, &to.id, &bundle, now()).unwrap());
        }
        let session = self.session.as_mut().unwrap();
        let mut out = Vec::new();
        for (msg_id, pt, sid) in self.outbox.iter_mut() {
            if *sid != Some(session.session_id) {
                out.push(dm::encrypt_message(session, *msg_id, pt).unwrap());
                *sid = Some(session.session_id);
            }
        }
        out
    }

    fn receive(&mut self, from: &str, msg: &DmMessage) -> Result<bool, RejectReason> {
        // Wire round trip, as on the network.
        let msg = DmMessage::from_bytes(&msg.to_bytes().unwrap()).unwrap();
        if self.received_ids.contains(&msg.msg_id) {
            return Ok(false);
        }
        let spk = self.spk.clone();
        let spk_pub = self.bundle.signed_prekey;
        let lookup = move |k: &[u8; 32]| (k == &spk_pub).then(|| spk.clone());
        let seen = self.seen_sessions.clone();
        let seen_fn = move |s: &SessionId| seen.contains(s);
        match dm::handle_incoming(
            &self.me,
            from,
            self.session.as_ref(),
            &msg,
            &lookup,
            &seen_fn,
        ) {
            Incoming::Delivered {
                plaintext,
                session,
                new_session,
                ..
            } => {
                if new_session {
                    self.seen_sessions.insert(session.session_id);
                }
                // Session round trip through persistence.
                self.session = Some(DmSession::from_bytes(&session.to_bytes().unwrap()).unwrap());
                self.received_ids.insert(msg.msg_id);
                if !plaintext.control {
                    self.inbox.push(plaintext.text);
                }
                Ok(true)
            }
            Incoming::Rejected(r) => Err(r),
        }
    }

    /// Direct acknowledgement from the peer (transport-authenticated).
    fn acked(&mut self, msg: &DmMessage) {
        self.outbox.retain(|(id, _, _)| *id != msg.msg_id);
        if let Some(s) = self.session.as_mut()
            && s.session_id == msg.session_id
        {
            s.confirm();
        }
    }
}

/// Returns (lower peer id, higher peer id).
fn ordered_pair() -> (Peer, Peer) {
    let a = Peer::new();
    let b = Peer::new();
    if a.id < b.id { (a, b) } else { (b, a) }
}

fn deliver(from: &mut Peer, to: &mut Peer, msg: &DmMessage) -> Result<bool, RejectReason> {
    let r = to.receive(&from.id, msg);
    if r.is_ok() {
        from.acked(msg);
    }
    r
}

#[test]
fn full_handshake_then_conversation() {
    let (mut a, mut b) = ordered_pair();
    let m1 = a.send(&b, "hello");
    assert!(m1.init.is_some(), "first message carries the X3DH init");
    assert_eq!(m1.init.as_ref().unwrap().ml_kem_ct.len(), 1088);
    assert_eq!(deliver(&mut a, &mut b, &m1), Ok(true));
    // Ack confirms the session: no more init attached.
    let m2 = a.send(&b, "second");
    assert!(m2.init.is_none());
    assert_eq!(deliver(&mut a, &mut b, &m2), Ok(true));
    let r1 = b.send(&a, "reply");
    assert!(r1.init.is_none(), "responder never attaches an init");
    assert_eq!(deliver(&mut b, &mut a, &r1), Ok(true));
    assert_eq!(b.inbox, vec!["hello", "second"]);
    assert_eq!(a.inbox, vec!["reply"]);
}

fn either_side_first(first_is_lower: bool) {
    let (lo, hi) = ordered_pair();
    let (mut x, mut y) = if first_is_lower { (lo, hi) } else { (hi, lo) };
    let m1 = x.send(&y, "x1");
    let m2 = x.send(&y, "x2");
    // Out of order, and without an ack in between: both carry the init.
    assert!(m2.init.is_some());
    assert_eq!(y.receive(&x.id, &m2), Ok(true));
    assert_eq!(y.receive(&x.id, &m1), Ok(true));
    let r = y.send(&x, "y1");
    assert_eq!(x.receive(&y.id, &r), Ok(true));
    assert!(x.session.as_ref().unwrap().confirmed, "reply confirms");
    let m3 = x.send(&y, "x3");
    assert!(m3.init.is_none());
    assert_eq!(y.receive(&x.id, &m3), Ok(true));
    assert_eq!(y.inbox, vec!["x2", "x1", "x3"]);
    assert_eq!(x.inbox, vec!["y1"]);
}

#[test]
fn lower_peer_id_can_send_first() {
    either_side_first(true);
}

#[test]
fn higher_peer_id_can_send_first() {
    either_side_first(false);
}

fn simultaneous(winner_message_arrives_first: bool) {
    let (mut lo, mut hi) = ordered_pair();
    let lo1 = lo.send(&hi, "lo1");
    let hi1 = hi.send(&lo, "hi1");
    let hi2 = hi.send(&lo, "hi2");
    assert!(lo.session.as_ref().unwrap().is_pending_initiator());
    assert!(hi.session.as_ref().unwrap().is_pending_initiator());
    let lo_sid = lo.session.as_ref().unwrap().session_id;

    if winner_message_arrives_first {
        assert_eq!(deliver(&mut lo, &mut hi, &lo1), Ok(true));
        assert_eq!(
            deliver(&mut hi, &mut lo, &hi1),
            Err(RejectReason::LostTieBreak)
        );
    } else {
        assert_eq!(
            deliver(&mut hi, &mut lo, &hi1),
            Err(RejectReason::LostTieBreak)
        );
        assert_eq!(
            deliver(&mut hi, &mut lo, &hi2),
            Err(RejectReason::LostTieBreak)
        );
        assert_eq!(deliver(&mut lo, &mut hi, &lo1), Ok(true));
    }
    // The loser adopted the winner's session.
    assert_eq!(hi.session.as_ref().unwrap().session_id, lo_sid);
    // A late message from the loser's discarded session is still rejected.
    assert_eq!(
        deliver(&mut hi, &mut lo, &hi2),
        Err(RejectReason::LostTieBreak)
    );

    // The loser re-encrypts its pending messages on the winning session.
    let resent = hi.encrypt_pending(&lo);
    assert_eq!(resent.len(), 2, "both pending messages are re-sent");
    for m in &resent {
        assert_eq!(m.session_id, lo_sid);
        assert_eq!(deliver(&mut hi, &mut lo, m), Ok(true));
    }
    assert!(hi.outbox.is_empty() && lo.outbox.is_empty());
    assert_eq!(lo.inbox, vec!["hi1", "hi2"]);
    assert_eq!(hi.inbox, vec!["lo1"]);

    // Conversation continues in both directions on one session.
    let a = lo.send(&hi, "after-lo");
    let b = hi.send(&lo, "after-hi");
    assert_eq!(deliver(&mut lo, &mut hi, &a), Ok(true));
    assert_eq!(deliver(&mut hi, &mut lo, &b), Ok(true));
    assert_eq!(
        lo.session.as_ref().unwrap().session_id,
        hi.session.as_ref().unwrap().session_id
    );
}

#[test]
fn simultaneous_initiation_winner_first() {
    simultaneous(true);
}

#[test]
fn simultaneous_initiation_loser_first() {
    simultaneous(false);
}

#[test]
fn replay_and_unknown_session() {
    let (mut a, mut b) = ordered_pair();
    let m1 = a.send(&b, "one");
    assert_eq!(deliver(&mut a, &mut b, &m1), Ok(true));
    // Duplicate delivery is deduplicated by message id.
    assert_eq!(b.receive(&a.id, &m1), Ok(false));

    // Bob loses his session but keeps the seen-session list: replaying the
    // initial message with a fresh id must not resurrect the old session.
    b.session = None;
    b.received_ids.clear();
    assert_eq!(b.receive(&a.id, &m1), Err(RejectReason::Replay));
    assert!(RejectReason::Replay.sender_should_reset());

    // A message without init on a session Bob does not know asks for reset.
    let m2 = a.send(&b, "two");
    assert!(m2.init.is_none());
    let r = b.receive(&a.id, &m2);
    assert_eq!(r, Err(RejectReason::UnknownSession));
    assert!(r.unwrap_err().sender_should_reset());

    // Alice resets and re-sends on a fresh session: delivered.
    a.session = None;
    let resent = a.encrypt_pending(&b);
    assert_eq!(resent.len(), 1);
    assert!(resent[0].init.is_some());
    assert_eq!(deliver(&mut a, &mut b, &resent[0]), Ok(true));
    assert_eq!(b.inbox, vec!["one", "two"]);
}

#[test]
fn impersonation_and_tampering_rejected() {
    let (mut a, mut b) = ordered_pair();
    let mallory = Peer::new();
    let m1 = a.send(&b, "from alice");
    // Delivered as if it came from Mallory: identity signature does not match.
    assert!(matches!(
        b.receive(&mallory.id, &m1),
        Err(RejectReason::Invalid(_))
    ));
    // Tampered ciphertext.
    let mut t = m1.clone();
    t.envelope.ciphertext[0] ^= 1;
    assert!(matches!(
        b.receive(&a.id, &t),
        Err(RejectReason::Invalid(_))
    ));
    // Tampered message id (bound as associated data).
    let mut t = m1.clone();
    t.msg_id[0] ^= 1;
    assert!(b.receive(&a.id, &t).is_err());
    assert!(
        b.session.is_none(),
        "failed attempts do not create a session"
    );
    assert_eq!(b.receive(&a.id, &m1), Ok(true));

    // Bundle signed by someone else is refused for Bob's peer id.
    assert!(dm::parse_and_verify_bundle(&b.id, &mallory.bundle_json(), now()).is_err());
    assert!(dm::parse_and_verify_bundle(&b.id, b"{not json", now()).is_err());
    assert!(dm::parse_and_verify_bundle(&b.id, &b.bundle_json(), now()).is_ok());
    // Stale bundle refused.
    assert!(
        dm::parse_and_verify_bundle(&b.id, &b.bundle_json(), now() + 31 * 24 * 3600 * 1000)
            .is_err()
    );
}

#[test]
fn mailbox_roundtrip_and_forgery_rejection() {
    let (mut a, mut b) = ordered_pair();
    let mallory = Peer::new();
    let m1 = a.send(&b, "offline 1");
    let m2 = a.send(&b, "offline 2");
    let entries = vec![m1.to_bytes().unwrap(), m2.to_bytes().unwrap()];
    let key = mailbox::mailbox_key(&b.id, &a.id);
    let sealed_at = now();
    let value =
        mailbox::seal_mailbox(a.me.ed25519_seed(), &a.id, &b.id, &entries, sealed_at).unwrap();
    let friend_a = |p: &str| p == a.id;

    let opened = mailbox::open_mailbox(&key, &value, &b.id, now(), &friend_a).unwrap();
    assert_eq!(opened.sender, a.id);
    assert_eq!(opened.messages.len(), 2);
    for m in &opened.messages {
        assert_eq!(b.receive(&opened.sender, m), Ok(true));
    }
    assert_eq!(b.inbox, vec!["offline 1", "offline 2"]);
    // Re-reading the same record delivers nothing new.
    for m in &opened.messages {
        assert_eq!(b.receive(&opened.sender, m), Ok(false));
    }

    // Blocked / non-friend sender.
    assert_eq!(
        mailbox::open_mailbox(&key, &value, &b.id, now(), &|_| false).err(),
        Some(mailbox::MailboxError::SenderNotAllowed)
    );
    // Wrong recipient.
    let key_m = mailbox::mailbox_key(&mallory.id, &a.id);
    assert!(mailbox::open_mailbox(&key_m, &value, &mallory.id, now(), &friend_a).is_err());
    // Record moved to another key.
    let other = mailbox::mailbox_key(&b.id, &mallory.id);
    assert_eq!(
        mailbox::open_mailbox(&other, &value, &b.id, now(), &friend_a).err(),
        Some(mailbox::MailboxError::WrongKey)
    );
    // Mallory signs a record claiming to be Alice.
    let forged =
        mailbox::seal_mailbox(mallory.me.ed25519_seed(), &a.id, &b.id, &entries, now()).unwrap();
    assert_eq!(
        mailbox::open_mailbox(&key, &forged, &b.id, now(), &friend_a).err(),
        Some(mailbox::MailboxError::BadSignature)
    );
    // Bit flips anywhere are rejected (or at least never accepted as valid).
    for i in (0..value.len()).step_by(97) {
        let mut t = value.clone();
        t[i] ^= 0x40;
        assert!(mailbox::open_mailbox(&key, &t, &b.id, now(), &friend_a).is_err());
    }
    // Expired.
    assert_eq!(
        mailbox::open_mailbox(&key, &value, &b.id, now() + 8 * 24 * 3600 * 1000, &friend_a).err(),
        Some(mailbox::MailboxError::Expired)
    );
    assert!(mailbox::open_mailbox(&key, &[1, 2, 3], &b.id, now(), &friend_a).is_err());

    // DHT storage filter: no forged overwrite, no rollback, other keys pass.
    assert!(mailbox::accept_dht_record(&key, &value, None, now()));
    assert!(!mailbox::accept_dht_record(
        &key,
        &forged,
        Some(&value),
        now()
    ));
    assert!(!mailbox::accept_dht_record(
        &key,
        b"junk",
        Some(&value),
        now()
    ));
    let older = mailbox::seal_mailbox(
        a.me.ed25519_seed(),
        &a.id,
        &b.id,
        &entries,
        sealed_at - 1000,
    )
    .unwrap();
    assert!(!mailbox::accept_dht_record(
        &key,
        &older,
        Some(&value),
        now()
    ));
    assert!(mailbox::accept_dht_record(
        &key,
        &value,
        Some(&older),
        now()
    ));
    assert!(mailbox::accept_dht_record(
        b"other-key",
        b"anything",
        None,
        now()
    ));
}

#[test]
fn mailbox_respects_size_limits() {
    let (mut a, b) = ordered_pair();
    let entries: Vec<Vec<u8>> = (0..64)
        .map(|i| a.send(&b, &format!("m{i}")).to_bytes().unwrap())
        .collect();
    let value = mailbox::seal_mailbox(a.me.ed25519_seed(), &a.id, &b.id, &entries, now()).unwrap();
    assert!(value.len() <= mailbox::MAX_MAILBOX_RECORD_BYTES);
    let key = mailbox::mailbox_key(&b.id, &a.id);
    let opened = mailbox::open_mailbox(&key, &value, &b.id, now(), &|_| true).unwrap();
    assert!(opened.messages.len() <= mailbox::MAX_MAILBOX_ENTRIES);
    // The newest entries are kept.
    assert_eq!(
        opened.messages.last().unwrap().msg_id,
        DmMessage::from_bytes(entries.last().unwrap())
            .unwrap()
            .msg_id
    );
}

#[test]
fn onion_final_hop_delivers_x3dh_dm() {
    let (mut a, mut b) = ordered_pair();
    // Static X25519 "offline" keys used by sealed sender and onion layers.
    let a_offline = crypto::generate_static_secret();
    let b_offline = crypto::generate_static_secret();
    let r1 = crypto::generate_static_secret();
    let r2 = crypto::generate_static_secret();

    let m1 = a.send(&b, "via onion");
    let req = P2pRequest::X3dhDm {
        message: m1.to_bytes().unwrap(),
    };
    let req_bytes = bincode::serialize(&req).unwrap();
    let sealed = crypto::sealed_send(
        &a_offline,
        a.id.clone(),
        &crypto::get_public_key(&b_offline),
        &req_bytes,
    )
    .unwrap();
    let relays = onion::pick_relays(
        &[
            ("relay1".to_string(), crypto::get_public_key(&r1)),
            ("relay2".to_string(), crypto::get_public_key(&r2)),
        ],
        2,
    );
    assert_eq!(relays.len(), 2);
    let mut route = relays.clone();
    route.push((b.id.clone(), crypto::get_public_key(&b_offline)));
    let packet = onion::wrap_onion(&route, bincode::serialize(&sealed).unwrap()).unwrap();

    // Each relay peels one layer and forwards to the next hop.
    let secret_for = |name: &str| if name == "relay1" { r1 } else { r2 };
    let l1 = onion::peel_onion(&secret_for(&relays[0].0), &packet).unwrap();
    assert_eq!(l1.next_hop.as_deref(), Some(relays[1].0.as_str()));
    let l2 = onion::peel_onion(&secret_for(&relays[1].0), &l1.inner_packet.unwrap()).unwrap();
    assert_eq!(l2.next_hop.as_deref(), Some(b.id.as_str()));
    let last = onion::peel_onion(&b_offline, &l2.inner_packet.unwrap()).unwrap();
    assert!(last.next_hop.is_none());

    // Final hop: open the sealed request and dispatch it as a DM.
    let (sender_pk, sender_id, inner) =
        onion::open_sealed_request(&b_offline, &last.payload.unwrap()).unwrap();
    assert_eq!(sender_pk, crypto::get_public_key(&a_offline));
    assert_eq!(sender_id, a.id);
    let P2pRequest::X3dhDm { message } = inner else {
        panic!("expected X3dhDm");
    };
    let msg = DmMessage::from_bytes(&message).unwrap();
    assert_eq!(b.receive(&sender_id, &msg), Ok(true));
    assert_eq!(b.inbox, vec!["via onion"]);

    // Garbage payloads at the final hop are errors, not panics.
    assert!(onion::open_sealed_request(&b_offline, &[0xff; 100]).is_err());
}

#[test]
fn higher_peer_reset_converges_via_reannounce() {
    let (mut lo, mut hi) = ordered_pair();
    let m1 = lo.send(&hi, "before reset");
    assert_eq!(deliver(&mut lo, &mut hi, &m1), Ok(true));
    assert!(lo.session.as_ref().unwrap().confirmed);

    // The higher peer loses all state (new signed prekey, no session).
    let (bundle, spk) = hi.me.generate_signed_prekey();
    hi.bundle = bundle;
    hi.spk = spk;
    hi.session = None;
    hi.seen_sessions.clear();
    hi.received_ids.clear();

    // It sends first: the lower peer keeps its own (confirmed) session.
    let h1 = hi.send(&lo, "after reset");
    assert_eq!(
        deliver(&mut hi, &mut lo, &h1),
        Err(RejectReason::LostTieBreak)
    );
    // Lower peer re-announces its session with a control message.
    assert!(lo.session.as_mut().unwrap().reannounce());
    let ann = lo.queue(&hi, DmPlaintext::session_announce(2));
    assert!(ann.init.is_some());
    // The reset peer cannot use it (unknown signed prekey) and asks for reset.
    let r = deliver(&mut lo, &mut hi, &ann);
    assert_eq!(r, Err(RejectReason::UnknownSession));
    // Lower peer resets and re-sends pending messages on a fresh session.
    lo.session = None;
    let resent = lo.encrypt_pending(&hi);
    assert_eq!(resent.len(), 1);
    // The higher peer holds a pending initiator session and loses the tie.
    assert_eq!(deliver(&mut lo, &mut hi, &resent[0]), Ok(true));
    let again = hi.encrypt_pending(&lo);
    assert_eq!(again.len(), 1);
    assert_eq!(deliver(&mut hi, &mut lo, &again[0]), Ok(true));
    assert_eq!(lo.inbox, vec!["after reset"]);
    assert_eq!(hi.inbox, vec!["before reset"]);
    assert!(lo.outbox.is_empty() && hi.outbox.is_empty());
}
