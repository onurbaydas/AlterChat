//! Direct-message sessions: X3DH + ML-KEM-768 handshake followed by the
//! Double Ratchet.
//!
//! Protocol summary:
//! - Whoever sends first is the *initiator*. It fetches the peer's signed
//!   prekey bundle, runs X3DH and attaches the X3DH [`InitialMessage`] to
//!   every outgoing message until the session is *confirmed* (a reply was
//!   decrypted or the responder acknowledged a message directly).
//! - The responder runs `receive_x3dh` on the first message it sees for an
//!   unknown session and initialises the Double Ratchet as Bob, using its
//!   signed prekey as the first ratchet key.
//! - Simultaneous initiation (both sides hold an unconfirmed initiator
//!   session) is resolved deterministically: the session started by the
//!   lexicographically lower peer id wins. The winner rejects messages on the
//!   losing session; the loser adopts the winner's session and re-encrypts
//!   its pending messages on it (the caller keeps an outbox keyed by
//!   message id, and the receiver deduplicates by message id).
//! - All peer-controlled input is decoded with size limits and never panics.
use crate::double_ratchet::{self, DrEnvelope, DrState};
use crate::x3dh::{self, InitialMessage, PreKeyBundle, SignedPreKeySecrets};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const DM_PROTOCOL_VERSION: u8 = 1;
/// Upper bound for one encoded [`DmMessage`] (network input).
pub const MAX_DM_WIRE_BYTES: u64 = 48 * 1024;
/// Upper bound for the message text.
pub const MAX_DM_TEXT_BYTES: usize = 16 * 1024;
/// Upper bound for one encoded prekey bundle (JSON).
pub const MAX_BUNDLE_BYTES: usize = 8 * 1024;
/// Bundles older than this are not used to start new sessions.
pub const MAX_BUNDLE_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Tolerated clock skew for bundle timestamps in the future.
const MAX_CLOCK_SKEW_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_SESSION_BYTES: u64 = 512 * 1024;

pub type MsgId = [u8; 16];
pub type SessionId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmError {
    InvalidPeerId,
    StaleBundle,
    Crypto(&'static str),
    Encoding,
    TooLarge,
}

impl std::fmt::Display for DmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmError::InvalidPeerId => write!(f, "peer id does not embed an Ed25519 key"),
            DmError::StaleBundle => write!(f, "prekey bundle is too old or from the future"),
            DmError::Crypto(e) => write!(f, "crypto error: {e}"),
            DmError::Encoding => write!(f, "encoding error"),
            DmError::TooLarge => write!(f, "message too large"),
        }
    }
}

impl std::error::Error for DmError {}

fn codec(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
}

/// Bounded bincode decoding for peer-controlled bytes.
pub fn decode_bounded<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: u64) -> Option<T> {
    if bytes.len() as u64 > limit {
        return None;
    }
    codec(limit).deserialize(bytes).ok()
}

/// Encoding counterpart of [`decode_bounded`].
pub fn encode_bounded<T: Serialize>(value: &T, limit: u64) -> Option<Vec<u8>> {
    codec(limit).serialize(value).ok()
}

/// Extracts the Ed25519 public key embedded in a libp2p peer id string.
pub fn ed25519_public_from_peer_id(peer_id: &str) -> Option<[u8; 32]> {
    let peer: libp2p::PeerId = peer_id.parse().ok()?;
    let mh = peer.as_ref();
    // Ed25519 peer ids use the identity multihash (code 0x00).
    if mh.code() != 0 {
        return None;
    }
    let pk = libp2p::identity::PublicKey::try_decode_protobuf(mh.digest()).ok()?;
    Some(pk.try_into_ed25519().ok()?.to_bytes())
}

/// Long-term local identity used by the DM protocol.
pub struct LocalIdentity {
    peer_id: String,
    ed_seed: Zeroizing<[u8; 32]>,
    ik_secret: Zeroizing<[u8; 32]>,
    ik_pub: [u8; 32],
}

impl LocalIdentity {
    /// `ed25519_seed` is the 32-byte secret of the libp2p identity keypair.
    pub fn from_ed25519_seed(peer_id: &str, ed25519_seed: &[u8; 32]) -> Self {
        let ik_secret = Zeroizing::new(x3dh::derive_x3dh_identity_secret(ed25519_seed));
        let ik_pub = *X25519PublicKey::from(&StaticSecret::from(*ik_secret)).as_bytes();
        Self {
            peer_id: peer_id.to_string(),
            ed_seed: Zeroizing::new(*ed25519_seed),
            ik_secret,
            ik_pub,
        }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn ed25519_seed(&self) -> &[u8; 32] {
        &self.ed_seed
    }

    fn ik(&self) -> StaticSecret {
        StaticSecret::from(*self.ik_secret)
    }

    /// Generates a new signed prekey. Persist the secrets before publishing.
    pub fn generate_signed_prekey(&self) -> (PreKeyBundle, SignedPreKeySecrets) {
        x3dh::generate_prekey_bundle(&self.ik_secret, &self.ed_seed)
    }
}

/// Parses and verifies a peer's bundle (JSON) against its peer id.
pub fn parse_and_verify_bundle(
    peer_id: &str,
    bytes: &[u8],
    now_ms: u64,
) -> Result<PreKeyBundle, DmError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(DmError::TooLarge);
    }
    let bundle: PreKeyBundle = serde_json::from_slice(bytes).map_err(|_| DmError::Encoding)?;
    let signer = ed25519_public_from_peer_id(peer_id).ok_or(DmError::InvalidPeerId)?;
    x3dh::verify_prekey_bundle(&bundle, &signer).map_err(DmError::Crypto)?;
    check_bundle_age(&bundle, now_ms)?;
    Ok(bundle)
}

fn check_bundle_age(bundle: &PreKeyBundle, now_ms: u64) -> Result<(), DmError> {
    if bundle.created_at > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || bundle.created_at.saturating_add(MAX_BUNDLE_AGE_MS) < now_ms
    {
        return Err(DmError::StaleBundle);
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// Persistent per-peer session state.
#[derive(Serialize, Deserialize, Clone)]
pub struct DmSession {
    pub session_id: SessionId,
    pub role: SessionRole,
    /// Initiator only: the responder is known to hold this session.
    pub confirmed: bool,
    /// Initiator only: attached to outgoing messages while not confirmed
    /// (kept after confirmation so the session can be re-announced).
    pub init: Option<InitialMessage>,
    /// `domain || IK_initiator || IK_responder`.
    pub ad: Vec<u8>,
    pub dr: DrState,
}

impl DmSession {
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        encode_bounded(self, MAX_SESSION_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        decode_bounded(bytes, MAX_SESSION_BYTES)
    }

    /// Unconfirmed initiator session (relevant for the simultaneous
    /// initiation tie-break).
    pub fn is_pending_initiator(&self) -> bool {
        self.role == SessionRole::Initiator && !self.confirmed
    }

    pub fn confirm(&mut self) {
        if self.role == SessionRole::Initiator {
            self.confirmed = true;
        }
    }

    /// Whether this side started the session.
    pub fn is_initiator(&self) -> bool {
        self.role == SessionRole::Initiator
    }

    /// Initiator only: attach the initial message again on the next
    /// messages (used after a tie-break rejection of a late/peer-reset init,
    /// so the peer can adopt this session). Returns whether it changed.
    pub fn reannounce(&mut self) -> bool {
        if self.role == SessionRole::Initiator && self.init.is_some() && self.confirmed {
            self.confirmed = false;
            return true;
        }
        false
    }
}

/// Decrypted DM content.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DmPlaintext {
    pub sender_nick: String,
    pub text: String,
    pub timestamp: i64,
    pub ttl: Option<i64>,
    /// Protocol-only message (session announcement); not shown to the user.
    pub control: bool,
}

impl DmPlaintext {
    /// Empty control message used to (re-)announce an initiator session.
    pub fn session_announce(timestamp: i64) -> Self {
        Self {
            sender_nick: String::new(),
            text: String::new(),
            timestamp,
            ttl: None,
            control: true,
        }
    }
}

impl DmPlaintext {
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        encode_bounded(self, MAX_DM_WIRE_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        decode_bounded(bytes, MAX_DM_WIRE_BYTES)
    }
}

/// What travels on the wire (direct request, onion payload or mailbox entry).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DmMessage {
    pub version: u8,
    pub msg_id: MsgId,
    pub session_id: SessionId,
    pub init: Option<InitialMessage>,
    pub envelope: DrEnvelope,
}

impl DmMessage {
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        encode_bounded(self, MAX_DM_WIRE_BYTES)
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        decode_bounded(bytes, MAX_DM_WIRE_BYTES)
    }
}

pub fn new_msg_id() -> MsgId {
    use rand::RngExt;
    let mut id = [0u8; 16];
    rand::rng().fill(&mut id);
    id
}

fn session_id_for(init: &InitialMessage) -> SessionId {
    let mut h = Sha256::new();
    h.update(b"AlterChat-DM-session-v1");
    h.update(init.identity_key);
    h.update(init.ephemeral_key);
    h.update(init.signed_prekey);
    h.update(&init.ml_kem_ct);
    h.finalize().into()
}

fn session_ad(ik_initiator: &[u8; 32], ik_responder: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(80);
    ad.extend_from_slice(b"AlterChat-DM-v1");
    ad.extend_from_slice(ik_initiator);
    ad.extend_from_slice(ik_responder);
    ad
}

fn message_ad(session: &DmSession, msg_id: &MsgId) -> Vec<u8> {
    let mut ad = session.ad.clone();
    ad.push(DM_PROTOCOL_VERSION);
    ad.extend_from_slice(&session.session_id);
    ad.extend_from_slice(msg_id);
    ad
}

/// Starts an initiator session from a peer's bundle (verifies signatures
/// against the Ed25519 key embedded in `peer_id`).
pub fn start_session(
    me: &LocalIdentity,
    peer_id: &str,
    bundle: &PreKeyBundle,
    now_ms: u64,
) -> Result<DmSession, DmError> {
    let signer = ed25519_public_from_peer_id(peer_id).ok_or(DmError::InvalidPeerId)?;
    check_bundle_age(bundle, now_ms)?;
    let (init, sk) =
        x3dh::initiate_x3dh(&me.ik(), &me.ed_seed, bundle, &signer).map_err(DmError::Crypto)?;
    let session_id = session_id_for(&init);
    let ad = session_ad(&me.ik_pub, &bundle.identity_key);
    let dr = double_ratchet::init_alice(sk, bundle.signed_prekey);
    Ok(DmSession {
        session_id,
        role: SessionRole::Initiator,
        confirmed: false,
        init: Some(init),
        ad,
        dr,
    })
}

/// Encrypts one message on `session` (mutates the ratchet).
pub fn encrypt_message(
    session: &mut DmSession,
    msg_id: MsgId,
    plaintext: &DmPlaintext,
) -> Result<DmMessage, DmError> {
    if plaintext.text.len() > MAX_DM_TEXT_BYTES || plaintext.sender_nick.len() > 256 {
        return Err(DmError::TooLarge);
    }
    let bytes = plaintext.to_bytes().ok_or(DmError::Encoding)?;
    let ad = message_ad(session, &msg_id);
    let envelope =
        double_ratchet::encrypt_with_ad(&mut session.dr, &bytes, &ad).map_err(DmError::Crypto)?;
    Ok(DmMessage {
        version: DM_PROTOCOL_VERSION,
        msg_id,
        session_id: session.session_id,
        init: if session.is_pending_initiator() {
            session.init.clone()
        } else {
            None
        },
        envelope,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The sender (higher peer id) sent an initial message while we hold a
    /// session we initiated: our session wins. The sender adopts ours when
    /// our initial message reaches it and re-sends. If our session was
    /// already confirmed, the caller should [`DmSession::reannounce`] it
    /// (once per rejected session id) so a peer that lost its state can
    /// converge.
    LostTieBreak,
    /// We do not know the session (or the prekey it targets): the sender
    /// should discard its session and start a new one.
    UnknownSession,
    /// The initial message was already consumed before.
    Replay,
    /// Malformed, unauthenticated or undecryptable.
    Invalid(&'static str),
}

impl RejectReason {
    /// Whether the sender should discard its session and re-handshake.
    pub fn sender_should_reset(&self) -> bool {
        matches!(self, RejectReason::UnknownSession | RejectReason::Replay)
    }
}

pub enum Incoming {
    /// Decrypted. Persist `session` as the current session for the peer.
    Delivered {
        plaintext: DmPlaintext,
        session: Box<DmSession>,
        /// A new responder session was created from an initial message
        /// (record its id as seen).
        new_session: bool,
        /// A previously stored session was replaced; pending outgoing
        /// messages must be re-encrypted on the new session.
        replaced_existing: bool,
    },
    Rejected(RejectReason),
}

/// Processes one incoming message from `peer_id` (already authenticated as
/// the transport-level sender, mailbox signer or sealed sender).
///
/// `lookup_spk` returns our signed-prekey secrets by public key;
/// `seen_session` reports whether an initial message was already consumed.
pub fn handle_incoming(
    me: &LocalIdentity,
    peer_id: &str,
    current: Option<&DmSession>,
    msg: &DmMessage,
    lookup_spk: &dyn Fn(&[u8; 32]) -> Option<SignedPreKeySecrets>,
    seen_session: &dyn Fn(&SessionId) -> bool,
) -> Incoming {
    if msg.version != DM_PROTOCOL_VERSION {
        return Incoming::Rejected(RejectReason::Invalid("unsupported version"));
    }

    if let Some(cur) = current.filter(|c| c.session_id == msg.session_id) {
        let mut session = cur.clone();
        let ad = message_ad(&session, &msg.msg_id);
        return match double_ratchet::decrypt_with_ad(&mut session.dr, &msg.envelope, &ad) {
            Ok(bytes) => match DmPlaintext::from_bytes(&bytes) {
                Some(plaintext) => {
                    // A decrypted reply proves the responder holds the session.
                    session.confirm();
                    Incoming::Delivered {
                        plaintext,
                        session: Box::new(session),
                        new_session: false,
                        replaced_existing: false,
                    }
                }
                None => Incoming::Rejected(RejectReason::Invalid("bad plaintext")),
            },
            Err(e) => Incoming::Rejected(RejectReason::Invalid(e)),
        };
    }

    let Some(init) = &msg.init else {
        return Incoming::Rejected(RejectReason::UnknownSession);
    };
    if session_id_for(init) != msg.session_id {
        return Incoming::Rejected(RejectReason::Invalid("session id mismatch"));
    }
    if let Some(cur) = current
        && cur.is_initiator()
        && me.peer_id.as_str() < peer_id
    {
        // Simultaneous initiation (or a late message from the peer's
        // discarded session): the lower peer id's session wins.
        return Incoming::Rejected(RejectReason::LostTieBreak);
    }
    if seen_session(&msg.session_id) {
        return Incoming::Rejected(RejectReason::Replay);
    }

    let Some(signer) = ed25519_public_from_peer_id(peer_id) else {
        return Incoming::Rejected(RejectReason::Invalid("peer id without Ed25519 key"));
    };
    let Some(spk) = lookup_spk(&init.signed_prekey) else {
        return Incoming::Rejected(RejectReason::UnknownSession);
    };
    let sk = match x3dh::receive_x3dh(&me.ik(), &spk, init, &signer) {
        Ok(sk) => sk,
        Err(e) => return Incoming::Rejected(RejectReason::Invalid(e)),
    };
    let mut session = DmSession {
        session_id: msg.session_id,
        role: SessionRole::Responder,
        confirmed: true,
        init: None,
        ad: session_ad(&init.identity_key, &me.ik_pub),
        dr: double_ratchet::init_bob(sk, spk.spk_secret, init.signed_prekey),
    };
    let ad = message_ad(&session, &msg.msg_id);
    match double_ratchet::decrypt_with_ad(&mut session.dr, &msg.envelope, &ad) {
        Ok(bytes) => match DmPlaintext::from_bytes(&bytes) {
            Some(plaintext) => Incoming::Delivered {
                plaintext,
                session: Box::new(session),
                new_session: true,
                replaced_existing: current.is_some(),
            },
            None => Incoming::Rejected(RejectReason::Invalid("bad plaintext")),
        },
        Err(e) => Incoming::Rejected(RejectReason::Invalid(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_id_key_extraction() {
        let kp = libp2p::identity::Keypair::generate_ed25519();
        let peer = kp.public().to_peer_id().to_string();
        let expected = kp.public().try_into_ed25519().unwrap().to_bytes();
        assert_eq!(ed25519_public_from_peer_id(&peer), Some(expected));
        assert_eq!(ed25519_public_from_peer_id("not-a-peer-id"), None);
        assert_eq!(ed25519_public_from_peer_id(""), None);
    }

    #[test]
    fn bounded_decoding_rejects_garbage() {
        assert!(DmMessage::from_bytes(&[0xff; 64]).is_none());
        assert!(DmMessage::from_bytes(&vec![0u8; (MAX_DM_WIRE_BYTES + 1) as usize]).is_none());
        // Huge length prefix must not allocate.
        let mut evil = vec![1u8];
        evil.extend_from_slice(&[0u8; 48]);
        evil.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(DmMessage::from_bytes(&evil).is_none());
        assert!(DmSession::from_bytes(&[1, 2, 3]).is_none());
    }
}
