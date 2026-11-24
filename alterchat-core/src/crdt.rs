//! Group room state as an Automerge CRDT.
//!
//! # Message authenticity
//! Every message is stored as one bytes value under its own root key
//! (`m/<msg_id>`): a bincode [`Record`] holding the fields, the author's
//! protobuf-encoded libp2p public key and an Ed25519 signature over a canonical
//! encoding of `(room_id, msg_id, peer_id, sender, text, timestamp, ttl)` (see
//! [`signing_payload`]). One Automerge op per message keeps changes small;
//! Automerge 0.9's per-op cost grows with document size. [`Room::get_messages`]
//! re-checks the signature against the *current* CRDT value and requires
//! `peer_id == PeerId(pubkey)`. Messages that fail are still returned but with
//! `verified == false`, so the UI can flag them instead of silently trusting
//! them (an edit made by another member to someone else's message shows up as
//! unverified, which is more useful than having it vanish).
//!
//! # Wire format (incremental sync)
//! Nothing on the wire carries the whole document any more. A payload is
//! `nonce(12) || AES-256-GCM(room_key, bincode(ChangeBundle), aad)` where
//! [`ChangeBundle`] holds a list of raw Automerge change chunks. Gossip
//! publishes carry exactly the change produced by [`Room::add_message`];
//! catch-up goes through [`Room::sync_response`] (changes the requester is
//! missing given its heads, chunked to [`MAX_SYNC_CHUNK_BYTES`]).
//! Old whole-document gossip payloads are rejected (alpha: no wire backward
//! compatibility). Documents stored locally in the old layout still load and
//! their `messages` list is shown as unverified legacy history.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload, rand_core::RngCore},
};
use automerge::{
    AutoCommit, Change, ChangeHash, ObjType, ROOT, ReadDoc, ScalarValue, transaction::Transactable,
};
use bincode::Options;
use libp2p::identity::{Keypair, PublicKey};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum UTF-8 size of a message body.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 size of a nickname.
pub const MAX_NICK_BYTES: usize = 128;
/// Maximum size of a single Automerge change accepted from the network.
pub const MAX_CHANGE_BYTES: usize = 48 * 1024;
/// Maximum number of changes in one bundle.
pub const MAX_CHANGES_PER_BUNDLE: usize = 8192;
/// Target plaintext size of one sync response chunk.
pub const MAX_SYNC_CHUNK_BYTES: usize = 512 * 1024;
/// Hard limit for any encrypted payload handed to [`Room::apply_remote`].
pub const MAX_PAYLOAD_BYTES: usize = MAX_SYNC_CHUNK_BYTES + MAX_CHANGE_BYTES + 4096;
/// Maximum number of heads accepted in a sync request.
pub const MAX_SYNC_HEADS: usize = 64;

const MSG_KEY_PREFIX: &str = "m/";
const SIGNING_DOMAIN: &[u8] = b"alterchat/room-msg/v1\0";
const CHANGES_AAD: &[u8] = b"alterchat/room-changes/v1";
const TAG_DOMAIN: &[u8] = b"alterchat/room-tag/v1";
const BUNDLE_VERSION: u8 = 1;
const VERIFY_CACHE_MAX: usize = 100_000;

#[derive(Debug, Clone)]
pub struct CrdtMessage {
    pub id: String,
    pub peer_id: String,
    pub sender: String,
    pub text: String,
    pub timestamp: i64,
    pub ttl: Option<i64>,
    /// Signature valid and `peer_id` matches the signing key.
    pub verified: bool,
}

/// Result of merging a remote payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// The document heads changed (new data became visible).
    pub changed: bool,
    /// Some received changes wait for dependencies we do not have yet;
    /// the caller should request a sync from the sender.
    pub missing_deps: bool,
}

/// One chunk of a sync response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncChunk {
    /// Encrypted [`ChangeBundle`]; empty when the requester is up to date.
    pub payload: Vec<u8>,
    /// More changes remain; re-request with the new heads after applying.
    pub more: bool,
    /// The requester announced heads we do not know: it has data we lack.
    pub requester_ahead: bool,
}

#[derive(Serialize, Deserialize)]
struct ChangeBundle {
    v: u8,
    changes: Vec<Vec<u8>>,
}

pub struct Room {
    pub id: String,
    pub doc: AutoCommit,
    encryption_key: [u8; 32],
    verify_cache: RefCell<HashMap<[u8; 32], bool>>,
}

fn derive_room_key(id: &str, password: Option<&str>) -> [u8; 32] {
    let mut key = [0u8; 32];
    match password {
        Some(pwd) => pbkdf2_hmac::<Sha256>(pwd.as_bytes(), id.as_bytes(), 100_000, &mut key),
        // Parolasız oda: oda adından deterministik anahtar türet.
        // Gizli değil — ağ trafiğini şifreler, içerik güvenliği için şifre gerekir.
        None => pbkdf2_hmac::<Sha256>(b"alterchat-open-room", id.as_bytes(), 1_000, &mut key),
    }
    key
}

fn bincode_opts() -> impl Options {
    bincode::DefaultOptions::new().with_limit(MAX_PAYLOAD_BYTES as u64)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Canonical byte string signed by a message author.
pub fn signing_payload(
    room_id: &str,
    msg_id: &str,
    peer_id: &str,
    sender: &str,
    text: &str,
    timestamp: i64,
    ttl: Option<i64>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNING_DOMAIN.len() + text.len() + 128);
    out.extend_from_slice(SIGNING_DOMAIN);
    for field in [room_id, msg_id, peer_id, sender, text] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out.extend_from_slice(&timestamp.to_be_bytes());
    match ttl {
        Some(t) => {
            out.push(1);
            out.extend_from_slice(&t.to_be_bytes());
        }
        None => out.push(0),
    }
    out
}

const RECORD_VERSION: u8 = 1;

/// Serialized form of a message inside the CRDT (value of `m/<msg_id>`).
#[derive(Serialize, Deserialize)]
struct Record<'a> {
    v: u8,
    peer_id: &'a str,
    sender: &'a str,
    text: &'a str,
    timestamp: i64,
    ttl: Option<i64>,
    pubkey: &'a [u8],
    sig: &'a [u8],
}

/// Fields of a message as stored in the CRDT.
struct StoredMessage<'a> {
    msg_id: &'a str,
    peer_id: &'a str,
    sender: &'a str,
    text: &'a str,
    timestamp: i64,
    ttl: Option<i64>,
    pubkey: Vec<u8>,
    sig: Vec<u8>,
}

impl Room {
    pub fn new(id: String, password: Option<&str>) -> Self {
        Room {
            encryption_key: derive_room_key(&id, password),
            id,
            doc: AutoCommit::new(),
            verify_cache: RefCell::new(HashMap::new()),
        }
    }

    pub fn load(id: String, bytes: &[u8], password: Option<&str>) -> Result<Self, String> {
        let mut room = Room::new(id, password);
        let decrypted = room.decrypt_payload(bytes, None)?;
        room.doc = AutoCommit::load(&decrypted).map_err(|e| e.to_string())?;
        Ok(room)
    }

    /// Opaque identifier for sync requests: only peers holding the room key
    /// can link it to this room.
    pub fn sync_tag(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(TAG_DOMAIN);
        h.update(self.encryption_key);
        h.finalize().to_vec()
    }

    fn encrypt_payload(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 12 bytes
        let ciphertext = match aad {
            Some(aad) => cipher.encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            ),
            None => cipher.encrypt(&nonce, plaintext),
        }
        .map_err(|_| "Encryption failed".to_string())?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_payload(&self, payload: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, String> {
        if payload.len() < 12 {
            return Err("Payload too short for decryption".to_string());
        }
        let (nonce_bytes, ciphertext) = payload.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.encryption_key));
        match aad {
            Some(aad) => cipher.decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            ),
            None => cipher.decrypt(nonce, ciphertext),
        }
        .map_err(|_| "Decryption failed (wrong password?)".to_string())
    }

    /// Encrypted snapshot of the whole document, for local storage only.
    pub fn save(&mut self) -> Result<Vec<u8>, String> {
        let bytes = self.doc.save();
        self.encrypt_payload(&bytes, None)
    }

    fn encode_bundle(&self, changes: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
        let bundle = ChangeBundle {
            v: BUNDLE_VERSION,
            changes,
        };
        let plain = bincode_opts()
            .serialize(&bundle)
            .map_err(|e| e.to_string())?;
        self.encrypt_payload(&plain, Some(CHANGES_AAD))
    }

    /// Adds a message signed with `keypair` and returns the encrypted payload
    /// containing only the new change (to be padded and published).
    pub fn add_message(
        &mut self,
        keypair: &Keypair,
        sender: &str,
        text: &str,
        ttl: Option<i64>,
    ) -> Result<Vec<u8>, String> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(format!("Message too long (max {MAX_TEXT_BYTES} bytes)"));
        }
        if sender.len() > MAX_NICK_BYTES {
            return Err(format!("Nickname too long (max {MAX_NICK_BYTES} bytes)"));
        }
        let mut id_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut id_bytes);
        let msg_id: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let peer_id = keypair.public().to_peer_id().to_string();
        let timestamp = now_ms();
        let payload = signing_payload(&self.id, &msg_id, &peer_id, sender, text, timestamp, ttl);
        let sig = keypair.sign(&payload).map_err(|e| e.to_string())?;
        self.put_message(&StoredMessage {
            msg_id: &msg_id,
            peer_id: &peer_id,
            sender,
            text,
            timestamp,
            ttl,
            pubkey: keypair.public().encode_protobuf(),
            sig,
        })
    }

    fn put_message(&mut self, m: &StoredMessage<'_>) -> Result<Vec<u8>, String> {
        let key = format!("{MSG_KEY_PREFIX}{}", m.msg_id);
        let record = bincode_opts()
            .serialize(&Record {
                v: RECORD_VERSION,
                peer_id: m.peer_id,
                sender: m.sender,
                text: m.text,
                timestamp: m.timestamp,
                ttl: m.ttl,
                pubkey: &m.pubkey,
                sig: &m.sig,
            })
            .map_err(|e| e.to_string())?;
        if let Err(e) = self.doc.put(ROOT, key.as_str(), ScalarValue::Bytes(record)) {
            self.doc.rollback();
            return Err(e.to_string());
        }
        self.doc.commit();
        let change = self
            .doc
            .get_last_local_change()
            .ok_or("No local change produced")?;
        self.encode_bundle(vec![change.raw_bytes().to_vec()])
    }

    /// Decrypts and applies a change bundle from the network. Malformed input
    /// returns an error and leaves the document untouched.
    pub fn apply_remote(&mut self, payload: &[u8]) -> Result<ApplyOutcome, String> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err("Payload too large".to_string());
        }
        let plain = self.decrypt_payload(payload, Some(CHANGES_AAD))?;
        let bundle: ChangeBundle = bincode_opts()
            .deserialize(&plain)
            .map_err(|e| format!("Malformed change bundle: {e}"))?;
        if bundle.v != BUNDLE_VERSION {
            return Err(format!("Unsupported bundle version {}", bundle.v));
        }
        if bundle.changes.len() > MAX_CHANGES_PER_BUNDLE {
            return Err("Too many changes in bundle".to_string());
        }
        let mut changes = Vec::with_capacity(bundle.changes.len());
        for raw in &bundle.changes {
            if raw.len() > MAX_CHANGE_BYTES {
                return Err("Change too large".to_string());
            }
            changes.push(Change::try_from(&raw[..]).map_err(|e| format!("Bad change: {e}"))?);
        }
        let before = self.doc.get_heads();
        // Automerge is not designed for adversarial input; apply on the live
        // document but keep a copy so an error or panic cannot leave it half-merged.
        let backup = self.doc.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.doc.apply_changes(changes)
        }));
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                self.doc = backup;
                return Err(e.to_string());
            }
            Err(_) => {
                self.doc = backup;
                return Err("Change application panicked".to_string());
            }
        }
        let after = self.doc.get_heads();
        let missing_deps = !self.doc.get_missing_deps(&[]).is_empty();
        Ok(ApplyOutcome {
            changed: before != after,
            missing_deps,
        })
    }

    /// Current heads, for a sync request.
    pub fn heads(&mut self) -> Vec<Vec<u8>> {
        self.doc
            .get_heads()
            .into_iter()
            .map(|h| h.0.to_vec())
            .collect()
    }

    /// Builds the next chunk of changes a peer with `their_heads` is missing.
    pub fn sync_response(&mut self, their_heads: &[Vec<u8>]) -> Result<SyncChunk, String> {
        self.sync_response_limited(their_heads, MAX_SYNC_CHUNK_BYTES)
    }

    fn sync_response_limited(
        &mut self,
        their_heads: &[Vec<u8>],
        max_bytes: usize,
    ) -> Result<SyncChunk, String> {
        if their_heads.len() > MAX_SYNC_HEADS {
            return Err("Too many heads".to_string());
        }
        let mut known = Vec::with_capacity(their_heads.len());
        let mut requester_ahead = false;
        for h in their_heads {
            let hash = ChangeHash::try_from(&h[..]).map_err(|_| "Bad head hash".to_string())?;
            if self.doc.get_change_by_hash(&hash).is_some() {
                known.push(hash);
            } else {
                requester_ahead = true;
            }
        }
        let changes = self.doc.get_changes(&known);
        let mut out = Vec::new();
        let mut size = 0usize;
        let mut more = false;
        for c in changes {
            let raw = c.raw_bytes();
            if !out.is_empty()
                && (size + raw.len() > max_bytes || out.len() >= MAX_CHANGES_PER_BUNDLE)
            {
                more = true;
                break;
            }
            size += raw.len();
            out.push(raw.to_vec());
        }
        let payload = if out.is_empty() {
            Vec::new()
        } else {
            self.encode_bundle(out)?
        };
        Ok(SyncChunk {
            payload,
            more,
            requester_ahead,
        })
    }

    fn verify_cached(&self, m: &StoredMessage<'_>) -> bool {
        let payload = signing_payload(
            &self.id,
            m.msg_id,
            m.peer_id,
            m.sender,
            m.text,
            m.timestamp,
            m.ttl,
        );
        let mut h = Sha256::new();
        h.update(&payload);
        h.update((m.pubkey.len() as u32).to_be_bytes());
        h.update(&m.pubkey);
        h.update(&m.sig);
        let cache_key: [u8; 32] = h.finalize().into();
        if let Some(v) = self.verify_cache.borrow().get(&cache_key) {
            return *v;
        }
        let ok = verify_signature(m.peer_id, &m.pubkey, &payload, &m.sig);
        let mut cache = self.verify_cache.borrow_mut();
        if cache.len() >= VERIFY_CACHE_MAX {
            cache.clear();
        }
        cache.insert(cache_key, ok);
        ok
    }

    fn get_str(&self, obj: &automerge::ObjId, key: &str) -> String {
        self.doc
            .get(obj, key)
            .ok()
            .flatten()
            .and_then(|(v, _)| v.to_str().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    fn get_i64(&self, obj: &automerge::ObjId, key: &str) -> Option<i64> {
        self.doc
            .get(obj, key)
            .ok()
            .flatten()
            .and_then(|(v, _)| v.to_i64())
    }

    /// All messages sorted by (timestamp, id), each with its verification status.
    pub fn get_messages(&self) -> Result<Vec<CrdtMessage>, String> {
        let now = now_ms();
        let mut result = Vec::new();

        for key in self.doc.keys(ROOT) {
            let Some(msg_id) = key.strip_prefix(MSG_KEY_PREFIX) else {
                continue;
            };
            let Some((value, _)) = self.doc.get(ROOT, key.as_str()).ok().flatten() else {
                continue;
            };
            // Anything that is not a well-formed record is ignored.
            let Some(bytes) = value.to_bytes() else {
                continue;
            };
            let Ok(r) = bincode_opts().deserialize::<Record<'_>>(bytes) else {
                continue;
            };
            if r.v != RECORD_VERSION {
                continue;
            }
            let verified = self.verify_cached(&StoredMessage {
                msg_id,
                peer_id: r.peer_id,
                sender: r.sender,
                text: r.text,
                timestamp: r.timestamp,
                ttl: r.ttl,
                pubkey: r.pubkey.to_vec(),
                sig: r.sig.to_vec(),
            });
            result.push(build_message(
                msg_id.to_string(),
                r.peer_id.to_string(),
                r.sender.to_string(),
                r.text.to_string(),
                r.timestamp,
                r.ttl,
                verified,
                now,
            ));
        }

        // Legacy layout (pre-signature): a `messages` list. Shown, never verified.
        if let Some((value, list)) = self.doc.get(ROOT, "messages").ok().flatten()
            && value.to_objtype() == Some(ObjType::List)
        {
            for i in 0..self.doc.length(&list) {
                if let Some((_, obj)) = self.doc.get(&list, i).ok().flatten() {
                    result.push(build_message(
                        format!("legacy-{i}"),
                        self.get_str(&obj, "peer_id"),
                        self.get_str(&obj, "sender"),
                        self.get_str(&obj, "text"),
                        self.get_i64(&obj, "timestamp").unwrap_or(0),
                        self.get_i64(&obj, "ttl"),
                        false,
                        now,
                    ));
                }
            }
        }

        result.sort_by(|a, b| a.timestamp.cmp(&b.timestamp).then_with(|| a.id.cmp(&b.id)));
        Ok(result)
    }
}

fn verify_signature(peer_id: &str, pubkey: &[u8], payload: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = PublicKey::try_decode_protobuf(pubkey) else {
        return false;
    };
    if pk.to_peer_id().to_string() != peer_id {
        return false;
    }
    pk.verify(payload, sig)
}

#[allow(clippy::too_many_arguments)]
fn build_message(
    id: String,
    peer_id: String,
    sender: String,
    text: String,
    timestamp: i64,
    ttl: Option<i64>,
    verified: bool,
    now: i64,
) -> CrdtMessage {
    let expired = ttl.is_some_and(|t| now.saturating_sub(timestamp) > t.saturating_mul(1000));
    CrdtMessage {
        id,
        peer_id,
        sender,
        text: if expired {
            "[MESSAGE EXPIRED]".to_string()
        } else {
            text
        },
        timestamp,
        ttl,
        verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kp() -> Keypair {
        Keypair::generate_ed25519()
    }

    /// Pull everything `to` is missing from `from`, chunk by chunk.
    fn catch_up(from: &mut Room, to: &mut Room, max_bytes: usize) -> usize {
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 1000, "sync did not terminate");
            let chunk = from.sync_response_limited(&to.heads(), max_bytes).unwrap();
            if !chunk.payload.is_empty() {
                to.apply_remote(&chunk.payload).unwrap();
            }
            if !chunk.more {
                return rounds;
            }
        }
    }

    fn texts(room: &Room) -> Vec<String> {
        room.get_messages()
            .unwrap()
            .into_iter()
            .map(|m| m.text)
            .collect()
    }

    #[test]
    fn signed_message_verifies() {
        let key = kp();
        let mut room = Room::new("r".into(), None);
        room.add_message(&key, "alice", "hello", Some(3600))
            .unwrap();
        let msgs = room.get_messages().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].verified);
        assert_eq!(msgs[0].peer_id, key.public().to_peer_id().to_string());
        assert_eq!(msgs[0].text, "hello");
        assert_eq!(msgs[0].ttl, Some(3600));
    }

    fn forged(room: &mut Room, m: StoredMessage<'_>) -> CrdtMessage {
        room.put_message(&m).unwrap();
        room.get_messages()
            .unwrap()
            .into_iter()
            .find(|x| x.id == m.msg_id)
            .unwrap()
    }

    #[test]
    fn wrong_key_rejected() {
        let (a, b) = (kp(), kp());
        let mut room = Room::new("r".into(), None);
        let peer_b = b.public().to_peer_id().to_string();
        let payload = signing_payload("r", "x1", &peer_b, "bob", "hi", 1, None);
        // Signed by A, but claims B's key and peer id.
        let m = forged(
            &mut room,
            StoredMessage {
                msg_id: "x1",
                peer_id: &peer_b,
                sender: "bob",
                text: "hi",
                timestamp: 1,
                ttl: None,
                pubkey: b.public().encode_protobuf(),
                sig: a.sign(&payload).unwrap(),
            },
        );
        assert!(!m.verified);
    }

    #[test]
    fn spoofed_peer_id_rejected() {
        let (a, b) = (kp(), kp());
        let mut room = Room::new("r".into(), None);
        let peer_b = b.public().to_peer_id().to_string();
        // Valid signature by A over a payload naming B as author.
        let payload = signing_payload("r", "x2", &peer_b, "bob", "hi", 1, None);
        let m = forged(
            &mut room,
            StoredMessage {
                msg_id: "x2",
                peer_id: &peer_b,
                sender: "bob",
                text: "hi",
                timestamp: 1,
                ttl: None,
                pubkey: a.public().encode_protobuf(),
                sig: a.sign(&payload).unwrap(),
            },
        );
        assert!(!m.verified);
        // Garbage key bytes do not panic.
        let m = forged(
            &mut room,
            StoredMessage {
                msg_id: "x3",
                peer_id: &peer_b,
                sender: "bob",
                text: "hi",
                timestamp: 1,
                ttl: None,
                pubkey: vec![1, 2, 3],
                sig: vec![],
            },
        );
        assert!(!m.verified);
    }

    #[test]
    fn tampered_text_and_replay_rejected() {
        let key = kp();
        let mut alice = Room::new("r".into(), None);
        let mut mallory = Room::new("r".into(), None);
        let p = alice.add_message(&key, "alice", "pay 1", None).unwrap();
        mallory.apply_remote(&p).unwrap();
        let id = mallory.get_messages().unwrap()[0].id.clone();

        // Mallory rewrites Alice's record (keeping her key and signature)
        // through a regular CRDT change.
        let doc_key = format!("m/{id}");
        let (value, _) = mallory.doc.get(ROOT, doc_key.as_str()).unwrap().unwrap();
        let bytes = value.to_bytes().unwrap().to_vec();
        let mut r: Record<'_> = bincode_opts().deserialize(&bytes).unwrap();
        r.text = "pay 1000";
        let forged_bytes = bincode_opts().serialize(&r).unwrap();
        mallory
            .doc
            .put(ROOT, doc_key.as_str(), ScalarValue::Bytes(forged_bytes))
            .unwrap();
        mallory.doc.commit();
        let change = mallory.doc.get_last_local_change().unwrap();
        let p = mallory
            .encode_bundle(vec![change.raw_bytes().to_vec()])
            .unwrap();
        alice.apply_remote(&p).unwrap();
        let msgs = alice.get_messages().unwrap();
        assert_eq!(msgs[0].text, "pay 1000");
        assert!(!msgs[0].verified);

        // Copying a valid signature to another message id / room fails.
        let mut other = Room::new("other".into(), None);
        let ok = signing_payload(
            "r",
            "a",
            &key.public().to_peer_id().to_string(),
            "alice",
            "x",
            1,
            None,
        );
        let pid = key.public().to_peer_id().to_string();
        let m = forged(
            &mut other,
            StoredMessage {
                msg_id: "a",
                peer_id: &pid,
                sender: "alice",
                text: "x",
                timestamp: 1,
                ttl: None,
                pubkey: key.public().encode_protobuf(),
                sig: key.sign(&ok).unwrap(),
            },
        );
        assert!(!m.verified, "cross-room replay must fail");
    }

    #[test]
    fn incremental_changes_converge() {
        let (ka, kb) = (kp(), kp());
        let mut a = Room::new("room".into(), Some("pw"));
        let mut b = Room::new("room".into(), Some("pw"));
        let pa1 = a.add_message(&ka, "a", "a1", None).unwrap();
        let pb1 = b.add_message(&kb, "b", "b1", None).unwrap();
        let pa2 = a.add_message(&ka, "a", "a2", None).unwrap();
        // Out-of-order delivery: a2 before a1 is queued, then resolved.
        let out = b.apply_remote(&pa2).unwrap();
        assert!(out.missing_deps);
        let out = b.apply_remote(&pa1).unwrap();
        assert!(out.changed && !out.missing_deps);
        a.apply_remote(&pb1).unwrap();
        // Duplicate delivery is idempotent.
        let out = a.apply_remote(&pb1).unwrap();
        assert!(!out.changed);

        let ma = a.get_messages().unwrap();
        let mb = b.get_messages().unwrap();
        assert_eq!(ma.len(), 3);
        assert_eq!(texts(&a), texts(&b));
        assert!(ma.iter().chain(mb.iter()).all(|m| m.verified));
        assert_eq!(a.heads(), b.heads());

        // A different password cannot decrypt.
        let mut c = Room::new("room".into(), Some("other"));
        assert!(c.apply_remote(&pa1).is_err());
        assert_ne!(a.sync_tag(), c.sync_tag());
        assert_eq!(a.sync_tag(), b.sync_tag());
    }

    #[test]
    fn catch_up_from_empty_and_bidirectional() {
        let (ka, kb) = (kp(), kp());
        let mut a = Room::new("room".into(), None);
        for i in 0..50 {
            a.add_message(&ka, "a", &format!("msg {i}"), None).unwrap();
        }
        let mut b = Room::new("room".into(), None);
        catch_up(&mut a, &mut b, MAX_SYNC_CHUNK_BYTES);
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(b.get_messages().unwrap().len(), 50);

        // Up to date: empty response.
        let chunk = a.sync_response(&b.heads()).unwrap();
        assert!(chunk.payload.is_empty() && !chunk.more && !chunk.requester_ahead);

        // B writes offline; A notices B is ahead and pulls.
        b.add_message(&kb, "b", "from b", None).unwrap();
        let chunk = a.sync_response(&b.heads()).unwrap();
        assert!(chunk.requester_ahead);
        catch_up(&mut b, &mut a, MAX_SYNC_CHUNK_BYTES);
        assert_eq!(texts(&a), texts(&b));
        assert_eq!(a.get_messages().unwrap().len(), 51);
    }

    /// Fast bulk seeding: `n` unsigned records spread over `commits` changes.
    fn seed(room: &mut Room, n: usize, commits: usize) {
        let per = n.div_ceil(commits);
        for i in 0..n {
            let text = format!("message number {i} with some text");
            let record = bincode_opts()
                .serialize(&Record {
                    v: RECORD_VERSION,
                    peer_id: "seed",
                    sender: "seed",
                    text: &text,
                    timestamp: i as i64,
                    ttl: None,
                    pubkey: &[],
                    sig: &[],
                })
                .unwrap();
            room.doc
                .put(
                    ROOT,
                    format!("m/seed{i:06}").as_str(),
                    ScalarValue::Bytes(record),
                )
                .unwrap();
            if (i + 1) % per == 0 {
                room.doc.commit();
            }
        }
        room.doc.commit();
    }

    /// Per-message payload does not grow with room size, and a big backlog is
    /// synced in several bounded chunks. Kept small enough for debug builds;
    /// the 2000-message variant below is `#[ignore]`d.
    #[test]
    fn large_room_payloads_stay_small_and_chunked_sync_works() {
        let key = kp();
        let mut a = Room::new("big".into(), Some("pw"));
        let first = a.add_message(&key, "alice", "first", None).unwrap();
        seed(&mut a, 300, 30);
        let last = a.add_message(&key, "alice", "last!", None).unwrap();
        // Same size regardless of how many messages the room holds.
        assert!(
            last.len() <= first.len() + 64,
            "{} vs {}",
            last.len(),
            first.len()
        );
        let padded = crate::traffic::pad_message(&last).len();
        assert!(padded <= 1024, "per-message payload {padded}");
        // A whole-document broadcast would be much larger.
        assert!(a.doc.save_nocompress().len() > 10 * padded);

        let mut b = Room::new("big".into(), Some("pw"));
        let rounds = catch_up(&mut a, &mut b, 2 * 1024);
        assert!(rounds > 1, "expected chunking, got {rounds} round(s)");
        let mb = b.get_messages().unwrap();
        assert_eq!(mb.len(), 302);
        assert_eq!(mb.iter().filter(|m| m.verified).count(), 2);
        assert_eq!(a.heads(), b.heads());

        // Default chunk limit keeps every response under the payload cap.
        let mut c = Room::new("big".into(), Some("pw"));
        let chunk = a.sync_response(&c.heads()).unwrap();
        assert!(chunk.payload.len() <= MAX_PAYLOAD_BYTES);
        c.apply_remote(&chunk.payload).unwrap();
        assert_eq!(c.get_messages().unwrap().len(), 302);
    }

    /// Same with 2000 real signed messages. Slow in debug builds (minutes);
    /// run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn large_room_2000_signed_messages() {
        let key = kp();
        let mut a = Room::new("big".into(), Some("pw"));
        let mut max_payload = 0;
        for i in 0..2000 {
            let p = a
                .add_message(&key, "alice", &format!("message number {i}"), None)
                .unwrap();
            max_payload = max_payload.max(crate::traffic::pad_message(&p).len());
        }
        assert!(max_payload <= 1024, "per-message payload {max_payload}");
        let mut b = Room::new("big".into(), Some("pw"));
        assert!(catch_up(&mut a, &mut b, 64 * 1024) > 1);
        let mb = b.get_messages().unwrap();
        assert_eq!(mb.len(), 2000);
        assert!(mb.iter().all(|m| m.verified));
    }

    #[test]
    fn malformed_input_rejected_without_state_change() {
        let key = kp();
        let mut room = Room::new("r".into(), None);
        room.add_message(&key, "a", "keep me", None).unwrap();
        let heads = room.heads();

        let garbage: [Vec<u8>; 4] = [
            vec![],
            vec![0; 5],
            vec![0xAB; 200],
            vec![0; MAX_PAYLOAD_BYTES + 1],
        ];
        for g in &garbage {
            assert!(room.apply_remote(g).is_err());
        }
        // Correctly encrypted but semantically bad content.
        let bad_bincode = room
            .encrypt_payload(&[0xFF; 64], Some(CHANGES_AAD))
            .unwrap();
        assert!(room.apply_remote(&bad_bincode).is_err());
        let bad_change = room
            .encode_bundle(vec![vec![0x85, 0x6f, 0x4a, 0x83, 1, 2, 3]])
            .unwrap();
        assert!(room.apply_remote(&bad_change).is_err());
        let wrong_version = room
            .encrypt_payload(
                &bincode_opts()
                    .serialize(&ChangeBundle {
                        v: 9,
                        changes: vec![],
                    })
                    .unwrap(),
                Some(CHANGES_AAD),
            )
            .unwrap();
        assert!(room.apply_remote(&wrong_version).is_err());
        // Whole-doc snapshot (old wire format) is not accepted as a bundle.
        let snapshot = room.save().unwrap();
        assert!(room.apply_remote(&snapshot).is_err());

        // Sync request validation.
        assert!(room.sync_response(&[vec![1, 2, 3]]).is_err());
        let too_many: Vec<Vec<u8>> = std::iter::repeat_n(vec![0; 32], MAX_SYNC_HEADS + 1).collect();
        assert!(room.sync_response(&too_many).is_err());

        assert_eq!(room.heads(), heads);
        assert_eq!(texts(&room), vec!["keep me".to_string()]);

        // Limits on local input.
        assert!(
            room.add_message(&key, "a", &"x".repeat(MAX_TEXT_BYTES + 1), None)
                .is_err()
        );
        assert!(
            room.add_message(&key, &"n".repeat(MAX_NICK_BYTES + 1), "x", None)
                .is_err()
        );
    }

    #[test]
    fn save_load_round_trip_keeps_verification() {
        let key = kp();
        let mut room = Room::new("r".into(), Some("pw"));
        room.add_message(&key, "a", "persisted", None).unwrap();
        let saved = room.save().unwrap();
        let loaded = Room::load("r".into(), &saved, Some("pw")).unwrap();
        let msgs = loaded.get_messages().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].verified);
        assert!(Room::load("r".into(), &saved, Some("bad")).is_err());
    }

    #[test]
    fn legacy_list_shown_unverified() {
        let mut room = Room::new("r".into(), None);
        let list = room
            .doc
            .put_object(ROOT, "messages", ObjType::List)
            .unwrap();
        let m = room.doc.insert_object(&list, 0, ObjType::Map).unwrap();
        room.doc.put(&m, "text", "old").unwrap();
        room.doc.put(&m, "timestamp", 5i64).unwrap();
        room.doc.commit();
        let msgs = room.get_messages().unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].verified);
    }
}
