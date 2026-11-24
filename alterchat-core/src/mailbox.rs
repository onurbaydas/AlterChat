//! Offline DHT mailbox for direct messages.
//!
//! One record per (recipient, sender) pair under the key
//! `MAILBOX_KEY_PREFIX || SHA256(recipient, sender)`. The value carries a list
//! of Double Ratchet [`DmMessage`]s (the same session as direct delivery, so
//! forward secrecy is preserved) and is signed with the sender's Ed25519
//! identity, the key embedded in the sender's peer id.
//!
//! - Recipients verify the signature, that the record is addressed to them,
//!   that the key matches the (recipient, sender) pair and that the sender is
//!   an allowed (non-blocked friend) peer; forgeries are dropped.
//! - DHT nodes running AlterChat validate inbound records under the mailbox
//!   prefix with [`accept_dht_record`] (Kademlia record filtering), so a third
//!   party cannot overwrite or roll back another sender's mailbox record on
//!   honest nodes.
//! - Deduplication by message id is the caller's job (persisted in the DB).
use crate::dm::{self, DmMessage};
use crate::x3dh::verify_ed25519;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAILBOX_KEY_PREFIX: &[u8] = b"/alterchat/mbox/1/";
pub const MAX_MAILBOX_ENTRIES: usize = 32;
/// Kademlia's default maximum record size is 65 KiB.
pub const MAX_MAILBOX_RECORD_BYTES: usize = 60 * 1024;
pub const MAILBOX_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_CLOCK_SKEW_MS: u64 = 10 * 60 * 1000;
const SIG_DOMAIN: &[u8] = b"AlterChat-mailbox-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxError {
    Malformed,
    WrongKey,
    WrongRecipient,
    BadSignature,
    SenderNotAllowed,
    Expired,
    TooLarge,
}

impl std::fmt::Display for MailboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for MailboxError {}

#[derive(Serialize, Deserialize)]
struct MailboxBody {
    version: u8,
    recipient: String,
    sender: String,
    created_at: u64,
    entries: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct MailboxRecord {
    body: Vec<u8>,
    signature: Vec<u8>,
}

pub fn mailbox_key(recipient: &str, sender: &str) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(SIG_DOMAIN);
    h.update((recipient.len() as u64).to_be_bytes());
    h.update(recipient.as_bytes());
    h.update((sender.len() as u64).to_be_bytes());
    h.update(sender.as_bytes());
    let mut key = MAILBOX_KEY_PREFIX.to_vec();
    key.extend_from_slice(&h.finalize());
    key
}

pub fn is_mailbox_key(key: &[u8]) -> bool {
    key.starts_with(MAILBOX_KEY_PREFIX)
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut m = SIG_DOMAIN.to_vec();
    m.extend_from_slice(body);
    m
}

/// Builds a signed mailbox record value. Keeps the newest entries that fit
/// into the size/count limits (`entries` is ordered oldest first).
pub fn seal_mailbox(
    sender_ed25519_seed: &[u8; 32],
    sender: &str,
    recipient: &str,
    entries: &[Vec<u8>],
    now_ms: u64,
) -> Result<Vec<u8>, MailboxError> {
    let budget = MAX_MAILBOX_RECORD_BYTES - 1024;
    let mut kept: Vec<Vec<u8>> = Vec::new();
    let mut size = 0usize;
    for entry in entries.iter().rev() {
        if kept.len() >= MAX_MAILBOX_ENTRIES || size + entry.len() + 8 > budget {
            break;
        }
        size += entry.len() + 8;
        kept.push(entry.clone());
    }
    kept.reverse();
    let body = MailboxBody {
        version: 1,
        recipient: recipient.to_string(),
        sender: sender.to_string(),
        created_at: now_ms,
        entries: kept,
    };
    let limit = MAX_MAILBOX_RECORD_BYTES as u64;
    let body = dm::encode_bounded(&body, limit).ok_or(MailboxError::TooLarge)?;
    let signature = SigningKey::from_bytes(sender_ed25519_seed)
        .sign(&signed_message(&body))
        .to_bytes()
        .to_vec();
    dm::encode_bounded(&MailboxRecord { body, signature }, limit).ok_or(MailboxError::TooLarge)
}

/// Verifies a record's structure, key binding, signature and age.
fn verify(key: &[u8], value: &[u8], now_ms: u64) -> Result<MailboxBody, MailboxError> {
    let limit = MAX_MAILBOX_RECORD_BYTES as u64;
    let record: MailboxRecord = dm::decode_bounded(value, limit).ok_or(MailboxError::Malformed)?;
    let body: MailboxBody =
        dm::decode_bounded(&record.body, limit).ok_or(MailboxError::Malformed)?;
    if body.version != 1 || body.entries.len() > MAX_MAILBOX_ENTRIES {
        return Err(MailboxError::Malformed);
    }
    if key != mailbox_key(&body.recipient, &body.sender).as_slice() {
        return Err(MailboxError::WrongKey);
    }
    let signer = dm::ed25519_public_from_peer_id(&body.sender).ok_or(MailboxError::BadSignature)?;
    if !verify_ed25519(&signer, &signed_message(&record.body), &record.signature) {
        return Err(MailboxError::BadSignature);
    }
    if body.created_at > now_ms.saturating_add(MAX_CLOCK_SKEW_MS)
        || body.created_at.saturating_add(MAILBOX_TTL_MS) < now_ms
    {
        return Err(MailboxError::Expired);
    }
    Ok(body)
}

pub struct OpenedMailbox {
    pub sender: String,
    pub created_at: u64,
    /// Entries that decoded as DM messages (others are skipped).
    pub messages: Vec<DmMessage>,
}

/// Opens a mailbox record addressed to `me`. `sender_allowed` must return
/// true only for non-blocked friends.
pub fn open_mailbox(
    key: &[u8],
    value: &[u8],
    me: &str,
    now_ms: u64,
    sender_allowed: &dyn Fn(&str) -> bool,
) -> Result<OpenedMailbox, MailboxError> {
    let body = verify(key, value, now_ms)?;
    if body.recipient != me {
        return Err(MailboxError::WrongRecipient);
    }
    if !sender_allowed(&body.sender) {
        return Err(MailboxError::SenderNotAllowed);
    }
    let messages = body
        .entries
        .iter()
        .filter_map(|e| DmMessage::from_bytes(e))
        .collect();
    Ok(OpenedMailbox {
        sender: body.sender,
        created_at: body.created_at,
        messages,
    })
}

/// Stores an inbound Kademlia PUT / ADD_PROVIDER when record filtering
/// (`StoreInserts::FilterBoth`) is enabled. Returns whether it was stored.
pub fn store_filtered_inbound(
    kad: &mut libp2p::kad::Behaviour<libp2p::kad::store::MemoryStore>,
    request: libp2p::kad::InboundRequest,
    now_ms: u64,
) -> bool {
    use libp2p::kad::store::RecordStore;
    match request {
        libp2p::kad::InboundRequest::PutRecord {
            record: Some(record),
            ..
        } => {
            let key = record.key.to_vec();
            let existing = kad.store_mut().get(&record.key).map(|r| r.value.clone());
            accept_dht_record(&key, &record.value, existing.as_deref(), now_ms)
                && kad.store_mut().put(record).is_ok()
        }
        libp2p::kad::InboundRequest::AddProvider {
            record: Some(record),
        } => kad.store_mut().add_provider(record).is_ok(),
        _ => false,
    }
}

/// Storage-side filter for inbound Kademlia PUTs. Address records are checked
/// by [`crate::nat::accept_addr_record`]; other records outside the mailbox
/// prefix are accepted unchanged. Mailbox records must be validly signed by
/// the sender named in them, bound to their key, fresh, and not older than
/// the record already stored (no rollback).
pub fn accept_dht_record(key: &[u8], value: &[u8], existing: Option<&[u8]>, now_ms: u64) -> bool {
    if crate::nat::is_addr_record_key(key) {
        // Signed peer address records (relay circuits), see `nat`.
        return crate::nat::accept_addr_record(key, value, existing, now_ms / 1000);
    }
    if !is_mailbox_key(key) {
        return true;
    }
    let Ok(new) = verify(key, value, now_ms) else {
        return false;
    };
    match existing.and_then(|old| verify(key, old, now_ms).ok()) {
        Some(old) => new.created_at >= old.created_at,
        None => true,
    }
}
