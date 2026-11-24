//! File transfer state machine used by the event loop in `lib.rs`.
//!
//! The pure protocol pieces (validation, sealing, chunk verification,
//! reassembly) live in `alterchat_core::transfer`; this module keeps the
//! per-session bookkeeping (who is sending what, outstanding requests,
//! timeouts, partial chunk files) and turns network events into
//! [`Notice`]s for the UI. It never touches the swarm directly: requests go
//! out through a `send` callback so the logic stays testable.

use crate::{db, AppCommand, AppState};
use alterchat_core::file_transfer::{P2pRequest, P2pResponse};
use alterchat_core::libp2p::{request_response::OutboundRequestId, PeerId};
use alterchat_core::storage::EncryptedChunk;
use alterchat_core::transfer::{self, FileOffer, IncomingTransfer};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager};

pub const DEFAULT_MAX_FILE_MB: i64 = 100;
pub const DEFAULT_MAX_CONCURRENT: i64 = 3;
/// Chunk requests kept in flight per incoming transfer (backpressure).
pub const CHUNK_WINDOW: usize = 4;
/// An offer the user has not answered is dropped after this.
pub const OFFER_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// An accepted transfer that makes no progress for this long is failed.
pub const STALL_TIMEOUT: Duration = Duration::from_secs(90);
/// The sender forgets an offer nobody pulled from for this long.
pub const OUTGOING_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const RECEIVE: &str = "receive";
const SEND: &str = "send";

/// User-configurable limits, stored as raw settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransferSettings {
    pub max_file_size_mb: i64,
    pub max_concurrent_transfers: i64,
}

impl Default for TransferSettings {
    fn default() -> Self {
        Self {
            max_file_size_mb: DEFAULT_MAX_FILE_MB,
            max_concurrent_transfers: DEFAULT_MAX_CONCURRENT,
        }
    }
}

impl TransferSettings {
    pub fn clamped(self) -> Self {
        Self {
            max_file_size_mb: self.max_file_size_mb.clamp(1, 4096),
            max_concurrent_transfers: self.max_concurrent_transfers.clamp(1, 16),
        }
    }

    pub fn load(conn: &rusqlite::Connection) -> Self {
        Self {
            max_file_size_mb: crate::setting_i64(conn, "file_max_size_mb", DEFAULT_MAX_FILE_MB),
            max_concurrent_transfers: crate::setting_i64(
                conn,
                "file_max_concurrent",
                DEFAULT_MAX_CONCURRENT,
            ),
        }
        .clamped()
    }

    pub fn save(self, conn: &rusqlite::Connection) -> rusqlite::Result<()> {
        let s = self.clamped();
        db::save_setting(conn, "file_max_size_mb", &s.max_file_size_mb.to_string())?;
        db::save_setting(
            conn,
            "file_max_concurrent",
            &s.max_concurrent_transfers.to_string(),
        )
    }

    pub fn max_file_bytes(self) -> u64 {
        self.clamped().max_file_size_mb as u64 * 1024 * 1024
    }

    pub fn max_concurrent(self) -> usize {
        self.clamped().max_concurrent_transfers as usize
    }
}

/// Local policy inputs for deciding whether an offer may reach the user.
pub struct OfferPolicy {
    pub blocked: bool,
    pub trust_level: i64,
    pub min_trust_file: i64,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub limits: TransferSettings,
}

#[derive(Clone, serde::Serialize)]
pub struct OfferEvent {
    pub transfer_id: String,
    pub peer_id: String,
    pub filename: String,
    pub size: u64,
    pub mime: Option<String>,
}

#[derive(Clone, serde::Serialize)]
pub struct ProgressEvent {
    pub transfer_id: String,
    pub peer_id: String,
    pub direction: &'static str,
    pub done_chunks: u64,
    pub total_chunks: u64,
    pub size: u64,
}

#[derive(Clone, serde::Serialize)]
pub struct FailedEvent {
    pub transfer_id: String,
    pub peer_id: String,
    pub direction: &'static str,
    pub reason: String,
}

#[derive(Clone, serde::Serialize)]
pub struct ReceivedEvent {
    pub transfer_id: String,
    pub peer_id: String,
    pub filename: String,
    pub path: String,
    pub size: u64,
}

#[derive(Clone, serde::Serialize)]
pub struct SentEvent {
    pub transfer_id: String,
    pub peer_id: String,
}

/// A completed incoming transfer waiting to be decrypted and written out.
pub struct FinalizeJob {
    pub transfer_id: String,
    pub peer: PeerId,
    pub state: IncomingTransfer,
    pub chunk_dir: PathBuf,
}

pub enum Notice {
    Progress(ProgressEvent),
    Failed(FailedEvent),
    Sent(SentEvent),
    Finalize(Box<FinalizeJob>),
}

struct Outgoing {
    peer: PeerId,
    offer: FileOffer,
    chunks: Arc<Vec<EncryptedChunk>>,
    served: HashSet<u64>,
    last_activity: Instant,
}

struct Incoming {
    peer: PeerId,
    state: IncomingTransfer,
    accepted: bool,
    created: Instant,
    last_progress: Instant,
    chunk_dir: PathBuf,
}

enum Pending {
    Offer(String),
    Chunk(String, u64),
}

/// Sends a request and returns its id (the swarm's `OutboundRequestId` in
/// production, a counter in tests).
pub type SendFn<'a, K> = dyn FnMut(PeerId, P2pRequest) -> K + 'a;

pub struct FileTransfers<K = OutboundRequestId> {
    /// `<profile>/storage/incoming`; partial chunks live in per-transfer dirs.
    incoming_root: PathBuf,
    outgoing: HashMap<String, Outgoing>,
    incoming: HashMap<String, Incoming>,
    pending: HashMap<K, Pending>,
}

fn finished(transfer_id: &str, ok: bool, reason: &str) -> P2pRequest {
    P2pRequest::FileFinished {
        transfer_id: transfer_id.to_string(),
        ok,
        reason: reason.chars().take(200).collect(),
    }
}

fn failed(transfer_id: &str, peer: &PeerId, direction: &'static str, reason: &str) -> Notice {
    Notice::Failed(FailedEvent {
        transfer_id: transfer_id.to_string(),
        peer_id: peer.to_string(),
        direction,
        reason: reason.to_string(),
    })
}

/// Peer-supplied text shown in the UI: strip control chars, bound length.
fn clean_reason(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

impl<K: Eq + std::hash::Hash> FileTransfers<K> {
    /// Placeholder before a session exists; nothing is ever stored.
    pub fn idle() -> Self {
        Self {
            incoming_root: PathBuf::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Fresh state for a session. Stale partial transfers from a previous
    /// run are removed.
    pub fn new(storage_root: &Path) -> Self {
        let incoming_root = storage_root.join("incoming");
        let _ = std::fs::remove_dir_all(&incoming_root);
        Self {
            incoming_root,
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    fn reserved_incoming_bytes(&self) -> i64 {
        self.incoming
            .values()
            .map(|t| t.state.offer().size as i64)
            .sum()
    }

    /// Validate an offer against local policy and queue it for the user.
    pub fn handle_offer(
        &mut self,
        peer: PeerId,
        offer: FileOffer,
        my_secret: &[u8; 32],
        policy: &OfferPolicy,
    ) -> Result<OfferEvent, String> {
        if policy.blocked {
            return Err("blocked".into());
        }
        if policy.trust_level < policy.min_trust_file {
            return Err("blocked by trust policy".into());
        }
        let offer = transfer::validate_offer(&offer, policy.limits.max_file_bytes())
            .map_err(|e| e.to_string())?;
        if self.incoming.contains_key(&offer.transfer_id)
            || self.outgoing.contains_key(&offer.transfer_id)
        {
            return Err("duplicate transfer id".into());
        }
        if self.incoming.len() >= policy.limits.max_concurrent() {
            return Err("too many concurrent transfers".into());
        }
        let needed = policy
            .used_bytes
            .saturating_add(self.reserved_incoming_bytes())
            .saturating_add(offer.size as i64);
        if needed > policy.quota_bytes {
            return Err("storage quota exceeded".into());
        }
        let state = IncomingTransfer::new(offer, my_secret).map_err(|e| e.to_string())?;
        let o = state.offer();
        let event = OfferEvent {
            transfer_id: o.transfer_id.clone(),
            peer_id: peer.to_string(),
            filename: o.filename.clone(),
            size: o.size,
            mime: o.mime.clone(),
        };
        let now = Instant::now();
        self.incoming.insert(
            event.transfer_id.clone(),
            Incoming {
                peer,
                chunk_dir: self.incoming_root.join(&event.transfer_id),
                state,
                accepted: false,
                created: now,
                last_progress: now,
            },
        );
        Ok(event)
    }

    /// User accepted a pending offer: start pulling chunks.
    pub fn accept(&mut self, transfer_id: &str, send: &mut SendFn<K>) -> Vec<Notice> {
        let Some(t) = self.incoming.get_mut(transfer_id) else {
            return Vec::new();
        };
        if t.accepted {
            return Vec::new();
        }
        t.accepted = true;
        t.last_progress = Instant::now();
        if let Err(e) = std::fs::create_dir_all(&t.chunk_dir) {
            return self.fail_incoming(transfer_id, &format!("cannot store chunks: {e}"), send);
        }
        self.pump(transfer_id, send)
    }

    /// User rejected an offer or cancelled a transfer in either direction.
    pub fn cancel(&mut self, transfer_id: &str, reason: &str, send: &mut SendFn<K>) -> Vec<Notice> {
        if self.incoming.contains_key(transfer_id) {
            return self.fail_incoming(transfer_id, reason, send);
        }
        if let Some(t) = self.outgoing.remove(transfer_id) {
            send(t.peer, finished(transfer_id, false, reason));
            return vec![failed(transfer_id, &t.peer, SEND, reason)];
        }
        Vec::new()
    }

    fn fail_incoming(
        &mut self,
        transfer_id: &str,
        reason: &str,
        send: &mut SendFn<K>,
    ) -> Vec<Notice> {
        let Some(t) = self.incoming.remove(transfer_id) else {
            return Vec::new();
        };
        let _ = std::fs::remove_dir_all(&t.chunk_dir);
        send(t.peer, finished(transfer_id, false, reason));
        vec![failed(transfer_id, &t.peer, RECEIVE, reason)]
    }

    /// Keep the request window full, or hand a complete transfer over for
    /// reassembly.
    fn pump(&mut self, transfer_id: &str, send: &mut SendFn<K>) -> Vec<Notice> {
        let Some(t) = self.incoming.get_mut(transfer_id) else {
            return Vec::new();
        };
        if t.state.is_complete() {
            let t = self.incoming.remove(transfer_id).expect("present");
            return vec![Notice::Finalize(Box::new(FinalizeJob {
                transfer_id: transfer_id.to_string(),
                peer: t.peer,
                state: t.state,
                chunk_dir: t.chunk_dir,
            }))];
        }
        for index in t.state.next_requests(CHUNK_WINDOW) {
            let id = send(
                t.peer,
                P2pRequest::FileChunkRequest {
                    transfer_id: transfer_id.to_string(),
                    index,
                },
            );
            self.pending
                .insert(id, Pending::Chunk(transfer_id.to_string(), index));
        }
        Vec::new()
    }

    fn chunk_failed(&mut self, transfer_id: &str, index: u64, send: &mut SendFn<K>) -> Vec<Notice> {
        let Some(t) = self.incoming.get_mut(transfer_id) else {
            return Vec::new();
        };
        match t.state.request_failed(index) {
            Ok(()) => self.pump(transfer_id, send),
            Err(e) => self.fail_incoming(transfer_id, &e.to_string(), send),
        }
    }

    /// A response to one of our requests arrived.
    pub fn on_response(
        &mut self,
        peer: PeerId,
        request_id: K,
        response: P2pResponse,
        send: &mut SendFn<K>,
    ) -> Vec<Notice> {
        let Some(pending) = self.pending.remove(&request_id) else {
            return Vec::new();
        };
        match (pending, response) {
            (
                Pending::Offer(tid),
                P2pResponse::FileOfferAck {
                    success, message, ..
                },
            ) => {
                if success {
                    return Vec::new();
                }
                match self.outgoing.remove(&tid) {
                    Some(t) => vec![failed(
                        &tid,
                        &t.peer,
                        SEND,
                        &format!("recipient refused: {}", clean_reason(&message)),
                    )],
                    None => Vec::new(),
                }
            }
            (Pending::Offer(tid), _) => match self.outgoing.remove(&tid) {
                Some(t) => vec![failed(
                    &tid,
                    &t.peer,
                    SEND,
                    "recipient does not support file transfer",
                )],
                None => Vec::new(),
            },
            (
                Pending::Chunk(tid, index),
                P2pResponse::FileChunkData {
                    transfer_id,
                    index: got_index,
                    chunk,
                },
            ) if transfer_id == tid && got_index == index => {
                self.on_chunk(peer, &tid, index, chunk, send)
            }
            (Pending::Chunk(tid, index), _) => self.chunk_failed(&tid, index, send),
        }
    }

    fn on_chunk(
        &mut self,
        peer: PeerId,
        tid: &str,
        index: u64,
        chunk: Option<EncryptedChunk>,
        send: &mut SendFn<K>,
    ) -> Vec<Notice> {
        let Some(t) = self.incoming.get_mut(tid) else {
            return Vec::new();
        };
        if t.peer != peer || !t.accepted {
            return Vec::new();
        }
        let Some(chunk) = chunk else {
            return self.fail_incoming(tid, "sender no longer offers this file", send);
        };
        if t.state.verify_chunk(index, &chunk).is_err() {
            return self.chunk_failed(tid, index, send);
        }
        let persisted = bincode::serialize(&chunk).ok().and_then(|bytes| {
            std::fs::write(t.chunk_dir.join(format!("{index}.chunk")), bytes).ok()
        });
        if persisted.is_none() {
            return self.fail_incoming(tid, "cannot store chunk", send);
        }
        t.state.mark_received(index);
        t.last_progress = Instant::now();
        let mut notices = vec![Notice::Progress(ProgressEvent {
            transfer_id: tid.to_string(),
            peer_id: peer.to_string(),
            direction: RECEIVE,
            done_chunks: t.state.received_chunks(),
            total_chunks: t.state.total_chunks(),
            size: t.state.offer().size,
        })];
        notices.extend(self.pump(tid, send));
        notices
    }

    /// One of our requests failed at the transport level (timeout, closed
    /// connection, dial failure).
    pub fn on_outbound_failure(&mut self, request_id: K, send: &mut SendFn<K>) -> Vec<Notice> {
        match self.pending.remove(&request_id) {
            Some(Pending::Offer(tid)) => match self.outgoing.remove(&tid) {
                Some(t) => vec![failed(&tid, &t.peer, SEND, "recipient unreachable")],
                None => Vec::new(),
            },
            Some(Pending::Chunk(tid, index)) => self.chunk_failed(&tid, index, send),
            None => Vec::new(),
        }
    }

    /// Register a prepared outgoing transfer and send its offer.
    pub fn start_outgoing(
        &mut self,
        peer: PeerId,
        offer: FileOffer,
        chunks: Arc<Vec<EncryptedChunk>>,
        max_concurrent: usize,
        send: &mut SendFn<K>,
    ) -> Result<(), String> {
        if self.outgoing.len() >= max_concurrent {
            return Err("too many concurrent transfers".into());
        }
        let tid = offer.transfer_id.clone();
        let id = send(
            peer,
            P2pRequest::FileOffer {
                offer: offer.clone(),
            },
        );
        self.pending.insert(id, Pending::Offer(tid.clone()));
        self.outgoing.insert(
            tid,
            Outgoing {
                peer,
                offer,
                chunks,
                served: HashSet::new(),
                last_activity: Instant::now(),
            },
        );
        Ok(())
    }

    /// Chunk pulls for our own offers are flow-controlled by the recipient's
    /// window, so they bypass the generic per-peer request rate limit.
    pub fn is_outgoing_to(&self, transfer_id: &str, peer: &PeerId) -> bool {
        self.outgoing
            .get(transfer_id)
            .map(|t| t.peer == *peer)
            .unwrap_or(false)
    }

    /// Answer a chunk pull from the recipient.
    pub fn serve_chunk(
        &mut self,
        peer: PeerId,
        transfer_id: String,
        index: u64,
    ) -> (P2pResponse, Option<Notice>) {
        let mut notice = None;
        let chunk = match self.outgoing.get_mut(&transfer_id) {
            Some(t) if t.peer == peer => {
                let chunk = usize::try_from(index)
                    .ok()
                    .and_then(|i| t.chunks.get(i))
                    .cloned();
                if chunk.is_some() {
                    t.last_activity = Instant::now();
                    if t.served.insert(index) {
                        notice = Some(Notice::Progress(ProgressEvent {
                            transfer_id: transfer_id.clone(),
                            peer_id: peer.to_string(),
                            direction: SEND,
                            done_chunks: t.served.len() as u64,
                            total_chunks: t.offer.total_chunks,
                            size: t.offer.size,
                        }));
                    }
                }
                chunk
            }
            _ => None,
        };
        (
            P2pResponse::FileChunkData {
                transfer_id,
                index,
                chunk,
            },
            notice,
        )
    }

    /// The other side reports that a transfer ended.
    pub fn handle_finished(
        &mut self,
        peer: PeerId,
        transfer_id: &str,
        ok: bool,
        reason: &str,
    ) -> Vec<Notice> {
        if self.outgoing.get(transfer_id).map(|t| t.peer) == Some(peer) {
            self.outgoing.remove(transfer_id);
            return if ok {
                vec![Notice::Sent(SentEvent {
                    transfer_id: transfer_id.to_string(),
                    peer_id: peer.to_string(),
                })]
            } else {
                vec![failed(transfer_id, &peer, SEND, &clean_reason(reason))]
            };
        }
        if self.incoming.get(transfer_id).map(|t| t.peer) == Some(peer) {
            if let Some(t) = self.incoming.remove(transfer_id) {
                let _ = std::fs::remove_dir_all(&t.chunk_dir);
            }
            return vec![failed(
                transfer_id,
                &peer,
                RECEIVE,
                &format!("cancelled by sender: {}", clean_reason(reason)),
            )];
        }
        Vec::new()
    }

    /// Expire unanswered offers, stalled downloads and idle uploads.
    pub fn tick(&mut self, now: Instant, send: &mut SendFn<K>) -> Vec<Notice> {
        let mut notices = Vec::new();
        let expired: Vec<(String, &'static str)> = self
            .incoming
            .iter()
            .filter_map(|(id, t)| {
                if !t.accepted && now.duration_since(t.created) > OFFER_TIMEOUT {
                    Some((id.clone(), "offer expired"))
                } else if t.accepted && now.duration_since(t.last_progress) > STALL_TIMEOUT {
                    Some((id.clone(), "transfer stalled"))
                } else {
                    None
                }
            })
            .collect();
        for (id, reason) in expired {
            notices.extend(self.fail_incoming(&id, reason, send));
        }
        let idle: Vec<String> = self
            .outgoing
            .iter()
            .filter(|(_, t)| now.duration_since(t.last_activity) > OUTGOING_IDLE_TIMEOUT)
            .map(|(id, _)| id.clone())
            .collect();
        for id in idle {
            notices.extend(self.cancel(&id, "timed out", send));
        }
        notices
    }
}

/// Decrypt the stored chunks of a complete transfer into `dest_dir`,
/// verify the content hash and place the file without overwriting
/// anything. Partial data is removed on every path.
pub fn finalize(job: &FinalizeJob, dest_dir: &Path) -> Result<PathBuf, String> {
    let result = (|| {
        std::fs::create_dir_all(dest_dir).map_err(|e| e.to_string())?;
        let tmp = dest_dir.join(format!(".{}.alterchat-part", job.transfer_id));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        let max_len = job.state.offer().chunk_size as u64 + 1024;
        let write = (|| {
            let mut out = std::io::BufWriter::new(file);
            job.state
                .reassemble(
                    |i| {
                        let path = job.chunk_dir.join(format!("{i}.chunk"));
                        if std::fs::metadata(&path)?.len() > max_len {
                            return Err(std::io::Error::other("chunk file too large"));
                        }
                        let bytes = std::fs::read(&path)?;
                        bincode::deserialize::<EncryptedChunk>(&bytes)
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    },
                    &mut out,
                )
                .map_err(|e| e.to_string())?;
            out.flush().map_err(|e| e.to_string())?;
            out.get_ref().sync_all().map_err(|e| e.to_string())
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        transfer::place_without_overwrite(&tmp, dest_dir, &job.state.offer().filename).map_err(
            |e| {
                let _ = std::fs::remove_file(&tmp);
                e.to_string()
            },
        )
    })();
    let _ = std::fs::remove_dir_all(&job.chunk_dir);
    result
}

/// Where received files go: the OS downloads folder, or the profile's
/// storage directory if there is none.
pub fn destination_dir(app: &tauri::AppHandle, db_path: Option<&str>) -> PathBuf {
    app.path()
        .download_dir()
        .ok()
        .filter(|d| d.is_dir())
        .unwrap_or_else(|| {
            db_path
                .map(|p| crate::profile::storage_root(p).join("received"))
                .unwrap_or_else(|| std::env::temp_dir().join("alterchat-received"))
        })
}

/// Emit UI events; run reassembly off the event loop and report back with
/// `AppCommand::FileFinalized`.
pub fn dispatch(app: &tauri::AppHandle, db_path: Option<&str>, notices: Vec<Notice>) {
    for notice in notices {
        match notice {
            Notice::Progress(ev) => {
                let _ = app.emit("file-progress", ev);
            }
            Notice::Failed(ev) => {
                let _ = app.emit("file-transfer-failed", ev);
            }
            Notice::Sent(ev) => {
                let _ = app.emit("file-sent", ev);
            }
            Notice::Finalize(job) => {
                let dest = destination_dir(app, db_path);
                let app = app.clone();
                tauri::async_runtime::spawn_blocking(move || {
                    let result = finalize(&job, &dest);
                    let offer = job.state.offer();
                    let cmd = AppCommand::FileFinalized {
                        transfer_id: job.transfer_id.clone(),
                        peer: job.peer,
                        filename: offer.filename.clone(),
                        size: offer.size,
                        result,
                    };
                    let _ = app.state::<AppState>().tx.blocking_send(cmd);
                });
            }
        }
    }
}

/// Extensions that run code when "opened"; for these we only reveal the
/// file in its folder.
pub fn is_executable_name(name: &str) -> bool {
    const RISKY: &[&str] = &[
        "exe",
        "com",
        "bat",
        "cmd",
        "msi",
        "msp",
        "scr",
        "pif",
        "cpl",
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "hta",
        "jar",
        "lnk",
        "url",
        "reg",
        "inf",
        "dll",
        "sys",
        "appref-ms",
        "application",
        "gadget",
        "msc",
        "sh",
        "bash",
        "zsh",
        "command",
        "app",
        "pkg",
        "dmg",
        "run",
        "bin",
        "desktop",
        "appimage",
        "deb",
        "rpm",
        "py",
        "pl",
        "rb",
        "library-ms",
        "settingcontent-ms",
        "iso",
        "img",
        "vhd",
        "vhdx",
    ];
    let lower = name.to_ascii_lowercase();
    match lower.rsplit_once('.') {
        Some((_, ext)) => RISKY.contains(&ext),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alterchat_core::crypto::{generate_static_secret, get_public_key};

    fn policy() -> OfferPolicy {
        OfferPolicy {
            blocked: false,
            trust_level: 0,
            min_trust_file: 0,
            quota_bytes: 512 << 20,
            used_bytes: 0,
            limits: TransferSettings::default(),
        }
    }

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("alterchat-fx-{}", transfer::new_transfer_id()))
    }

    #[test]
    fn policy_rejections() {
        let secret = generate_static_secret();
        let public = get_public_key(&secret);
        let (offer, _) = transfer::prepare_outgoing("a.txt", None, &[1u8; 1000], &public).unwrap();
        let peer = PeerId::random();
        let mut ft: FileTransfers<u64> = FileTransfers::new(&temp_root());

        let blocked = OfferPolicy {
            blocked: true,
            ..policy()
        };
        assert!(ft
            .handle_offer(peer, offer.clone(), &secret, &blocked)
            .is_err());
        let low_trust = OfferPolicy {
            min_trust_file: 5,
            ..policy()
        };
        assert!(ft
            .handle_offer(peer, offer.clone(), &secret, &low_trust)
            .is_err());
        let full = OfferPolicy {
            used_bytes: 512 << 20,
            ..policy()
        };
        assert!(ft
            .handle_offer(peer, offer.clone(), &secret, &full)
            .is_err());
        let tiny = OfferPolicy {
            limits: TransferSettings {
                max_file_size_mb: 1,
                max_concurrent_transfers: 1,
            },
            ..policy()
        };
        let big = FileOffer {
            size: 2 << 20,
            total_chunks: (2u64 << 20).div_ceil(transfer::CHUNK_SIZE as u64),
            ..offer.clone()
        };
        assert!(ft.handle_offer(peer, big, &secret, &tiny).is_err());
        // Wrong recipient key.
        let other = generate_static_secret();
        assert!(ft
            .handle_offer(peer, offer.clone(), &other, &policy())
            .is_err());

        let ev = ft
            .handle_offer(peer, offer.clone(), &secret, &tiny)
            .unwrap();
        assert_eq!(ev.filename, "a.txt");
        // Duplicate id and concurrency limit.
        assert!(ft
            .handle_offer(peer, offer.clone(), &secret, &policy())
            .is_err());
        let (second, _) = transfer::prepare_outgoing("b", None, b"x", &public).unwrap();
        assert!(ft.handle_offer(peer, second, &secret, &tiny).is_err());
    }

    #[test]
    fn end_to_end_pull_with_retries_and_backpressure() {
        use std::collections::VecDeque;
        let rx_secret = generate_static_secret();
        let rx_pub = get_public_key(&rx_secret);
        let data: Vec<u8> = (0..transfer::CHUNK_SIZE * 9 + 3)
            .map(|i| (i * 7 % 256) as u8)
            .collect();
        let (offer, chunks) =
            transfer::prepare_outgoing("notes.txt", Some("text/plain"), &data, &rx_pub).unwrap();
        let tid = offer.transfer_id.clone();
        let sender_peer = PeerId::random();
        let receiver_peer = PeerId::random();
        let root = temp_root();
        let mut sender: FileTransfers<u64> = FileTransfers::new(&root.join("s"));
        let mut receiver: FileTransfers<u64> = FileTransfers::new(&root.join("r"));

        let (mut sid, mut rid) = (0u64, 0u64);
        let mut sq: VecDeque<(u64, PeerId, P2pRequest)> = VecDeque::new();
        let mut rq: VecDeque<(u64, PeerId, P2pRequest)> = VecDeque::new();

        sender
            .start_outgoing(receiver_peer, offer, Arc::new(chunks), 3, &mut |p, r| {
                sid += 1;
                sq.push_back((sid, p, r));
                sid
            })
            .unwrap();
        let (offer_id, to, P2pRequest::FileOffer { offer }) = sq.pop_front().unwrap() else {
            panic!("expected offer");
        };
        assert_eq!(to, receiver_peer);
        let ev = receiver
            .handle_offer(sender_peer, offer, &rx_secret, &policy())
            .unwrap();
        assert_eq!(ev.filename, "notes.txt");
        let ack = P2pResponse::FileOfferAck {
            transfer_id: tid.clone(),
            success: true,
            message: String::new(),
        };
        assert!(sender
            .on_response(receiver_peer, offer_id, ack, &mut |_, _| unreachable!())
            .is_empty());

        // Unsolicited responses are ignored.
        let bogus = P2pResponse::FileChunkData {
            transfer_id: tid.clone(),
            index: 0,
            chunk: None,
        };
        assert!(receiver
            .on_response(sender_peer, 999, bogus, &mut |_, _| unreachable!())
            .is_empty());

        let mut push = |rq: &mut VecDeque<(u64, PeerId, P2pRequest)>, p, r| {
            rid += 1;
            rq.push_back((rid, p, r));
            rid
        };
        assert!(receiver
            .accept(&tid, &mut |p, r| push(&mut rq, p, r))
            .is_empty());
        let mut job = None;
        let mut round = 0;
        while let Some((id, to, req)) = rq.pop_front() {
            assert!(rq.len() < CHUNK_WINDOW, "window exceeded");
            assert_eq!(to, sender_peer);
            round += 1;
            let notices = if round == 2 {
                // Transport failure: retried.
                receiver.on_outbound_failure(id, &mut |p, r| push(&mut rq, p, r))
            } else {
                let P2pRequest::FileChunkRequest { transfer_id, index } = req else {
                    panic!("expected chunk request");
                };
                let (mut resp, _) = sender.serve_chunk(receiver_peer, transfer_id, index);
                if round == 3 {
                    // Tampered in transit: rejected and retried.
                    if let P2pResponse::FileChunkData { chunk: Some(c), .. } = &mut resp {
                        c.ciphertext[0] ^= 1;
                    }
                }
                receiver.on_response(sender_peer, id, resp, &mut |p, r| push(&mut rq, p, r))
            };
            for n in notices {
                match n {
                    Notice::Finalize(j) => job = Some(j),
                    Notice::Failed(f) => panic!("unexpected failure: {}", f.reason),
                    _ => {}
                }
            }
        }
        let job = job.expect("transfer completed");
        let path = finalize(&job, &root.join("dl")).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);

        let done = sender.handle_finished(receiver_peer, &tid, true, "");
        assert!(matches!(done.as_slice(), [Notice::Sent(_)]));
        // A different peer cannot pull or finish someone else's transfer.
        let (resp, _) = sender.serve_chunk(PeerId::random(), tid.clone(), 0);
        assert!(matches!(
            resp,
            P2pResponse::FileChunkData { chunk: None, .. }
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cancel_and_timeouts_clean_up() {
        let secret = generate_static_secret();
        let public = get_public_key(&secret);
        let root = temp_root();
        let mut ft: FileTransfers<u64> = FileTransfers::new(&root);
        let peer = PeerId::random();
        let mut sent = Vec::new();
        let mut n = 0u64;
        let mut send = |p: PeerId, r: P2pRequest| {
            n += 1;
            sent.push((p, r));
            n
        };
        let (a, _) = transfer::prepare_outgoing("a", None, &[0; 70_000], &public).unwrap();
        let (b, _) = transfer::prepare_outgoing("b", None, &[0; 300_000], &public).unwrap();
        ft.handle_offer(peer, a.clone(), &secret, &policy())
            .unwrap();
        ft.handle_offer(peer, b.clone(), &secret, &policy())
            .unwrap();
        ft.accept(&b.transfer_id, &mut send);
        let dir = root.join("incoming").join(&b.transfer_id);
        assert!(dir.is_dir());

        // Rejecting an offer notifies the sender.
        let out = ft.cancel(&a.transfer_id, "rejected", &mut send);
        assert!(matches!(out.as_slice(), [Notice::Failed(_)]));
        // A stalled accepted transfer is failed and its chunk dir removed.
        let later = Instant::now() + STALL_TIMEOUT + Duration::from_secs(1);
        let out = ft.tick(later, &mut send);
        assert!(matches!(out.as_slice(), [Notice::Failed(_)]));
        assert!(!dir.exists());
        let finishes = sent
            .iter()
            .filter(|(_, r)| matches!(r, P2pRequest::FileFinished { ok: false, .. }))
            .count();
        assert_eq!(finishes, 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finalize_writes_verified_file_and_cleans_up() {
        let secret = generate_static_secret();
        let public = get_public_key(&secret);
        let data: Vec<u8> = (0..(transfer::CHUNK_SIZE * 2 + 99))
            .map(|i| (i % 253) as u8)
            .collect();
        let (offer, chunks) =
            transfer::prepare_outgoing("../../evil/CON.txt", None, &data, &public).unwrap();
        let root = temp_root();
        let chunk_dir = root.join("incoming").join(&offer.transfer_id);
        std::fs::create_dir_all(&chunk_dir).unwrap();
        let mut state = IncomingTransfer::new(offer.clone(), &secret).unwrap();
        while !state.is_complete() {
            for i in state.next_requests(CHUNK_WINDOW) {
                let c = &chunks[i as usize];
                state.verify_chunk(i, c).unwrap();
                std::fs::write(
                    chunk_dir.join(format!("{i}.chunk")),
                    bincode::serialize(c).unwrap(),
                )
                .unwrap();
                state.mark_received(i);
            }
        }
        let dest = root.join("downloads");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("_CON.txt"), b"keep me").unwrap();
        let job = FinalizeJob {
            transfer_id: offer.transfer_id.clone(),
            peer: PeerId::random(),
            state,
            chunk_dir: chunk_dir.clone(),
        };
        let path = finalize(&job, &dest).unwrap();
        assert_eq!(path, dest.join("_CON (1).txt"));
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert_eq!(std::fs::read(dest.join("_CON.txt")).unwrap(), b"keep me");
        assert!(!chunk_dir.exists());
        // Only the two real files remain (no temp files).
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn finalize_rejects_tampered_storage() {
        let secret = generate_static_secret();
        let public = get_public_key(&secret);
        let data = vec![7u8; transfer::CHUNK_SIZE + 1];
        let (offer, chunks) = transfer::prepare_outgoing("x.bin", None, &data, &public).unwrap();
        let root = temp_root();
        let chunk_dir = root.join("c");
        std::fs::create_dir_all(&chunk_dir).unwrap();
        let mut state = IncomingTransfer::new(offer.clone(), &secret).unwrap();
        for i in state.next_requests(CHUNK_WINDOW) {
            let mut c = chunks[i as usize].clone();
            state.verify_chunk(i, &c).unwrap();
            if i == 1 {
                c.ciphertext[0] ^= 1;
            }
            std::fs::write(
                chunk_dir.join(format!("{i}.chunk")),
                bincode::serialize(&c).unwrap(),
            )
            .unwrap();
            state.mark_received(i);
        }
        let dest = root.join("d");
        let job = FinalizeJob {
            transfer_id: offer.transfer_id.clone(),
            peer: PeerId::random(),
            state,
            chunk_dir: chunk_dir.clone(),
        };
        assert!(finalize(&job, &dest).is_err());
        assert_eq!(std::fs::read_dir(&dest).unwrap().count(), 0);
        assert!(!chunk_dir.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn executable_names_are_not_opened() {
        for (name, risky) in [
            ("a.exe", true),
            ("A.BAT", true),
            ("photo.jpg", false),
            ("doc.pdf", false),
            ("noext", true),
            ("x.tar.gz", false),
            ("run.ps1", true),
        ] {
            assert_eq!(is_executable_name(name), risky, "{name}");
        }
    }
}
