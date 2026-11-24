//! Peer-to-peer file transfer: offer validation, per-file key sealing,
//! chunk bookkeeping, reassembly and safe placement on disk.
//!
//! Protocol (pull based, see `file_transfer::P2pRequest`):
//! 1. Sender encrypts the file into AES-256-GCM chunks with a random per-file
//!    key, seals that key to the recipient's X25519 `offline_pubkey` and sends
//!    a [`FileOffer`].
//! 2. The recipient validates the offer and asks the user. On accept it pulls
//!    chunks with `FileChunkRequest` (bounded in-flight window, per-chunk
//!    retries); the sender answers with `FileChunkData`.
//! 3. The recipient verifies every chunk (AEAD + expected length), stores the
//!    ciphertext, and when complete decrypts, checks the whole-file SHA-256
//!    and writes the file without overwriting anything. `FileFinished` tells
//!    the other side the outcome either way.
//!
//! Everything in an offer or chunk is peer supplied and validated here.

use crate::storage::{self, EncryptedChunk};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Chunk size used by this implementation when sending.
pub const CHUNK_SIZE: usize = storage::DEFAULT_CHUNK_SIZE;
/// Smallest / largest chunk size accepted from a peer. The upper bound keeps
/// a CBOR-encoded chunk response far below the 10 MiB response limit.
pub const MIN_CHUNK_SIZE: u32 = 16 * 1024;
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;
/// Hard cap on chunk count, independent of the configured size limit.
pub const MAX_TOTAL_CHUNKS: u64 = 1 << 16;
/// Longest sanitised file name in bytes.
pub const MAX_FILENAME_BYTES: usize = 200;
/// Longest raw (unsanitised) file name accepted in an offer.
pub const MAX_RAW_FILENAME_BYTES: usize = 4096;
pub const MAX_MIME_BYTES: usize = 127;
/// AES-GCM tag overhead per chunk.
pub const CHUNK_OVERHEAD: usize = 16;
/// Attempts per chunk before the whole transfer is failed.
pub const MAX_CHUNK_ATTEMPTS: u32 = 4;
/// Sealed key = ephemeral pubkey (32) + nonce (12) + AEAD(key || transfer id).
const MAX_SEALED_KEY_BYTES: usize = 32 + 12 + 32 + 128 + CHUNK_OVERHEAD;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOffer {
    pub transfer_id: String,
    pub filename: String,
    pub size: u64,
    pub mime: Option<String>,
    pub chunk_size: u32,
    pub total_chunks: u64,
    /// Lowercase hex SHA-256 of the whole plaintext.
    pub content_hash: String,
    /// Per-file AES key sealed to the recipient, see [`seal_file_key`].
    pub sealed_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransferError {
    #[error("invalid transfer id")]
    InvalidTransferId,
    #[error("file name too long")]
    FilenameTooLong,
    #[error("file too large ({size} bytes, limit {limit})")]
    TooLarge { size: u64, limit: u64 },
    #[error("invalid chunk size")]
    InvalidChunkSize,
    #[error("chunk count does not match file size")]
    ChunkCountMismatch,
    #[error("too many chunks")]
    TooManyChunks,
    #[error("invalid content hash")]
    InvalidContentHash,
    #[error("invalid sealed key")]
    InvalidSealedKey,
    #[error("chunk index out of range")]
    IndexOutOfRange,
    #[error("unexpected chunk")]
    UnexpectedChunk,
    #[error("chunk rejected: {0}")]
    BadChunk(&'static str),
    #[error("chunk {0} failed too many times")]
    TooManyRetries(u64),
    #[error("transfer incomplete")]
    Incomplete,
    #[error("content hash mismatch")]
    HashMismatch,
    #[error("encryption failed")]
    Crypto,
    #[error("i/o error: {0}")]
    Io(String),
}

impl From<io::Error> for TransferError {
    fn from(e: io::Error) -> Self {
        TransferError::Io(e.to_string())
    }
}

/// `[A-Za-z0-9_-]{16,128}`: the id ends up in a directory name.
pub fn is_valid_transfer_id(id: &str) -> bool {
    (16..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_hex_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn new_transfer_id() -> String {
    hex(&storage::generate_file_key()[..16])
}

/// Invisible/format characters that can disguise an extension
/// (e.g. U+202E RIGHT-TO-LEFT OVERRIDE turning `exe.txt` into `txt.exe`).
fn is_invisible(c: char) -> bool {
    matches!(c,
        '\u{00AD}' | '\u{061C}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}')
}

fn is_reserved_windows_stem(stem: &str) -> bool {
    let upper = stem.trim_end_matches(' ').to_ascii_uppercase();
    if matches!(
        upper.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) {
        return true;
    }
    for prefix in ["COM", "LPT"] {
        if let Some(rest) = upper.strip_prefix(prefix) {
            let mut chars = rest.chars();
            if let (Some(c), None) = (chars.next(), chars.next())
                && (c.is_ascii_digit() || matches!(c, '¹' | '²' | '³'))
            {
                return true;
            }
        }
    }
    false
}

fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Turn a peer-supplied name into a single safe path component: no
/// separators, no drive/stream syntax, no control or bidi characters, no
/// leading/trailing dots or spaces, no reserved Windows device names, at
/// most [`MAX_FILENAME_BYTES`] bytes (keeping a short extension).
pub fn sanitize_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let mut cleaned = String::with_capacity(base.len());
    for c in base.chars() {
        if c.is_control() || is_invisible(c) {
            continue;
        }
        if matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') {
            cleaned.push('_');
        } else {
            cleaned.push(c);
        }
    }
    let mut name = cleaned.trim_matches(|c| c == ' ' || c == '.').to_string();

    let stem = name.split('.').next().unwrap_or("");
    if is_reserved_windows_stem(stem) {
        name.insert(0, '_');
    }

    if name.len() > MAX_FILENAME_BYTES {
        let (stem, ext) = match name.rfind('.') {
            Some(pos) if pos > 0 && name.len() - pos <= 20 => name.split_at(pos),
            _ => (name.as_str(), ""),
        };
        let stem = truncate_utf8(stem, MAX_FILENAME_BYTES - ext.len()).trim_end_matches([' ', '.']);
        name = format!("{stem}{ext}");
    }
    if name.is_empty() {
        "file".to_string()
    } else {
        name
    }
}

fn sanitize_mime(mime: Option<&str>) -> Option<String> {
    let m = mime?.trim();
    let ok = !m.is_empty()
        && m.len() <= MAX_MIME_BYTES
        && m.matches('/').count() == 1
        && m.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-/".contains(&b));
    ok.then(|| m.to_ascii_lowercase())
}

fn expected_chunks(size: u64, chunk_size: u32) -> u64 {
    size.div_ceil(u64::from(chunk_size.max(1)))
}

/// Validate every peer-supplied offer field and return a copy with the file
/// name and mime type sanitised.
pub fn validate_offer(offer: &FileOffer, max_file_size: u64) -> Result<FileOffer, TransferError> {
    if !is_valid_transfer_id(&offer.transfer_id) {
        return Err(TransferError::InvalidTransferId);
    }
    if offer.filename.len() > MAX_RAW_FILENAME_BYTES {
        return Err(TransferError::FilenameTooLong);
    }
    if offer.size > max_file_size {
        return Err(TransferError::TooLarge {
            size: offer.size,
            limit: max_file_size,
        });
    }
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&offer.chunk_size) {
        return Err(TransferError::InvalidChunkSize);
    }
    if offer.total_chunks > MAX_TOTAL_CHUNKS {
        return Err(TransferError::TooManyChunks);
    }
    if offer.total_chunks != expected_chunks(offer.size, offer.chunk_size) {
        return Err(TransferError::ChunkCountMismatch);
    }
    if !is_hex_sha256(&offer.content_hash) {
        return Err(TransferError::InvalidContentHash);
    }
    if offer.sealed_key.len() < 32 + 12 + 32 + CHUNK_OVERHEAD
        || offer.sealed_key.len() > MAX_SEALED_KEY_BYTES
    {
        return Err(TransferError::InvalidSealedKey);
    }
    Ok(FileOffer {
        filename: sanitize_filename(&offer.filename),
        mime: sanitize_mime(offer.mime.as_deref()),
        ..offer.clone()
    })
}

/// Seal the per-file key to the recipient's X25519 key. The transfer id is
/// sealed along with it so a key cannot be replayed into another offer.
pub fn seal_file_key(
    recipient_pubkey: &[u8; 32],
    transfer_id: &str,
    key: &[u8; 32],
) -> Result<Vec<u8>, TransferError> {
    let mut plaintext = Zeroizing::new(Vec::with_capacity(32 + transfer_id.len()));
    plaintext.extend_from_slice(key);
    plaintext.extend_from_slice(transfer_id.as_bytes());
    let payload = crate::crypto::encrypt_for_peer(recipient_pubkey, &plaintext)
        .map_err(|_| TransferError::Crypto)?;
    let mut out = Vec::with_capacity(44 + payload.ciphertext.len());
    out.extend_from_slice(&payload.ephemeral_pubkey);
    out.extend_from_slice(&payload.nonce);
    out.extend_from_slice(&payload.ciphertext);
    Ok(out)
}

pub fn open_file_key(
    my_secret: &[u8; 32],
    transfer_id: &str,
    sealed: &[u8],
) -> Result<Zeroizing<[u8; 32]>, TransferError> {
    if sealed.len() < 44 + CHUNK_OVERHEAD || sealed.len() > MAX_SEALED_KEY_BYTES {
        return Err(TransferError::InvalidSealedKey);
    }
    let mut ephemeral_pubkey = [0u8; 32];
    ephemeral_pubkey.copy_from_slice(&sealed[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sealed[32..44]);
    let payload = crate::crypto::EncryptedPayload {
        ephemeral_pubkey,
        nonce,
        ciphertext: sealed[44..].to_vec(),
    };
    let plaintext = Zeroizing::new(
        crate::crypto::decrypt_for_me(my_secret, &payload)
            .map_err(|_| TransferError::InvalidSealedKey)?,
    );
    if plaintext.len() != 32 + transfer_id.len() || &plaintext[32..] != transfer_id.as_bytes() {
        return Err(TransferError::InvalidSealedKey);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&plaintext[..32]);
    Ok(key)
}

/// Sender side: encrypt `data` into chunks and build the offer.
pub fn prepare_outgoing(
    filename: &str,
    mime: Option<&str>,
    data: &[u8],
    recipient_pubkey: &[u8; 32],
) -> Result<(FileOffer, Vec<EncryptedChunk>), TransferError> {
    let transfer_id = new_transfer_id();
    let key = Zeroizing::new(storage::generate_file_key());
    let chunks = storage::split_chunks(data, CHUNK_SIZE)
        .into_iter()
        .enumerate()
        .map(|(i, plain)| {
            storage::encrypt_chunk(i as u64, &key, plain).map_err(|_| TransferError::Crypto)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let offer = FileOffer {
        sealed_key: seal_file_key(recipient_pubkey, &transfer_id, &key)?,
        transfer_id,
        filename: sanitize_filename(filename),
        size: data.len() as u64,
        mime: sanitize_mime(mime),
        chunk_size: CHUNK_SIZE as u32,
        total_chunks: chunks.len() as u64,
        content_hash: storage::content_hash(data),
    };
    Ok((offer, chunks))
}

/// Receiver side bookkeeping for one accepted transfer.
pub struct IncomingTransfer {
    offer: FileOffer,
    key: Zeroizing<[u8; 32]>,
    received: Vec<bool>,
    received_count: u64,
    next_fresh: u64,
    in_flight: HashSet<u64>,
    retry_queue: VecDeque<u64>,
    attempts: Vec<u8>,
}

impl IncomingTransfer {
    /// `offer` must already have passed [`validate_offer`].
    pub fn new(offer: FileOffer, my_secret: &[u8; 32]) -> Result<Self, TransferError> {
        let key = open_file_key(my_secret, &offer.transfer_id, &offer.sealed_key)?;
        let total = usize::try_from(offer.total_chunks.min(MAX_TOTAL_CHUNKS))
            .map_err(|_| TransferError::TooManyChunks)?;
        Ok(Self {
            offer,
            key,
            received: vec![false; total],
            received_count: 0,
            next_fresh: 0,
            in_flight: HashSet::new(),
            retry_queue: VecDeque::new(),
            attempts: vec![0; total],
        })
    }

    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    pub fn total_chunks(&self) -> u64 {
        self.received.len() as u64
    }

    pub fn received_chunks(&self) -> u64 {
        self.received_count
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.total_chunks()
    }

    /// Plaintext length chunk `index` must have.
    pub fn expected_len(&self, index: u64) -> Option<usize> {
        let cs = u64::from(self.offer.chunk_size);
        let start = index.checked_mul(cs)?;
        if index >= self.total_chunks() || start >= self.offer.size {
            return None;
        }
        usize::try_from((self.offer.size - start).min(cs)).ok()
    }

    /// Chunk indices to request now so that at most `window` are in flight.
    pub fn next_requests(&mut self, window: usize) -> Vec<u64> {
        let mut out = Vec::new();
        while self.in_flight.len() < window {
            let next = if let Some(i) = self.retry_queue.pop_front() {
                i
            } else if self.next_fresh < self.total_chunks() {
                self.next_fresh += 1;
                self.next_fresh - 1
            } else {
                break;
            };
            if self.received[next as usize] {
                continue;
            }
            self.in_flight.insert(next);
            out.push(next);
        }
        out
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.len()
    }

    /// Verify a chunk answered for an outstanding request: index, AEAD and
    /// exact plaintext length. Does not mark it received (see
    /// [`Self::mark_received`]) so the caller can persist it first.
    pub fn verify_chunk(&self, index: u64, chunk: &EncryptedChunk) -> Result<(), TransferError> {
        if index >= self.total_chunks() {
            return Err(TransferError::IndexOutOfRange);
        }
        if !self.in_flight.contains(&index) || chunk.index != index {
            return Err(TransferError::UnexpectedChunk);
        }
        let expected = self
            .expected_len(index)
            .ok_or(TransferError::IndexOutOfRange)?;
        if chunk.ciphertext.len() != expected + CHUNK_OVERHEAD {
            return Err(TransferError::BadChunk("wrong length"));
        }
        let plain = Zeroizing::new(
            storage::decrypt_chunk(&self.key, chunk).map_err(TransferError::BadChunk)?,
        );
        if plain.len() != expected {
            return Err(TransferError::BadChunk("wrong length"));
        }
        Ok(())
    }

    pub fn mark_received(&mut self, index: u64) {
        if index < self.total_chunks() && self.in_flight.remove(&index) {
            let slot = &mut self.received[index as usize];
            if !*slot {
                *slot = true;
                self.received_count += 1;
            }
        }
    }

    /// A request for `index` failed or returned a bad chunk: queue a retry,
    /// or give up after [`MAX_CHUNK_ATTEMPTS`].
    pub fn request_failed(&mut self, index: u64) -> Result<(), TransferError> {
        if index >= self.total_chunks() || !self.in_flight.remove(&index) {
            return Ok(());
        }
        let attempts = &mut self.attempts[index as usize];
        *attempts = attempts.saturating_add(1);
        if u32::from(*attempts) >= MAX_CHUNK_ATTEMPTS {
            return Err(TransferError::TooManyRetries(index));
        }
        self.retry_queue.push_back(index);
        Ok(())
    }

    /// Decrypt all chunks in order into `out`, verifying each chunk and the
    /// whole-file hash. Returns the number of bytes written.
    pub fn reassemble<W: Write>(
        &self,
        mut load: impl FnMut(u64) -> io::Result<EncryptedChunk>,
        out: &mut W,
    ) -> Result<u64, TransferError> {
        if !self.is_complete() {
            return Err(TransferError::Incomplete);
        }
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        for index in 0..self.total_chunks() {
            let chunk = load(index)?;
            if chunk.index != index {
                return Err(TransferError::BadChunk("index mismatch"));
            }
            let plain = Zeroizing::new(
                storage::decrypt_chunk(&self.key, &chunk).map_err(TransferError::BadChunk)?,
            );
            if Some(plain.len()) != self.expected_len(index) {
                return Err(TransferError::BadChunk("wrong length"));
            }
            hasher.update(&plain[..]);
            out.write_all(&plain)?;
            written += plain.len() as u64;
        }
        out.flush()?;
        if written != self.offer.size || hex(&hasher.finalize()) != self.offer.content_hash {
            return Err(TransferError::HashMismatch);
        }
        Ok(written)
    }
}

/// `name`, `name (1).ext`, `name (2).ext`, ...
pub fn candidate_name(filename: &str, n: u32) -> String {
    if n == 0 {
        return filename.to_string();
    }
    match filename.rfind('.') {
        Some(pos) if pos > 0 => format!("{} ({n}){}", &filename[..pos], &filename[pos..]),
        _ => format!("{filename} ({n})"),
    }
}

/// Move the finished temp file `src` into `dir` under `filename` (already
/// sanitised) without ever replacing an existing file. Returns the path.
pub fn place_without_overwrite(src: &Path, dir: &Path, filename: &str) -> io::Result<PathBuf> {
    for n in 0..1000 {
        let dest = dir.join(candidate_name(filename, n));
        // A hard link fails atomically if `dest` exists.
        match std::fs::hard_link(src, &dest) {
            Ok(()) => {
                let _ = std::fs::remove_file(src);
                return Ok(dest);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => {}
        }
        // Filesystem without hard links: reserve the name, then replace our
        // own empty placeholder.
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)
        {
            Ok(_) => {
                std::fs::rename(src, &dest)?;
                return Ok(dest);
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free file name",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_static_secret, get_public_key};

    fn keys() -> ([u8; 32], [u8; 32]) {
        let secret = generate_static_secret();
        (secret, get_public_key(&secret))
    }

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn receive_all(
        incoming: &mut IncomingTransfer,
        chunks: &[EncryptedChunk],
    ) -> Result<(), TransferError> {
        loop {
            let batch = incoming.next_requests(4);
            if batch.is_empty() {
                return Ok(());
            }
            for i in batch {
                let chunk = &chunks[i as usize];
                incoming.verify_chunk(i, chunk)?;
                incoming.mark_received(i);
            }
        }
    }

    #[test]
    fn chunk_reassemble_verify_roundtrip() {
        let (secret, public) = keys();
        for len in [0usize, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE - 7] {
            let file = data(len);
            let (offer, chunks) =
                prepare_outgoing("report.pdf", Some("application/pdf"), &file, &public).unwrap();
            let offer = validate_offer(&offer, 100 << 20).unwrap();
            assert_eq!(offer.total_chunks as usize, chunks.len());
            let mut incoming = IncomingTransfer::new(offer, &secret).unwrap();
            receive_all(&mut incoming, &chunks).unwrap();
            assert!(incoming.is_complete());
            let mut out = Vec::new();
            let n = incoming
                .reassemble(|i| Ok(chunks[i as usize].clone()), &mut out)
                .unwrap();
            assert_eq!(n as usize, len);
            assert_eq!(out, file);
        }
    }

    #[test]
    fn tampered_chunk_rejected() {
        let (secret, public) = keys();
        let (offer, mut chunks) =
            prepare_outgoing("a.bin", None, &data(CHUNK_SIZE * 2), &public).unwrap();
        let mut incoming = IncomingTransfer::new(offer, &secret).unwrap();
        assert_eq!(incoming.next_requests(4), vec![0, 1]);
        chunks[1].ciphertext[10] ^= 1;
        assert!(incoming.verify_chunk(0, &chunks[0]).is_ok());
        assert!(matches!(
            incoming.verify_chunk(1, &chunks[1]),
            Err(TransferError::BadChunk(_))
        ));
        // A chunk for one index answered at another index is rejected too.
        assert!(incoming.verify_chunk(1, &chunks[0]).is_err());
        // Retries are bounded.
        for _ in 0..MAX_CHUNK_ATTEMPTS - 1 {
            incoming.request_failed(1).unwrap();
            assert_eq!(incoming.next_requests(4), vec![1]);
        }
        assert_eq!(
            incoming.request_failed(1),
            Err(TransferError::TooManyRetries(1))
        );
    }

    #[test]
    fn reassembly_detects_swapped_or_tampered_storage() {
        let (secret, public) = keys();
        let (offer, chunks) =
            prepare_outgoing("a.bin", None, &data(CHUNK_SIZE * 2), &public).unwrap();
        let mut incoming = IncomingTransfer::new(offer, &secret).unwrap();
        receive_all(&mut incoming, &chunks).unwrap();
        let mut out = Vec::new();
        let swapped = incoming.reassemble(|i| Ok(chunks[1 - i as usize].clone()), &mut out);
        assert!(swapped.is_err());
        let mut bad = chunks.clone();
        bad[0].ciphertext[0] ^= 0xff;
        assert!(
            incoming
                .reassemble(|i| Ok(bad[i as usize].clone()), &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn wrong_recipient_or_replayed_key_rejected() {
        let (_, public) = keys();
        let (other_secret, _) = keys();
        let (offer, _) = prepare_outgoing("a", None, b"x", &public).unwrap();
        assert!(IncomingTransfer::new(offer.clone(), &other_secret).is_err());

        let (secret, public) = keys();
        let (mut offer, _) = prepare_outgoing("a", None, b"x", &public).unwrap();
        offer.transfer_id = new_transfer_id();
        assert!(matches!(
            IncomingTransfer::new(offer, &secret),
            Err(TransferError::InvalidSealedKey)
        ));
    }

    #[test]
    fn filename_sanitisation_table() {
        let long = format!("{}.txt", "a".repeat(400));
        let cases: &[(&str, &str)] = &[
            ("report.pdf", "report.pdf"),
            ("../../etc/passwd", "passwd"),
            ("..\\..\\Windows\\System32\\evil.dll", "evil.dll"),
            ("C:\\Users\\x\\a.txt", "a.txt"),
            ("C:evil.txt", "C_evil.txt"),
            ("file.txt:stream", "file.txt_stream"),
            ("a<b>c|d?e*f\"g", "a_b_c_d_e_f_g"),
            ("..", "file"),
            ("", "file"),
            ("/", "file"),
            ("   .hidden  ", "hidden"),
            ("trailing. . .", "trailing"),
            ("CON", "_CON"),
            ("con.txt", "_con.txt"),
            ("Nul.tar.gz", "_Nul.tar.gz"),
            ("COM1", "_COM1"),
            ("lpt9.log", "_lpt9.log"),
            ("COM10", "COM10"),
            ("CONSOLE.txt", "CONSOLE.txt"),
            ("bell\u{7}\n\r.txt", "bell.txt"),
            ("invoice\u{202E}fdp.exe", "invoicefdp.exe"),
            ("résumé 2024.docx", "résumé 2024.docx"),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitize_filename(raw), *want, "input {raw:?}");
        }
        let s = sanitize_filename(&long);
        assert!(s.len() <= MAX_FILENAME_BYTES && s.ends_with(".txt"));
        let multibyte = "ğ".repeat(300);
        let s = sanitize_filename(&multibyte);
        assert!(s.len() <= MAX_FILENAME_BYTES && s.chars().all(|c| c == 'ğ'));
    }

    fn valid_offer() -> FileOffer {
        let (_, public) = keys();
        prepare_outgoing("a.txt", Some("text/plain"), &data(CHUNK_SIZE + 5), &public)
            .unwrap()
            .0
    }

    #[test]
    fn oversized_or_invalid_offers_rejected() {
        let ok = valid_offer();
        assert!(validate_offer(&ok, 100 << 20).is_ok());
        assert!(matches!(
            validate_offer(&ok, 1000),
            Err(TransferError::TooLarge { .. })
        ));

        let bad: Vec<(FileOffer, TransferError)> = vec![
            (
                FileOffer {
                    transfer_id: "../../x".into(),
                    ..ok.clone()
                },
                TransferError::InvalidTransferId,
            ),
            (
                FileOffer {
                    transfer_id: "short".into(),
                    ..ok.clone()
                },
                TransferError::InvalidTransferId,
            ),
            (
                FileOffer {
                    filename: "a".repeat(MAX_RAW_FILENAME_BYTES + 1),
                    ..ok.clone()
                },
                TransferError::FilenameTooLong,
            ),
            (
                FileOffer {
                    total_chunks: ok.total_chunks + 1,
                    ..ok.clone()
                },
                TransferError::ChunkCountMismatch,
            ),
            (
                FileOffer {
                    total_chunks: 0,
                    ..ok.clone()
                },
                TransferError::ChunkCountMismatch,
            ),
            (
                FileOffer {
                    chunk_size: 0,
                    ..ok.clone()
                },
                TransferError::InvalidChunkSize,
            ),
            (
                FileOffer {
                    chunk_size: u32::MAX,
                    ..ok.clone()
                },
                TransferError::InvalidChunkSize,
            ),
            (
                FileOffer {
                    size: u64::MAX,
                    total_chunks: u64::MAX,
                    ..ok.clone()
                },
                TransferError::TooLarge {
                    size: u64::MAX,
                    limit: 100 << 20,
                },
            ),
            (
                FileOffer {
                    content_hash: "zz".into(),
                    ..ok.clone()
                },
                TransferError::InvalidContentHash,
            ),
            (
                FileOffer {
                    content_hash: ok.content_hash.to_uppercase(),
                    ..ok.clone()
                },
                TransferError::InvalidContentHash,
            ),
            (
                FileOffer {
                    sealed_key: vec![0; 4],
                    ..ok.clone()
                },
                TransferError::InvalidSealedKey,
            ),
            (
                FileOffer {
                    sealed_key: vec![0; 100_000],
                    ..ok.clone()
                },
                TransferError::InvalidSealedKey,
            ),
        ];
        for (offer, want) in bad {
            assert_eq!(validate_offer(&offer, 100 << 20), Err(want));
        }

        // Too many chunks even when the size limit would allow it.
        let huge = FileOffer {
            size: (MAX_TOTAL_CHUNKS + 1) * u64::from(MIN_CHUNK_SIZE),
            chunk_size: MIN_CHUNK_SIZE,
            total_chunks: MAX_TOTAL_CHUNKS + 1,
            ..ok.clone()
        };
        assert_eq!(
            validate_offer(&huge, u64::MAX),
            Err(TransferError::TooManyChunks)
        );

        // Fields that are cleaned rather than rejected.
        let cleaned = validate_offer(
            &FileOffer {
                filename: "../x/CON.txt".into(),
                mime: Some("text/html; <script>".into()),
                ..ok.clone()
            },
            100 << 20,
        )
        .unwrap();
        assert_eq!(cleaned.filename, "_CON.txt");
        assert_eq!(cleaned.mime, None);
    }

    #[test]
    fn out_of_range_and_unrequested_chunks_rejected() {
        let (secret, public) = keys();
        let (offer, chunks) = prepare_outgoing("a", None, &data(10), &public).unwrap();
        let mut incoming = IncomingTransfer::new(offer, &secret).unwrap();
        assert_eq!(
            incoming.verify_chunk(0, &chunks[0]),
            Err(TransferError::UnexpectedChunk)
        );
        assert_eq!(
            incoming.verify_chunk(u64::MAX, &chunks[0]),
            Err(TransferError::IndexOutOfRange)
        );
        incoming.mark_received(u64::MAX);
        assert_eq!(incoming.request_failed(u64::MAX), Ok(()));
        assert_eq!(incoming.received_chunks(), 0);
    }

    #[test]
    fn placement_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("alterchat-xfer-test-{}", new_transfer_id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"existing").unwrap();
        let mut placed = Vec::new();
        for i in 0..2 {
            let tmp = dir.join(format!(".tmp{i}"));
            std::fs::write(&tmp, format!("new{i}")).unwrap();
            placed.push(place_without_overwrite(&tmp, &dir, "a.txt").unwrap());
            assert!(!tmp.exists());
        }
        assert_eq!(std::fs::read(dir.join("a.txt")).unwrap(), b"existing");
        assert_eq!(placed[0], dir.join("a (1).txt"));
        assert_eq!(placed[1], dir.join("a (2).txt"));
        assert_eq!(std::fs::read(&placed[1]).unwrap(), b"new1");
        assert_eq!(candidate_name("noext", 3), "noext (3)");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
