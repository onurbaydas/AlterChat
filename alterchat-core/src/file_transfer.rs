use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2pRequest {
    File {
        filename: String,
        data: Vec<u8>,
    },
    FileChunk {
        transfer_id: String,
        index: u64,
        total: u64,
        content_hash: String,
        data: Vec<u8>,
    },
    WebRtcSignal {
        signal: String,
    },
    #[deprecated(since = "0.2.0", note = "Use X3dhDm instead")]
    PrivateMessage {
        text: String,
        sender_nick: String,
        timestamp: i64,
        ttl: Option<i64>,
        pow_token: Option<crate::pow::PoWToken>,
    },
    #[deprecated(since = "0.2.0", note = "Use X3dhDm instead")]
    RatchetPrivateMessage {
        envelope: Vec<u8>,
        sender_nick: String,
        timestamp: i64,
        ttl: Option<i64>,
    },
    /// X3DH + ML-KEM handshake and Double Ratchet encrypted DM.
    /// `message` is an encoded [`crate::dm::DmMessage`]; it carries the X3DH
    /// initial message until the initiator's session is confirmed. Nick,
    /// timestamp and TTL are inside the ciphertext.
    X3dhDm {
        message: Vec<u8>,
    },
    /// Asks the peer for its current signed prekey bundle.
    GetPrekeyBundle,
    CapabilityAnnouncement {
        peer_id: String,
        storage_node: bool,
        relay_node: bool,
        dht_server: bool,
        media_relay: bool,
        capacity_score: u32,
        protocol_versions: Vec<String>,
    },
    OnionForward {
        packet: Vec<u8>,
    },
    PluginEvent {
        plugin_id: String,
        event_json: String,
    },
    PowChallenge {
        challenge_id: String,
        difficulty_bits: u8,
        nonce: Vec<u8>,
    },
    PowSolution {
        challenge_id: String,
        solution: Vec<u8>,
    },
    /// Sender -> recipient: announce a file (see `transfer` module docs).
    FileOffer {
        offer: crate::transfer::FileOffer,
    },
    /// Recipient -> sender: pull one encrypted chunk of an accepted offer.
    FileChunkRequest {
        transfer_id: String,
        index: u64,
    },
    /// Either side: the transfer ended (rejected, cancelled, failed or done).
    FileFinished {
        transfer_id: String,
        ok: bool,
        reason: String,
    },
    /// Group room catch-up: "these are my heads, send what I am missing".
    /// `room_tag` is `crdt::Room::sync_tag()` (hash of the room key), so the
    /// room name is not revealed to peers that do not hold the key.
    RoomSyncRequest {
        room_tag: Vec<u8>,
        heads: Vec<Vec<u8>>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum P2pResponse {
    FileAck {
        success: bool,
        message: String,
    },
    FileChunkAck {
        transfer_id: String,
        index: u64,
        success: bool,
    },
    WebRtcAck {
        success: bool,
    },
    PrivateMessageAck {
        success: bool,
    },
    RatchetPrivateMessageAck {
        success: bool,
    },
    X3dhDmAck {
        success: bool,
        /// The receiver does not know the session the message was sent on;
        /// the sender should discard it and start a new handshake.
        #[serde(default)]
        reset_session: bool,
    },
    /// JSON-encoded [`crate::x3dh::PreKeyBundle`], `None` if refused.
    PrekeyBundle {
        bundle: Option<Vec<u8>>,
    },
    CapabilityAck {
        success: bool,
    },
    OnionAck {
        success: bool,
    },
    PluginEventAck {
        success: bool,
    },
    PowAck {
        success: bool,
    },
    /// `success` means the offer was queued for the user's decision.
    FileOfferAck {
        transfer_id: String,
        success: bool,
        message: String,
    },
    /// `chunk` is `None` if the sender has no such transfer/index.
    FileChunkData {
        transfer_id: String,
        index: u64,
        chunk: Option<crate::storage::EncryptedChunk>,
    },
    FileFinishedAck {
        success: bool,
    },
    /// `payload` is a padded, room-key-encrypted change bundle (empty when
    /// nothing is missing or the room is unknown). `more` asks the requester
    /// to send another request with its updated heads.
    RoomSyncResponse {
        payload: Vec<u8>,
        more: bool,
    },
}
