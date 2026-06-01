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
    /// X3DH el sıkışması + Double Ratchet ile şifreli DM.
    /// İlk mesajda init_msg Some, sonrakilerde None.
    X3dhDm {
        /// X3DH InitialMessage (bincode serialize edilmiş), sadece ilk mesajda
        init_msg: Option<Vec<u8>>,
        /// Double Ratchet DrEnvelope (bincode serialize edilmiş)
        dr_envelope: Vec<u8>,
        sender_dh_pub: [u8; 32],
        sender_nick: String,
        timestamp: i64,
        ttl: Option<i64>,
    },
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
}
