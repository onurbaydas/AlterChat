// Legacy DM request variants are deprecated but still handled for
// compatibility with older peers.
#![allow(deprecated)]

pub mod db;
pub mod dm_runtime;
pub mod profile;
#[macro_use]
pub mod commands;
use alterchat_core::{crdt, governance, libp2p, network, plugin, storage};
use libp2p::{futures::StreamExt, gossipsub, mdns, swarm::SwarmEvent, PeerId};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use tauri::{Emitter, Manager};
use tokio::sync::mpsc;

#[derive(Clone, serde::Serialize)]
struct ChatMessage {
    peer_id: String,
    sender: String,
    text: String,
    timestamp: i64,
    ttl: Option<i64>,
}

#[derive(Clone)]
pub enum AppCommand {
    SendMessage {
        text: String,
        nick: String,
        ttl: Option<i64>,
    },
    JoinChannel {
        name: String,
        password: Option<String>,
    },
    SendFile {
        peer_id: String,
        filename: String,
        data: Vec<u8>,
    },
    SendWebRtcSignal {
        peer_id: String,
        signal: String,
    },
    SetBootstrap {
        addr: String,
    },
    SaveSettings {
        config: FullConfig,
    },
    AddFriend {
        peer_id: String,
        nickname: String,
        offline_pubkey: Option<String>,
    },
    RemoveFriend {
        peer_id: String,
    },
    SendPrivateMessage {
        peer_id: String,
        text: String,
        sender_nick: String,
        ttl: Option<i64>,
        use_onion: bool,
    },
    SaveGroup {
        channel_name: String,
        password: Option<String>,
    },
    RemoveGroup {
        channel_name: String,
    },
    StartSession {
        db_path: String,
        db_key: String,
        keypair: libp2p::identity::Keypair,
    },
    // #4 Dağıtık revokasyon
    RevokeInviteGlobal {
        invite_id: String,
    },
    // #11 Anonim kanal: kalıcısız, tek kullanımlık oda
    JoinAnonymousChannel {
        display_name: String,
    },
    // #15 Oda revokasyon listesini DHT'e yayınla
    PublishRoomRevocations {
        room_id: String,
    },
}

pub struct AppState {
    tx: mpsc::Sender<AppCommand>,
    db_path: tokio::sync::Mutex<Option<String>>,
    db_key: tokio::sync::Mutex<Option<String>>,
    keypair: tokio::sync::Mutex<Option<libp2p::identity::Keypair>>,
    pub peer_id: tokio::sync::Mutex<Option<String>>,
    pub offline_pubkey: tokio::sync::Mutex<Option<String>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct FullConfig {
    nick: String,
    offline_pubkey: Option<String>,
    bootstrap_ip: String,
    bootstrap_addrs: Vec<String>,
    tor_enabled: bool,
    proxy_mode: String,
    proxy_addr: String,
    mdns_enabled: bool,
    dht_server_mode: bool,
    relay_enabled: bool,
    transport_preference: String,
    relay_fallback_enabled: bool,
    publish_capabilities: bool,
    cover_traffic: bool,
    msg_delay: bool,
    local_notifications: bool,
    unknown_peer_policy: String,
    min_trust_dm: i64,
    min_trust_file: i64,
    min_trust_invite: i64,
    default_ttl: Option<i64>,
    persistence_enabled: bool,
    invite_only_default: bool,
    proof_of_work_enabled: bool,
    rate_limit_per_minute: i64,
    storage_node_enabled: bool,
    storage_quota_mb: i64,
    storage_retention_days: i64,
    sfu_threshold: i64,
    preferred_sfu_peer: String,
    accept_relay: bool,
    experimental_media_e2ee: bool,
}

impl Default for FullConfig {
    fn default() -> Self {
        Self {
            nick: String::new(),
            offline_pubkey: None,
            bootstrap_ip: String::new(),
            bootstrap_addrs: Vec::new(),
            tor_enabled: false,
            proxy_mode: "none".to_string(),
            proxy_addr: String::new(),
            mdns_enabled: true,
            dht_server_mode: false,
            relay_enabled: false,
            transport_preference: "tcp".to_string(),
            relay_fallback_enabled: false,
            publish_capabilities: true,
            cover_traffic: false,
            msg_delay: true,
            local_notifications: true,
            unknown_peer_policy: "request-only".to_string(),
            min_trust_dm: 0,
            min_trust_file: 0,
            min_trust_invite: 0,
            default_ttl: None,
            persistence_enabled: true,
            invite_only_default: false,
            proof_of_work_enabled: false,
            rate_limit_per_minute: 30,
            storage_node_enabled: false,
            storage_quota_mb: 512,
            storage_retention_days: 7,
            sfu_threshold: 6,
            preferred_sfu_peer: String::new(),
            accept_relay: false,
            experimental_media_e2ee: false,
        }
    }
}

fn setting_bool(conn: &rusqlite::Connection, key: &str, default: bool) -> bool {
    db::load_setting(conn, key)
        .unwrap_or(None)
        .map(|v| v == "true")
        .unwrap_or(default)
}

fn setting_i64(conn: &rusqlite::Connection, key: &str, default: i64) -> i64 {
    db::load_setting(conn, key)
        .unwrap_or(None)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(default)
}

fn setting_opt_i64(conn: &rusqlite::Connection, key: &str) -> Option<i64> {
    db::load_setting(conn, key).unwrap_or(None).and_then(|v| {
        if v.is_empty() {
            None
        } else {
            v.parse::<i64>().ok()
        }
    })
}

fn load_full_config(conn: &rusqlite::Connection) -> FullConfig {
    let mut config = FullConfig::default();
    config.nick = db::load_setting(conn, "nick")
        .unwrap_or(None)
        .unwrap_or_default();
    config.bootstrap_ip = db::load_setting(conn, "bootstrap_ip")
        .unwrap_or(None)
        .unwrap_or_default();
    config.bootstrap_addrs = db::load_setting(conn, "bootstrap_addrs")
        .unwrap_or(None)
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .unwrap_or_else(|| {
            if config.bootstrap_ip.trim().is_empty() {
                Vec::new()
            } else {
                vec![config.bootstrap_ip.clone()]
            }
        });
    config.tor_enabled = setting_bool(conn, "tor_enabled", false);
    config.proxy_mode = db::load_setting(conn, "proxy_mode")
        .unwrap_or(None)
        .unwrap_or_else(|| "none".to_string());
    config.proxy_addr = db::load_setting(conn, "proxy_addr")
        .unwrap_or(None)
        .unwrap_or_default();
    config.mdns_enabled = setting_bool(conn, "mdns_enabled", true);
    config.dht_server_mode = setting_bool(conn, "dht_server_mode", false);
    config.relay_enabled = setting_bool(conn, "relay_enabled", false);
    config.transport_preference = db::load_setting(conn, "transport_preference")
        .unwrap_or(None)
        .unwrap_or_else(|| "tcp".to_string());
    config.relay_fallback_enabled = setting_bool(conn, "relay_fallback_enabled", false);
    config.publish_capabilities = setting_bool(conn, "publish_capabilities", true);
    config.cover_traffic = setting_bool(conn, "cover_traffic", false);
    config.msg_delay = setting_bool(conn, "msg_delay", true);
    config.local_notifications = setting_bool(conn, "local_notifications", true);
    config.unknown_peer_policy = db::load_setting(conn, "unknown_peer_policy")
        .unwrap_or(None)
        .unwrap_or_else(|| "request-only".to_string());
    config.min_trust_dm = setting_i64(conn, "min_trust_dm", 0);
    config.min_trust_file = setting_i64(conn, "min_trust_file", 0);
    config.min_trust_invite = setting_i64(conn, "min_trust_invite", 0);
    config.default_ttl = setting_opt_i64(conn, "default_ttl");
    config.persistence_enabled = setting_bool(conn, "persistence_enabled", true);
    config.invite_only_default = setting_bool(conn, "invite_only_default", false);
    config.proof_of_work_enabled = setting_bool(conn, "proof_of_work_enabled", false);
    config.rate_limit_per_minute = setting_i64(conn, "rate_limit_per_minute", 30);
    if let Ok(storage) = db::get_storage_settings(conn) {
        config.storage_node_enabled = storage.storage_node_enabled;
        config.storage_quota_mb = storage.quota_mb;
        config.storage_retention_days = storage.retention_days;
    }
    config.sfu_threshold = setting_i64(conn, "sfu_threshold", 6);
    config.preferred_sfu_peer = db::load_setting(conn, "preferred_sfu_peer")
        .unwrap_or(None)
        .unwrap_or_default();
    config.accept_relay = setting_bool(conn, "accept_relay", false);
    config.experimental_media_e2ee = setting_bool(conn, "experimental_media_e2ee", false);
    config
}

fn save_full_config_to_db(conn: &rusqlite::Connection, config: &FullConfig) -> Result<(), String> {
    db::save_setting(conn, "nick", &config.nick).map_err(|e| e.to_string())?;
    db::save_setting(conn, "bootstrap_ip", &config.bootstrap_ip).map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "bootstrap_addrs",
        &serde_json::to_string(&config.bootstrap_addrs).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "tor_enabled",
        if config.tor_enabled { "true" } else { "false" },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(conn, "proxy_mode", &config.proxy_mode).map_err(|e| e.to_string())?;
    db::save_setting(conn, "proxy_addr", &config.proxy_addr).map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "mdns_enabled",
        if config.mdns_enabled { "true" } else { "false" },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "dht_server_mode",
        if config.dht_server_mode {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "relay_enabled",
        if config.relay_enabled {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(conn, "transport_preference", &config.transport_preference)
        .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "relay_fallback_enabled",
        if config.relay_fallback_enabled {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "publish_capabilities",
        if config.publish_capabilities {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "cover_traffic",
        if config.cover_traffic {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "msg_delay",
        if config.msg_delay { "true" } else { "false" },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "local_notifications",
        if config.local_notifications {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(conn, "unknown_peer_policy", &config.unknown_peer_policy)
        .map_err(|e| e.to_string())?;
    db::save_setting(conn, "min_trust_dm", &config.min_trust_dm.to_string())
        .map_err(|e| e.to_string())?;
    db::save_setting(conn, "min_trust_file", &config.min_trust_file.to_string())
        .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "min_trust_invite",
        &config.min_trust_invite.to_string(),
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "default_ttl",
        &config
            .default_ttl
            .map(|v| v.to_string())
            .unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "persistence_enabled",
        if config.persistence_enabled {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "invite_only_default",
        if config.invite_only_default {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "proof_of_work_enabled",
        if config.proof_of_work_enabled {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "rate_limit_per_minute",
        &config.rate_limit_per_minute.to_string(),
    )
    .map_err(|e| e.to_string())?;
    db::save_storage_settings(
        conn,
        &db::StorageSettings {
            storage_node_enabled: config.storage_node_enabled,
            quota_mb: config.storage_quota_mb,
            retention_days: config.storage_retention_days,
        },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(conn, "sfu_threshold", &config.sfu_threshold.to_string())
        .map_err(|e| e.to_string())?;
    db::save_setting(conn, "preferred_sfu_peer", &config.preferred_sfu_peer)
        .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "accept_relay",
        if config.accept_relay { "true" } else { "false" },
    )
    .map_err(|e| e.to_string())?;
    db::save_setting(
        conn,
        "experimental_media_e2ee",
        if config.experimental_media_e2ee {
            "true"
        } else {
            "false"
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn decode_x25519_hex(hex_key: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_key).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn load_or_init_ratchet_state(
    conn: &rusqlite::Connection,
    peer_id: &str,
    my_peer_id: &str,
    my_secret: &[u8; 32],
    peer_pubkey: &[u8; 32],
) -> alterchat_core::crypto::RatchetState {
    if let Ok(Some(blob)) = db::load_ratchet_state(conn, peer_id) {
        if let Ok(state) = bincode::deserialize::<alterchat_core::crypto::RatchetState>(&blob) {
            return state;
        }
    }
    let shared = alterchat_core::crypto::derive_static_shared_secret(my_secret, peer_pubkey);
    alterchat_core::crypto::RatchetState::for_peer_pair(shared, my_peer_id, peer_id)
}

fn save_ratchet_state(
    conn: &rusqlite::Connection,
    peer_id: &str,
    state: &alterchat_core::crypto::RatchetState,
) {
    if let Ok(blob) = bincode::serialize(state) {
        let _ = db::save_ratchet_state(conn, peer_id, &blob);
    }
}

fn current_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn my_capacity_score() -> u32 {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    let mem_gb = sys.total_memory() / 1024 / 1024;
    let cores = sys.cpus().len() as u64;
    ((mem_gb * 10) + (cores * 50)) as u32
}

/// Files belonging to the active profile. `whole_profile == false` keeps the
/// identity key and only removes the message database and stored chunks.
fn active_profile_paths(db_path: Option<&str>, whole_profile: bool) -> Vec<PathBuf> {
    let Some(db) = db_path else {
        return Vec::new();
    };
    let db = PathBuf::from(db);
    if whole_profile {
        if let Some(dir) = db.parent() {
            return vec![dir.to_path_buf()];
        }
    }
    let mut paths = vec![db.clone()];
    for suffix in ["-shm", "-wal", "-journal"] {
        let mut p = db.clone().into_os_string();
        p.push(suffix);
        paths.push(PathBuf::from(p));
    }
    paths.push(storage_root_for_db(&db.to_string_lossy()));
    paths
}

fn all_profile_paths(root: &Path) -> Vec<PathBuf> {
    vec![root.to_path_buf()]
}

fn wipe_path(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.is_file() {
            if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                use std::io::Write;
                let mut remaining = meta.len();
                let zeroes = [0u8; 8192];
                while remaining > 0 {
                    let n = remaining.min(zeroes.len() as u64) as usize;
                    if f.write_all(&zeroes[..n]).is_err() {
                        break;
                    }
                    remaining -= n as u64;
                }
                let _ = f.flush();
            }
        }
    }
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                wipe_path(&entry.path());
            }
        }
        let _ = std::fs::remove_dir(path);
    } else {
        let _ = std::fs::remove_file(path);
    }
}

/// Accept only `[A-Za-z0-9_-]{1,128}` so a peer-supplied id can never escape
/// the chunk directory (`..`, `/`, `\`, drive letters, ...).
pub(crate) fn is_safe_transfer_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn storage_root_for_db(db_path: &str) -> PathBuf {
    profile::storage_root(db_path)
}

/// Root directory that holds all non-amnesic profiles.
pub(crate) fn profiles_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|d| d.join("profiles"))
        .map_err(|e| format!("Cannot resolve app data dir: {e}"))
}

fn ensure_default_room_governance(
    conn: &rusqlite::Connection,
    room_id: &str,
    keypair: &libp2p::identity::Keypair,
    peer_id: &str,
) -> Result<(), String> {
    if db::count_roles(conn, room_id).map_err(|e| e.to_string())? > 0 {
        return Ok(());
    }
    let grant = governance::create_permission_grant(
        keypair,
        room_id.to_string(),
        peer_id.to_string(),
        "owner".to_string(),
        None,
    )?;
    let grant_json = serde_json::to_string(&grant).map_err(|e| e.to_string())?;
    db::seed_default_roles(conn, room_id, Some(&grant_json)).map_err(|e| e.to_string())
}

fn peer_can_contact(conn: &rusqlite::Connection, peer_id: &str, config: &FullConfig) -> bool {
    let settings = db::get_peer_settings(conn, peer_id).ok();
    if settings.as_ref().map(|s| s.blocked).unwrap_or(false) {
        return false;
    }
    let is_known = db::get_friends(conn)
        .map(|friends| friends.iter().any(|friend| friend.peer_id == peer_id))
        .unwrap_or(false);
    match config.unknown_peer_policy.as_str() {
        "allow" => true,
        "block" => is_known,
        _ => is_known,
    }
}

fn rate_limit_allows(
    buckets: &mut HashMap<String, VecDeque<i64>>,
    peer_id: &str,
    per_minute: i64,
) -> bool {
    let now = current_millis();
    let bucket = buckets.entry(peer_id.to_string()).or_default();
    while bucket.front().map(|ts| now - *ts > 60_000).unwrap_or(false) {
        bucket.pop_front();
    }
    if bucket.len() >= per_minute.max(1) as usize {
        return false;
    }
    bucket.push_back(now);
    true
}

fn load_roles_and_grants(
    conn: &rusqlite::Connection,
    room_id: &str,
) -> (Vec<governance::Role>, Vec<governance::PermissionGrant>) {
    let roles = db::list_roles(conn, room_id)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|json| serde_json::from_str::<governance::Role>(&json).ok())
        .collect();
    let grants = db::list_permission_grants(conn, room_id)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|json| serde_json::from_str::<governance::PermissionGrant>(&json).ok())
        .collect();
    (roles, grants)
}

fn room_action_allowed(
    conn: &rusqlite::Connection,
    room_id: &str,
    peer_id: &str,
    permission: governance::Permission,
) -> bool {
    let role_count = db::count_roles(conn, room_id).unwrap_or(0);
    if role_count == 0 {
        return true;
    }
    let (roles, grants) = load_roles_and_grants(conn, room_id);
    governance::has_permission(&grants, &roles, peer_id, permission, governance::now_ms())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ProfileConfigExport {
    app: FullConfig,
    raw_settings: Vec<(String, String)>,
}

fn cleanup_expired_storage(conn: &rusqlite::Connection) {
    if let Ok(expired) = db::expired_stored_chunks(conn) {
        for (chunk_hash, path) in expired {
            let _ = std::fs::remove_file(path);
            let _ = db::delete_stored_chunk(conn, &chunk_hash);
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PluginRegistryEntry {
    manifest: plugin::PluginManifest,
    enabled: bool,
    granted_capabilities: Vec<plugin::PluginCapability>,
}

fn rejection_for_request(
    request: &alterchat_core::file_transfer::P2pRequest,
) -> alterchat_core::file_transfer::P2pResponse {
    use alterchat_core::file_transfer::{P2pRequest, P2pResponse};
    match request {
        P2pRequest::File { .. } => P2pResponse::FileAck {
            success: false,
            message: "local policy rejected request".to_string(),
        },
        P2pRequest::FileChunk {
            transfer_id, index, ..
        } => P2pResponse::FileChunkAck {
            transfer_id: transfer_id.clone(),
            index: *index,
            success: false,
        },
        P2pRequest::WebRtcSignal { .. } => P2pResponse::WebRtcAck { success: false },
        P2pRequest::PrivateMessage { .. } => P2pResponse::PrivateMessageAck { success: false },
        P2pRequest::RatchetPrivateMessage { .. } => {
            P2pResponse::RatchetPrivateMessageAck { success: false }
        }
        P2pRequest::X3dhDm { .. } => P2pResponse::X3dhDmAck {
            success: false,
            reset_session: false,
        },
        P2pRequest::GetPrekeyBundle => P2pResponse::PrekeyBundle { bundle: None },
        P2pRequest::CapabilityAnnouncement { .. } => P2pResponse::CapabilityAck { success: false },
        P2pRequest::OnionForward { .. } => P2pResponse::OnionAck { success: false },
        P2pRequest::PluginEvent { .. } => P2pResponse::PluginEventAck { success: false },
        P2pRequest::PowChallenge { .. } | P2pRequest::PowSolution { .. } => {
            P2pResponse::PowAck { success: false }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (tx, mut rx) = mpsc::channel(100);

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            tx,
            db_path: tokio::sync::Mutex::new(None),
            db_key: tokio::sync::Mutex::new(None),
            keypair: tokio::sync::Mutex::new(None),
            peer_id: tokio::sync::Mutex::new(None),
            offline_pubkey: tokio::sync::Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::social::get_peer_id, commands::messaging::send_message, commands::messaging::join_channel, commands::media::send_file, commands::settings::set_bootstrap_addr, commands::media::send_webrtc_signal,
            commands::settings::get_settings, commands::settings::save_settings, commands::settings::get_full_config, commands::settings::save_full_config, commands::settings::export_profile_config, commands::settings::import_profile_config,
            commands::social::get_friends, commands::social::add_friend, commands::social::remove_friend, commands::social::send_private_message, commands::social::endorse_peer,
            commands::social::get_private_messages, commands::social::get_peer_settings, commands::social::save_peer_settings, commands::room::get_room_settings, commands::room::save_room_settings,
            commands::social::get_saved_groups, commands::social::save_group, commands::social::remove_group, commands::settings::get_capacity_score,
            commands::governance::create_invite, commands::governance::accept_invite, commands::governance::list_invites, commands::governance::revoke_invite,
            commands::governance::save_role, commands::governance::list_roles, commands::governance::create_permission_grant, commands::governance::save_permission_grant, commands::governance::list_permission_grants,
            commands::governance::create_trust_edge, commands::governance::save_trust_edge, commands::governance::list_trust_edges, commands::messaging::search_messages,
            commands::media::prepare_encrypted_file, commands::storage::list_file_manifests, commands::storage::list_stored_chunks, commands::storage::list_peer_capabilities,
            commands::plugin::save_plugin, commands::plugin::list_plugins, commands::auth::solve_pow_challenge,
            commands::auth::panic_wipe, commands::auth::panic_wipe_all, commands::auth::login_profile,
            // Yeni komutlar (#5 Safety, #6 QR, #9/#14 Vault, #11 Anon, #4 Revoke, #21 System)
            commands::settings::get_safety_number, commands::settings::get_peer_uri,
            commands::settings::export_vault_encrypted, commands::settings::import_vault_encrypted,
            commands::settings::revoke_invite_global, commands::settings::join_anonymous_channel,
            commands::system::get_network_status, commands::system::get_crypto_capabilities,
            commands::network_cmds::revoke_invite_network, commands::network_cmds::publish_room_revocations,
            commands::network_cmds::join_anonymous_channel_cmd
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();

            tauri::async_runtime::spawn(async move {
                let mut swarm: Option<libp2p::Swarm<network::AlterChatBehaviour>> = None;
                let mut current_topic_name = "alterchat-global".to_string();
                let mut room = crdt::Room::new(current_topic_name.clone(), None);
                let mut topic = gossipsub::IdentTopic::new(current_topic_name.clone());
                let mut my_peer_id = String::new();
                let mut my_offline_pubkey = String::new();
                let mut offline_secret_bytes = zeroize::Zeroizing::new([0u8; 32]);
                let mut current_keypair: Option<libp2p::identity::Keypair> = None;
                let mut dht_check_interval = tokio::time::interval(std::time::Duration::from_secs(30));
                let mut capability_interval = tokio::time::interval(std::time::Duration::from_secs(45));

                let mut conn_opt: Option<rusqlite::Connection> = None;
                let mut current_db_path: Option<String> = None;
                let mut cover_traffic_enabled = false;
                let mut msg_delay_enabled = true;
                let mut mdns_enabled = true;
                let mut runtime_config = FullConfig::default();
                let mut rate_buckets: HashMap<String, VecDeque<i64>> = HashMap::new();
                // #16 PoW ban listesi: 3 başarısız PoW → peer yasaklanır
                let mut pow_ban = alterchat_core::traffic::PowBanList::new();
                const POW_BAN_THRESHOLD: u32 = 3;
                let mut chaff_interval = tokio::time::interval(std::time::Duration::from_secs(60));
                let mut x3dh_rotation_interval = tokio::time::interval(std::time::Duration::from_secs(3600));
                // X3DH + Double Ratchet DM sessions, outbox and DHT mailbox.
                let mut dm_rt = dm_runtime::DmRuntime::new();

                loop {
                    tokio::select! {
                        _ = dht_check_interval.tick() => {
                            if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                dm_rt.on_tick(conn, s, &ctx);
                            }
                            if let Some(ref mut s) = swarm {
                                let my_pubkey_key = alterchat_core::crypto::get_dht_pubkey_key(&my_peer_id);
                                let pubkey_record = libp2p::kad::Record {
                                    key: my_pubkey_key,
                                    value: hex::decode(&my_offline_pubkey).unwrap_or_default(),
                                    publisher: None,
                                    expires: None,
                                };
                                let _ = s.behaviour_mut().kademlia.put_record(pubkey_record, libp2p::kad::Quorum::One);
                            }
                        }
                        _ = x3dh_rotation_interval.tick() => {
                            if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                // Rotates the signed prekey when it is older than a week
                                // (secrets are persisted before the bundle is published).
                                dm_rt.maybe_rotate(conn, s, false);
                            }
                        }
                        _ = chaff_interval.tick() => {
                            // Cover Traffic: periyodik sahte mesaj gönder
                            if cover_traffic_enabled {
                                if let Some(ref mut s) = swarm {
                                    let chaff = alterchat_core::traffic::generate_chaff_payload();
                                    let _ = s.behaviour_mut().gossipsub.publish(topic.clone(), chaff);
                                }
                            }
                        }
                        _ = capability_interval.tick() => {
                            if runtime_config.publish_capabilities {
                                if let Some(ref mut s) = swarm {
                                    let peers = s.connected_peers().cloned().collect::<Vec<_>>();
                                    let protocol_versions = vec!["/alterchat/p2p/1.0.0".to_string()];
                                    for peer in peers {
                                        let _ = s.behaviour_mut().request_response.send_request(
                                            &peer,
                                            alterchat_core::file_transfer::P2pRequest::CapabilityAnnouncement {
                                                peer_id: my_peer_id.clone(),
                                                storage_node: runtime_config.storage_node_enabled,
                                                relay_node: runtime_config.relay_enabled,
                                                dht_server: runtime_config.dht_server_mode,
                                                media_relay: runtime_config.accept_relay,
                                                capacity_score: my_capacity_score(),
                                                protocol_versions: protocol_versions.clone(),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                        Some(cmd) = rx.recv() => match cmd {
                            AppCommand::StartSession { db_path, db_key, keypair } => {
                                current_db_path = Some(db_path.clone());

                                let conn = match db::init_db(&db_path, &db_key) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        let _ = app_handle.emit("session-error", format!("Database open failed: {e}"));
                                        continue;
                                    }
                                };
                                let Ok(ed_keypair) = keypair.clone().try_into_ed25519() else {
                                    let _ = app_handle.emit("session-error", "Identity key is not Ed25519".to_string());
                                    continue;
                                };
                                current_keypair = Some(keypair.clone());
                                my_peer_id = keypair.public().to_peer_id().to_string();
                                offline_secret_bytes.copy_from_slice(ed_keypair.secret().as_ref());
                                my_offline_pubkey = hex::encode(alterchat_core::crypto::get_public_key(&offline_secret_bytes));
                                {
                                    let state = app_handle.state::<AppState>();
                                    *state.peer_id.lock().await = Some(my_peer_id.clone());
                                    *state.offline_pubkey.lock().await = Some(my_offline_pubkey.clone());
                                }

                                let full_config = load_full_config(&conn);
                                runtime_config = full_config.clone();
                                cover_traffic_enabled = full_config.cover_traffic;
                                msg_delay_enabled = full_config.msg_delay;
                                mdns_enabled = full_config.mdns_enabled;
                                let proxy_mode = if full_config.tor_enabled || full_config.proxy_mode == "tor" {
                                    network::ProxyMode::Tor
                                } else if full_config.proxy_mode == "socks5" {
                                    network::ProxyMode::Socks5
                                } else if full_config.proxy_mode == "i2p" {
                                    network::ProxyMode::I2p
                                } else {
                                    network::ProxyMode::Direct
                                };
                                let network_config = network::NetworkPrivacyConfig {
                                    proxy_mode,
                                    transport_preference: match full_config.transport_preference.as_str() {
                                        "quic" => network::TransportPreference::Quic,
                                        "tor" => network::TransportPreference::Tor,
                                        _ => network::TransportPreference::Tcp,
                                    },
                                    proxy_addr: if full_config.proxy_addr.trim().is_empty() { None } else { Some(full_config.proxy_addr.clone()) },
                                    bootstrap_addrs: full_config.bootstrap_addrs.clone(),
                                    mdns_enabled: full_config.mdns_enabled,
                                    dht_server_mode: full_config.dht_server_mode,
                                    relay_enabled: full_config.relay_enabled,
                                    relay_fallback_enabled: full_config.relay_fallback_enabled,
                                    publish_capabilities: full_config.publish_capabilities,
                                    protocol_versions: vec!["/alterchat/p2p/1.0.0".to_string()],
                                };
                                let mut new_swarm = match network::create_swarm(keypair.clone(), network_config.clone()).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        let _ = app_handle.emit("network-status", "offline".to_string());
                                        let _ = app_handle.emit("session-error", format!("Network start failed: {e}"));
                                        continue;
                                    }
                                };
                                let _ = ensure_default_room_governance(&conn, &current_topic_name, &keypair, &my_peer_id);

                                room = match db::load_room(&conn, &current_topic_name) {
                                    Ok(Some(bytes)) => crdt::Room::load(current_topic_name.clone(), &bytes, None).unwrap_or_else(|_| crdt::Room::new(current_topic_name.clone(), None)),
                                    _ => crdt::Room::new(current_topic_name.clone(), None),
                                };

                                // Zero-config: kullanıcı hiçbir şey girmeden ağa girer.
                                // Öncelik sırası: (1) kaydedilmiş peer'lar, (2) user bootstrap, (3) topluluk listesi
                                if let Some(conn) = &conn_opt {
                                    // 7 günden eski peer'ları temizle
                                    let _ = db::cleanup_old_peers(conn, 7 * 24 * 60 * 60 * 1000);
                                    // Önceki oturumdan bilinen peer'lara bağlan
                                    if let Ok(known) = db::load_known_peers(conn) {
                                        for (_, addr_str) in known {
                                            if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                                let _ = new_swarm.dial(addr);
                                            }
                                        }
                                    }
                                }
                                // Kullanıcı bootstrap listesi
                                let mut user_addrs = network_config.bootstrap_addrs.clone();
                                // Kullanıcı hiçbir şey girmediyse topluluk listesini kullan
                                if user_addrs.is_empty() {
                                    user_addrs = alterchat_core::network::COMMUNITY_BOOTSTRAP_ADDRS
                                        .iter().map(|s| s.to_string()).collect();
                                }
                                for addr_str in user_addrs {
                                    if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                        let _ = new_swarm.dial(addr);
                                    }
                                }

                                if let Ok(msgs) = room.get_messages() {
                                    let history: Vec<ChatMessage> = msgs.into_iter().map(|msg| ChatMessage { peer_id: msg.peer_id, sender: msg.sender, text: msg.text, timestamp: msg.timestamp, ttl: msg.ttl }).collect();
                                    let _ = app_handle.emit("chat-history", history);
                                }

                                new_swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
                                // Revokasyon topic'ini her zaman dinle
                                let revoke_topic = gossipsub::IdentTopic::new(alterchat_core::governance::REVOCATION_TOPIC);
                                let _ = new_swarm.behaviour_mut().gossipsub.subscribe(&revoke_topic);
                                let record_key = libp2p::kad::RecordKey::new(&current_topic_name.as_bytes());
                                let _ = new_swarm.behaviour_mut().kademlia.start_providing(record_key.clone());
                                new_swarm.behaviour_mut().kademlia.get_providers(record_key);

                                // X3DH: load or rotate our signed prekey (secrets persisted in the
                                // encrypted DB), publish the bundle, poll friends' DHT mailboxes.
                                dm_rt.start(&conn, &mut new_swarm, &my_peer_id, &offline_secret_bytes);

                                // Kendi offline pubkey'ini DHT mailbox'a yayınla
                                {
                                    let pubkey_bytes = alterchat_core::crypto::get_public_key(&offline_secret_bytes);
                                    let pubkey_hex = hex::encode(pubkey_bytes);
                                    let pubkey_key = alterchat_core::crypto::get_dht_pubkey_key(&my_peer_id);
                                    let record = libp2p::kad::Record {
                                        key: pubkey_key,
                                        value: pubkey_hex.into_bytes(),
                                        publisher: None,
                                        expires: None,
                                    };
                                    let _ = new_swarm.behaviour_mut().kademlia.put_record(record, libp2p::kad::Quorum::One);
                                }

                                match (&network_config.proxy_mode, &network_config.transport_preference) {
                                    (alterchat_core::network::ProxyMode::Direct, alterchat_core::network::TransportPreference::Tcp) => {
                                        let _ = new_swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse().unwrap());
                                    }
                                    (_, alterchat_core::network::TransportPreference::Quic) => {
                                        let _ = new_swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap());
                                    }
                                    _ => {}
                                }
                                swarm = Some(new_swarm);
                                conn_opt = Some(conn);
                            }
                            AppCommand::SendMessage { text, nick, ttl } => {
                                // Rastgele gecikme (timing obfuscation) — conn borrow öncesinde
                                if msg_delay_enabled {
                                    let delay = alterchat_core::traffic::random_send_delay_ms();
                                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                                }
                                if let Some(conn) = &conn_opt {
                                    if let Some(s) = &mut swarm {
                                        if !room_action_allowed(
                                            conn,
                                            &current_topic_name,
                                            &my_peer_id,
                                            governance::Permission::Write,
                                        ) {
                                            let _ = app_handle.emit("room-action-denied", "write");
                                            continue;
                                        }
                                        if let Ok(bytes) = room.add_message(&my_peer_id, &nick, &text, ttl) {
                                            // Sabit boyut padding
                                            let padded = alterchat_core::traffic::pad_message(&bytes);
                                            let _ = db::save_room(conn, &current_topic_name, &bytes);
                                            let timestamp = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_millis() as i64;
                                            let _ = db::index_room_message(
                                                conn,
                                                &current_topic_name,
                                                &nick,
                                                &text,
                                                timestamp,
                                            );
                                            let _ = s.behaviour_mut().gossipsub.publish(topic.clone(), padded);
                                            let _ = app_handle.emit("new-message", ChatMessage {
                                                peer_id: my_peer_id.clone(),
                                                sender: nick.clone(),
                                                text: text.clone(),
                                                timestamp,
                                                ttl,
                                            });
                                        }
                                    }
                                }
                            }
                            AppCommand::JoinChannel { name, password } => {
                                if let Some(conn) = &conn_opt {
                                    if let Some(s) = &mut swarm {
                                        // Open the stored room first. A wrong password must not
                                        // replace (and later overwrite) the saved history.
                                        let new_room = match db::load_room(conn, &name) {
                                            Ok(Some(bytes)) => match crdt::Room::load(name.clone(), &bytes, password.as_deref()) {
                                                Ok(r) => r,
                                                Err(_) => {
                                                    let _ = app_handle.emit("room-join-failed", name.clone());
                                                    continue;
                                                }
                                            },
                                            _ => crdt::Room::new(name.clone(), password.as_deref()),
                                        };
                                        let _ = s.behaviour_mut().gossipsub.unsubscribe(&topic);
                                        current_topic_name = name.clone();
                                        topic = gossipsub::IdentTopic::new(current_topic_name.clone());
                                        let _ = s.behaviour_mut().gossipsub.subscribe(&topic);
                                        room = new_room;

                                        if let Ok(msgs) = room.get_messages() {
                                            let history: Vec<ChatMessage> = msgs.into_iter().map(|msg| ChatMessage { peer_id: msg.peer_id, sender: msg.sender, text: msg.text, timestamp: msg.timestamp, ttl: msg.ttl }).collect();
                                            let _ = app_handle.emit("chat-history", history);
                                        }
                                    }
                                }
                            }
                            AppCommand::SendFile { peer_id, filename, data } => {
                                if let Some(conn) = &conn_opt {
                                    if !room_action_allowed(
                                            conn,
                                            &current_topic_name,
                                            &my_peer_id,
                                            governance::Permission::SendFile,
                                        )
                                    {
                                        let _ = app_handle.emit("room-action-denied", "commands::media::send_file");
                                        continue;
                                    }
                                }
                                if let Some(s) = &mut swarm {
                                    if let Ok(peer) = peer_id.parse::<PeerId>() {
                                        let _ = s.behaviour_mut().request_response.send_request(
                                            &peer,
                                            alterchat_core::file_transfer::P2pRequest::File { filename, data },
                                        );
                                    }
                                }
                            }
                            AppCommand::SetBootstrap { addr } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = db::save_setting(conn, "bootstrap_addr", &addr);
                                    if let Some(s) = &mut swarm {
                                        if let Ok(multiaddr) = addr.parse::<libp2p::Multiaddr>() {
                                            let _ = s.dial(multiaddr);
                                        }
                                    }
                                }
                            }
                            AppCommand::SaveSettings { config } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = save_full_config_to_db(conn, &config);
                                    // Runtime güncelle
                                    cover_traffic_enabled = config.cover_traffic;
                                    msg_delay_enabled = config.msg_delay;
                                    mdns_enabled = config.mdns_enabled;
                                    runtime_config = config;
                                }
                            }
                            // #4 Dağıtık revokasyon: davetiyeyi iptal et + Gossipsub'a yayınla
                            AppCommand::RevokeInviteGlobal { invite_id } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = db::revoke_invite(conn, &invite_id);
                                    let _ = db::mark_invite_revoked(conn, &invite_id, &my_peer_id);
                                    let ann = current_keypair.as_ref().and_then(|kp| {
                                        alterchat_core::governance::create_revocation(kp, &invite_id, &current_topic_name).ok()
                                    });
                                    if let Some(bytes) = ann.and_then(|a| bincode::serialize(&a).ok()) {
                                        if let Some(s) = &mut swarm {
                                            let revoke_topic = gossipsub::IdentTopic::new(alterchat_core::governance::REVOCATION_TOPIC);
                                            let _ = s.behaviour_mut().gossipsub.publish(revoke_topic, bytes);
                                        }
                                    }
                                    // DHT'e de yayınla (#15)
                                    if let Some(s) = &mut swarm {
                                        if let Ok(ids) = db::list_revoked_invite_ids(conn) {
                                            let rev_key = alterchat_core::crypto::get_dht_revocation_key(&current_topic_name);
                                            if let Ok(ids_json) = serde_json::to_string(&ids) {
                                                let record = libp2p::kad::Record {
                                                    key: rev_key,
                                                    value: ids_json.into_bytes(),
                                                    publisher: None,
                                                    expires: None,
                                                };
                                                let _ = s.behaviour_mut().kademlia.put_record(record, libp2p::kad::Quorum::One);
                                            }
                                        }
                                    }
                                }
                            }
                            // #11 Anonim kanal: kalıcısız, rastgele oda ID
                            AppCommand::JoinAnonymousChannel { display_name } => {
                                use std::collections::hash_map::DefaultHasher;
                                use std::hash::{Hash, Hasher};
                                let mut h = DefaultHasher::new();
                                display_name.hash(&mut h);
                                alterchat_core::governance::now_ms().hash(&mut h);
                                let anon_room_id = format!("anon_{:016x}", h.finish());
                                current_topic_name = anon_room_id.clone();
                                topic = gossipsub::IdentTopic::new(&anon_room_id);
                                // Kalıcı olmayan oda — kayıt yok
                                room = alterchat_core::crdt::Room::new(anon_room_id.clone(), None);
                                if let Some(s) = &mut swarm {
                                    let _ = s.behaviour_mut().gossipsub.subscribe(&topic);
                                }
                                let _ = app_handle.emit("anonymous-channel-joined", anon_room_id);
                            }
                            // #15 Oda revokasyon listesini DHT'e yayınla
                            AppCommand::PublishRoomRevocations { room_id } => {
                                if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                    if let Ok(ids) = db::list_revoked_invite_ids(conn) {
                                        let rev_key = alterchat_core::crypto::get_dht_revocation_key(&room_id);
                                        if let Ok(ids_json) = serde_json::to_string(&ids) {
                                            let record = libp2p::kad::Record {
                                                key: rev_key,
                                                value: ids_json.into_bytes(),
                                                publisher: None,
                                                expires: None,
                                            };
                                            let _ = s.behaviour_mut().kademlia.put_record(record, libp2p::kad::Quorum::One);
                                        }
                                    }
                                }
                            }
                            AppCommand::AddFriend { peer_id, nickname, offline_pubkey } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = db::add_friend(conn, &peer_id, &nickname, offline_pubkey.as_deref());
                                }
                            }
                            AppCommand::RemoveFriend { peer_id } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = db::remove_friend(conn, &peer_id);
                                }
                            }
                            AppCommand::SaveGroup { channel_name, password } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = db::save_group(conn, &channel_name, password.as_deref());
                                    if let Some(keypair) = &current_keypair {
                                        let _ = ensure_default_room_governance(conn, &channel_name, keypair, &my_peer_id);
                                    }
                                }
                            }
                            AppCommand::RemoveGroup { channel_name } => {
                                if let Some(conn) = &conn_opt {
                                    let _ = db::remove_group(conn, &channel_name);
                                }
                            }
                            AppCommand::SendPrivateMessage { peer_id, text, sender_nick, ttl, use_onion } => {
                                // #17 Zaman-kör mesaj iletimi: sabit pencere içinde rastgele gecikme
                                if msg_delay_enabled {
                                    let delay = alterchat_core::traffic::time_blind_delay_ms();
                                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                                }
                                if let Some(conn) = &conn_opt {
                                    if let Some(s) = &mut swarm {
                                        if peer_id.parse::<PeerId>().is_ok() {
                                            let peer_settings = db::get_peer_settings(conn, &peer_id).ok();
                                            if peer_settings.as_ref().map(|p| p.blocked).unwrap_or(false) {
                                                let _ = app_handle.emit("private-message-blocked", peer_id.clone());
                                                continue;
                                            }
                                            if peer_settings.as_ref().map(|p| p.trust_level).unwrap_or(0) < runtime_config.min_trust_dm {
                                                let _ = app_handle.emit("private-message-blocked", peer_id.clone());
                                                continue;
                                            }
                                            let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
                                            let friend_ok = db::get_friends(conn)
                                                .unwrap_or_default()
                                                .iter()
                                                .any(|f| f.peer_id == peer_id && !f.blocked);
                                            if !friend_ok || alterchat_core::dm::ed25519_public_from_peer_id(&peer_id).is_none() {
                                                // Not a (non-blocked) friend or not an Ed25519 peer id: no session possible.
                                                let _ = app_handle.emit("dm-requires-pubkey", peer_id.clone());
                                                continue;
                                            }
                                            let plaintext = alterchat_core::dm::DmPlaintext {
                                                sender_nick,
                                                text: text.clone(),
                                                timestamp,
                                                ttl,
                                                control: false,
                                            };
                                            // Queued in the encrypted outbox first; delivered directly, via
                                            // onion relays or the signed DHT mailbox (see dm_runtime.rs).
                                            let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                            if dm_rt.send(conn, s, &ctx, &peer_id, plaintext, use_onion) {
                                                let _ = db::save_private_message(conn, &peer_id, true, &text, timestamp, ttl);
                                            }
                                        }
                                    }
                                }
                            }
                            AppCommand::SendWebRtcSignal { peer_id, signal } => {
                                if let Some(conn) = &conn_opt {
                                    if !room_action_allowed(
                                        conn,
                                        &current_topic_name,
                                        &my_peer_id,
                                        governance::Permission::StartCall,
                                    ) {
                                        let _ = app_handle.emit("room-action-denied", "start_call");
                                        continue;
                                    }
                                }
                                if let Some(s) = &mut swarm {
                                    if let Ok(peer) = peer_id.parse::<PeerId>() {
                                        let _ = s.behaviour_mut().request_response.send_request(
                                            &peer,
                                            alterchat_core::file_transfer::P2pRequest::WebRtcSignal { signal },
                                        );
                                    }
                                }
                            }
                        },
                        Some(event) = (async {
                            if let Some(s) = &mut swarm {
                                Some(s.select_next_some().await)
                            } else {
                                libp2p::futures::future::pending().await
                            }
                        }) => {
                            match event {
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source: _, message_id: _, message })) => {
                                if let Some(conn) = &conn_opt {
                                    // Revokasyon topic'i mi?
                                    let topic_str = message.topic.to_string();
                                    if topic_str == alterchat_core::governance::REVOCATION_TOPIC {
                                        if let Ok(ann) = bincode::deserialize::<alterchat_core::governance::RevocationAnnouncement>(&message.data) {
                                            // Only the signed issuer of a known invite may revoke it.
                                            let issuer_ok = db::get_invite_issuer(conn, &ann.invite_id)
                                                .ok()
                                                .flatten()
                                                .map(|issuer| issuer == ann.revoked_by)
                                                .unwrap_or(false);
                                            if !alterchat_core::governance::verify_revocation(&ann) || !issuer_ok {
                                                continue;
                                            }
                                            let _ = db::mark_invite_revoked(conn, &ann.invite_id, &ann.revoked_by);
                                            let _ = db::revoke_invite(conn, &ann.invite_id);
                                            let _ = app_handle.emit("invite-revoked-global", ann.invite_id.clone());
                                        }
                                    } else {
                                        let payload = alterchat_core::traffic::unpad_message(&message.data)
                                            .unwrap_or_else(|| message.data.clone());
                                        if room.merge(&payload).is_ok() {
                                            if let Ok(merged) = room.save() {
                                                let _ = db::save_room(conn, &current_topic_name, &merged);
                                            }
                                            if let Ok(msgs) = room.get_messages() {
                                                let history: Vec<ChatMessage> = msgs.into_iter().map(|msg| ChatMessage { peer_id: msg.peer_id, sender: msg.sender, text: msg.text, timestamp: msg.timestamp, ttl: msg.ttl }).collect();
                                                let _ = app_handle.emit("chat-history", history);
                                            }
                                        }
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::Message { peer, message, .. })) => {
                                match message {
                                    libp2p::request_response::Message::Request { request, channel, .. } => {
                                        if let Some(s) = &mut swarm {
                                            if let Some(conn) = &conn_opt {
                                                let peer_str = peer.to_string();
                                                let settings = db::get_peer_settings(conn, &peer_str).ok();
                                                if settings.as_ref().map(|p| p.blocked).unwrap_or(false)
                                                    || !peer_can_contact(conn, &peer_str, &runtime_config)
                                                {
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        rejection_for_request(&request),
                                                    );
                                                    continue;
                                                }
                                                let per_minute = settings
                                                    .as_ref()
                                                    .map(|p| p.rate_limit_per_minute)
                                                    .unwrap_or(runtime_config.rate_limit_per_minute);
                                                if !rate_limit_allows(&mut rate_buckets, &peer_str, per_minute) {
                                                    let _ = app_handle.emit("peer-rate-limited", peer_str);
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        rejection_for_request(&request),
                                                    );
                                                    continue;
                                                }
                                            }
                                            match request {
                                                alterchat_core::file_transfer::P2pRequest::File { filename, data } => {
                                                    let mut allowed = true;
                                                    if let Some(conn) = &conn_opt {
                                                        if let Ok(settings) = db::get_peer_settings(conn, &peer.to_string()) {
                                                            if settings.blocked || settings.trust_level < db::load_setting(conn, "min_trust_file").ok().flatten().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) {
                                                                allowed = false;
                                                            }
                                                        }
                                                    }
                                                    if !allowed {
                                                        let _ = s.behaviour_mut().request_response.send_response(
                                                            channel,
                                                            alterchat_core::file_transfer::P2pResponse::FileAck { success: false, message: "Blocked by trust policy".to_string() }
                                                        );
                                                        continue;
                                                    }
                                                    let _ = app_handle.emit("file-received", (filename.clone(), data.len()));
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::FileAck { success: true, message: "File received".to_string() }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::FileChunk { transfer_id, index, total: _, content_hash, data } => {
                                                    let mut allowed = true;
                                                    if let Some(conn) = &conn_opt {
                                                        if let Ok(settings) = db::get_peer_settings(conn, &peer.to_string()) {
                                                            if settings.blocked || settings.trust_level < db::load_setting(conn, "min_trust_file").ok().flatten().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) {
                                                                allowed = false;
                                                            }
                                                        }
                                                    }
                                                    if !allowed {
                                                        let _ = s.behaviour_mut().request_response.send_response(
                                                            channel,
                                                            alterchat_core::file_transfer::P2pResponse::FileChunkAck { transfer_id: transfer_id.clone(), index, success: false }
                                                        );
                                                        continue;
                                                    }
                                                    let mut success = false;
                                                    // transfer_id comes from the remote peer and is used in a file
                                                    // name: only allow a strict charset to prevent path traversal.
                                                    if is_safe_transfer_id(&transfer_id) && storage::content_hash(&data) == content_hash {
                                                        if let Some(conn) = &conn_opt {
                                                            if let Ok(settings) = db::get_storage_settings(conn) {
                                                                let current = db::stored_chunk_bytes(conn).unwrap_or(0);
                                                                let quota = settings.quota_mb.max(1) * 1024 * 1024;
                                                                if current + data.len() as i64 <= quota {
                                                                    if let Some(db_path) = &current_db_path {
                                                                        let root = storage_root_for_db(db_path);
                                                                        let _ = std::fs::create_dir_all(&root);
                                                                        let chunk_path = root.join(format!("{}-{}.chunk", transfer_id, index));
                                                                        if std::fs::write(&chunk_path, &data).is_ok() {
                                                                            let expires_at = Some(current_millis() + settings.retention_days.max(1) * 24 * 60 * 60 * 1000);
                                                                            success = db::save_stored_chunk(
                                                                                conn,
                                                                                &content_hash,
                                                                                &transfer_id,
                                                                                index,
                                                                                &chunk_path.to_string_lossy(),
                                                                                data.len(),
                                                                                expires_at,
                                                                            ).is_ok();
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    let _ = app_handle.emit("file-chunk-received", (transfer_id.clone(), index, data.len()));
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::FileChunkAck { transfer_id, index, success }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::WebRtcSignal { signal } => {
                                                    #[derive(serde::Serialize, Clone)]
                                                    struct SignalPayload {
                                                        peer_id: String,
                                                        signal: String,
                                                    }
                                                    let _ = app_handle.emit("webrtc-signal", SignalPayload {
                                                        peer_id: peer.to_string(),
                                                        signal,
                                                    });
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::WebRtcAck { success: true }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::PrivateMessage { text, sender_nick, timestamp, ttl, pow_token } => {
                                                    tracing::warn!("Received legacy plaintext DM from peer {peer}; this path is deprecated.");
                                                    if let Some(conn) = &conn_opt {
                                                        let friends = db::get_friends(conn).unwrap_or_default();
                                                        let is_friend = friends.iter().any(|f| f.peer_id == peer.to_string());
                                                        if !is_friend {
                                                            let valid_pow = pow_token.map(|t| t.verify(&my_peer_id, 16, 300)).unwrap_or(false);
                                                            if !valid_pow {
                                                                // #16 PoW ban: başarısız PoW sayacı artır
                                                                let should_ban = pow_ban.record_failure(&peer.to_string(), POW_BAN_THRESHOLD);
                                                                let _ = app_handle.emit("peer-blocked-pow", peer.to_string());
                                                                if should_ban {
                                                                    // Kademlia'dan peer'ı çıkar (ağ seviyesi ban)
                                                                    s.behaviour_mut().kademlia.remove_peer(&peer);
                                                                    let _ = app_handle.emit("peer-network-banned", peer.to_string());
                                                                }
                                                                let _ = s.behaviour_mut().request_response.send_response(
                                                                    channel,
                                                                    alterchat_core::file_transfer::P2pResponse::PrivateMessageAck { success: false }
                                                                );
                                                                continue;
                                                            }
                                                        }

                                                        if let Ok(settings) = db::get_peer_settings(conn, &peer.to_string()) {
                                                            if settings.blocked || settings.trust_level < db::load_setting(conn, "min_trust_dm").ok().flatten().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) {
                                                                let _ = app_handle.emit("private-message-blocked", peer.to_string());
                                                                let _ = s.behaviour_mut().request_response.send_response(
                                                                    channel,
                                                                    alterchat_core::file_transfer::P2pResponse::PrivateMessageAck { success: false }
                                                                );
                                                                continue;
                                                            }
                                                        }
                                                        let _ = db::save_private_message(conn, &peer.to_string(), false, &text, timestamp, ttl);

                                                        #[derive(serde::Serialize, Clone)]
                                                        struct PmPayload {
                                                            peer_id: String,
                                                            sender_nick: String,
                                                            text: String,
                                                            timestamp: i64,
                                                            ttl: Option<i64>,
                                                        }
                                                        let _ = app_handle.emit("new-private-message", PmPayload {
                                                            peer_id: peer.to_string(),
                                                            sender_nick,
                                                            text,
                                                            timestamp,
                                                            ttl,
                                                        });
                                                    }

                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::PrivateMessageAck { success: true }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::RatchetPrivateMessage { envelope, sender_nick, timestamp, ttl } => {
                                                    let mut success = false;
                                                    if let Some(conn) = &conn_opt {
                                                        let peer_id = peer.to_string();
                                                        let friends = db::get_friends(conn).unwrap_or_default();
                                                        if let Some(friend) = friends.iter().find(|f| f.peer_id == peer_id && !f.blocked) {
                                                            if let Some(pubkey_hex) = &friend.offline_pubkey {
                                                                if let Some(pk) = decode_x25519_hex(pubkey_hex) {
                                                                    if let Ok(envelope) = bincode::deserialize::<alterchat_core::crypto::RatchetEnvelope>(&envelope) {
                                                                        let mut ratchet_state = load_or_init_ratchet_state(
                                                                            conn,
                                                                            &peer_id,
                                                                            &my_peer_id,
                                                                            &offline_secret_bytes,
                                                                            &pk,
                                                                        );
                                                                        if let Ok(plaintext) = alterchat_core::crypto::ratchet_decrypt(&mut ratchet_state, &envelope) {
                                                                            if let Ok(text) = String::from_utf8(plaintext) {
                                                                                let _ = db::save_private_message(conn, &peer_id, false, &text, timestamp, ttl);
                                                                                save_ratchet_state(conn, &peer_id, &ratchet_state);

                                                                                #[derive(serde::Serialize, Clone)]
                                                                                struct PmPayload {
                                                                                    peer_id: String,
                                                                                    sender_nick: String,
                                                                                    text: String,
                                                                                    timestamp: i64,
                                                                                    ttl: Option<i64>,
                                                                                }
                                                                                let _ = app_handle.emit("new-private-message", PmPayload {
                                                                                    peer_id,
                                                                                    sender_nick,
                                                                                    text,
                                                                                    timestamp,
                                                                                    ttl,
                                                                                });
                                                                                success = true;
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }

                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::RatchetPrivateMessageAck { success }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::X3dhDm { message } => {
                                                    let peer_str = peer.to_string();
                                                    match &conn_opt {
                                                        Some(conn) => {
                                                            let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                                            let processed = dm_rt.on_dm_request(conn, &ctx, &peer_str, &message);
                                                            let _ = s.behaviour_mut().request_response.send_response(channel, processed.response());
                                                            if processed.flush {
                                                                dm_rt.flush_peer(conn, s, &ctx, &peer_str, false);
                                                            }
                                                        }
                                                        None => {
                                                            let _ = s.behaviour_mut().request_response.send_response(
                                                                channel,
                                                                alterchat_core::file_transfer::P2pResponse::X3dhDmAck { success: false, reset_session: false },
                                                            );
                                                        }
                                                    }
                                                }
                                                alterchat_core::file_transfer::P2pRequest::GetPrekeyBundle => {
                                                    let response = match &conn_opt {
                                                        Some(conn) => dm_rt.bundle_response(conn),
                                                        None => alterchat_core::file_transfer::P2pResponse::PrekeyBundle { bundle: None },
                                                    };
                                                    let _ = s.behaviour_mut().request_response.send_response(channel, response);
                                                }
                                                alterchat_core::file_transfer::P2pRequest::CapabilityAnnouncement { peer_id, storage_node, relay_node, dht_server, media_relay, capacity_score, protocol_versions } => {
                                                    #[derive(serde::Serialize, Clone)]
                                                    struct CapabilityPayload {
                                                        peer_id: String,
                                                        capacity_score: u32,
                                                    }
                                                    if let Some(conn) = &conn_opt {
                                                        let _ = db::save_capability(conn, &peer_id, storage_node, relay_node, dht_server, media_relay, capacity_score, &protocol_versions);
                                                    }
                                                    let _ = app_handle.emit("peer-capability", CapabilityPayload { peer_id, capacity_score });
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::CapabilityAck { success: true }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::OnionForward { packet } => {
                                                    let _ = app_handle.emit("onion-packet-received", (peer.to_string(), packet.len()));
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::OnionAck { success: true }
                                                    );

                                                    // Attempt to peel the onion
                                                    if let Ok(onion_packet) = bincode::deserialize::<alterchat_core::onion::OnionPacket>(&packet) {
                                                        if let Ok(layer) = alterchat_core::onion::peel_onion(&offline_secret_bytes, &onion_packet) {
                                                            if let Some(next_hop) = layer.next_hop {
                                                                if let Some(inner) = layer.inner_packet {
                                                                    if let Ok(next_peer) = std::str::FromStr::from_str(&next_hop) {
                                                                        if let Ok(inner_bytes) = bincode::serialize(&inner) {
                                                                            let _ = app_handle.emit("onion-forwarding", (peer.to_string(), next_hop.clone()));
                                                                            s.behaviour_mut().request_response.send_request(
                                                                                &next_peer,
                                                                                alterchat_core::file_transfer::P2pRequest::OnionForward { packet: inner_bytes }
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                            } else if let Some(payload) = layer.payload {
                                                                // It's for us! Bounded decoding of the sealed request.
                                                                if let Ok((sender_pubkey, sender_peer_id, req)) = alterchat_core::onion::open_sealed_request(&offline_secret_bytes, &payload) {
                                                                    {
                                                                        {
                                                                            if let (alterchat_core::file_transfer::P2pRequest::X3dhDm { message }, Some(conn)) = (&req, &conn_opt) {
                                                                                // Same DM path as a direct X3dhDm; the sealed-sender key
                                                                                // must equal the claimed friend's stored offline key.
                                                                                let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                                                                dm_runtime::onion_final_hop(&mut dm_rt, conn, s, &ctx, sender_pubkey, &sender_peer_id, message);
                                                                            } else if let (alterchat_core::file_transfer::P2pRequest::RatchetPrivateMessage { envelope, sender_nick, timestamp, ttl }, Some(conn)) = (req, &conn_opt) {
                                                                                {
                                                                                    let peer_id = sender_peer_id;
                                                                                    let friends = db::get_friends(conn).unwrap_or_default();
                                                                                    if let Some(friend) = friends.iter().find(|f| f.peer_id == peer_id && !f.blocked) {
                                                                                        if let Some(pubkey_hex) = &friend.offline_pubkey {
                                                                                            // The claimed sender id is inside the envelope: only accept it
                                                                                            // if the envelope was sealed with that friend's stored key.
                                                                                            if let Some(pk) = decode_x25519_hex(pubkey_hex).filter(|pk| *pk == sender_pubkey) {
                                                                                                if let Ok(envelope) = bincode::deserialize::<alterchat_core::crypto::RatchetEnvelope>(&envelope) {
                                                                                                    let mut ratchet_state = load_or_init_ratchet_state(conn, &peer_id, &my_peer_id, &offline_secret_bytes, &pk);
                                                                                                    if let Ok(plaintext) = alterchat_core::crypto::ratchet_decrypt(&mut ratchet_state, &envelope) {
                                                                                                        if let Ok(text) = String::from_utf8(plaintext) {
                                                                                                            let _ = db::save_private_message(conn, &peer_id, false, &text, timestamp, ttl);
                                                                                                            save_ratchet_state(conn, &peer_id, &ratchet_state);
                                                                                                            #[derive(serde::Serialize, Clone)]
                                                                                                            struct PmPayload { peer_id: String, sender_nick: String, text: String, timestamp: i64, ttl: Option<i64> }
                                                                                                            let _ = app_handle.emit("new-private-message", PmPayload { peer_id, sender_nick, text, timestamp, ttl });
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        } else {
                                                            let _ = app_handle.emit("onion-peel-failed", peer.to_string());
                                                        }
                                                    }
                                                }
                                                alterchat_core::file_transfer::P2pRequest::PluginEvent { plugin_id, event_json } => {
                                                    let _ = app_handle.emit("plugin-event", (plugin_id, event_json));
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::PluginEventAck { success: true }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::PowChallenge { challenge_id, difficulty_bits: _, nonce: _ } => {
                                                    let _ = app_handle.emit("pow-challenge", challenge_id);
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::PowAck { success: true }
                                                    );
                                                }
                                                alterchat_core::file_transfer::P2pRequest::PowSolution { challenge_id, solution: _ } => {
                                                    let _ = app_handle.emit("pow-solution", challenge_id);
                                                    let _ = s.behaviour_mut().request_response.send_response(
                                                        channel,
                                                        alterchat_core::file_transfer::P2pResponse::PowAck { success: true }
                                                    );
                                                }
                                            }
                                        }
                                    }
                                    libp2p::request_response::Message::Response { request_id, response } => {
                                        if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                            let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                            dm_rt.on_response(conn, s, &ctx, request_id, response);
                                        }
                                    }
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                                if mdns_enabled {
                                if let Some(s) = &mut swarm {
                                    for (peer_id, _) in list {
                                        s.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                        let _ = app_handle.emit("peer-discovered", peer_id.to_string());
                                    }
                                }
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                                if mdns_enabled {
                                if let Some(s) = &mut swarm {
                                    for (peer_id, _) in list {
                                        s.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                                        let _ = app_handle.emit("peer-expired", peer_id.to_string());
                                    }
                                }
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Identify(libp2p::identify::Event::Received { peer_id, info, .. })) => {
                                if let Some(s) = &mut swarm {
                                    for addr in &info.listen_addrs {
                                        s.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                                        // PEX: peer adresini SQLite'a kaydet (gelecek oturumlar için)
                                        if let Some(conn) = &conn_opt {
                                            let ts = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default().as_millis() as i64;
                                            let _ = db::save_known_peer(conn, &peer_id.to_string(), &addr.to_string(), ts);
                                        }
                                    }
                                    let _ = s.behaviour_mut().kademlia.bootstrap();
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Kademlia(libp2p::kad::Event::OutboundQueryProgressed {
                                id,
                                result: libp2p::kad::QueryResult::GetRecord(Ok(libp2p::kad::GetRecordOk::FoundRecord(peer_record))),
                                ..
                            })) => {
                                // Prekey bundles and signed (recipient, sender) mailbox records;
                                // everything is verified before use (see dm_runtime.rs).
                                if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                    let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                    dm_rt.on_record(conn, s, &ctx, id, &peer_record.record);
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::Kademlia(libp2p::kad::Event::InboundRequest { request })) => {
                                // Record filtering is enabled: validate mailbox records before storing.
                                if let Some(s) = &mut swarm {
                                    alterchat_core::mailbox::store_filtered_inbound(&mut s.behaviour_mut().kademlia, request, current_millis() as u64);
                                }
                            }
                            SwarmEvent::Behaviour(network::AlterChatBehaviourEvent::RequestResponse(libp2p::request_response::Event::OutboundFailure { request_id, .. })) => {
                                if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                    dm_rt.on_outbound_failure(conn, s, request_id);
                                }
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                if let (Some(conn), Some(s)) = (&conn_opt, &mut swarm) {
                                    let ctx = dm_runtime::DmCtx { app: &app_handle, offline_secret: &offline_secret_bytes };
                                    dm_rt.on_connected(conn, s, &ctx, &peer_id);
                                }
                            }
                            _ => {}
                        }
                        }
                    }
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
