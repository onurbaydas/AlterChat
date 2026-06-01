use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn get_settings(state: tauri::State<'_, AppState>) -> Result<FullConfig, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    
    let mut config = load_full_config(&conn);
    let pubkey_guard = state.offline_pubkey.lock().await;
    if let Some(pubkey) = pubkey_guard.clone() {
        config.offline_pubkey = Some(pubkey);
    }
    Ok(config)
}

#[tauri::command]
pub async fn get_full_config(state: tauri::State<'_, AppState>) -> Result<FullConfig, String> {
    get_settings(state).await
}

#[tauri::command]
pub async fn save_settings(
    nick: String,
    bootstrap_ip: String,
    bootstrap_addrs: Option<Vec<String>>,
    tor_enabled: bool,
    proxy_mode: String,
    proxy_addr: String,
    mdns_enabled: Option<bool>,
    dht_server_mode: Option<bool>,
    relay_enabled: Option<bool>,
    transport_preference: Option<String>,
    relay_fallback_enabled: Option<bool>,
    publish_capabilities: Option<bool>,
    cover_traffic: bool,
    msg_delay: bool,
    local_notifications: Option<bool>,
    unknown_peer_policy: Option<String>,
    min_trust_dm: Option<i64>,
    min_trust_file: Option<i64>,
    min_trust_invite: Option<i64>,
    default_ttl: Option<i64>,
    persistence_enabled: Option<bool>,
    invite_only_default: Option<bool>,
    proof_of_work_enabled: Option<bool>,
    rate_limit_per_minute: Option<i64>,
    storage_node_enabled: Option<bool>,
    storage_quota_mb: Option<i64>,
    storage_retention_days: Option<i64>,
    sfu_threshold: Option<i64>,
    preferred_sfu_peer: Option<String>,
    accept_relay: Option<bool>,
    experimental_media_e2ee: Option<bool>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let mut config = FullConfig::default();
    config.nick = nick;
    config.bootstrap_ip = bootstrap_ip.clone();
    config.bootstrap_addrs = bootstrap_addrs.unwrap_or_else(|| {
        if bootstrap_ip.trim().is_empty() {
            Vec::new()
        } else {
            vec![bootstrap_ip]
        }
    });
    config.tor_enabled = tor_enabled;
    config.proxy_mode = proxy_mode;
    config.proxy_addr = proxy_addr;
    config.mdns_enabled = mdns_enabled.unwrap_or(true);
    config.dht_server_mode = dht_server_mode.unwrap_or(false);
    config.relay_enabled = relay_enabled.unwrap_or(false);
    config.transport_preference = transport_preference.unwrap_or_else(|| "tcp".to_string());
    config.relay_fallback_enabled = relay_fallback_enabled.unwrap_or(false);
    config.publish_capabilities = publish_capabilities.unwrap_or(true);
    config.cover_traffic = cover_traffic;
    config.msg_delay = msg_delay;
    config.local_notifications = local_notifications.unwrap_or(true);
    config.unknown_peer_policy = unknown_peer_policy.unwrap_or_else(|| "request-only".to_string());
    config.min_trust_dm = min_trust_dm.unwrap_or(0);
    config.min_trust_file = min_trust_file.unwrap_or(0);
    config.min_trust_invite = min_trust_invite.unwrap_or(0);
    config.default_ttl = default_ttl;
    config.persistence_enabled = persistence_enabled.unwrap_or(true);
    config.invite_only_default = invite_only_default.unwrap_or(false);
    config.proof_of_work_enabled = proof_of_work_enabled.unwrap_or(false);
    config.rate_limit_per_minute = rate_limit_per_minute.unwrap_or(30);
    config.storage_node_enabled = storage_node_enabled.unwrap_or(false);
    config.storage_quota_mb = storage_quota_mb.unwrap_or(512);
    config.storage_retention_days = storage_retention_days.unwrap_or(7);
    config.sfu_threshold = sfu_threshold.unwrap_or(6);
    config.preferred_sfu_peer = preferred_sfu_peer.unwrap_or_default();
    config.accept_relay = accept_relay.unwrap_or(false);
    config.experimental_media_e2ee = experimental_media_e2ee.unwrap_or(false);
    state
        .tx
        .send(AppCommand::SaveSettings { config })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn save_full_config(
    config: FullConfig,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SaveSettings { config })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn set_bootstrap_addr(addr: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SetBootstrap { addr })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn export_profile_config(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    
    let mut config = load_full_config(&conn);
    let pubkey_guard = state.offline_pubkey.lock().await;
    if let Some(pubkey) = pubkey_guard.clone() {
        config.offline_pubkey = Some(pubkey);
    }

    let export = ProfileConfigExport {
        app: config,
        raw_settings: db::export_settings(&conn).map_err(|e| e.to_string())?,
    };
    serde_json::to_string_pretty(&export).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn import_profile_config(
    json: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let export: ProfileConfigExport = serde_json::from_str(&json).map_err(|e| e.to_string())?;
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    save_full_config_to_db(&conn, &export.app)
}

#[tauri::command]
pub async fn get_capacity_score() -> Result<u32, String> {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();

    // Simple heuristic: Total Memory (GB) * 10 + CPU Cores * 50
    let mem_gb = sys.total_memory() / 1024 / 1024;
    let cores = sys.cpus().len() as u64;

    let score = (mem_gb * 10) + (cores * 50);
    Ok(score as u32)
}

// ─── #5 Safety Numbers ───────────────────────────────────────────────────────

/// İki peer'ın pubkey'lerinden Signal tarzı 60-haneli güvenlik numarası türetir.
/// Her iki tarafta aynı sonuç üretilir; kullanıcı sesli/görüntülü doğrulama yapabilir.
#[tauri::command]
pub async fn get_safety_number(
    peer_pubkey_hex: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let my_pubkey_hex = state.offline_pubkey.lock().await.clone().ok_or("Not logged in")?;
    let my_bytes = hex::decode(&my_pubkey_hex).map_err(|e| e.to_string())?;
    let peer_bytes = hex::decode(&peer_pubkey_hex).map_err(|e| e.to_string())?;
    if my_bytes.len() != 32 || peer_bytes.len() != 32 {
        return Err("Invalid pubkey length".to_string());
    }
    let my_arr: [u8; 32] = my_bytes.try_into().unwrap();
    let peer_arr: [u8; 32] = peer_bytes.try_into().unwrap();
    Ok(alterchat_core::crypto::derive_safety_number(&my_arr, &peer_arr))
}

// ─── #6 QR / alterchat:// URI ────────────────────────────────────────────────

/// Peer ID + pubkey'den `alterchat://connect?peer=...&pk=...` URI'si üretir.
/// Bu URI QR koda dönüştürülebilir veya doğrudan paylaşılabilir.
#[tauri::command]
pub async fn get_peer_uri(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let peer_id = state.peer_id.lock().await.clone().ok_or("Not logged in")?;
    let pubkey = state.offline_pubkey.lock().await.clone().unwrap_or_default();
    Ok(format!("alterchat://connect?peer={}&pk={}", peer_id, pubkey))
}

// ─── #9/#14 Şifreli vault export/import (çoklu cihaz) ───────────────────────

/// Tüm ayarları + DB'yi AES-256-GCM ile şifrelenmiş JSON olarak export eder.
/// Şifreyi bilen başka bir cihazda import edebilir (çoklu cihaz desteği).
#[tauri::command]
pub async fn export_vault_encrypted(
    export_password: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;

    let settings = db::export_settings(&conn).map_err(|e| e.to_string())?;
    let friends = db::get_friends(&conn).map_err(|e| e.to_string())?;
    let groups = db::get_saved_groups(&conn).map_err(|e| e.to_string())?;

    #[derive(serde::Serialize)]
    struct VaultExport {
        settings: Vec<(String, String)>,
        friends: Vec<db::Friend>,
        groups: Vec<db::SavedGroup>,
        version: u32,
    }
    let export = VaultExport { settings, friends, groups, version: 1 };
    let plaintext = serde_json::to_vec(&export).map_err(|e| e.to_string())?;

    // AES-256-GCM ile şifrele: Argon2 ile şifreden anahtar türet
    let encrypted = alterchat_core::secure_storage::encrypt_file_data(&export_password, &plaintext);
    Ok(hex::encode(encrypted))
}

/// export_vault_encrypted çıktısını şifreyle çözüp bu oturuma yükler.
#[tauri::command]
pub async fn import_vault_encrypted(
    encrypted_hex: String,
    import_password: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;

    let bytes = hex::decode(&encrypted_hex).map_err(|e| e.to_string())?;
    let plaintext = alterchat_core::secure_storage::decrypt_file_data(&import_password, &bytes)
        .map_err(|e| e.to_string())?;

    #[derive(serde::Deserialize)]
    struct VaultExport {
        settings: Vec<(String, String)>,
    }
    let export: VaultExport = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;

    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    for (k, v) in &export.settings {
        let _ = db::save_setting(&conn, k, v);
    }
    Ok(())
}

// ─── #4 Dağıtık revokasyon Tauri komutu ─────────────────────────────────────

#[tauri::command]
pub async fn revoke_invite_global(
    invite_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.tx.send(AppCommand::RevokeInviteGlobal { invite_id })
        .await.map_err(|e| e.to_string())
}

// ─── #11 Anonim kanal ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn join_anonymous_channel(
    display_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.tx.send(AppCommand::JoinAnonymousChannel { display_name })
        .await.map_err(|e| e.to_string())
}