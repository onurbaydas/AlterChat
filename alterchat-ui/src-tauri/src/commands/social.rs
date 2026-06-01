use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn get_peer_id(state: tauri::State<'_, AppState>) -> Result<String, String> {
    let guard = state.peer_id.lock().await;
    guard.clone().ok_or_else(|| "Not logged in".to_string())
}

#[tauri::command]
pub async fn get_friends(state: tauri::State<'_, AppState>) -> Result<Vec<db::Friend>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;

    db::get_friends(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn endorse_peer(
    peer_id: String,
    score: i32,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;

    let mut settings = db::get_peer_settings(&conn, &peer_id).unwrap_or(db::PeerSettings {
        peer_id: peer_id.clone(),
        trust_level: 0,
        blocked: false,
        muted: false,
        rate_limit_per_minute: 0,
        proof_of_work_required: false,
    });
    settings.trust_level += score as i64;
    db::save_peer_settings(&conn, &settings).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_friend(
    peer_id: String,
    nickname: String,
    offline_pubkey: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::AddFriend {
            peer_id,
            nickname,
            offline_pubkey,
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn remove_friend(peer_id: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::RemoveFriend { peer_id })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn send_private_message(
    peer_id: String,
    text: String,
    sender_nick: String,
    ttl: Option<i64>,
    use_onion: bool,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SendPrivateMessage {
            peer_id,
            text,
            sender_nick,
            ttl,
            use_onion,
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn get_private_messages(
    peer_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<db::PrivateMessage>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;

    db::get_private_messages(&conn, &peer_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_peer_settings(
    peer_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<db::PeerSettings, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::get_peer_settings(&conn, &peer_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_peer_settings(
    settings: db::PeerSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::save_peer_settings(&conn, &settings).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_saved_groups(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<db::SavedGroup>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;

    db::get_saved_groups(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_group(
    channel_name: String,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SaveGroup {
            channel_name,
            password,
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn remove_group(
    channel_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::RemoveGroup { channel_name })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}