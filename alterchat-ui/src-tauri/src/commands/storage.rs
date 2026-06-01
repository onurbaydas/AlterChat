use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn list_file_manifests(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<alterchat_core::storage::FileManifest>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_file_manifests(&conn)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|json| serde_json::from_str(&json).map_err(|e| e.to_string()))
        .collect()
}

#[tauri::command]
pub async fn list_stored_chunks(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<db::StoredChunk>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    cleanup_expired_storage(&conn);
    db::list_stored_chunks(&conn).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_peer_capabilities(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<db::PeerCapability>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_active_capabilities(&conn, 10 * 60 * 1000).map_err(|e| e.to_string())
}