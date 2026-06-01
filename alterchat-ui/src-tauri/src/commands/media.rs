use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn send_file(
    peer_id: String,
    filename: String,
    data: Vec<u8>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SendFile {
            peer_id,
            filename,
            data,
        })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn send_webrtc_signal(
    peer_id: String,
    signal: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SendWebRtcSignal { peer_id, signal })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn prepare_encrypted_file(
    filename: String,
    mime: Option<String>,
    data: Vec<u8>,
    state: tauri::State<'_, AppState>,
) -> Result<alterchat_core::storage::FileManifest, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    let settings = db::get_storage_settings(&conn).map_err(|e| e.to_string())?;
    let current_bytes = db::stored_chunk_bytes(&conn).map_err(|e| e.to_string())?;
    let quota_bytes = settings.quota_mb.max(1) * 1024 * 1024;
    if current_bytes + data.len() as i64 > quota_bytes {
        return Err("Storage quota exceeded".to_string());
    }
    cleanup_expired_storage(&conn);

    let file_key = alterchat_core::storage::generate_file_key();
    let mut manifest = alterchat_core::storage::build_manifest(filename, mime, &data, alterchat_core::storage::DEFAULT_CHUNK_SIZE);
    manifest.encrypted_key = Some(file_key.to_vec());
    let root = storage_root_for_db(path);
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let chunks = alterchat_core::storage::split_chunks(&data, alterchat_core::storage::DEFAULT_CHUNK_SIZE);
    let expires_at = Some(current_millis() + settings.retention_days.max(1) * 24 * 60 * 60 * 1000);
    for (index, plaintext) in chunks.into_iter().enumerate() {
        let encrypted = alterchat_core::storage::encrypt_chunk(index as u64, &file_key, plaintext)?;
        let chunk_hash = alterchat_core::storage::content_hash(&encrypted.ciphertext);
        let path = root.join(format!("{}-{}.chunk", manifest.content_hash, index));
        let chunk_json = serde_json::to_vec(&encrypted).map_err(|e| e.to_string())?;
        std::fs::write(&path, &chunk_json).map_err(|e| e.to_string())?;
        db::save_stored_chunk(
            &conn,
            &chunk_hash,
            &manifest.content_hash,
            index as u64,
            &path.to_string_lossy(),
            chunk_json.len(),
            expires_at,
        )
        .map_err(|e| e.to_string())?;
    }
    let manifest_json = serde_json::to_string(&manifest).map_err(|e| e.to_string())?;
    db::save_file_manifest(&conn, &manifest.content_hash, &manifest_json)
        .map_err(|e| e.to_string())?;
    Ok(manifest)
}