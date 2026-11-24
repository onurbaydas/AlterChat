use crate::*;
use tauri_plugin_opener::OpenerExt;

#[tauri::command]
pub async fn accept_file_offer(
    transfer_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::FileDecision {
            transfer_id,
            accept: true,
        })
        .await
        .map_err(|e| e.to_string())
}

/// Rejects a pending offer, or cancels a running transfer in either direction.
#[tauri::command]
pub async fn reject_file_offer(
    transfer_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::FileDecision {
            transfer_id,
            accept: false,
        })
        .await
        .map_err(|e| e.to_string())
}

/// Opens a file received this session (by transfer id, never an arbitrary
/// path from the UI). Executables and unknown types are only revealed in
/// their folder. Returns `"opened"` or `"revealed"`.
#[tauri::command]
pub async fn open_received_file(
    transfer_id: String,
    reveal: bool,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let path = state
        .received_files
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&transfer_id)
        .cloned()
        .ok_or("Unknown transfer")?;
    if !path.is_file() {
        return Err("File no longer exists".to_string());
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if reveal || file_xfer::is_executable_name(&name) {
        app.opener()
            .reveal_item_in_dir(&path)
            .map_err(|e| e.to_string())?;
        return Ok("revealed".to_string());
    }
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())?;
    Ok("opened".to_string())
}

#[tauri::command]
pub async fn get_file_transfer_settings(
    state: tauri::State<'_, AppState>,
) -> Result<file_xfer::TransferSettings, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    Ok(file_xfer::TransferSettings::load(&conn))
}

#[tauri::command]
pub async fn save_file_transfer_settings(
    settings: file_xfer::TransferSettings,
    state: tauri::State<'_, AppState>,
) -> Result<file_xfer::TransferSettings, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    settings.save(&conn).map_err(|e| e.to_string())?;
    Ok(file_xfer::TransferSettings::load(&conn))
}
