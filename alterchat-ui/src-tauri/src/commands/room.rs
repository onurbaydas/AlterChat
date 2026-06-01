use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn get_room_settings(
    channel_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<db::RoomSettings, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::get_room_settings(&conn, &channel_name).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_room_settings(
    settings: db::RoomSettings,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::save_room_settings(&conn, &settings).map_err(|e| e.to_string())
}