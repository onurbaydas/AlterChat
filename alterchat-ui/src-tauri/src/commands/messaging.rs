use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn send_message(
    text: String,
    nick: String,
    ttl: Option<i64>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::SendMessage { text, nick, ttl })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn join_channel(
    name: String,
    password: Option<String>,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state
        .tx
        .send(AppCommand::JoinChannel { name, password })
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn search_messages(
    query: String,
    limit: Option<i64>,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<(String, String, String, i64)>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::search_messages(&conn, &query, limit.unwrap_or(25)).map_err(|e| e.to_string())
}