use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn save_plugin(
    entry: PluginRegistryEntry,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    let manifest_json = serde_json::to_string(&entry.manifest).map_err(|e| e.to_string())?;
    let caps_json =
        serde_json::to_string(&entry.granted_capabilities).map_err(|e| e.to_string())?;
    db::save_plugin_manifest(
        &conn,
        &entry.manifest.id,
        &manifest_json,
        entry.enabled,
        &caps_json,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_plugins(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<PluginRegistryEntry>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_plugin_manifests(&conn)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(manifest_json, enabled, caps_json)| {
            Ok(PluginRegistryEntry {
                manifest: serde_json::from_str(&manifest_json).map_err(|e| e.to_string())?,
                enabled,
                granted_capabilities: serde_json::from_str(&caps_json)
                    .map_err(|e| e.to_string())?,
            })
        })
        .collect()
}