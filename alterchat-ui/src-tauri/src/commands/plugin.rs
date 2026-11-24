use crate::*;

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

/// Number of recent room messages exposed to plugins holding `ReadMessages`.
const PLUGIN_ROOM_SNAPSHOT: i64 = 50;

/// Result of a sandboxed plugin run, as returned to the UI.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRunOutput {
    status: i32,
    /// Plugin output (`output_write`), decoded as UTF-8 (lossy).
    output: String,
    log: Vec<String>,
    sent_messages: Vec<String>,
    notifications: Vec<String>,
    fuel_consumed: u64,
}

/// Run an installed plugin's entrypoint with an event payload.
///
/// The manifest, `enabled` flag and granted capabilities come from the
/// plugin registry in the DB; `wasm` must match the manifest's signed hash.
/// Execution happens on a blocking thread inside the wasmi sandbox (see
/// `docs/PLUGINS.md`). Side effects the plugin requested are applied after the
/// run: room messages go through the normal send path, notifications are
/// emitted as `plugin-notification` events.
#[tauri::command]
pub async fn run_plugin(
    plugin_id: String,
    wasm: Vec<u8>,
    event_json: String,
    room_id: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<PluginRunOutput, String> {
    use plugin::PluginCapability;

    // Load registry entry + optional room snapshot; the connection is dropped
    // before any await.
    let (entry, room_messages) = {
        let path_guard = state.db_path.lock().await;
        let path = path_guard.as_ref().ok_or("Not logged in")?;
        let key_guard = state.db_key.lock().await;
        let key = key_guard.as_ref().ok_or("Not logged in")?;
        let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
        let mut entry: Option<PluginRegistryEntry> = None;
        for (manifest_json, enabled, caps_json) in
            db::list_plugin_manifests(&conn).map_err(|e| e.to_string())?
        {
            let manifest: plugin::PluginManifest =
                serde_json::from_str(&manifest_json).map_err(|e| e.to_string())?;
            if manifest.id == plugin_id {
                entry = Some(PluginRegistryEntry {
                    manifest,
                    enabled,
                    granted_capabilities: serde_json::from_str(&caps_json)
                        .map_err(|e| e.to_string())?,
                });
                break;
            }
        }
        let entry = entry.ok_or("plugin is not installed")?;
        let can_read = entry.enabled
            && entry
                .granted_capabilities
                .contains(&PluginCapability::ReadMessages)
            && entry
                .manifest
                .capabilities
                .contains(&PluginCapability::ReadMessages);
        let room_messages = match (&room_id, can_read) {
            (Some(room), true) => {
                let rows = db::recent_room_messages(&conn, room, PLUGIN_ROOM_SNAPSHOT)
                    .map_err(|e| e.to_string())?;
                let json: Vec<serde_json::Value> = rows
                    .into_iter()
                    .map(|(sender, text, timestamp)| {
                        serde_json::json!({ "sender": sender, "text": text, "timestamp": timestamp })
                    })
                    .collect();
                serde_json::to_vec(&json).map_err(|e| e.to_string())?
            }
            _ => Vec::new(),
        };
        (entry, room_messages)
    };

    let policy = plugin::PluginPolicy {
        plugin_id: entry.manifest.id.clone(),
        enabled: entry.enabled,
        granted_capabilities: entry.granted_capabilities,
    };
    let manifest = entry.manifest;
    let nick = manifest.name.clone();
    let ctx = plugin::PluginContext {
        input: event_json.into_bytes(),
        room_messages,
    };
    let result = tauri::async_runtime::spawn_blocking(move || {
        let host = plugin::PluginHost::new()?;
        host.run_plugin(
            &manifest,
            &wasm,
            &policy,
            ctx,
            plugin::PluginLimits::default(),
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| format!("plugin task failed: {e}"))??;

    for text in &result.sent_messages {
        state
            .tx
            .send(AppCommand::SendMessage {
                text: text.clone(),
                nick: nick.clone(),
                ttl: None,
            })
            .await
            .map_err(|e| e.to_string())?;
    }
    for note in &result.notifications {
        let _ = app.emit("plugin-notification", (&plugin_id, note));
    }

    Ok(PluginRunOutput {
        status: result.status,
        output: String::from_utf8_lossy(&result.output).into_owned(),
        log: result.log,
        sent_messages: result.sent_messages,
        notifications: result.notifications,
        fuel_consumed: result.fuel_consumed,
    })
}
