use crate::*;

/// Gossipsub revokasyon duyurusu gönder (#4)
#[tauri::command]
pub async fn revoke_invite_network(
    invite_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.tx.send(AppCommand::RevokeInviteGlobal { invite_id })
        .await.map_err(|e| e.to_string())
}

/// Oda revokasyon listesini DHT'e yayınla (#15)
#[tauri::command]
pub async fn publish_room_revocations(
    room_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.tx.send(AppCommand::PublishRoomRevocations { room_id })
        .await.map_err(|e| e.to_string())
}

/// Anonim kanala katıl (#11)
#[tauri::command]
pub async fn join_anonymous_channel_cmd(
    display_name: String,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    state.tx.send(AppCommand::JoinAnonymousChannel { display_name })
        .await.map_err(|e| e.to_string())
}
