use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn create_invite(
    room_id: String,
    room_password: Option<String>,
    expires_in_seconds: Option<i64>,
    max_uses: Option<u32>,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    let key_path_guard = state.key_path.lock().await;
    let key_path = key_path_guard.as_ref().ok_or("Not logged in")?;
    let keypair = alterchat_core::identity::load_or_generate_keypair(key_path).map_err(|e| e.to_string())?;
    let my_peer_id = libp2p::PeerId::from(keypair.public()).to_string();
    if !room_action_allowed(&conn, &room_id, &my_peer_id, alterchat_core::governance::Permission::Invite) {
        return Err("Invite permission denied".to_string());
    }
    let expires_at = expires_in_seconds.map(|seconds| alterchat_core::governance::now_ms() + seconds * 1000);
    let token = alterchat_core::governance::create_invite(
        &keypair,
        room_id.clone(),
        room_password,
        None,
        expires_at,
        max_uses,
        vec![
            alterchat_core::governance::Permission::Read,
            alterchat_core::governance::Permission::Write,
            alterchat_core::governance::Permission::SendFile,
            alterchat_core::governance::Permission::StartCall,
        ],
    )?;
    let invite_id = alterchat_core::governance::invite_id(&token);
    let token_json = serde_json::to_string(&token).map_err(|e| e.to_string())?;
    db::save_invite(&conn, &invite_id, &room_id, &token_json).map_err(|e| e.to_string())?;
    Ok(token_json)
}

#[tauri::command]
pub async fn accept_invite(
    token_json: String,
    state: tauri::State<'_, AppState>,
) -> Result<(String, Option<String>), String> {
    let token: alterchat_core::governance::InviteToken =
        serde_json::from_str(&token_json).map_err(|e| e.to_string())?;
    alterchat_core::governance::verify_invite(&token)?;
    if alterchat_core::governance::is_invite_expired(&token, alterchat_core::governance::now_ms()) {
        return Err("Invite expired".to_string());
    }
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;

    let min_trust_invite = db::load_setting(&conn, "min_trust_invite").ok().flatten().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
    if let Ok(settings) = db::get_peer_settings(&conn, &token.issuer_peer_id) {
        if settings.blocked || settings.trust_level < min_trust_invite {
            return Err("Invite issuer is blocked or below trust threshold".to_string());
        }
    } else {
        if min_trust_invite > 0 {
            return Err("Invite issuer does not meet trust threshold".to_string());
        }
    }

    let invite_id = alterchat_core::governance::invite_id(&token);
    if let Some((revoked, uses)) =
        db::get_invite_state(&conn, &invite_id).map_err(|e| e.to_string())?
    {
        if revoked {
            return Err("Invite revoked".to_string());
        }
        if token
            .max_uses
            .map(|max| uses >= max as i64)
            .unwrap_or(false)
        {
            return Err("Invite use limit reached".to_string());
        }
    }
    db::save_group(&conn, &token.room_id, token.room_password.as_deref()).map_err(|e| e.to_string())?;
    if db::get_invite_state(&conn, &invite_id)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        db::increment_invite_use(&conn, &invite_id).map_err(|e| e.to_string())?;
    }
    Ok((token.room_id, token.room_password))
}

#[tauri::command]
pub async fn list_invites(
    room_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<String>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_invites(&conn, &room_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn revoke_invite(invite_id: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::revoke_invite(&conn, &invite_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_role(
    role: alterchat_core::governance::Role,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    let role_json = serde_json::to_string(&role).map_err(|e| e.to_string())?;
    db::save_role(&conn, &role.room_id, &role.role_id, &role_json).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_roles(
    room_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<alterchat_core::governance::Role>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_roles(&conn, &room_id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|json| serde_json::from_str(&json).map_err(|e| e.to_string()))
        .collect()
}

#[tauri::command]
pub async fn save_trust_edge(
    edge: alterchat_core::governance::TrustEdge,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    alterchat_core::governance::verify_trust_edge(&edge)?;
    let edge_json = serde_json::to_string(&edge).map_err(|e| e.to_string())?;
    db::save_trust_edge(&conn, &edge.from_peer_id, &edge.to_peer_id, &edge_json)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_trust_edge(
    to_peer_id: String,
    score: i32,
    reason: String,
    state: tauri::State<'_, AppState>,
) -> Result<alterchat_core::governance::TrustEdge, String> {
    let key_path_guard = state.key_path.lock().await;
    let key_path = key_path_guard.as_ref().ok_or("Not logged in")?;
    let keypair = alterchat_core::identity::load_or_generate_keypair(key_path).map_err(|e| e.to_string())?;
    let edge = alterchat_core::governance::create_trust_edge(&keypair, to_peer_id, score, reason)?;
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    let edge_json = serde_json::to_string(&edge).map_err(|e| e.to_string())?;
    db::save_trust_edge(&conn, &edge.from_peer_id, &edge.to_peer_id, &edge_json)
        .map_err(|e| e.to_string())?;
    Ok(edge)
}

#[tauri::command]
pub async fn list_trust_edges(
    state: tauri::State<'_, AppState>,
) -> Result<Vec<alterchat_core::governance::TrustEdge>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_trust_edges(&conn)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|json| serde_json::from_str(&json).map_err(|e| e.to_string()))
        .collect()
}

#[tauri::command]
pub async fn save_permission_grant(
    grant: alterchat_core::governance::PermissionGrant,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    alterchat_core::governance::verify_permission_grant(&grant)?;
    let grant_json = serde_json::to_string(&grant).map_err(|e| e.to_string())?;
    db::save_permission_grant(
        &conn,
        &grant.room_id,
        &grant.subject_peer_id,
        &grant.role_id,
        &grant_json,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_permission_grant(
    room_id: String,
    subject_peer_id: String,
    role_id: String,
    expires_at: Option<i64>,
    state: tauri::State<'_, AppState>,
) -> Result<alterchat_core::governance::PermissionGrant, String> {
    let key_path_guard = state.key_path.lock().await;
    let key_path = key_path_guard.as_ref().ok_or("Not logged in")?;
    let keypair = alterchat_core::identity::load_or_generate_keypair(key_path).map_err(|e| e.to_string())?;
    let issuer_peer = libp2p::PeerId::from(keypair.public()).to_string();
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    if !room_action_allowed(
        &conn,
        &room_id,
        &issuer_peer,
        alterchat_core::governance::Permission::ManageRoles,
    ) {
        return Err("Manage roles permission denied".to_string());
    }
    let grant = alterchat_core::governance::create_permission_grant(
        &keypair,
        room_id.clone(),
        subject_peer_id,
        role_id,
        expires_at,
    )?;
    let grant_json = serde_json::to_string(&grant).map_err(|e| e.to_string())?;
    db::save_permission_grant(
        &conn,
        &grant.room_id,
        &grant.subject_peer_id,
        &grant.role_id,
        &grant_json,
    )
    .map_err(|e| e.to_string())?;
    Ok(grant)
}

#[tauri::command]
pub async fn list_permission_grants(
    room_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<Vec<alterchat_core::governance::PermissionGrant>, String> {
    let path_guard = state.db_path.lock().await;
    let path = path_guard.as_ref().ok_or("Not logged in")?;
    let key_guard = state.db_key.lock().await;
    let key = key_guard.as_ref().ok_or("Not logged in")?;
    let conn = db::init_db(path, key).map_err(|e| e.to_string())?;
    db::list_permission_grants(&conn, &room_id)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|json| serde_json::from_str(&json).map_err(|e| e.to_string()))
        .collect()
}