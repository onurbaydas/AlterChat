use crate::*;
use super::*;
use alterchat_core::*;

#[tauri::command]
pub async fn panic_wipe(scope: String, state: tauri::State<'_, AppState>) -> Result<(), String> {
    let db_path = state.db_path.lock().await.clone();
    let key_path = state.key_path.lock().await.clone();
    let paths = match scope.as_str() {
        "active_profile" => active_profile_paths(db_path.as_deref(), key_path.as_deref()),
        "message_db_only" => active_profile_paths(db_path.as_deref(), None),
        "all_profiles" => all_profile_paths(),
        _ => return Err("Unknown panic wipe scope".to_string()),
    };
    for path in paths {
        wipe_path(&path);
    }
    std::process::exit(0);
}

#[tauri::command]
pub async fn panic_wipe_all(state: tauri::State<'_, AppState>) -> Result<(), String> {
    panic_wipe("all_profiles".to_string(), state).await
}

#[tauri::command]
pub async fn login_profile(
    password: String,
    amnesic: bool,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let mut hasher = sha2::Sha256::new();
    sha2::Digest::update(&mut hasher, password.as_bytes());
    let result = sha2::Digest::finalize(hasher);
    let hash_hex = hex::encode(result);

    let key_path = if amnesic {
        ":memory:".to_string()
    } else {
        format!("keypair_{}.bin", &hash_hex[0..16])
    };

    let local_keypair = alterchat_core::identity::load_or_generate_encrypted_keypair(&key_path, &password)
        .map_err(|e| format!("Failed to load keypair: {}", e))?;
    let my_peer_id = libp2p::PeerId::from(local_keypair.public());

    let mut path_guard = state.db_path.lock().await;
    let db_path = if amnesic {
        ":memory:".to_string()
    } else {
        format!("alterchat_{}.db", &hash_hex[0..16])
    };
    *path_guard = Some(db_path);
    let mut key_path_guard = state.key_path.lock().await;
    *key_path_guard = Some(key_path);
    state
        .tx
        .send(AppCommand::StartSession { password, amnesic })
        .await
        .map_err(|e| e.to_string())?;

    Ok(my_peer_id.to_string())
}

#[tauri::command]
pub async fn solve_pow_challenge(
    challenge_id: String,
    difficulty_bits: u8,
    nonce: Vec<u8>,
    max_iters: u64,
) -> Result<Option<Vec<u8>>, String> {
    let challenge = alterchat_core::spam::PowChallenge {
        challenge_id,
        difficulty_bits,
        nonce,
    };
    Ok(alterchat_core::spam::solve_pow(&challenge, max_iters))
}