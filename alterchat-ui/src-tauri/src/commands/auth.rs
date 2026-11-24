use crate::*;

/// Wipe local data and exit.
///
/// `confirm` must equal `"WIPE"`; this guards against accidental or scripted
/// invocation from the webview.
#[tauri::command]
pub async fn panic_wipe(
    scope: String,
    confirm: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    if confirm.as_deref() != Some("WIPE") {
        return Err("Panic wipe requires confirmation".to_string());
    }
    let db_path = state.db_path.lock().await.clone();
    let paths = match scope.as_str() {
        "active_profile" => active_profile_paths(db_path.as_deref(), true),
        "message_db_only" => active_profile_paths(db_path.as_deref(), false),
        "all_profiles" => all_profile_paths(&profiles_root(&app)?),
        _ => return Err("Unknown panic wipe scope".to_string()),
    };
    for path in paths {
        wipe_path(&path);
    }
    profile::cleanup_amnesic_dirs();
    std::process::exit(0);
}

#[tauri::command]
pub async fn panic_wipe_all(
    confirm: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    panic_wipe("all_profiles".to_string(), confirm, app, state).await
}

/// Unlock (or create) a profile and start the network session.
///
/// `create`: when `false` (default) a non-matching password is an error;
/// when `true` a new profile is created if no existing profile matches.
#[tauri::command]
pub async fn login_profile(
    password: String,
    amnesic: bool,
    create: Option<bool>,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    if state.db_path.lock().await.is_some() {
        return Err("A profile is already open in this session".to_string());
    }
    let root = profiles_root(&app)?;
    let create = create.unwrap_or(false);
    // Argon2id is CPU-heavy: keep it off the async runtime threads.
    let resolved = tokio::task::spawn_blocking(move || {
        if amnesic {
            profile::cleanup_amnesic_dirs();
        }
        profile::resolve(&root, &password, create, amnesic)
    })
    .await
    .map_err(|e| e.to_string())??;

    let my_peer_id = libp2p::PeerId::from(resolved.keypair.public());

    *state.db_path.lock().await = Some(resolved.db_path.clone());
    *state.db_key.lock().await = Some(resolved.db_key.clone());
    *state.keypair.lock().await = Some(resolved.keypair.clone());

    state
        .tx
        .send(AppCommand::StartSession {
            db_path: resolved.db_path,
            db_key: resolved.db_key,
            keypair: resolved.keypair,
        })
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
