use crate::*;

/// Ağ durumu anlık görüntüsü — UI'da bağlı peer sayısı, DHT durumu gösterir.
#[derive(serde::Serialize)]
pub struct NetworkStatus {
    pub peer_id: Option<String>,
    pub offline_pubkey: Option<String>,
    pub logged_in: bool,
}

#[tauri::command]
pub async fn get_network_status(state: tauri::State<'_, AppState>) -> Result<NetworkStatus, String> {
    let peer_id = state.peer_id.lock().await.clone();
    let offline_pubkey = state.offline_pubkey.lock().await.clone();
    Ok(NetworkStatus {
        logged_in: peer_id.is_some(),
        peer_id,
        offline_pubkey,
    })
}

/// Sistemin kriptografik yeteneklerini raporlar (manifesto uyum göstergesi).
#[derive(serde::Serialize)]
pub struct CryptoCapabilities {
    pub double_ratchet: bool,
    pub x3dh_mlkem: bool,
    pub sealed_sender: bool,
    pub onion_routing: bool,
    pub pow_antispam: bool,
    pub crdt_rooms: bool,
    pub peerstore: bool,
    pub gossipsub_anonymous: bool,
    pub zero_config_bootstrap: bool,
}

#[tauri::command]
pub async fn get_crypto_capabilities() -> Result<CryptoCapabilities, String> {
    Ok(CryptoCapabilities {
        double_ratchet: true,
        x3dh_mlkem: true,
        sealed_sender: true,
        onion_routing: true,
        pow_antispam: true,
        crdt_rooms: true,
        peerstore: true,
        gossipsub_anonymous: true,
        zero_config_bootstrap: true,
    })
}
