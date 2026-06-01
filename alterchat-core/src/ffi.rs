use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// Global Tokio runtime for FFI calls.
/// Mobile platforms need a single long-lived runtime.
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Runtime::new().expect("Failed to create Tokio runtime for FFI")
    })
}

/// FFI configuration passed as JSON from the host (Flutter/Swift/Kotlin).
#[derive(serde::Deserialize, Debug)]
pub struct FfiConfig {
    /// Vault password for identity encryption.
    pub password: String,
    /// Data directory for database and keypair storage.
    pub data_dir: String,
    /// Optional bootstrap multiaddr list.
    #[serde(default)]
    pub bootstrap_addrs: Vec<String>,
    /// Enable mDNS for local network discovery.
    #[serde(default = "default_true")]
    pub mdns_enabled: bool,
    /// Enable Tor transport.
    #[serde(default)]
    pub tor_enabled: bool,
    /// Amnesic mode: database in RAM, vanishes on close.
    #[serde(default)]
    pub amnesic: bool,
}

fn default_true() -> bool { true }

/// Callback function type for events from the core node.
/// Events are JSON-encoded strings describing what happened.
pub type EventCallback = extern "C" fn(event_json: *const c_char);

/// Global event callback (set by the host app).
static EVENT_CALLBACK: OnceLock<EventCallback> = OnceLock::new();

/// Register a callback function for receiving events from the core node.
///
/// # Safety
/// The callback must remain valid for the lifetime of the application.
#[unsafe(no_mangle)]
pub extern "C" fn register_event_callback(callback: EventCallback) {
    EVENT_CALLBACK.get_or_init(|| callback);
}

/// Emit an event to the registered callback (if any).
fn emit_event(event_json: &str) {
    if let Some(callback) = EVENT_CALLBACK.get() {
        if let Ok(cstr) = CString::new(event_json) {
            callback(cstr.as_ptr());
        }
    }
}

/// Starts the AlterChat core node in the background.
///
/// `config_json`: JSON string matching `FfiConfig` structure.
///
/// Returns true if the node started successfully, false on error.
/// The node runs on a background thread with its own Tokio runtime.
///
/// # Safety
/// `config_json` must be a valid null-terminated UTF-8 C string.
#[unsafe(no_mangle)]
pub extern "C" fn start_core_node(config_json: *const c_char) -> bool {
    if config_json.is_null() {
        return false;
    }
    let c_str = unsafe { CStr::from_ptr(config_json) };
    let json_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let config: FfiConfig = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // Spawn the node on the Tokio runtime
    let rt = get_runtime();
    rt.spawn(async move {
        match start_node_async(config).await {
            Ok(peer_id) => {
                let event = serde_json::json!({
                    "type": "node_started",
                    "peer_id": peer_id,
                });
                emit_event(&event.to_string());
            }
            Err(e) => {
                let event = serde_json::json!({
                    "type": "node_error",
                    "error": e,
                });
                emit_event(&event.to_string());
            }
        }
    });

    true
}

/// Internal async node startup.
async fn start_node_async(config: FfiConfig) -> Result<String, String> {
    use crate::network::{NetworkPrivacyConfig, ProxyMode, TransportPreference};

    let key_path = if config.amnesic {
        ":memory:".to_string()
    } else {
        format!("{}/keypair.bin", config.data_dir)
    };

    let keypair = crate::identity::load_or_generate_encrypted_keypair(
        &key_path,
        &config.password,
    ).map_err(|e| format!("keypair error: {e}"))?;

    let peer_id = libp2p::PeerId::from(keypair.public()).to_string();

    let net_config = NetworkPrivacyConfig {
        proxy_mode: if config.tor_enabled { ProxyMode::Tor } else { ProxyMode::Direct },
        transport_preference: TransportPreference::Tcp,
        proxy_addr: None,
        bootstrap_addrs: config.bootstrap_addrs,
        mdns_enabled: config.mdns_enabled,
        dht_server_mode: false,
        relay_enabled: false,
        relay_fallback_enabled: false,
        publish_capabilities: true,
        protocol_versions: vec!["/alterchat/p2p/1.0.0".to_string()],
    };

    let mut swarm = crate::network::create_swarm(keypair, net_config)
        .await
        .map_err(|e| format!("swarm error: {e}"))?;

    // Listen on a random port
    let listen_addr: libp2p::Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
    swarm.listen_on(listen_addr).map_err(|e| format!("listen error: {e}"))?;

    // Run the swarm event loop
    tokio::spawn(async move {
        use libp2p::futures::StreamExt;
        loop {
            let event = swarm.select_next_some().await;
            // Emit relevant events to the callback
            match &event {
                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                    let ev = serde_json::json!({
                        "type": "listening",
                        "address": address.to_string(),
                    });
                    emit_event(&ev.to_string());
                }
                libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    let ev = serde_json::json!({
                        "type": "peer_connected",
                        "peer_id": peer_id.to_string(),
                    });
                    emit_event(&ev.to_string());
                }
                _ => {}
            }
        }
    });

    Ok(peer_id)
}

/// Retrieves the system capacity score.
/// Used by Manifesto II: stronger machines carry more network load.
#[unsafe(no_mangle)]
pub extern "C" fn get_capacity_score() -> u32 {
    crate::calculate_system_capacity()
}

/// Sends a message to the specified DHT offline mailbox.
///
/// # Safety
/// Both `pubkey` and `msg` must be valid null-terminated UTF-8 C strings.
#[unsafe(no_mangle)]
pub extern "C" fn send_offline_message(pubkey: *const c_char, msg: *const c_char) -> bool {
    if pubkey.is_null() || msg.is_null() {
        return false;
    }
    let _pubkey_str = match unsafe { CStr::from_ptr(pubkey) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return false,
    };
    let _msg_str = match unsafe { CStr::from_ptr(msg) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return false,
    };
    // TODO: Dispatch to the running swarm via a channel
    // This requires storing the swarm command sender in a static
    true
}

/// Returns the library version as a C string.
/// The returned pointer is valid for the lifetime of the program.
#[unsafe(no_mangle)]
pub extern "C" fn alterchat_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION.get_or_init(|| {
        CString::new(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| CString::new("0.0.0").unwrap())
    }).as_ptr()
}

/// Frees a C string allocated by this library.
///
/// # Safety
/// The pointer must have been allocated by this library via `CString::into_raw`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn alterchat_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)); }
    }
}
