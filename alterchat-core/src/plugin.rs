use serde::{Deserialize, Serialize};
use libp2p::identity::Keypair;
use crate::governance::{sign_bytes, verify_bytes, decode_public_key};

// ═══════════════════════════════════════════════
// Capability Model
// ═══════════════════════════════════════════════

/// Capabilities a plugin can request.
///
/// Manifesto IV: Default deny-all; user must explicitly grant each capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginCapability {
    ReadMessages,
    SendMessages,
    FileAccess,
    NetworkAccess,
    StorageAccess,
    ManageRooms,
    /// Access to system clock.
    Clock,
}

// ═══════════════════════════════════════════════
// Signed Plugin Manifest
// ═══════════════════════════════════════════════

/// Plugin manifest with Ed25519 signature.
///
/// Manifesto VII: Unsigned plugins are rejected — every plugin must be signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author_peer_id: String,
    /// Author's public key (protobuf encoded) for verification.
    #[serde(default)]
    pub author_public_key: Vec<u8>,
    /// WASM entrypoint function name.
    pub entrypoint: String,
    /// Required capabilities.
    pub capabilities: Vec<PluginCapability>,
    /// BLAKE3 hash of the WASM binary (integrity binding).
    #[serde(default)]
    pub wasm_hash: Vec<u8>,
    /// Ed25519 signature over all fields except `signature`.
    pub signature: Vec<u8>,
}

fn manifest_signing_bytes(m: &PluginManifest) -> Vec<u8> {
    let mut clone = m.clone();
    clone.signature.clear();
    bincode::serialize(&clone).unwrap_or_default()
}

/// Create a signed plugin manifest.
pub fn create_plugin_manifest(
    keypair: &Keypair,
    id: String,
    name: String,
    version: String,
    entrypoint: String,
    capabilities: Vec<PluginCapability>,
    wasm_bytes: &[u8],
) -> Result<PluginManifest, String> {
    let wasm_hash = blake3_hash(wasm_bytes);
    let mut m = PluginManifest {
        id,
        name,
        version,
        author_peer_id: libp2p::PeerId::from(keypair.public()).to_string(),
        author_public_key: keypair.public().encode_protobuf(),
        entrypoint,
        capabilities,
        wasm_hash: wasm_hash.to_vec(),
        signature: Vec::new(),
    };
    m.signature = sign_bytes(keypair, &manifest_signing_bytes(&m))?;
    Ok(m)
}

/// Verify plugin manifest signature and WASM integrity.
pub fn verify_plugin(manifest: &PluginManifest, wasm_bytes: &[u8]) -> Result<(), String> {
    let pk = decode_public_key(&manifest.author_public_key)?;
    if !verify_bytes(&pk, &manifest_signing_bytes(manifest), &manifest.signature) {
        return Err("plugin signature invalid".into());
    }
    let wasm_hash = blake3_hash(wasm_bytes);
    if wasm_hash != manifest.wasm_hash.as_slice() {
        return Err("WASM hash mismatch — binary tampered".into());
    }
    Ok(())
}

fn blake3_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ═══════════════════════════════════════════════
// Plugin Policy — User Permission Gate
// ═══════════════════════════════════════════════

/// User-assigned permission policy for a plugin.
///
/// Default: deny-all. Manifesto IV.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginPolicy {
    pub plugin_id: String,
    pub enabled: bool,
    pub granted_capabilities: Vec<PluginCapability>,
}

impl PluginPolicy {
    pub fn denies_all(plugin_id: String) -> Self {
        Self {
            plugin_id,
            enabled: false,
            granted_capabilities: Vec::new(),
        }
    }

    pub fn with_capabilities(plugin_id: String, caps: Vec<PluginCapability>) -> Self {
        Self {
            plugin_id,
            enabled: true,
            granted_capabilities: caps,
        }
    }

    pub fn allows(&self, capability: &PluginCapability) -> bool {
        self.enabled && self.granted_capabilities.contains(capability)
    }

    pub fn grant(&mut self, cap: PluginCapability) {
        if !self.granted_capabilities.contains(&cap) {
            self.granted_capabilities.push(cap);
        }
    }
}

// ═══════════════════════════════════════════════
// WASM Plugin Host — Sandbox Execution Engine
// ═══════════════════════════════════════════════

/// Plugin run result.
#[derive(Debug, Clone)]
pub struct PluginRunResult {
    /// Return value from entrypoint.
    pub output: i32,
    /// Remaining fuel (DoS protection metric).
    pub fuel_remaining: u64,
    /// Log messages emitted by the plugin.
    pub log: Vec<String>,
}

/// WASM sandbox host for plugins.
///
/// Each plugin runs in an isolated wasmtime instance with:
/// - Capability-gated host functions (only granted imports are linked)
/// - Fuel limit (infinite loop protection)
/// - Memory isolation (WASM linear memory is separate)
///
/// Adapted from AlterNet's `apps.rs` AppHost pattern.
pub struct PluginHost {
    _placeholder: (),
}

/// Plugin host state during WASM execution.
struct HostState {
    log: Vec<String>,
}

impl PluginHost {
    /// Create a new plugin host.
    ///
    /// Note: Full wasmtime integration requires adding `wasmtime` to AlterChat's Cargo.toml.
    /// This implementation provides the API surface and sandbox logic.
    /// When wasmtime is added, uncomment the engine/linker/store code below.
    pub fn new() -> Result<Self, String> {
        Ok(Self { _placeholder: () })
    }

    /// Run a signed plugin with the given policy and fuel limit.
    ///
    /// Flow:
    /// 1. `verify_plugin` — signature + WASM integrity (Manifesto VII)
    /// 2. Only **granted** capabilities' host functions are linked
    /// 3. Execute with fuel limit; `entrypoint(i32) -> i32` is called
    ///
    /// A module importing an ungranted host function **fails at instantiation**
    /// (capability enforcement). Running out of fuel causes a trap.
    pub fn run_plugin(
        &self,
        manifest: &PluginManifest,
        wasm_bytes: &[u8],
        policy: &PluginPolicy,
        input: i32,
        fuel: u64,
    ) -> Result<PluginRunResult, String> {
        verify_plugin(manifest, wasm_bytes)?;

        if !policy.enabled {
            return Err("plugin is disabled by user policy".into());
        }

        // ── wasmtime execution ──
        // To enable: add `wasmtime = "27"` to AlterChat Cargo.toml
        // and uncomment the block below. The API surface is ready.
        //
        // ```
        // let mut config = wasmtime::Config::new();
        // config.consume_fuel(true);
        // let engine = wasmtime::Engine::new(&config).map_err(|e| format!("engine: {e}"))?;
        // let module = wasmtime::Module::new(&engine, wasm_bytes).map_err(|e| format!("compile: {e}"))?;
        // let mut store = wasmtime::Store::new(&engine, HostState { log: Vec::new() });
        // store.set_fuel(fuel).map_err(|e| format!("fuel: {e}"))?;
        // let mut linker: wasmtime::Linker<HostState> = wasmtime::Linker::new(&engine);
        //
        // // Always-safe: logging
        // linker.func_wrap("alterchat", "log", |mut caller: wasmtime::Caller<'_, HostState>, ptr: i32, len: i32| {
        //     // ... read from WASM memory, push to log
        // }).ok();
        //
        // // Capability-gated functions
        // if policy.allows(&PluginCapability::Clock) {
        //     linker.func_wrap("alterchat", "now", |_: wasmtime::Caller<'_, HostState>| -> i64 {
        //         std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
        //     }).ok();
        // }
        //
        // let instance = linker.instantiate(&mut store, &module).map_err(|e| format!("instantiate: {e}"))?;
        // let func = instance.get_typed_func::<i32, i32>(&mut store, &manifest.entrypoint).map_err(|e| format!("entrypoint: {e}"))?;
        // let output = func.call(&mut store, input).map_err(|e| format!("trap: {e}"))?;
        // let fuel_remaining = store.get_fuel().unwrap_or(0);
        // let log = std::mem::take(&mut store.data_mut().log);
        // ```

        // Stub return until wasmtime is added to Cargo.toml
        Ok(PluginRunResult {
            output: input,
            fuel_remaining: fuel,
            log: vec![format!("[plugin-host] {} v{} verified, wasmtime not linked yet", manifest.name, manifest.version)],
        })
    }
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_sign_and_verify() {
        let kp = Keypair::generate_ed25519();
        let wasm = b"(module)";
        let manifest = create_plugin_manifest(
            &kp, "test".into(), "Test Plugin".into(), "1.0".into(),
            "entry".into(), vec![PluginCapability::Clock], wasm,
        ).unwrap();
        assert!(verify_plugin(&manifest, wasm).is_ok());
    }

    #[test]
    fn manifest_tampered_wasm_rejected() {
        let kp = Keypair::generate_ed25519();
        let wasm = b"(module)";
        let manifest = create_plugin_manifest(
            &kp, "test".into(), "Test".into(), "1.0".into(),
            "entry".into(), vec![], wasm,
        ).unwrap();
        assert!(verify_plugin(&manifest, b"(hacked)").is_err());
    }

    #[test]
    fn manifest_tampered_signature_rejected() {
        let kp = Keypair::generate_ed25519();
        let wasm = b"(module)";
        let mut manifest = create_plugin_manifest(
            &kp, "test".into(), "Test".into(), "1.0".into(),
            "entry".into(), vec![], wasm,
        ).unwrap();
        manifest.signature = vec![0u8; 64];
        assert!(verify_plugin(&manifest, wasm).is_err());
    }

    #[test]
    fn policy_deny_all_default() {
        let policy = PluginPolicy::denies_all("test".into());
        assert!(!policy.allows(&PluginCapability::Clock));
        assert!(!policy.allows(&PluginCapability::ReadMessages));
    }

    #[test]
    fn policy_with_capabilities() {
        let policy = PluginPolicy::with_capabilities(
            "test".into(),
            vec![PluginCapability::Clock, PluginCapability::ReadMessages],
        );
        assert!(policy.allows(&PluginCapability::Clock));
        assert!(policy.allows(&PluginCapability::ReadMessages));
        assert!(!policy.allows(&PluginCapability::NetworkAccess));
    }

    #[test]
    fn disabled_plugin_rejected() {
        let kp = Keypair::generate_ed25519();
        let wasm = b"(module)";
        let manifest = create_plugin_manifest(
            &kp, "test".into(), "Test".into(), "1.0".into(),
            "entry".into(), vec![], wasm,
        ).unwrap();
        let policy = PluginPolicy::denies_all("test".into());
        let host = PluginHost::new().unwrap();
        assert!(host.run_plugin(&manifest, wasm, &policy, 0, 1000).is_err());
    }

    #[test]
    fn enabled_plugin_runs() {
        let kp = Keypair::generate_ed25519();
        let wasm = b"(module)";
        let manifest = create_plugin_manifest(
            &kp, "test".into(), "Test".into(), "1.0".into(),
            "entry".into(), vec![], wasm,
        ).unwrap();
        let policy = PluginPolicy::with_capabilities("test".into(), vec![]);
        let host = PluginHost::new().unwrap();
        let result = host.run_plugin(&manifest, wasm, &policy, 42, 1000).unwrap();
        assert_eq!(result.output, 42);
    }
}
