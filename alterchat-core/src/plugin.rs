use crate::governance::{decode_public_key, sign_bytes, verify_bytes};
use libp2p::identity::Keypair;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════
// Capability Model
// ═══════════════════════════════════════════════

/// Capabilities a plugin can request.
///
/// Default deny-all: the user must explicitly grant each capability.
///
/// A capability is only effective when it is both *requested* in the signed
/// manifest and *granted* in the user's [`PluginPolicy`]. Capabilities without
/// a host function (`FileAccess`, `NetworkAccess`, `StorageAccess`,
/// `ManageRooms`) are reserved: granting them links nothing, so a plugin can
/// never reach the filesystem, network or environment. See `docs/PLUGINS.md`.
///
/// New variants must be appended at the end: manifests are signed over their
/// bincode encoding, which uses the variant index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginCapability {
    /// `read_room_messages` / `room_messages_len`.
    ReadMessages,
    /// `send_room_message`.
    SendMessages,
    FileAccess,
    NetworkAccess,
    StorageAccess,
    ManageRooms,
    /// `now_ms` — access to the system clock.
    Clock,
    /// `notify` — show a local notification.
    Notify,
}

// ═══════════════════════════════════════════════
// Signed Plugin Manifest
// ═══════════════════════════════════════════════

/// Plugin manifest with Ed25519 signature.
///
/// Unsigned plugins are rejected — every plugin must be signed.
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
/// Default: deny-all.
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
//
// Runtime: `wasmi` (pure-Rust interpreter). No WASI, no ambient authority:
// the only things a guest can touch are its own linear memory and the host
// functions linked below, each of which is gated on an effective capability.
// The ABI is documented in `docs/PLUGINS.md`.

/// Import module name for every host function.
pub const HOST_MODULE: &str = "alterchat";

/// Name of the linear memory a plugin must export to use pointer-taking
/// host functions.
pub const MEMORY_EXPORT: &str = "memory";

/// Size of a WebAssembly page in bytes.
pub const WASM_PAGE_SIZE: usize = 64 * 1024;

/// Host function table: `(import name, capability required to link it)`.
/// `None` means the function is always linked (it grants no authority).
const HOST_FUNCTIONS: &[(&str, Option<PluginCapability>)] = &[
    ("log", None),
    ("input_len", None),
    ("input_read", None),
    ("output_write", None),
    ("room_messages_len", Some(PluginCapability::ReadMessages)),
    ("read_room_messages", Some(PluginCapability::ReadMessages)),
    ("send_room_message", Some(PluginCapability::SendMessages)),
    ("notify", Some(PluginCapability::Notify)),
    ("now_ms", Some(PluginCapability::Clock)),
];

/// Resource limits applied to a single plugin run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLimits {
    /// Instruction budget (wasmi fuel). Host functions also charge 1 fuel per
    /// byte they copy across the sandbox boundary.
    pub fuel: u64,
    /// Maximum linear memory size in 64 KiB pages (initial and grown).
    pub max_memory_pages: u32,
    /// Maximum size of the WASM binary accepted for compilation.
    pub max_wasm_bytes: usize,
    /// Maximum total bytes written via `output_write`.
    pub max_output_bytes: usize,
    /// Maximum number of `log` entries kept (further entries are dropped).
    pub max_log_entries: usize,
    /// Maximum size of a single `log` entry.
    pub max_log_entry_bytes: usize,
    /// Maximum number of `send_room_message` calls per run.
    pub max_sent_messages: usize,
    /// Maximum size of a single outgoing room message.
    pub max_message_bytes: usize,
    /// Maximum number of `notify` calls per run.
    pub max_notifications: usize,
    /// Maximum size of a single notification.
    pub max_notification_bytes: usize,
}

impl Default for PluginLimits {
    fn default() -> Self {
        Self {
            fuel: 10_000_000,
            max_memory_pages: 16, // 1 MiB
            max_wasm_bytes: 4 * 1024 * 1024,
            max_output_bytes: 64 * 1024,
            max_log_entries: 64,
            max_log_entry_bytes: 1024,
            max_sent_messages: 8,
            max_message_bytes: 4 * 1024,
            max_notifications: 4,
            max_notification_bytes: 256,
        }
    }
}

/// Data the host exposes to a plugin for one run.
#[derive(Debug, Clone, Default)]
pub struct PluginContext {
    /// Event payload, readable via `input_len` / `input_read`.
    pub input: Vec<u8>,
    /// Snapshot of recent room messages (UTF-8 JSON), readable via
    /// `read_room_messages` only when `ReadMessages` is effective.
    pub room_messages: Vec<u8>,
}

/// Plugin run result.
///
/// Side effects (`sent_messages`, `notifications`) are *requests*: the host
/// application applies them after the run, outside the sandbox.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginRunResult {
    /// Status code returned by the entrypoint.
    pub status: i32,
    /// Bytes written via `output_write`.
    pub output: Vec<u8>,
    /// Fuel consumed by this run.
    pub fuel_consumed: u64,
    /// Remaining fuel (DoS protection metric).
    pub fuel_remaining: u64,
    /// Log messages emitted by the plugin.
    pub log: Vec<String>,
    /// Room messages the plugin asked to send (`SendMessages`).
    pub sent_messages: Vec<String>,
    /// Notifications the plugin asked to show (`Notify`).
    pub notifications: Vec<String>,
}

/// Why a plugin run was refused or aborted. Every variant fails closed: no
/// partial side effects are returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PluginError {
    #[error("plugin verification failed: {0}")]
    Verification(String),
    #[error("plugin is disabled by user policy")]
    Disabled,
    #[error("plugin binary is {size} bytes, limit is {limit}")]
    TooLarge { size: usize, limit: usize },
    #[error("invalid WASM module: {0}")]
    InvalidModule(String),
    #[error("plugin imports `{module}.{name}`, which is not provided (no WASI or foreign imports)")]
    UnknownImport { module: String, name: String },
    #[error(
        "plugin imports `{HOST_MODULE}.{name}`, which requires capability {capability:?}; it is not granted"
    )]
    CapabilityNotGranted {
        name: String,
        capability: PluginCapability,
    },
    #[error("plugin instantiation failed: {0}")]
    Instantiation(String),
    #[error("entrypoint `{0}` missing or not of type `() -> i32`")]
    MissingEntrypoint(String),
    #[error("plugin ran out of fuel")]
    OutOfFuel,
    #[error("plugin exceeded its memory limit: {0}")]
    MemoryLimit(String),
    #[error("sandbox violation: {0}")]
    SandboxViolation(String),
    #[error("plugin trapped: {0}")]
    Trap(String),
    #[error("plugin host error: {0}")]
    Host(String),
}

/// Host error raised when a guest violates the ABI (bad pointer, oversized
/// buffer, invalid UTF-8, quota exceeded). Aborts the run as a trap.
#[derive(Debug)]
struct SandboxViolation(String);

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl wasmi::errors::HostError for SandboxViolation {}

fn violation(msg: impl Into<String>) -> wasmi::Error {
    wasmi::Error::host(SandboxViolation(msg.into()))
}

/// Per-run store data.
struct HostState {
    limits: PluginLimits,
    store_limits: wasmi::StoreLimits,
    ctx: PluginContext,
    output: Vec<u8>,
    log: Vec<String>,
    dropped_logs: usize,
    sent_messages: Vec<String>,
    notifications: Vec<String>,
}

type HostCaller<'a> = wasmi::Caller<'a, HostState>;

/// Validate a guest `(ptr, len)` pair against the current memory size and a
/// per-call size cap. Pointers and lengths are interpreted as unsigned 32-bit
/// values, matching wasm32 semantics; overflow is rejected.
fn guest_range(
    ptr: i32,
    len: i32,
    max_len: usize,
    mem_size: usize,
    what: &str,
) -> Result<std::ops::Range<usize>, wasmi::Error> {
    let start = ptr as u32 as usize;
    let len = len as u32 as usize;
    if len > max_len {
        return Err(violation(format!(
            "{what}: length {len} exceeds limit {max_len}"
        )));
    }
    let end = start
        .checked_add(len)
        .ok_or_else(|| violation(format!("{what}: pointer overflow")))?;
    if end > mem_size {
        return Err(violation(format!(
            "{what}: range {start}..{end} out of bounds (memory is {mem_size} bytes)"
        )));
    }
    Ok(start..end)
}

fn guest_memory(caller: &HostCaller<'_>) -> Result<wasmi::Memory, wasmi::Error> {
    match caller.get_export(MEMORY_EXPORT) {
        Some(wasmi::Extern::Memory(mem)) => Ok(mem),
        _ => Err(violation(format!(
            "plugin must export a linear memory named `{MEMORY_EXPORT}`"
        ))),
    }
}

/// Charge fuel for bytes copied across the boundary so host calls cannot be
/// used to amplify work beyond the instruction budget.
fn charge_fuel(caller: &mut HostCaller<'_>, bytes: usize) -> Result<(), wasmi::Error> {
    let fuel = caller.get_fuel()?;
    let cost = bytes as u64;
    if cost > fuel {
        caller.set_fuel(0)?;
        return Err(wasmi::TrapCode::OutOfFuel.into());
    }
    caller.set_fuel(fuel - cost)
}

/// Copy `len` bytes out of guest memory (bounds-checked, size-capped).
fn read_guest(
    caller: &mut HostCaller<'_>,
    ptr: i32,
    len: i32,
    max_len: usize,
    what: &str,
) -> Result<Vec<u8>, wasmi::Error> {
    let mem = guest_memory(caller)?;
    let bytes = {
        let data = mem.data(&*caller);
        let range = guest_range(ptr, len, max_len, data.len(), what)?;
        data[range].to_vec()
    };
    charge_fuel(caller, bytes.len())?;
    Ok(bytes)
}

/// Copy as much of `src` as fits into the guest buffer `(ptr, cap)`.
/// Returns the number of bytes written.
fn write_guest(
    caller: &mut HostCaller<'_>,
    ptr: i32,
    cap: i32,
    src: &[u8],
    what: &str,
) -> Result<i32, wasmi::Error> {
    let mem = guest_memory(caller)?;
    let mem_size = mem.data_size(&*caller);
    let range = guest_range(ptr, cap, usize::MAX, mem_size, what)?;
    let n = src.len().min(range.len());
    charge_fuel(caller, n)?;
    mem.data_mut(&mut *caller)[range.start..range.start + n].copy_from_slice(&src[..n]);
    // n <= cap <= u32::MAX as i32 range of the original argument.
    Ok(n as i32)
}

fn len_as_i32(len: usize) -> i32 {
    i32::try_from(len).unwrap_or(i32::MAX)
}

fn link_host_function(
    linker: &mut wasmi::Linker<HostState>,
    name: &str,
) -> Result<(), wasmi::Error> {
    match name {
        "log" => {
            linker.func_wrap(
                HOST_MODULE,
                "log",
                |mut caller: HostCaller<'_>, ptr: i32, len: i32| -> Result<(), wasmi::Error> {
                    let max = caller.data().limits.max_log_entry_bytes;
                    let bytes = read_guest(&mut caller, ptr, len, max, "log")?;
                    let state = caller.data_mut();
                    if state.log.len() < state.limits.max_log_entries {
                        state.log.push(String::from_utf8_lossy(&bytes).into_owned());
                    } else {
                        state.dropped_logs += 1;
                    }
                    Ok(())
                },
            )?;
        }
        "input_len" => {
            linker.func_wrap(HOST_MODULE, "input_len", |caller: HostCaller<'_>| -> i32 {
                len_as_i32(caller.data().ctx.input.len())
            })?;
        }
        "input_read" => {
            linker.func_wrap(
                HOST_MODULE,
                "input_read",
                |mut caller: HostCaller<'_>, ptr: i32, cap: i32| -> Result<i32, wasmi::Error> {
                    let input = std::mem::take(&mut caller.data_mut().ctx.input);
                    let res = write_guest(&mut caller, ptr, cap, &input, "input_read");
                    caller.data_mut().ctx.input = input;
                    res
                },
            )?;
        }
        "output_write" => {
            linker.func_wrap(
                HOST_MODULE,
                "output_write",
                |mut caller: HostCaller<'_>, ptr: i32, len: i32| -> Result<i32, wasmi::Error> {
                    let state = caller.data();
                    let remaining = state
                        .limits
                        .max_output_bytes
                        .saturating_sub(state.output.len());
                    let bytes = read_guest(&mut caller, ptr, len, remaining, "output_write")?;
                    caller.data_mut().output.extend_from_slice(&bytes);
                    Ok(0)
                },
            )?;
        }
        "room_messages_len" => {
            linker.func_wrap(
                HOST_MODULE,
                "room_messages_len",
                |caller: HostCaller<'_>| -> i32 {
                    len_as_i32(caller.data().ctx.room_messages.len())
                },
            )?;
        }
        "read_room_messages" => {
            linker.func_wrap(
                HOST_MODULE,
                "read_room_messages",
                |mut caller: HostCaller<'_>, ptr: i32, cap: i32| -> Result<i32, wasmi::Error> {
                    let msgs = std::mem::take(&mut caller.data_mut().ctx.room_messages);
                    let res = write_guest(&mut caller, ptr, cap, &msgs, "read_room_messages");
                    caller.data_mut().ctx.room_messages = msgs;
                    res
                },
            )?;
        }
        "send_room_message" => {
            linker.func_wrap(
                HOST_MODULE,
                "send_room_message",
                |mut caller: HostCaller<'_>, ptr: i32, len: i32| -> Result<i32, wasmi::Error> {
                    let limits = caller.data().limits;
                    if caller.data().sent_messages.len() >= limits.max_sent_messages {
                        return Err(violation("send_room_message: per-run quota exceeded"));
                    }
                    let bytes = read_guest(
                        &mut caller,
                        ptr,
                        len,
                        limits.max_message_bytes,
                        "send_room_message",
                    )?;
                    let text = String::from_utf8(bytes)
                        .map_err(|_| violation("send_room_message: text is not valid UTF-8"))?;
                    caller.data_mut().sent_messages.push(text);
                    Ok(0)
                },
            )?;
        }
        "notify" => {
            linker.func_wrap(
                HOST_MODULE,
                "notify",
                |mut caller: HostCaller<'_>, ptr: i32, len: i32| -> Result<i32, wasmi::Error> {
                    let limits = caller.data().limits;
                    if caller.data().notifications.len() >= limits.max_notifications {
                        return Err(violation("notify: per-run quota exceeded"));
                    }
                    let bytes = read_guest(
                        &mut caller,
                        ptr,
                        len,
                        limits.max_notification_bytes,
                        "notify",
                    )?;
                    let text = String::from_utf8(bytes)
                        .map_err(|_| violation("notify: text is not valid UTF-8"))?;
                    caller.data_mut().notifications.push(text);
                    Ok(0)
                },
            )?;
        }
        "now_ms" => {
            linker.func_wrap(HOST_MODULE, "now_ms", |_: HostCaller<'_>| -> i64 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
                    .unwrap_or(0)
            })?;
        }
        other => {
            return Err(wasmi::Error::new(format!("unknown host function {other}")));
        }
    }
    Ok(())
}

/// Is `cap` effective, i.e. requested by the signed manifest *and* granted
/// by the user policy?
fn capability_effective(
    manifest: &PluginManifest,
    policy: &PluginPolicy,
    cap: &PluginCapability,
) -> bool {
    manifest.capabilities.contains(cap) && policy.allows(cap)
}

fn map_run_error(err: wasmi::Error) -> PluginError {
    use wasmi::errors::ErrorKind;
    if let Some(v) = err.downcast_ref::<SandboxViolation>() {
        return PluginError::SandboxViolation(v.0.clone());
    }
    match err.as_trap_code() {
        Some(wasmi::TrapCode::OutOfFuel) => return PluginError::OutOfFuel,
        Some(wasmi::TrapCode::GrowthOperationLimited) => {
            return PluginError::MemoryLimit(err.to_string());
        }
        _ => {}
    }
    match err.kind() {
        ErrorKind::Fuel(_) => PluginError::OutOfFuel,
        ErrorKind::Memory(_) => PluginError::MemoryLimit(err.to_string()),
        _ => PluginError::Trap(err.to_string()),
    }
}

/// WASM sandbox host for plugins.
///
/// Each run gets a fresh [`wasmi::Store`] with:
/// - Capability-gated host functions (only effective capabilities are linked;
///   importing anything else is refused before instantiation)
/// - A fuel budget (infinite loop protection)
/// - A memory limit (max pages; growth beyond it traps)
/// - No WASI, no start function, single memory, strict parse limits
pub struct PluginHost {
    engine: wasmi::Engine,
}

impl PluginHost {
    /// Create a new plugin host.
    pub fn new() -> Result<Self, String> {
        let mut config = wasmi::Config::default();
        config
            .consume_fuel(true)
            .allow_start_fn(false)
            .wasm_multi_memory(false)
            .enforced_limits(wasmi::EnforcedLimits::strict());
        Ok(Self {
            engine: wasmi::Engine::new(&config),
        })
    }

    /// Verify, link and run a signed plugin.
    ///
    /// Flow:
    /// 1. `verify_plugin` — signature + WASM integrity
    /// 2. Policy must be enabled
    /// 3. Every import is checked: it must be a function in [`HOST_MODULE`]
    ///    whose capability (if any) is effective — otherwise the run is
    ///    refused with a clear error (fail closed)
    /// 4. Only those host functions are linked; the module is instantiated
    ///    under the memory limit and `manifest.entrypoint: () -> i32` is
    ///    called with `limits.fuel`
    pub fn run_plugin(
        &self,
        manifest: &PluginManifest,
        wasm_bytes: &[u8],
        policy: &PluginPolicy,
        ctx: PluginContext,
        limits: PluginLimits,
    ) -> Result<PluginRunResult, PluginError> {
        verify_plugin(manifest, wasm_bytes).map_err(PluginError::Verification)?;
        if policy.plugin_id != manifest.id {
            return Err(PluginError::Verification(
                "policy does not belong to this plugin".into(),
            ));
        }
        if !policy.enabled {
            return Err(PluginError::Disabled);
        }
        if wasm_bytes.len() > limits.max_wasm_bytes {
            return Err(PluginError::TooLarge {
                size: wasm_bytes.len(),
                limit: limits.max_wasm_bytes,
            });
        }

        let module = wasmi::Module::new(&self.engine, wasm_bytes)
            .map_err(|e| PluginError::InvalidModule(e.to_string()))?;

        // ── Capability check + selective linking ──
        let mut linker: wasmi::Linker<HostState> = wasmi::Linker::new(&self.engine);
        let mut linked: Vec<&'static str> = Vec::new();
        for import in module.imports() {
            let unknown = || PluginError::UnknownImport {
                module: import.module().to_string(),
                name: import.name().to_string(),
            };
            if import.module() != HOST_MODULE || !matches!(import.ty(), wasmi::ExternType::Func(_))
            {
                return Err(unknown());
            }
            let (name, required) = HOST_FUNCTIONS
                .iter()
                .find(|(n, _)| *n == import.name())
                .ok_or_else(unknown)?;
            if let Some(cap) = required
                && !capability_effective(manifest, policy, cap)
            {
                return Err(PluginError::CapabilityNotGranted {
                    name: (*name).to_string(),
                    capability: *cap,
                });
            }
            if !linked.contains(name) {
                link_host_function(&mut linker, name)
                    .map_err(|e| PluginError::Host(e.to_string()))?;
                linked.push(name);
            }
        }

        // ── Store with fuel + memory limits ──
        let max_memory_bytes = (limits.max_memory_pages as usize).saturating_mul(WASM_PAGE_SIZE);
        let store_limits = wasmi::StoreLimitsBuilder::new()
            .memory_size(max_memory_bytes)
            .memories(1)
            .tables(1)
            .table_elements(10_000)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = wasmi::Store::new(
            &self.engine,
            HostState {
                limits,
                store_limits,
                ctx,
                output: Vec::new(),
                log: Vec::new(),
                dropped_logs: 0,
                sent_messages: Vec::new(),
                notifications: Vec::new(),
            },
        );
        store.limiter(|state| &mut state.store_limits);
        store
            .set_fuel(limits.fuel)
            .map_err(|e| PluginError::Host(e.to_string()))?;

        let instance = linker
            .instantiate_and_start(&mut store, &module)
            .map_err(|e| match map_run_error(e) {
                PluginError::Trap(msg) => PluginError::Instantiation(msg),
                other => other,
            })?;
        let entry = instance
            .get_typed_func::<(), i32>(&store, &manifest.entrypoint)
            .map_err(|_| PluginError::MissingEntrypoint(manifest.entrypoint.clone()))?;
        let status = entry.call(&mut store, ()).map_err(map_run_error)?;

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let mut state = store.into_data();
        if state.dropped_logs > 0 {
            state.log.push(format!(
                "[plugin-host] {} log entries dropped (limit {})",
                state.dropped_logs, limits.max_log_entries
            ));
        }
        Ok(PluginRunResult {
            status,
            output: state.output,
            fuel_consumed: limits.fuel.saturating_sub(fuel_remaining),
            fuel_remaining,
            log: state.log,
            sent_messages: state.sent_messages,
            notifications: state.notifications,
        })
    }
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const ECHO_WAT: &str = include_str!("../tests/fixtures/plugins/echo.wat");

    fn wasm(wat_src: &str) -> Vec<u8> {
        wat::parse_str(wat_src).expect("valid WAT")
    }

    fn signed(wasm: &[u8], caps: Vec<PluginCapability>) -> PluginManifest {
        let kp = Keypair::generate_ed25519();
        create_plugin_manifest(
            &kp,
            "test".into(),
            "Test Plugin".into(),
            "1.0".into(),
            "on_event".into(),
            caps,
            wasm,
        )
        .unwrap()
    }

    fn run(
        wasm: &[u8],
        requested: Vec<PluginCapability>,
        granted: Vec<PluginCapability>,
        ctx: PluginContext,
        limits: PluginLimits,
    ) -> Result<PluginRunResult, PluginError> {
        let manifest = signed(wasm, requested);
        let policy = PluginPolicy::with_capabilities("test".into(), granted);
        PluginHost::new()
            .unwrap()
            .run_plugin(&manifest, wasm, &policy, ctx, limits)
    }

    fn input(bytes: &[u8]) -> PluginContext {
        PluginContext {
            input: bytes.to_vec(),
            ..Default::default()
        }
    }

    #[test]
    fn manifest_sign_and_verify() {
        let wasm = b"(module)";
        let manifest = signed(wasm, vec![PluginCapability::Clock]);
        assert!(verify_plugin(&manifest, wasm).is_ok());
    }

    #[test]
    fn manifest_tampered_wasm_rejected() {
        let wasm = b"(module)";
        let manifest = signed(wasm, vec![]);
        assert!(verify_plugin(&manifest, b"(hacked)").is_err());
    }

    #[test]
    fn manifest_tampered_signature_rejected() {
        let wasm = b"(module)";
        let mut manifest = signed(wasm, vec![]);
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
        let wasm = wasm(ECHO_WAT);
        let manifest = signed(&wasm, vec![]);
        let policy = PluginPolicy::denies_all("test".into());
        let host = PluginHost::new().unwrap();
        let err = host
            .run_plugin(
                &manifest,
                &wasm,
                &policy,
                input(b"x"),
                PluginLimits::default(),
            )
            .unwrap_err();
        assert_eq!(err, PluginError::Disabled);
    }

    #[test]
    fn valid_signed_plugin_runs_and_returns_output() {
        let wasm = wasm(ECHO_WAT);
        let res = run(
            &wasm,
            vec![],
            vec![],
            input(b"{\"hello\":1}"),
            PluginLimits::default(),
        )
        .unwrap();
        assert_eq!(res.status, 0);
        assert_eq!(res.output, b"echo: {\"hello\":1}");
        assert_eq!(res.log, vec!["echo plugin started".to_string()]);
        assert!(res.fuel_consumed > 0);
        assert!(res.sent_messages.is_empty());
    }

    #[test]
    fn tampered_wasm_rejected_before_execution() {
        let wasm = wasm(ECHO_WAT);
        let manifest = signed(&wasm, vec![]);
        let mut tampered = wasm.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        let policy = PluginPolicy::with_capabilities("test".into(), vec![]);
        let err = PluginHost::new()
            .unwrap()
            .run_plugin(
                &manifest,
                &tampered,
                &policy,
                input(b""),
                PluginLimits::default(),
            )
            .unwrap_err();
        assert!(matches!(err, PluginError::Verification(_)), "{err}");
    }

    #[test]
    fn infinite_loop_stopped_by_fuel() {
        let wasm = wasm(
            r#"(module (func (export "on_event") (result i32)
                (loop $l (br $l)) (i32.const 0)))"#,
        );
        let limits = PluginLimits {
            fuel: 100_000,
            ..Default::default()
        };
        let err = run(&wasm, vec![], vec![], input(b""), limits).unwrap_err();
        assert_eq!(err, PluginError::OutOfFuel);
    }

    #[test]
    fn memory_growth_beyond_limit_fails() {
        let wasm = wasm(
            r#"(module (memory (export "memory") 1)
                (func (export "on_event") (result i32)
                  (drop (memory.grow (i32.const 64))) (i32.const 0)))"#,
        );
        let limits = PluginLimits {
            max_memory_pages: 4,
            ..Default::default()
        };
        let err = run(&wasm, vec![], vec![], input(b""), limits).unwrap_err();
        assert!(matches!(err, PluginError::MemoryLimit(_)), "{err}");
    }

    #[test]
    fn initial_memory_beyond_limit_fails() {
        let wasm = wasm(
            r#"(module (memory (export "memory") 32)
                (func (export "on_event") (result i32) (i32.const 0)))"#,
        );
        let limits = PluginLimits {
            max_memory_pages: 4,
            ..Default::default()
        };
        assert!(run(&wasm, vec![], vec![], input(b""), limits).is_err());
    }

    #[test]
    fn ungranted_capability_import_refused() {
        let wasm = wasm(
            r#"(module
                (import "alterchat" "send_room_message" (func (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "on_event") (result i32) (i32.const 0)))"#,
        );
        // Requested in the manifest but not granted by the user.
        let err = run(
            &wasm,
            vec![PluginCapability::SendMessages],
            vec![],
            input(b""),
            PluginLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            PluginError::CapabilityNotGranted {
                name: "send_room_message".into(),
                capability: PluginCapability::SendMessages,
            }
        );
        // Granted by the user but not requested in the signed manifest.
        let err = run(
            &wasm,
            vec![],
            vec![PluginCapability::SendMessages],
            input(b""),
            PluginLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(err, PluginError::CapabilityNotGranted { .. }));
    }

    #[test]
    fn wasi_and_unknown_imports_refused() {
        let wasm = wasm(
            r#"(module
                (import "wasi_snapshot_preview1" "fd_write" (func (param i32 i32 i32 i32) (result i32)))
                (func (export "on_event") (result i32) (i32.const 0)))"#,
        );
        let err = run(&wasm, vec![], vec![], input(b""), PluginLimits::default()).unwrap_err();
        assert!(matches!(err, PluginError::UnknownImport { .. }), "{err}");

        let wasm2 = wasm_imported_memory();
        let err = run(&wasm2, vec![], vec![], input(b""), PluginLimits::default()).unwrap_err();
        assert!(matches!(err, PluginError::UnknownImport { .. }), "{err}");
    }

    fn wasm_imported_memory() -> Vec<u8> {
        wasm(
            r#"(module (import "alterchat" "memory" (memory 1))
                (func (export "on_event") (result i32) (i32.const 0)))"#,
        )
    }

    #[test]
    fn granted_capabilities_work() {
        let wasm = wasm(
            r#"(module
                (import "alterchat" "read_room_messages" (func $read (param i32 i32) (result i32)))
                (import "alterchat" "send_room_message" (func $send (param i32 i32) (result i32)))
                (import "alterchat" "notify" (func $notify (param i32 i32) (result i32)))
                (import "alterchat" "now_ms" (func $now (result i64)))
                (memory (export "memory") 1)
                (data (i32.const 0) "hi")
                (func (export "on_event") (result i32)
                  (local $n i32)
                  (local.set $n (call $read (i32.const 100) (i32.const 1000)))
                  (drop (call $send (i32.const 100) (local.get $n)))
                  (drop (call $notify (i32.const 0) (i32.const 2)))
                  (i64.gt_s (call $now) (i64.const 0))))"#,
        );
        let caps = vec![
            PluginCapability::ReadMessages,
            PluginCapability::SendMessages,
            PluginCapability::Notify,
            PluginCapability::Clock,
        ];
        let ctx = PluginContext {
            input: vec![],
            room_messages: b"[\"m1\"]".to_vec(),
        };
        let res = run(&wasm, caps.clone(), caps, ctx, PluginLimits::default()).unwrap();
        assert_eq!(res.status, 1);
        assert_eq!(res.sent_messages, vec!["[\"m1\"]".to_string()]);
        assert_eq!(res.notifications, vec!["hi".to_string()]);
    }

    fn oob_plugin(call: &str) -> Vec<u8> {
        wasm(&format!(
            r#"(module
                (import "alterchat" "log" (func $log (param i32 i32)))
                (import "alterchat" "input_read" (func $input_read (param i32 i32) (result i32)))
                (import "alterchat" "output_write" (func $output_write (param i32 i32) (result i32)))
                (memory (export "memory") 1 1)
                (func (export "on_event") (result i32) {call} (i32.const 0)))"#
        ))
    }

    #[test]
    fn out_of_bounds_guest_pointers_rejected_without_panic() {
        let cases = [
            // ptr past end of the 64 KiB memory
            "(call $log (i32.const 65530) (i32.const 100))",
            // negative ptr (=> huge u32)
            "(call $log (i32.const -1) (i32.const 1))",
            // ptr + len overflowing u32
            "(drop (call $output_write (i32.const 65535) (i32.const -1)))",
            // write target out of bounds
            "(drop (call $input_read (i32.const 65536) (i32.const 8)))",
            // write target with negative capacity
            "(drop (call $input_read (i32.const 0) (i32.const -8)))",
            // oversized log entry (in bounds, over size cap)
            "(call $log (i32.const 0) (i32.const 4096))",
        ];
        for call in cases {
            let wasm = oob_plugin(call);
            let err = run(
                &wasm,
                vec![],
                vec![],
                input(b"payload"),
                PluginLimits::default(),
            )
            .unwrap_err();
            assert!(
                matches!(err, PluginError::SandboxViolation(_)),
                "{call}: {err}"
            );
        }
    }

    #[test]
    fn output_size_is_capped() {
        let wasm = oob_plugin(
            "(drop (call $output_write (i32.const 0) (i32.const 1024)))
             (drop (call $output_write (i32.const 0) (i32.const 1024)))",
        );
        let limits = PluginLimits {
            max_output_bytes: 1500,
            ..Default::default()
        };
        let err = run(&wasm, vec![], vec![], input(b""), limits).unwrap_err();
        assert!(matches!(err, PluginError::SandboxViolation(_)), "{err}");
    }

    #[test]
    fn missing_entrypoint_reported() {
        let wasm = wasm(r#"(module (func (export "other") (result i32) (i32.const 0)))"#);
        let err = run(&wasm, vec![], vec![], input(b""), PluginLimits::default()).unwrap_err();
        assert_eq!(err, PluginError::MissingEntrypoint("on_event".into()));
    }

    #[test]
    fn policy_for_other_plugin_rejected() {
        let wasm = wasm(ECHO_WAT);
        let manifest = signed(&wasm, vec![]);
        let policy = PluginPolicy::with_capabilities("someone-else".into(), vec![]);
        let err = PluginHost::new()
            .unwrap()
            .run_plugin(
                &manifest,
                &wasm,
                &policy,
                input(b""),
                PluginLimits::default(),
            )
            .unwrap_err();
        assert!(matches!(err, PluginError::Verification(_)));
    }
}
