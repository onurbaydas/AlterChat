pub mod crdt;
pub mod crypto;
pub mod double_ratchet;
pub mod x3dh;
pub mod file_transfer;
pub mod governance;
pub mod identity;
pub mod network;
pub mod onion;
pub mod plugin;
pub mod pluggable;
pub mod pow;
pub mod sharding;
pub mod spam;
pub mod ffi; // For Phase 5
pub mod push; // For Phase 5

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true)
        .with_target(false)
        .try_init();
}

pub fn calculate_system_capacity() -> u32 {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_all();
    let memory_gb = sys.total_memory() / (1024 * 1024 * 1024);
    let cpu_cores = sys.cpus().len() as u64;
    
    // Score based on cores and memory (e.g. 8 cores + 16GB = 24 score)
    // Mobile phones will generally have lower score or can be forced to 0
    (memory_gb + cpu_cores) as u32
}
pub mod storage;
pub mod traffic;
pub use libp2p;
pub mod secure_storage;
