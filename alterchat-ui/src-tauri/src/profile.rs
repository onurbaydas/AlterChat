//! Profile discovery and key derivation.
//!
//! Layout (under the Tauri app-data directory):
//!
//! ```text
//! profiles/<random-profile-id>/
//!     keypair.bin   libp2p identity, Argon2id + AES-256-GCM (password)
//!     db.salt       16 random bytes, salt for the SQLCipher key
//!     profile.db    SQLCipher database (raw 256-bit key, Argon2id(password, db.salt))
//!     storage/      encrypted file chunks
//! ```
//!
//! Profile ids are random, so nothing on disk is derived from the password.
//! A password is matched to its profile by attempting to decrypt each
//! profile's `keypair.bin` (AES-GCM authentication makes this a reliable check).

use alterchat_core::libp2p::identity::Keypair;
use alterchat_core::secure_storage::{decrypt_file_data, derive_key, encrypt_file_data};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const KEYPAIR_FILE: &str = "keypair.bin";
const DB_SALT_FILE: &str = "db.salt";
const DB_FILE: &str = "profile.db";
const AMNESIC_PREFIX: &str = "alterchat-amnesic-";

pub struct ResolvedProfile {
    pub dir: PathBuf,
    pub db_path: String,
    /// SQLCipher raw-key literal: `x'<64 hex chars>'`
    pub db_key: String,
    pub keypair: Keypair,
    pub amnesic: bool,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| format!("OS RNG failure: {e}"))?;
    Ok(buf)
}

fn sqlcipher_key(password: &str, salt: &[u8]) -> String {
    let mut raw = derive_key(password, salt);
    let literal = format!("x'{}'", hex::encode(raw));
    raw.zeroize();
    literal
}

fn profile_from_dir(
    dir: &Path,
    password: &str,
    keypair: Keypair,
) -> Result<ResolvedProfile, String> {
    let salt =
        std::fs::read(dir.join(DB_SALT_FILE)).map_err(|e| format!("Missing db salt: {e}"))?;
    Ok(ResolvedProfile {
        dir: dir.to_path_buf(),
        db_path: dir.join(DB_FILE).to_string_lossy().into_owned(),
        db_key: sqlcipher_key(password, &salt),
        keypair,
        amnesic: false,
    })
}

/// Try to unlock an existing profile with `password`.
fn find_profile(root: &Path, password: &str) -> Result<Option<ResolvedProfile>, String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Ok(None);
    };
    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(blob) = std::fs::read(dir.join(KEYPAIR_FILE)) else {
            continue;
        };
        if let Ok(mut plain) = decrypt_file_data(password, &blob) {
            let keypair = Keypair::from_protobuf_encoding(&plain);
            plain.zeroize();
            let keypair = keypair.map_err(|e| format!("Corrupted keypair: {e}"))?;
            return profile_from_dir(&dir, password, keypair).map(Some);
        }
    }
    Ok(None)
}

fn create_profile(root: &Path, password: &str) -> Result<ResolvedProfile, String> {
    let id = hex::encode(random_bytes::<16>()?);
    let dir = root.join(id);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Cannot create profile dir: {e}"))?;

    let keypair = Keypair::generate_ed25519();
    let mut encoded = keypair.to_protobuf_encoding().map_err(|e| e.to_string())?;
    let blob = encrypt_file_data(password, &encoded);
    encoded.zeroize();
    std::fs::write(dir.join(KEYPAIR_FILE), blob).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(DB_SALT_FILE), random_bytes::<16>()?).map_err(|e| e.to_string())?;
    profile_from_dir(&dir, password, keypair)
}

/// Amnesic sessions live in a temp directory with a random key that is never
/// written to disk. The directory is removed on exit and on the next start.
fn create_amnesic() -> Result<ResolvedProfile, String> {
    let dir = std::env::temp_dir().join(format!(
        "{AMNESIC_PREFIX}{}",
        hex::encode(random_bytes::<8>()?)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut raw = random_bytes::<32>()?;
    let db_key = format!("x'{}'", hex::encode(raw));
    raw.zeroize();
    Ok(ResolvedProfile {
        db_path: dir.join(DB_FILE).to_string_lossy().into_owned(),
        dir,
        db_key,
        keypair: Keypair::generate_ed25519(),
        amnesic: true,
    })
}

/// Remove leftovers of amnesic sessions (e.g. after a crash).
pub fn cleanup_amnesic_dirs() {
    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with(AMNESIC_PREFIX)
            {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
}

/// Resolve the profile for a login attempt.
///
/// - `amnesic`: always a fresh throwaway profile.
/// - `create == true`: open the matching profile if one exists, otherwise create one.
/// - `create == false`: open the matching profile or fail (never silently creates).
pub fn resolve(
    root: &Path,
    password: &str,
    create: bool,
    amnesic: bool,
) -> Result<ResolvedProfile, String> {
    if amnesic {
        return create_amnesic();
    }
    if password.chars().count() < 8 {
        return Err("Password must be at least 8 characters".to_string());
    }
    std::fs::create_dir_all(root).map_err(|e| format!("Cannot create data dir: {e}"))?;
    match find_profile(root, password)? {
        Some(p) => Ok(p),
        None if create => create_profile(root, password),
        None => Err("No profile matches this password".to_string()),
    }
}

/// Storage directory for encrypted file chunks of a profile.
pub fn storage_root(db_path: &str) -> PathBuf {
    Path::new(db_path)
        .parent()
        .map(|p| p.join("storage"))
        .unwrap_or_else(|| PathBuf::from("alterchat_storage"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "alterchat-test-{tag}-{}",
            hex::encode(random_bytes::<4>().unwrap())
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn create_then_open_same_profile() {
        let root = tmp_root("open");
        let a = resolve(&root, "correct horse", true, false).unwrap();
        let b = resolve(&root, "correct horse", false, false).unwrap();
        assert_eq!(a.dir, b.dir);
        assert_eq!(a.db_key, b.db_key);
        assert_eq!(a.keypair.public(), b.keypair.public());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn wrong_password_does_not_create() {
        let root = tmp_root("wrong");
        resolve(&root, "correct horse", true, false).unwrap();
        assert!(resolve(&root, "wrong password", false, false).is_err());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn profile_dir_name_is_not_password_derived() {
        let r1 = tmp_root("r1");
        let r2 = tmp_root("r2");
        let a = resolve(&r1, "same password", true, false).unwrap();
        let b = resolve(&r2, "same password", true, false).unwrap();
        assert_ne!(a.dir.file_name(), b.dir.file_name());
        assert_ne!(a.db_key, b.db_key, "per-profile salt must differ");
        let _ = std::fs::remove_dir_all(r1);
        let _ = std::fs::remove_dir_all(r2);
    }
}
