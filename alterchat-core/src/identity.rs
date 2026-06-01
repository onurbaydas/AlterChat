use libp2p::identity::Keypair;
use std::fs;
use std::path::Path;
use crate::secure_storage::{encrypt_file_data, decrypt_file_data};

/// Loads an existing keypair from a file or generates a new one.
pub fn load_or_generate_keypair<P: AsRef<Path>>(
    path: P,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    let path_ref = path.as_ref();
    if path_ref.to_string_lossy() == ":memory:" {
        return Ok(Keypair::generate_ed25519());
    }
    if path_ref.exists() {
        let bytes = fs::read(path_ref)?;
        // We use ed25519 as our standard keypair format for high security and performance
        let keypair = Keypair::from_protobuf_encoding(&bytes)
            .map_err(|e| format!("Failed to parse keypair: {}", e))?;
        Ok(keypair)
    } else {
        let keypair = Keypair::generate_ed25519();
        fs::write(
            path_ref,
            keypair
                .to_protobuf_encoding()
                .map_err(|e| format!("Failed to encode keypair: {:?}", e))?,
        )?;
        Ok(keypair)
    }
}

pub fn load_or_generate_encrypted_keypair<P: AsRef<Path>>(
    path: P,
    password: &str,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    let path_ref = path.as_ref();
    if path_ref.to_string_lossy() == ":memory:" {
        return Ok(Keypair::generate_ed25519());
    }
    if path_ref.exists() {
        let bytes = fs::read(path_ref)?;
        
        let decrypted = decrypt_file_data(password, &bytes)
            .map_err(|e| format!("Key decryption failed: {}", e))?;
            
        let keypair = Keypair::from_protobuf_encoding(&decrypted)
            .map_err(|e| format!("Failed to parse keypair: {}", e))?;
        Ok(keypair)
    } else {
        let keypair = Keypair::generate_ed25519();
        let encoded = keypair
            .to_protobuf_encoding()
            .map_err(|e| format!("Failed to encode keypair: {:?}", e))?;
            
        let encrypted = encrypt_file_data(password, &encoded);
        fs::write(path_ref, encrypted)?;
        Ok(keypair)
    }
}
