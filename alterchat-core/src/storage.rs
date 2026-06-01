use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_CHUNK_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunkMeta {
    pub index: u64,
    pub hash: String,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileManifest {
    pub transfer_id: String,
    pub filename: String,
    pub total_size: usize,
    pub mime: Option<String>,
    pub content_hash: String,
    pub chunks: Vec<FileChunkMeta>,
    pub encrypted_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedChunk {
    pub index: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub plaintext_hash: String,
}

pub fn content_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_string(&hasher.finalize())
}

pub fn generate_file_key() -> [u8; 32] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn split_chunks(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    data.chunks(chunk_size.max(1)).collect()
}

pub fn encrypt_chunk(
    index: u64,
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedChunk, &'static str> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "chunk encryption failed")?;
    Ok(EncryptedChunk {
        index,
        nonce: nonce.into(),
        ciphertext,
        plaintext_hash: content_hash(plaintext),
    })
}

pub fn decrypt_chunk(key: &[u8; 32], chunk: &EncryptedChunk) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&chunk.nonce);
    let plaintext = cipher
        .decrypt(nonce, chunk.ciphertext.as_ref())
        .map_err(|_| "chunk decryption failed")?;
    if content_hash(&plaintext) != chunk.plaintext_hash {
        return Err("chunk hash mismatch");
    }
    Ok(plaintext)
}

pub fn build_manifest(
    filename: String,
    mime: Option<String>,
    data: &[u8],
    chunk_size: usize,
) -> FileManifest {
    let chunks = split_chunks(data, chunk_size)
        .into_iter()
        .enumerate()
        .map(|(index, chunk)| FileChunkMeta {
            index: index as u64,
            hash: content_hash(chunk),
            size: chunk.len(),
        })
        .collect::<Vec<_>>();
    let content_hash = content_hash(data);
    FileManifest {
        transfer_id: content_hash.clone(),
        filename,
        total_size: data.len(),
        mime,
        content_hash,
        chunks,
        encrypted_key: None,
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_encryption_detects_hash_mismatch() {
        let key = generate_file_key();
        let mut chunk = encrypt_chunk(0, &key, b"sovereign bytes").unwrap();
        assert_eq!(decrypt_chunk(&key, &chunk).unwrap(), b"sovereign bytes");
        chunk.plaintext_hash = content_hash(b"different");
        assert!(decrypt_chunk(&key, &chunk).is_err());
    }

    #[test]
    fn manifest_is_content_addressed() {
        let manifest = build_manifest(
            "a.txt".to_string(),
            Some("text/plain".to_string()),
            b"abc",
            2,
        );
        assert_eq!(manifest.total_size, 3);
        assert_eq!(manifest.chunks.len(), 2);
        assert_eq!(manifest.content_hash, content_hash(b"abc"));
    }
}
