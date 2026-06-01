use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, rand_core::RngCore},
};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedPayload {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Encrypts data for a specific recipient using their X25519 public key.
pub fn encrypt_for_peer(
    recipient_pubkey_bytes: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedPayload, &'static str> {
    let recipient_pubkey = X25519PublicKey::from(*recipient_pubkey_bytes);

    // Generate an ephemeral X25519 keypair for Alice
    let ephemeral_secret = EphemeralSecret::random_from_rng(&mut OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);

    // Perform Diffie-Hellman to get the shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pubkey);

    // Use shared secret as AES-256-GCM key
    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    // Generate random 96-bit nonce
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    Ok(EncryptedPayload {
        ephemeral_pubkey: *ephemeral_pubkey.as_bytes(),
        nonce: nonce.into(),
        ciphertext,
    })
}

/// Decrypts data using our own static X25519 secret key.
pub fn decrypt_for_me(
    my_secret_bytes: &[u8; 32],
    payload: &EncryptedPayload,
) -> Result<Vec<u8>, &'static str> {
    let my_secret = StaticSecret::from(*my_secret_bytes);
    let sender_ephemeral_pubkey = X25519PublicKey::from(payload.ephemeral_pubkey);

    // Perform Diffie-Hellman to recover the shared secret
    let shared_secret = my_secret.diffie_hellman(&sender_ephemeral_pubkey);

    // Use shared secret as AES-256-GCM key
    let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::from_slice(&payload.nonce);

    let plaintext = cipher
        .decrypt(nonce, payload.ciphertext.as_ref())
        .map_err(|_| "Decryption failed")?;
    Ok(plaintext)
}

pub fn generate_static_secret() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn get_public_key(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_bytes);
    let pubkey = X25519PublicKey::from(&secret);
    *pubkey.as_bytes()
}

use libp2p::kad::RecordKey;
use sha2::{Digest, Sha256};

pub fn get_dht_mailbox_key(peer_id_str: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(peer_id_str.as_bytes());
    hasher.update(b"_offline_inbox");
    let result = hasher.finalize();
    RecordKey::new(&result.as_slice())
}

pub fn get_dht_pubkey_key(peer_id_str: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(peer_id_str.as_bytes());
    hasher.update(b"_offline_pubkey");
    let result = hasher.finalize();
    RecordKey::new(&result.as_slice())
}

/// X3DH PreKeyBundle DHT anahtarı: `pkb:{peer_id}` hash'i
pub fn get_dht_prekey_bundle_key(peer_id_str: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(peer_id_str.as_bytes());
    hasher.update(b"_x3dh_prekey_bundle");
    let result = hasher.finalize();
    RecordKey::new(&result.as_slice())
}

/// Revokasyon listesi DHT anahtarı: toplulukça bilinen iptal edilmiş davetiyeler
pub fn get_dht_revocation_key(room_id: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(room_id.as_bytes());
    hasher.update(b"_revocation_list");
    let result = hasher.finalize();
    RecordKey::new(&result.as_slice())
}

/// Safety Number: iki peer'ın pubkey'lerinden 60-karakterlik güvenlik numarası türetir.
/// Signal benzeri: her iki tarafta aynı sayı görünür; insan doğrulaması için.
pub fn derive_safety_number(my_pubkey: &[u8; 32], peer_pubkey: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    // Sıra bağımsız: her iki taraf aynı sonucu üretir
    let (first, second) = if my_pubkey < peer_pubkey {
        (my_pubkey, peer_pubkey)
    } else {
        (peer_pubkey, my_pubkey)
    };
    hasher.update(first);
    hasher.update(second);
    hasher.update(b"AlterChat_SafetyNumber_v1");
    let hash = hasher.finalize();
    // 60 haneli güvenlik numarası (5 x 12 haneli blok)
    let nums: Vec<u8> = hash.iter().take(30).copied().collect();
    nums.chunks(6)
        .map(|chunk| {
            let n: u64 = chunk.iter().fold(0u64, |acc, &b| acc * 256 + b as u64) % 1_000_000_000_000;
            format!("{:012}", n)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// === SEALED SENDER ===
/// Gönderenin kimliği, mesajın içine şifreli olarak gömülür.
/// Ağ katmanında gönderen görünmez. Alıcı bile açana kadar kim gönderdi bilemez.

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SealedMessage {
    /// Alıcı anahtarıyla şifreli dış katman (sealed envelope)
    pub outer: EncryptedPayload,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct SealedInner {
    /// Gönderenin X25519 public key'i (kimlik kanıtı için)
    pub sender_pubkey: [u8; 32],
    /// Gönderenin libp2p PeerId stringi
    pub sender_peer_id: String,
    /// Gerçek mesaj verisi
    pub payload: Vec<u8>,
}

/// Mesajı mühürlü zarf olarak gönderir. Gönderen kimliği içine gömülüdür.
pub fn sealed_send(
    my_secret: &[u8; 32],
    my_peer_id: String,
    recipient_pubkey: &[u8; 32],
    plaintext: &[u8],
) -> Result<SealedMessage, &'static str> {
    let my_static = StaticSecret::from(*my_secret);
    let my_pubkey = X25519PublicKey::from(&my_static);

    let inner = SealedInner {
        sender_pubkey: *my_pubkey.as_bytes(),
        sender_peer_id: my_peer_id,
        payload: plaintext.to_vec(),
    };
    let inner_bytes = bincode::serialize(&inner).map_err(|_| "Serialize error")?;

    // Dış katman: alıcı anahtarıyla şifrele
    let outer = encrypt_for_peer(recipient_pubkey, &inner_bytes)?;

    Ok(SealedMessage { outer })
}

/// Mühürlü zarfı açar. Hem mesajı hem gönderen pubkey'i döndürür.
pub fn sealed_receive(
    my_secret: &[u8; 32],
    msg: &SealedMessage,
) -> Result<([u8; 32], String, Vec<u8>), &'static str> {
    let inner_bytes = decrypt_for_me(my_secret, &msg.outer)?;
    let inner: SealedInner = bincode::deserialize(&inner_bytes).map_err(|_| "Deserialize error")?;
    Ok((inner.sender_pubkey, inner.sender_peer_id.clone(), inner.payload.clone()))
}

pub fn load_or_generate_encrypted_x25519_secret(path: &str, password: &str) -> [u8; 32] {
    if let Ok(bytes) = std::fs::read(path) {
        if let Ok(decrypted) = crate::secure_storage::decrypt_file_data(password, &bytes) {
            if decrypted.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decrypted);
                return arr;
            }
        }
    }
    let secret = generate_static_secret();
    let encrypted = crate::secure_storage::encrypt_file_data(password, &secret);
    let _ = std::fs::write(path, encrypted);
    secret
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    pub root_key: [u8; 32],
    pub send_chain_key: [u8; 32],
    pub recv_chain_key: [u8; 32],
    pub send_count: u64,
    pub recv_count: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RatchetEnvelope {
    pub counter: u64,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl RatchetState {
    pub fn from_shared_secret(shared_secret: [u8; 32]) -> Self {
        Self {
            root_key: derive_key(&shared_secret, b"root"),
            send_chain_key: derive_key(&shared_secret, b"send"),
            recv_chain_key: derive_key(&shared_secret, b"recv"),
            send_count: 0,
            recv_count: 0,
        }
    }

    pub fn for_peer_pair(shared_secret: [u8; 32], local_id: &str, remote_id: &str) -> Self {
        let root_key = derive_key(&shared_secret, b"root");
        let low_to_high = derive_key(&shared_secret, b"low_to_high");
        let high_to_low = derive_key(&shared_secret, b"high_to_low");
        let (send_chain_key, recv_chain_key) = if local_id <= remote_id {
            (low_to_high, high_to_low)
        } else {
            (high_to_low, low_to_high)
        };
        Self {
            root_key,
            send_chain_key,
            recv_chain_key,
            send_count: 0,
            recv_count: 0,
        }
    }
}

pub fn derive_static_shared_secret(
    my_secret_bytes: &[u8; 32],
    peer_pubkey_bytes: &[u8; 32],
) -> [u8; 32] {
    let my_secret = StaticSecret::from(*my_secret_bytes);
    let peer_pubkey = X25519PublicKey::from(*peer_pubkey_bytes);
    let shared = my_secret.diffie_hellman(&peer_pubkey);
    *shared.as_bytes()
}

fn derive_key(input: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.update(label);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn advance_chain(chain_key: &[u8; 32]) -> [u8; 32] {
    derive_key(chain_key, b"next")
}

pub fn ratchet_encrypt(
    state: &mut RatchetState,
    plaintext: &[u8],
) -> Result<RatchetEnvelope, &'static str> {
    let message_key = derive_key(&state.send_chain_key, &state.send_count.to_be_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&message_key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| "Ratchet encryption failed")?;
    let envelope = RatchetEnvelope {
        counter: state.send_count,
        nonce: nonce.into(),
        ciphertext,
    };
    state.send_chain_key = advance_chain(&state.send_chain_key);
    state.send_count += 1;
    Ok(envelope)
}

pub fn ratchet_decrypt(
    state: &mut RatchetState,
    envelope: &RatchetEnvelope,
) -> Result<Vec<u8>, &'static str> {
    while state.recv_count < envelope.counter {
        state.recv_chain_key = advance_chain(&state.recv_chain_key);
        state.recv_count += 1;
    }
    let message_key = derive_key(&state.recv_chain_key, &envelope.counter.to_be_bytes());
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&message_key));
    let nonce = Nonce::from_slice(&envelope.nonce);
    let plaintext = cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|_| "Ratchet decryption failed")?;
    state.recv_chain_key = advance_chain(&state.recv_chain_key);
    state.recv_count = envelope.counter + 1;
    Ok(plaintext)
}
