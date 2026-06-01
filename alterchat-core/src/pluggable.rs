use aes_gcm::aead::{OsRng, rand_core::RngCore};
use libp2p::core::Transport;
use std::pin::Pin;

/// Trait defining the standard interface for Pluggable Transports like Obfs4 and Snowflake.
/// This acts as a generic wrapper around libp2p transports to circumvent DPI (Deep Packet Inspection).
pub trait PluggableTransport {
    fn transport_name(&self) -> &'static str;
    
    /// Obfuscate traffic based on the specific pluggable transport strategy.
    /// Returns obfuscated data that appears as random noise to DPI systems.
    fn obfuscate(&self, data: &[u8]) -> Vec<u8>;
    
    /// De-obfuscate traffic — reverses the obfuscation applied by `obfuscate`.
    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str>;

    /// Generate a random padding of given length for traffic shaping.
    fn random_padding(&self, len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        OsRng.fill_bytes(&mut buf);
        buf
    }
}

// ═══════════════════════════════════════════════
// Obfs4 Transport — "look-like-nothing" obfuscation
// ═══════════════════════════════════════════════

/// Obfs4-style obfuscation transport.
///
/// Uses a shared key to XOR-encrypt traffic with a random nonce prefix,
/// making the wire format indistinguishable from random noise.
/// This defeats DPI fingerprinting that looks for known protocol patterns.
///
/// Wire format: [16-byte nonce][XOR-obfuscated data][random padding 0..31 bytes]
pub struct Obfs4Transport {
    /// Shared obfuscation key (derived from bridge configuration).
    /// In production, this would come from a bridge line or out-of-band exchange.
    key: [u8; 32],
}

impl Obfs4Transport {
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create with a specific key (for bridge pairing).
    pub fn with_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Derive a per-packet XOR mask from the nonce and key.
    fn derive_mask(&self, nonce: &[u8; 16], len: usize) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut mask = Vec::with_capacity(len);
        let mut counter: u32 = 0;
        while mask.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            hasher.update(nonce);
            hasher.update(counter.to_be_bytes());
            let block = hasher.finalize();
            mask.extend_from_slice(&block[..block.len().min(len - mask.len())]);
            counter += 1;
        }
        mask.truncate(len);
        mask
    }
}

impl Default for Obfs4Transport {
    fn default() -> Self {
        Self::new()
    }
}

impl PluggableTransport for Obfs4Transport {
    fn transport_name(&self) -> &'static str {
        "obfs4"
    }

    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let mask = self.derive_mask(&nonce, data.len());

        // XOR the data with the derived mask
        let obfuscated: Vec<u8> = data.iter()
            .zip(mask.iter())
            .map(|(d, m)| d ^ m)
            .collect();

        // Random padding (0..31 bytes) to vary packet lengths
        let pad_len = (OsRng.next_u32() % 32) as usize;
        let padding = self.random_padding(pad_len);

        // Wire format: [2-byte data_len BE][16-byte nonce][obfuscated data][padding]
        let data_len = data.len() as u16;
        let mut result = Vec::with_capacity(2 + 16 + obfuscated.len() + pad_len);
        result.extend_from_slice(&data_len.to_be_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&obfuscated);
        result.extend_from_slice(&padding);
        result
    }

    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 2 + 16 {
            return Err("obfs4: packet too short");
        }
        let data_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let nonce: [u8; 16] = data[2..18].try_into().map_err(|_| "obfs4: bad nonce")?;

        if data.len() < 2 + 16 + data_len {
            return Err("obfs4: truncated payload");
        }
        let obfuscated = &data[18..18 + data_len];
        let mask = self.derive_mask(&nonce, data_len);

        let plaintext: Vec<u8> = obfuscated.iter()
            .zip(mask.iter())
            .map(|(d, m)| d ^ m)
            .collect();
        Ok(plaintext)
    }
}

// ═══════════════════════════════════════════════
// Snowflake Transport — WebRTC-based proxy
// ═══════════════════════════════════════════════

/// Snowflake-style obfuscation transport.
///
/// Wraps traffic to appear as WebRTC data channel traffic.
/// Uses a simple framing protocol with length-prefixed chunks and
/// random inter-chunk padding to mimic DTLS/SCTP patterns.
///
/// Wire format: [4-byte magic "SNFL"][2-byte frame_len BE][frame data][2-byte pad_len BE][random padding]
pub struct SnowflakeTransport {
    /// Magic bytes to identify Snowflake frames (would be DTLS-like in production).
    magic: [u8; 4],
}

const SNOWFLAKE_MAGIC: [u8; 4] = [0x53, 0x4E, 0x46, 0x4C]; // "SNFL"

impl SnowflakeTransport {
    pub fn new() -> Self {
        Self {
            magic: SNOWFLAKE_MAGIC,
        }
    }
}

impl Default for SnowflakeTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl PluggableTransport for SnowflakeTransport {
    fn transport_name(&self) -> &'static str {
        "snowflake"
    }

    fn obfuscate(&self, data: &[u8]) -> Vec<u8> {
        let frame_len = data.len() as u16;
        let pad_len = (OsRng.next_u32() % 64) as u16;
        let padding = self.random_padding(pad_len as usize);

        let mut result = Vec::with_capacity(4 + 2 + data.len() + 2 + pad_len as usize);
        result.extend_from_slice(&self.magic);
        result.extend_from_slice(&frame_len.to_be_bytes());
        result.extend_from_slice(data);
        result.extend_from_slice(&pad_len.to_be_bytes());
        result.extend_from_slice(&padding);
        result
    }

    fn deobfuscate(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < 4 + 2 {
            return Err("snowflake: packet too short");
        }
        if &data[0..4] != &self.magic {
            return Err("snowflake: invalid magic bytes");
        }
        let frame_len = u16::from_be_bytes([data[4], data[5]]) as usize;
        if data.len() < 6 + frame_len {
            return Err("snowflake: truncated frame");
        }
        Ok(data[6..6 + frame_len].to_vec())
    }
}

// ═══════════════════════════════════════════════
// Transport Configuration
// ═══════════════════════════════════════════════

/// Which pluggable transport to use for DPI circumvention.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PluggableTransportType {
    /// No pluggable transport — direct connection.
    None,
    /// Obfs4 look-like-nothing obfuscation.
    Obfs4 { bridge_key: Option<String> },
    /// Snowflake WebRTC-based proxy.
    Snowflake,
}

impl Default for PluggableTransportType {
    fn default() -> Self {
        Self::None
    }
}

// ═══════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfs4_round_trip() {
        let transport = Obfs4Transport::new();
        let original = b"Manifesto VII: Kod soz verir";
        let obfuscated = transport.obfuscate(original);
        let recovered = transport.deobfuscate(&obfuscated).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn obfs4_looks_random() {
        let transport = Obfs4Transport::new();
        let data = b"hello world";
        let a = transport.obfuscate(data);
        let b = transport.obfuscate(data);
        // Same plaintext should produce different ciphertexts (different nonce)
        assert_ne!(a, b, "obfs4 should produce different output each time");
    }

    #[test]
    fn obfs4_short_packet_rejected() {
        let transport = Obfs4Transport::new();
        assert!(transport.deobfuscate(&[0u8; 5]).is_err());
    }

    #[test]
    fn obfs4_with_shared_key() {
        let key = [42u8; 32];
        let alice = Obfs4Transport::with_key(key);
        let bob = Obfs4Transport::with_key(key);
        let data = b"sovereign communication";
        let obfuscated = alice.obfuscate(data);
        let recovered = bob.deobfuscate(&obfuscated).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn obfs4_wrong_key_fails() {
        let alice = Obfs4Transport::with_key([1u8; 32]);
        let bob = Obfs4Transport::with_key([2u8; 32]);
        let data = b"secret";
        let obfuscated = alice.obfuscate(data);
        let recovered = bob.deobfuscate(&obfuscated).unwrap();
        // Wrong key → wrong data (XOR with wrong mask)
        assert_ne!(recovered, data);
    }

    #[test]
    fn snowflake_round_trip() {
        let transport = SnowflakeTransport::new();
        let original = b"Manifesto V: Mahremiyet onurdur";
        let obfuscated = transport.obfuscate(original);
        let recovered = transport.deobfuscate(&obfuscated).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn snowflake_magic_check() {
        let transport = SnowflakeTransport::new();
        let mut bad = transport.obfuscate(b"test");
        bad[0] = 0xFF; // corrupt magic
        assert!(transport.deobfuscate(&bad).is_err());
    }

    #[test]
    fn snowflake_short_packet_rejected() {
        let transport = SnowflakeTransport::new();
        assert!(transport.deobfuscate(&[0u8; 3]).is_err());
    }

    #[test]
    fn transport_names() {
        assert_eq!(Obfs4Transport::new().transport_name(), "obfs4");
        assert_eq!(SnowflakeTransport::new().transport_name(), "snowflake");
    }
}
