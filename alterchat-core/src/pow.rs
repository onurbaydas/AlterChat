use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PoWToken {
    pub resource: String,
    pub timestamp: u64,
    pub nonce: u64,
}

impl PoWToken {
    /// Mint a new Proof of Work token for a given resource.
    /// `difficulty` is the number of leading zero bits required in the hash.
    pub fn mint(resource: &str, difficulty: u32) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonce = 0u64;
        let resource_bytes = resource.as_bytes();

        loop {
            let mut hasher = Sha256::new();
            hasher.update(resource_bytes);
            hasher.update(timestamp.to_le_bytes());
            hasher.update(nonce.to_le_bytes());
            let hash = hasher.finalize();

            if check_difficulty(&hash, difficulty) {
                return Self {
                    resource: resource.to_string(),
                    timestamp,
                    nonce,
                };
            }
            nonce += 1;
        }
    }

    /// Verify the token.
    /// Returns true if the hash meets the difficulty and the timestamp is within the validity window.
    pub fn verify(&self, expected_resource: &str, difficulty: u32, max_age_seconds: u64) -> bool {
        if self.resource != expected_resource {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if token is too old or from the future
        if now < self.timestamp || now - self.timestamp > max_age_seconds {
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(self.resource.as_bytes());
        hasher.update(self.timestamp.to_le_bytes());
        hasher.update(self.nonce.to_le_bytes());
        let hash = hasher.finalize();

        check_difficulty(&hash, difficulty)
    }
}

/// Checks if the first `difficulty` bits of the hash are zero.
fn check_difficulty(hash: &[u8], difficulty: u32) -> bool {
    let mut bits_checked = 0;
    for &byte in hash.iter() {
        if bits_checked >= difficulty {
            return true;
        }
        let remaining_bits = difficulty - bits_checked;
        if remaining_bits >= 8 {
            if byte != 0 {
                return false;
            }
            bits_checked += 8;
        } else {
            let mask = 0xFF << (8 - remaining_bits);
            return (byte & mask) == 0;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_mint_and_verify() {
        let resource = "test_room";
        let difficulty = 12; // Small difficulty for fast test execution
        
        let token = PoWToken::mint(resource, difficulty);
        
        assert!(token.verify(resource, difficulty, 60));
        assert!(!token.verify("wrong_room", difficulty, 60)); // Wrong resource
        assert!(!token.verify(resource, difficulty + 8, 60)); // Higher difficulty should fail
    }
}
