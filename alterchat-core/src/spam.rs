use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowChallenge {
    pub challenge_id: String,
    pub difficulty_bits: u8,
    pub nonce: Vec<u8>,
}

pub fn verify_pow(challenge: &PowChallenge, solution: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(challenge.challenge_id.as_bytes());
    hasher.update(&challenge.nonce);
    hasher.update(solution);
    has_leading_zero_bits(&hasher.finalize(), challenge.difficulty_bits)
}

pub fn solve_pow(challenge: &PowChallenge, max_iters: u64) -> Option<Vec<u8>> {
    for counter in 0..max_iters {
        let solution = counter.to_be_bytes().to_vec();
        if verify_pow(challenge, &solution) {
            return Some(solution);
        }
    }
    None
}

fn has_leading_zero_bits(bytes: &[u8], bits: u8) -> bool {
    let full_bytes = (bits / 8) as usize;
    let rem_bits = bits % 8;
    if bytes.iter().take(full_bytes).any(|b| *b != 0) {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xff << (8 - rem_bits);
    bytes
        .get(full_bytes)
        .map(|b| (*b & mask) == 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leading_zero_bits() {
        assert!(has_leading_zero_bits(&[0x00, 0x00], 16));
        assert!(has_leading_zero_bits(&[0x0F, 0x00], 4)); // 0000 1111
        assert!(!has_leading_zero_bits(&[0x80, 0x00], 1)); // 1000 0000
    }

    #[test]
    fn test_pow_verify_and_solve() {
        let challenge = PowChallenge {
            challenge_id: "test_msg_1".to_string(),
            difficulty_bits: 8, // kolay seviye
            nonce: vec![1, 2, 3, 4],
        };

        let solution = solve_pow(&challenge, 1_000_000).expect("Should solve PoW");
        assert!(verify_pow(&challenge, &solution));

        // Yanlış çözüm
        assert!(!verify_pow(&challenge, &[0xFF, 0xFF, 0xFF, 0xFF]));
    }
}

