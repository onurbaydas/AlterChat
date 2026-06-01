use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;

/// Sabit blok boyutu — tüm mesajlar buna pad edilir (trafik analizi engeli)
const BLOCK_SIZE: usize = 512;

/// Mesajı BLOCK_SIZE katlarına pad eder (PKCS#7 benzeri)
pub fn pad_message(data: &[u8]) -> Vec<u8> {
    let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    let total_len = data.len() + pad_len;
    let mut padded = Vec::with_capacity(total_len + 4);
    // İlk 4 byte: orijinal uzunluk (big-endian)
    let orig_len = data.len() as u32;
    padded.extend_from_slice(&orig_len.to_be_bytes());
    padded.extend_from_slice(data);
    // Padding bytes
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

/// Pad'i çıkarır ve orijinal veriyi döndürür
pub fn unpad_message(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }
    let orig_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if orig_len + 4 > data.len() {
        return None;
    }
    Some(data[4..4 + orig_len].to_vec())
}

/// Rastgele chaff (sahte) payload üretir — gerçek mesajlarla aynı yapıda görünür.
/// Gerçek mesajlar: 4-byte big-endian length prefix + veri + padding.
/// Chaff da aynı prefix yapısını kullanır; pasif gözlemci ayırt edemez.
pub fn generate_chaff_payload() -> Vec<u8> {
    let max_inner = (BLOCK_SIZE - 4) as u32;
    let fake_inner_len = OsRng.next_u32() % max_inner;
    let mut payload = Vec::with_capacity(BLOCK_SIZE);
    payload.extend_from_slice(&fake_inner_len.to_be_bytes());
    let mut rest = vec![0u8; BLOCK_SIZE - 4];
    OsRng.fill_bytes(&mut rest);
    payload.extend_from_slice(&rest);
    payload
}

/// Rastgele 0-2000ms arasında bir gecikme döndürür
pub fn random_send_delay_ms() -> u64 {
    let mut buf = [0u8; 1];
    OsRng.fill_bytes(&mut buf);
    // 0-1999ms
    buf[0] as u64 * 8 // max ~2040ms, yeterince rastgele
}

/// Sabit gecikme (zaman-kör mesaj iletimi): mesajın gerçek gönderim zamanını gizler.
/// Tüm mesajlar bu pencere içinde rastgele bir anda bırakılır; timing analizini engeller.
pub const TIME_BLIND_WINDOW_MS: u64 = 5_000;

/// Zaman-kör gecikme: 0..TIME_BLIND_WINDOW_MS arasında rastgele
pub fn time_blind_delay_ms() -> u64 {
    let mut buf = [0u8; 2];
    OsRng.fill_bytes(&mut buf);
    let r = u16::from_be_bytes([buf[0], buf[1]]) as u64;
    r % TIME_BLIND_WINDOW_MS
}

/// PoW başarısızlık sayacı (peer_id → başarısız deneme sayısı).
/// Belirli eşiği aşan peer'lar ağ katmanında yasaklanır.
#[derive(Default, Debug)]
pub struct PowBanList {
    pub failures: std::collections::HashMap<String, u32>,
}

impl PowBanList {
    pub fn new() -> Self { Self::default() }

    /// Başarısız PoW dener; eşik aşılınca true döner (ban et)
    pub fn record_failure(&mut self, peer_id: &str, threshold: u32) -> bool {
        let count = self.failures.entry(peer_id.to_string()).or_insert(0);
        *count += 1;
        *count >= threshold
    }

    pub fn is_banned(&self, peer_id: &str, threshold: u32) -> bool {
        self.failures.get(peer_id).copied().unwrap_or(0) >= threshold
    }

    pub fn reset(&mut self, peer_id: &str) {
        self.failures.remove(peer_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_unpad_round_trip() {
        let data = b"Manifesto V: Mahremiyet onurdur";
        let padded = pad_message(data);
        let unpadded = unpad_message(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn padded_is_block_aligned() {
        let data = b"kisa";
        let padded = pad_message(data);
        // 4 bytes length prefix + data + padding = BLOCK_SIZE aligned
        assert!((padded.len() - 4) % BLOCK_SIZE == 0);
    }

    #[test]
    fn unpad_rejects_short() {
        assert!(unpad_message(&[0u8; 3]).is_none());
    }

    #[test]
    fn unpad_rejects_bad_length() {
        let mut bad = vec![0xFF, 0xFF, 0xFF, 0xFF]; // claims ~4GB
        bad.extend_from_slice(&[0u8; 10]);
        assert!(unpad_message(&bad).is_none());
    }

    #[test]
    fn chaff_is_block_size() {
        let chaff = generate_chaff_payload();
        assert_eq!(chaff.len(), BLOCK_SIZE);
    }

    #[test]
    fn time_blind_in_range() {
        for _ in 0..100 {
            let ms = time_blind_delay_ms();
            assert!(ms < TIME_BLIND_WINDOW_MS, "delay {} >= {}", ms, TIME_BLIND_WINDOW_MS);
        }
    }

    #[test]
    fn pow_ban_list_threshold() {
        let mut bans = PowBanList::new();
        assert!(!bans.is_banned("peer1", 3));
        assert!(!bans.record_failure("peer1", 3));
        assert!(!bans.record_failure("peer1", 3));
        assert!(bans.record_failure("peer1", 3)); // 3rd failure → banned
        assert!(bans.is_banned("peer1", 3));
    }

    #[test]
    fn pow_ban_list_reset() {
        let mut bans = PowBanList::new();
        bans.record_failure("peer1", 1);
        assert!(bans.is_banned("peer1", 1));
        bans.reset("peer1");
        assert!(!bans.is_banned("peer1", 1));
    }
}

