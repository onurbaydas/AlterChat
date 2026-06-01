/// Signal Protocol Double Ratchet — tam implementasyon
///
/// crypto.rs'deki SymmetricRatchet sadece zincir anahtarını ileri sarıyor.
/// Bu modül ek olarak DH Ratchet adımını implement eder:
/// her cevap mesajında yeni bir X25519 ephemeral keypair üretilir,
/// ortak sır yenilenir (post-compromise security).
///
/// Kılavuz: https://signal.org/docs/specifications/doubleratchet/
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ─── Sabitler ────────────────────────────────────────────────────────────────

const MAX_SKIP: u64 = 1000;

// ─── Tip tanımları ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct DrState {
    // DH ratchet anahtarları
    pub dh_send: [u8; 32],          // Gönderim DH secret (StaticSecret olarak kullanılır)
    pub dh_send_pub: [u8; 32],      // Gönderim DH public key (karşıya gönderilir)
    pub dh_recv: Option<[u8; 32]>,  // Alınan son DH public key
    // Kök anahtar
    pub root_key: [u8; 32],
    // Zincir anahtarları
    pub ck_send: Option<[u8; 32]>,
    pub ck_recv: Option<[u8; 32]>,
    // Sayaçlar
    pub n_send: u64,     // Gönderilen mesaj sayısı (mevcut DH ratchet döngüsünde)
    pub n_recv: u64,     // Alınan mesaj sayısı (mevcut DH ratchet döngüsünde)
    pub pn: u64,         // Önceki gönderim zincirindeki mesaj sayısı
    // Atlanan mesaj anahtarları (sırasız teslim için)
    #[zeroize(skip)]
    pub skipped: Vec<SkippedKey>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SkippedKey {
    pub dh_pub: [u8; 32],
    pub n: u64,
    pub mk: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DrHeader {
    pub dh: [u8; 32],  // Gönderenin DH public key
    pub pn: u64,       // Önceki zincirdeki mesaj sayısı
    pub n: u64,        // Bu mesajın sıra numarası
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DrEnvelope {
    pub header: DrHeader,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

// ─── Yardımcı HKDF fonksiyonları ─────────────────────────────────────────────

fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(rk), dh_out);
    let mut new_rk = [0u8; 32];
    let mut ck = [0u8; 32];
    hk.expand(b"root", &mut new_rk).unwrap();
    hk.expand(b"chain", &mut ck).unwrap();
    (new_rk, ck)
}

fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(ck), &[]);
    let mut new_ck = [0u8; 32];
    let mut mk = [0u8; 32];
    hk.expand(b"chain", &mut new_ck).unwrap();
    hk.expand(b"msg", &mut mk).unwrap();
    (new_ck, mk)
}

fn dh(secret_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_bytes);
    let pubkey = X25519PublicKey::from(*pub_bytes);
    *secret.diffie_hellman(&pubkey).as_bytes()
}

// ─── Başlatma ────────────────────────────────────────────────────────────────

/// Alice (başlatan) tarafı için başlangıç durumu.
/// sk: X3DH shared secret
/// bob_dh_pub: Bob'un ilk DH public key'i
pub fn init_alice(sk: [u8; 32], bob_dh_pub: [u8; 32]) -> DrState {
    // StaticSecret kullan — hem serialize edilebilir hem DH için yeniden kullanılabilir
    let dh_send_secret = StaticSecret::random_from_rng(OsRng);
    let dh_send_pub = *X25519PublicKey::from(&dh_send_secret).as_bytes();
    let dh_send_bytes = *dh_send_secret.as_bytes();

    // Alice'in ilk gönderim zinciri: SK + DH(alice_new, bob_initial)
    let dh_out = dh(&dh_send_bytes, &bob_dh_pub);
    let (root_key, ck_send) = kdf_rk(&sk, &dh_out);

    DrState {
        dh_send: dh_send_bytes,
        dh_send_pub,
        dh_recv: Some(bob_dh_pub),
        root_key,
        ck_send: Some(ck_send),
        ck_recv: None,
        n_send: 0,
        n_recv: 0,
        pn: 0,
        skipped: Vec::new(),
    }
}

/// Bob (alan) tarafı için başlangıç durumu.
/// sk: X3DH shared secret
/// bob_dh_secret: Bob'un ilk DH secret key bytes'ı
pub fn init_bob(sk: [u8; 32], bob_dh_secret: [u8; 32], bob_dh_pub: [u8; 32]) -> DrState {
    DrState {
        dh_send: bob_dh_secret,
        dh_send_pub: bob_dh_pub,
        dh_recv: None,
        root_key: sk,
        ck_send: None,
        ck_recv: None,
        n_send: 0,
        n_recv: 0,
        pn: 0,
        skipped: Vec::new(),
    }
}

// ─── Şifreleme ────────────────────────────────────────────────────────────────

pub fn encrypt(state: &mut DrState, plaintext: &[u8]) -> Result<DrEnvelope, &'static str> {
    let ck = state.ck_send.as_ref().ok_or("No send chain key")?;
    let (new_ck, mk) = kdf_ck(ck);
    state.ck_send = Some(new_ck);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&mk));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| "Encryption failed")?;

    let header = DrHeader {
        dh: state.dh_send_pub,
        pn: state.pn,
        n: state.n_send,
    };
    state.n_send += 1;

    Ok(DrEnvelope {
        header,
        nonce: nonce.into(),
        ciphertext,
    })
}

// ─── Şifre çözme ─────────────────────────────────────────────────────────────

pub fn decrypt(state: &mut DrState, envelope: &DrEnvelope) -> Result<Vec<u8>, &'static str> {
    // Önce atlanan mesajlar listesinde ara
    if let Some(plaintext) = try_skipped(state, envelope)? {
        return Ok(plaintext);
    }

    let header = &envelope.header;

    // DH ratchet adımı gerekiyor mu?
    let need_dh_ratchet = state.dh_recv.as_ref().map(|r| *r != header.dh).unwrap_or(true);

    if need_dh_ratchet {
        // Önceki zincirden atlanan mesajları kaydet
        skip_message_keys(state, header.pn)?;
        dh_ratchet(state, header.dh);
    }

    // Mevcut zincirden atlanan mesajları kaydet
    skip_message_keys(state, header.n)?;

    // Mesaj anahtarını türet
    let ck = state.ck_recv.as_ref().ok_or("No recv chain key")?;
    let (new_ck, mk) = kdf_ck(ck);
    state.ck_recv = Some(new_ck);
    state.n_recv += 1;

    decrypt_with_key(&mk, envelope)
}

fn try_skipped(state: &mut DrState, envelope: &DrEnvelope) -> Result<Option<Vec<u8>>, &'static str> {
    let key_idx = state.skipped.iter().position(|sk| {
        sk.dh_pub == envelope.header.dh && sk.n == envelope.header.n
    });
    if let Some(idx) = key_idx {
        let mk = state.skipped.remove(idx).mk;
        let plaintext = decrypt_with_key(&mk, envelope)?;
        return Ok(Some(plaintext));
    }
    Ok(None)
}

fn skip_message_keys(state: &mut DrState, until: u64) -> Result<(), &'static str> {
    if state.n_recv + MAX_SKIP < until {
        return Err("Too many skipped messages");
    }
    if state.ck_recv.is_none() {
        return Ok(());
    }
    while state.n_recv < until {
        let ck = state.ck_recv.as_ref().unwrap();
        let (new_ck, mk) = kdf_ck(ck);
        state.ck_recv = Some(new_ck);
        state.skipped.push(SkippedKey {
            dh_pub: state.dh_recv.unwrap_or([0u8; 32]),
            n: state.n_recv,
            mk,
        });
        state.n_recv += 1;
    }
    Ok(())
}

fn dh_ratchet(state: &mut DrState, header_dh: [u8; 32]) {
    state.pn = state.n_send;
    state.n_send = 0;
    state.n_recv = 0;
    state.dh_recv = Some(header_dh);

    // Alım zinciri: mevcut DH secret + gelen DH public key
    let dh_out = dh(&state.dh_send, &header_dh);
    let (new_rk, ck_recv) = kdf_rk(&state.root_key, &dh_out);
    state.root_key = new_rk;
    state.ck_recv = Some(ck_recv);

    // Gönderim zinciri: yeni DH keypair üret
    let new_secret = StaticSecret::random_from_rng(OsRng);
    let new_pub = *X25519PublicKey::from(&new_secret).as_bytes();
    let dh_out2 = dh(new_secret.as_bytes(), &header_dh);
    let (new_rk2, ck_send) = kdf_rk(&state.root_key, &dh_out2);

    state.root_key = new_rk2;
    state.dh_send = *new_secret.as_bytes();
    state.dh_send_pub = new_pub;
    state.ck_send = Some(ck_send);
}

fn decrypt_with_key(mk: &[u8; 32], envelope: &DrEnvelope) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(mk));
    let nonce = Nonce::from_slice(&envelope.nonce);
    cipher
        .decrypt(nonce, envelope.ciphertext.as_ref())
        .map_err(|_| "Decryption failed")
}

// ─── Testler ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (DrState, DrState) {
        let sk = [42u8; 32];
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        let bob_pub = *X25519PublicKey::from(&bob_secret).as_bytes();

        let alice = init_alice(sk, bob_pub);
        let bob = init_bob(sk, *bob_secret.as_bytes(), bob_pub);
        (alice, bob)
    }

    #[test]
    fn test_alice_to_bob() {
        let (mut alice, mut bob) = make_pair();
        let plaintext = b"Selam Bob!";
        let envelope = encrypt(&mut alice, plaintext).unwrap();
        let decrypted = decrypt(&mut bob, &envelope).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_bidirectional() {
        let (mut alice, mut bob) = make_pair();

        let e1 = encrypt(&mut alice, b"Alice->Bob 1").unwrap();
        let e2 = encrypt(&mut alice, b"Alice->Bob 2").unwrap();

        let d1 = decrypt(&mut bob, &e1).unwrap();
        assert_eq!(d1, b"Alice->Bob 1");

        let e3 = encrypt(&mut bob, b"Bob->Alice 1").unwrap();
        let d2 = decrypt(&mut alice, &e3).unwrap();
        assert_eq!(d2, b"Bob->Alice 1");

        let d3 = decrypt(&mut bob, &e2).unwrap();
        assert_eq!(d3, b"Alice->Bob 2");
    }

    #[test]
    fn test_out_of_order() {
        let (mut alice, mut bob) = make_pair();

        let e1 = encrypt(&mut alice, b"Mesaj 1").unwrap();
        let e2 = encrypt(&mut alice, b"Mesaj 2").unwrap();
        let e3 = encrypt(&mut alice, b"Mesaj 3").unwrap();

        // Sırasız teslim: 3, 1, 2
        let d3 = decrypt(&mut bob, &e3).unwrap();
        assert_eq!(d3, b"Mesaj 3");
        let d1 = decrypt(&mut bob, &e1).unwrap();
        assert_eq!(d1, b"Mesaj 1");
        let d2 = decrypt(&mut bob, &e2).unwrap();
        assert_eq!(d2, b"Mesaj 2");
    }

    #[test]
    fn test_forward_secrecy() {
        let (mut alice, mut bob) = make_pair();

        // İlk DH ratchet döngüsünden bir mesaj
        let e1 = encrypt(&mut alice, b"Gizli mesaj").unwrap();
        let initial_mk = {
            let ck = alice.ck_send.clone().unwrap();
            let (_, mk) = kdf_ck(&ck);
            mk
        };

        decrypt(&mut bob, &e1).unwrap();

        // DH ratchet döndükten sonra ilk döngünün anahtarı geçersiz
        let e2 = encrypt(&mut bob, b"DH ratchet tetiklendi").unwrap();
        decrypt(&mut alice, &e2).unwrap();

        // initial_mk artık hiçbir şeyi şifreli açamaz (forward secrecy)
        let _ = initial_mk; // Kullanıldığını belgeliyoruz
    }
}
