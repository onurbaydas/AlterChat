//! X3DH key agreement extended with ML-KEM-768 (hybrid, post-quantum).
//!
//! Every prekey bundle is signed by the owner's Ed25519 identity key (the key
//! behind the libp2p `PeerId`). Both signatures cover the X3DH identity key,
//! so the bundle as a whole is bound to the peer id. The initial message
//! carries an Ed25519 signature over the initiator's X3DH identity key so
//! the responder can bind it to the initiator's peer id too.
//!
//! The X25519 X3DH identity key is derived from the Ed25519 seed with HKDF and
//! a dedicated label (domain separation): it never reuses the raw Ed25519
//! seed as an X25519 scalar.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::MlKem768;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport};
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SPK_SIG_DOMAIN: &[u8] = b"AlterChat-X3DH-SPK-v1";
const KEM_SIG_DOMAIN: &[u8] = b"AlterChat-X3DH-KEM-v1";
const IK_SIG_DOMAIN: &[u8] = b"AlterChat-X3DH-IK-v1";
const IK_DERIVE_SALT: &[u8] = b"AlterChat-X3DH-IK-derive-v1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PreKeyBundle {
    pub identity_key: [u8; 32], // X25519 X3DH identity public key
    pub signed_prekey: [u8; 32],
    /// Ed25519 signature over `SPK_SIG_DOMAIN || identity_key || signed_prekey || created_at`.
    pub signed_prekey_sig: Vec<u8>,
    /// One-time prekeys are not used; initiators ignore this field.
    pub one_time_prekey: Option<[u8; 32]>,
    pub ml_kem_ek: Vec<u8>,
    /// Ed25519 signature over `KEM_SIG_DOMAIN || identity_key || ml_kem_ek`.
    pub ml_kem_ek_sig: Vec<u8>,
    /// Creation time (unix ms), covered by `signed_prekey_sig`.
    #[serde(default)]
    pub created_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct InitialMessage {
    pub identity_key: [u8; 32],
    /// Ed25519 signature over `IK_SIG_DOMAIN || identity_key` by the initiator.
    pub identity_sig: Vec<u8>,
    pub ephemeral_key: [u8; 32],
    /// The responder's signed prekey this handshake was made against.
    pub signed_prekey: [u8; 32],
    pub ml_kem_ct: Vec<u8>,
    pub used_opk: bool,
}

/// Secret half of a signed prekey: X25519 signed-prekey secret and the
/// 64-byte ML-KEM-768 decapsulation seed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKeySecrets {
    pub spk_secret: [u8; 32],
    pub ml_kem_seed: [u8; 64],
}

/// Derives the X25519 X3DH identity secret from the Ed25519 identity seed.
pub fn derive_x3dh_identity_secret(ed25519_seed: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(IK_DERIVE_SALT), ed25519_seed);
    let mut out = [0u8; 32];
    hk.expand(b"x25519 identity", &mut out)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

fn spk_message(ik: &[u8; 32], spk: &[u8; 32], created_at: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(SPK_SIG_DOMAIN.len() + 72);
    m.extend_from_slice(SPK_SIG_DOMAIN);
    m.extend_from_slice(ik);
    m.extend_from_slice(spk);
    m.extend_from_slice(&created_at.to_be_bytes());
    m
}

fn kem_message(ik: &[u8; 32], ek: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(KEM_SIG_DOMAIN.len() + 32 + ek.len());
    m.extend_from_slice(KEM_SIG_DOMAIN);
    m.extend_from_slice(ik);
    m.extend_from_slice(ek);
    m
}

fn ik_message(ik: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(IK_SIG_DOMAIN.len() + 32);
    m.extend_from_slice(IK_SIG_DOMAIN);
    m.extend_from_slice(ik);
    m
}

/// Strict Ed25519 verification; never panics on malformed input.
pub fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    vk.verify_strict(message, &sig).is_ok()
}

/// Signs the X3DH identity key with the Ed25519 identity seed.
pub fn sign_identity_key(ed25519_seed: &[u8; 32], ik_pub: &[u8; 32]) -> Vec<u8> {
    SigningKey::from_bytes(ed25519_seed)
        .sign(&ik_message(ik_pub))
        .to_bytes()
        .to_vec()
}

/// Verifies both bundle signatures against the owner's Ed25519 public key.
pub fn verify_prekey_bundle(
    bundle: &PreKeyBundle,
    signer_ed25519_pub: &[u8; 32],
) -> Result<(), &'static str> {
    if !verify_ed25519(
        signer_ed25519_pub,
        &spk_message(
            &bundle.identity_key,
            &bundle.signed_prekey,
            bundle.created_at,
        ),
        &bundle.signed_prekey_sig,
    ) {
        return Err("Invalid signed prekey signature");
    }
    if !verify_ed25519(
        signer_ed25519_pub,
        &kem_message(&bundle.identity_key, &bundle.ml_kem_ek),
        &bundle.ml_kem_ek_sig,
    ) {
        return Err("Invalid ML-KEM key signature");
    }
    Ok(())
}

fn checked_dh(secret: &StaticSecret, public: &X25519PublicKey) -> Result<[u8; 32], &'static str> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err("Non-contributory X25519 key");
    }
    Ok(*shared.as_bytes())
}

fn kdf_sk(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32], ss_kem: &[u8]) -> [u8; 32] {
    let mut ikm = zeroize::Zeroizing::new(Vec::with_capacity(16 + 96 + ss_kem.len()));
    ikm.extend_from_slice(b"X3DH_MLKEM768_V1");
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(ss_kem);
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(b"AlterChat_X3DH_SK", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Initiator side. Verifies the bundle signatures against
/// `peer_signer_ed25519_pub` before using any key from it.
pub fn initiate_x3dh(
    my_identity: &StaticSecret,
    my_ed25519_seed: &[u8; 32],
    peer_bundle: &PreKeyBundle,
    peer_signer_ed25519_pub: &[u8; 32],
) -> Result<(InitialMessage, [u8; 32]), &'static str> {
    verify_prekey_bundle(peer_bundle, peer_signer_ed25519_pub)?;

    let mut ephemeral_bytes = zeroize::Zeroizing::new([0u8; 32]);
    rand::rng().fill(&mut ephemeral_bytes[..]);
    let my_ephemeral = StaticSecret::from(*ephemeral_bytes);

    let my_ek_pub = X25519PublicKey::from(&my_ephemeral);
    let my_ik_pub = X25519PublicKey::from(my_identity);

    let ek_arr: &ml_kem::kem::Key<EncapsulationKey<MlKem768>> = peer_bundle
        .ml_kem_ek
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid ML-KEM EK size")?;
    let ek = EncapsulationKey::<MlKem768>::new(ek_arr).map_err(|_| "Invalid ML-KEM key")?;
    let (ct, ss_kem) = ek.encapsulate();

    let peer_ik = X25519PublicKey::from(peer_bundle.identity_key);
    let peer_spk = X25519PublicKey::from(peer_bundle.signed_prekey);
    let dh1 = checked_dh(my_identity, &peer_spk)?;
    let dh2 = checked_dh(&my_ephemeral, &peer_ik)?;
    let dh3 = checked_dh(&my_ephemeral, &peer_spk)?;
    let sk = kdf_sk(&dh1, &dh2, &dh3, ss_kem.as_slice());

    let init_msg = InitialMessage {
        identity_key: *my_ik_pub.as_bytes(),
        identity_sig: sign_identity_key(my_ed25519_seed, my_ik_pub.as_bytes()),
        ephemeral_key: *my_ek_pub.as_bytes(),
        signed_prekey: peer_bundle.signed_prekey,
        ml_kem_ct: ct.as_slice().to_vec(),
        // One-time prekeys are not part of this protocol version.
        used_opk: false,
    };

    Ok((init_msg, sk))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Generates a fresh signed prekey + ML-KEM-768 keypair and the signed
/// bundle. The returned secrets MUST be persisted, otherwise nobody can
/// complete a handshake against the published bundle.
/// `identity_secret`: X25519 X3DH identity secret
/// (see [`derive_x3dh_identity_secret`]); `ed_signing_key`: Ed25519 seed.
pub fn generate_prekey_bundle(
    identity_secret: &[u8; 32],
    ed_signing_key: &[u8; 32],
) -> (PreKeyBundle, SignedPreKeySecrets) {
    let my_identity = StaticSecret::from(*identity_secret);
    let ik_pub = *X25519PublicKey::from(&my_identity).as_bytes();

    let mut spk_bytes = [0u8; 32];
    rand::rng().fill(&mut spk_bytes);
    let spk_secret = StaticSecret::from(spk_bytes);
    let spk_pub = *X25519PublicKey::from(&spk_secret).as_bytes();
    let created_at = now_ms();

    let signing_key = SigningKey::from_bytes(ed_signing_key);
    let spk_sig = signing_key
        .sign(&spk_message(&ik_pub, &spk_pub, created_at))
        .to_bytes()
        .to_vec();

    let mut seed_bytes = [0u8; 64];
    rand::rng().fill(&mut seed_bytes);
    let ml_kem_ek_bytes = ml_kem_ek_from_seed(&seed_bytes);
    let ml_kem_ek_sig = signing_key
        .sign(&kem_message(&ik_pub, &ml_kem_ek_bytes))
        .to_bytes()
        .to_vec();

    let bundle = PreKeyBundle {
        identity_key: ik_pub,
        signed_prekey: spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekey: None,
        ml_kem_ek: ml_kem_ek_bytes,
        ml_kem_ek_sig,
        created_at,
    };
    let secrets = SignedPreKeySecrets {
        spk_secret: *spk_secret.as_bytes(),
        ml_kem_seed: seed_bytes,
    };
    spk_bytes.zeroize();
    seed_bytes.zeroize();
    (bundle, secrets)
}

fn ml_kem_dk_from_seed(seed: &[u8; 64]) -> DecapsulationKey<MlKem768> {
    let seed: ml_kem::Seed = (*seed).into();
    DecapsulationKey::<MlKem768>::from_seed(seed)
}

fn ml_kem_ek_from_seed(seed: &[u8; 64]) -> Vec<u8> {
    let dk = ml_kem_dk_from_seed(seed);
    KeyExport::to_bytes(dk.encapsulation_key())
        .as_slice()
        .to_vec()
}

/// Responder side. Verifies the initiator's identity-key signature against
/// `peer_signer_ed25519_pub` and that the handshake targets `my_spk`.
pub fn receive_x3dh(
    my_identity: &StaticSecret,
    my_spk: &SignedPreKeySecrets,
    init_msg: &InitialMessage,
    peer_signer_ed25519_pub: &[u8; 32],
) -> Result<[u8; 32], &'static str> {
    if !verify_ed25519(
        peer_signer_ed25519_pub,
        &ik_message(&init_msg.identity_key),
        &init_msg.identity_sig,
    ) {
        return Err("Invalid initiator identity signature");
    }
    if init_msg.used_opk {
        return Err("One-time prekeys are not supported");
    }
    let spk_secret = StaticSecret::from(my_spk.spk_secret);
    if X25519PublicKey::from(&spk_secret).as_bytes() != &init_msg.signed_prekey {
        return Err("Handshake targets a different signed prekey");
    }

    let peer_ik = X25519PublicKey::from(init_msg.identity_key);
    let peer_ek = X25519PublicKey::from(init_msg.ephemeral_key);
    let dh1 = checked_dh(&spk_secret, &peer_ik)?;
    let dh2 = checked_dh(my_identity, &peer_ek)?;
    let dh3 = checked_dh(&spk_secret, &peer_ek)?;

    let ct_array = init_msg
        .ml_kem_ct
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid ML-KEM CT size")?;
    let dk = ml_kem_dk_from_seed(&my_spk.ml_kem_seed);
    let ss_kem = dk.decapsulate(&ct_array);

    Ok(kdf_sk(&dh1, &dh2, &dh3, ss_kem.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Party {
        ed_seed: [u8; 32],
        ed_pub: [u8; 32],
        ik: StaticSecret,
    }

    fn party() -> Party {
        let mut ed_seed = [0u8; 32];
        rand::rng().fill(&mut ed_seed);
        let ed_pub = SigningKey::from_bytes(&ed_seed).verifying_key().to_bytes();
        let ik = StaticSecret::from(derive_x3dh_identity_secret(&ed_seed));
        Party {
            ed_seed,
            ed_pub,
            ik,
        }
    }

    fn bundle_for(p: &Party) -> (PreKeyBundle, SignedPreKeySecrets) {
        generate_prekey_bundle(&p.ik.to_bytes(), &p.ed_seed)
    }

    #[test]
    fn test_x3dh_mlkem_full_handshake() {
        let alice = party();
        let bob = party();
        let (bundle, bob_spk) = bundle_for(&bob);

        let (init, alice_sk) =
            initiate_x3dh(&alice.ik, &alice.ed_seed, &bundle, &bob.ed_pub).expect("initiate");
        assert_eq!(init.ml_kem_ct.len(), 1088, "ML-KEM-768 ciphertext");
        let bob_sk = receive_x3dh(&bob.ik, &bob_spk, &init, &alice.ed_pub).expect("receive");
        assert_eq!(alice_sk, bob_sk);
        assert_ne!(alice_sk, [0u8; 32]);
    }

    #[test]
    fn test_bundle_signature_tamper_rejected() {
        let alice = party();
        let bob = party();
        let mallory = party();
        let (bundle, _) = bundle_for(&bob);

        let mut t = bundle.clone();
        t.signed_prekey[0] ^= 1;
        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &t, &bob.ed_pub).is_err());

        let mut t = bundle.clone();
        t.ml_kem_ek[10] ^= 1;
        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &t, &bob.ed_pub).is_err());

        let mut t = bundle.clone();
        t.identity_key[0] ^= 1;
        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &t, &bob.ed_pub).is_err());

        let mut t = bundle.clone();
        t.created_at += 1;
        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &t, &bob.ed_pub).is_err());

        let mut t = bundle.clone();
        t.signed_prekey_sig.truncate(10);
        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &t, &bob.ed_pub).is_err());

        // A bundle validly signed by somebody else is not Bob's bundle.
        let (mallory_bundle, _) = bundle_for(&mallory);
        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &mallory_bundle, &bob.ed_pub).is_err());

        assert!(initiate_x3dh(&alice.ik, &alice.ed_seed, &bundle, &bob.ed_pub).is_ok());
    }

    #[test]
    fn test_initial_message_identity_signature_checked() {
        let alice = party();
        let bob = party();
        let mallory = party();
        let (bundle, bob_spk) = bundle_for(&bob);
        let (init, _) =
            initiate_x3dh(&alice.ik, &alice.ed_seed, &bundle, &bob.ed_pub).expect("initiate");
        // Claiming to be Mallory fails.
        assert!(receive_x3dh(&bob.ik, &bob_spk, &init, &mallory.ed_pub).is_err());
        // Swapping in Mallory's identity key without her signature fails.
        let mut t = init.clone();
        t.identity_key = *X25519PublicKey::from(&mallory.ik).as_bytes();
        assert!(receive_x3dh(&bob.ik, &bob_spk, &t, &alice.ed_pub).is_err());
        // Wrong signed prekey secret is detected.
        let (_, other_spk) = bundle_for(&bob);
        assert!(receive_x3dh(&bob.ik, &other_spk, &init, &alice.ed_pub).is_err());
        // Truncated KEM ciphertext is an error, not a panic.
        let mut t = init.clone();
        t.ml_kem_ct.pop();
        assert!(receive_x3dh(&bob.ik, &bob_spk, &t, &alice.ed_pub).is_err());
    }

    #[test]
    fn test_x3dh_shared_secret_uniqueness() {
        let alice = party();
        let bob = party();
        let (bundle, _) = bundle_for(&bob);
        let (_, a) = initiate_x3dh(&alice.ik, &alice.ed_seed, &bundle, &bob.ed_pub).unwrap();
        let (_, b) = initiate_x3dh(&alice.ik, &alice.ed_seed, &bundle, &bob.ed_pub).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_identity_derivation_is_domain_separated() {
        let p = party();
        let derived = derive_x3dh_identity_secret(&p.ed_seed);
        assert_ne!(derived, p.ed_seed);
        assert_eq!(derived, derive_x3dh_identity_secret(&p.ed_seed));
    }
}
