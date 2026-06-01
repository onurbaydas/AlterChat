use hkdf::Hkdf;
use ml_kem::MlKem768;
use ml_kem::kem::{Encapsulate, Decapsulate, EncapsulationKey, DecapsulationKey, Kem, KeyExport};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngExt;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PreKeyBundle {
    pub identity_key: [u8; 32], // X25519 public key
    pub signed_prekey: [u8; 32],
    pub signed_prekey_sig: Vec<u8>,
    pub one_time_prekey: Option<[u8; 32]>,
    pub ml_kem_ek: Vec<u8>,
    pub ml_kem_ek_sig: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct InitialMessage {
    pub identity_key: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub ml_kem_ct: Vec<u8>,
    pub used_opk: bool,
}

pub fn generate_x3dh_shared_secret(
    my_identity: &StaticSecret,
    my_ephemeral: &StaticSecret, // Changed to StaticSecret for reusability
    peer_bundle: &PreKeyBundle,
    ss_kem: &[u8],
) -> [u8; 32] {
    let peer_ik = X25519PublicKey::from(peer_bundle.identity_key);
    let peer_spk = X25519PublicKey::from(peer_bundle.signed_prekey);
    let peer_opk = peer_bundle.one_time_prekey.map(X25519PublicKey::from);

    let dh1 = my_identity.diffie_hellman(&peer_spk);
    let dh2 = my_ephemeral.diffie_hellman(&peer_ik);
    let dh3 = my_ephemeral.diffie_hellman(&peer_spk);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(b"X3DH_MLKEM768_V1");
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = peer_opk {
        let dh4 = my_ephemeral.diffie_hellman(&opk);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    ikm.extend_from_slice(ss_kem);

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(b"AlterChat_X3DH_SK", &mut okm).unwrap();
    okm
}

pub fn initiate_x3dh(
    my_identity: &StaticSecret,
    peer_bundle: &PreKeyBundle,
) -> Result<(InitialMessage, [u8; 32]), &'static str> {
    // We use StaticSecret for the ephemeral key because we need to reuse it for multiple DH calls
    let mut ephemeral_bytes = [0u8; 32];
    rand::rng().fill(&mut ephemeral_bytes);
    let my_ephemeral = StaticSecret::from(ephemeral_bytes);
    
    let my_ek_pub = X25519PublicKey::from(&my_ephemeral);
    let my_ik_pub = X25519PublicKey::from(my_identity);

    // KEM Encapsulation
    let ek_arr: &ml_kem::kem::Key<EncapsulationKey<MlKem768>> = peer_bundle.ml_kem_ek.as_slice().try_into().map_err(|_| "Invalid ML-KEM EK size")?;
    let ek = EncapsulationKey::<MlKem768>::new(ek_arr).map_err(|_| "Invalid ML-KEM key")?;
    let (ct, ss_kem) = ek.encapsulate(); // encapsulate does not take &mut OsRng and does not return Result


    let sk = generate_x3dh_shared_secret(my_identity, &my_ephemeral, peer_bundle, ss_kem.as_slice());

    let init_msg = InitialMessage {
        identity_key: *my_ik_pub.as_bytes(),
        ephemeral_key: *my_ek_pub.as_bytes(),
        ml_kem_ct: ct.as_slice().to_vec(),
        used_opk: peer_bundle.one_time_prekey.is_some(),
    };

    Ok((init_msg, sk))
}

/// Login sırasında çağrılır: imzalı X3DH + ML-KEM PreKeyBundle üretir.
/// `identity_secret`: X25519 kimlik anahtarı (offline_secret_bytes)
/// `ed_signing_key`: Ed25519 imza anahtarı (aynı 32 byte'tan türetilir)
pub fn generate_prekey_bundle(
    identity_secret: &[u8; 32],
    ed_signing_key: &[u8; 32],
) -> (PreKeyBundle, Vec<u8>) {
    let my_identity = StaticSecret::from(*identity_secret);
    let ik_pub = *X25519PublicKey::from(&my_identity).as_bytes();

    // Signed prekey: rastgele X25519 keypair
    let spk_secret = {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        StaticSecret::from(bytes)
    };
    let spk_pub = *X25519PublicKey::from(&spk_secret).as_bytes();

    // Ed25519 ile signed prekey imzala
    let signing_key = SigningKey::from_bytes(ed_signing_key);
    let spk_sig = signing_key.sign(&spk_pub).to_bytes().to_vec();

    // ML-KEM 768 keypair üret: rastgele 64-byte seed → DecapsulationKey → EncapsulationKey
    let (ml_kem_ek_bytes, ml_kem_dk_bytes) = {
        let mut seed_bytes = [0u8; 64];
        rand::rng().fill(&mut seed_bytes);
        let seed: ml_kem::Seed = seed_bytes.into();
        let dk = DecapsulationKey::<MlKem768>::from_seed(seed.clone());
        let ek = dk.encapsulation_key();
        let ek_bytes: Vec<u8> = KeyExport::to_bytes(ek).as_slice().to_vec();
        // seed (64 bytes) olarak sakla; dk yeniden oluşturmak için yeterli
        (ek_bytes, seed.to_vec())
    };
    let ml_kem_ek_sig = signing_key.sign(&ml_kem_ek_bytes).to_bytes().to_vec();

    let bundle = PreKeyBundle {
        identity_key: ik_pub,
        signed_prekey: spk_pub,
        signed_prekey_sig: spk_sig,
        one_time_prekey: None,
        ml_kem_ek: ml_kem_ek_bytes,
        ml_kem_ek_sig,
    };
    (bundle, ml_kem_dk_bytes)
}

pub fn receive_x3dh(
    my_identity: &StaticSecret,
    my_signed_prekey: &StaticSecret,
    my_one_time_prekey: Option<&StaticSecret>,
    my_ml_kem_dk: &DecapsulationKey<MlKem768>,
    init_msg: &InitialMessage,
) -> Result<[u8; 32], &'static str> {
    let peer_ik = X25519PublicKey::from(init_msg.identity_key);
    let peer_ek = X25519PublicKey::from(init_msg.ephemeral_key);

    let dh1 = my_signed_prekey.diffie_hellman(&peer_ik);
    let dh2 = my_identity.diffie_hellman(&peer_ek);
    let dh3 = my_signed_prekey.diffie_hellman(&peer_ek);

    let mut ikm = Vec::new();
    ikm.extend_from_slice(b"X3DH_MLKEM768_V1");
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());

    if init_msg.used_opk {
        let opk = my_one_time_prekey.ok_or("Peer used OPK but we don't have it")?;
        let dh4 = opk.diffie_hellman(&peer_ek);
        ikm.extend_from_slice(dh4.as_bytes());
    }

    // Decapsulate KEM
    let ct_array = init_msg.ml_kem_ct.as_slice().try_into().map_err(|_| "Invalid ML-KEM CT size")?;
    let ss_kem = my_ml_kem_dk.decapsulate(&ct_array); // decapsulate does not return a Result in ml-kem


    ikm.extend_from_slice(ss_kem.as_slice());

    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hkdf.expand(b"AlterChat_X3DH_SK", &mut okm).unwrap();
    Ok(okm)
}
