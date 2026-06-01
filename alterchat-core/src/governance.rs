use libp2p::{PeerId, identity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    Read,
    Write,
    Invite,
    SendFile,
    StartCall,
    ModerateLocal,
    ManageRoles,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteToken {
    pub room_id: String,
    pub room_password: Option<String>,
    pub issuer_peer_id: String,
    #[serde(default)]
    pub issuer_public_key: Vec<u8>,
    pub subject_peer_id: Option<String>,
    pub expires_at: Option<i64>,
    pub max_uses: Option<u32>,
    pub capabilities: Vec<Permission>,
    pub nonce: [u8; 16],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub room_id: String,
    pub role_id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionGrant {
    pub room_id: String,
    pub subject_peer_id: String,
    pub role_id: String,
    pub issuer_peer_id: String,
    #[serde(default)]
    pub issuer_public_key: Vec<u8>,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub from_peer_id: String,
    #[serde(default)]
    pub from_public_key: Vec<u8>,
    pub to_peer_id: String,
    pub score: i32,
    pub reason: String,
    pub issued_at: i64,
    pub signature: Vec<u8>,
}

/// Dağıtık revokasyon duyurusu — Gossipsub üzerinden yayınlanır.
/// Herhangi bir peer davetiyeyi iptal edilmiş olarak işaretleyebilir;
/// alıcılar imzayı doğrulayarak yerel DB'lerini günceller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationAnnouncement {
    pub invite_id: String,
    pub room_id: String,
    pub revoked_by: String,
    pub revoked_at: i64,
    pub signature: Vec<u8>,
}

/// Gossipsub topic: tüm revokasyon duyuruları bu topic'e yayınlanır.
pub const REVOCATION_TOPIC: &str = "_alterchat_revocations";

pub fn revocation_signing_bytes(ann: &RevocationAnnouncement) -> Vec<u8> {
    let mut clone = ann.clone();
    clone.signature.clear();
    bincode::serialize(&clone).unwrap_or_default()
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn random_nonce() -> [u8; 16] {
    use aes_gcm::aead::{OsRng, rand_core::RngCore};
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn invite_signing_bytes(token: &InviteToken) -> Vec<u8> {
    let mut clone = token.clone();
    clone.signature.clear();
    bincode::serialize(&clone).unwrap_or_default()
}

pub fn grant_signing_bytes(grant: &PermissionGrant) -> Vec<u8> {
    let mut clone = grant.clone();
    clone.signature.clear();
    bincode::serialize(&clone).unwrap_or_default()
}

pub fn trust_edge_signing_bytes(edge: &TrustEdge) -> Vec<u8> {
    let mut clone = edge.clone();
    clone.signature.clear();
    bincode::serialize(&clone).unwrap_or_default()
}

pub fn sign_bytes(keypair: &identity::Keypair, payload: &[u8]) -> Result<Vec<u8>, String> {
    keypair
        .sign(payload)
        .map_err(|e| format!("sign failed: {e:?}"))
}

pub fn verify_bytes(public_key: &identity::PublicKey, payload: &[u8], signature: &[u8]) -> bool {
    public_key.verify(payload, signature)
}

pub fn create_invite(
    keypair: &identity::Keypair,
    room_id: String,
    room_password: Option<String>,
    subject_peer_id: Option<String>,
    expires_at: Option<i64>,
    max_uses: Option<u32>,
    capabilities: Vec<Permission>,
) -> Result<InviteToken, String> {
    let issuer_peer_id = PeerId::from(keypair.public()).to_string();
    let mut token = InviteToken {
        room_id,
        room_password,
        issuer_peer_id,
        issuer_public_key: keypair.public().encode_protobuf(),
        subject_peer_id,
        expires_at,
        max_uses,
        capabilities,
        nonce: random_nonce(),
        signature: Vec::new(),
    };
    token.signature = sign_bytes(keypair, &invite_signing_bytes(&token))?;
    Ok(token)
}

pub fn create_permission_grant(
    keypair: &identity::Keypair,
    room_id: String,
    subject_peer_id: String,
    role_id: String,
    expires_at: Option<i64>,
) -> Result<PermissionGrant, String> {
    let issuer_peer_id = PeerId::from(keypair.public()).to_string();
    let mut grant = PermissionGrant {
        room_id,
        subject_peer_id,
        role_id,
        issuer_peer_id,
        issuer_public_key: keypair.public().encode_protobuf(),
        issued_at: now_ms(),
        expires_at,
        signature: Vec::new(),
    };
    grant.signature = sign_bytes(keypair, &grant_signing_bytes(&grant))?;
    Ok(grant)
}

pub fn create_trust_edge(
    keypair: &identity::Keypair,
    to_peer_id: String,
    score: i32,
    reason: String,
) -> Result<TrustEdge, String> {
    let mut edge = TrustEdge {
        from_peer_id: PeerId::from(keypair.public()).to_string(),
        from_public_key: keypair.public().encode_protobuf(),
        to_peer_id,
        score: score.clamp(-10, 10),
        reason,
        issued_at: now_ms(),
        signature: Vec::new(),
    };
    edge.signature = sign_bytes(keypair, &trust_edge_signing_bytes(&edge))?;
    Ok(edge)
}

pub fn invite_id(token: &InviteToken) -> String {
    let mut hasher = Sha256::new();
    hasher.update(invite_signing_bytes(token));
    hasher.update(&token.signature);
    hex_string(&hasher.finalize())
}

pub fn is_invite_expired(token: &InviteToken, now_ms: i64) -> bool {
    token
        .expires_at
        .map(|expires| expires < now_ms)
        .unwrap_or(false)
}

pub fn decode_public_key(bytes: &[u8]) -> Result<identity::PublicKey, String> {
    identity::PublicKey::try_decode_protobuf(bytes)
        .map_err(|e| format!("invalid public key: {e:?}"))
}

pub fn public_key_peer_id(public_key: &identity::PublicKey) -> String {
    PeerId::from(public_key.clone()).to_string()
}

pub fn verify_invite(token: &InviteToken) -> Result<(), String> {
    let public_key = decode_public_key(&token.issuer_public_key)?;
    if public_key_peer_id(&public_key) != token.issuer_peer_id {
        return Err("invite issuer public key does not match issuer peer id".to_string());
    }
    if !verify_bytes(
        &public_key,
        &invite_signing_bytes(token),
        token.signature.as_slice(),
    ) {
        return Err("invite signature rejected".to_string());
    }
    Ok(())
}

pub fn verify_permission_grant(grant: &PermissionGrant) -> Result<(), String> {
    let public_key = decode_public_key(&grant.issuer_public_key)?;
    if public_key_peer_id(&public_key) != grant.issuer_peer_id {
        return Err("permission issuer public key does not match issuer peer id".to_string());
    }
    if !verify_bytes(
        &public_key,
        &grant_signing_bytes(grant),
        grant.signature.as_slice(),
    ) {
        return Err("permission grant signature rejected".to_string());
    }
    Ok(())
}

pub fn verify_trust_edge(edge: &TrustEdge) -> Result<(), String> {
    let public_key = decode_public_key(&edge.from_public_key)?;
    if public_key_peer_id(&public_key) != edge.from_peer_id {
        return Err("trust edge public key does not match source peer id".to_string());
    }
    if !verify_bytes(
        &public_key,
        &trust_edge_signing_bytes(edge),
        edge.signature.as_slice(),
    ) {
        return Err("trust edge signature rejected".to_string());
    }
    Ok(())
}

pub fn default_roles(room_id: &str) -> Vec<Role> {
    vec![
        Role {
            room_id: room_id.to_string(),
            role_id: "owner".to_string(),
            name: "Owner".to_string(),
            permissions: vec![
                Permission::Read,
                Permission::Write,
                Permission::Invite,
                Permission::SendFile,
                Permission::StartCall,
                Permission::ModerateLocal,
                Permission::ManageRoles,
            ],
        },
        Role {
            room_id: room_id.to_string(),
            role_id: "member".to_string(),
            name: "Member".to_string(),
            permissions: vec![
                Permission::Read,
                Permission::Write,
                Permission::Invite,
                Permission::SendFile,
                Permission::StartCall,
            ],
        },
        Role {
            room_id: room_id.to_string(),
            role_id: "guest".to_string(),
            name: "Guest".to_string(),
            permissions: vec![Permission::Read],
        },
    ]
}

pub fn has_permission(
    grants: &[PermissionGrant],
    roles: &[Role],
    peer_id: &str,
    permission: Permission,
    now_ms: i64,
) -> bool {
    grants.iter().any(|grant| {
        grant.subject_peer_id == peer_id
            && verify_permission_grant(grant).is_ok()
            && grant
                .expires_at
                .map(|expires| expires >= now_ms)
                .unwrap_or(true)
            && roles.iter().any(|role| {
                role.room_id == grant.room_id
                    && role.role_id == grant.role_id
                    && role.permissions.contains(&permission)
            })
    })
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_signature_rejects_tampering() {
        let keypair = identity::Keypair::generate_ed25519();
        let mut token = create_invite(
            &keypair,
            "room-a".to_string(),
            None,
            None,
            None,
            Some(1),
            vec![Permission::Read],
        )
        .unwrap();
        assert!(verify_invite(&token).is_ok());
        token.room_id = "room-b".to_string();
        assert!(verify_invite(&token).is_err());
    }

    #[test]
    fn grant_signature_is_required_for_permission() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public()).to_string();
        let role = default_roles("room-a")
            .into_iter()
            .find(|role| role.role_id == "owner")
            .unwrap();
        let mut grant = create_permission_grant(
            &keypair,
            "room-a".to_string(),
            peer_id.clone(),
            "owner".to_string(),
            None,
        )
        .unwrap();
        assert!(has_permission(
            &[grant.clone()],
            &[role.clone()],
            &peer_id,
            Permission::ManageRoles,
            now_ms()
        ));
        grant.subject_peer_id = "other-peer".to_string();
        assert!(!has_permission(
            &[grant],
            &[role],
            &peer_id,
            Permission::ManageRoles,
            now_ms()
        ));
    }

    #[test]
    fn trust_edge_signature_rejects_tampering() {
        let keypair = identity::Keypair::generate_ed25519();
        let mut edge =
            create_trust_edge(&keypair, "peer-b".to_string(), 7, "known".to_string()).unwrap();
        assert!(verify_trust_edge(&edge).is_ok());
        edge.score = -7;
        assert!(verify_trust_edge(&edge).is_err());
    }
}
