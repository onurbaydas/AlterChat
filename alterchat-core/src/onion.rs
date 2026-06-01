use crate::crypto::{EncryptedPayload, decrypt_for_me, encrypt_for_peer};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionPacket {
    pub layer: EncryptedPayload,
    pub route_len: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    pub next_hop: Option<String>,
    pub inner_packet: Option<OnionPacket>,
    pub payload: Option<Vec<u8>>,
    pub padding: Vec<u8>,
}

pub fn wrap_onion(
    route: &[(String, [u8; 32])],
    payload: Vec<u8>,
) -> Result<OnionPacket, &'static str> {
    let mut next_packet: Option<OnionPacket> = None;
    let mut next_payload = Some(payload);

    for (hop_index, (peer_id, pubkey)) in route.iter().enumerate().rev() {
        let mut layer = OnionLayer {
            next_hop: route
                .get(hop_index + 1)
                .map(|(next_peer, _)| next_peer.clone()),
            inner_packet: next_packet,
            payload: next_payload.take(),
            padding: vec![],
        };
        let initial_bytes = bincode::serialize(&layer).map_err(|_| "onion serialize failed")?;
        let target_size = 16 * 1024; // 16 KB Sphinx fixed packet size
        if initial_bytes.len() < target_size {
            // bincode uses 8 bytes for Vec length
            layer.padding = vec![0u8; target_size - initial_bytes.len() - 8];
        }
        let bytes = bincode::serialize(&layer).map_err(|_| "onion serialize failed")?;
        next_packet = Some(OnionPacket {
            layer: encrypt_for_peer(pubkey, &bytes)?,
            route_len: route.len() as u8,
        });
        let _ = peer_id;
    }

    next_packet.ok_or("empty onion route")
}

pub fn peel_onion(my_secret: &[u8; 32], packet: &OnionPacket) -> Result<OnionLayer, &'static str> {
    let bytes = decrypt_for_me(my_secret, &packet.layer)?;
    bincode::deserialize(&bytes).map_err(|_| "onion deserialize failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_static_secret, get_public_key};

    #[test]
    fn single_hop_wrap_peel() {
        let secret = generate_static_secret();
        let pubkey = get_public_key(&secret);
        let route = vec![("peer1".to_string(), pubkey)];
        let payload = b"Manifesto V: Mahremiyet onurdur".to_vec();
        let packet = wrap_onion(&route, payload.clone()).unwrap();
        let layer = peel_onion(&secret, &packet).unwrap();
        assert_eq!(layer.payload.unwrap(), payload);
        assert!(layer.next_hop.is_none());
        assert!(layer.inner_packet.is_none());
    }

    #[test]
    fn three_hop_relay() {
        let s1 = generate_static_secret();
        let s2 = generate_static_secret();
        let s3 = generate_static_secret();
        let route = vec![
            ("hop1".to_string(), get_public_key(&s1)),
            ("hop2".to_string(), get_public_key(&s2)),
            ("hop3".to_string(), get_public_key(&s3)),
        ];
        let payload = b"secret data".to_vec();
        let packet = wrap_onion(&route, payload.clone()).unwrap();

        // Hop 1: peel and forward
        let layer1 = peel_onion(&s1, &packet).unwrap();
        assert_eq!(layer1.next_hop.as_deref(), Some("hop2"));
        assert!(layer1.payload.is_none());
        let inner1 = layer1.inner_packet.unwrap();

        // Hop 2: peel and forward
        let layer2 = peel_onion(&s2, &inner1).unwrap();
        assert_eq!(layer2.next_hop.as_deref(), Some("hop3"));
        assert!(layer2.payload.is_none());
        let inner2 = layer2.inner_packet.unwrap();

        // Hop 3: final destination
        let layer3 = peel_onion(&s3, &inner2).unwrap();
        assert!(layer3.next_hop.is_none());
        assert_eq!(layer3.payload.unwrap(), payload);
    }

    #[test]
    fn empty_route_rejected() {
        let result = wrap_onion(&[], b"data".to_vec());
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let secret = generate_static_secret();
        let pubkey = get_public_key(&secret);
        let wrong_secret = generate_static_secret();
        let route = vec![("peer".to_string(), pubkey)];
        let packet = wrap_onion(&route, b"secret".to_vec()).unwrap();
        assert!(peel_onion(&wrong_secret, &packet).is_err());
    }
}
