#![no_main]

// Fuzz target: attempt to peel arbitrary bytes as an OnionPacket.
//
// peel_onion (alterchat-core/src/onion.rs) takes a static X25519 secret and an
// OnionPacket, decrypts the outer layer with AES-256-GCM, then bincode-deserializes
// the plaintext into an OnionLayer.  We exercise two things:
//
//   1. Deserializing the raw bytes as an OnionPacket (bincode).  If the bytes are
//      not a valid OnionPacket the call returns Err — no panic expected.
//
//   2. If deserialization succeeds, calling peel_onion with a fixed (all-zero)
//      secret.  Decryption will almost certainly fail on random input, returning
//      Err.  The goal is to confirm that neither path panics.
//
// To run:
//   cargo +nightly fuzz run fuzz_onion_packet -- -max_total_time=60

use libfuzzer_sys::fuzz_target;
use alterchat_core::onion::{OnionPacket, peel_onion};

fuzz_target!(|data: &[u8]| {
    // Try to interpret the fuzz input as a serialized OnionPacket.
    let packet: OnionPacket = match bincode::deserialize(data) {
        Ok(p) => p,
        Err(_) => return, // Not a valid OnionPacket — no panic, just skip.
    };

    // Use a fixed all-zero key; real decryption will fail, but must not panic.
    let dummy_secret = [0u8; 32];
    let _ = peel_onion(&dummy_secret, &packet);
});
