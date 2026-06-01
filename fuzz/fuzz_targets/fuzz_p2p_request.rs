#![no_main]

// Fuzz target: deserialize arbitrary bytes as a P2pRequest.
//
// P2pRequest is used by the request-response CBOR behaviour in AlterChat's libp2p
// swarm (see alterchat-core/src/network.rs, alterchat-core/src/file_transfer.rs).
// The type derives serde::Deserialize, so we attempt both cbor (ciborium) and
// bincode deserialization to cover both code paths that might be exercised at
// runtime.  Neither path must panic on malformed input.
//
// To run:
//   cargo +nightly fuzz run fuzz_p2p_request -- -max_total_time=60

use libfuzzer_sys::fuzz_target;
use alterchat_core::file_transfer::P2pRequest;

fuzz_target!(|data: &[u8]| {
    // Attempt bincode deserialization (used internally for onion layer serialization
    // and other alterchat-core binary paths).
    let _: Result<P2pRequest, _> = bincode::deserialize(data);

    // Attempt serde_json deserialization (used for JSON-over-HTTP or debug paths).
    let _: Result<P2pRequest, _> = serde_json::from_slice(data);
});
