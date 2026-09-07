// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Rust half of the composite cross-language byte-parity check (R-16.2): prints the hex of a
//! deterministic, signed N-AALP object envelope carrying the opt-in LAMPS composite signature
//! (§4.2), for a fixed worked object. The ML-DSA-65 key is derived from the 32-byte seed given
//! as the first argument; the Ed25519 key from a fixed seed. scripts/verify.sh runs this and
//! the Go `naalp-composite` command with the same seed and asserts identical bytes.

use naalp::cbor::Value;
use naalp::cose;
use naalp::envelope::{self, Object};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: naalp_composite <seed-hex-32-bytes>");
        std::process::exit(2);
    }
    let seed: [u8; 32] = hex::decode(&args[1])
        .expect("seed must be hex")
        .try_into()
        .expect("seed must be 32 bytes");
    let (_, sk) = cose::mldsa65_keypair_from_seed(&seed);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(b"naalp-composite-ed25519-seed-32b");

    let mut o = Object {
        audience: String::new(),
        suite: 0,
        id: vec![],
        kind: 2,
        channel: 4,
        tier: 0,
        signer: b"SIGNER_A".to_vec(),
        created: 1785000000000,
        effect: 2,
        causes: vec![],
        profile: 1,
        body: Value::Tstr("hello".to_string()),
        ext: None,
        cext: None,
    };
    let obj = envelope::sign(
        &mut o,
        &cose::CompositeSigner {
            ml65: sk,
            ed: ed_sk,
        },
    );
    println!("{}", hex::encode(obj));
}
