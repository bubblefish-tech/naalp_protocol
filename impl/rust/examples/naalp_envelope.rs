// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Rust half of the C3 cross-language byte-parity check (R-16.2): prints the hex of a
//! deterministic, signed N-AALP object envelope for a fixed worked object, using an
//! ML-DSA-65 key derived from the 32-byte seed given as the first argument. scripts/verify.sh
//! runs this and the Go `naalp-envelope` command with the same seed and asserts identical
//! bytes. The worked object matches tools/envelope_oracle.py.

use naalp::cbor::Value;
use naalp::cose;
use naalp::envelope::{self, Object};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: naalp_envelope <seed-hex-32-bytes>");
        std::process::exit(2);
    }
    let seed: [u8; 32] = hex::decode(&args[1])
        .expect("seed must be hex")
        .try_into()
        .expect("seed must be 32 bytes");
    let (_, sk) = cose::mldsa65_keypair_from_seed(&seed);

    let mut o = Object {
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
    let obj = envelope::sign(&mut o, &cose::MlDsa65Signer(sk));
    println!("{}", hex::encode(obj));
}
