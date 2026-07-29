// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Rust half of the cross-language byte-parity demonstration (R-16.2): prints the hex of
//! a deterministic COSE_Sign1 object over a fixed payload ({7:0}), using an ML-DSA-65 key
//! derived from the 32-byte seed passed as the first argument. scripts/verify.sh runs this
//! and the Go `naalp-cose-sig` command with the same NIST keyGen seed and asserts they
//! print identical bytes.

use naalp::cose;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: naalp_cose_sig <seed-hex-32-bytes>");
        std::process::exit(2);
    }
    let seed: [u8; 32] = hex::decode(&args[1])
        .expect("seed must be hex")
        .try_into()
        .expect("seed must be 32 bytes");
    let (_, sk) = cose::mldsa65_keypair_from_seed(&seed);
    let obj = cose::sign1(&cose::MlDsa65Signer(sk), &[0xa1, 0x07, 0x00]);
    println!("{}", hex::encode(obj));
}
