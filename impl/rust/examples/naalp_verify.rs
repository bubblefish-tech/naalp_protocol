// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Demonstrates the N-AALP headline capability: verifying a signed object OFFLINE -- from the
//! object bytes, the signer's public key, and the spec alone, with no network call and no issuer
//! callback (R-2.4) -- and rejecting, fail-closed, anything that fails a check.
//!
//! It builds and signs a Governance Approval object (channel 0x0004, kind 1), then exercises four
//! outcomes: (1) the untouched object verifies and decodes back to its fields; (2) a one-bit tamper
//! is rejected; (3) verification under the wrong public key is rejected; (4) a kind the channel
//! validator does not admit is rejected (kind dispatch runs before the signature check). The
//! program exits non-zero if any outcome differs from the expected one, so it doubles as a
//! self-checking smoke test:
//!
//!   cargo run --example naalp_verify

use fips204::traits::SerDes;
use naalp::cbor::Value;
use naalp::cose;
use naalp::envelope::{self, Object};
use naalp::identity;

fn main() {
    // A deterministic ML-DSA-65 signer, plus a DIFFERENT key standing in for an impostor.
    let seed = [0x2au8; 32];
    let wrong_seed = [0x99u8; 32];
    let (pk, sk) = cose::mldsa65_keypair_from_seed(&seed);
    let (wrong_pk, _) = cose::mldsa65_keypair_from_seed(&wrong_seed);
    let pkb = pk.clone().into_bytes().to_vec();
    let signer_id = identity::signer_id(cose::ALG_MLDSA65, &pkb).expect("signer id");

    // A Governance Approval object (channel 0x0004, kind 1), effect non_idempotent_write, Public.
    let mut o = Object {
        id: vec![],
        kind: 1,
        channel: 4,
        tier: 0,
        signer: signer_id.clone().into_bytes(),
        created: 1785000000000,
        effect: 2,
        causes: vec![],
        profile: cose::PROFILE_PUBLIC as u64,
        body: Value::Tstr("approve: deploy build 4".to_string()),
        ext: None,
        cext: None,
    };
    let signed = envelope::sign(&mut o, &cose::MlDsa65Signer(sk));
    println!("signed object: {} bytes, signer {}...", signed.len(), &signer_id[..12]);

    let v = cose::MlDsa65Verifier(pk);
    // The channel validator admits kind 1 on the Governance channel (0x0004) and nothing else.
    let kind_ok = |ch: u64, k: u64| ch == 4 && k == 1;

    // (1) The untouched object verifies offline and decodes back to its fields.
    let got = envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &signed)
        .expect("a valid object failed to verify");
    println!(
        "(1) VERIFIED offline: channel={} kind={} effect={}",
        got.channel, got.kind, got.effect
    );

    // (2) A one-bit tamper anywhere in the bytes is rejected, fail-closed.
    let mut tampered = signed.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    match envelope::verify(cose::PROFILE_PUBLIC, &v, &kind_ok, &[], &tampered) {
        Ok(_) => fail("a tampered object verified (it should have been rejected)"),
        Err(e) => println!("(2) REJECTED tampered object: {:?}", e),
    }

    // (3) The genuine object under the WRONG public key is rejected at the signature check.
    let wrong_v = cose::MlDsa65Verifier(wrong_pk);
    match envelope::verify(cose::PROFILE_PUBLIC, &wrong_v, &kind_ok, &[], &signed) {
        Ok(_) => fail("an object verified under the wrong key (it should have been rejected)"),
        Err(e) => println!("(3) REJECTED wrong-key verification: {:?}", e),
    }

    // (4) A kind the channel validator does not admit is rejected before the signature is checked.
    let deny_kind = |_ch: u64, _k: u64| false;
    match envelope::verify(cose::PROFILE_PUBLIC, &v, &deny_kind, &[], &signed) {
        Ok(_) => fail("an unadmitted kind verified (it should have been rejected)"),
        Err(e) => println!("(4) REJECTED unadmitted kind: {:?}", e),
    }

    println!("OK: every offline-verification outcome was as expected");
}

fn fail(msg: &str) -> ! {
    eprintln!("naalp_verify: {}", msg);
    std::process::exit(1);
}
