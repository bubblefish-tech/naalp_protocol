// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

//! Emits the worked-example N-AALP object as one line of lowercase hex: the whole
//! COSE_Sign1 the reference produces from the fixed 0x2a seed for the Governance
//! Approval object (channel 0x0004, kind 1). The Go half is
//! cmd/naalp-worked-example; both must produce the same bytes as
//! vectors/worked/example.json. scripts/record_cross_port_objects.py runs this and
//! records the bytes it prints; the cross-port object gate compares them to the
//! pinned authority. This prints ONLY the hex so the recorder reads it unambiguously.

use fips204::traits::SerDes;
use naalp::cbor::Value;
use naalp::cose;
use naalp::envelope::{self, Object};
use naalp::identity;

fn main() {
    let seed = [0x2au8; 32];
    let (pk, sk) = cose::mldsa65_keypair_from_seed(&seed);
    let pk_bytes = pk.clone().into_bytes().to_vec();
    let signer_id = identity::signer_id(cose::ALG_MLDSA65, &pk_bytes).expect("signer id");

    // The approval body: content id of the approved args, the signer, granted effect
    // 2, an 8-byte nonce, and an expiry -- identical to the Go worked example.
    let args_id = hex::decode(
        "20304e8abef02897dcc39231d926feb79b34534c6d474cd49a5b4dec2cc2cce90d251eef7418782006d829bd7f30ae8626ff",
    )
    .expect("args id hex");
    let approval_body = Value::Map(vec![
        (Value::Uint(1), Value::Bstr(args_id)),
        (Value::Uint(2), Value::Tstr(signer_id.clone())),
        (Value::Uint(3), Value::Uint(2)),
        (Value::Uint(4), Value::Bstr(vec![1, 2, 3, 4, 5, 6, 7, 8])),
        (Value::Uint(5), Value::Uint(1785000000000)),
    ]);

    let mut o = Object {
        audience: String::new(),
        suite: 0,
        id: vec![],
        kind: 1,    // Governance Approval
        channel: 4, // Governance (0x0004)
        tier: 0,
        signer: signer_id.into_bytes(),
        created: 1785000000000,
        effect: 2, // non_idempotent_write
        causes: vec![],
        profile: cose::PROFILE_PUBLIC as u64,
        body: approval_body,
        ext: None,
        cext: None,
    };
    let signed = envelope::sign(&mut o, &cose::MlDsa65Signer(sk));
    println!("{}", hex::encode(signed));
}
