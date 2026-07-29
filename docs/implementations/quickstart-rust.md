<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Rust quickstart

Sign and verify an N-AALP object with the Rust reference implementation.

```rust
use naalp::cbor::Value;
use naalp::{channels, cose, envelope};

fn main() {
    // 1. A signing key (use a real 32-byte seed in production).
    let (pk, sk) = cose::mldsa65_keypair_from_seed(&[0u8; 32]);
    use fips204::traits::SerDes;
    let signer_bytes = pk.clone().into_bytes().to_vec();
    let (verifier, signer) = (cose::MlDsa65Verifier(pk), cose::MlDsa65Signer(sk));

    // 2. Build a Control/Hello object (channel 0x0000, kind 0, read_only, Public profile).
    let mut obj = envelope::Object {
        id: vec![],
        kind: 0,        // Hello
        channel: 0,     // Control
        tier: 0,
        signer: signer_bytes,
        created: 1_785_000_000_000,
        effect: 0,      // read_only
        causes: vec![],
        profile: cose::PROFILE_PUBLIC as u64,
        body: Value::Tstr("hello".into()),
        ext: None,
        cext: None,
    };

    // 3. Sign.
    let signed = envelope::sign(&mut obj, &signer);

    // 4. Verify offline against the channel-surface kind validator.
    let kind_ok = |ch: u64, k: u64| channels::kind_validator(ch, k);
    let got = envelope::verify(cose::PROFILE_PUBLIC, &verifier, &kind_ok, &[], &signed)
        .expect("verifies; any tamper or wrong effect is a named error, fail-closed");
    println!("verified: channel={} kind={} effect={} bytes={}",
        got.channel, got.kind, got.effect, signed.len());
}
```

Run the tests:

```console
$ cd impl/rust && cargo test
$ bash scripts/verify.sh          # from the repo root: Go == Rust byte parity
```
