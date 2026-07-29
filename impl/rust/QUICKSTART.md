<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Rust SDK

The Rust reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — one of the two
primary references (Go and Rust produce byte-identical output for every construction). Every
N-AALP object is a deterministically-encoded CBOR structure signed with COSE that carries, under
one signature, its content identity, its signer, a closed effect label, optional approval/audit
bindings, and its causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `envelope::Object` + `envelope::sign` / `envelope::verify`.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) via `fips204`, and
  Ed25519 via `ed25519-dalek`, in COSE_Sign1 (`cose`).
- **The byte-level primitives** — deterministic CBOR + content id (`cbor`), self-certifying
  identity (`identity`), effect + authorization (`policy`), the spine record bodies (`approval`,
  `audit`, `delivery`, `streaming`, `carriage`), causal + federation ordering, the transport
  boundary (`transport`), and the twenty-channel registry (`channels`).

Every construction is graded byte-for-byte against the shared conformance corpus (Go == Rust ==
oracle), and the reference worked object is reproduced exactly.

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `transport::emit`.

## Install

```sh
cargo add naalp        # from crates.io
```

## Sign and verify an object

```rust
use naalp::cbor::Value;
use naalp::cose::{self, MlDsa65Signer, MlDsa65Verifier};
use naalp::envelope::{self, Object};

fn main() {
    let seed = [0x2au8; 32];                       // a real 32-byte key seed in production
    let (pk, sk) = cose::mldsa65_keypair_from_seed(&seed);

    // In production, `signer` is identity::signer_id(cose::ALG_MLDSA65, &pk_bytes)
    // as UTF-8 bytes; it must equal the protected-header copy that sign() writes.
    let mut o = Object {
        id: vec![], kind: 1, channel: 4, tier: 0, signer: b"SIGNER_A".to_vec(),
        created: 1785000000000, effect: 2, causes: vec![], profile: cose::PROFILE_PUBLIC as u64,
        body: Value::Map(vec![(Value::Uint(1), Value::Tstr("hello".into()))]),
        ext: None, cext: None,
    };
    let signed = envelope::sign(&mut o, &MlDsa65Signer(sk));

    let accept = |ch: u64, k: u64| ch == 4 && k == 1;
    let _obj = envelope::verify(cose::PROFILE_PUBLIC, &MlDsa65Verifier(pk), &accept, &[], &signed)
        .expect("verifies offline");
}
```

(See `examples/naalp_envelope.rs` for the exact, runnable version.)

## Run the examples and tests

```sh
cd impl/rust
cargo run --example naalp_envelope
cargo test                              # conformance + KAT tests (Go == Rust == oracle)
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
./harness/runner/naalp-conform run --testee "./harness/adapters/rust/target/release/naalp-adapter-rust"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
