<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Rust examples — two-agent quickstart

Runnable examples for the N-AALP Rust SDK. The headline one is `naalp_quickstart`: the
core sign → send → verify loop between two agents, end to end, with **no hand-rolled crypto**.

## Prerequisites

- A Rust toolchain (stable). Verify with `rustc --version` / `cargo --version`.
- From the SDK directory `impl/rust/` (this file's parent's parent).

No other setup: the SDK depends only on published crates (`fips204`, `ed25519-dalek`,
`sha2`, `unicode-normalization`, `data-encoding`), fetched by cargo on first build.

## Run the two-agent quickstart

```sh
cd impl/rust
cargo run --example naalp_quickstart
```

### What it does

1. **Agent A generates an identity** — a deterministic ML-DSA-65 keypair from a 32-byte
   seed, plus its self-certifying signer id (a pure function of the public key).
2. **Agent A builds and signs a message** on the Interaction surface (channel `15`,
   kind `1` = `Respond`), producing a real deterministic-CBOR + COSE_Sign1 envelope.
3. **Agent B verifies it offline** — given only the envelope bytes and Agent A's public
   key (no network, no issuer callback) — reads the message, and confirms Agent A's signer
   id is bound to the key that signed.
4. **Tamper is rejected, fail-closed** — one flipped bit makes verification fail with a
   named error. The program `exit`s non-zero if any step differs from the expected outcome,
   so it doubles as a self-checking smoke test: if verification were bypassed, the tamper
   step would not reject and the run would fail.

Every crypto step goes through the SDK's ergonomic layer (`naalp::easy`), which delegates to
the same primitives (`naalp::cose`, `naalp::identity`, `naalp::envelope`, `naalp::channels`)
that the cross-language conformance corpus grades byte-for-byte.

### Expected output

```
N-AALP two-agent quickstart

[Agent A] generated identity
          signer id : bciqi6sj436d3ft6lgoghdddlsgxtp22vph2jbqd7gvvchz6ecr7mvdi
          public key: 1952 bytes (ML-DSA-65)

[Agent A] signed a Respond object on channel 15 (Interaction), effect idempotent_write
          envelope  : 3548 bytes (deterministic CBOR + COSE_Sign1)
          --> sends the envelope bytes + its public key to Agent B

[Agent B] VERIFIED offline (no network, no issuer callback)
          channel 15 (Interaction), kind 1 (Respond), effect idempotent_write
          message   : hello from Agent A
          signer id : bciqi6sj436d3ft6lgoghdddlsgxtp22vph2jbqd7gvvchz6ecr7mvdi (self-certifying: bound to the key)

[Agent B] REJECTED a tampered object, fail-closed: Error { kind: "BadSignature", msg: "signature verification failed" }

OK: signed, verified offline, and rejected tampering — using the real SDK.
```

The signer id and byte length above are deterministic (the example uses a fixed seed).

## The ergonomic layer this uses

`naalp::easy` collapses the common paths to one well-named call each. It adds no
cryptography and no second encoding — it composes the raw SDK:

```rust
use naalp::cbor::Value;
use naalp::easy;

let alice = easy::Signer::from_seed(&[0x0a; 32]);          // identity from a 32-byte seed
let env = alice.sign(0x000F, 1, Value::Tstr("hi".into()))?; // sign Interaction/Respond
let v = easy::verifier_from_public_key(alice.public_key())?; // peer rebuilds a verifier
let obj = easy::verify(&v, &env)?;                           // verify offline, fail-closed
```

See the rustdoc on each `easy` item for exactly what it does. The command-line equivalent is
documented in [`../CLI.md`](../CLI.md).

## The other examples

| Example | Command | What it shows |
|---|---|---|
| `naalp_quickstart` | `cargo run --example naalp_quickstart` | the two-agent sign/verify loop (this file) |
| `naalp_verify` | `cargo run --example naalp_verify` | offline verify + four fail-closed rejections, on the raw `envelope` API |
| `naalp_envelope` | `cargo run --example naalp_envelope -- <seed-hex-32>` | prints the hex of a fixed worked object (cross-language byte-parity check) |
| `naalp_cose_sig` | `cargo run --example naalp_cose_sig -- <seed-hex-32>` | prints a COSE_Sign1 over a fixed payload (byte-parity check) |

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`.
