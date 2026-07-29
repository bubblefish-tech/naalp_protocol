<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Swift SDK

The Swift reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents. SwiftPM package, module `Naalp`. Every
N-AALP object is a deterministically-encoded CBOR structure signed with COSE that carries, under
one signature, its content identity, its signer, a closed effect label, optional approval/audit
bindings, and its causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `Envelope.Object` + the assembly surface (`Envelope.toBeSigned` /
  `Envelope.assembleSigned`) + `Envelope.verify`: build, content-id-bind, produce the exact
  signing input, assemble the tagged COSE_Sign1, and offline-verify a complete N-AALP object.
- **A real Ed25519 (RFC 8032) sign/verify leg** — `Envelope.signEd25519` / `Cose.coseVerify1` via
  swift-crypto: a genuine from-key round-trip on the COSE layer.
- **The byte-level primitives** — deterministic CBOR + content id (`Cbor`), self-certifying
  identity (`Identity`), effect + authorization (`Policy`), the spine record bodies (`Records`),
  causal + federation ordering (`Graph`), and the twenty-channel registry (`Channels`).

Every pure construction is byte-identical to the Go, Rust, and Python reference implementations;
the worked object in `vectors/worked/example.json` is the byte-level known-answer for the pure
surface.

## Crypto scope (PURE-ONLY)

SwiftDilithium 3.6.0 has **no deterministic-from-seed (NIST ACVP ξ) FIPS 204 path**, so this SDK
does **not** produce ML-DSA signatures. It exposes the ML-DSA-*agnostic* assembly surface
(`toBeSigned` / `assembleSigned`) so you can pair it with any external FIPS 204 signer while
keeping the exact object bytes, plus a real Ed25519 leg. In `verify`, the ML-DSA signature step is
**skip-tracked** — it throws `Unavailable` (an honest Unimplemented, never a false green); every
structural check (content-id, ranges, header/body copies, critical extensions, kind dispatch,
profile floor) is fully exercised regardless. Ed25519 is a classical (level-0) leg below every
profile floor, so a pure-Ed25519 object is rejected at `ProfileDowngrade` on the Sovereign/Public
floors — it is an interop/demo signature, not a production Sovereign one.

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `Records.transportEmit`.
- Deterministic ML-DSA signing (see Crypto scope). Bring an external FIPS 204 signer.

## Add the package

`impl/swift/Package.swift` defines the `Naalp` module (it depends on `swift-crypto`). Add it as a
SwiftPM dependency and import `Naalp`:

```swift
import Naalp
```

Or work with the reference package in place from the repo root:

```sh
swift build --package-path impl/swift
```

## Sign and verify an object (Ed25519 round-trip)

```swift
import Naalp

let seed = [UInt8](repeating: 0x2a, count: 32)          // a real 32-byte key seed in production
let pk   = try Cose.ed25519PublicKey(seed)
let sid  = try Identity.signerId(Cose.ALG_ED25519, pk)

var obj = Envelope.Object(kind: 1, channel: 4, signer: Array(sid.utf8),
                          created: 1785000000000, effect: 2,
                          body: .m([(.u(1), .t("hello"))]),
                          profile: UInt64(Cose.PROFILE_PUBLIC))

let signed = try Envelope.signEd25519(&obj, seed)       // tagged COSE_Sign1 bytes
let ok     = try Cose.coseVerify1(Cose.ALG_ED25519, pk, signed)   // true
```

For an ML-DSA object, build the `Object`, take `Envelope.toBeSigned(&obj, Cose.ALG_MLDSA65)`, have
your external FIPS 204 signer sign those exact bytes, then `Envelope.assembleSigned(&obj,
Cose.ALG_MLDSA65, signature)` — the object bytes are identical to what Go/Rust/Python produce.

## Run the example and tests

```sh
swift run  -c release --package-path impl/swift naalp-example   # Ed25519 round-trip + ML-DSA worked object
swift test            --package-path impl/swift                 # worked-example byte KAT
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness.
The Swift toolchain is provided in CI, where the adapter is built and graded against the shared
corpus; the pure ops and Ed25519 are graded, and the ML-DSA crypto ops report an honest `skipped`
(Unimplemented for Swift by design, like PHP — never a failure):

```sh
./harness/runner/naalp-conform run --testee "harness/adapters/swift/.build/release/naalp-adapter"
```

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
