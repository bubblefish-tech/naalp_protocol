<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP Ruby SDK

The Ruby reference implementation of **N-AALP** (draft-bubblefish-naalp-00) — an
application-layer object protocol for autonomous agents. Every N-AALP object is a
deterministically-encoded CBOR structure signed with COSE that carries, under one signature, its
content identity, its signer, a closed effect label, optional approval/audit bindings, and its
causal derivation — **verifiable offline, over any transport.**

## What this SDK provides

- **The full object envelope** — `Naalp::Envelope::Object` + `Naalp.sign` / `Naalp.verify`: build,
  content-id-bind, deterministically sign, and offline-verify a complete N-AALP object.
- **Post-quantum signatures** — deterministic ML-DSA-65/-87 (FIPS 204, rnd=0) and Ed25519
  (RFC 8032), in COSE_Sign1 (`Naalp::COSE`).
- **The byte-level primitives** — deterministic CBOR + content id (`Naalp::CBOR`), self-certifying
  signer id (`Naalp::Identity`), the effect lattice + authorization (`Naalp::Policy`), the spine
  record bodies — approval, receipt, delivery, stream, carriage, transport boundary
  (`Naalp::Records`), causal verify + federation reconcile (`Naalp::Graph`), and the twenty-channel
  registry (`Naalp::Channels`).

Every construction is **graded byte-for-byte** against the shared conformance corpus
(== Go == Rust == Python); the reference worked object is reproduced exactly
(`test/worked_example_test.rb`).

## What this SDK does NOT provide

- A transport. N-AALP objects are transport-independent; carry them over N-PAMP, QUIC, WebSocket,
  or HTTP with your own client. The confidentiality boundary is `Naalp::Records.transport_emit`.
- A bundled cryptographic library. The crypto leg (ML-DSA, Ed25519, SHA-2) is provided by the
  **platform OpenSSL** (≥ 3.5) through Ruby's stdlib `openssl` binding — no native-extension gems
  and no C toolchain are needed. On an older OpenSSL (< 3.5, no ML-DSA provider) the ML-DSA path
  raises and the tests/adapter skip it loudly (never a false green); pure ops and Ed25519 still run.

## Install

```sh
gem build naalp.gemspec && gem install ./naalp-0.1.0.gem
```

Or use it straight from a checkout with `ruby -Ilib` (as the example and tests below do).

- **Ruby ≥ 3.1** (developed and graded on Ruby 4.0.5).
- **OpenSSL ≥ 3.5** as the `openssl` binding's backend (supplies ML-DSA-65/-87 and Ed25519).
  Everything else (deterministic CBOR, SHA-384/256, base32, the record bodies, the channel table,
  the causal graph) is pure Ruby stdlib. Check it: `ruby -ropenssl -e 'puts OpenSSL::OPENSSL_VERSION'`.

## Layout (gem)

```
impl/ruby/
  naalp.gemspec       # the package manifest (spec.name "naalp", require_paths ["lib"])
  lib/
    naalp.rb          # require this — loads the whole SDK + the ergonomic facade
    naalp/
      cbor.rb         # C1  deterministic CBOR encode/strict-decode + content_id
      cose.rb         # C2  COSE_Sign1 signing input/object + ML-DSA + Ed25519 + profile floors
      envelope.rb     # C3  the full Object + sign + verify
      identity.rb     # C4  signer_id (multiformats) + require_nfc
      policy.rb       # C5  effect normalize / authorize / safety-label bytes
      records.rb      # C6-C9,C11-C12 approval, ledger, receipt, delivery, stream, carriage, transport
      graph.rb        # causal verify + deterministic reconcile + reconcile record
      channels.rb     # C10 the 20-channel / 65-kind registry
  examples/sign_object.rb
  test/{worked_example_test.rb,conformance_test.rb}
```

## Sign and verify an object

```ruby
require "naalp"
include Naalp::CBOR

seed = ("\x00" * 32).b                              # a real 32-byte key seed in production
alg  = Naalp::COSE::ALG_MLDSA65
pk   = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
sid  = Naalp::Identity.signer_id(alg, pk)

body   = M.new([[U.new(1), T.new("hello")]])
obj    = Naalp.object(kind: 1, channel: 4, signer: sid.b,
                      created: 1785000000000, effect: 2, body: body)
signed = Naalp.sign(obj, alg, seed)                 # a self-describing signed object (bytes)
got    = Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, alg, pk, ->(c, k) { [c, k] == [4, 1] }, signed)
```

## Run the example

```sh
ruby -Ilib examples/sign_object.rb
# signer   bciq...
# signed   <N> bytes, verifies=true
# tampered rejected: BadSignature
```

## Run the tests

```sh
ruby -Ilib test/worked_example_test.rb   # the full-object byte KAT (reproduces signed_object_hex)
ruby -Ilib test/conformance_test.rb      # standards-anchored primitives smoke suite
```

Cross-language conformance (the authoritative grade) runs the adapter through the shared harness:

```sh
./harness/runner/naalp-conform.exe run --testee "ruby harness/adapters/ruby/adapter.rb"
# RESULT: PASS (239 graded, 0 unimplemented/skipped)
```

The Ruby SDK implements **every** op, including the crypto leg (`mldsa.keygen`, `ed25519.sign`,
`cose.sign1`), because the platform OpenSSL provides deterministic ML-DSA and Ed25519.

## Notes on byte-exactness

- **Deterministic CBOR** (RFC 8949 §4.2.1): shortest-form integer heads, no indefinite lengths,
  map keys sorted by their *encoded* bytes (bytewise ascending), duplicate keys rejected. The
  strict decoder rejects out-of-order keys, non-shortest integers (e.g. `0x1800`), indefinite
  lengths (`0x9f…0xff`), duplicate keys, and trailing bytes.
- **content_id** = `0x20 0x30 || SHA-384(body)` (multihash sha2-384, 48-byte length), computed over
  the object body **without** field 1 (the id itself).
- **signer_id** = `"b" || base32-lower-nopad( 0x12 0x20 || SHA-256( uvarint(multicodec) || pubkey ) )`
  with multicodec ed25519-pub `0xed`, mldsa-65-pub `0x1211`, mldsa-87-pub `0x1212`.
- **Deterministic ML-DSA** uses OpenSSL's seed-only PKCS#8 (`[0]` seed CHOICE) so the seed expands
  to the same key material as the NIST ACVP `keyGen`, plus the signature parameter
  `deterministic=1` (FIPS 204 rnd = 32 zero bytes) so signatures match the other references.

## License

Apache-2.0 — see the repository `LICENSE.md` and `NOTICE`. The Internet-Draft is additionally
under the IETF Trust's BCP 78.
