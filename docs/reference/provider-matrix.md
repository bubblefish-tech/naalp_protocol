<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Signature algorithm and profile matrix

N-AALP's own cryptographic weight is a **single object signature** — the heavy ML-KEM key
exchange that secures a transport session is N-PAMP's concern and never lands on an N-AALP
object (the draft's Cryptographic Constructions section). Every N-AALP object is signed exactly once with **COSE_Sign1** (RFC
9052), and algorithm agility is carried entirely in COSE's `alg` header parameter (the draft's Cryptographic Constructions section): changing the signature suite changes the `alg` value and the key type, with no change
to the COSE_Sign1 construction or the envelope. This page is the suite → algorithm → profile →
status matrix; it does not repeat the composite construction's byte-level detail, which lives
in [crypto agility and migration](../spec/crypto-agility.md).

## Algorithm registry

| Algorithm | COSE `alg` | Security level | Role | Source |
|---|---|---|---|---|
| ML-DSA-87 | `-50` | 5 | post-quantum signature | FIPS 204; COSE identifier RFC 9964 |
| ML-DSA-65 | `-49` | 3 | post-quantum signature | FIPS 204; COSE identifier RFC 9964 |
| ML-DSA-44 | `-48` | 2 | post-quantum signature, edge/light tier only | FIPS 204; COSE identifier RFC 9964 |
| Ed25519 | `-19` | 0 (classical) | opt-in composite leg only, never standalone | RFC 9864 §2.2 (also RFC 9053) |
| the opt-in composite | `-65537` (provisional, private-use) | 3 (PQ leg) | ML-DSA-65 + Ed25519, LAMPS composite | N-AALP private-use allocation pending an IANA composite code point (the draft's Cryptographic Constructions section) |

These five rows are exactly the algorithm identifiers `impl/go/cose/cose.go` declares
([`AlgMLDSA65`, `AlgMLDSA87`, `AlgEd25519`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L22-L26),
[`AlgComposite65Ed25519` / `AlgComposite44Ed25519`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L433-L435))
and the security levels its `algLevel` function returns for each
([cose.go:60-75](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L60-L75)).
`AlgComposite44Ed25519` (the edge-suite composite) is a **reserved** registry entry only — it is
registered but not implemented or graded this wave.

## The profile table

One wire, one construction, one parameter row per profile (the draft's Cryptographic Constructions section). The
profile is bound under the signature (envelope field 9 plus the protected header), so
stripping or downgrading it invalidates the object:

| Property | Public (1) | Enterprise (2) | Sovereign (3) |
|---|---|---|---|
| Default signature | ML-DSA-65 (`-49`) | ML-DSA-65 (`-49`) | ML-DSA-87 (`-50`) |
| Minimum signature level accepted | 3 | 3 | 5 (refuses below) |
| Opt-in composite (Ed25519 + ML-DSA) | permitted | permitted | **refused** |
| Digest | SHA-384 | SHA-384 | SHA-384 or stronger |
| Composes with N-PAMP profile | Standard / High | High | Sovereign |

`impl/go/cose/cose.go`'s
[`profileMinLevel`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L77-L85)
is the profile floor enforced at verify time: Sovereign requires level 5 and refuses anything
below (`ErrProfileDowngrade`); Public and Enterprise both require at least a level-3
post-quantum signature — **no profile has a classical-only default**. A Sovereign
verifier additionally refuses any composite (non-pure) object outright
([`Verify1`, cose.go:291-320](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L291-L320),
`ErrCompositeRefused`), because CNSA 2.0 mandates ML-DSA-87 with no classical leg for
national-security signatures (the draft's Cryptographic Constructions section).

ML-DSA-44 (level 2, COSE `-48`) is licensed only in an explicitly negotiated edge/constrained
deployment outside these three editions — never as a silent downgrade of Public, Enterprise,
or Sovereign (the draft's Cryptographic Constructions section).

## Status column

| Suite | Public | Enterprise | Sovereign | Status |
|---|---|---|---|---|
| ML-DSA-65 (pure) | default (MTI) | default (MTI) | refused (below floor) | implemented, graded |
| ML-DSA-87 (pure) | permitted | permitted | default (MTI) | implemented, graded |
| ML-DSA-44 (pure) | edge-only | edge-only | refused | registered; edge-tier only, outside the three editions |
| Ed25519 + ML-DSA-65 composite (`COMPSIG-MLDSA65-Ed25519-SHA512`) | permitted (opt-in) | permitted (opt-in) | **refused** | implemented, graded — the ten-port composite wave |
| Ed25519 + ML-DSA-44 composite (`COMPSIG-MLDSA44-Ed25519-SHA512`) | — | — | — | reserved (registered, not implemented) |
| SLH-DSA (FIPS 205) | — | — | — | reserved for the future (the draft's Cryptographic Constructions section) — a hash-based alternative to hedge the lattice monoculture, no envelope change needed to add it |

"MTI" (mandatory-to-implement) marks the suite every conformant implementation must support at
that profile; "default" marks what a signer emits absent an explicit suite selection. Which
suite signed a given object is carried under the signature itself as a **signed suite
declaration** (naalp-object field 14, present iff the composite algorithm id is in use), so
turning the composite on — or changing the default suite later — is a suite-id change through
the registry, never a wire break (the draft's Cryptographic Constructions section).

## The opt-in composite, briefly

The composite is **one** COSE_Sign1 whose signature value is the IETF LAMPS composite of an
ML-DSA-65 signature and an Ed25519 signature over a domain-separated message representative —
not two independent signatures (the draft's Cryptographic Constructions section). It exists for two reasons: bridging a
classical peer during migration, and as the pre-declared fallback path should ML-DSA ever be
weakened. `impl/go/cose/cose.go` implements both directions:

- [`SignHybrid`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L321-L358) —
  the two-signature COSE_Sign (tag 98) form used for identity rotation objects (§5.2), not the
  object-signature composite.
- [`CompositeSigner.Sign` / `CompositeVerifier`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/cose/cose.go#L469-L509) —
  the actual LAMPS composite object signature: `ComputeMprime` builds the domain-separated
  representative, the ML-DSA-65 leg signs it deterministically (`rnd = 0`) with context set to
  the suite label, and the Ed25519 leg signs it with no context.

Pure ML-DSA is SUF-CMA (strongly unforgeable); the composite is EUF-CMA but not SUF-CMA. This
is never load-bearing for N-AALP's own security properties, because the single-use consume
ledger keys off the content id and receipt chain, not raw signature bytes (the draft's Cryptographic Constructions section).

## Digests

Every digest in the spine — content id, stream commitment, receipt chain — is SHA-384 or
stronger, carried as a multihash so the algorithm is self-described and can be raised
without a wire change (the draft's Cryptographic Constructions section). No profile admits a hash below SHA-384.

## Signer identity depends on the algorithm

A signer's id is derived from its public key through a per-algorithm multicodec
(`impl/go/identity/identity.go`,
[`multicodecFor`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L47-L60),
[`SignerID`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L75-L93)):
ML-DSA-87 uses multicodec `0x1212`, ML-DSA-65 its own ML-DSA-65 multicodec, and Ed25519 `0xed`.
A composite signer gets a distinct derivation
([`CompositeSignerID`](https://github.com/bubblefish-tech/naalp_protocol/blob/main/impl/go/identity/identity.go#L94-L114))
binding both component public keys, so a composite identity is never confusable with a pure
ML-DSA identity holding the same ML-DSA key. See [identity and key lifecycle](../spec/object-model.md)
for the full derivation and rotation model.

## Failure modes

| Error kind | When |
|---|---|
| `ProfileDowngrade` | signature level is below the verifying profile's floor |
| `UnknownAlg` | the COSE `alg` value is not in the N-AALP registry |
| `HybridIncomplete` | the composite is present but either component signature fails to verify |
| `KeyAlgMismatch` | the key's algorithm does not match the object's declared header |
| `SuiteMismatch` | the signed suite declaration (field 14) disagrees with the actual signature structure or `alg` |
| `CompositeRefused` | a Sovereign verifier receives a composite (non-pure) object |

Every check is fail-closed (the draft's Security Considerations section): a failing object is rejected whole, returns its
named error, and causes no state change.

## What this page does not cover

- **Per-language ML-DSA library sourcing.** Unlike N-PAMP's KEM provider survey, this page does
  not audit which third-party library each of the ten SDKs uses to implement ML-DSA — that is
  a ten-port parity question tracked in the SDK build ledger, not a protocol-level algorithm
  choice. All ten ports are graded against the same non-circular oracle regardless of which
  underlying library each language binds.
- **The composite's byte-level construction** (the exact `M'` formula, the LAMPS label octets,
  the concatenation order). That detail, including the primary-source re-verification date, is
  authoritative in [crypto agility and migration](../spec/crypto-agility.md) and the draft's Cryptographic Constructions section.

See also: [the object model](../spec/object-model.md), [crypto agility and migration](../spec/crypto-agility.md).
