<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# Conformance

`bash harness/run.sh` is the single command that grades the whole protocol. It composes three
gates, each backed by an independent authority — never the code under test.

## The three gates

1. **Two-implementation parity** (`scripts/verify.sh`): every non-circular oracle regenerates the
   committed corpus; Go and Rust both build/vet/test (`-race`) and produce **byte-identical**
   COSE_Sign1 and object-envelope bytes; no vector drift.
2. **CDDL conformance** (`scripts/cddl_check.sh`): `spec/naalp-draft-00.cddl` is well-formed in the
   Bormann `cddl` tool and **validates the committed vectors** against their production, rejecting
   cross-rule mismatches.
3. **Registry drift** (`scripts/registry_drift.py`): the machine-readable registries stay
   consistent with the graded vectors.

## Non-circular oracles

Every graded construction's expected values come from an independent authority:

| construction | authority |
|---|---|
| deterministic CBOR / content id | RFC 8949 §4.2.1 + FIPS 180-4 SHA-384 KAT |
| COSE_Sign1 / ML-DSA / Ed25519 | RFC 9052 §4.4 + NIST ACVP keyGen KAT + RFC 8032 |
| signer id | multiformats multibase/multihash/multicodec constructor |
| effect authorization | N-PAMP Bridge SafetyLabel + an independent lattice matrix |
| approval / consume ledger | a from-scratch compare-and-set hash-chain model |
| audit chain / causal graph | SHA-384 chain + an independent topological check |
| stream commitment | an independent rolling-SHA-384 constructor |
| carriage octet-exactness | each foreign protocol's own bytes + round-trip identity |
| channel surfaces | an independent transcription of the frozen channel table |
| federated reconcile | an independent deterministic causal-merge model |

## Two-implementation byte parity

Every construction carrying a security or interoperability claim is demonstrated by two
independent implementations (Go + Rust) producing byte-identical output. This is the strongest
interoperability evidence N-AALP offers and is run in CI (`.github/workflows/conformance.yml`).

See the harness overview in `harness/README.md`.
