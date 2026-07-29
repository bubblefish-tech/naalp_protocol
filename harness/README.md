<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# N-AALP conformance harness

`bash harness/run.sh` is the single command that grades the whole protocol. It composes three
gates, each backed by an independent authority (never the code under test):

| gate | script | what it proves |
|---|---|---|
| two-implementation parity | `scripts/verify.sh` | every non-circular oracle regenerates the committed corpus; Go and Rust both build/vet/test (`-race`) and produce **byte-identical** COSE_Sign1 and object-envelope bytes (R-16.2); no vector drift |
| CDDL conformance | `scripts/cddl_check.sh` | `spec/naalp-draft-00.cddl` is well-formed in the Bormann `cddl` tool and **validates the committed vectors** against their production (10 positive), rejecting cross-rule mismatches (3 negative) |
| registry drift | `scripts/registry_drift.py` | the machine-readable registries (`vectors/registry/*.csv`) stay consistent with the graded vectors — signatures, multicodec, all 65 channel kinds (both directions), carriage protocol ids |

## Non-circular oracles

Every graded construction's expected values come from an independent authority (R-16.1):

| construction | authority (in `tools/*_oracle.py`) |
|---|---|
| deterministic CBOR / content-id | RFC 8949 §4.2.1 + FIPS 180-4 SHA-384 KAT |
| COSE_Sign1 / ML-DSA / Ed25519 | RFC 9052 §4.4 + NIST ACVP keyGen KAT + RFC 8032 |
| signer id | multiformats multibase/multihash/multicodec constructor |
| effect authorization | N-PAMP Bridge SafetyLabel + an independent lattice matrix |
| approval / consume ledger | a from-scratch compare-and-set hash-chain model |
| audit chain / causal graph | SHA-384 chain + an independent topological check |
| delivery.update | independent CBOR body constructor |
| stream commitment | an independent rolling-SHA-384 constructor |
| carriage octet-exactness | each foreign protocol's own bytes + round-trip identity |
| channel surfaces | an independent transcription of the frozen channel table (65 kinds) |
| federated reconcile | an independent deterministic causal-merge model |

## Toolchain

Go (`go 1.24`+, `GOWORK=off`), Rust (`cargo`), Python 3 (oracles + drift check, stdlib only),
Ruby + the Bormann `cddl` gem (CDDL validation). The same commands run in CI
(`.github/workflows/conformance.yml`).
