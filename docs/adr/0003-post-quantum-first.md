<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# 0003 — Post-quantum-first signatures

- Status: accepted
- Date: 2026-07-27

## Context

N-AALP objects — receipts, approvals, audit chains — are long-lived, non-repudiable records. A
classical-only signature on such a record is a latent forgery exposure: an adversary can store the
record now and forge a signature later once a cryptographically relevant quantum computer exists
(store-now-verify-later).

## Decision

The mandatory-to-implement signature is **ML-DSA** (FIPS 204), using the deterministic variant
(rnd = 0) so two implementations produce byte-identical signatures. An **optional Ed25519 hybrid**
(COSE_Sign, accepted only when both legs verify) provides defense-in-depth during the transition.
No classical-only default is permitted.

## Consequences

Long-lived records are safe against future quantum forgery. Signatures are large (≈3.3 KB for
ML-DSA-65), so streaming amortizes one signature over many chunks rather than signing each chunk.
The COSE algorithm identifiers reuse the existing IANA COSE registry; N-AALP defines no new COSE
code points. Algorithm agility is bound under the signature and checked against the profile floor,
so agility cannot become a downgrade.
