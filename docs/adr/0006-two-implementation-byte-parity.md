<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# 0006 — Two independent implementations, byte-identical

- Status: accepted
- Date: 2026-07-27

## Context

A specification whose only evidence is one implementation cannot prove interoperability: two
parties might each build against the prose and disagree on the bytes. And an implementation graded
only against its own output proves nothing (a circular oracle).

## Decision

Every construction carrying a security or interoperability claim is demonstrated by **two
independent implementations from different language runtimes** (Go and Rust) producing
**byte-identical** output, each cross-validated against an **independent, non-circular oracle**
whose expected values come from the relevant RFC, FIPS, or NIST vector or a from-scratch
constructor — never from the code under test. The CDDL module is machine-validated against the
committed vectors.

## Consequences

Byte-parity is the strongest interoperability evidence N-AALP offers and is enforced in CI. The
deterministic ML-DSA variant (rnd = 0) is required so signatures are byte-identical across
implementations. Additional-language SDKs are graded against the same corpus through a shared
conformance-adapter contract, so adoption does not weaken the parity guarantee.
