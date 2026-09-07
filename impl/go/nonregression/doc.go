// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package nonregression carries the N-AALP non-regression guard (T2.1;
// coding-instructions §2). N-AALP is built to hold three core properties, and each can
// quietly regress. This package's tests NAME the three regression modes and fail if any occurs:
//
//	(1) SESSION-TOKEN-CANNOT-AUTHORIZE — a transport/session/foreign/client token must
//	    never satisfy object authorization; only a signature-derived principal can
//	    (identity-as-authority; §2 item 1, R-6.5).
//	(2) NO-CLASSICAL-ONLY-ON-GOVERNED-TIER — no downgrade may select a classical-only
//	    signature suite on a governed N-AALP profile; a post-quantum floor holds at every
//	    profile (§2 item 2, R-4.2/R-4.3/R-15.3; PLAN D-CRYPTO "no classical-only anywhere").
//	(3) NO-JSON-CANONICALIZER-ON-SIGNING-PATH — the signed input is deterministic CBOR
//	    only; no JSON/JSON-LD canonicalizer sits on any signing path (§2 item 3, R-2.1).
//
// There is no production code here — the guard is the tests. The file exists so the
// package builds and vets as a real package.
package nonregression
