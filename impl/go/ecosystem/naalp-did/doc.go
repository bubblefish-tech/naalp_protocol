// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

// Package naalpdid bridges an N-AALP signer's public key (design.md §5.1,
// impl/go/identity/identity.go) to a did:jwk decentralized identifier (E4.1: DID/VC
// interoperability for N-AALP signer identities), per the grounded recommendation
// documented under design.md addendum E4.1 §(d). It is purely additive: no
// wire format, CDDL, conformance vector, or corpus file is touched. It reimplements no
// cryptography — every function here is deterministic encoding/decoding of key bytes
// already produced or consumed elsewhere in this tree (cose.Signer/Verifier,
// identity.SignerID, identity.ForeignLinkRecord).
//
// # Grounding (primary sources fetched and read this session, 2026-08-31)
//
//   - did:jwk method construction: https://raw.githubusercontent.com/quartzjer/did-jwk/main/spec.md
//     (also mirrored at https://github.com/quartzjer/did-jwk) — an informal
//     community specification (single-maintainer repo), NOT a W3C or DIF ratified
//     document (confirmed absent from any formal adoption listing this session). Its
//     construction rule (§"DID Format"/"Create"): base64url-encode the UTF-8 JWK JSON,
//     prefix "did:jwk:"; no canonicalization (e.g. JCS) is required.
//   - ML-DSA JWK/COSE key representation: RFC 9964, "ML-DSA for JSON Object Signing and
//     Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)",
//     https://www.rfc-editor.org/rfc/rfc9964.html — IETF Standards Track, published May
//     2026. Confirmed THIS SESSION by downloading the raw RFC text
//     (rfc-editor.org/rfc/rfc9964.txt) directly and reading it, not by AI-summarized
//     fetch: it registers the JOSE "kty":"AKP" key type (§3, §8.1.5.1) and the JWK
//     parameters "pub" (§8.1.6.1, REQUIRED, public key bytes) and "priv" (§8.1.6.2, MUST
//     NOT be present in a public key), with "alg" values "ML-DSA-44"/"ML-DSA-65"/"ML-DSA-87"
//     (§8.1.4.1-3) and matching COSE algorithm ids -48/-49/-50 (Figure 2) — the JOSE/COSE
//     ids -49/-50 for ML-DSA-65/87 are the SAME integers impl/go/cose already uses
//     (cose.AlgMLDSA65 = -49, cose.AlgMLDSA87 = -50), confirming N-AALP's existing
//     algorithm constants already track the RFC 9964 registration. RFC 9964's own Table 1
//     gives the ML-DSA public-key sizes this package's length checks enforce: ML-DSA-65 =
//     1952 bytes, ML-DSA-87 = 2592 bytes (matching mldsa65.PublicKeySize /
//     mldsa87.PublicKeySize from the same circl package cose.go already imports).
//   - Ed25519 JWK (OKP) representation: RFC 8037, "CFRG Elliptic Curve Diffie-Hellman
//     (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)",
//     https://www.rfc-editor.org/rfc/rfc8037.html (downloaded and read as raw text this
//     session) — Appendix A.1's public-key-only example gives {"kty":"OKP",
//     "crv":"Ed25519","x":base64url(pubkey)}.
//
// # Honest, named gap (not a blocker, tracked forward per E4.1 scope)
//
// The did:jwk METHOD ITSELF (the DID scheme, not the ML-DSA cryptographic
// representation it carries) has no formal W3C/DIF ratification as of this session — it
// remains a community convention with multiple independent implementations. This is the
// SAME gap the grounding note names and accepts: did:jwk's genuine weakness is its
// DID-method-level informality, traded for the fact that its PQ path (RFC 9964) is
// already Standards Track, unlike did:key's competing multicodec/Data-Integrity route,
// which is blocked on two separate not-yet-ratified artifacts. This package does not
// paper over that gap; ToDIDJWK/FromDIDJWK implement exactly the did:jwk spec's own
// documented Create/Read steps, nothing more.
//
// There is NO gap on the cryptographic (ML-DSA JWK "kty":"AKP") side: RFC 9964 is
// published and covers all three ML-DSA parameter sets N-AALP could ever use, so this
// package implements the full ML-DSA-65/ML-DSA-87 path (identity.go's supported
// algorithms), not a placeholder.
package naalpdid
