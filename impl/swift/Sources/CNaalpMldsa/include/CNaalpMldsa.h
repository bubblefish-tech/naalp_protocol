// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// C shim to swift-crypto's vendored BoringSSL ML-DSA (FIPS 204). Every ML-DSA operation the N-AALP
// SDK needs — deterministic (rnd=0) sign, keygen-from-seed, and verify — is routed through this
// shim rather than swift-crypto's public MLDSA65/87 Swift API, for two reasons:
//   1. The public sign API is HEDGED (a fresh randomizer per signature), which can never reproduce
//      a pinned FIPS-204 known-answer vector; only the vendored BoringSSL internal
//      BCM_mldsa{65,87}_sign_internal takes the 32-byte randomizer explicitly (passing 32 zero
//      bytes yields deterministic signing == the N-AALP composite oracle and the Go/Rust/... byte
//      consensus).
//   2. On Apple platforms swift-crypto's public MLDSA65/87 types are gated behind a recent OS
//      (Apple shipped system ML-DSA in macOS 26), so keygen/verify through the public API would
//      require an unacceptably high platform floor. The BoringSSL BCM_* entry points are raw C with
//      no OS-availability gate, so routing keygen and verify through them keeps the SDK buildable on
//      macOS 10.15+ while producing bytes byte-identical to the Linux grade (same BoringSSL backend).
// All BCM_* symbols are OPENSSL_EXPORT (default visibility) and declared inside `extern "C"` in
// bcm_interface.h; swift-crypto prefixes them to CCryptoBoringSSL_*, so a plain C extern resolves
// them from the CCryptoBoringSSL static archive the Crypto product links (proven to link + byte-
// match in CI, task #142).
#ifndef NAALP_CNAALPMLDSA_H
#define NAALP_CNAALPMLDSA_H

#include <stddef.h>
#include <stdint.h>

// Deterministic (rnd=0) ML-DSA-65 sign of `msg` with FIPS-204 context = `context`, regenerating the
// private key from the 32-byte `seed`. Writes the 3309-byte signature to `out_sig`. Returns
// ((from_seed_status << 8) | sign_status); each BoringSSL bcm_status is 0=approved / 1=not_approved
// (both success) / 2=failure, so a low byte of 2 means the sign call itself failed.
int naalp_mldsa65_det_sign(
    const uint8_t seed[32],
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context, size_t context_len,
    uint8_t out_sig[3309]);

// Deterministic (rnd=0) ML-DSA-87 sign; identical contract, 4627-byte signature.
int naalp_mldsa87_det_sign(
    const uint8_t seed[32],
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context, size_t context_len,
    uint8_t out_sig[4627]);

// FIPS-204 ML-DSA-65 keygen: derive the raw 1952-byte encoded public key deterministically from the
// 32-byte `seed` (xi). Writes to `out_pub`. Returns the BoringSSL bcm_status (0=approved /
// 1=not_approved are success, 2=failure), so a return of 2 means keygen failed.
int naalp_mldsa65_pubkey_from_seed(const uint8_t seed[32], uint8_t out_pub[1952]);

// FIPS-204 ML-DSA-87 keygen; identical contract, 2592-byte encoded public key.
int naalp_mldsa87_pubkey_from_seed(const uint8_t seed[32], uint8_t out_pub[2592]);

// Verify a pure-mode ML-DSA-65 signature `sig` (must be 3309 bytes) over `msg` with FIPS-204
// `context`, against the raw encoded public key `pk` (must be exactly 1952 bytes). Returns 1 iff the
// signature is valid, else 0. FAIL-CLOSED: a wrong public-key/signature length, a public-key parse
// failure, or any BoringSSL verification failure all return 0 — never a false accept.
int naalp_mldsa65_verify(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *context, size_t context_len);

// Verify a pure-mode ML-DSA-87 signature; identical fail-closed contract, pk = 2592 bytes,
// sig = 4627 bytes.
int naalp_mldsa87_verify(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *context, size_t context_len);

#endif
