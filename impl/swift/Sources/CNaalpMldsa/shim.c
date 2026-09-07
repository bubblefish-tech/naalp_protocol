// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#include "CNaalpMldsa.h"

// BoringSSL's opaque ML-DSA key structs. Layouts copied VERBATIM from swift-crypto
// Sources/CCryptoBoringSSL/crypto/fipsmodule/bcm_interface.h; the static_asserts in
// crypto/mldsa/mldsa.cc guarantee sizeof/alignof equal the public MLDSA{65,87}_{private,public}_key,
// so passing a pointer to these through the BCM entry points below is layout-sound.
struct BCM_mldsa65_private_key {
  union {
    uint8_t bytes[32 + 32 + 64 + 256 * 4 * (5 + 6 + 6)];
    uint32_t alignment;
  } opaque;
};

struct BCM_mldsa87_private_key {
  union {
    uint8_t bytes[32 + 32 + 64 + 256 * 4 * (7 + 8 + 8)];
    uint32_t alignment;
  } opaque;
};

struct BCM_mldsa65_public_key {
  union {
    uint8_t bytes[32 + 64 + 256 * 4 * 6];
    uint32_t alignment;
  } opaque;
};

struct BCM_mldsa87_public_key {
  union {
    uint8_t bytes[32 + 64 + 256 * 4 * 8];
    uint32_t alignment;
  } opaque;
};

// Mirror of BoringSSL's CBS (crypto/bytestring): a read-only {data,len} view. CBS_init merely sets
// these two fields, so we construct one directly and pass its address where the BCM parse entry
// points expect a CBS* — identical layout, no need to link the (prefixed) CBS_init symbol.
struct naalp_cbs {
  const uint8_t *data;
  size_t len;
};

// swift-crypto prefixes every vendored BoringSSL symbol with `CCryptoBoringSSL_` (see
// Sources/CCryptoBoringSSL/include/CCryptoBoringSSL_boringssl_prefix_symbols.h). All of these are
// OPENSSL_EXPORT (default visibility) and declared inside `extern "C"` in bcm_interface.h, so a
// plain C extern with the prefixed name resolves them from the CCryptoBoringSSL static archive that
// the Crypto product links. Return type bcm_status is an int-sized enum {approved=0, not_approved=1,
// failure=2}; bcm_success == (status == approved || status == not_approved).
extern int CCryptoBoringSSL_BCM_mldsa65_private_key_from_seed(
    struct BCM_mldsa65_private_key *out_private_key, const uint8_t seed[32]);
extern int CCryptoBoringSSL_BCM_mldsa65_sign_internal(
    uint8_t out_encoded_signature[3309],
    const struct BCM_mldsa65_private_key *private_key,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len,
    const uint8_t randomizer[32]);
extern int CCryptoBoringSSL_BCM_mldsa65_generate_key_external_entropy(
    uint8_t out_encoded_public_key[1952],
    struct BCM_mldsa65_private_key *out_private_key, const uint8_t entropy[32]);
extern int CCryptoBoringSSL_BCM_mldsa65_parse_public_key(
    struct BCM_mldsa65_public_key *out_public_key, struct naalp_cbs *in);
extern int CCryptoBoringSSL_BCM_mldsa65_verify_internal(
    const struct BCM_mldsa65_public_key *public_key,
    const uint8_t encoded_signature[3309],
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len);

extern int CCryptoBoringSSL_BCM_mldsa87_private_key_from_seed(
    struct BCM_mldsa87_private_key *out_private_key, const uint8_t seed[32]);
extern int CCryptoBoringSSL_BCM_mldsa87_sign_internal(
    uint8_t out_encoded_signature[4627],
    const struct BCM_mldsa87_private_key *private_key,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len,
    const uint8_t randomizer[32]);
extern int CCryptoBoringSSL_BCM_mldsa87_generate_key_external_entropy(
    uint8_t out_encoded_public_key[2592],
    struct BCM_mldsa87_private_key *out_private_key, const uint8_t entropy[32]);
extern int CCryptoBoringSSL_BCM_mldsa87_parse_public_key(
    struct BCM_mldsa87_public_key *out_public_key, struct naalp_cbs *in);
extern int CCryptoBoringSSL_BCM_mldsa87_verify_internal(
    const struct BCM_mldsa87_public_key *public_key,
    const uint8_t encoded_signature[4627],
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context_prefix, size_t context_prefix_len,
    const uint8_t *context, size_t context_len);

// bcm_status low byte: approved(0) / not_approved(1) are success; failure(2) is not. Matches the
// reference `bcm_success` in swift-crypto crypto/fipsmodule/bcm_interface.h.
static int naalp_bcm_success(int status) {
  int low = status & 0xff;
  return (low == 0 || low == 1) ? 1 : 0;
}

// ===== Deterministic sign (rnd=0) =====
// FIPS-204 pure-mode context encoding is {0x00, len(context)} || context, exactly as the hedged
// BCM_mldsa*_sign builds it before delegating to sign_internal — with the randomizer forced to 32
// zero bytes so the signature is deterministic and matches the oracle's rnd=0 ML-DSA leg.
int naalp_mldsa65_det_sign(
    const uint8_t seed[32],
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context, size_t context_len,
    uint8_t out_sig[3309]) {
  struct BCM_mldsa65_private_key priv;
  int r1 = CCryptoBoringSSL_BCM_mldsa65_private_key_from_seed(&priv, seed);
  unsigned char context_prefix[2];
  context_prefix[0] = 0x00;
  context_prefix[1] = (unsigned char)context_len;
  unsigned char randomizer[32];
  for (size_t i = 0; i < 32; i++) {
    randomizer[i] = 0x00;
  }
  int r2 = CCryptoBoringSSL_BCM_mldsa65_sign_internal(
      out_sig, &priv, msg, msg_len,
      context_prefix, (size_t)2, context, context_len, randomizer);
  return (r1 << 8) | (r2 & 0xff);
}

int naalp_mldsa87_det_sign(
    const uint8_t seed[32],
    const uint8_t *msg, size_t msg_len,
    const uint8_t *context, size_t context_len,
    uint8_t out_sig[4627]) {
  struct BCM_mldsa87_private_key priv;
  int r1 = CCryptoBoringSSL_BCM_mldsa87_private_key_from_seed(&priv, seed);
  unsigned char context_prefix[2];
  context_prefix[0] = 0x00;
  context_prefix[1] = (unsigned char)context_len;
  unsigned char randomizer[32];
  for (size_t i = 0; i < 32; i++) {
    randomizer[i] = 0x00;
  }
  int r2 = CCryptoBoringSSL_BCM_mldsa87_sign_internal(
      out_sig, &priv, msg, msg_len,
      context_prefix, (size_t)2, context, context_len, randomizer);
  return (r1 << 8) | (r2 & 0xff);
}

// ===== Keygen-from-seed (raw encoded public key) =====
// generate_key_external_entropy derives the keypair from the 32-byte seed (xi) and writes the raw
// FIPS-204 encoded public key directly (no CBB marshaling). Deterministic function of the seed, so
// byte-identical to the composite oracle's mldsa_pubkey_hex (proven by the keygen KAT).
int naalp_mldsa65_pubkey_from_seed(const uint8_t seed[32], uint8_t out_pub[1952]) {
  struct BCM_mldsa65_private_key priv;
  int r = CCryptoBoringSSL_BCM_mldsa65_generate_key_external_entropy(out_pub, &priv, seed);
  return r & 0xff;
}

int naalp_mldsa87_pubkey_from_seed(const uint8_t seed[32], uint8_t out_pub[2592]) {
  struct BCM_mldsa87_private_key priv;
  int r = CCryptoBoringSSL_BCM_mldsa87_generate_key_external_entropy(out_pub, &priv, seed);
  return r & 0xff;
}

// ===== Verify (fail-closed) =====
// Parse the raw encoded public key into the BCM struct, then verify in pure mode with the same
// {0x00,len}||context prefix the sign path uses. Every non-success path returns 0 (invalid):
// wrong pk/sig length, a parse failure, or a verification failure — never a false accept.
int naalp_mldsa65_verify(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *context, size_t context_len) {
  if (pk_len != 1952 || sig_len != 3309) {
    return 0;
  }
  struct BCM_mldsa65_public_key pub;
  struct naalp_cbs in;
  in.data = pk;
  in.len = pk_len;
  int pr = CCryptoBoringSSL_BCM_mldsa65_parse_public_key(&pub, &in);
  if (!naalp_bcm_success(pr)) {
    return 0;
  }
  unsigned char context_prefix[2];
  context_prefix[0] = 0x00;
  context_prefix[1] = (unsigned char)context_len;
  int vr = CCryptoBoringSSL_BCM_mldsa65_verify_internal(
      &pub, sig, msg, msg_len, context_prefix, (size_t)2, context, context_len);
  return naalp_bcm_success(vr);
}

int naalp_mldsa87_verify(
    const uint8_t *pk, size_t pk_len,
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *context, size_t context_len) {
  if (pk_len != 2592 || sig_len != 4627) {
    return 0;
  }
  struct BCM_mldsa87_public_key pub;
  struct naalp_cbs in;
  in.data = pk;
  in.len = pk_len;
  int pr = CCryptoBoringSSL_BCM_mldsa87_parse_public_key(&pub, &in);
  if (!naalp_bcm_success(pr)) {
    return 0;
  }
  unsigned char context_prefix[2];
  context_prefix[0] = 0x00;
  context_prefix[1] = (unsigned char)context_len;
  int vr = CCryptoBoringSSL_BCM_mldsa87_verify_internal(
      &pub, sig, msg, msg_len, context_prefix, (size_t)2, context, context_len);
  return naalp_bcm_success(vr);
}
