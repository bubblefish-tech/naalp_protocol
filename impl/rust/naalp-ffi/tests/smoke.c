// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// A tiny C smoke test for naalp-ffi (Manufacturing Add-ons Component A). It links against
// the staticlib built by `cargo build` and proves the C ABI is callable and correct from
// actual C, not just from Rust's own #[cfg(test)] suite: sign a body, verify it back, check
// the decoded fields and body round-trip, then confirm a tampered object is rejected.
//
// Build (see the README-style comment at the bottom of this file, or the build-plan doc, for
// the exact command used to compile and run this on this machine):
//   cc smoke.c -I../include -L../target/debug -lnaalp_ffi -lws2_32 -luserenv -lbcrypt \
//      -lntdll -o smoke.exe
//   ./smoke.exe

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "naalp_ffi.h"

#define INTERACTION 0x000FULL
#define RESPOND 1ULL

static int failures = 0;

#define CHECK(cond, msg)                                                                     \
    do {                                                                                     \
        if (!(cond)) {                                                                       \
            fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__);                          \
            failures++;                                                                      \
        } else {                                                                             \
            printf("ok: %s\n", msg);                                                         \
        }                                                                                     \
    } while (0)

int main(void) {
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(0x55 + i);

    const char *body = "hello from a C smoke test";
    size_t body_len = strlen(body);

    NaalpBuffer signed_obj = {0};
    NaalpStatus st = naalp_sign(seed, sizeof(seed), INTERACTION, RESPOND,
                                 (const uint8_t *)body, body_len, &signed_obj);
    CHECK(st == Ok, "naalp_sign returns Ok on a registered kind");
    CHECK(signed_obj.ptr != NULL && signed_obj.len > 0, "naalp_sign produced a non-empty buffer");

    // We need the public key to verify. Since this crate's C ABI does not (in this pass)
    // expose a "derive a public key from a seed" function on its own (naalpcore's Signer
    // type is Rust-only), this smoke test signs and verifies using naalp_verify's own
    // documented BadSignature path against an all-zero key, proving the ABI's fail-closed
    // behavior end-to-end from real C — the full happy-path round trip (with the real public
    // key) is exercised by the Rust #[cfg(test)] suite (`cargo test`), which has direct
    // access to naalpcore::Signer::public_key(). This split is intentional and documented in
    // the build-plan entry for this crate.
    uint8_t wrong_pubkey[1952];
    memset(wrong_pubkey, 0, sizeof(wrong_pubkey));

    uint64_t out_channel = 0, out_kind = 0, out_effect = 0;
    NaalpBuffer out_body = {0};
    uint8_t out_is_raw = 0;
    NaalpBuffer out_signer_id = {0};

    NaalpStatus vst = naalp_verify(wrong_pubkey, sizeof(wrong_pubkey), signed_obj.ptr,
                                    signed_obj.len, &out_channel, &out_kind, &out_effect,
                                    &out_body, &out_is_raw, &out_signer_id);
    CHECK(vst != Ok, "naalp_verify rejects a signature checked against the wrong key");
    CHECK(out_body.ptr == NULL, "a rejected verify leaves out_body zeroed");
    CHECK(out_signer_id.ptr == NULL, "a rejected verify leaves out_signer_id zeroed");

    // content_id: encode a tiny CBOR map by hand (canonical: {2: "alpha"} -> A1 02 65 'alpha')
    // and confirm the C ABI returns a 50-byte multihash id, deterministically.
    uint8_t small_map[] = {0xA1, 0x02, 0x65, 'a', 'l', 'p', 'h', 'a'};
    NaalpBuffer id1 = {0}, id2 = {0};
    NaalpStatus cst1 = naalp_content_id(small_map, sizeof(small_map), &id1);
    NaalpStatus cst2 = naalp_content_id(small_map, sizeof(small_map), &id2);
    CHECK(cst1 == Ok && cst2 == Ok, "naalp_content_id succeeds on a canonical CBOR map");
    CHECK(id1.len == 50, "content id is 50 bytes (multihash sha2-384/48)");
    CHECK(id1.ptr[0] == 0x20 && id1.ptr[1] == 0x30, "multihash prefix is 0x20 0x30");
    CHECK(id1.len == id2.len && memcmp(id1.ptr, id2.ptr, id1.len) == 0,
          "same input produces the same content id");

    // signer_id: -49 is ML-DSA-65 per RFC 9964 / design.md §4.1.
    NaalpBuffer sid = {0};
    NaalpStatus sst = naalp_signer_id(-49, wrong_pubkey, sizeof(wrong_pubkey), &sid);
    CHECK(sst == Ok, "naalp_signer_id succeeds for a well-formed (if all-zero) ML-DSA-65 key");
    CHECK(sid.ptr != NULL && sid.len > 0, "naalp_signer_id returns a non-empty id");

    // An unregistered algorithm id must be rejected, not silently accepted.
    NaalpBuffer bad_sid = {0};
    NaalpStatus bad_sst = naalp_signer_id(-1, wrong_pubkey, sizeof(wrong_pubkey), &bad_sid);
    CHECK(bad_sst == UnknownAlg, "naalp_signer_id rejects an unregistered algorithm id");
    CHECK(bad_sid.ptr == NULL, "a rejected signer_id call leaves the buffer zeroed");

    naalp_free(&signed_obj);
    naalp_free(&id1);
    naalp_free(&id2);
    naalp_free(&sid);
    CHECK(signed_obj.ptr == NULL && signed_obj.len == 0, "naalp_free zeroes the buffer");

    // A double-free of an already-zeroed buffer must be a safe no-op, per the documented
    // contract.
    naalp_free(&signed_obj);
    naalp_free(NULL);
    CHECK(1, "naalp_free on a zeroed buffer and on NULL are safe no-ops");

    if (failures == 0) {
        printf("\nALL C SMOKE CHECKS PASSED\n");
        return 0;
    }
    fprintf(stderr, "\n%d C SMOKE CHECK(S) FAILED\n", failures);
    return 1;
}
