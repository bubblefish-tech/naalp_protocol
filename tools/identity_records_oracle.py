# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
N-AALP independent oracle for the C4 identity RECORD + THREAD surfaces (design.md §5.3/§5.4,
plus the durable-thread mechanics of §5.2/R-1.4): RevocationRecord, RevokedAt, VerifyRevocation,
ForeignLinkRecord, VerifyForeignLink, RotationEvidence, Thread, Thread.Attributable, and
ResolveThread. These are the eleven surfaces that today have NO independent oracle — the Go
(impl/go/identity/identity.go) and Rust (impl/rust/src/identity.rs) tests are self-referential.

WIRE AUTHORITY (independent of impl/go, impl/rust): spec/naalp-draft-01.cddl §"Identity-channel
(0x0003) lifecycle record bodies":
    naalp-revocation   = { 1: tstr key, 2: uint not_after }            ; §5.3
    naalp-foreign-link = { 1: tstr controls, 2: tstr foreign_id (NFC), 3: uint not_after }  ; §5.4
    naalp-rotation     = { 1: tstr old, 2: tstr new, 3: uint not_before }                    ; §5.2
Field numbers and types come straight from this CDDL, not from any Go/Rust source file.

WHAT IS SIGNED (design.md §5.2-§5.4): a Revocation is "signed by the key it revokes (or a
recovery key)"; a ForeignLink is "cross-signed by the FOREIGN identity's key"; a Rotation is
"co-signed by BOTH the old and new key". Each of these three record kinds is signed RAW over its
own deterministic-CBOR record bytes directly — there is no COSE_Sign1/COSE_Sign envelope framing
at this layer (that framing belongs to the separately-graded object-envelope surface, C3/§2, and
to the already-anchored tag-98 Rotation *object* graded by tools/rotation_oracle.py). The
signature primitive is deterministic ML-DSA-65 (rnd=0, empty/nil context) — the same primitive
already established non-circularly in tools/rotation_oracle.py (dilithium_py, no impl/go or
impl/rust import).

SIGNER-ID FORM: DELIBERATE DEVIATION FROM THE ORIGINAL TASKING, disclosed here. §5.1 fixes one
formula for every signer id in the whole protocol:
    signer = multibase(base32, multihash(0x12, SHA-256(multicodec(mc, pubkey))))
This oracle uses that REAL derivation (reusing tools/signerid_oracle.py's independent
implementation of the same formula, itself built only from the multiformats registry + RFC 4648,
not from impl/go or impl/rust) for every field that is later checked against a signing key's
recomputed id: RevocationRecord.key and RotationRecord.old/new. Those specific fields are
load-bearing for VerifyRevocation/ResolveThread's own correctness (a mismatch is the *named*
SignerMismatch failure mode, §5.5) — an opaque, non-derived label there would make every
would-be-valid case fail for a reason that has nothing to do with the behavior under test. Fields
that are never recomputed against a key (ForeignLinkRecord.controls, ForeignLinkRecord.foreign_id)
stay OPAQUE worked strings, matching the original tasking and every other oracle's convention
(rotation_oracle.py's ROT_RECORD old/new labels, signer_counter_oracle.py's signer ids).

F3 NON-CIRCULARITY: this file shares no code with impl/go/identity or impl/rust/src/identity.rs.
It builds record bytes from cbor_oracle (RFC 8949 §4.2.1, already graded), derives signer ids from
signerid_oracle's independent multiformats construction (already graded), and signs/verifies with
dilithium_py directly (the same library rotation_oracle.py already uses non-circularly). Verdicts
(accept/reject, RevokedAt boundary, ResolveThread contiguity, Thread.Attributable membership) are
independent models written directly from design.md §5.3/§5.4/§5.2/R-1.4 below the fixture builders,
never inferred from Go/Rust control flow.

RECOVERY-KEY AUTHORIZATION (design.md §5.3): a Revocation may be signed EITHER by the key it
revokes OR by a deployer-configured recovery key. The recovery set is a deployer-configured
VERIFICATION input — §5.3 gives no wire structure for it. VerifyRevocation is authorized iff the
recomputed signer id equals record.key OR is a member of that configured recovery set; a signer
that is neither is SignerMismatch (§5.5), fail-closed — an empty recovery set admits only the
revoked key. impl/go and impl/rust implement exactly this (Shawn approved option (a), 2026-08-21;
the earlier recovery-key deferral is resolved). The `revocation.verify` matrix covers all
six authorization×signature cells plus a check-order case; verdicts are DERIVED from an
independent verify model (recompute id + real ML-DSA-65 verify), never hardcoded — see
build_revocation().

Emits vectors/identity_records/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys
import unicodedata

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle       # shared deterministic-CBOR encoder (RFC 8949 §4.2.1); already graded
import rotation_oracle    # reused ONLY for its from-scratch ML-DSA primitives (mldsa_pub/mldsa_sign)
import signerid_oracle    # reused ONLY for its from-scratch §5.1 self-certifying id derivation

enc = cbor_oracle.encode
mldsa_pub = rotation_oracle.mldsa_pub
mldsa_sign = rotation_oracle.mldsa_sign

ALG_MLDSA65 = -49
CODE_MLDSA65 = signerid_oracle.CODE_MLDSA65   # 0x1211 (multiformats mldsa-65-pub, draft status)


def real_signer_id(seed):
    """The REAL §5.1 self-certifying id for an ML-DSA-65 keypair derived from `seed`, via
    signerid_oracle's independent multicodec/multihash/multibase construction (not impl/go or
    impl/rust)."""
    pub = mldsa_pub(ALG_MLDSA65, seed)
    return signerid_oracle.signer_id(CODE_MLDSA65, pub), pub


# ---- record-level deterministic-CBOR encoders (CDDL naalp-revocation / naalp-foreign-link /
#      naalp-rotation, field numbers/types straight from spec/naalp-draft-01.cddl) --------------

def revocation_record_bytes(key, not_after):
    return enc(("map", [(1, key), (2, not_after)]))


def foreign_link_record_bytes(controls, foreign_id, not_after):
    return enc(("map", [(1, controls), (2, foreign_id), (3, not_after)]))


def rotation_record_bytes(old, new, not_before):
    return enc(("map", [(1, old), (2, new), (3, not_before)]))


# ---- key fixture (distinct ML-DSA-65 seeds; single-repeated-byte, readable, rotation_oracle
#      style) -------------------------------------------------------------------------------
SEED_A, SEED_B, SEED_C, SEED_D, SEED_X, SEED_BROKEN = (
    bytes([0xA1]) * 32, bytes([0xA2]) * 32, bytes([0xA3]) * 32,
    bytes([0xA4]) * 32, bytes([0xA5]) * 32, bytes([0xA6]) * 32,
)
SEED_E, SEED_R, SEED_G, SEED_F = (
    bytes([0xB1]) * 32, bytes([0xB2]) * 32, bytes([0xB3]) * 32, bytes([0xB4]) * 32,
)
SEED_H, SEED_I = bytes([0xC1]) * 32, bytes([0xC2]) * 32

BASE_T = 1785000000000   # baseline epoch-ms, matching the rest of the corpus's fixture convention


# =================================================================================================
# §5.3 Revocation: RevocationRecord, RevokedAt, VerifyRevocation
# =================================================================================================

def build_revocation():
    id_e, pub_e = real_signer_id(SEED_E)   # the key being revoked
    id_r, pub_r = real_signer_id(SEED_R)   # a distinct deployer-configured recovery key
    id_g, pub_g = real_signer_id(SEED_G)   # an unrelated third key (wrong-key case)
    id_f, pub_f = real_signer_id(SEED_F)   # a second, distinct revoked key (multi-revocation case)

    # ---- RevocationRecord.Bytes (deterministic CBOR of {1:key, 2:not_after}) ------------------
    record_bytes_cases = [
        {"name": "real_id_small_notafter", "key": id_e, "not_after": 100,
         "bytes_hex": revocation_record_bytes(id_e, 100).hex(),
         "note": "key is the REAL §5.1 self-certifying id of SEED_E; small not_after (1-byte uint)"},
        {"name": "real_id_epoch_notafter", "key": id_e, "not_after": BASE_T + 100000,
         "bytes_hex": revocation_record_bytes(id_e, BASE_T + 100000).hex(),
         "note": "same key, epoch-ms-scale not_after (8-byte uint head) — width sensitivity"},
        {"name": "opaque_label_notafter_zero", "key": "signer-arbitrary-label", "not_after": 0,
         "bytes_hex": revocation_record_bytes("signer-arbitrary-label", 0).hex(),
         "note": "Bytes() is a pure CBOR encoder — agnostic to whether `key` is a real derived id; "
                 "not_after=0 edge case"},
    ]
    assert record_bytes_cases[0]["bytes_hex"] != record_bytes_cases[1]["bytes_hex"]

    # ---- RevokedAt(revocations, key, position) -> not_after iff revoked-before ----------------
    # Independent model (design.md §5.3, R-5.3, R-8.4): an object whose AUTHORITATIVE receipt
    # position is AFTER not_after is revoked; a position at or before not_after stays valid
    # ("objects fixed before it stay valid"). `position` is the authority-anchored evidence R-8.4
    # requires (not the signer's self-claimed `created`); this oracle models it as an epoch-ms-
    # scale integer, matching not_after's own CDDL unit, and the comparison is a bare `>`.
    def revoked_at_model(revocations, key, position):
        for r in revocations:
            if r["key"] == key and position > r["not_after"]:
                return True, r["not_after"]
        return False, None

    na_e = BASE_T + 100000
    na_f = BASE_T + 50000
    revoked_at_scenarios = [
        {"name": "well_before", "revocations": [{"key": id_e, "not_after": na_e}],
         "query_key": id_e, "query_position": BASE_T + 50000},
        {"name": "at_boundary_still_valid", "revocations": [{"key": id_e, "not_after": na_e}],
         "query_key": id_e, "query_position": na_e},
        {"name": "strictly_after_revoked", "revocations": [{"key": id_e, "not_after": na_e}],
         "query_key": id_e, "query_position": BASE_T + 150000},
        {"name": "different_key_unaffected", "revocations": [{"key": id_e, "not_after": na_e}],
         "query_key": id_g, "query_position": BASE_T + 999999999},
        {"name": "multi_revocation_picks_right_key",
         "revocations": [{"key": id_e, "not_after": na_e}, {"key": id_f, "not_after": na_f}],
         "query_key": id_f, "query_position": BASE_T + 60000},
        {"name": "multi_revocation_other_key_valid",
         "revocations": [{"key": id_e, "not_after": na_e}, {"key": id_f, "not_after": na_f}],
         "query_key": id_f, "query_position": BASE_T + 40000},
    ]
    for s in revoked_at_scenarios:
        revoked, not_after = revoked_at_model(s["revocations"], s["query_key"], s["query_position"])
        s["expect_revoked"] = revoked
        s["expect_not_after"] = not_after

    # ---- VerifyRevocation(record, verifier, candidate_pubkey, sig, authorized_recovery_ids) ->
    #      verify a revocation signature (design.md §5.3, §5.5). §5.3 permits a Revocation to be
    #      signed EITHER by the key it revokes OR by a deployer-configured recovery key. The
    #      recovery set is a deployer-configured VERIFICATION input (there is no wire structure for
    #      it — §5.3 gives none). A signer that is neither the revoked key nor a member of that
    #      configured set is SignerMismatch (§5.5), fail-closed. ---------------------------------
    na = BASE_T + 100000
    record_e = {"key": id_e, "not_after": na}
    body_e = revocation_record_bytes(id_e, na)

    sig_self = mldsa_sign(ALG_MLDSA65, SEED_E, body_e)          # signed by the revoked key itself
    sig_recovery = mldsa_sign(ALG_MLDSA65, SEED_R, body_e)      # signed by the recovery key (§5.3)
    sig_wrongkey = mldsa_sign(ALG_MLDSA65, SEED_G, body_e)      # signed by an unrelated third key
    sig_tampered = bytearray(sig_self)
    sig_tampered[0] ^= 0xFF                                     # flip one byte: correct key, bad sig
    sig_tampered = bytes(sig_tampered)
    sig_recovery_tampered = bytearray(sig_recovery)
    sig_recovery_tampered[0] ^= 0xFF                           # recovery signer, corrupted signature
    sig_recovery_tampered = bytes(sig_recovery_tampered)

    from dilithium_py.ml_dsa import ML_DSA_65

    def verify_revocation_model(record, candidate_pub, sig, authorized_recovery_ids):
        """Independent verdict (design.md §5.3/§5.5), DERIVED not hardcoded: recompute the signer
        id from the candidate public key via signerid_oracle's §5.1 construction; the signer is
        AUTHORIZED iff it equals record.key OR is a member of the deployer-configured recovery set.
        An unauthorized signer -> SignerMismatch, checked BEFORE the signature (matching §5.5's
        named-failure ordering). An authorized signer whose signature does not verify -> plain
        reject (no design-named kind beyond 'reject'). Fail-closed: an empty recovery set admits
        only the revoked key itself. The signature is verified with dilithium_py directly (real
        ML-DSA-65 verify over the record bytes), not modeled."""
        signer_id = signerid_oracle.signer_id(CODE_MLDSA65, candidate_pub)
        if signer_id != record["key"] and signer_id not in authorized_recovery_ids:
            return False, "SignerMismatch"
        rec_bytes = revocation_record_bytes(record["key"], record["not_after"])
        if not ML_DSA_65.verify(candidate_pub, rec_bytes, sig, b""):
            return False, ""
        return True, ""

    def vcase(name, candidate_pub, sig, authorized_recovery_ids, note):
        valid, kind = verify_revocation_model(record_e, candidate_pub, sig, authorized_recovery_ids)
        return {"name": name, "record": record_e, "candidate_alg": ALG_MLDSA65,
                "candidate_pubkey_hex": candidate_pub.hex(), "sig_hex": sig.hex(),
                "authorized_recovery_ids": authorized_recovery_ids,
                "expect_valid": valid, "expect_error_kind": kind, "note": note}

    # Six authorization×signature cells + one check-order case. authorized_recovery_ids is the
    # deployer-configured recovery set (§5.3); verdicts are DERIVED from verify_revocation_model.
    verify_cases = [
        vcase("valid_self_revoked", pub_e, sig_self, [],
              "§5.3: signed by the key it revokes, no recovery key configured -> valid"),
        vcase("valid_self_with_recovery_configured", pub_e, sig_self, [id_r],
              "§5.3: the revoked key signs while a recovery key is ALSO configured -> still valid; "
              "the recovery set does not perturb the self-signature path"),
        vcase("recovery_key_valid_per_design", pub_r, sig_recovery, [id_r],
              "§5.3: 'signed by the key (or a deployer-configured recovery key)'. K_R's id is in "
              "authorized_recovery_ids, so a revocation of K_E signed by K_R is VALID. impl/go and "
              "impl/rust implement this (Shawn approved option (a), 2026-08-21)."),
        vcase("recovery_key_not_configured_reject", pub_r, sig_recovery, [],
              "FAIL-CLOSED anchor: the SAME K_R signature, but no recovery key is configured "
              "(authorized_recovery_ids empty) -> SignerMismatch. Proves the recovery path is "
              "authorization-gated, not accept-any-valid-signature."),
        vcase("wrong_key_reject", pub_g, sig_wrongkey, [id_r],
              "even with K_R configured as a recovery key, a revocation signed by an UNRELATED "
              "third key K_G (neither the revoked key nor a configured recovery id) -> "
              "SignerMismatch (§5.5). Proves 'recovery configured' != 'accept any signer'."),
        vcase("tampered_signature_reject", pub_e, sig_tampered, [],
              "correct key/id, corrupted signature bytes -> reject (authorized signer, bad "
              "signature; no design-named kind beyond 'reject')"),
        vcase("recovery_signer_tampered_sig_reject", pub_r, sig_recovery_tampered, [id_r],
              "CHECK-ORDER anchor: K_R is a configured recovery id (authorization passes) but its "
              "signature is corrupted -> reject. Proves the signature is still verified after the "
              "membership check on the recovery path too."),
    ]

    return {
        "field_numbers": {"key": 1, "not_after": 2},
        "keys": {"id_e": id_e, "pub_e_hex": pub_e.hex(), "id_r": id_r, "pub_r_hex": pub_r.hex(),
                 "id_g": id_g, "pub_g_hex": pub_g.hex(), "id_f": id_f, "pub_f_hex": pub_f.hex()},
        "record_bytes": record_bytes_cases,
        "revoked_at": revoked_at_scenarios,
        "verify": verify_cases,
    }


# =================================================================================================
# §5.4 Carried foreign identity: ForeignLinkRecord, VerifyForeignLink
# =================================================================================================

def build_foreign_link():
    id_h, pub_h = real_signer_id(SEED_H)   # the foreign identity's real key (signs the link)
    _id_i, pub_i = real_signer_id(SEED_I)  # an unrelated key (wrong-key case)

    controls = "signer-controls-x"   # opaque worked N-AALP signer id (never CheckSigner'd here)
    foreign_id_nfc = unicodedata.normalize("NFC", "did:example:café")
    foreign_id_nfd = unicodedata.normalize("NFD", "did:example:café")
    assert foreign_id_nfc != foreign_id_nfd

    # ---- ForeignLinkRecord.Bytes (deterministic CBOR of {1:controls, 2:foreign_id, 3:not_after}) -
    na = BASE_T + 100000
    record_bytes_cases = [
        {"name": "nfc_form", "controls": controls, "foreign_id": foreign_id_nfc, "not_after": na,
         "bytes_hex": foreign_link_record_bytes(controls, foreign_id_nfc, na).hex(),
         "note": "foreign_id in NFC form (the CDDL-required form)"},
        {"name": "nfd_form_different_bytes", "controls": controls, "foreign_id": foreign_id_nfd,
         "not_after": na, "bytes_hex": foreign_link_record_bytes(controls, foreign_id_nfd, na).hex(),
         "note": "SAME logical identity string in NFD form -> DIFFERENT bytes (Bytes() is a pure "
                 "encoder; the NFC requirement is enforced by VerifyForeignLink, not by Bytes())"},
        {"name": "empty_not_after", "controls": "signer-controls-y", "foreign_id": "did:example:y",
         "not_after": 0, "bytes_hex": foreign_link_record_bytes("signer-controls-y", "did:example:y", 0).hex(),
         "note": "not_after=0 edge case"},
    ]
    assert record_bytes_cases[0]["bytes_hex"] != record_bytes_cases[1]["bytes_hex"], \
        "NFC vs NFD foreign_id must encode to different bytes"

    # ---- VerifyForeignLink(record, verifier, candidate_pubkey, sig, now) ----------------------
    # Independent model (design.md §5.4, §5.5, CDDL "foreign_id ... MUST be NFC (else NonNFC)"):
    #   1. foreign_id not NFC -> reject NonNFC (checked before signature/expiry).
    #   2. now > not_after -> link IGNORED (linked=false), NOT an error; object stays valid on its
    #      own signature (§5.5). now == not_after is NOT expired (same boundary convention as
    #      RevokedAt: "objects fixed before it stay valid" applied uniformly to every not_after
    #      field in this design).
    #   3. signature does not verify under the candidate key -> link IGNORED (linked=false), NOT
    #      an error ("expired or wrong key -> link ignored" is ONE bucket in §5.5).
    #   4. otherwise -> LINKED (controls, foreign_id).
    record_h = {"controls": controls, "foreign_id": foreign_id_nfc, "not_after": na}
    body_h = foreign_link_record_bytes(controls, foreign_id_nfc, na)
    sig_h = mldsa_sign(ALG_MLDSA65, SEED_H, body_h)

    record_nfd = {"controls": controls, "foreign_id": foreign_id_nfd, "not_after": na}
    body_nfd = foreign_link_record_bytes(controls, foreign_id_nfd, na)
    sig_nfd = mldsa_sign(ALG_MLDSA65, SEED_H, body_nfd)   # still real-signed; NFC check fires first

    verify_cases = [
        {"name": "valid_unexpired", "record": record_h, "candidate_alg": ALG_MLDSA65,
         "candidate_pubkey_hex": pub_h.hex(), "sig_hex": sig_h.hex(), "now": BASE_T + 50000,
         "expect_linked": True, "expect_error_kind": "",
         "expect_controls": controls, "expect_foreign_id": foreign_id_nfc,
         "note": "valid cross-signature under the FOREIGN key, before not_after -> linked"},
        {"name": "at_boundary_still_linked", "record": record_h, "candidate_alg": ALG_MLDSA65,
         "candidate_pubkey_hex": pub_h.hex(), "sig_hex": sig_h.hex(), "now": na,
         "expect_linked": True, "expect_error_kind": "",
         "expect_controls": controls, "expect_foreign_id": foreign_id_nfc,
         "note": "now == not_after -> not yet expired (uniform not_after boundary convention)"},
        {"name": "expired_ignored", "record": record_h, "candidate_alg": ALG_MLDSA65,
         "candidate_pubkey_hex": pub_h.hex(), "sig_hex": sig_h.hex(), "now": BASE_T + 150000,
         "expect_linked": False, "expect_error_kind": "",
         "expect_controls": None, "expect_foreign_id": None,
         "note": "§5.5: expired -> link ignored, no error, object stays valid on its own signature"},
        {"name": "wrong_key_ignored", "record": record_h, "candidate_alg": ALG_MLDSA65,
         "candidate_pubkey_hex": pub_i.hex(), "sig_hex": sig_h.hex(), "now": BASE_T + 50000,
         "expect_linked": False, "expect_error_kind": "",
         "expect_controls": None, "expect_foreign_id": None,
         "note": "§5.5: cross-signature does not verify under the candidate key -> link ignored"},
        {"name": "non_nfc_foreign_id_rejected", "record": record_nfd, "candidate_alg": ALG_MLDSA65,
         "candidate_pubkey_hex": pub_h.hex(), "sig_hex": sig_nfd.hex(), "now": BASE_T + 50000,
         "expect_linked": False, "expect_error_kind": "NonNFC",
         "expect_controls": None, "expect_foreign_id": None,
         "note": "CDDL: foreign_id MUST be NFC (else NonNFC) — checked before expiry/signature"},
    ]

    return {
        "field_numbers": {"controls": 1, "foreign_id": 2, "not_after": 3},
        "keys": {"id_h": id_h, "pub_h_hex": pub_h.hex(), "pub_i_hex": pub_i.hex()},
        "record_bytes": record_bytes_cases,
        "verify": verify_cases,
    }


# =================================================================================================
# §5.2/R-1.4 durable identity thread: RotationEvidence, Thread, Thread.Attributable, ResolveThread
# =================================================================================================

def build_thread():
    id_a, pub_a = real_signer_id(SEED_A)
    id_b, pub_b = real_signer_id(SEED_B)
    id_c, pub_c = real_signer_id(SEED_C)
    id_d, pub_d = real_signer_id(SEED_D)
    id_x, _pub_x = real_signer_id(SEED_X)          # unrelated key (Attributable-false case)
    id_broken, pub_broken = real_signer_id(SEED_BROKEN)   # deliberately does NOT equal id_b

    def link(seed_old, id_old, pub_old, seed_new, id_new, pub_new, not_before):
        """One RotationEvidence: record {old,new,not_before}, RAW-signed by BOTH keys over the
        SAME record bytes (design.md §5.2: 'signed by both keys'; impl/go SignRotation signs
        r.Bytes() with each signer, no per-leg framing at the record layer — the tag-98
        envelope framing is a DIFFERENT, already-anchored surface, tools/rotation_oracle.py)."""
        body = rotation_record_bytes(id_old, id_new, not_before)
        old_sig = mldsa_sign(ALG_MLDSA65, seed_old, body)
        new_sig = mldsa_sign(ALG_MLDSA65, seed_new, body)
        return {
            "old": id_old, "new": id_new, "not_before": not_before,
            "old_alg": ALG_MLDSA65, "old_pubkey_hex": pub_old.hex(), "old_sig_hex": old_sig.hex(),
            "new_alg": ALG_MLDSA65, "new_pubkey_hex": pub_new.hex(), "new_sig_hex": new_sig.hex(),
            "record_bytes_hex": body.hex(),
        }

    link_ab = link(SEED_A, id_a, pub_a, SEED_B, id_b, pub_b, BASE_T)
    link_bc = link(SEED_B, id_b, pub_b, SEED_C, id_c, pub_c, BASE_T + 100000)
    link_cd = link(SEED_C, id_c, pub_c, SEED_D, id_d, pub_d, BASE_T + 200000)
    # a broken second link: individually well-formed and validly self-signed (SEED_BROKEN signs
    # its own "old" leg, SEED_D signs "new"), but old=id_broken != prevNew(id_b) — the chain does
    # not connect. Isolates the CONTIGUITY guard from the co-signature guard.
    link_broken_old = link(SEED_BROKEN, id_broken, pub_broken, SEED_D, id_d, pub_d, BASE_T + 100000)
    # a contiguous-but-forged second link: old DOES equal prevNew (id_b), but the "old" leg is
    # signed by the WRONG key (SEED_X instead of SEED_B) — isolates the co-signature guard.
    body_forged = rotation_record_bytes(id_b, id_c, BASE_T + 100000)
    forged_old_sig = mldsa_sign(ALG_MLDSA65, SEED_X, body_forged)   # wrong key signs the old leg
    forged_new_sig = mldsa_sign(ALG_MLDSA65, SEED_C, body_forged)
    link_bc_forged = {
        "old": id_b, "new": id_c, "not_before": BASE_T + 100000,
        "old_alg": ALG_MLDSA65, "old_pubkey_hex": pub_b.hex(), "old_sig_hex": forged_old_sig.hex(),
        "new_alg": ALG_MLDSA65, "new_pubkey_hex": pub_c.hex(), "new_sig_hex": forged_new_sig.hex(),
        "record_bytes_hex": body_forged.hex(),
    }

    # ---- independent model of ResolveThread (design.md §5.2, R-1.4) ---------------------------
    # walk(evs): contiguity = each rotation's `old` == the prior's `new`; each link's co-signature
    # must independently verify under (old_pubkey recomputes to `old`, new_pubkey recomputes to
    # `new`, both signatures verify raw over the record bytes) — a genuine substitution (either
    # break) is RotationUnauthorized. Root=evs[0].old, Current=last .new, Chain=[old0,new0,new1,...].
    def resolve_thread_model(evs):
        if not evs:
            return None, "RotationUnauthorized"
        chain = [evs[0]["old"]]
        prev_new = evs[0]["old"]
        for e in evs:
            if e["old"] != prev_new:
                return None, "RotationUnauthorized"
            # co-signature check: recomputed id from each pubkey must equal the claimed old/new,
            # and both signatures must verify raw over the record bytes (the ML-DSA library
            # itself, not a model — the actual signature bytes were produced/consumed for real).
            got_old = signerid_oracle.signer_id(CODE_MLDSA65, bytes.fromhex(e["old_pubkey_hex"]))
            got_new = signerid_oracle.signer_id(CODE_MLDSA65, bytes.fromhex(e["new_pubkey_hex"]))
            if got_old != e["old"] or got_new != e["new"]:
                return None, "RotationUnauthorized"
            from dilithium_py.ml_dsa import ML_DSA_65
            # verify with the REAL public keys (independent of impl/go or impl/rust):
            if not ML_DSA_65.verify(bytes.fromhex(e["old_pubkey_hex"]), bytes.fromhex(e["record_bytes_hex"]),
                                     bytes.fromhex(e["old_sig_hex"]), b""):
                return None, "RotationUnauthorized"
            if not ML_DSA_65.verify(bytes.fromhex(e["new_pubkey_hex"]), bytes.fromhex(e["record_bytes_hex"]),
                                     bytes.fromhex(e["new_sig_hex"]), b""):
                return None, "RotationUnauthorized"
            chain.append(e["new"])
            prev_new = e["new"]
        return {"root": chain[0], "current": prev_new, "chain": chain}, ""

    def result_case(name, evs, note):
        thread, err = resolve_thread_model(evs)
        return {"name": name, "evidence": evs, "expect_error": err,
                "expect_thread": thread, "note": note}

    resolve_cases = [
        result_case("empty_chain", [], "len(evidence)==0 -> RotationUnauthorized (fail-closed)"),
        result_case("single_link", [link_ab],
                    "one rotation A->B -> Root=A, Current=B, Chain=[A,B]"),
        result_case("contiguous_chain_3", [link_ab, link_bc, link_cd],
                    "A->B->C->D, three rotations -> Root=A, Current=D, Chain=[A,B,C,D]"),
        result_case("broken_link_old_mismatch", [link_ab, link_broken_old],
                    "second link's old != first link's new (id_broken != id_b) — each link is "
                    "individually validly self-signed, but the chain does not connect -> "
                    "RotationUnauthorized from the CONTIGUITY guard, before any co-signature check "
                    "on the second link"),
        result_case("broken_link_forged_old_signature", [link_ab, link_bc_forged],
                    "second link's old DOES equal the first link's new (contiguous), but the old "
                    "leg is signed by the WRONG key (SEED_X, not SEED_B) -> RotationUnauthorized "
                    "from the CO-SIGNATURE guard, isolating it from the contiguity guard"),
    ]

    # ---- Thread.Attributable(signer) -> is `signer` in the resolved thread's Chain ------------
    thread3 = next(c for c in resolve_cases if c["name"] == "contiguous_chain_3")["expect_thread"]
    attributable_cases = [
        {"name": "root_attributable", "thread": thread3, "query": id_a, "expect": True},
        {"name": "intermediate_b_attributable", "thread": thread3, "query": id_b, "expect": True},
        {"name": "intermediate_c_attributable", "thread": thread3, "query": id_c, "expect": True},
        {"name": "current_attributable", "thread": thread3, "query": id_d, "expect": True},
        {"name": "unrelated_key_not_attributable", "thread": thread3, "query": id_x, "expect": False},
    ]

    return {
        "field_numbers_rotation_record": {"old": 1, "new": 2, "not_before": 3},
        "keys": {"id_a": id_a, "id_b": id_b, "id_c": id_c, "id_d": id_d, "id_x": id_x,
                  "id_broken": id_broken},
        "resolve": resolve_cases,
        "attributable": attributable_cases,
    }


def build():
    return {
        "note": ("Independent oracle for the N-AALP C4 identity RECORD + THREAD surfaces "
                 "(design.md §5.2/§5.3/§5.4/§5.5, R-1.4/R-5.2/R-5.3/R-5.4, spec/naalp-draft-01.cddl "
                 "naalp-revocation/naalp-foreign-link/naalp-rotation): RevocationRecord, RevokedAt, "
                 "VerifyRevocation, ForeignLinkRecord, VerifyForeignLink, RotationEvidence, Thread, "
                 "Thread.Attributable, ResolveThread. Go (impl/go/identity) and Rust "
                 "(impl/rust/src/identity.rs) MUST reproduce every *_hex byte and every "
                 "expect_valid/expect_linked/expect_error/expect_revoked/expect_thread/expect verdict. "
                 "Real §5.1 self-certifying signer ids (via signerid_oracle's independent "
                 "multicodec/multihash/multibase construction) are used for RevocationRecord.key and "
                 "RotationRecord.old/new, the fields later CheckSigner'd against a pubkey; opaque "
                 "worked labels are used for ForeignLinkRecord.controls/foreign_id, which are not. "
                 "VerifyRevocation grades a deployer-configured recovery-key authorization set "
                 "(§5.3), fail-closed; impl/go and impl/rust implement it (see the file docstring). "
                 "Generated by tools/identity_records_oracle.py; do not hand-edit."),
        "alg_mldsa65": ALG_MLDSA65,
        "channel_identity": 3,
        "kinds": {"Rotation": 0, "Revocation": 1, "ForeignLink": 2, "KeyAnnounce": 3},
        "effects": {"Rotation": 2, "Revocation": 3, "ForeignLink": 1},
        "revocation": build_revocation(),
        "foreign_link": build_foreign_link(),
        "thread": build_thread(),
    }


def main():
    out_dir = os.path.normpath(os.path.join(HERE, "..", "vectors", "identity_records"))
    os.makedirs(out_dir, exist_ok=True)
    data = build()
    path = os.path.join(out_dir, "cases.json")
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print("revocation record_bytes:", len(data["revocation"]["record_bytes"]), "cases")
    print("revocation revoked_at  :", len(data["revocation"]["revoked_at"]), "scenarios")
    print("revocation verify      :", len(data["revocation"]["verify"]), "cases:",
          ", ".join(c["name"] for c in data["revocation"]["verify"]))
    print("foreign_link record_bytes:", len(data["foreign_link"]["record_bytes"]), "cases")
    print("foreign_link verify      :", len(data["foreign_link"]["verify"]), "cases:",
          ", ".join(c["name"] for c in data["foreign_link"]["verify"]))
    print("thread resolve  :", len(data["thread"]["resolve"]), "cases:",
          ", ".join(c["name"] for c in data["thread"]["resolve"]))
    print("thread attributable:", len(data["thread"]["attributable"]), "cases")
    print("wrote", path)


if __name__ == "__main__":
    main()
