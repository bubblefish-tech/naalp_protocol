# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent vector constructor (F3) for the N-AALP evidentiality primitive (E6.4, R12.4).

Non-circular authority (NOT the code under test -- naalp_evidentiality.evidentiality is never
imported or called by this script):
  * The closed basis registry and every expected admit/reject VERDICT below is authored
    independently, directly from the requirement text (requirements.md R12.4 + the design table
    in this task's brief: 4 basis codes, their basis_ref fields, and their re-check procedures)
    -- never computed by calling the module under test.
  * The non-cryptographic wire bytes -- deterministic-CBOR content ids and the C4 self-certifying
    signer id -- are cross-checked byte-for-byte against the EXISTING, independent top-level
    oracle constructors `tools/cbor_oracle.py` and `tools/signerid_oracle.py` (read-only; shared
    with no code path naalp_evidentiality touches).
  * The actual cryptographic material (ML-DSA signatures, the audit receipt chain) is produced
    with the REAL Part-1 SDK (impl/python/naalp: naalp.cose / naalp.identity / naalp.audit) --
    this is legitimate reuse of the already-independently-graded Part-1 primitives
    naalp_evidentiality itself delegates every check to (see evidentiality.py's own docstring);
    it is not the code under test producing its own expected values.

Emits ecosystem/naalp-evidentiality/vectors/cases.json (LF-normalized), containing must-ADMIT
cases (one per basis code) and must-REJECT cases (bare assertion, unknown basis code, and one
mismatch per named error kind) as hex-encoded fixtures the test suite feeds through
naalp_evidentiality.verify_and_admit and checks against the recorded `expect`/`expect_error`.
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG_ROOT = os.path.dirname(HERE)                       # ecosystem/naalp-evidentiality
REPO_ROOT = os.path.normpath(os.path.join(PKG_ROOT, "..", ".."))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
IMPL_PYTHON = os.path.join(REPO_ROOT, "impl", "python")

sys.path.insert(0, TOOLS_DIR)     # independent, read-only oracle constructors
sys.path.insert(0, IMPL_PYTHON)   # the real Part-1 SDK (reused, not re-derived)

import cbor_oracle       # noqa: E402  (independent deterministic-CBOR constructor, RFC 8949)
import signerid_oracle    # noqa: E402  (independent C4 signer-id constructor)

from naalp import audit, cbor, cose, identity  # noqa: E402
from naalp.cbor import U, T, M                  # noqa: E402


def hx(b):
    return bytes(b).hex()


def seed_for(byte):
    return bytes([byte]) * 32


def build():
    alg = cose.ALG_MLDSA65

    # ---- shared key material -------------------------------------------------------------
    seed_a = seed_for(0x11)
    pk_a = cose.mldsa_keygen("ML-DSA-65", seed_a)
    seed_wrong = seed_for(0x22)
    pk_wrong = cose.mldsa_keygen("ML-DSA-65", seed_wrong)

    signer_a = identity.signer_id(alg, pk_a)
    signer_wrong = identity.signer_id(alg, pk_wrong)

    # Independent grounding: naalp.identity.signer_id must match the independent
    # signerid_oracle constructor for the SAME public key (F3 non-circularity on the
    # non-cryptographic wire form).
    grounded_signer_a = signerid_oracle.signer_id(signerid_oracle.CODE_MLDSA65, pk_a)
    assert grounded_signer_a == signer_a, "signer id disagrees with the independent oracle"

    # ---- Basis 0: signature-verified -------------------------------------------------------
    fact0 = M([(U(1), T("audit.chain.head")), (U(2), U(1))])
    signed_bytes0 = cbor.encode(fact0)
    value0 = cbor.content_id(signed_bytes0)
    # Independent grounding: naalp.cbor.content_id (multihash 0x20,0x30 || SHA-384(body)) must
    # match the SAME formula built from the independent cbor_oracle.encode() constructor plus
    # Python's standard-library hashlib (not code under test) -- not cbor_oracle.content_id(),
    # whose own convention excludes a record's field 1, which does not apply to this plain body.
    grounded_body0 = cbor_oracle.encode(("map", [(1, "audit.chain.head"), (2, 1)]))
    grounded_value0 = b"\x20\x30" + hashlib.sha384(grounded_body0).digest()
    assert grounded_value0 == value0, "content id disagrees with the independent oracle"
    sig0 = cose.mldsa_sign(alg, seed_a, signed_bytes0)
    tampered_bytes0 = cbor.encode(M([(U(1), T("audit.chain.head")), (U(2), U(2))]))
    # A signature that FAILS verify under pk_a: genuinely signed, but under seed_wrong, not
    # seed_a -- so it never verifies against the pubkey the evidence (falsely) claims.
    bad_sig0 = cose.mldsa_sign(alg, seed_wrong, tampered_bytes0)

    # ---- Basis 1: oracle-established (Sha384Oracle over an input) -------------------------
    input1 = b"evidentiality-oracle-input-1"
    value1_raw = hashlib.sha384(input1).digest()   # what Sha384Oracle.establish() returns
    value1 = cbor.content_id(value1_raw)
    input1_id = cbor.content_id(input1)
    other_input1 = b"a-different-input"

    # ---- Basis 2: authority-attested (a real 3-receipt chain) ------------------------------
    seed_auth = seed_for(0x33)
    pk_auth = cose.mldsa_keygen("ML-DSA-65", seed_auth)
    authority_id = identity.signer_id(alg, pk_auth)
    grounded_authority_id = signerid_oracle.signer_id(signerid_oracle.CODE_MLDSA65, pk_auth)
    assert grounded_authority_id == authority_id, "authority signer id disagrees with the independent oracle"

    authority = audit.Authority(alg, seed_auth)
    obj_a = cbor.content_id(M([(U(1), T("objA"))]))
    obj_b = cbor.content_id(M([(U(1), T("objB"))]))
    obj_c = cbor.content_id(M([(U(1), T("objC"))]))
    r0, s0 = authority.append(obj_a, 100)
    r1, s1 = authority.append(obj_b, 101)
    r2, s2 = authority.append(obj_c, 102)
    chain_receipts = [r0, r1, r2]
    chain_sigs = [s0, s1, s2]

    # Independent grounding: the receipt bodies must match the independent audit_oracle
    # deterministic-CBOR construction (prev/obj/seq/at, SHA-384 chain head).
    def _receipt_body(prev, obj, seq, at):
        return cbor_oracle.encode(("map", [(1, prev), (2, obj), (3, seq), (4, at)]))

    grounded_r0 = _receipt_body(bytes(audit.HEAD_SIZE), obj_a, 0, 100)
    assert grounded_r0 == r0.bytes(), "receipt body disagrees with the independent oracle"

    # A second, unrelated authority (for the AuthorityMismatch reject case).
    seed_auth_wrong = seed_for(0x44)
    pk_auth_wrong = cose.mldsa_keygen("ML-DSA-65", seed_auth_wrong)

    # A tampered chain (breaks verify_chain -> AuditError ChainBroken) for the ChainInvalid case.
    tampered_receipts = [r0, audit.Receipt(bytes(audit.HEAD_SIZE), obj_c, 1, 101), r2]
    tampered_sigs = [s0, s1, s2]

    # ---- Basis 3: input-computed (recheck procedure 1, recompute-content-id) --------------
    input3 = b"evidentiality-input-computed-body"
    value3 = cbor.content_id(input3)
    # Independent grounding: content_id over RAW bytes is directly multihash(0x20,0x30) ||
    # SHA-384(bytes) -- no CBOR encoding step involved (naalp.cbor.content_id takes the bytes
    # as-is when they are already bytes, not a structured Value).
    grounded_value3 = b"\x20\x30" + hashlib.sha384(input3).digest()
    assert grounded_value3 == value3, "content id disagrees with the independent oracle"
    other_input3 = b"a-tampered-input-computed-body"

    admit_cases = [
        {
            "name": "signature_verified_admit",
            "basis_code": 0,
            "value_content_id_hex": hx(value0),
            "basis_ref": {"signer_id": signer_a},
            "evidence": {"alg": alg, "pubkey_hex": hx(pk_a), "signed_bytes_hex": hx(signed_bytes0), "sig_hex": hx(sig0)},
            "expect": "admit",
        },
        {
            "name": "oracle_established_admit",
            "basis_code": 1,
            "value_content_id_hex": hx(value1),
            "basis_ref": {"oracle_id": "sha384-demo", "input_content_id_hex": hx(input1_id)},
            "evidence": {"input_bytes_hex": hx(input1)},
            "expect": "admit",
        },
        {
            "name": "authority_attested_admit",
            "basis_code": 2,
            "value_content_id_hex": hx(obj_b),
            "basis_ref": {"authority_signer_id": authority_id, "receipt_seq": 1},
            "evidence": {
                "authority_alg": alg,
                "authority_pubkey_hex": hx(pk_auth),
                "receipts": [
                    {"prev_hex": hx(r.prev), "obj_hex": hx(r.obj), "seq": r.seq, "at": r.at}
                    for r in chain_receipts
                ],
                "sigs_hex": [hx(s) for s in chain_sigs],
            },
            "expect": "admit",
        },
        {
            "name": "input_computed_admit",
            "basis_code": 3,
            "value_content_id_hex": hx(value3),
            "basis_ref": {"input_content_id_hex": hx(value3)},
            "evidence": {"input_bytes_hex": hx(input3)},
            "expect": "admit",
        },
    ]

    reject_cases = [
        {
            "name": "bare_assertion",
            "basis_code": None,
            "value_content_id_hex": hx(value0),
            "expect_error": "NoBasis",
        },
        {
            "name": "unknown_basis_code",
            "basis_code": 99,
            "value_content_id_hex": hx(value0),
            "basis_ref": {"signer_id": signer_a},
            "evidence": {"alg": alg, "pubkey_hex": hx(pk_a), "signed_bytes_hex": hx(signed_bytes0), "sig_hex": hx(sig0)},
            "expect_error": "UnknownBasis",
        },
        {
            "name": "signature_signer_mismatch",
            "basis_code": 0,
            "value_content_id_hex": hx(value0),
            "basis_ref": {"signer_id": signer_wrong},  # names the WRONG signer
            "evidence": {"alg": alg, "pubkey_hex": hx(pk_a), "signed_bytes_hex": hx(signed_bytes0), "sig_hex": hx(sig0)},
            "expect_error": "SignerMismatch",
        },
        {
            "name": "signature_content_mismatch",
            "basis_code": 0,
            "value_content_id_hex": hx(cbor.content_id(tampered_bytes0)),  # names a DIFFERENT body's id
            "basis_ref": {"signer_id": signer_a},
            "evidence": {"alg": alg, "pubkey_hex": hx(pk_a), "signed_bytes_hex": hx(signed_bytes0), "sig_hex": hx(sig0)},
            "expect_error": "SignedContentMismatch",
        },
        {
            "name": "signature_invalid",
            "basis_code": 0,
            "value_content_id_hex": hx(cbor.content_id(tampered_bytes0)),
            "basis_ref": {"signer_id": signer_a},
            "evidence": {"alg": alg, "pubkey_hex": hx(pk_a), "signed_bytes_hex": hx(tampered_bytes0), "sig_hex": hx(bad_sig0)},
            "expect_error": "SignatureInvalid",
            "note": "bad_sig0 is a REAL signature over yet another body, not sig0 -- so it fails verify, not just mismatch",
        },
        {
            "name": "oracle_unregistered",
            "basis_code": 1,
            "value_content_id_hex": hx(value1),
            "basis_ref": {"oracle_id": "not-a-registered-oracle", "input_content_id_hex": hx(input1_id)},
            "evidence": {"input_bytes_hex": hx(input1)},
            "expect_error": "OracleUnregistered",
        },
        {
            "name": "oracle_input_mismatch",
            "basis_code": 1,
            "value_content_id_hex": hx(value1),
            "basis_ref": {"oracle_id": "sha384-demo", "input_content_id_hex": hx(input1_id)},
            "evidence": {"input_bytes_hex": hx(other_input1)},  # wrong input for the named id
            "expect_error": "OracleInputMismatch",
        },
        {
            "name": "oracle_value_mismatch",
            "basis_code": 1,
            "value_content_id_hex": hx(cbor.content_id(b"a-value-the-oracle-never-derives")),
            "basis_ref": {"oracle_id": "sha384-demo", "input_content_id_hex": hx(input1_id)},
            "evidence": {"input_bytes_hex": hx(input1)},
            "expect_error": "OracleValueMismatch",
        },
        {
            "name": "authority_mismatch",
            "basis_code": 2,
            "value_content_id_hex": hx(obj_b),
            "basis_ref": {"authority_signer_id": identity.signer_id(alg, pk_auth_wrong), "receipt_seq": 1},
            "evidence": {
                "authority_alg": alg,
                "authority_pubkey_hex": hx(pk_auth),  # the REAL chain's key, but basis_ref names a DIFFERENT authority
                "receipts": [
                    {"prev_hex": hx(r.prev), "obj_hex": hx(r.obj), "seq": r.seq, "at": r.at}
                    for r in chain_receipts
                ],
                "sigs_hex": [hx(s) for s in chain_sigs],
            },
            "expect_error": "AuthorityMismatch",
        },
        {
            "name": "chain_invalid",
            "basis_code": 2,
            "value_content_id_hex": hx(obj_b),
            "basis_ref": {"authority_signer_id": authority_id, "receipt_seq": 1},
            "evidence": {
                "authority_alg": alg,
                "authority_pubkey_hex": hx(pk_auth),
                "receipts": [
                    {"prev_hex": hx(r.prev), "obj_hex": hx(r.obj), "seq": r.seq, "at": r.at}
                    for r in tampered_receipts
                ],
                "sigs_hex": [hx(s) for s in tampered_sigs],
            },
            "expect_error": "ChainInvalid",
        },
        {
            "name": "receipt_not_at_seq",
            "basis_code": 2,
            "value_content_id_hex": hx(obj_c),  # obj_c is really at seq 2, not seq 1
            "basis_ref": {"authority_signer_id": authority_id, "receipt_seq": 1},
            "evidence": {
                "authority_alg": alg,
                "authority_pubkey_hex": hx(pk_auth),
                "receipts": [
                    {"prev_hex": hx(r.prev), "obj_hex": hx(r.obj), "seq": r.seq, "at": r.at}
                    for r in chain_receipts
                ],
                "sigs_hex": [hx(s) for s in chain_sigs],
            },
            "expect_error": "ReceiptNotAtSeq",
        },
        {
            "name": "input_computed_input_mismatch",
            "basis_code": 3,
            "value_content_id_hex": hx(value3),
            "basis_ref": {"input_content_id_hex": hx(value3)},
            "evidence": {"input_bytes_hex": hx(other_input3)},  # different bytes than the input named
            "expect_error": "InputMismatch",
        },
        {
            "name": "input_computed_recompute_mismatch",
            "basis_code": 3,
            "value_content_id_hex": hx(cbor.content_id(b"a-value-that-is-not-input3s-own-content-id")),
            "basis_ref": {"input_content_id_hex": hx(value3)},  # basis_ref correctly names input3's real id
            "evidence": {"input_bytes_hex": hx(input3)},
            "expect_error": "RecomputeMismatch",
        },
    ]

    return {
        "source": (
            "R12.4 (requirements.md lines 113-116) + the closed basis-registry design table "
            "(4 codes: signature-verified/oracle-established/authority-attested/input-computed) "
            "authored in this task's brief. Expected admit/reject verdicts are reasoned directly "
            "from that text, never computed by naalp_evidentiality.evidentiality (not imported "
            "here). Non-cryptographic wire bytes (content ids, the C4 signer id) are "
            "cross-checked against the independent tools/cbor_oracle.py and "
            "tools/signerid_oracle.py constructors (asserted equal above, before this dict is "
            "returned). Cryptographic material (ML-DSA signatures, the audit receipt chain) is "
            "produced with the real, independently-graded Part-1 SDK (naalp.cose / "
            "naalp.identity / naalp.audit) -- the SAME primitives naalp_evidentiality itself "
            "delegates every check to."
        ),
        "admit_cases": admit_cases,
        "reject_cases": reject_cases,
    }


def main():
    data = build()
    out = os.path.join(PKG_ROOT, "vectors", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=False)
        f.write("\n")
    print("wrote", os.path.relpath(out, REPO_ROOT))
    print("  admit_cases =", len(data["admit_cases"]), " reject_cases =", len(data["reject_cases"]))


if __name__ == "__main__":
    main()
