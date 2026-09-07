# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Isolation demonstration (A9) for the N-AALP evidentiality primitive (Part-2 ecosystem task
E6.4, requirement R12.4): concrete input -> concrete output, independent of any other
ecosystem component (no HITL interceptor, no verify-at-use guard, no N-PAMP transport) -- just
naalp_evidentiality called directly against the real Part-1 identity/cose/audit/cbor
primitives.

Run:  python scripts/isolation_demo.py   (from ecosystem/naalp-evidentiality/)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from naalp_evidentiality import (  # noqa: E402
    AuthorityEvidence,
    BasisRef,
    EvidencedAssertion,
    EvidentialityError,
    InputEvidence,
    OracleEvidence,
    OracleRegistry,
    Sha384Oracle,
    SignatureEvidence,
    verify_and_admit,
)
from naalp import audit, cbor, cose, identity  # noqa: E402
from naalp.cbor import U, T, M  # noqa: E402

ALG = cose.ALG_MLDSA65


def _keypair(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def main():
    print("=== N-AALP evidentiality primitive -- isolation demo ===\n")

    # ---- 1. A well-founded signature-verified assertion admits. --------------------------
    print("1. A well-founded signature-verified assertion:")
    seed, pk = _keypair(0x77)
    signer = identity.signer_id(ALG, pk)
    fact_bytes = cbor.encode(M([(U(1), T("audit.chain.head")), (U(2), U(1))]))
    value_id = cbor.content_id(fact_bytes)
    sig = cose.mldsa_sign(ALG, seed, fact_bytes)
    assertion1 = EvidencedAssertion(
        what="audit.chain.head", value_content_id=value_id,
        basis_code=0, basis_ref=BasisRef(signer_id=signer),
    )
    evidence1 = SignatureEvidence(alg=ALG, pubkey=pk, signed_bytes=fact_bytes, sig=sig)
    result = verify_and_admit(assertion1, evidence1)
    print("   admitted, result =", result)
    assert result is None

    # ---- 2. A bare assertion -- no basis at all -- is refused fail-closed. ---------------
    print("\n2. A BARE assertion, no basis stated at all:")
    bare = EvidencedAssertion(what="bare-claim", value_content_id=value_id)
    try:
        verify_and_admit(bare, evidence1)
        raised = None
    except EvidentialityError as e:
        raised = e.kind
    print("   raised =", raised)
    assert raised == "NoBasis"

    # ---- 3. An assertion naming a basis code outside the closed registry is refused. -----
    print("\n3. An assertion naming an UNKNOWN basis code (99):")
    unknown = EvidencedAssertion(
        what="unknown-basis-claim", value_content_id=value_id,
        basis_code=99, basis_ref=BasisRef(signer_id=signer),
    )
    try:
        verify_and_admit(unknown, evidence1)
        raised2 = None
    except EvidentialityError as e:
        raised2 = e.kind
    print("   raised =", raised2)
    assert raised2 == "UnknownBasis"

    # ---- 4. A stated basis whose re-check FAILS is refused (a forged signer claim). ------
    print("\n4. A signature-verified assertion whose stated signer does NOT match the evidence:")
    _, pk_other = _keypair(0x88)
    forged = EvidencedAssertion(
        what="audit.chain.head", value_content_id=value_id,
        basis_code=0, basis_ref=BasisRef(signer_id=identity.signer_id(ALG, pk_other)),
    )
    try:
        verify_and_admit(forged, evidence1)
        raised3 = None
    except EvidentialityError as e:
        raised3 = e.kind
    print("   raised =", raised3)
    assert raised3 == "SignerMismatch"

    # ---- 5. oracle-established: a real, deterministic oracle re-derives the value. -------
    print("\n5. An oracle-established assertion, re-run against the real registered oracle:")
    registry = OracleRegistry()
    registry.register("sha384-demo", Sha384Oracle())
    oracle_input = b"evidentiality-demo-input"
    oracle_value = cbor.content_id(Sha384Oracle().establish(oracle_input))
    assertion5 = EvidencedAssertion(
        what="oracle-fact", value_content_id=oracle_value,
        basis_code=1, basis_ref=BasisRef(oracle_id="sha384-demo", input_content_id=cbor.content_id(oracle_input)),
    )
    result5 = verify_and_admit(assertion5, OracleEvidence(input_bytes=oracle_input), registry)
    print("   admitted, result =", result5)
    assert result5 is None

    # ---- 6. authority-attested: a real audit receipt chain places the value at a seq. ----
    print("\n6. An authority-attested assertion, re-checked against a real receipt chain:")
    auth_seed, auth_pk = _keypair(0x99)
    authority_id = identity.signer_id(ALG, auth_pk)
    authority = audit.Authority(ALG, auth_seed)
    obj_a = cbor.content_id(M([(U(1), T("objA"))]))
    obj_b = cbor.content_id(M([(U(1), T("objB"))]))
    r0, s0 = authority.append(obj_a, 100)
    r1, s1 = authority.append(obj_b, 101)
    assertion6 = EvidencedAssertion(
        what="chain-fact", value_content_id=obj_b,
        basis_code=2, basis_ref=BasisRef(authority_signer_id=authority_id, receipt_seq=1),
    )
    evidence6 = AuthorityEvidence(receipts=[r0, r1], sigs=[s0, s1], authority_alg=ALG, authority_pubkey=auth_pk)
    result6 = verify_and_admit(assertion6, evidence6)
    print("   admitted, result =", result6)
    assert result6 is None

    # ---- 7. input-computed: recompute-content-id (recheck procedure 1) recomputes the value.
    print("\n7. An input-computed assertion (recheck procedure 1, recompute-content-id):")
    body = b"evidentiality-demo-input-computed-body"
    body_id = cbor.content_id(body)
    assertion7 = EvidencedAssertion(
        what="recompute-fact", value_content_id=body_id,
        basis_code=3, basis_ref=BasisRef(input_content_id=body_id),
    )
    result7 = verify_and_admit(assertion7, InputEvidence(input_bytes=body))
    print("   admitted, result =", result7)
    assert result7 is None

    print("\n=== all isolation assertions held ===")


if __name__ == "__main__":
    main()
