# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""naalp_evidentiality -- the N-AALP evidentiality primitive (Part-2 ecosystem task E6.4,
requirement R12.4, the evidence-layer primitives).

Every assertion in an audit/receipt record SHALL carry how it is known -- its derivation. A
bare assertion, an assertion naming a basis code outside the closed registry, or an assertion
whose stated basis does not actually hold when RE-RUN against real evidence is REFUSED,
fail-closed, with a named error. See evidentiality.py for the closed basis registry and the
re-check dispatch.
"""
from .evidentiality import (
    BASIS_AUTHORITY_ATTESTED,
    BASIS_INPUT_COMPUTED,
    BASIS_ORACLE_ESTABLISHED,
    BASIS_SIGNATURE_VERIFIED,
    AuthorityEvidence,
    BasisRef,
    EvidencedAssertion,
    EvidentialityError,
    InputEvidence,
    Oracle,
    OracleEvidence,
    OracleRegistry,
    SignatureEvidence,
    basis_name,
    verify_and_admit,
)
from .oracles import Sha384Oracle

__all__ = [
    "BASIS_AUTHORITY_ATTESTED",
    "BASIS_INPUT_COMPUTED",
    "BASIS_ORACLE_ESTABLISHED",
    "BASIS_SIGNATURE_VERIFIED",
    "AuthorityEvidence",
    "BasisRef",
    "EvidencedAssertion",
    "EvidentialityError",
    "InputEvidence",
    "Oracle",
    "OracleEvidence",
    "OracleRegistry",
    "Sha384Oracle",
    "SignatureEvidence",
    "basis_name",
    "verify_and_admit",
]

__version__ = "0.1.0"
