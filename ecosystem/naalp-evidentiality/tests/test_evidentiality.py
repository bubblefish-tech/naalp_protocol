# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP evidentiality primitive (E6.4/R12.4).

VectorConformanceTests loads ecosystem/naalp-evidentiality/vectors/cases.json (built by
scripts/build_vectors.py, an F3 non-circular constructor that never imports
naalp_evidentiality.evidentiality) and drives every admit_case/reject_case through
naalp_evidentiality.verify_and_admit, asserting each admits or raises the exact named error
recorded in the vector.

DirectTests cover the assertion-shape edge cases the vectors do not (a basis_code with no
basis_ref, evidence of the wrong TYPE for the stated basis) directly against the module.

Run (from ecosystem/naalp-evidentiality/, PYTHONDONTWRITEBYTECODE=1, using the real Python
interpreter for this platform -- on Windows the Microsoft-Store `python`/`python3`
execution-alias stubs resolve ahead of a real install on PATH and hang, so invoke the actual
interpreter binary directly rather than the bare `python` command):
    PYTHONDONTWRITEBYTECODE=1 python -m unittest -v tests.test_evidentiality
"""
import json
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-evidentiality
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

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
    basis_name,
    verify_and_admit,
)
from naalp import audit  # noqa: E402

_VECTORS_PATH = os.path.join(_PKG_ROOT, "vectors", "cases.json")


def _load_vectors():
    with open(_VECTORS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _unhex(h):
    return bytes.fromhex(h)


def _basis_ref_from(d):
    if d is None:
        return None
    kwargs = {}
    if "signer_id" in d:
        kwargs["signer_id"] = d["signer_id"]
    if "oracle_id" in d:
        kwargs["oracle_id"] = d["oracle_id"]
    if "authority_signer_id" in d:
        kwargs["authority_signer_id"] = d["authority_signer_id"]
    if "receipt_seq" in d:
        kwargs["receipt_seq"] = d["receipt_seq"]
    if "input_content_id_hex" in d:
        kwargs["input_content_id"] = _unhex(d["input_content_id_hex"])
    return BasisRef(**kwargs)


def _evidence_for(basis_code, ev):
    """Build the evidence object a vector's `evidence` dict describes. Dispatches on the
    DICT'S OWN SHAPE (which keys it carries), not strictly on basis_code, because the
    unknown_basis_code reject case deliberately pairs an out-of-registry code (99) with a
    basis-0-shaped evidence dict (unreachable evidence -- UnknownBasis is refused before any
    evidence is ever inspected)."""
    if ev is None:
        return None
    if "sig_hex" in ev:
        return SignatureEvidence(
            alg=ev["alg"], pubkey=_unhex(ev["pubkey_hex"]),
            signed_bytes=_unhex(ev["signed_bytes_hex"]), sig=_unhex(ev["sig_hex"]),
        )
    if "receipts" in ev:
        receipts = [
            audit.Receipt(_unhex(r["prev_hex"]), _unhex(r["obj_hex"]), r["seq"], r["at"])
            for r in ev["receipts"]
        ]
        sigs = [_unhex(s) for s in ev["sigs_hex"]]
        return AuthorityEvidence(
            receipts=receipts, sigs=sigs,
            authority_alg=ev["authority_alg"], authority_pubkey=_unhex(ev["authority_pubkey_hex"]),
        )
    if "input_bytes_hex" in ev and basis_code == 3:
        return InputEvidence(input_bytes=_unhex(ev["input_bytes_hex"]))
    if "input_bytes_hex" in ev:
        return OracleEvidence(input_bytes=_unhex(ev["input_bytes_hex"]))
    raise AssertionError("test harness does not recognize this evidence shape: %r" % (ev,))


def _oracle_registry_for_vectors():
    reg = OracleRegistry()
    reg.register("sha384-demo", Sha384Oracle())
    return reg


class VectorConformanceTests(unittest.TestCase):
    """Every admit_case/reject_case in vectors/cases.json, driven through the real
    verify_and_admit dispatch. The vectors' expected admit/reject verdicts were reasoned
    independently from R12.4's text (scripts/build_vectors.py never imports this module)."""

    @classmethod
    def setUpClass(cls):
        cls.data = _load_vectors()

    def _assertion_from(self, case):
        return EvidencedAssertion(
            what=case["name"],
            value_content_id=_unhex(case["value_content_id_hex"]),
            basis_code=case["basis_code"],
            basis_ref=_basis_ref_from(case.get("basis_ref")),
        )

    def test_admit_cases(self):
        registry = _oracle_registry_for_vectors()
        for case in self.data["admit_cases"]:
            with self.subTest(case=case["name"]):
                assertion = self._assertion_from(case)
                evidence = _evidence_for(case["basis_code"], case.get("evidence"))
                self.assertIsNone(verify_and_admit(assertion, evidence, registry))

    def test_reject_cases(self):
        registry = _oracle_registry_for_vectors()
        for case in self.data["reject_cases"]:
            with self.subTest(case=case["name"]):
                assertion = self._assertion_from(case)
                evidence = _evidence_for(case["basis_code"], case.get("evidence"))
                with self.assertRaises(EvidentialityError) as ctx:
                    verify_and_admit(assertion, evidence, registry)
                self.assertEqual(ctx.exception.kind, case["expect_error"], msg=case["name"])

    def test_vector_file_covers_every_named_error(self):
        """Every named error the module can raise appears in at least one reject_case, so the
        conformance run exercises the FULL fail-closed surface, not a subset."""
        expected_errors = {
            "NoBasis", "UnknownBasis", "EvidenceMissing",
            "SignerMismatch", "SignedContentMismatch", "SignatureInvalid",
            "OracleUnregistered", "OracleInputMismatch", "OracleValueMismatch",
            "AuthorityMismatch", "ChainInvalid", "ReceiptNotAtSeq",
            "InputMismatch", "RecomputeMismatch",
        }
        seen = {c["expect_error"] for c in self.data["reject_cases"]}
        # EvidenceMissing is covered by DirectTests below (a vector's basis_code always carries
        # matching evidence by construction), not by the JSON vectors themselves.
        self.assertEqual(expected_errors - seen, {"EvidenceMissing"})


class DirectTests(unittest.TestCase):
    """Assertion-shape edge cases the JSON vectors do not exercise: a basis_code with no
    basis_ref, and evidence of the wrong TYPE for the stated basis (EvidenceMissing)."""

    def test_basis_code_with_no_basis_ref_refused(self):
        assertion = EvidencedAssertion(what="x", value_content_id=b"\x20\x30" + b"\x00" * 48, basis_code=0, basis_ref=None)
        with self.assertRaises(EvidentialityError) as ctx:
            verify_and_admit(assertion, SignatureEvidence(alg=-49, pubkey=b"", signed_bytes=b"", sig=b""))
        self.assertEqual(ctx.exception.kind, "NoBasis")

    def test_no_evidence_at_all_refused(self):
        assertion = EvidencedAssertion(
            what="x", value_content_id=b"\x20\x30" + b"\x00" * 48,
            basis_code=0, basis_ref=BasisRef(signer_id="anything"),
        )
        with self.assertRaises(EvidentialityError) as ctx:
            verify_and_admit(assertion, None)
        self.assertEqual(ctx.exception.kind, "EvidenceMissing")

    def test_wrong_evidence_type_for_basis_refused(self):
        assertion = EvidencedAssertion(
            what="x", value_content_id=b"\x20\x30" + b"\x00" * 48,
            basis_code=0, basis_ref=BasisRef(signer_id="anything"),
        )
        # OracleEvidence supplied for a signature-verified (basis 0) assertion.
        with self.assertRaises(EvidentialityError) as ctx:
            verify_and_admit(assertion, OracleEvidence(input_bytes=b"x"))
        self.assertEqual(ctx.exception.kind, "EvidenceMissing")

    def test_basis_name_lookup(self):
        self.assertEqual(basis_name(0), "signature-verified")
        self.assertEqual(basis_name(1), "oracle-established")
        self.assertEqual(basis_name(2), "authority-attested")
        self.assertEqual(basis_name(3), "input-computed")
        self.assertEqual(basis_name(99), "unknown")
        self.assertEqual(basis_name(None), "unknown")


if __name__ == "__main__":
    unittest.main()
