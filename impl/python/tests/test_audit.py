# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C7 audit conformance for the Python SDK, graded against the shared independent corpus
vectors/audit/cases.json (NOT produced by this code): the hash-chained signed receipt body +
head, offline chain verification (ChainBroken / ReceiptUnsigned), equivocation detection, the
draft-01 fork-proof preimage (signatures elided), and the offline causal graph (valid topo
order, cycle rejection, future-cause rejection).

The receipt/fork-proof SIGNATURES are real deterministic ML-DSA-65 (dilithium-py, rnd=0), but
the corpus carries no signature vector for this channel (signatures are graded by the shared
cose byte-parity elsewhere), so the sign/verify round-trips here are demonstrated in isolation
with a fixed local seed -- stated honestly, not corpus-graded. Every byte-exact assertion
(body/head/preimage/topo) IS corpus-graded.

Written test-first; the audit module is absent until ported, so this fails RED on import until
impl/python/naalp/audit.py lands, and a mutation to the equivocation object-difference check
flips test_equivocation_detected.

Run:  python -m unittest -v tests.test_audit      (from impl/python/)
"""
import json
import os
import unittest

from naalp import audit, cose, graph


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "audit", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/audit/cases.json not found")


ALG = cose.ALG_MLDSA65
SEED = bytes(32)
PK = cose.mldsa_keygen("ML-DSA-65", SEED)


def _hb(s):
    return bytes.fromhex(s)


class AuditConformance(unittest.TestCase):
    C = _vectors()

    # ---- signed hash-chained receipt (design §8.1) ----------------------------------------

    def test_chain_receipts_match_oracle(self):
        head = _hb(self.C["chain"]["genesis_prev_hex"])
        self.assertEqual(len(head), audit.HEAD_SIZE)
        for rv in self.C["chain"]["receipts"]:
            r = audit.Receipt(_hb(rv["prev_hex"]), _hb(rv["obj_hex"]), rv["seq"], rv["at"])
            self.assertEqual(r.bytes().hex(), rv["body_hex"], "receipt body seq=%d" % rv["seq"])
            self.assertEqual(r.head().hex(), rv["head_after_hex"], "receipt head seq=%d" % rv["seq"])
            self.assertEqual(r.prev.hex(), head.hex(), "prev links to previous head seq=%d" % rv["seq"])
            head = r.head()
        self.assertEqual(head.hex(), self.C["chain"]["final_head_hex"])

    def test_authority_reproduces_chain_and_verifies(self):
        # A fresh authority appending the same object ids at the same anchors reproduces the
        # byte-exact corpus chain, and the resulting real-ML-DSA-signed chain verifies offline.
        a = audit.Authority(ALG, SEED)
        receipts, sigs = [], []
        for rv in self.C["chain"]["receipts"]:
            r, sig = a.append(_hb(rv["obj_hex"]), rv["at"])
            self.assertEqual(r.bytes().hex(), rv["body_hex"], "append body seq=%d" % rv["seq"])
            receipts.append(r)
            sigs.append(sig)
        self.assertIsNone(audit.verify_chain(receipts, sigs, ALG, PK))

    def test_verify_chain_detects_broken_prev_link(self):
        cb = self.C["chain_broken"]
        receipts, sigs = [], []
        a = audit.Authority(ALG, SEED)  # sign each body with a real key so the break, not a bad sig, is what fires
        for rv in cb["receipts"]:
            r = audit.Receipt(_hb(rv["prev_hex"]), _hb(rv["obj_hex"]), rv["seq"], rv["at"])
            self.assertEqual(r.bytes().hex(), rv["body_hex"])
            receipts.append(r)
            sigs.append(cose.mldsa_sign(ALG, SEED, r.bytes()))
        with self.assertRaises(audit.AuditError) as cm:
            audit.verify_chain(receipts, sigs, ALG, PK)
        self.assertEqual(cm.exception.kind, cb["expect"])  # ChainBroken

    def test_verify_chain_detects_tampered_signature(self):
        # Isolation: a validly-chained receipt with a corrupted signature is ReceiptUnsigned.
        r = audit.Receipt(_hb(self.C["chain"]["genesis_prev_hex"]),
                          _hb(self.C["chain"]["receipts"][0]["obj_hex"]),
                          0, self.C["chain"]["receipts"][0]["at"])
        good = cose.mldsa_sign(ALG, SEED, r.bytes())
        bad = bytearray(good)
        bad[-1] ^= 1
        with self.assertRaises(audit.AuditError) as cm:
            audit.verify_chain([r], [bytes(bad)], ALG, PK)
        self.assertEqual(cm.exception.kind, "ReceiptUnsigned")

    def test_consistent_with_anchor(self):
        self.assertTrue(audit.consistent_with_anchor(100, 100))
        self.assertTrue(audit.consistent_with_anchor(99, 100))
        self.assertFalse(audit.consistent_with_anchor(101, 100))  # created after ordered

    # ---- equivocation detection (design §8.5) ---------------------------------------------

    def _fork_receipts(self):
        f = self.C["fork_proof"]
        ra = audit.Receipt(_hb(f["prev_hex"]), _hb(f["obj_a_hex"]), f["seq"], f["at"])
        rb = audit.Receipt(_hb(f["prev_hex"]), _hb(f["obj_b_hex"]), f["seq"], f["at"])
        return f, ra, rb

    def test_equivocation_receipts_match_oracle(self):
        f, ra, rb = self._fork_receipts()
        self.assertEqual(ra.bytes().hex(), f["body_a_hex"])
        self.assertEqual(rb.bytes().hex(), f["body_b_hex"])
        # cross-check against the corpus equivocation section (same seq-1 conflict)
        eq = self.C["equivocation"]
        self.assertEqual(ra.bytes().hex(), eq["receipt_a"]["body_hex"])
        self.assertEqual(rb.bytes().hex(), eq["receipt_b"]["body_hex"])

    def test_equivocation_detected(self):
        # Two validly-signed receipts by ONE authority at one seq naming DIFFERENT objects: the
        # auditor mints a fork proof (corpus expect == "Equivocation"). A benign first observe
        # returns None. THIS is the mutation-target assertion.
        f, ra, rb = self._fork_receipts()
        sig_a = cose.mldsa_sign(ALG, SEED, ra.bytes())
        sig_b = cose.mldsa_sign(ALG, SEED, rb.bytes())
        auditor = audit.Auditor(ALG, PK, _hb(f["signer_hex"]), f["ext_counter"])
        self.assertIsNone(auditor.observe(ra, sig_a), "first observe is benign")
        fp = auditor.observe(rb, sig_b)
        self.assertIsNotNone(fp, "a genuine fork at one seq must be detected")
        self.assertIsNone(fp.verify(ALG, PK), "the minted proof verifies against the accused key")
        self.assertEqual(self.C["equivocation"]["expect"], "Equivocation")

    def test_benign_duplicate_is_not_equivocation(self):
        f, ra, _ = self._fork_receipts()
        sig_a = cose.mldsa_sign(ALG, SEED, ra.bytes())
        auditor = audit.Auditor(ALG, PK, _hb(f["signer_hex"]), f["ext_counter"])
        self.assertIsNone(auditor.observe(ra, sig_a))
        self.assertIsNone(auditor.observe(ra, sig_a), "an exact duplicate is not a fork")

    def test_observe_rejects_unsigned(self):
        f, ra, _ = self._fork_receipts()
        auditor = audit.Auditor(ALG, PK, _hb(f["signer_hex"]), f["ext_counter"])
        with self.assertRaises(audit.AuditError) as cm:
            auditor.observe(ra, b"\x00" * 8)
        self.assertEqual(cm.exception.kind, "ReceiptUnsigned")

    # ---- fork proof (draft-01 §8.5) -------------------------------------------------------

    def test_fork_proof_preimage_matches_oracle(self):
        # The framing witness (both signatures elided to empty) is reproduced byte-for-byte from
        # the corpus, independent of the signature bytes. Corpus-graded.
        f, ra, rb = self._fork_receipts()
        fp = audit.new_fork_proof(_hb(f["signer_hex"]), ra, b"", rb, b"", f["ext_counter"])
        self.assertEqual(fp.preimage().hex(), f["preimage_hex"])

    def test_fork_proof_verify_accepts_and_fails_closed(self):
        f, ra, rb = self._fork_receipts()
        sig_a = cose.mldsa_sign(ALG, SEED, ra.bytes())
        sig_b = cose.mldsa_sign(ALG, SEED, rb.bytes())
        signer = _hb(f["signer_hex"])
        good = audit.new_fork_proof(signer, ra, sig_a, rb, sig_b, f["ext_counter"])
        self.assertIsNone(good.verify(ALG, PK))  # a valid, non-repudiable proof

        # same object named twice -> not equivocation -> ForkProofInvalid (fail-closed)
        same = audit.new_fork_proof(signer, ra, sig_a, ra, sig_a, f["ext_counter"])
        with self.assertRaises(audit.AuditError) as cm:
            same.verify(ALG, PK)
        self.assertEqual(cm.exception.kind, "ForkProofInvalid")

        # unnamed accused -> ForkProofInvalid
        unnamed = audit.new_fork_proof(b"", ra, sig_a, rb, sig_b, f["ext_counter"])
        with self.assertRaises(audit.AuditError) as cm:
            unnamed.verify(ALG, PK)
        self.assertEqual(cm.exception.kind, "ForkProofInvalid")

        # seq mismatch -> ForkProofInvalid
        rb_seq = audit.Receipt(rb.prev, rb.obj, rb.seq + 1, rb.at)
        sig_b2 = cose.mldsa_sign(ALG, SEED, rb_seq.bytes())
        mism = audit.new_fork_proof(signer, ra, sig_a, rb_seq, sig_b2, f["ext_counter"])
        with self.assertRaises(audit.AuditError) as cm:
            mism.verify(ALG, PK)
        self.assertEqual(cm.exception.kind, "ForkProofInvalid")

        # tampered signature -> ReceiptUnsigned
        bad = bytearray(sig_b)
        bad[-1] ^= 1
        tampered = audit.new_fork_proof(signer, ra, sig_a, rb, bytes(bad), f["ext_counter"])
        with self.assertRaises(audit.AuditError) as cm:
            tampered.verify(ALG, PK)
        self.assertEqual(cm.exception.kind, "ReceiptUnsigned")

    # ---- offline causal graph (design §8.2-§8.3) ------------------------------------------

    def _nodes(self, key):
        return [audit.CausalNode(_hb(n["id_hex"]),
                                 [_hb(c) for c in n["causes_hex"]], n["position"])
                for n in self.C[key]["nodes"]]

    def test_causal_valid_topo_order_matches_oracle(self):
        nodes = self._nodes("causal_valid")
        self.assertIsNone(audit.verify_causal(nodes))
        order = audit.topo_order(nodes)
        self.assertEqual([o.hex() for o in order], self.C["causal_valid"]["topo_order_hex"])

    def test_causal_cycle_rejected(self):
        with self.assertRaises(graph.CausalViolation) as cm:
            audit.verify_causal(self._nodes("causal_cycle"))
        self.assertEqual(cm.exception.kind, self.C["causal_cycle"]["expect"])

    def test_causal_future_cause_rejected(self):
        with self.assertRaises(graph.CausalViolation) as cm:
            audit.verify_causal(self._nodes("causal_future"))
        self.assertEqual(cm.exception.kind, self.C["causal_future"]["expect"])


if __name__ == "__main__":
    unittest.main()
