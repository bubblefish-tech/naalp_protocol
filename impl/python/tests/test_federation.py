# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Federation higher-tier (tier 1) conformance for the Python SDK, graded against the shared
independent corpus vectors/federation/cases.json (NOT produced by this code): the deterministic
reconcile order over the shared causal DAG, the causal validity of that order, the fact that a
naive content-id sort is NOT causally valid (which is what distinguishes reconcile from a plain
sort), and the byte-exact ReconcileRecord encoding (record_hex).

The sign/verify_reconcile round-trip is demonstrated in isolation only: the corpus carries no
signing seed or signature vector, so it is NOT corpus-graded here (stated honestly).

Written test-first; the federation module is absent until ported, so this fails RED on import
until impl/python/naalp/federation.py lands, and a mutation to the reconcile ready-node guard
flips test_reconcile_matches_oracle.

Run:  python -m unittest -v tests.test_federation      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cose, federation, graph


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "federation", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/federation/cases.json not found")


class FederationConformance(unittest.TestCase):
    C = _vectors()

    def _nodes(self):
        return [
            federation.CausalNode(bytes.fromhex(n["id_hex"]),
                                  [bytes.fromhex(c) for c in n["causes_hex"]])
            for n in self.C["nodes"]
        ]

    def test_reconcile_matches_oracle(self):
        order = federation.reconcile(self._nodes())
        self.assertEqual([o.hex() for o in order], self.C["reconcile_order_hex"])

    def test_reconcile_order_is_causally_valid(self):
        order = [bytes.fromhex(h) for h in self.C["reconcile_order_hex"]]
        self.assertEqual(federation.causally_valid(order, self._nodes()),
                         self.C["reconcile_order_causally_valid"])

    def test_naive_content_id_sort_is_not_causally_valid(self):
        # The distinguishing property: a plain bytewise content-id sort violates causality; the
        # deterministic reconcile does not. If these agreed, reconcile could be a mere sort.
        naive = [bytes.fromhex(h) for h in self.C["naive_content_id_sort_hex"]]
        self.assertEqual(federation.causally_valid(naive, self._nodes()),
                         self.C["naive_causally_valid"])
        self.assertFalse(self.C["naive_causally_valid"])

    def test_reconcile_record_bytes_match_oracle(self):
        order = [bytes.fromhex(h) for h in self.C["reconcile_order_hex"]]
        rec = federation.ReconcileRecord(self.C["authorities"], order)
        self.assertEqual(rec.bytes().hex(), self.C["record_hex"])

    def test_sign_verify_reconcile_round_trip_in_isolation(self):
        # NOT corpus-graded: the federation corpus has no signing seed or signature vector. This
        # demonstrates the sign/verify_reconcile surface in isolation with a fixed local seed.
        order = [bytes.fromhex(h) for h in self.C["reconcile_order_hex"]]
        rec = federation.ReconcileRecord(self.C["authorities"], order)
        seed = bytes(32)
        alg = cose.ALG_MLDSA65
        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        sig = federation.sign_reconcile(rec, alg, seed)
        self.assertTrue(federation.verify_reconcile(rec, alg, pk, sig))
        tampered = federation.ReconcileRecord(["bauthority-z"], order)
        self.assertFalse(federation.verify_reconcile(tampered, alg, pk, sig))


class VerifyReconcileOrderTests(unittest.TestCase):
    """Exercises the verify-event choke point of the Reconcile state machine (draft "## Reconcile
    state machine"): an independent recomputation agrees with the record (verified), disagrees on a
    causally-valid but non-deterministic order (ReconcileMismatch), rejects a wrong-length claim
    (ReconcileMismatch), or rejects a node set that is not a valid partial order (CausalViolation).
    Mirrors impl/go/federation/verify_reconcile_test.go TestVerifyReconcileOrder. The mutation that
    neuters the order comparison flips the mismatch and mismatch-length subtests RED."""

    # Two causally-INDEPENDENT objects (no cause between them). reconcile orders concurrent objects
    # by content id bytewise-ascending, so id_a < id_b => the one deterministic order is [id_a, id_b].
    ID_A = bytes([0x01])
    ID_B = bytes([0x02])

    def _concurrent(self):
        return [federation.CausalNode(self.ID_A, []), federation.CausalNode(self.ID_B, [])]

    def test_agrees(self):
        # verify agrees: the claimed order IS the deterministic order -> verified (None).
        rec = federation.ReconcileRecord(["auth-1"], [self.ID_A, self.ID_B])
        self.assertIsNone(federation.verify_reconcile_order(rec, self._concurrent()))

    def test_mismatch(self):
        # A causally-VALID-but-different order (the two objects are concurrent, so [id_b, id_a] is
        # causally valid) is not the deterministic order -> ReconcileMismatch.
        rec = federation.ReconcileRecord(["auth-1"], [self.ID_B, self.ID_A])
        with self.assertRaises(federation.ReconcileMismatch) as cm:
            federation.verify_reconcile_order(rec, self._concurrent())
        self.assertEqual(cm.exception.kind, "ReconcileMismatch")

    def test_mismatch_length(self):
        # A wrong-length claim (drops an element) -> ReconcileMismatch.
        rec = federation.ReconcileRecord(["auth-1"], [self.ID_A])
        with self.assertRaises(federation.ReconcileMismatch) as cm:
            federation.verify_reconcile_order(rec, self._concurrent())
        self.assertEqual(cm.exception.kind, "ReconcileMismatch")

    def test_causal_violation(self):
        # A cyclic node set is not a valid partial order; the recomputation rejects it before any
        # order comparison, so the record is rejected under the graph fault, fail-closed.
        id_c = bytes([0x03])
        id_d = bytes([0x04])
        cyclic = [federation.CausalNode(id_c, [id_d]), federation.CausalNode(id_d, [id_c])]
        rec = federation.ReconcileRecord(["auth-1"], [id_c, id_d])
        with self.assertRaises(graph.CausalViolation) as cm:
            federation.verify_reconcile_order(rec, cyclic)
        self.assertEqual(cm.exception.kind, "CausalViolation")


if __name__ == "__main__":
    unittest.main()
