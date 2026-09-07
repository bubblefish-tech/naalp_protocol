# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Mutation-surviving conformance tests for the N-AALP multi-agent reconcile step
(E1.3/R2.3), exercised directly against hand-built causal graphs (never routed through
`ParallelFanout`, whose own construction can never produce a cycle by design -- see
`fanout.py`'s module docstring).

The required fail-closed matrix (task bar) is:
  (f) test_two_node_mutual_cycle_is_rejected_with_a_named_error
      test_self_referencing_node_is_rejected_as_a_cycle
        reconcile over cyclic/inconsistent causal input is rejected with a named error
        (`naalp.graph.CausalViolation`, propagated unchanged from the real Part-1
        primitive).

Also exercises the deterministic bytewise content-id tie-break directly (independent of any
thread-pool timing), and that a node whose declared cause is absent from the graph (a
scope-external cause, R-8.6) does not block reconciliation.

Run (from ecosystem/naalp-multiagent/, PYTHONDONTWRITEBYTECODE=1, using the real Python on
this machine -- not the Microsoft Store `python`/`python3` execution-alias stubs):
    python -m unittest -v tests.test_reconcile
"""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-multiagent
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_multiagent import CausalNode, reconcile_nodes  # noqa: E402
from naalp import graph  # noqa: E402


class ReconcileNodesTests(unittest.TestCase):
    # (f) a two-node mutual cycle (A causes B, B causes A) is not a valid partial order.
    def test_two_node_mutual_cycle_is_rejected_with_a_named_error(self):
        a_id, b_id = b"\x01" * 32, b"\x02" * 32
        nodes = [CausalNode(id=a_id, causes=[b_id]), CausalNode(id=b_id, causes=[a_id])]
        with self.assertRaises(graph.CausalViolation) as cm:
            reconcile_nodes(nodes)
        self.assertEqual(cm.exception.kind, "CausalViolation")

    # (f) a node naming itself as its own cause is the degenerate cycle.
    def test_self_referencing_node_is_rejected_as_a_cycle(self):
        a_id = b"\x03" * 32
        nodes = [CausalNode(id=a_id, causes=[a_id])]
        with self.assertRaises(graph.CausalViolation) as cm:
            reconcile_nodes(nodes)
        self.assertEqual(cm.exception.kind, "CausalViolation")

    # (f) a longer cycle (A -> B -> C -> A) is also rejected.
    def test_three_node_cycle_is_rejected(self):
        a_id, b_id, c_id = b"\x04" * 32, b"\x05" * 32, b"\x06" * 32
        nodes = [
            CausalNode(id=a_id, causes=[c_id]),
            CausalNode(id=b_id, causes=[a_id]),
            CausalNode(id=c_id, causes=[b_id]),
        ]
        with self.assertRaises(graph.CausalViolation) as cm:
            reconcile_nodes(nodes)
        self.assertEqual(cm.exception.kind, "CausalViolation")

    # A valid partial order reconciles: the root before its dependents, ties among
    # causally-concurrent objects broken bytewise-ascending by content id.
    def test_acyclic_graph_reconciles_deterministically_with_content_id_tiebreak(self):
        root_id = b"\x00" * 32
        big_id = b"\xff" + b"\x00" * 31
        small_id = b"\x01" + b"\x00" * 31
        nodes = [
            CausalNode(id=root_id, causes=[]),
            CausalNode(id=big_id, causes=[root_id]),
            CausalNode(id=small_id, causes=[root_id]),
        ]
        order = reconcile_nodes(nodes)
        self.assertEqual(order, (root_id, small_id, big_id))

    # A cause pointing outside the given node set (scope-external, R-8.6) does not block
    # reconciliation -- it is simply not an edge within this graph.
    def test_cause_outside_the_given_node_set_does_not_block_reconciliation(self):
        external_id = b"\x99" * 32
        node_id = b"\x07" * 32
        nodes = [CausalNode(id=node_id, causes=[external_id])]
        order = reconcile_nodes(nodes)
        self.assertEqual(order, (node_id,))

    # Duplicate reconciliation of the identical node set is byte-for-byte identical.
    def test_reconcile_nodes_is_idempotent_over_the_same_node_set(self):
        root_id = b"\x10" * 32
        x_id = b"\x11" * 32
        y_id = b"\x12" * 32
        nodes = [
            CausalNode(id=root_id, causes=[]),
            CausalNode(id=x_id, causes=[root_id]),
            CausalNode(id=y_id, causes=[root_id]),
        ]
        self.assertEqual(reconcile_nodes(nodes), reconcile_nodes(list(reversed(nodes))))


if __name__ == "__main__":
    unittest.main()
