# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""Conformance + mutation-surviving tests for the N-AALP A2A agent-coordination bridge (E2.2,
R4.1/R4.2/R4.3).

Non-circularity (F3): the byte-level shape of the wire objects this bridge produces (the
task-transition body/head/content-id, the A2A Agent Card import body/content-id, the A2A
TaskState string<->code mapping) is checked against vectors/naming/cases.json's `a2a` fixture --
an independent, pre-existing oracle (tools/naming_oracle.py, a from-scratch standard-library
model sharing no code with impl/python/naalp/naming.py, impl/python/naalp/description.py, or
naalp_a2a_bridge) that predates and is independent of this package. `test_activity_matches_the_
independent_oracle_byte_for_byte` drives THIS bridge's own bridge_activity/verify_activity
functions -- not naming.py directly -- through the oracle's exact scenario (task id, card id,
state sequence) and asserts every produced Transition's bytes equal the oracle's pinned
body_hex, so the check exercises this package's own construction path, not merely Part-1's
(which is graded elsewhere, by impl/python/tests/test_naming.py). The real A2A Agent Card JSON
bytes carried in that same fixture (`a2a.card.foreign_hex`) are also reused verbatim as this
suite's card_bytes fixture.

Run (from ecosystem/naalp-a2a-bridge/, PYTHONDONTWRITEBYTECODE=1, using the real Python on this
machine -- not the Microsoft Store `python` stub):
    python -m unittest -v tests.test_a2a_bridge
"""
import os
import sys
import unittest

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)
import _paths  # noqa: E402

_PKG_ROOT = os.path.dirname(_THIS_DIR)  # ecosystem/naalp-a2a-bridge
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from naalp_a2a_bridge import (  # noqa: E402
    A2ABridgeError, ForeignTaskEvent, SkillMapping,
    bridge_activity, bridge_card, verify_activity, verify_and_recover, verify_card,
)
from naalp_a2a_bridge.a2a_bridge import _STATE_BY_NAME  # noqa: E402  (white-box: the table itself)
from naalp import cose, description, identity, naming, policy  # noqa: E402

ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC

# The real A2A Agent Card JSON bytes from vectors/naming/cases.json's a2a.card.foreign_hex --
# reused verbatim (not retyped) so this suite's card fixture is provably the same bytes the
# independent oracle carries, byte for byte.
_ORACLE_CARD_BYTES = (
    b'{"protocolVersion":"0.2.5","name":"billing-agent","url":"https://agent.example/a2a",'
    b'"skills":[{"id":"submit","name":"Submit invoice"},{"id":"get","name":"Get status"}]}'
)


def _seed(b):
    return bytes([b]) * 32


class A2ABridgeConformance(unittest.TestCase):

    # ---- the state-name<->code table (F3: matches the independent oracle) ------------------

    def test_state_table_matches_independent_oracle(self):
        C = _paths.load_naming_cases()
        states = C["a2a"]["states"]
        self.assertEqual(len(_STATE_BY_NAME), 8)
        # Every name this bridge knows maps to the code the oracle's naming.state_name-equivalent
        # table assigns -- cross-checked via naming.state_name (Part-1's own reverse of the SAME
        # table, itself graded against this oracle by impl/python/tests/test_naming.py).
        for name, code in _STATE_BY_NAME.items():
            self.assertEqual(naming.state_name(code), name)
        self.assertEqual(_STATE_BY_NAME["submitted"], states["start"])
        for code in states["terminal"]:
            self.assertIn(naming.state_name(code), _STATE_BY_NAME)
            self.assertTrue(naming.is_terminal(code))

    def test_unknown_state_name_rejected(self):
        with self.assertRaises(A2ABridgeError) as cm:
            bridge_activity([ForeignTaskEvent("t-1", "bogus-state")], b"\x00" * 50, _seed(0x01))
        self.assertEqual(cm.exception.kind, "UnknownTaskState")

    # ---- the card side: octet-exact round trip (R4) -----------------------------------------

    def test_card_round_trip_is_octet_exact_and_preserves_effect(self):
        mappings = [
            SkillMapping("submit", policy.NON_IDEMPOTENT_WRITE, True),
            SkillMapping("get", policy.READ_ONLY, False),
        ]
        seed = _seed(0xA1)
        im, obj = bridge_card(seed, _ORACLE_CARD_BYTES, mappings, alg=ALG)

        pk = cose.mldsa_keygen("ML-DSA-65", seed)
        resolved, im2 = verify_card(obj, pk, alg=ALG, profile=PROFILE)

        # OCTET-EXACT: the recovered card bytes equal the original, exactly (R-14.4: carriage,
        # not adoption -- the foreign bytes are never re-serialized).
        self.assertEqual(im2.foreign, _ORACLE_CARD_BYTES)
        self.assertEqual(im2.id(), im.id())
        self.assertEqual(resolved.foreign_id, description.content_id(_ORACLE_CARD_BYTES))
        self.assertEqual(resolved.authority_id, identity.signer_id(ALG, pk))

        # EFFECT survives: the per-skill effect + approval declaration round-trips unchanged.
        submit, ok = im2.operation("submit")
        self.assertTrue(ok)
        self.assertEqual(submit.effect_class(), policy.NON_IDEMPOTENT_WRITE)
        self.assertTrue(submit.requires_approval_flag())
        get_op, ok = im2.operation("get")
        self.assertTrue(ok)
        self.assertEqual(get_op.effect_class(), policy.READ_ONLY)
        self.assertFalse(get_op.requires_approval_flag())

        # A tampered card fails closed: flipping the LAST byte of the signed object corrupts the
        # ML-DSA signature itself (the tagged COSE_Sign1 array's final element).
        tampered = bytearray(obj)
        tampered[-1] ^= 0xFF
        with self.assertRaises(description.DescriptionError) as cm:
            verify_card(bytes(tampered), pk, alg=ALG, profile=PROFILE)
        self.assertEqual(cm.exception.kind, "BadSignature")

    # ---- the activity side: value-exact round trip (R4) -------------------------------------

    def test_activity_round_trip_is_value_exact(self):
        _, card_obj = bridge_card(_seed(0xA1), _ORACLE_CARD_BYTES,
                                   [SkillMapping("submit", policy.NON_IDEMPOTENT_WRITE, True)], alg=ALG)
        im = description.parse_import(cose.parse_sign1_raw(card_obj)[1])
        card_id = im.id()

        events = [
            ForeignTaskEvent("task-0001", "working"),
            ForeignTaskEvent("task-0001", "input-required"),
            ForeignTaskEvent("task-0001", "working"),
            ForeignTaskEvent("task-0001", "completed"),
        ]
        task_seed = _seed(0xB1)
        transitions, objs = bridge_activity(events, card_id, task_seed, alg=ALG)
        self.assertEqual(len(transitions), 4)
        self.assertEqual(transitions[0].frm, naming.START_STATE)

        task_pk = cose.mldsa_keygen("ML-DSA-65", task_seed)
        verified, recovered = verify_activity(objs, card_id, task_pk, alg=ALG, profile=PROFILE)
        self.assertEqual(len(verified), 4)
        # VALUE-EXACT: the recovered foreign-native activity equals the original, in order.
        self.assertEqual(recovered, events)

    # ---- the combined entry point (R4.1-4.3) -------------------------------------------------

    def test_verify_and_recover_end_to_end(self):
        mappings = [SkillMapping("submit", policy.NON_IDEMPOTENT_WRITE, True)]
        card_seed = _seed(0xA1)
        im, card_obj = bridge_card(card_seed, _ORACLE_CARD_BYTES, mappings, alg=ALG)
        card_pk = cose.mldsa_keygen("ML-DSA-65", card_seed)

        events = [
            ForeignTaskEvent("task-0001", "working"),
            ForeignTaskEvent("task-0001", "completed"),
        ]
        task_seed = _seed(0xB1)
        _, objs = bridge_activity(events, im.id(), task_seed, alg=ALG)
        task_pk = cose.mldsa_keygen("ML-DSA-65", task_seed)

        resolved_card, recovered_card_bytes, im2, verified, recovered_events = verify_and_recover(
            card_obj, card_pk, objs, task_pk, alg=ALG, profile=PROFILE)
        self.assertEqual(recovered_card_bytes, _ORACLE_CARD_BYTES)
        self.assertEqual(recovered_events, events)
        self.assertEqual(im2.id(), im.id())
        self.assertEqual(len(verified), 2)

    # ---- LOAD-BEARING (b): an illegal edge is refused, before any signature is spent --------

    def test_illegal_edge_refused_before_signing(self):
        card_id = b"\x00" * 50
        seed = _seed(0xB1)
        # completed (terminal) -> working: not in the A2A legal-edge table (design sec22.4).
        events = [
            ForeignTaskEvent("task-x", "working"),
            ForeignTaskEvent("task-x", "completed"),
            ForeignTaskEvent("task-x", "working"),
        ]
        with self.assertRaises(naming.NamingError) as cm:
            bridge_activity(events, card_id, seed)
        self.assertEqual(cm.exception.kind, "IllegalTransition")

    def test_empty_activity_rejected(self):
        with self.assertRaises(A2ABridgeError) as cm:
            bridge_activity([], b"\x00" * 50, _seed(0xB1))
        self.assertEqual(cm.exception.kind, "EmptyActivity")

    def test_mixed_task_activity_rejected(self):
        events = [ForeignTaskEvent("task-a", "working"), ForeignTaskEvent("task-b", "completed")]
        with self.assertRaises(A2ABridgeError) as cm:
            bridge_activity(events, b"\x00" * 50, _seed(0xB1))
        self.assertEqual(cm.exception.kind, "ForeignTask")

    # ---- receipt (chain ordering) survives the boundary --------------------------------------

    def test_tampered_and_reordered_chain_refused(self):
        card_id = b"\x00" * 50
        seed = _seed(0xB1)
        events = [ForeignTaskEvent("task-y", "working"), ForeignTaskEvent("task-y", "completed")]
        _, objs = bridge_activity(events, card_id, seed)
        pk = cose.mldsa_keygen("ML-DSA-65", seed)

        # A tampered signature fails closed.
        tampered = bytearray(objs[0])
        tampered[-1] ^= 0xFF
        with self.assertRaises(naming.NamingError) as cm:
            verify_activity([bytes(tampered), objs[1]], card_id, pk, alg=ALG, profile=PROFILE)
        self.assertEqual(cm.exception.kind, "BadSignature")

        # A reordered chain breaks the receipt-chain linkage.
        with self.assertRaises(naming.NamingError) as cm:
            verify_activity([objs[1], objs[0]], card_id, pk, alg=ALG, profile=PROFILE)
        self.assertIn(cm.exception.kind, ("TaskChainBroken", "IllegalTransition"))

    # ---- LOAD-BEARING (c): the card scope (audience) is non-circularly enforced --------------

    def test_activity_bound_to_a_foreign_card_is_refused(self):
        # Card A: the real attestation the caller will present for verification.
        im_a, card_obj_a = bridge_card(_seed(0xA1), _ORACLE_CARD_BYTES,
                                        [SkillMapping("submit", policy.NON_IDEMPOTENT_WRITE, True)], alg=ALG)
        pk_a = cose.mldsa_keygen("ML-DSA-65", _seed(0xA1))

        # Card B: a DIFFERENT, independently valid attestation (different importer key AND
        # different card bytes) -- what the activity is ACTUALLY bound to.
        card_b_bytes = b'{"protocolVersion":"0.2.5","name":"other-agent","skills":[]}'
        im_b, _ = bridge_card(_seed(0xA2), card_b_bytes, [], alg=ALG)
        self.assertNotEqual(im_a.id(), im_b.id())

        task_seed = _seed(0xB1)
        events = [ForeignTaskEvent("task-z", "working")]
        _, objs = bridge_activity(events, im_b.id(), task_seed, alg=ALG)
        task_pk = cose.mldsa_keygen("ML-DSA-65", task_seed)

        # Verifying the activity against card A's attestation -- while the chain actually names
        # card B's scope -- must be refused: card A genuinely, independently verifies, and the
        # activity chain genuinely, independently verifies under ITS card id, but the two do not
        # name the same scope.
        with self.assertRaises(naming.NamingError) as cm:
            verify_and_recover(card_obj_a, pk_a, objs, task_pk, alg=ALG, profile=PROFILE)
        self.assertEqual(cm.exception.kind, "ForeignCard")

    # ---- F3: this package's OWN construction reproduces the independent oracle byte-for-byte -

    def test_activity_matches_the_independent_oracle_byte_for_byte(self):
        C = _paths.load_naming_cases()
        a = C["a2a"]
        card_id = bytes.fromhex(a["card"]["card_id_hex"])
        task_id = a["task_utf8"]
        # The oracle's own transition sequence, expressed as foreign-native A2A TaskState
        # strings via naming.state_name -- the SAME reverse table this bridge itself uses.
        events = [ForeignTaskEvent(task_id, naming.state_name(tv["to"])) for tv in a["transitions"]]
        transitions, objs = bridge_activity(events, card_id, _seed(0x11), alg=ALG)
        self.assertEqual(len(transitions), len(a["transitions"]))
        for i, t in enumerate(transitions):
            tv = a["transitions"][i]
            self.assertEqual(t.bytes().hex(), tv["body_hex"], "transition[%d].bytes vs oracle" % i)
            self.assertEqual(t.head().hex(), tv["head_hex"], "transition[%d].head vs oracle" % i)
            self.assertEqual(t.id().hex(), tv["id_hex"], "transition[%d].id vs oracle" % i)
            self.assertEqual(t.frm, tv["from"])
            self.assertEqual(t.to, tv["to"])

        # The pinned cross-language signed-object digest (seed=0x11*32) -- Python == Go == Rust.
        import hashlib
        self.assertEqual(hashlib.sha384(objs[0]).hexdigest(),
                          "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787")

        # Round trip through this bridge's own verifier recovers the oracle's own scenario.
        pk = cose.mldsa_keygen("ML-DSA-65", _seed(0x11))
        verified, recovered = verify_activity(objs, card_id, pk, alg=ALG, profile=PROFILE)
        self.assertEqual(recovered, events)

    def test_card_import_body_matches_independent_oracle(self):
        # Sanity check on this package's understanding of the wire format, mirroring
        # impl/python/tests/test_naming.py's own _card_import() construction (Part-1's Import,
        # not this bridge's bridge_card, since the oracle's importer_hex is a fixed literal, not
        # a real derived signer id -- description.verify_import's confused-deputy check would
        # reject it under any real key, by design; that check is exercised separately above).
        C = _paths.load_naming_cases()
        c = C["a2a"]["card"]
        ops = [description.Operation(o["name"], o["effect"], o["requires_approval"]) for o in c["operations"]]
        im = description.Import(bytes.fromhex(c["importer_hex"]), c["format"], bytes.fromhex(c["foreign_hex"]), ops)
        self.assertEqual(im.bytes().hex(), c["import_body_hex"])
        self.assertEqual(im.id().hex(), c["card_id_hex"])
        self.assertEqual(im.foreign, _ORACLE_CARD_BYTES)


if __name__ == "__main__":
    unittest.main()
