# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C19 name-bindings + signed A2A task-state profile conformance for the Python SDK (design §22),
graded against the shared independent corpus vectors/naming/cases.json (NOT produced by this code):
the name-binding and task-transition body/head/content-id byte parity, the A2A Agent Card
attestation content-id (a C18 naalp-description-import), the offline name-history walk, hole/fork
detection with the non-repudiable NameForkProof, the A2A legal-edge table (every legal edge accepted,
every illegal edge rejected), the signed task-chain verifier (illegal edge / non-contiguous / bad
start / foreign card / gap / bad signature), the >2^53 seq round-trip, the minimal encodings, the
strict canonical-key rejection, and the look-alike cross-parse rejection.

The chain verifiers run over REAL deterministic ML-DSA-65 signed COSE_Sign1 objects (dilithium-py,
rnd=0). The two cross-language pins (SHA-384 of the seq-0 signed binding and transition, seed=0x11*32)
are the Go+Rust reference constants; asserting them proves Python == Go == Rust byte-identical signed
objects. The A2A legal-edge table is the C19 mutation target: forcing legal_edge to accept every edge
(as the Go/Rust naming red-evidence records) flips test_transition_table_matches_oracle on the
illegal-edge assertion.

Written test-first; the module is absent until ported, so this fails RED on import until
impl/python/naalp/naming.py lands.

Run:  python -m unittest -v tests.test_naming      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cose, description, identity, naming, policy


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "naming", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/naming/cases.json not found")


def _hb(s):
    return bytes.fromhex(s)


ALG = cose.ALG_MLDSA65
PROFILE = cose.PROFILE_PUBLIC

# The Go + Rust reference pins for the deterministic signed seq-0 binding/transition (seed=0x11*32).
PIN_SIGNED_BINDING_SHA384 = "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91"
PIN_SIGNED_TRANSITION_SHA384 = "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787"


def _key(seed_byte):
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk, identity.signer_id(ALG, pk)


class NamingConformance(unittest.TestCase):
    C = _vectors()

    # ---- helpers -------------------------------------------------------------------------

    def _bindings(self):
        n = self.C["name"]
        return [naming.NameBinding(n["name_utf8"], _hb(b["signer_hex"]), b["seq"], _hb(b["prev_hex"]))
                for b in n["bindings"]]

    def _transitions(self):
        a = self.C["a2a"]
        task = a["task_utf8"].encode("utf-8")
        card = _hb(a["card"]["card_id_hex"])
        return [naming.Transition(task, card, t["from"], t["to"], t["seq"], _hb(t["prev_hex"]))
                for t in a["transitions"]]

    def _card_import(self):
        c = self.C["a2a"]["card"]
        ops = [description.Operation(o["name"], o["effect"], o["requires_approval"]) for o in c["operations"]]
        return description.Import(_hb(c["importer_hex"]), c["format"], _hb(c["foreign_hex"]), ops)

    # ---- byte parity (design §22) --------------------------------------------------------

    def test_byte_parity_against_oracle(self):
        n = self.C["name"]
        self.assertEqual(len(n["bindings"]), 3)
        for i, nb in enumerate(self._bindings()):
            bv = n["bindings"][i]
            self.assertEqual(nb.bytes().hex(), bv["body_hex"], "binding[%d].bytes" % i)
            self.assertEqual(nb.head().hex(), bv["head_hex"], "binding[%d].head" % i)
            self.assertEqual(nb.id().hex(), bv["id_hex"], "binding[%d].id" % i)
        # The fork sibling b' at seq 1 also encodes byte-identically.
        fp = n["fork"]["b_prime"]
        bp = naming.NameBinding(n["name_utf8"], _hb(fp["signer_hex"]), fp["seq"], _hb(fp["prev_hex"]))
        self.assertEqual(bp.bytes().hex(), fp["body_hex"])

        a = self.C["a2a"]
        self.assertEqual(len(a["transitions"]), 4)
        for i, tr in enumerate(self._transitions()):
            tv = a["transitions"][i]
            self.assertEqual(tr.bytes().hex(), tv["body_hex"], "transition[%d].bytes" % i)
            self.assertEqual(tr.head().hex(), tv["head_hex"], "transition[%d].head" % i)
            self.assertEqual(tr.id().hex(), tv["id_hex"], "transition[%d].id" % i)

        im = self._card_import()
        self.assertEqual(im.bytes().hex(), a["card"]["import_body_hex"], "card import body")
        self.assertEqual(im.id().hex(), a["card"]["card_id_hex"], "card import id (the bound card)")

    # ---- name-history walk ---------------------------------------------------------------

    def test_walk_history_matches_oracle(self):
        n = self.C["name"]
        bindings = self._bindings()
        events = naming.walk_history(bindings)
        self.assertEqual(len(events), len(n["walk"]))
        for i, e in enumerate(events):
            self.assertEqual(e.seq, n["walk"][i]["seq"])
            self.assertEqual(e.signer.hex(), n["walk"][i]["signer_hex"])
        # The current signer is the last event's signer.
        self.assertEqual(events[-1].signer.hex(), n["bindings"][-1]["signer_hex"])
        # A name change mid-chain breaks the walk (one name per chain).
        bad = list(bindings)
        bad1 = naming.NameBinding("other.name", bindings[1].signer, bindings[1].seq, bindings[1].prev)
        with self.assertRaises(naming.NamingError) as cm:
            naming.walk_history([bad[0], bad1])
        self.assertEqual(cm.exception.kind, "NameChainBroken")

    def test_name_hole_detected_with_position(self):
        n = self.C["name"]
        bindings = self._bindings()
        pos, hole = naming.detect_hole(bindings)
        self.assertFalse(hole, "contiguous chain wrongly reported a hole")
        present = [bindings[0], bindings[2]]     # seq 1 deleted
        pos, hole = naming.detect_hole(present)
        self.assertTrue(hole)
        self.assertEqual(pos, n["hole"]["first_hole_position"])

    def test_name_fork_detected_with_position(self):
        n = self.C["name"]
        bindings = self._bindings()
        fp = n["fork"]["b_prime"]
        bp = naming.NameBinding(n["name_utf8"], _hb(fp["signer_hex"]), fp["seq"], _hb(fp["prev_hex"]))
        pos, fork = naming.detect_fork(bindings[1], bp)
        self.assertTrue(fork)
        self.assertEqual(pos, n["fork"]["position"])
        # Identical bindings are a benign duplicate; a different seq is a distinct binding.
        self.assertFalse(naming.detect_fork(bindings[1], bindings[1])[1])
        self.assertFalse(naming.detect_fork(bindings[1], bindings[2])[1])

        # Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
        seed, pk, sid = _key(0x11)
        _, fpk, _ = _key(0x22)
        signed_a = naming.sign_binding(bindings[1], ALG, seed)
        signed_b = naming.sign_binding(bp, ALG, seed)
        proof = naming.NameForkProof(sid.encode(), signed_a, signed_b)
        self.assertEqual(proof.verify(PROFILE, ALG, pk), n["fork"]["position"])
        # A foreign key does not verify the accused's signatures.
        with self.assertRaises(naming.NamingError) as cm:
            proof.verify(PROFILE, ALG, fpk)
        self.assertEqual(cm.exception.kind, "BadSignature")
        # An unnamed accused, and identical bodies, are NameForkProofInvalid.
        with self.assertRaises(naming.NamingError) as cm:
            naming.NameForkProof(b"", signed_a, signed_b).verify(PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "NameForkProofInvalid")
        with self.assertRaises(naming.NamingError) as cm:
            naming.NameForkProof(sid.encode(), signed_a, signed_a).verify(PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "NameForkProofInvalid")

    def test_name_chain_verify_fail_closed(self):
        n = self.C["name"]
        seed, pk, _ = _key(0x11)
        _, fpk, _ = _key(0x22)
        # Build a signed chain via the Registrar (rotation A -> B -> C).
        reg = naming.Registrar(n["name_utf8"], ALG, seed)
        bindings, objs = [], []
        for bv in n["bindings"]:
            nb, obj = reg.append(_hb(bv["signer_hex"]))
            bindings.append(nb)
            objs.append(obj)
        for i, nb in enumerate(bindings):
            self.assertEqual(nb.bytes().hex(), n["bindings"][i]["body_hex"], "registrar reproduces oracle body")
        verified = naming.verify_chain(objs, PROFILE, ALG, pk)
        self.assertEqual(len(naming.walk_history(verified)), len(bindings))
        # A reordered chain breaks the prev/seq linkage.
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_chain([objs[0], objs[2], objs[1]], PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "NameChainBroken")
        # A tampered object fails its signature.
        corrupt = bytearray(objs[1])
        corrupt[-1] ^= 0x01
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_chain([objs[0], bytes(corrupt), objs[2]], PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "BadSignature")
        # A foreign verifier authenticates none of the bindings.
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_chain(objs, PROFILE, ALG, fpk)
        self.assertEqual(cm.exception.kind, "BadSignature")
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_binding(objs[0], PROFILE, ALG, fpk)
        self.assertEqual(cm.exception.kind, "BadSignature")

    # ---- A2A legal-edge table (THIS is the mutation-target assertion) ----------------------

    def test_transition_table_matches_oracle(self):
        a = self.C["a2a"]
        self.assertEqual(len(naming.legal_edges()), len(a["legal_edges"]))
        for e in a["legal_edges"]:
            self.assertTrue(naming.legal_edge(e[0], e[1]), "legal edge %d->%d" % (e[0], e[1]))
            self.assertIsNone(naming.verify_transition(e[0], e[1]))
        for e in a["illegal_edges"]:
            self.assertFalse(naming.legal_edge(e[0], e[1]), "illegal edge %d->%d wrongly accepted" % (e[0], e[1]))
            with self.assertRaises(naming.NamingError) as cm:
                naming.verify_transition(e[0], e[1])
            self.assertEqual(cm.exception.kind, "IllegalTransition")
        # Categories match the oracle.
        self.assertEqual(naming.START_STATE, a["states"]["start"])
        for s in a["states"]["terminal"]:
            self.assertTrue(naming.is_terminal(s))
        for s in a["states"]["interrupted"]:
            self.assertTrue(naming.is_interrupted(s))
        # A terminal state has no legal out-edge.
        for s in a["states"]["terminal"]:
            for to in range(8):
                self.assertFalse(naming.legal_edge(s, to), "terminal %d has out-edge to %d" % (s, to))

    def test_task_chain_legal_and_illegal(self):
        a = self.C["a2a"]
        seed, pk, _ = _key(0x11)
        card = _hb(a["card"]["card_id_hex"])
        task = a["task_utf8"].encode("utf-8")
        transitions = self._transitions()
        objs = [naming.sign_transition(t, ALG, seed) for t in transitions]
        # LEGAL ordered lifecycle verifies.
        self.assertEqual(len(naming.verify_task_chain(objs, card, PROFILE, ALG, pk)), 4)

        def chain_err(trs):
            with self.assertRaises(naming.NamingError) as cm:
                naming.verify_task_chain([naming.sign_transition(t, ALG, seed) for t in trs], card, PROFILE, ALG, pk)
            return cm.exception.kind

        t0 = naming.Transition(task, card, naming.STATE_SUBMITTED, naming.STATE_WORKING, 0, naming.genesis())
        # ILLEGAL edge inside a chain: working -> submitted.
        illegal = naming.Transition(task, card, naming.STATE_WORKING, naming.STATE_SUBMITTED, 1, t0.head())
        self.assertEqual(chain_err([t0, illegal]), "IllegalTransition")
        # NON-CONTIGUOUS from: input-required -> working after a working->? gap.
        noncontig = naming.Transition(task, card, naming.STATE_INPUT_REQUIRED, naming.STATE_WORKING, 1, t0.head())
        self.assertEqual(chain_err([t0, noncontig]), "IllegalTransition")
        # BAD START: seq-0 does not leave the start state.
        badstart = naming.Transition(task, card, naming.STATE_WORKING, naming.STATE_INPUT_REQUIRED, 0, naming.genesis())
        self.assertEqual(chain_err([badstart]), "IllegalTransition")
        # FOREIGN CARD.
        fc = naming.Transition(task, _hb(a["foreign_card_id_hex"]), naming.STATE_SUBMITTED, naming.STATE_WORKING, 0, naming.genesis())
        self.assertEqual(chain_err([fc]), "ForeignCard")
        # GAP: present [t0, t2].
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_task_chain([objs[0], objs[2]], card, PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "TaskChainBroken")
        # BAD SIGNATURE.
        corrupt = bytearray(objs[0])
        corrupt[-1] ^= 0x01
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_task_chain([bytes(corrupt), objs[1], objs[2], objs[3]], card, PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_task_gap_detected_with_position(self):
        a = self.C["a2a"]
        transitions = self._transitions()
        self.assertFalse(naming.detect_task_gap(transitions)[1])
        present = [transitions[0], transitions[2]]
        pos, gap = naming.detect_task_gap(present)
        self.assertTrue(gap)
        self.assertEqual(pos, a["gap"]["first_gap_position"])

    def test_card_attestation_binds_profile(self):
        a = self.C["a2a"]
        seed, pk, _ = _key(0x11)
        im = self._card_import()
        card = im.id()
        self.assertEqual(card.hex(), a["card"]["card_id_hex"])
        submit, ok = im.operation("submit")
        self.assertTrue(ok)
        self.assertEqual(submit.effect_class(), policy.IDEMPOTENT_WRITE)
        self.assertTrue(submit.requires_approval_flag())
        # A chain bound to this card verifies.
        objs = [naming.sign_transition(t, ALG, seed) for t in self._transitions()]
        self.assertEqual(len(naming.verify_task_chain(objs, card, PROFILE, ALG, pk)), 4)
        # A different importer yields a different card id; a chain carrying it is refused.
        other = description.Import(b"IMPORTER_ID_B", im.format, im.foreign, im.operations)
        self.assertNotEqual(other.id(), card)
        foreign_t = naming.Transition(a["task_utf8"].encode("utf-8"), other.id(),
                                      naming.STATE_SUBMITTED, naming.STATE_WORKING, 0, naming.genesis())
        with self.assertRaises(naming.NamingError) as cm:
            naming.verify_task_chain([naming.sign_transition(foreign_t, ALG, seed)], card, PROFILE, ALG, pk)
        self.assertEqual(cm.exception.kind, "ForeignCard")

    def test_malformed_rejected(self):
        with self.assertRaises(naming.NamingError) as cm:
            naming.parse_name_binding(bytes([0x80]))          # an empty CBOR array
        self.assertEqual(cm.exception.kind, "NameMalformed")
        with self.assertRaises(naming.NamingError) as cm:
            naming.parse_transition(bytes([0x00]))            # a bare uint 0
        self.assertEqual(cm.exception.kind, "NameMalformed")

    # ---- cross-language signed-object byte parity (Python == Go == Rust) -------------------

    def test_cross_lang_signed_binding_pin(self):
        import hashlib
        nb = self._bindings()[0]
        seed = bytes([0x11]) * 32
        obj = naming.sign_binding(nb, ALG, seed)
        self.assertEqual(hashlib.sha384(obj).hexdigest(), PIN_SIGNED_BINDING_SHA384,
                         "Python signed name-binding must be byte-identical to Go+Rust")

    def test_cross_lang_signed_transition_pin(self):
        import hashlib
        tr = self._transitions()[0]
        seed = bytes([0x11]) * 32
        obj = naming.sign_transition(tr, ALG, seed)
        self.assertEqual(hashlib.sha384(obj).hexdigest(), PIN_SIGNED_TRANSITION_SHA384,
                         "Python signed task-transition must be byte-identical to Go+Rust")

    # ---- >2^53 seq round-trip, minimal, canonical-key, look-alike --------------------------

    def test_oversized_seq_round_trip(self):
        n = self.C["name"]
        a = self.C["a2a"]
        bseq = int(n["big_seq"]["seq_str"])
        self.assertGreater(bseq, 1 << 53)
        nb = naming.NameBinding(n["name_utf8"], _hb(n["big_seq"]["signer_hex"]), bseq, _hb(n["big_seq"]["prev_hex"]))
        self.assertEqual(nb.bytes().hex(), n["big_seq"]["body_hex"])
        self.assertEqual(naming.parse_name_binding(nb.bytes()).seq, bseq)

        tseq = int(a["big_seq"]["seq_str"])
        tr = naming.Transition(a["task_utf8"].encode("utf-8"), _hb(a["card"]["card_id_hex"]),
                               a["big_seq"]["from"], a["big_seq"]["to"], tseq, _hb(a["big_seq"]["prev_hex"]))
        self.assertEqual(tr.bytes().hex(), a["big_seq"]["body_hex"])
        self.assertEqual(naming.parse_transition(tr.bytes()).seq, tseq)

    def test_minimal(self):
        n = self.C["name"]["minimal"]
        a = self.C["a2a"]["minimal"]
        nb = naming.NameBinding(n["name_utf8"], _hb(n["signer_hex"]), n["seq"], _hb(n["prev_hex"]))
        self.assertEqual(nb.bytes().hex(), n["body_hex"])
        self.assertEqual(nb.id().hex(), n["id_hex"])
        self.assertIsNotNone(naming.parse_name_binding(nb.bytes()))
        tr = naming.Transition(_hb(a["task_hex"]), _hb(a["card_hex"]), a["from"], a["to"], a["seq"], _hb(a["prev_hex"]))
        self.assertEqual(tr.bytes().hex(), a["body_hex"])
        self.assertIsNotNone(naming.parse_transition(tr.bytes()))

    def test_keys_out_of_order_rejected(self):
        from naalp import cbor
        n = self.C["name"]
        koo = n["keys_out_of_order"]
        b0 = n["bindings"][0]
        nb = naming.NameBinding(n["name_utf8"], _hb(b0["signer_hex"]), b0["seq"], _hb(b0["prev_hex"]))
        self.assertEqual(nb.bytes().hex(), koo["canonical_binding_body_hex"])
        self.assertIsNotNone(cbor.decode(_hb(koo["canonical_binding_body_hex"])))
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(_hb(koo["noncanonical_binding_body_hex"]))

    def test_look_alike_rejected_by_sibling(self):
        la = self.C["name"]["look_alike"]
        with self.assertRaises(naming.NamingError) as cm:
            naming.parse_transition(_hb(la["binding_body_hex"]))
        self.assertEqual(cm.exception.kind, "NameMalformed")
        with self.assertRaises(naming.NamingError) as cm:
            naming.parse_name_binding(_hb(la["transition_body_hex"]))
        self.assertEqual(cm.exception.kind, "NameMalformed")


if __name__ == "__main__":
    unittest.main()
