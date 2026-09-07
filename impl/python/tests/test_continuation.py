# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C17 N-AALP-CONT flow-continuation conformance for the Python SDK, graded against the shared
independent corpus vectors/continuation/cases.json (NOT produced by this code): the FlowOpen body/
head/content-id (incl. the minimal and empty-vs-populated-approvals forms), the cheap Continuation
body/head hash-chain (incl. the >2^53 seq), the Checkpoint and FlowCommit bodies, the whole-chain
VerifyChain final head, the AboveCeiling escalation refusal, the GapDetected checkpoint (dropped
link + the u64::MAX overflow), the WrongFlow replay refusal, the RangeError out-of-lattice refusal,
the NonCanonical decode refusal, and the look-alike shape refusal (a 2-field FlowCommit fed to the
3-field Checkpoint parser).

The FlowOpen / FlowCommit full ML-DSA-65 signatures are real but not corpus-graded (the corpus
carries no signed vector), so sign/verify is demonstrated in isolation only. test_above_ceiling_
rejected is the mutation target: making the cheap path skip the effect-ceiling check (an escalation
past the one full signature + approval) flips it.

Written test-first; the module is absent until ported, so this fails RED on import until
impl/python/naalp/continuation.py lands.

Run:  python -m unittest -v tests.test_continuation      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cbor, continuation, cose


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "continuation", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/continuation/cases.json not found")


def _hb(s):
    return bytes.fromhex(s)


ALG = cose.ALG_MLDSA65
SEED = bytes(32)
PK = cose.mldsa_keygen("ML-DSA-65", SEED)


class ContinuationConformance(unittest.TestCase):
    C = _vectors()

    def _flow_open(self, fo):
        return continuation.FlowOpen(
            _hb(fo["flow_id_hex"]), fo["effect_ceiling"], [_hb(a) for a in fo["approvals_hex"]])

    def _cont(self, cv, flow_open_id):
        return continuation.Continuation(
            flow_open_id, cv["seq"], cv["effect"], _hb(cv["payload_id_hex"]), _hb(cv["prev_hex"]))

    # ---- FlowOpen byte parity (design §20.2) ----------------------------------------------

    def test_flow_open_bytes_match_oracle(self):
        fo = self.C["flow_open"]
        o = self._flow_open(fo)
        self.assertEqual(o.bytes().hex(), fo["body_hex"])
        self.assertEqual(o.head().hex(), fo["head_hex"])
        self.assertEqual(o.id().hex(), fo["id_hex"])
        # parse round-trips from the body bytes alone (the bearer-authority property)
        p = continuation.parse_flow_open(_hb(fo["body_hex"]))
        self.assertEqual(p.flow_id, _hb(fo["flow_id_hex"]))
        self.assertEqual(p.effect_ceiling, fo["effect_ceiling"])
        self.assertEqual(p.approvals, [_hb(a) for a in fo["approvals_hex"]])

    def test_flow_open_minimal_and_empty_vs_nonempty(self):
        m = self.C["minimal"]
        o = continuation.FlowOpen(_hb(m["flow_id_hex"]), m["effect_ceiling"],
                                  [_hb(a) for a in m["approvals_hex"]])
        self.assertEqual(o.bytes().hex(), m["body_hex"])
        self.assertEqual(o.head().hex(), m["head_hex"])
        self.assertEqual(o.id().hex(), m["id_hex"])
        ev = self.C["empty_vs_nonempty"]
        empty = continuation.parse_flow_open(_hb(ev["empty_approvals"]["body_hex"]))
        self.assertEqual(empty.id().hex(), ev["empty_approvals"]["id_hex"])
        self.assertEqual(empty.approvals, [])
        one = continuation.parse_flow_open(_hb(ev["one_approval"]["body_hex"]))
        self.assertEqual(one.id().hex(), ev["one_approval"]["id_hex"])
        self.assertEqual(len(one.approvals), 1)
        self.assertNotEqual(empty.id(), one.id())    # distinct on the wire and by content-id

    # ---- Continuation cheap hash-chain byte parity (design §20.3) --------------------------

    def test_continuation_bytes_match_oracle(self):
        fo = self.C["flow_open"]
        fid = self._flow_open(fo).id()
        for cv in self.C["continuations"]:
            c = self._cont(cv, fid)
            self.assertEqual(c.bytes().hex(), cv["body_hex"], "seq %d body" % cv["seq"])
            self.assertEqual(c.head().hex(), cv["head_hex"], "seq %d head" % cv["seq"])

    def test_big_seq_round_trips(self):
        bs = self.C["big_seq"]
        seq = int(bs["seq_str"])                     # 72623859790382856 > 2^53, exact (Python bigint)
        self.assertGreater(seq, 2 ** 53)
        fid = self._flow_open(self.C["flow_open"]).id()
        c = continuation.Continuation(fid, seq, bs["effect"], _hb(bs["payload_id_hex"]), _hb(bs["prev_hex"]))
        self.assertEqual(c.bytes().hex(), bs["body_hex"])
        self.assertEqual(c.head().hex(), bs["head_hex"])
        rp = continuation.parse_continuation(_hb(bs["body_hex"]))
        self.assertEqual(rp.seq, seq)

    # ---- whole-chain verification -> final head (design §20.3) -----------------------------

    def test_verify_chain_final_head(self):
        open_ = self._flow_open(self.C["flow_open"])
        conts = [self._cont(cv, open_.id()) for cv in self.C["continuations"]]
        final = continuation.verify_chain(open_, conts)
        self.assertEqual(final.hex(), self.C["final_head_hex"])

    # ---- Checkpoint + FlowCommit bodies + confirm prefix (design §20.4, §20.5) -------------

    def test_checkpoint_body_and_verify(self):
        cp = self.C["checkpoint"]
        open_ = self._flow_open(self.C["flow_open"])
        obj = continuation.Checkpoint(open_.id(), cp["through_seq"], _hb(cp["head_hex"]))
        self.assertEqual(obj.bytes().hex(), cp["body_hex"])
        prefix = [self._cont(cv, open_.id()) for cv in self.C["continuations"][:cp["through_seq"] + 1]]
        self.assertIsNone(continuation.verify_checkpoint(obj, open_, prefix))   # contiguous prefix ok

    def test_flow_commit_body(self):
        fc = self.C["flow_commit"]
        open_ = self._flow_open(self.C["flow_open"])
        obj = continuation.FlowCommit(open_.id(), _hb(fc["final_head_hex"]))
        self.assertEqual(obj.bytes().hex(), fc["body_hex"])

    # ---- the cheap path can never escalate (AboveCeiling) — MUTATION TARGET ----------------

    def test_above_ceiling_rejected(self):
        ac = self.C["above_ceiling"]
        open_ = self._flow_open(self.C["flow_open"])
        c = continuation.Continuation(open_.id(), ac["seq"], ac["effect"],
                                      _hb(ac["payload_id_hex"]), _hb(ac["prev_hex"]))
        self.assertEqual(c.bytes().hex(), ac["body_hex"])
        self.assertEqual(c.head().hex(), ac["head_hex"])
        with self.assertRaises(continuation.ContError) as cm:
            continuation.verify_continuation(c, open_.id(), _hb(ac["prev_hex"]), ac["seq"], ac["ceiling"])
        self.assertEqual(cm.exception.kind, ac["reject"])          # AboveCeiling

    # ---- a dropped/reordered link is a GapDetected checkpoint (design §20.4) ----------------

    def test_gap_detected(self):
        gap = self.C["gap"]
        open_ = self._flow_open(self.C["flow_open"])
        cs = self.C["continuations"]
        # non-contiguous prefix: seq0 then seq2 (seq1 dropped) claimed to cover through_seq=2.
        prefix = [self._cont(cs[0], open_.id()), self._cont(cs[2], open_.id())]
        cp = continuation.Checkpoint(open_.id(), gap["through_seq"], _hb(gap["claimed_head_hex"]))
        with self.assertRaises(continuation.ContError) as cm:
            continuation.verify_checkpoint(cp, open_, prefix)
        self.assertEqual(cm.exception.kind, gap["detect"])         # GapDetected

    def test_checkpoint_overflow_rejected(self):
        co = self.C["checkpoint_overflow"]
        open_ = self._flow_open(self.C["flow_open"])
        through = int(co["through_seq_str"])                       # u64::MAX
        cp = continuation.Checkpoint(open_.id(), through, _hb(co["head_hex"]))
        self.assertEqual(cp.bytes().hex(), co["body_hex"])
        with self.assertRaises(continuation.ContError) as cm:
            continuation.verify_checkpoint(cp, open_, [])          # prefix_len 0
        self.assertEqual(cm.exception.kind, co["reject"])          # GapDetected

    # ---- a continuation replayed under a different FlowOpen fails WrongFlow -----------------

    def test_replay_wrong_flow(self):
        rp = self.C["replay"]
        open_a = self._flow_open(self.C["flow_open"])
        open_b = continuation.parse_flow_open(_hb(rp["flow_open_b_body_hex"]))
        self.assertEqual(open_b.id().hex(), rp["flow_open_b_id_hex"])
        self.assertEqual(open_b.head().hex(), rp["flow_open_b_head_hex"])
        cont0 = self._cont(self.C["continuations"][0], open_a.id())  # carries flow_open_id = A
        with self.assertRaises(continuation.ContError) as cm:
            continuation.verify_continuation(cont0, open_b.id(), open_b.head(), 0, open_b.effect_ceiling)
        self.assertEqual(cm.exception.kind, rp["detect"])          # WrongFlow

    # ---- out-of-lattice effect/ceiling is RangeError, never normalized ---------------------

    def test_range_reject(self):
        rr = self.C["range_reject"]
        with self.assertRaises(continuation.ContError) as cm:
            continuation.parse_flow_open(_hb(rr["flow_open_ceiling_body_hex"]))
        self.assertEqual(cm.exception.kind, rr["reject"])          # RangeError (ceiling=4)
        with self.assertRaises(continuation.ContError) as cm:
            continuation.parse_continuation(_hb(rr["continuation_effect_body_hex"]))
        self.assertEqual(cm.exception.kind, rr["reject"])          # RangeError (effect=4)

    # ---- fail-closed decode + shape refusals -----------------------------------------------

    def test_non_canonical_decode_rejected(self):
        ko = self.C["keys_out_of_order"]
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(_hb(ko["noncanonical_commit_body_hex"]))
        # the canonical form of the same content decodes cleanly
        self.assertIsNotNone(cbor.decode(_hb(ko["canonical_commit_body_hex"])))

    def test_look_alike_shape_rejected(self):
        la = self.C["look_alike"]
        # a 2-field FlowCommit body fed to the 3-field Checkpoint parser is malformed (fail-closed).
        with self.assertRaises(continuation.ContError) as cm:
            continuation.parse_checkpoint(_hb(la["flow_commit_body_hex"]))
        self.assertEqual(cm.exception.kind, "ContMalformed")

    # ---- FlowOpen / FlowCommit full signature in isolation (design §20.2, §20.5) -----------

    def test_flow_open_sign_verify_isolation(self):
        # NOT corpus-graded (no signed vector). Real deterministic ML-DSA-65 over a COSE_Sign1.
        open_ = self._flow_open(self.C["flow_open"])
        obj = continuation.sign_flow_open(open_, ALG, SEED)
        got = continuation.verify_flow_open(obj, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(got.id(), open_.id())
        bad = bytearray(obj)
        bad[-1] ^= 0x01
        with self.assertRaises(continuation.ContError) as cm:
            continuation.verify_flow_open(bytes(bad), cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(cm.exception.kind, "BadSignature")


if __name__ == "__main__":
    unittest.main()
