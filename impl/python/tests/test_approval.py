# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C6 approval-object + single-use consume-ledger conformance for the Python SDK, graded against
the shared independent corpus vectors/approval/cases.json (NOT produced by this code): the §7.1
approval body/head/content-id, the durable hash-chained consume ledger (genesis head, per-consume
entry bytes + head_after, AlreadyConsumed on a replayed id, final head), the §7.3 expiry, and the
ApprovalMismatch binding property. The approval SIGNATURE is real deterministic ML-DSA-65 signed
over the body bytes directly (as the reference cose.Signer.Sign); the corpus carries no signed
vector, so sign/verify is demonstrated in isolation only -- stated honestly, not corpus-graded.

The SECURITY-CRITICAL property is the atomic single-use consume: a consume must succeed exactly
once, and every subsequent consume of the same approval id is rejected AlreadyConsumed (fail-closed).
The first-write-wins compare-and-set is serialised under one lock (as the Go single-writer mutex),
so a read-then-write TOCTOU cannot let two consumers spend one approval -- the replay skeleton key
this capability exists to prevent. test_second_consume_rejected_alreadyconsumed and
test_consume_atomic_under_race are the mutation targets: making consume always-succeed flips both.

Written test-first; the module is absent until ported, so this fails RED on import until
impl/python/naalp/approval.py lands.

Run:  python -m unittest -v tests.test_approval      (from impl/python/)
"""
import json
import os
import tempfile
import threading
import unittest

from naalp import approval, cbor, cose, policy


def _vectors_file(*parts):
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", *parts)
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/%s not found" % os.path.join(*parts))


def _vectors():
    return _vectors_file("approval", "cases.json")


def _cr_vectors():
    return _vectors_file("consume_receipt", "cases.json")


def _td_vectors():
    return _vectors_file("trust_decision", "cases.json")


def _hb(s):
    return bytes.fromhex(s)


def _ledger_key(seed_byte):
    """A throwaway ML-DSA-65 (seed, pubkey) pair for an ordering-authority / approver test key,
    mirroring impl/go/approval's ledgerKey(t, seedByte)."""
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _cr_receipt(rj):
    return approval.ConsumeReceipt(_hb(rj["ledger_hex"]), _hb(rj["approval_id_hex"]), rj["position"])


ALG = cose.ALG_MLDSA65
SEED = bytes(32)                              # approver test key (isolation; sig not corpus-graded)
PK = cose.mldsa_keygen("ML-DSA-65", SEED)


class ApprovalConformance(unittest.TestCase):
    C = _vectors()

    def _record(self, av):
        return approval.ApprovalRecord(
            _hb(av["approves_hex"]), av["approver"], av["grant"],
            _hb(av["nonce_hex"]), av["not_after"])

    # ---- §7.1 approval body / content-id byte parity --------------------------------------

    def test_approval_bodies_match_oracle(self):
        for av in self.C["approvals"]:
            r = self._record(av)
            self.assertEqual(r.bytes().hex(), av["record_hex"], av["name"])
            self.assertEqual(r.id().hex(), av["approval_id_hex"], av["name"])

    # ---- §7.2 hash-chained consume ledger byte parity -------------------------------------

    def test_ledger_genesis_head(self):
        with tempfile.TemporaryDirectory() as d:
            led = approval.open_ledger(os.path.join(d, "consume.log"))
            try:
                self.assertEqual(led.head().hex(), self.C["ledger"]["genesis_head_hex"])
                self.assertEqual(len(led), 0)
            finally:
                led.close()

    def test_ledger_consume_chain_matches_oracle(self):
        v = self.C["ledger"]
        with tempfile.TemporaryDirectory() as d:
            led = approval.open_ledger(os.path.join(d, "consume.log"))
            try:
                c0 = v["consumes"][0]
                e0 = led.consume(_hb(c0["approval_id_hex"]), c0["by"])
                self.assertEqual(e0.seq, c0["seq"])
                self.assertEqual(e0.bytes().hex(), c0["entry_hex"], "consume 0 entry")
                self.assertEqual(led.head().hex(), c0["head_after_hex"], "head after 0")
                c1 = v["consumes"][1]
                e1 = led.consume(_hb(c1["approval_id_hex"]), c1["by"])
                self.assertEqual(e1.seq, c1["seq"])
                self.assertEqual(e1.bytes().hex(), c1["entry_hex"], "consume 1 entry")
                self.assertEqual(led.head().hex(), c1["head_after_hex"], "head after 1")
                self.assertEqual(led.head().hex(), v["final_head_hex"], "final head")
                self.assertEqual(len(led), 2)
            finally:
                led.close()

    # ---- the atomic single-use property (SECURITY-CRITICAL, mutation target) ---------------

    def test_second_consume_rejected_alreadyconsumed(self):
        v = self.C["ledger"]
        c0 = v["consumes"][0]
        c2 = v["consumes"][2]            # same approval id as c0, different consumer -> AlreadyConsumed
        self.assertEqual(c2["expect"], "AlreadyConsumed")
        self.assertEqual(c2["approval_id_hex"], c0["approval_id_hex"])
        with tempfile.TemporaryDirectory() as d:
            led = approval.open_ledger(os.path.join(d, "consume.log"))
            try:
                led.consume(_hb(c0["approval_id_hex"]), c0["by"])
                self.assertTrue(led.is_consumed(_hb(c0["approval_id_hex"])))
                head_before = led.head()
                with self.assertRaises(approval.ApprovalError) as cm:
                    led.consume(_hb(c2["approval_id_hex"]), c2["by"])
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")
                # fail-closed: a rejected consume appends nothing (head + length unchanged).
                self.assertEqual(led.head(), head_before)
                self.assertEqual(len(led), 1)
            finally:
                led.close()

    def test_consume_atomic_under_race(self):
        # 16 threads race to consume the SAME approval id: exactly one wins, every other is rejected
        # AlreadyConsumed, and exactly one entry lands. A non-atomic consume would let many win.
        v = self.C["ledger"]
        aid = _hb(v["consumes"][0]["approval_id_hex"])
        with tempfile.TemporaryDirectory() as d:
            led = approval.open_ledger(os.path.join(d, "consume.log"))
            try:
                wins, rejects = [], []
                barrier = threading.Barrier(16)

                def worker(i):
                    barrier.wait()
                    try:
                        led.consume(aid, "consumer-%d" % i)
                        wins.append(i)
                    except approval.ApprovalError as e:
                        if e.kind == "AlreadyConsumed":
                            rejects.append(i)

                ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join()
                self.assertEqual(len(wins), 1, "exactly one consumer must win the CAS")
                self.assertEqual(len(rejects), 15, "every losing consumer must be AlreadyConsumed")
                self.assertEqual(len(led), 1, "exactly one ledger entry for one approval id")
            finally:
                led.close()

    # ---- §7 verify: expiry + the ApprovalMismatch binding, fail-closed ---------------------

    def test_verify_approval_mismatch_and_expiry(self):
        av = self.C["approvals"][0]      # approval A
        r = self._record(av)
        sig = approval.sign_approval(r, ALG, SEED)   # real ML-DSA-65 (isolation; not corpus-graded)
        args_id = _hb(av["approves_hex"])            # the exact args this approval binds
        exp = self.C["expiry"]
        # valid at not_after (inclusive) -> ok (returns None)
        self.assertIsNone(approval.verify_approval(r, ALG, PK, sig, args_id, exp["valid_at"]))
        # past not_after -> ApprovalExpired
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_approval(r, ALG, PK, sig, args_id, exp["expired_at"])
        self.assertEqual(cm.exception.kind, "ApprovalExpired")
        # a changed bound object (different args content id) no longer matches -> ApprovalMismatch
        wrong = _hb(self.C["mismatch"]["wrong_args_id_hex"])
        self.assertNotEqual(wrong, args_id)
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_approval(r, ALG, PK, sig, wrong, exp["valid_at"])
        self.assertEqual(cm.exception.kind, "ApprovalMismatch")

    def test_verify_approval_bad_signature_failclosed(self):
        av = self.C["approvals"][0]
        r = self._record(av)
        sig = bytearray(approval.sign_approval(r, ALG, SEED))
        sig[-1] ^= 0x01                              # tamper one signature byte
        args_id = _hb(av["approves_hex"])
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_approval(r, ALG, PK, bytes(sig), args_id, av["not_after"])
        self.assertEqual(cm.exception.kind, "BadSignature")

    def test_held_result_signed_in_isolation(self):
        # The §7.4 held outcome is a distinct signed non-success result (never a silent success).
        av = self.C["approvals"][0]
        h = approval.HeldResult(_hb(av["approves_hex"]), "awaiting approver")
        sig = approval.sign_held(h, ALG, SEED)
        self.assertTrue(cose.cose_verify1_raw(ALG, PK, h.bytes(), sig))

    # ---- fail-closed ledger integrity (§7.2 durability) -----------------------------------

    def test_ledger_replay_detects_corruption_failclosed(self):
        v = self.C["ledger"]
        c0 = v["consumes"][0]
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "consume.log")
            led = approval.open_ledger(p)
            led.consume(_hb(c0["approval_id_hex"]), c0["by"])
            led.close()
            with open(p, "rb") as f:
                raw = bytearray(f.read())
            raw[10] ^= 0x01                          # flip a byte inside entry 0's prev (genesis) field
            with open(p, "wb") as f:
                f.write(raw)
            with self.assertRaises(approval.ApprovalError) as cm:
                approval.open_ledger(p)
            self.assertEqual(cm.exception.kind, "LedgerCorrupt")


class ConsumeReceiptConformance(unittest.TestCase):
    """T1.5 (NAALP-REQ-121) ledger-signed consume-receipt / fork-evidence / receipt-set
    conformance, graded against the independent corpus vectors/consume_receipt/cases.json (NOT
    produced by this code): every receipt body byte-parity, ledger-signed sign/verify with
    fail-closed rejection (unnamed ledger, tampered signature, wrong ledger key), fork detection
    (same-ledger different position; cross-ledger same approval id), the first-append-wins
    compare-and-set MUTATION anchor, and the section-4 wire cases (non-canonical key order, a
    64-bit position, empty-vs-absent ledger). Mirrors impl/go/approval/approval_test.go's T1.5
    section and impl/rust/src/approval.rs's consume_receipt_* tests.

    test_consume_first_append_wins_cas is the mutation target: mutating the ConsumeWithReceipt
    compare-and-set to always-succeed mints a second receipt at position 1 for the same approval
    id, flipping AlreadyConsumed -> a second receipt and len(l) 1 -> 2.
    """

    C = _cr_vectors()

    def test_consume_receipt_bytes_match_oracle(self):
        all_cases = [self.C["base"]] + list(self.C["sequence"])
        for f in self.C["forks"]:
            all_cases += [f["a"], f["b"]]
        self.assertTrue(all_cases)
        for rj in all_cases:
            got = _cr_receipt(rj).bytes().hex()
            self.assertEqual(got, rj["body_hex"], rj.get("name", rj["body_hex"]))

    def test_open_ledger_signed_failclosed(self):
        # An unnamed ordering authority (empty ledger id) or a missing signing key (seed=None) is
        # refused fail-closed -- it cannot mint an accountable ledger-signed receipt.
        seed, _pk = _ledger_key(0x41)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(approval.ApprovalError) as cm:
                approval.open_ledger_signed(os.path.join(d, "unnamed.wal"), b"", ALG, seed)
            self.assertEqual(cm.exception.kind, "LedgerUnsigned")
            with self.assertRaises(approval.ApprovalError) as cm:
                approval.open_ledger_signed(os.path.join(d, "keyless.wal"), b"ledger-x", ALG, None)
            self.assertEqual(cm.exception.kind, "LedgerUnsigned")

    def test_consume_receipt_sign_verify_failclosed(self):
        seed, pk = _ledger_key(0x51)
        r = _cr_receipt(self.C["base"])
        sig = approval.sign_consume_receipt(r, ALG, seed)
        self.assertIsNone(approval.verify_consume_receipt(r, ALG, pk, sig))

        # unnamed ordering authority (empty ledger id) is not evidence.
        unnamed = approval.ConsumeReceipt(b"", r.approval_id, r.position)
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_consume_receipt(unnamed, ALG, pk, sig)
        self.assertEqual(cm.exception.kind, "ConsumeReceiptUnsigned")

        # tampered signature.
        bad = bytearray(sig)
        bad[-1] ^= 0x01
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_consume_receipt(r, ALG, pk, bytes(bad))
        self.assertEqual(cm.exception.kind, "ConsumeReceiptUnsigned")

        # wrong ledger key.
        _other_seed, other_pk = _ledger_key(0x52)
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_consume_receipt(r, ALG, other_pk, sig)
        self.assertEqual(cm.exception.kind, "ConsumeReceiptUnsigned")

    def test_consume_fork_detected_same_ledger(self):
        fk = next(f for f in self.C["forks"] if f["name"] == "same_ledger_diff_position")
        self.assertEqual(fk["expect"], "fork")
        seed, pk = _ledger_key(0x41)  # one ledger signs both conflicting positions (a partition)
        ra, rb = _cr_receipt(fk["a"]), _cr_receipt(fk["b"])
        sig_a = approval.sign_consume_receipt(ra, ALG, seed)
        sig_b = approval.sign_consume_receipt(rb, ALG, seed)

        def resolve(lid):
            return (ALG, pk) if lid == ra.ledger else None

        rs = approval.new_receipt_set(resolve)
        self.assertIsNone(rs.observe(ra, sig_a))
        fe = rs.observe(rb, sig_b)
        self.assertIsNotNone(fe, "fork not detected on same approval id / different positions")
        self.assertNotEqual(fe.a.position, fe.b.position, "fork evidence hides the position conflict")
        self.assertIsNone(fe.verify(resolve))

        # a byte-identical re-emission is a benign duplicate, never flagged.
        rs2 = approval.new_receipt_set(resolve)
        rs2.observe(ra, sig_a)
        self.assertIsNone(rs2.observe(ra, sig_a))

    def test_consume_fork_cross_ledger(self):
        # Two DIFFERENT ledgers each sign a receipt for the SAME approval id (a single-use
        # approval spent twice) -- two INDEPENDENT ordering authorities that cannot see each
        # other, each locally successful; comparing the two resulting receipts surfaces the fork
        # (the double spend is not prevented, only made provable on comparison).
        #
        # Run sequentially rather than on separate threads (unlike impl/go's goroutine-driven
        # TestConsumeForkCrossLedger): this port's underlying ML-DSA library (dilithium_py, wrapped
        # by naalp.cose) is NOT thread-safe for concurrent sign/verify calls from different threads
        # -- reproduced independently outside this test (~15-20% signature corruption rate under
        # true thread concurrency). That is a property of the shared crypto dependency, out of
        # this cluster's scope (cose.py is not touched here); it does not weaken what this test
        # proves -- no assertion here depends on interleaving order, only on the two INDEPENDENTLY
        # minted receipts after both consumes complete, which is the real property under test.
        ledger_a = _hb(self.C["ledgers"]["a_hex"])
        ledger_b = _hb(self.C["ledgers"]["b_hex"])
        approval_x = _hb(self.C["approvals"]["x_hex"])
        seed_a, pk_a = _ledger_key(0x41)
        seed_b, pk_b = _ledger_key(0x42)

        with tempfile.TemporaryDirectory() as d:
            l_a = approval.open_ledger_signed(os.path.join(d, "a.wal"), ledger_a, ALG, seed_a)
            l_b = approval.open_ledger_signed(os.path.join(d, "b.wal"), ledger_b, ALG, seed_b)
            try:
                results = []
                for l in (l_a, l_b):
                    _e, r, sig = l.consume_with_receipt(approval_x, "requester")
                    results.append((r, sig))
                self.assertEqual(len(results), 2)

                def resolve(lid):
                    if lid == ledger_a:
                        return (ALG, pk_a)
                    if lid == ledger_b:
                        return (ALG, pk_b)
                    return None

                rs = approval.new_receipt_set(resolve)
                fork = None
                for r, sig in results:
                    fe = rs.observe(r, sig)
                    if fe is not None:
                        fork = fe
                self.assertIsNotNone(fork, "cross-ledger double spend not detected")
                self.assertNotEqual(fork.a.ledger, fork.b.ledger, "cross-ledger evidence names one ledger twice")
                self.assertIsNone(fork.verify(resolve))
            finally:
                l_a.close()
                l_b.close()

    def test_consume_first_append_wins_cas(self):
        # T1.5 CAS MUTATION anchor: on ONE honest signed ledger, consuming the same approval id
        # twice must yield exactly ONE ledger-signed receipt (first-append-wins): the first
        # consume returns a receipt at position 0, the second raises AlreadyConsumed and signs
        # nothing. If the CAS in consume_with_receipt were mutated to always-succeed, the second
        # consume would mint a SECOND receipt at position 1 for the same approval id.
        ledger_a = _hb(self.C["ledgers"]["a_hex"])
        approval_x = _hb(self.C["approvals"]["x_hex"])
        seed, _pk = _ledger_key(0x41)
        with tempfile.TemporaryDirectory() as d:
            l = approval.open_ledger_signed(os.path.join(d, "cas.wal"), ledger_a, ALG, seed)
            try:
                e, r1, _sig1 = l.consume_with_receipt(approval_x, "requester")
                self.assertEqual(e.seq, 0)
                self.assertEqual(r1.position, 0)

                with self.assertRaises(approval.ApprovalError) as cm:
                    l.consume_with_receipt(approval_x, "requester")
                self.assertEqual(cm.exception.kind, "AlreadyConsumed",
                                  "second consume must be first-append-wins")
                self.assertEqual(len(l), 1, "ledger must have exactly one entry")
            finally:
                l.close()

    def test_consume_receipt_exactly_once_under_race(self):
        ledger_a = _hb(self.C["ledgers"]["a_hex"])
        approval_x = _hb(self.C["approvals"]["x_hex"])
        seed, pk = _ledger_key(0x41)
        with tempfile.TemporaryDirectory() as d:
            l = approval.open_ledger_signed(os.path.join(d, "race.wal"), ledger_a, ALG, seed)
            try:
                wins, alreadys, winner = [], [], []
                barrier = threading.Barrier(16)

                def worker(i):
                    barrier.wait()
                    try:
                        _e, r, sig = l.consume_with_receipt(approval_x, "requester-%d" % i)
                        wins.append(i)
                        winner.append((r, sig))
                    except approval.ApprovalError as e:
                        if e.kind == "AlreadyConsumed":
                            alreadys.append(i)

                ts = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
                for t in ts:
                    t.start()
                for t in ts:
                    t.join()
                self.assertEqual(len(wins), 1, "exactly-once violated")
                self.assertEqual(len(alreadys), 15)
                self.assertEqual(len(l), 1)

                # the single minted receipt is not a fork with itself.
                rs = approval.new_receipt_set(lambda lid: (ALG, pk) if lid == ledger_a else None)
                r, sig = winner[0]
                self.assertIsNone(rs.observe(r, sig), "sole winning receipt flagged")
            finally:
                l.close()

    def test_consume_receipt_wire_cases(self):
        w = self.C["wire"]

        # keys out of order -> the strict decoder rejects NonCanonical.
        noncanon = _hb(w["keys_out_of_order"]["payload_hex"])
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(noncanon)
        # the canonical variant of the same logical receipt decodes cleanly.
        cbor.decode(_hb(w["keys_out_of_order"]["canonical_payload_hex"]))

        # position too large: a 64-bit uint position round-trips (encode == oracle, decode == value).
        ledger_x = _hb(self.C["base"]["ledger_hex"])
        approval_x = _hb(self.C["base"]["approval_id_hex"])
        for big in w["position_too_large"]:
            # R12 (NAALP-01-03): a position above 2^53 is carried as a decimal string so a float64
            # decoder cannot round it; parse it to an exact int (Python ints are arbitrary precision).
            big_pos = int(big["position"])
            r = approval.ConsumeReceipt(ledger_x, approval_x, big_pos)
            self.assertEqual(r.bytes().hex(), big["body_hex"], big["name"])
            v = cbor.decode(_hb(big["body_hex"]))
            pos = None
            for k, val in v.pairs:
                if isinstance(k, cbor.U) and k.v == 3 and isinstance(val, cbor.U):
                    pos = val.v
            self.assertEqual(pos, big_pos, big["name"])

        # empty-ledger receipt: well-formed bytes (match oracle) but verify-rejected fail-closed,
        # and its bytes differ from the absent-ledger variant (empty != absent).
        el = w["empty_ledger"]
        empty = approval.ConsumeReceipt(_hb(el["ledger_hex"]), _hb(el["approval_id_hex"]), el["position"])
        self.assertEqual(empty.bytes().hex(), el["body_hex"])
        _seed, pk = _ledger_key(0x41)
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_consume_receipt(empty, ALG, pk, b"\x00" * 10)
        self.assertEqual(cm.exception.kind, "ConsumeReceiptUnsigned")
        self.assertNotEqual(el["body_hex"], w["absent_ledger"]["body_hex"], "empty != absent")


class TrustDecisionConformance(unittest.TestCase):
    """R-TDCS-3/4/5 (design.md §25, C22) trust-decision closure-sovereignty conformance.
    R-TDCS-5 (audience) and R-TDCS-3 (refusal) are graded against the independent corpus
    vectors/trust_decision/cases.json (NOT produced by this code); R-TDCS-4 (freshness
    independence) and R-TDCS-2 (deterministic verification) are behavioral graders built from
    real signed material, mirroring impl/go/approval/tdcs_test.go and wire_tdcs_test.go.

    test_tdcs4_freshness_independence is the mutation target for the distinctness check (removing
    the party==ledger comparison flips the self-asserted case from rejected to accepted);
    test_tdcs3_refusal_coarse_and_no_leak's unknown-outcome reject is the mutation target for
    is_known_refusal_outcome (see the red-evidence mutation recorded for this port)."""

    C = _td_vectors()

    def test_tdcs5_audience_byte_parity_and_check(self):
        a = self.C["audience"]
        for tc in a["cases"]:
            rec = approval.ApprovalRecord(
                _hb(a["approves_hex"]), a["approver"], a["grant"],
                _hb(a["nonce_hex"]), a["not_after"], tc["audience"])
            self.assertEqual(rec.bytes().hex(), tc["record_hex"], tc["name"])
            self.assertEqual(rec.id().hex(), tc["approval_id_hex"], tc["name"])

        # A named audience must change the signed bytes vs the absent-audience approval -- naming a
        # context is not silently invisible.
        present = approval.ApprovalRecord(
            _hb(a["approves_hex"]), a["approver"], a["grant"],
            _hb(a["nonce_hex"]), a["not_after"], a["use_context_match"])
        absent = approval.ApprovalRecord(
            _hb(a["approves_hex"]), a["approver"], a["grant"],
            _hb(a["nonce_hex"]), a["not_after"])
        self.assertNotEqual(present.bytes(), absent.bytes())

        # the check: named audience must match the use context; absent audience passes any context.
        self.assertIsNone(approval.verify_audience(present, a["use_context_match"]))
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_audience(present, a["use_context_mismatch"])
        self.assertEqual(cm.exception.kind, "AudienceMismatch")
        self.assertIsNone(approval.verify_audience(absent, a["use_context_mismatch"]))

    def test_tdcs3_refusal_coarse_and_no_leak(self):
        r = self.C["refusal"]
        full_record = _hb(r["full_record_hex"])
        record_id = _hb(r["full_record_id_hex"])
        reason = r["leaked_reason"].encode("utf-8")

        for tc in r["cases"]:
            ref = approval.refusal_from_record(tc["outcome"], full_record)
            b = ref.bytes()
            self.assertEqual(b.hex(), tc["record_hex"], tc["name"])
            self.assertNotIn(reason, b, "%s: the record's reason LEAKED into the party-visible refusal" % tc["name"])
            self.assertIn(record_id, b, "%s: refusal does not carry the full-record content id" % tc["name"])
            # Round-trip: a conformant refusal parses back to the same outcome + record id.
            got = approval.parse_refusal(b)
            self.assertEqual(got.outcome, tc["outcome"], tc["name"])
            self.assertEqual(got.record, record_id, tc["name"])

        # Non-conformant refusals a conformant parser MUST reject.
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.parse_refusal(_hb(r["reject"]["unknown_outcome_hex"]))
        self.assertEqual(cm.exception.kind, "UnknownRefusalOutcome")

        for name, h in (
            ("extra field (leaked detail)", r["reject"]["detail_leak_extra_field_hex"]),
            ("missing record id", r["reject"]["missing_record_hex"]),
            ("empty record id", r["reject"]["empty_record_hex"]),
        ):
            with self.assertRaises(approval.ApprovalError) as cm:
                approval.parse_refusal(_hb(h))
            self.assertEqual(cm.exception.kind, "RefusalDetailLeak", name)

    def test_tdcs4_freshness_independence(self):
        approver_seed, approver_pk = _ledger_key(0x11)  # the approver's key (the authenticated party)
        ledger_seed, ledger_pk = _ledger_key(0x22)       # the ordering authority (ledger) -- DISTINCT key
        args_id = b"the-exact-canonical-args-content-id"
        approver_id = b"approver-authenticated-party-id"
        ledger_id = b"ordering-authority-ledger-id"
        a = approval.ApprovalRecord(args_id, "approver-authenticated-party-id", 1, b"anti-replay-nonce", 1000)
        a_sig = approval.sign_approval(a, ALG, approver_seed)
        r = approval.ConsumeReceipt(ledger_id, a.id(), 7)
        r_sig = approval.sign_consume_receipt(r, ALG, ledger_seed)

        # Distinct ordering authority (party != ledger): verifies.
        self.assertIsNone(approval.verify_fresh_independent(
            a, ALG, approver_pk, a_sig, args_id, 1000, r, ALG, ledger_pk, r_sig, approver_id))

        # Self-asserted freshness (party == ledger): the party is the source of its own time --
        # rejected. This is the load-bearing distinctness the closure property requires.
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_fresh_independent(
                a, ALG, approver_pk, a_sig, args_id, 1000, r, ALG, ledger_pk, r_sig, ledger_id)
        self.assertEqual(cm.exception.kind, "FreshnessSelfAsserted")

        # The distinctness check does not weaken the underlying checks: an expired approval still
        # fails closed, and a distinct authority does not rescue it.
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_fresh_independent(
                a, ALG, approver_pk, a_sig, args_id, a.not_after + 1, r, ALG, ledger_pk, r_sig, approver_id)
        self.assertEqual(cm.exception.kind, "ApprovalExpired")

        # A receipt with no named ordering authority is not evidence (unnamed authority), even
        # when the party id supplied is distinct.
        empty_seed, _empty_pk = _ledger_key(0x33)
        empty = approval.ConsumeReceipt(b"", a.id(), 7)
        empty_sig = approval.sign_consume_receipt(empty, ALG, empty_seed)
        with self.assertRaises(approval.ApprovalError) as cm:
            approval.verify_fresh_independent(
                a, ALG, approver_pk, a_sig, args_id, 1000, empty, ALG, ledger_pk, empty_sig, approver_id)
        self.assertEqual(cm.exception.kind, "ConsumeReceiptUnsigned")

    def test_tdcs2_verification_determinism(self):
        # R-TDCS-2: verify_approval is a pure function of its inputs -- the same
        # (approval, key, args, pos_time) yields the same verdict on every call. Interleaving
        # accept and reject inputs across many iterations proves the verify path depends on no
        # clock, RNG, dict iteration order, or call count.
        approver_seed, approver_pk = _ledger_key(0x11)
        args_id = b"the-exact-canonical-args-content-id"
        wrong = b"a-different-args-content-id-------"
        a = approval.ApprovalRecord(args_id, "approver", 1, b"nonce", 1000)
        sig = approval.sign_approval(a, ALG, approver_seed)

        want_body = a.bytes()
        for i in range(256):
            self.assertIsNone(approval.verify_approval(a, ALG, approver_pk, sig, args_id, 500),
                               "iter %d: valid approval verdict changed (non-deterministic accept)" % i)
            self.assertEqual(a.bytes(), want_body,
                              "iter %d: encoding is not byte-stable (non-deterministic serialization)" % i)
            with self.assertRaises(approval.ApprovalError) as cm:
                approval.verify_approval(a, ALG, approver_pk, sig, wrong, 500)
            self.assertEqual(cm.exception.kind, "ApprovalMismatch",
                              "iter %d: reject verdict changed (non-deterministic reject)" % i)


class ConsumeApprovalPrecedenceTest(unittest.TestCase):
    """Exercises the composed consume choke point (consume_approval) against every reaction of the
    draft's "## Approval state machine" table and its two precedence rules (ApprovalMismatch over
    every cell; ApprovalExpired over AlreadyConsumed), plus the effect-ceiling and grant-range
    fail-closed refusals. Mirrors impl/go/approval/consume_approval_test.go's
    TestConsumeApprovalPrecedence and impl/rust/src/approval.rs's consume_approval_precedence.

    Written to survive mutation: dropping the effect/grant guard (or wrapping its condition so it
    never fires) flips insufficient-grant/malformed-grant from ApprovalRequired to success -- the
    red-evidence mutation target for this port."""

    ARGS_CID = b"args-content-id-A"   # the content id the approval binds
    WRONG_CID = b"args-content-id-B"  # a different presented args content id -> ApprovalMismatch

    def setUp(self):
        # A deterministic Ed25519 approver key (the signature is verified, not graded).
        self.seed = bytes([7]) * 32
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._priv = Ed25519PrivateKey.from_private_bytes(self.seed)
        self.pk = self._priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def _approval_of(self, grant, not_after):
        a = approval.ApprovalRecord(self.ARGS_CID, "approver-1", grant, bytes([0x01, 0x02]), not_after)
        sig = cose.ed25519_sign(self.seed, a.bytes())
        return a, sig

    def _fresh_ledger(self, d):
        return approval.open_ledger(os.path.join(d, "wal"))

    def test_consumed(self):
        # approved + consume (match, grant covers required, unexpired, fresh) -> consumed; len 1.
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 500,
                                           policy.READ_ONLY, led, "by-1")
                self.assertEqual(len(led), 1)
                # consumed + consume (same id) -> AlreadyConsumed; ledger unchanged at 1.
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 500,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")
                self.assertEqual(len(led), 1)
            finally:
                led.close()

    def test_expired(self):
        # expired + consume -> ApprovalExpired; nothing appended.
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 2000,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "ApprovalExpired")
                self.assertEqual(len(led), 0)
            finally:
                led.close()

    def test_expiry_over_consume(self):
        # a first consume succeeds; a second, now past not_after, is ApprovalExpired (NOT
        # AlreadyConsumed) because expiry is checked before the ledger, and the ledger is untouched.
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 500,
                                           policy.READ_ONLY, led, "by-1")
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 2000,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "ApprovalExpired", "never AlreadyConsumed")
                self.assertEqual(len(led), 1)
            finally:
                led.close()

    def test_mismatch_fresh(self):
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.WRONG_CID, 500,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "ApprovalMismatch")
                self.assertEqual(len(led), 0)
            finally:
                led.close()

    def test_mismatch_over_expired(self):
        # mismatch takes precedence over every cell, even when the approval is also expired.
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.WRONG_CID, 2000,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "ApprovalMismatch", "mismatch precedence over expiry")
                self.assertEqual(len(led), 0)
            finally:
                led.close()

    def test_reject_then_valid(self):
        # a rejected mismatch leaves the ledger clean (no-state-change-on-rejection), so a
        # subsequent valid consume still succeeds.
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError):
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.WRONG_CID, 500,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(len(led), 0)
                approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 500,
                                           policy.READ_ONLY, led, "by-1")
                self.assertEqual(len(led), 1)
            finally:
                led.close()

    def test_insufficient_grant(self):
        # effect ceiling: the approval's granted effect does not cover the action -> ApprovalRequired,
        # no append. THIS is the red-evidence mutation target.
        a, sig = self._approval_of(policy.READ_ONLY, 1000)  # grants read_only
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 500,
                                               policy.DESTRUCTIVE, led, "by-1")
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
                self.assertEqual(len(led), 0)
            finally:
                led.close()

    def test_malformed_grant(self):
        # grant-range guard: a grant outside the closed 0..3 vocabulary authorizes nothing
        # (fail-closed), rather than being treated as an over-authorizing value.
        a, sig = self._approval_of(7, 1000)  # 7 is not a valid effect class
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, sig, self.ARGS_CID, 500,
                                               policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
                self.assertEqual(len(led), 0)
            finally:
                led.close()

    def test_bad_signature(self):
        a, sig = self._approval_of(policy.DESTRUCTIVE, 1000)
        bad = bytearray(sig)
        bad[-1] ^= 0x01
        with tempfile.TemporaryDirectory() as d:
            led = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    approval.consume_approval(a, cose.ALG_ED25519, self.pk, bytes(bad), self.ARGS_CID,
                                               500, policy.READ_ONLY, led, "by-1")
                self.assertEqual(cm.exception.kind, "BadSignature")
                self.assertEqual(len(led), 0)
            finally:
                led.close()


if __name__ == "__main__":
    unittest.main()
