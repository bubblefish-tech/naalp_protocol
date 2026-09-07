# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C21 (5B.1) NAALP-PAY payment-import conformance for the Python SDK, graded against the shared
independent corpus vectors/payment/cases.json (NOT produced by this code): the closed payment-format
registry, the byte-exact PaymentImport body/head/content-id (incl. the oversized >2^53 amount and the
minimal import), the foreign-payload content id (carriage binding), the byte-exact ChargeBinding
body/head/content-id, the parse round-trip, the fail-closed edge cases (non-canonical -> NonCanonical
/ PayMalformed, absent mandatory field -> PayMalformed, a bstr-currency look-alike -> PayMalformed,
empty vs populated foreign distinct by content-id), and the mismatch content-ids (a wrong amount,
wrong payee, or substituted foreign payload yields a DIFFERENT charge content-id, so a §7 approval
bound to the original no longer matches).

The PaymentImport SIGNATURE is real deterministic ML-DSA-65 via a bare-{1:alg} COSE_Sign1 (as the
reference's cose.Sign1); the corpus carries no signed vector for this channel, so sign/verify is
demonstrated in isolation only -- stated honestly, not corpus-graded.

STEP-2 parity: payment.authorize_charge (ported from impl/go/payment/payment.go:241) reuses the §7
approval object (naalp.approval.verify_approval), the §7 single-use consume ledger
(naalp.approval.Ledger.consume), and the closed C5 effect lattice (naalp.policy.authorizes) to gate
an imported payment charge. TestChargeSingleUseAndBindingPy (mirroring Go's
TestChargeSingleUseAndBinding) grades all four deny paths -- ApprovalMismatch (wrong amount / wrong
payee / substituted foreign payload), BadSignature (foreign key), ApprovalExpired, ApprovalRequired
(under-granting approval), and UnknownPaymentFormat -- plus the single-use success path (a replay is
AlreadyConsumed, no double-spend). These approval/ledger scenarios are constructed in isolation (not
corpus vectors) exactly as Go's payment_test.go does with its own ad hoc approvals, and cross-checked
against the mismatch content-ids that ARE corpus-graded (vectors/payment/cases.json "mismatch").

Written test-first; authorize_charge is absent until ported, so
TestChargeSingleUseAndBindingPy fails RED (AttributeError: module 'naalp.payment' has no attribute
'authorize_charge') until impl/python/naalp/payment.py lands it.

Run:  python -m unittest -v tests.test_payment      (from impl/python/)
"""
import json
import os
import tempfile
import unittest

from naalp import approval, cbor, cose, payment, policy


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "payment", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/payment/cases.json not found")


ALG = cose.ALG_MLDSA65
SEED = bytes(32)
PK = cose.mldsa_keygen("ML-DSA-65", SEED)


def _hb(s):
    return bytes.fromhex(s)


def _import_from(iv):
    return payment.PaymentImport(
        iv["format"], iv["amount"], iv["currency"], _hb(iv["payee_hex"]),
        iv["not_after"], _hb(iv["foreign_hex"]),
    )


def _key(seed_byte):
    """A throwaway ML-DSA-65 (seed, pubkey) pair for a test key, mirroring impl/go/payment_test.go's
    key(t, seed)."""
    seed = bytes([seed_byte]) * 32
    pk = cose.mldsa_keygen("ML-DSA-65", seed)
    return seed, pk


def _mk_approval(charge_cid, approver, grant, nonce_byte, not_after, approver_seed):
    """Build (and sign) a §7 approval binding a charge content-id at grant `grant`, mirroring
    impl/go/payment_test.go's mkApproval(t, chargeCID, approver, grant, nonce, notAfter, s)."""
    nonce = bytes([nonce_byte]) * 16
    a = approval.ApprovalRecord(charge_cid, approver, grant, nonce, not_after)
    sig = approval.sign_approval(a, ALG, approver_seed)
    return a, sig


class PaymentConformance(unittest.TestCase):
    C = _vectors()

    # ---- closed payment-format registry (design §24) --------------------------------------

    def test_format_vocabulary(self):
        for fv in self.C["format_vocabulary"]:
            self.assertTrue(payment.is_registered_format(fv["code"]), fv["name"])
            self.assertEqual(payment.format_name(fv["code"]), fv["name"])
        self.assertFalse(payment.is_registered_format(self.C["unknown_format"]))
        self.assertEqual(payment.format_name(self.C["unknown_format"]), "unknown")

    def test_charge_effect(self):
        # A payment spend is a non_idempotent_write (the value-bearing rule).
        self.assertEqual(payment.CHARGE_EFFECT, self.C["charge_effect"])
        self.assertEqual(payment.CHARGE_EFFECT, policy.NON_IDEMPOTENT_WRITE)

    # ---- PaymentImport byte parity (design §24) -------------------------------------------

    def test_import_bodies_match_oracle(self):
        for name in ("ap2", "acp", "x402"):
            iv = self.C["imports"][name]
            p = _import_from(iv)
            self.assertEqual(p.bytes().hex(), iv["body_hex"], name)
            self.assertEqual(p.head().hex(), iv["head_hex"], name)
            self.assertEqual(p.id().hex(), iv["id_hex"], name)
            self.assertEqual(p.foreign_id().hex(), iv["foreign_id_hex"], name)

    def test_charge_binding_ids_match_oracle(self):
        # THIS is the mutation-target assertion: the exact charge value a §7 approval binds.
        for name in ("ap2", "acp", "x402"):
            iv = self.C["imports"][name]
            cb = _import_from(iv).charge_binding()
            self.assertEqual(cb.bytes().hex(), iv["charge_binding"]["body_hex"], name)
            self.assertEqual(cb.head().hex(), iv["charge_binding"]["head_hex"], name)
            self.assertEqual(cb.content_id().hex(), iv["charge_binding"]["id_hex"], name)

    def test_big_amount_over_2_53_round_trips(self):
        bv = self.C["big_amount"]
        amount = int(bv["amount_str"])  # 72623859790382856 > 2^53, exact (Python bigint)
        self.assertGreater(amount, 2 ** 53)
        p = payment.PaymentImport(bv["format"], amount, bv["currency"], _hb(bv["payee_hex"]),
                                  bv["not_after"], _hb(bv["foreign_hex"]))
        self.assertEqual(p.bytes().hex(), bv["body_hex"])
        self.assertEqual(p.head().hex(), bv["head_hex"])
        self.assertEqual(p.id().hex(), bv["id_hex"])
        cb = p.charge_binding()
        self.assertEqual(cb.content_id().hex(), bv["charge_binding"]["id_hex"])
        # and the parsed amount round-trips byte-exact through the strict decoder
        rp = payment.parse_payment_import(_hb(bv["body_hex"]))
        self.assertEqual(rp.amount, amount)

    def test_minimal_import(self):
        m = self.C["minimal"]
        p = payment.PaymentImport(m["format"], m["amount"], m["currency"], _hb(m["payee_hex"]),
                                  m["not_after"], _hb(m["foreign_hex"]))
        self.assertEqual(p.bytes().hex(), m["body_hex"])
        self.assertEqual(p.head().hex(), m["head_hex"])
        self.assertEqual(p.id().hex(), m["id_hex"])

    # ---- parse round-trip + fail-closed edges (design §24, §15) ---------------------------

    def test_parse_roundtrips(self):
        for name in ("ap2", "acp", "x402"):
            iv = self.C["imports"][name]
            p = payment.parse_payment_import(_hb(iv["body_hex"]))
            self.assertEqual(p.format, iv["format"], name)
            self.assertEqual(p.amount, iv["amount"], name)
            self.assertEqual(p.currency, iv["currency"], name)
            self.assertEqual(p.payee, _hb(iv["payee_hex"]), name)
            self.assertEqual(p.not_after, iv["not_after"], name)
            self.assertEqual(p.foreign, _hb(iv["foreign_hex"]), name)

    def test_noncanonical_body_rejected(self):
        ec = self.C["edge_cases"]["keys_out_of_order"]
        with self.assertRaises(cbor.NonCanonical):
            cbor.decode(_hb(ec["noncanonical_body_hex"]))
        with self.assertRaises(payment.PayError) as cm:
            payment.parse_payment_import(_hb(ec["noncanonical_body_hex"]))
        self.assertEqual(cm.exception.kind, "PayMalformed")  # the corpus 'reject' family
        # the canonical form of the same content parses
        p = payment.parse_payment_import(_hb(ec["canonical_body_hex"]))
        self.assertEqual(p.format, ec["format"])

    def test_empty_vs_absent_foreign(self):
        ev = self.C["edge_cases"]["empty_vs_absent"]
        empty = payment.parse_payment_import(_hb(ev["empty_foreign"]["body_hex"]))
        self.assertEqual(empty.foreign, b"")
        self.assertEqual(empty.id().hex(), ev["empty_foreign"]["id_hex"])
        self.assertEqual(empty.foreign_id().hex(), ev["empty_foreign"]["foreign_id_hex"])
        populated = payment.parse_payment_import(_hb(ev["populated_foreign"]["body_hex"]))
        self.assertEqual(populated.id().hex(), ev["populated_foreign"]["id_hex"])
        self.assertEqual(populated.foreign_id().hex(), ev["populated_foreign"]["foreign_id_hex"])
        # an empty foreign payload is present and valid, distinct by content-id from a populated one
        self.assertNotEqual(empty.id(), populated.id())
        self.assertNotEqual(empty.foreign_id(), populated.foreign_id())
        # field 6 (foreign) is mandatory: a body missing it is rejected fail-closed
        with self.assertRaises(payment.PayError) as cm:
            payment.parse_payment_import(_hb(ev["absent_field"]["body_hex"]))
        self.assertEqual(cm.exception.kind, ev["absent_field"]["reject"])  # PayMalformed

    def test_look_alike_rejected(self):
        la = self.C["edge_cases"]["look_alike"]
        with self.assertRaises(payment.PayError) as cm:
            payment.parse_payment_import(_hb(la["body_hex"]))
        self.assertEqual(cm.exception.kind, la["reject"])  # PayMalformed (currency as bstr)

    # ---- the binding property: a changed charge is a different content-id -----------------

    def test_charge_binding_mismatch_ids(self):
        # An approval binds the base ap2 charge-binding content-id; a wrong amount, wrong payee, or
        # substituted foreign payload yields a DIFFERENT charge content-id (ApprovalMismatch at the
        # §7 layer). All three are reproduced byte-exact from the corpus base.
        base_iv = self.C["imports"]["ap2"]
        base = _import_from(base_iv)
        base_id = base.charge_binding().content_id()
        self.assertEqual(base_id.hex(), base_iv["charge_binding"]["id_hex"])
        mm = self.C["mismatch"]

        wrong_amount = payment.PaymentImport(base.format, base.amount + 8000, base.currency,
                                             base.payee, base.not_after, base.foreign)
        self.assertEqual(wrong_amount.charge_binding().content_id().hex(),
                         mm["wrong_amount_charge_id_hex"])

        wrong_payee = payment.PaymentImport(base.format, base.amount, base.currency,
                                            b"merchant:evil-store", base.not_after, base.foreign)
        self.assertEqual(wrong_payee.charge_binding().content_id().hex(),
                         mm["wrong_payee_charge_id_hex"])

        substituted = payment.PaymentImport(base.format, base.amount, base.currency, base.payee,
                                            base.not_after, _hb(mm["substituted_foreign_hex"]))
        self.assertEqual(substituted.foreign_id().hex(), mm["substituted_foreign_id_hex"])
        self.assertEqual(substituted.charge_binding().content_id().hex(),
                         mm["substituted_charge_id_hex"])

        for other in (mm["wrong_amount_charge_id_hex"], mm["wrong_payee_charge_id_hex"],
                      mm["substituted_charge_id_hex"]):
            self.assertNotEqual(base_id.hex(), other, "a changed charge must not match the bound one")

    # ---- signed import round-trip in isolation (design §24) -------------------------------

    def test_sign_verify_import_in_isolation(self):
        # NOT corpus-graded (no signed vector). Real deterministic ML-DSA-65 via a bare COSE_Sign1.
        iv = self.C["imports"]["ap2"]
        p = _import_from(iv)
        obj = payment.sign_payment_import(p, ALG, SEED)
        got = payment.verify_payment_import(obj, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual((got.format, got.amount, got.currency, got.payee, got.not_after, got.foreign),
                         (p.format, p.amount, p.currency, p.payee, p.not_after, p.foreign))
        # tampered signature -> BadSignature
        bad = bytearray(obj)
        bad[-1] ^= 1
        with self.assertRaises(payment.PayError) as cm:
            payment.verify_payment_import(bytes(bad), cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(cm.exception.kind, "BadSignature")
        # an unknown imported format is not chargeable -> UnknownPaymentFormat
        bad_fmt = payment.PaymentImport(self.C["unknown_format"], 1, "USD", b"x", 1, b"")
        bad_obj = payment.sign_payment_import(bad_fmt, ALG, SEED)
        with self.assertRaises(payment.PayError) as cm:
            payment.verify_payment_import(bad_obj, cose.PROFILE_PUBLIC, ALG, PK)
        self.assertEqual(cm.exception.kind, "UnknownPaymentFormat")


class AuthorizeChargeConformance(unittest.TestCase):
    """STEP-2 parity: payment.authorize_charge (ported from impl/go/payment/payment.go:241
    AuthorizeCharge + impl/go/payment/payment_test.go TestChargeSingleUseAndBinding). Composes the
    EXISTING §7 approval.verify_approval (binds the exact charge content id), policy.authorizes (the
    granted effect covers the charge), and the single-use approval.Ledger.consume (AlreadyConsumed on
    replay) -- reusing the shared payment corpus mismatch content-ids as the binding oracle."""

    C = _vectors()

    def setUp(self):
        self.approver_seed, self.approver_pk = _key(0x11)
        self.foreign_seed, self.foreign_pk = _key(0x22)   # a foreign key never authenticates the approval
        self.pi = _import_from(self.C["imports"]["ap2"])
        self.charge_cid = self.pi.charge_binding().content_id()
        self.appr, self.appr_sig = _mk_approval(
            self.charge_cid, "approver-A", payment.CHARGE_EFFECT, 0x01, self.pi.not_after,
            self.approver_seed)

    def _fresh_ledger(self, d):
        return approval.open_ledger(os.path.join(d, "fresh-%s.wal" % os.urandom(4).hex()))

    def test_charge_single_use_and_binding(self):
        v = self.C
        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "charge.wal"))
            try:
                # ---- success path: authorized and consumed exactly once ----------------------
                entry = payment.authorize_charge(
                    self.pi, self.appr, ALG, self.approver_pk, self.appr_sig,
                    "payer-1", self.pi.not_after, ledger)
                self.assertEqual(entry.seq, 0, "first charge did not consume at seq 0")

                # ---- replay: rejected by the ledger, no second spend, no state change --------
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(
                        self.pi, self.appr, ALG, self.approver_pk, self.appr_sig,
                        "payer-1", self.pi.not_after, ledger)
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")
                self.assertEqual(len(ledger), 1, "ledger must have exactly 1 entry after replay")
            finally:
                ledger.close()

            # ---- wrong amount: different charge content-id -> ApprovalMismatch ---------------
            wrong_amount = payment.PaymentImport(
                self.pi.format, self.pi.amount + 8000, self.pi.currency, self.pi.payee,
                self.pi.not_after, self.pi.foreign)
            self.assertEqual(wrong_amount.charge_binding().content_id().hex(),
                              v["mismatch"]["wrong_amount_charge_id_hex"])
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(wrong_amount, self.appr, ALG, self.approver_pk,
                                              self.appr_sig, "payer-1", self.pi.not_after, fresh)
                self.assertEqual(cm.exception.kind, "ApprovalMismatch")
                self.assertEqual(len(fresh), 0, "a denied charge must cause no ledger append")
            finally:
                fresh.close()

            # ---- wrong payee: different charge content-id -> ApprovalMismatch ----------------
            wrong_payee = payment.PaymentImport(
                self.pi.format, self.pi.amount, self.pi.currency, b"merchant:evil-store",
                self.pi.not_after, self.pi.foreign)
            self.assertEqual(wrong_payee.charge_binding().content_id().hex(),
                              v["mismatch"]["wrong_payee_charge_id_hex"])
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(wrong_payee, self.appr, ALG, self.approver_pk,
                                              self.appr_sig, "payer-1", self.pi.not_after, fresh)
                self.assertEqual(cm.exception.kind, "ApprovalMismatch")
            finally:
                fresh.close()

            # ---- substituted foreign payload: different foreign_id + charge id ---------------
            substituted = payment.PaymentImport(
                self.pi.format, self.pi.amount, self.pi.currency, self.pi.payee, self.pi.not_after,
                _hb(v["mismatch"]["substituted_foreign_hex"]))
            self.assertEqual(substituted.foreign_id().hex(), v["mismatch"]["substituted_foreign_id_hex"])
            self.assertEqual(substituted.charge_binding().content_id().hex(),
                              v["mismatch"]["substituted_charge_id_hex"])
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(substituted, self.appr, ALG, self.approver_pk,
                                              self.appr_sig, "payer-1", self.pi.not_after, fresh)
                self.assertEqual(cm.exception.kind, "ApprovalMismatch")
            finally:
                fresh.close()

            # ---- a foreign key never authenticates the approval -> BadSignature --------------
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(self.pi, self.appr, ALG, self.foreign_pk,
                                              self.appr_sig, "payer-1", self.pi.not_after, fresh)
                self.assertEqual(cm.exception.kind, "BadSignature")
            finally:
                fresh.close()

            # ---- an expired charge is rejected -> ApprovalExpired ----------------------------
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(self.pi, self.appr, ALG, self.approver_pk,
                                              self.appr_sig, "payer-1", self.pi.not_after + 1, fresh)
                self.assertEqual(cm.exception.kind, "ApprovalExpired")
            finally:
                fresh.close()

            # ---- an under-granting approval (read_only cannot authorize a          ----------
            # ---- non_idempotent_write charge) is denied -> ApprovalRequired         ----------
            under_cid = self.pi.charge_binding().content_id()
            under_appr, under_sig = _mk_approval(
                under_cid, "approver-A", policy.READ_ONLY, 0x03, self.pi.not_after,
                self.approver_seed)
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(payment.PayError) as cm:
                    payment.authorize_charge(self.pi, under_appr, ALG, self.approver_pk,
                                              under_sig, "payer-1", self.pi.not_after, fresh)
                self.assertEqual(cm.exception.kind, "ApprovalRequired")
                self.assertEqual(len(fresh), 0, "a denied charge must cause no ledger append")
            finally:
                fresh.close()

            # ---- an unknown imported format is not chargeable -> UnknownPaymentFormat -------
            unk = payment.PaymentImport(self.C["unknown_format"], self.pi.amount, self.pi.currency,
                                        self.pi.payee, self.pi.not_after, self.pi.foreign)
            fresh = self._fresh_ledger(d)
            try:
                with self.assertRaises(payment.PayError) as cm:
                    payment.authorize_charge(unk, self.appr, ALG, self.approver_pk, self.appr_sig,
                                              "payer-1", self.pi.not_after, fresh)
                self.assertEqual(cm.exception.kind, "UnknownPaymentFormat")
                self.assertEqual(len(fresh), 0, "an unknown-format charge must cause no ledger append")
            finally:
                fresh.close()

    def test_multi_use_mutation_reproduces_double_spend(self):
        """Mirrors impl/go/payment_test.go TestPaymentImportMultiUseMutation: the HONEST
        authorize_charge is single-use through the ledger (a replay is AlreadyConsumed); a MUTANT
        importer that verifies the binding but skips the ledger consume (treats the token as
        MULTI-USE) wrongly authorizes the replay a second time -- proving ledger.consume is the
        load-bearing single-use guarantee, not the binding check alone."""
        with tempfile.TemporaryDirectory() as d:
            ledger = approval.open_ledger(os.path.join(d, "honest.wal"))
            try:
                payment.authorize_charge(self.pi, self.appr, ALG, self.approver_pk, self.appr_sig,
                                          "payer-1", self.pi.not_after, ledger)
                with self.assertRaises(approval.ApprovalError) as cm:
                    payment.authorize_charge(self.pi, self.appr, ALG, self.approver_pk,
                                              self.appr_sig, "payer-1", self.pi.not_after, ledger)
                self.assertEqual(cm.exception.kind, "AlreadyConsumed")
            finally:
                ledger.close()

            # MUTANT: verifies the binding but never consumes -- the bug the ledger prevents.
            def mutant_authorize(p):
                cid = p.charge_binding().content_id()
                approval.verify_approval(self.appr, ALG, self.approver_pk, self.appr_sig, cid,
                                          p.not_after)  # no consume => multi-use

            mutant_authorize(self.pi)          # first charge: fine
            mutant_authorize(self.pi)          # replay: the mutant does NOT reject it (the bug reproduces)


if __name__ == "__main__":
    unittest.main()
