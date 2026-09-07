# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
identity_records_oracle.py: the eleven RECORD + THREAD surfaces that previously had NO
independent oracle (F3) -- RevocationRecord, RevokedAt, VerifyRevocation, ForeignLinkRecord,
VerifyForeignLink, RotationEvidence, Thread, Thread.attributable, ResolveThread -- graded
against the shared independent corpus vectors/identity_records/cases.json (NOT produced by
this code), mirroring impl/go/identity/identity_records_oracle_test.go and
impl/rust/src/identity.rs's identity_records tests byte/verdict-for-byte/verdict.

Mutation-surviving properties (see the corpus's per-case notes for the full derivation):
  1. RevocationRecord.bytes()/ForeignLinkRecord.bytes() -- deterministic-CBOR body byte parity.
  2. RevokedAt -- the `>` (not `>=`) boundary ("at_boundary_still_valid" is the anchor).
  3. VerifyRevocation -- §5.3/§5.5 fail-closed authorization: the signer id is recomputed from
     (alg, pub) and accepted iff it equals record.key OR is a member of the deployer-configured
     recovery_ids, THEN the signature is checked (membership BEFORE signature). "wrong_key_reject"
     and "recovery_key_not_configured_reject" (a VALID recovery-key signature over an EMPTY
     authorized set) are the anchors: dropping the membership guard flips both to accept.
  4. VerifyForeignLink -- non-NFC foreign_id is NonNFC; expiry and a bad/wrong-key signature both
     confer no linkage but are NOT errors (same bucket, §5.5); the not_after boundary (`now >
     not_after`) is a MUTATION ANCHOR.
  5. ResolveThread -- an empty chain is RotationUnauthorized; a broken link is caught by TWO
     independent guards (contiguity vs per-link co-signature), each pinned by its own case.
  6. Thread.attributable -- every id in Chain (root, intermediate, current) is attributable; an
     unrelated id is not (the anchor for the membership check itself).

Run:  python -m unittest -v tests.test_identity   (from impl/python/)
"""
import json
import os
import unittest

from naalp import identity


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "identity_records", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/identity_records/cases.json not found")


def _hb(s):
    return bytes.fromhex(s)


class RevocationRecordBytesTest(unittest.TestCase):
    """RevocationRecord.bytes() byte-for-byte against the independent oracle over varying key
    strings and not_after magnitudes."""

    def test_matches_oracle(self):
        c = _vectors()
        cases = c["revocation"]["record_bytes"]
        self.assertTrue(cases, "no revocation record_bytes cases")
        for tc in cases:
            with self.subTest(tc["name"]):
                r = identity.RevocationRecord(tc["key"], tc["not_after"])
                self.assertEqual(r.bytes().hex(), tc["bytes_hex"])


class RevokedAtTest(unittest.TestCase):
    """RevokedAt over the oracle's set-based scenarios: revoked_at(record, position) is a pure
    per-record boolean, so the test performs the (key -> matching revocation) selection itself,
    then asserts the per-record verdict. "at_boundary_still_valid" is the MUTATION ANCHOR: flipping
    `>` to `>=` flips it."""

    def test_matches_oracle(self):
        c = _vectors()
        scenarios = c["revocation"]["revoked_at"]
        self.assertTrue(scenarios, "no revoked_at scenarios")
        for sc in scenarios:
            with self.subTest(sc["name"]):
                revoked = False
                not_after = None
                for rv in sc["revocations"]:
                    if rv["key"] != sc["query_key"]:
                        continue
                    rec = identity.RevocationRecord(rv["key"], rv["not_after"])
                    if identity.revoked_at(rec, sc["query_position"]):
                        revoked = True
                        not_after = rv["not_after"]
                self.assertEqual(revoked, sc["expect_revoked"])
                if sc["expect_revoked"]:
                    self.assertEqual(not_after, sc.get("expect_not_after"))


class VerifyRevocationTest(unittest.TestCase):
    """VerifyRevocation against the independent oracle across all seven authorization x signature
    cases. §5.3 permits a Revocation to be signed by the key it revokes OR by a deployer-configured
    recovery key; verify_revocation takes the deployer's authorized recovery-id set and accepts a
    signer iff its recomputed id equals record.key or is a member of that set, then verifies the
    signature (membership BEFORE signature, fail-closed). MUTATION ANCHORS:
    "recovery_key_not_configured_reject" (a valid recovery-key signature with an EMPTY authorized
    set -> SignerMismatch) and "wrong_key_reject" -- dropping the membership guard flips both to
    accept."""

    def test_matches_oracle(self):
        c = _vectors()
        cases = c["revocation"]["verify"]
        self.assertGreaterEqual(len(cases), 7)
        for tc in cases:
            with self.subTest(tc["name"]):
                alg = tc["candidate_alg"]
                pub = _hb(tc["candidate_pubkey_hex"])
                rec = identity.RevocationRecord(tc["record"]["key"], tc["record"]["not_after"])
                sig = _hb(tc["sig_hex"])
                recovery_ids = tc.get("authorized_recovery_ids") or []
                if tc["expect_valid"]:
                    identity.verify_revocation(rec, alg, pub, sig, recovery_ids)
                    continue
                with self.assertRaises(ValueError) as cm:
                    identity.verify_revocation(rec, alg, pub, sig, recovery_ids)
                expect_kind = tc.get("expect_error_kind") or ""
                if expect_kind:
                    self.assertEqual(cm.exception.kind, expect_kind, tc.get("note", ""))


class ForeignLinkRecordBytesTest(unittest.TestCase):
    """ForeignLinkRecord.bytes() byte-for-byte, including the NFC-vs-NFD case proving bytes() is a
    pure encoder (the NFC requirement lives in verify_foreign_link, not in bytes()). MUTATION
    ANCHOR: collapsing NFC/NFD to the same bytes (e.g. via a normalizing encoder) would flip
    nfd_form_different_bytes' byte-inequality assertion."""

    def test_matches_oracle(self):
        c = _vectors()
        cases = c["foreign_link"]["record_bytes"]
        self.assertGreaterEqual(len(cases), 2)
        seen = {}
        for tc in cases:
            with self.subTest(tc["name"]):
                r = identity.ForeignLinkRecord(tc["controls"], tc["foreign_id"], tc["not_after"])
                got = r.bytes().hex()
                self.assertEqual(got, tc["bytes_hex"])
                seen[tc["name"]] = got
        self.assertNotEqual(seen.get("nfc_form"), seen.get("nfd_form_different_bytes"),
                             "NFC and NFD foreign_id forms must encode to different bytes")


class VerifyForeignLinkTest(unittest.TestCase):
    """VerifyForeignLink against the oracle: valid+unexpired links, the not_after boundary
    (MUTATION ANCHOR for `now > not_after`), expiry (ignored, no error), wrong-key (ignored, no
    error -- the SAME bucket as expiry per §5.5), and non-NFC foreign_id (NonNFC, checked before
    expiry/signature)."""

    def test_matches_oracle(self):
        c = _vectors()
        cases = c["foreign_link"]["verify"]
        self.assertTrue(cases, "no foreign_link verify cases")
        for tc in cases:
            with self.subTest(tc["name"]):
                alg = tc["candidate_alg"]
                pub = _hb(tc["candidate_pubkey_hex"])
                rec = identity.ForeignLinkRecord(tc["record"]["controls"],
                                                  tc["record"]["foreign_id"],
                                                  tc["record"]["not_after"])
                sig = _hb(tc["sig_hex"])
                now = tc["now"]
                expect_kind = tc.get("expect_error_kind") or ""
                if expect_kind:
                    with self.assertRaises(ValueError) as cm:
                        identity.verify_foreign_link(rec, alg, pub, sig, now)
                    self.assertEqual(cm.exception.kind, expect_kind, tc.get("note", ""))
                    continue
                linked = identity.verify_foreign_link(rec, alg, pub, sig, now)
                self.assertEqual(linked, tc["expect_linked"], tc.get("note", ""))
                if tc["expect_linked"]:
                    self.assertEqual(rec.controls, tc["expect_controls"])
                    self.assertEqual(rec.foreign_id, tc["expect_foreign_id"])


class ResolveThreadTest(unittest.TestCase):
    """ResolveThread against the oracle: empty chain, a single link, a 3-link contiguous chain, and
    TWO distinct broken-chain shapes that are each a MUTATION ANCHOR for a DIFFERENT guard --
    "broken_link_old_mismatch" pins the CONTIGUITY check (record.old != prev_new), and
    "broken_link_forged_old_signature" pins the per-link CO-SIGNATURE check (verify_rotation),
    isolating one from the other."""

    def _build_evidence(self, evs_json):
        out = []
        for e in evs_json:
            rec = identity.RotationRecord(e["old"], e["new"], e["not_before"])
            self.assertEqual(rec.bytes().hex(), e["record_bytes_hex"],
                              "RotationRecord.bytes() (RotationEvidence input)")
            out.append(identity.RotationEvidence(
                record=rec,
                old_alg=e["old_alg"], new_alg=e["new_alg"],
                old_pub=_hb(e["old_pubkey_hex"]), new_pub=_hb(e["new_pubkey_hex"]),
                old_sig=_hb(e["old_sig_hex"]), new_sig=_hb(e["new_sig_hex"]),
            ))
        return out

    def test_matches_oracle(self):
        c = _vectors()
        cases = c["thread"]["resolve"]
        self.assertTrue(cases, "no thread resolve cases")
        for tc in cases:
            with self.subTest(tc["name"]):
                evs = self._build_evidence(tc["evidence"])
                expect_error = tc.get("expect_error") or ""
                if expect_error:
                    with self.assertRaises(ValueError) as cm:
                        identity.resolve_thread(evs)
                    self.assertEqual(cm.exception.kind, expect_error, tc.get("note", ""))
                    continue
                th = identity.resolve_thread(evs)
                want = tc["expect_thread"]
                self.assertIsNotNone(want, "oracle declared no expected thread but impl accepted")
                self.assertEqual(th.root, want["root"])
                self.assertEqual(th.current, want["current"])
                self.assertEqual(th.chain, want["chain"])


class ThreadAttributableTest(unittest.TestCase):
    """Thread.attributable over the resolved 3-link thread: the root, every intermediate key, and
    the current key are all attributable; an unrelated key is not.
    "unrelated_key_not_attributable" is the MUTATION ANCHOR for the membership check itself (a stub
    that always returns true would flip it)."""

    def test_matches_oracle(self):
        c = _vectors()
        cases = c["thread"]["attributable"]
        self.assertTrue(cases, "no thread attributable cases")
        for tc in cases:
            with self.subTest(tc["name"]):
                th_json = tc["thread"]
                th = identity.Thread(th_json["root"], th_json["current"], th_json["chain"])
                self.assertEqual(th.attributable(tc["query"]), tc["expect"])


if __name__ == "__main__":
    unittest.main()
