# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""C9 native streaming for the Python SDK, graded against the shared independent corpus
vectors/stream/cases.json (NOT produced by this code): the rolling-SHA-384 commitment over chunks in
absolute-offset order, the mid-stream checkpoint digests, and the StreamOpen / StreamCommit /
StreamCheckpoint body bytes. A native stream is non-repudiable with ONE end-commitment signature, not
N per-chunk signatures; altering any delivered byte invalidates the commitment (StreamDigestMismatch),
and a stream whose effect exceeds the granted ceiling is refused at open, BEFORE any chunk (R-10.3).

NOTE ON THE ORACLE DIR NAME: the Go module is impl/go/streaming/ but its oracle lives at
vectors/stream/cases.json (the directory is `stream`, not `streaming`). This test grades against
vectors/stream/cases.json.

The StreamOpen/StreamCommit/StreamCheckpoint SIGNATURES are real deterministic ML-DSA-65 (a raw
signature over the body, matching impl/go/streaming's s.Sign) demonstrated in isolation; the corpus
carries no signed vector, so signing is NOT corpus-graded (stated honestly, D5).

Written test-first; the streaming module is absent until ported, so this fails RED on import until
impl/python/naalp/streaming.py lands. Mutation: inverting the digest comparison in verify_commit
(!= -> ==) makes a valid stream fail its commitment check and flips test_tamper_invalidates_commit.

Run:  python -m unittest tests.test_streaming      (from impl/python/)
"""
import json
import os
import unittest

from naalp import cose, policy, streaming


def _vectors():
    d = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        p = os.path.join(d, "vectors", "stream", "cases.json")
        if os.path.isfile(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        d = os.path.dirname(d)
    raise FileNotFoundError("vectors/stream/cases.json not found")


ALG = cose.ALG_MLDSA65
SEED = bytes([60]) * 32
PK = cose.mldsa_keygen("ML-DSA-65", SEED)


def hb(s):
    return bytes.fromhex(s)


class StreamingConformance(unittest.TestCase):
    C = _vectors()

    def _chunks(self):
        return [streaming.Chunk(c["offset"], hb(c["data_hex"])) for c in self.C["chunks"]]

    def test_digest_and_bodies_match_oracle(self):
        chunks = self._chunks()
        self.assertEqual(streaming.commit_digest(chunks).hex(), self.C["final_digest_hex"])
        # Rolling: DigestSoFar after each chunk equals the checkpoint, and the last equals final.
        sd = streaming.StreamDigest()
        for i, ch in enumerate(chunks):
            sd.update(ch.data)
            if i < len(self.C["checkpoints"]):
                self.assertEqual(sd.digest_so_far().hex(), self.C["checkpoints"][i]["digest_so_far_hex"],
                                 "checkpoint %d" % i)
        self.assertEqual(sd.digest_so_far().hex(), self.C["final_digest_hex"])

        stream_id = hb(self.C["stream_id_hex"])
        open_ = streaming.StreamOpen(stream_id, self.C["effect"], hb(self.C["approval_hex"]), self.C["substream"])
        self.assertEqual(open_.bytes().hex(), self.C["open_body_hex"])
        commit = streaming.StreamCommit(stream_id, hb(self.C["final_digest_hex"]))
        self.assertEqual(commit.bytes().hex(), self.C["commit_body_hex"])
        cp = streaming.StreamCheckpoint(stream_id, self.C["checkpoints"][0]["through_offset"],
                                        hb(self.C["checkpoints"][0]["digest_so_far_hex"]))
        self.assertEqual(cp.bytes().hex(), self.C["checkpoint_body_hex"])

    def test_tamper_invalidates_commit(self):
        # MUTATION TARGET: the valid stream verifies; altering one delivered byte invalidates the
        # commitment (StreamDigestMismatch) -- R-10.2.
        stream_id = hb(self.C["stream_id_hex"])
        chunks = self._chunks()
        commit = streaming.StreamCommit(stream_id, hb(self.C["final_digest_hex"]))
        self.assertIsNone(streaming.verify_commit(commit, chunks))  # valid stream verifies

        tampered = self._chunks()
        tampered[self.C["tamper"]["chunk_index"]].data = hb(self.C["tamper"]["flipped_data_hex"])
        with self.assertRaises(streaming.StreamError) as cm:
            streaming.verify_commit(commit, tampered)
        self.assertEqual(cm.exception.kind, "StreamDigestMismatch")
        # the tampered rolling digest is exactly the oracle's tamper digest
        self.assertEqual(streaming.commit_digest(tampered).hex(), self.C["tamper"]["digest_hex"])

    def test_checkpoint_verifies_prefix(self):
        stream_id = hb(self.C["stream_id_hex"])
        allc = self._chunks()
        for i, cpj in enumerate(self.C["checkpoints"]):
            cp = streaming.StreamCheckpoint(stream_id, cpj["through_offset"], hb(cpj["digest_so_far_hex"]))
            prefix = allc[:i + 1]  # chunks through this checkpoint, WITHOUT the end
            self.assertIsNone(streaming.verify_checkpoint(cp, prefix), "checkpoint %d" % i)
        # A checkpoint claiming the first prefix but given the full stream fails (wrong length).
        cp0 = streaming.StreamCheckpoint(stream_id, self.C["checkpoints"][0]["through_offset"],
                                         hb(self.C["checkpoints"][0]["digest_so_far_hex"]))
        with self.assertRaises(streaming.StreamError) as cm:
            streaming.verify_checkpoint(cp0, allc)
        self.assertEqual(cm.exception.kind, "StreamDigestMismatch")

    def test_effect_refused_before_chunk(self):
        stream_id = hb(self.C["stream_id_hex"])
        # A destructive stream under a read-only grant is refused (R-10.3).
        destructive = streaming.StreamOpen(stream_id, policy.DESTRUCTIVE, None, 1)
        with self.assertRaises(streaming.StreamError) as cm:
            streaming.open_stream(destructive, policy.READ_ONLY)
        self.assertEqual(cm.exception.kind, "EffectNotAuthorized")
        # The corpus stream (idempotent_write) under an idempotent_write grant is authorized.
        ok = streaming.StreamOpen(stream_id, self.C["effect"], hb(self.C["approval_hex"]), self.C["substream"])
        self.assertIsNone(streaming.open_stream(ok, policy.IDEMPOTENT_WRITE))
        # An unrecognized effect fails closed to destructive and is refused below destructive.
        unknown = streaming.StreamOpen(stream_id, 99, None, 1)
        with self.assertRaises(streaming.StreamError):
            streaming.open_stream(unknown, policy.NON_IDEMPOTENT_WRITE)

    def test_offset_order_matters(self):
        chunks = self._chunks()
        reversed_ = list(reversed(chunks))
        # CommitDigest sorts by absolute offset, so input order is irrelevant.
        self.assertEqual(streaming.commit_digest(chunks).hex(), streaming.commit_digest(reversed_).hex())
        # Swap the data at the first two offsets: same bytes, different positions -> different digest.
        swapped = self._chunks()
        swapped[0].data, swapped[1].data = swapped[1].data, swapped[0].data
        self.assertNotEqual(streaming.commit_digest(swapped).hex(), self.C["final_digest_hex"])

    def test_signed_commitment_in_isolation(self):
        # NOT corpus-graded (no signature vector). Real deterministic ML-DSA raw round-trip: one
        # end-commitment signature covers the whole stream (R-10.2).
        commit = streaming.StreamCommit(hb(self.C["stream_id_hex"]), hb(self.C["final_digest_hex"]))
        sig = streaming.sign_commit(commit, ALG, SEED)
        self.assertTrue(streaming.verify_commit_sig(commit, ALG, PK, sig))
        bad = bytearray(sig)
        bad[0] ^= 0x01
        self.assertFalse(streaming.verify_commit_sig(commit, ALG, PK, bytes(bad)))
        # StreamOpen is also a signed object.
        open_ = streaming.StreamOpen(hb(self.C["stream_id_hex"]), self.C["effect"],
                                     hb(self.C["approval_hex"]), self.C["substream"])
        osig = streaming.sign_open(open_, ALG, SEED)
        self.assertTrue(streaming.verify_open_sig(open_, ALG, PK, osig))


if __name__ == "__main__":
    unittest.main()
