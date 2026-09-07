# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Decoder resource bounds (design.md §3.4, R7) known-answer + fail-closed tests for the Python
SDK, mirroring impl/go/cbor/bounds_test.go, impl/go/envelope/bounds_test.go, and
impl/go/streaming/bounds_test.go.

Each bound is proven by a BOUNDARY PAIR: an otherwise-valid input exactly AT the limit
verifies, and an otherwise-valid input one past the limit is rejected with the named error.
"Otherwise valid" is load-bearing for mutation survival -- because the only defect is the
bound, deleting the bound check makes the over-limit input verify.

Run:  python -m unittest -v tests.test_bounds   (from impl/python/, PYTHONDONTWRITEBYTECODE=1)
"""
import unittest

from naalp import cbor, cose, envelope, streaming
from naalp.cbor import U, B, T, A, M

_ALG = cose.ALG_MLDSA65
_SEED = bytes(range(32))  # a LOCAL test signing seed -- the verdict is a real sign+verify.
_SIGNER = b"BOUNDS_SIGNER"


def _kind_ok(_ch, _k):
    return True


def _base_object(body=None, causes=None, ext=None, cext=None):
    """A minimal otherwise-valid object (channel 0, kind 1 -- not the Identity Rotation
    selector) so the only defect under test is the bound itself."""
    return envelope.Object(
        kind=1, channel=0, signer=_SIGNER, created=1785000000000, effect=0,
        body=body if body is not None else T("bounds"),
        tier=0, profile=cose.PROFILE_PUBLIC, causes=causes or [], ext=ext, cext=cext,
    )


def _make_causes(n):
    """n content-id-shaped bstrs (multihash sha2-384 = 0x20 0x30 + 48 zero bytes)."""
    out = []
    for _ in range(n):
        b = bytearray(50)
        b[0], b[1] = 0x20, 0x30
        out.append(bytes(b))
    return out


def _make_ext_map(n):
    """n distinct non-critical/unrecognized extension entries (unknown keys, which the
    may-ignore rule accepts), so the object is otherwise valid at any cardinality."""
    return M([(U(100 + i), U(0)) for i in range(n)])


def _nest_arrays(k):
    """k single-element arrays wrapping a zero scalar. As a body value it sits at depth 2 (the
    object body map is depth 1), so the scalar is at depth 2+k."""
    v = U(0)
    for _ in range(k):
        v = A([v])
    return v


# ---- CBOR-level nesting depth (mirrors impl/go/cbor/bounds_test.go) --------------------------

def _nested_arrays_cbor(k):
    """Canonical CBOR for k single-element arrays wrapping a zero scalar: 0x81 (array of one)
    repeated k times, then 0x00. Decoding it, the outermost array is at depth 1 and the
    innermost scalar is at depth k+1."""
    return bytes([0x81]) * k + bytes([0x00])


class DecodeBoundedDepthTest(unittest.TestCase):
    """Pins the nesting-depth counter (design.md §3.4, R7): the outermost item is depth 1, and
    decode_bounded rejects the first item at depth max_depth+1 with DepthExceeded, before it is
    materialized. The unbounded decode() path still accepts the same structure, so the bound is
    what does the work."""

    def test_decode_bounded_depth(self):
        d = 3

        # deepest scalar at depth d (k = d-1): accepted at max_depth=d.
        at_limit = _nested_arrays_cbor(d - 1)
        cbor.decode_bounded(at_limit, d)  # must not raise

        # deepest scalar at depth d+1 (k = d): rejected DepthExceeded at max_depth=d.
        over = _nested_arrays_cbor(d)
        with self.assertRaises(cbor.DepthExceeded) as cm:
            cbor.decode_bounded(over, d)
        self.assertEqual(cm.exception.kind, "DepthExceeded")

        # the unbounded path accepts the same over-depth structure: the bound, not another
        # check, is what rejected it above.
        cbor.decode(over)  # must not raise


# ---- Envelope-level bounds (mirrors impl/go/envelope/bounds_test.go) --------------------------

class EnvelopeBoundsAcceptAtLimitTest(unittest.TestCase):
    """An object exactly AT each cardinality/depth bound verifies, so the boundary is inclusive
    and the reject tests below prove the boundary itself."""

    def test_causes_at_limit(self):
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(causes=_make_causes(envelope.MAX_CAUSES))
        signed = envelope.sign(o, _ALG, _SEED)
        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)  # must not raise

    def test_ext_at_limit(self):
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        o = _base_object(ext=_make_ext_map(envelope.MAX_EXT))
        signed = envelope.sign(o, _ALG, _SEED)
        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)  # must not raise

    def test_depth_at_limit(self):
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        # body nested so the deepest scalar sits at exactly MAX_NESTING_DEPTH
        # (2 + (MAX_NESTING_DEPTH-2)).
        o = _base_object(body=_nest_arrays(envelope.MAX_NESTING_DEPTH - 2))
        signed = envelope.sign(o, _ALG, _SEED)
        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)  # must not raise


class EnvelopeBoundsRejectOverLimitTest(unittest.TestCase):
    """An otherwise-valid object one past each bound is rejected with its named error
    (fail-closed)."""

    def _expect(self, obj, kind):
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)
        signed = envelope.sign(obj, _ALG, _SEED)
        with self.assertRaises(Exception) as cm:
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, signed)
        self.assertEqual(getattr(cm.exception, "kind", None), kind)

    def test_causes_over_limit(self):
        self._expect(_base_object(causes=_make_causes(envelope.MAX_CAUSES + 1)), "TooManyCauses")

    def test_ext_over_limit(self):
        self._expect(_base_object(ext=_make_ext_map(envelope.MAX_EXT + 1)), "TooManyExtensions")

    def test_cext_over_limit(self):
        # cext over the limit also yields TooManyExtensions: the cardinality check in
        # _object_from_map fires before the critical-extension recognition check.
        self._expect(_base_object(cext=_make_ext_map(envelope.MAX_CEXT + 1)), "TooManyExtensions")

    def test_depth_over_limit(self):
        # body nested so the deepest scalar sits at MAX_NESTING_DEPTH+1.
        self._expect(_base_object(body=_nest_arrays(envelope.MAX_NESTING_DEPTH - 1)), "DepthExceeded")


class EnvelopeBoundTooLargeTest(unittest.TestCase):
    """Pins the object octet-size bound: a large-but-under-limit signed object verifies, and an
    otherwise-valid object over the limit is rejected TooLarge on the raw bytes before any parse
    (RFC 8949 §10 decoder-memory guard)."""

    def test_bound_too_large(self):
        pk = cose.mldsa_keygen("ML-DSA-65", _SEED)

        under = _base_object(body=B(bytes(envelope.MAX_OBJECT_SIZE - 16384)))
        uobj = envelope.sign(under, _ALG, _SEED)
        self.assertLessEqual(len(uobj), envelope.MAX_OBJECT_SIZE,
                              "under-limit object exceeded MAX_OBJECT_SIZE")
        envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, uobj)  # must not raise

        over = _base_object(body=B(bytes(envelope.MAX_OBJECT_SIZE)))
        bobj = envelope.sign(over, _ALG, _SEED)
        self.assertGreater(len(bobj), envelope.MAX_OBJECT_SIZE,
                            "over-limit object did not exceed MAX_OBJECT_SIZE")
        with self.assertRaises(envelope.EnvelopeError) as cm:
            envelope.verify(cose.PROFILE_PUBLIC, _ALG, pk, _kind_ok, bobj)
        self.assertEqual(cm.exception.kind, "TooLarge")


# ---- Streaming chunk-count bound (mirrors impl/go/streaming/bounds_test.go) -------------------

class StreamBoundTooManyChunksTest(unittest.TestCase):
    """Pins the stream chunk-count bound (design.md §3.4, R7): a commit over exactly
    MAX_STREAM_CHUNKS chunks verifies, and one over MAX_STREAM_CHUNKS+1 is rejected
    TooManyChunks. Both carry a MATCHING rolling digest, so the count is the only reason to
    reject -- deleting the count check makes the +1 case verify (the mutation is caught). The
    chunks are all-empty so the accept-at-limit case is built cheaply."""

    def test_bound_too_many_chunks(self):
        over = [streaming.Chunk(offset=0, data=b"") for _ in range(streaming.MAX_STREAM_CHUNKS + 1)]
        at_limit = over[:streaming.MAX_STREAM_CHUNKS]

        ok_commit = streaming.StreamCommit(stream_id=b"s", digest=streaming.commit_digest(at_limit))
        streaming.verify_commit(ok_commit, at_limit)  # must not raise

        over_commit = streaming.StreamCommit(stream_id=b"s", digest=streaming.commit_digest(over))
        with self.assertRaises(streaming.StreamError) as cm:
            streaming.verify_commit(over_commit, over)
        self.assertEqual(cm.exception.kind, "TooManyChunks")

        # verify_checkpoint enforces the same bound, and the count check fires before the
        # contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
        over_cp = streaming.StreamCheckpoint(stream_id=b"s", through_offset=0, digest_so_far=b"")
        with self.assertRaises(streaming.StreamError) as cm2:
            streaming.verify_checkpoint(over_cp, over)
        self.assertEqual(cm2.exception.kind, "TooManyChunks")


if __name__ == "__main__":
    unittest.main()
