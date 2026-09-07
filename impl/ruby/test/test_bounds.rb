# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Decoder resource bounds (design.md §3.4, R7) for the Ruby SDK: the object octet-size ceiling,
# the CBOR nesting-depth ceiling, the causes[]/ext/cext cardinality ceilings, and the stream
# chunk-count ceiling. Mirrors impl/go/cbor/bounds_test.go, impl/go/envelope/bounds_test.go, and
# impl/go/streaming/bounds_test.go (cross-read against impl/rust/src/{cbor,envelope,streaming}.rs).
#
# Every bound is proven by a BOUNDARY PAIR: an otherwise-valid input exactly AT the limit is
# accepted, and one just past the limit is rejected with its exact error kind. "Otherwise valid"
# is load-bearing for mutation survival -- the only defect is the bound, so deleting the bound
# check would make the over-limit case verify instead of reject.
#
# Run:  ruby -Ilib -Itest test/test_bounds.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'naalp'

include Naalp::CBOR

BOUNDS_ALG = Naalp::COSE::ALG_MLDSA65
BOUNDS_SIGNER = "SIGNER_BOUNDS".b

MAXD = Naalp::Envelope::MAX_NESTING_DEPTH
MAXC = Naalp::Envelope::MAX_CAUSES
MAXE = Naalp::Envelope::MAX_EXT
MAXX = Naalp::Envelope::MAX_CEXT
MAXO = Naalp::Envelope::MAX_OBJECT_SIZE
MAXS = Naalp::Envelope::MAX_STREAM_CHUNKS

# deterministic ML-DSA needs OpenSSL >= 3.5; skip loudly (never a false green) where unavailable.
def bounds_mldsa_key
  seed = ("\x07" * 32).b
  pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
  [seed, pk]
rescue Exception
  nil
end

def bounds_accept_kind
  ->(_ch, _k) { true }
end

# An otherwise-valid object (kind/channel/tier/signer/created/effect/profile all in range); only
# causes/ext/cext/body vary per bound under test.
def bounds_object(causes: [], ext: nil, cext: nil, body: T.new("bounds"))
  Naalp.object(
    kind: 1, channel: 4, tier: 0, signer: BOUNDS_SIGNER, created: 1785000000000,
    effect: 2, profile: Naalp::COSE::PROFILE_PUBLIC, causes: causes, ext: ext, cext: cext, body: body
  )
end

# n content-id-shaped bstrs (multihash sha2-384 = 0x20 0x30 + 48 bytes), like a real causes entry.
def bounds_causes(n)
  Array.new(n) do
    b = ("\x00" * 50).b
    b.setbyte(0, 0x20)
    b.setbyte(1, 0x30)
    b
  end
end

# n distinct non-critical extension entries (unknown keys, which the may-ignore rule accepts), so
# the object is otherwise valid at any cardinality.
def bounds_ext_map(n)
  M.new(Array.new(n) { |i| [U.new(100 + i), U.new(0)] })
end

# k single-element arrays wrapping a zero scalar, as a FIELD_BODY value. The object body map
# decodes at depth 1, so the FIELD_BODY map-entry value sits at depth 2, and the innermost scalar
# sits at depth 2+k (mirrors impl/go/envelope/bounds_test.go nestArrays).
def bounds_nest_arrays(k)
  v = U.new(0)
  k.times { v = A.new([v]) }
  v
end

# ---- C1 CBOR nesting depth (design.md §3.4, R7) --------------------------------------------

class CborBoundsTest < Minitest::Test
  # k single-element arrays (0x81 repeated) wrapping a zero scalar: decoding it, the outermost
  # array is at depth 1 and the innermost scalar is at depth k+1.
  def nested_arrays_cbor(k)
    ([0x81].pack("C") * k) + [0x00].pack("C")
  end

  # Pins the nesting-depth counter (design.md §3.4, R7): the outermost item is depth 1, and
  # decode_bounded rejects the first item at depth max_depth+1 with DepthExceeded, before it is
  # materialized. The unbounded decode path still accepts the same structure, so the bound, not
  # another check, is what does the work.
  def test_decode_bounded_depth
    d = 3

    # deepest scalar at depth d (k = d-1): accepted at max_depth=d.
    at_limit = nested_arrays_cbor(d - 1)
    Naalp::CBOR.decode_bounded(at_limit, d)

    # deepest scalar at depth d+1 (k = d): rejected DepthExceeded at max_depth=d.
    over = nested_arrays_cbor(d)
    err = assert_raises(Naalp::CBOR::DepthExceeded) { Naalp::CBOR.decode_bounded(over, d) }
    assert_equal "DepthExceeded", err.kind

    # the unbounded path accepts the same over-depth structure: the bound above, not another
    # check, is what rejected it.
    Naalp::CBOR.decode(over)
  end
end

# ---- C3 envelope bounds (design.md §3.4, R7) ------------------------------------------------

# An object exactly AT each cardinality/depth bound verifies, so the boundary is inclusive and
# the reject tests below prove the boundary itself.
class EnvelopeBoundsAcceptTest < Minitest::Test
  def setup
    @seed, @pk = bounds_mldsa_key
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" if @pk.nil?
  end

  def accept(name, obj)
    signed = Naalp.sign(obj, BOUNDS_ALG, @seed)
    Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, BOUNDS_ALG, @pk, bounds_accept_kind, signed)
  rescue StandardError => e
    flunk "#{name} verify at-limit: #{e.class}: #{e.message}"
  end

  def test_causes_at_limit
    accept("causes==MAX_CAUSES", bounds_object(causes: bounds_causes(MAXC)))
  end

  def test_ext_at_limit
    accept("ext==MAX_EXT", bounds_object(ext: bounds_ext_map(MAXE)))
  end

  def test_depth_at_limit
    # body nested so the deepest scalar sits at exactly MAX_NESTING_DEPTH (2 + (MAXD-2)).
    accept("depth==MAX_NESTING_DEPTH", bounds_object(body: bounds_nest_arrays(MAXD - 2)))
  end
end

# An otherwise-valid object one past each bound is rejected with its named error (fail-closed).
class EnvelopeBoundsRejectTest < Minitest::Test
  def setup
    @seed, @pk = bounds_mldsa_key
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" if @pk.nil?
  end

  def expect(name, obj, error_class, kind)
    signed = Naalp.sign(obj, BOUNDS_ALG, @seed)
    err = assert_raises(error_class) do
      Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, BOUNDS_ALG, @pk, bounds_accept_kind, signed)
    end
    assert_equal kind, err.kind, name
  end

  def test_too_many_causes
    expect("TooManyCauses", bounds_object(causes: bounds_causes(MAXC + 1)),
           Naalp::Envelope::EnvelopeError, "TooManyCauses")
  end

  def test_too_many_extensions_ext
    expect("TooManyExtensions(ext)", bounds_object(ext: bounds_ext_map(MAXE + 1)),
           Naalp::Envelope::EnvelopeError, "TooManyExtensions")
  end

  # cext over the limit also yields TooManyExtensions: the cardinality check in object_from_map
  # fires before the critical-extension recognition check.
  def test_too_many_extensions_cext
    expect("TooManyExtensions(cext)", bounds_object(cext: bounds_ext_map(MAXX + 1)),
           Naalp::Envelope::EnvelopeError, "TooManyExtensions")
  end

  def test_depth_exceeded
    # body nested so the deepest scalar sits at MAX_NESTING_DEPTH+1.
    expect("DepthExceeded", bounds_object(body: bounds_nest_arrays(MAXD - 1)),
           Naalp::CBOR::DepthExceeded, "DepthExceeded")
  end
end

# Pins the object octet-size bound: a large-but-under-limit signed object verifies, and an
# otherwise-valid object over the limit is rejected TooLarge on the raw bytes before any parse
# (RFC 8949 §10 decoder-memory guard).
class EnvelopeBoundsTooLargeTest < Minitest::Test
  def setup
    @seed, @pk = bounds_mldsa_key
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5)" if @pk.nil?
  end

  def test_too_large
    under = bounds_object(body: B.new(("\x00" * (MAXO - 16384)).b))
    uobj = Naalp.sign(under, BOUNDS_ALG, @seed)
    assert uobj.bytesize < MAXO, "under-limit object is #{uobj.bytesize} bytes, expected < #{MAXO}"
    Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, BOUNDS_ALG, @pk, bounds_accept_kind, uobj)

    over = bounds_object(body: B.new(("\x00" * MAXO).b))
    bobj = Naalp.sign(over, BOUNDS_ALG, @seed)
    assert bobj.bytesize > MAXO, "over-limit object is only #{bobj.bytesize} bytes, expected > #{MAXO}"
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp.verify(Naalp::COSE::PROFILE_PUBLIC, BOUNDS_ALG, @pk, bounds_accept_kind, bobj)
    end
    assert_equal "TooLarge", err.kind
  end
end

# ---- C9 streaming chunk-count bound (design.md §3.4, R7) ------------------------------------

# A commit/checkpoint over exactly MAX_STREAM_CHUNKS chunks verifies, and one over
# MAX_STREAM_CHUNKS+1 is rejected TooManyChunks. Both carry a MATCHING rolling digest, so the
# count is the only reason to reject -- deleting the count check would make the +1 case verify
# (the mutation is caught). The chunks are empty so building/hashing a million-plus of them stays
# cheap.
class StreamingBoundsTest < Minitest::Test
  def test_bound_too_many_chunks
    max = MAXS
    over = Array.new(max + 1) { Naalp::Streaming::Chunk.new(0, "".b) }
    at_limit = over[0, max]

    ok_commit = Naalp::Streaming::StreamCommit.new("".b, Naalp::Streaming.commit_digest(at_limit))
    Naalp::Streaming.verify_commit(ok_commit, at_limit)

    over_commit = Naalp::Streaming::StreamCommit.new("".b, Naalp::Streaming.commit_digest(over))
    err = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.verify_commit(over_commit, over) }
    assert_equal "TooManyChunks", err.kind

    # verify_checkpoint enforces the same bound, and the count check fires before the
    # contiguity/digest checks, so the diagnosis is TooManyChunks (not a digest error).
    cp = Naalp::Streaming::StreamCheckpoint.new("".b, 0, "".b)
    cerr = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.verify_checkpoint(cp, over) }
    assert_equal "TooManyChunks", cerr.kind
  end
end
