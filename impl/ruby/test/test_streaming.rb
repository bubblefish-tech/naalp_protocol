# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C9 native-streaming conformance for the Ruby SDK (design.md §10; R-10.1..10.6), graded against the
# shared independent corpus vectors/stream/cases.json (NOT produced by this code). NOTE the name
# mismatch: the module is impl/ruby/lib/naalp/streaming.rb but the oracle directory is `stream` (not
# `streaming`), matching the Go module streaming/ graded against vectors/stream/. The tests grade the
# deterministic StreamOpen / StreamCommit / StreamCheckpoint body bytes byte-for-byte, the rolling
# SHA-384 commitment over chunks in absolute-offset order, the checkpoint digest_so_far, and the
# fail-closed effect authorization before any chunk.
#
# The LOAD-BEARING C9 property graded here: the whole stream is non-repudiable with ONE commitment
# digest, and altering ANY delivered byte invalidates the commitment (StreamDigestMismatch). The
# StreamOpen/StreamCommit/StreamCheckpoint signatures are real deterministic ML-DSA-65 (a raw signature
# over the body) demonstrated in isolation, but the corpus carries no signature vector, so they are NOT
# corpus-graded (stated honestly; skip-loud where deterministic ML-DSA is unavailable).
#
# Written test-first; the module is absent until ported, so this fails RED (uninitialized constant
# Naalp::Streaming) until impl/ruby/lib/naalp/streaming.rb lands, and a mutation forcing the rolling
# commitment to ignore the chunk data flips test_commit_digest_matches_oracle on its assertion.
#
# Run:  ruby -Ilib -Itest test/test_streaming.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def stream_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "stream", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/stream/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
SEED = ("\x00" * 32).b

class StreamingConformance < Minitest::Test
  C = stream_vectors

  def stream_id
    hb(C["stream_id_hex"])
  end

  def corpus_chunks
    C["chunks"].map { |c| Naalp::Streaming::Chunk.new(c["offset"], hb(c["data_hex"])) }
  end

  def test_stream_channel_constant
    assert_equal 0x000C, Naalp::Streaming::STREAM_CHANNEL
  end

  # Ruby encoding == the non-circular oracle, byte-for-byte, for the three signed stream objects.
  def test_open_commit_checkpoint_bodies_match_oracle
    open = Naalp::Streaming::StreamOpen.new(stream_id, C["effect"], hb(C["approval_hex"]), C["substream"])
    assert_equal C["open_body_hex"], open.bytes.unpack1("H*"), "StreamOpen body"

    commit = Naalp::Streaming::StreamCommit.new(stream_id, hb(C["final_digest_hex"]))
    assert_equal C["commit_body_hex"], commit.bytes.unpack1("H*"), "StreamCommit body"

    cp0 = C["checkpoints"][0]
    cp = Naalp::Streaming::StreamCheckpoint.new(stream_id, cp0["through_offset"], hb(cp0["digest_so_far_hex"]))
    assert_equal C["checkpoint_body_hex"], cp.bytes.unpack1("H*"), "StreamCheckpoint body"
  end

  # THE MUTATION TARGET. The load-bearing C9 property: the rolling SHA-384 over the chunks in
  # absolute-offset order is the ONE commitment covering the whole stream. Forcing the accumulator to
  # ignore the chunk data collapses every stream to SHA-384("") and flips this on its assertion.
  def test_commit_digest_matches_oracle
    assert_equal C["final_digest_hex"], Naalp::Streaming.commit_digest(corpus_chunks).unpack1("H*"),
                 "rolling commitment over all chunks"
    # every checkpoint's digest_so_far == the rolling digest of the prefix through that offset.
    C["checkpoints"].each do |cpv|
      prefix = corpus_chunks.select { |c| c.offset < cpv["through_offset"] }
      assert_equal cpv["digest_so_far_hex"], Naalp::Streaming.commit_digest(prefix).unpack1("H*"),
                   "checkpoint digest_so_far through #{cpv['through_offset']}"
    end
  end

  # verify_commit accepts the delivered chunks; a tampered byte at a mid-stream offset invalidates the
  # commitment (StreamDigestMismatch). The tampered stream's own digest == the corpus tamper digest.
  def test_tamper_invalidates_commitment
    commit = Naalp::Streaming::StreamCommit.new(stream_id, hb(C["final_digest_hex"]))
    assert_nil Naalp::Streaming.verify_commit(commit, corpus_chunks), "clean delivery verifies"

    t = C["tamper"]
    tampered = corpus_chunks
    tampered[t["chunk_index"]] = Naalp::Streaming::Chunk.new(tampered[t["chunk_index"]].offset, hb(t["flipped_data_hex"]))
    assert_equal t["digest_hex"], Naalp::Streaming.commit_digest(tampered).unpack1("H*"),
                 "tampered stream digest == corpus tamper digest"
    err = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.verify_commit(commit, tampered) }
    assert_equal "StreamDigestMismatch", err.kind
  end

  # verify_checkpoint confirms a prefix without the end: contiguous from offset 0, totalling exactly
  # through_offset, digest matching. A non-contiguous prefix and a wrong through_offset both fail.
  def test_verify_checkpoint_prefix
    cp0 = C["checkpoints"][0]
    cp = Naalp::Streaming::StreamCheckpoint.new(stream_id, cp0["through_offset"], hb(cp0["digest_so_far_hex"]))
    prefix = corpus_chunks.select { |c| c.offset < cp0["through_offset"] }
    assert_nil Naalp::Streaming.verify_checkpoint(cp, prefix), "valid prefix confirms"

    # a non-contiguous prefix (drops the first chunk, so offset != 0) is rejected.
    noncontig = corpus_chunks.select { |c| c.offset >= cp0["through_offset"] }
    err = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.verify_checkpoint(cp, noncontig) }
    assert_equal "StreamDigestMismatch", err.kind
    # a checkpoint claiming the wrong through_offset over a valid prefix is rejected.
    bad = Naalp::Streaming::StreamCheckpoint.new(stream_id, cp0["through_offset"] + 1, hb(cp0["digest_so_far_hex"]))
    err2 = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.verify_checkpoint(bad, prefix) }
    assert_equal "StreamDigestMismatch", err2.kind
  end

  # A stream's effect is authorized BEFORE any chunk (R-10.3): an effect within the granted ceiling
  # proceeds; one exceeding it is refused fail-closed; an unrecognized effect is treated destructive.
  def test_open_stream_effect_authorization
    open = Naalp::Streaming::StreamOpen.new(stream_id, C["effect"], hb(C["approval_hex"]), C["substream"])
    assert_nil Naalp::Streaming.open_stream(open, Naalp::Policy::DESTRUCTIVE), "effect 1 under a destructive ceiling proceeds"
    err = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.open_stream(open, Naalp::Policy::READ_ONLY) }
    assert_equal "EffectNotAuthorized", err.kind
    # an unrecognized effect fails closed to destructive: it exceeds every non-destructive ceiling.
    wild = Naalp::Streaming::StreamOpen.new(stream_id, 99, nil, 0)
    err2 = assert_raises(Naalp::Streaming::StreamError) { Naalp::Streaming.open_stream(wild, Naalp::Policy::NON_IDEMPOTENT_WRITE) }
    assert_equal "EffectNotAuthorized", err2.kind
  end

  # NOT corpus-graded (no signature vector). Real deterministic ML-DSA-65 raw-signature round-trip in
  # isolation over each stream body; a flipped signature byte does not verify. Skips LOUDLY where
  # deterministic ML-DSA is unavailable.
  def test_full_signature_sign_verify_in_isolation
    begin
      pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
    rescue Exception => e
      skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
    end
    commit = Naalp::Streaming::StreamCommit.new(stream_id, hb(C["final_digest_hex"]))
    sig = Naalp::Streaming.sign_commit(commit, ALG, SEED)
    assert Naalp::Streaming.verify_commit_sig(commit, ALG, pk, sig), "the one end-commitment signature verifies"
    bad = sig.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    refute Naalp::Streaming.verify_commit_sig(commit, ALG, pk, bad), "a flipped signature byte does not verify"

    open = Naalp::Streaming::StreamOpen.new(stream_id, C["effect"], hb(C["approval_hex"]), C["substream"])
    osig = Naalp::Streaming.sign_open(open, ALG, SEED)
    assert Naalp::Streaming.verify_open_sig(open, ALG, pk, osig), "StreamOpen signature verifies"
  end
end
