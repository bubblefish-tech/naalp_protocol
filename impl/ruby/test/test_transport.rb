# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C11 transport-binding conformance for the Ruby SDK, graded against the shared independent
# corpus vectors/transport/cases.json (NOT produced by this code): the media type, the four
# bindings' confidentiality/peer-auth guarantees, the framing round-trip, and the §12.3/§12.4
# emit boundary matrix. Written test-first; the module is absent until ported, so this fails
# RED on require until impl/ruby/lib/naalp/transport.rb lands, and a mutation to the emit
# boundary flips test_emit_boundary_matrix.
#
# Run:  ruby -Ilib -Itest test/test_transport.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

# Walk up from this test dir to the repository's shared corpus (the independent oracle).
def transport_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "transport", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/transport/cases.json not found"
end

class TransportConformance < Minitest::Test
  C = transport_vectors

  def test_media_type
    assert_equal C["media_type"], Naalp::Transport::MEDIA_TYPE
  end

  def test_transport_variants_match_corpus
    C["transports"].each do |t|
      got, ok = Naalp::Transport.by_name(t["name"])
      assert ok, "unknown transport #{t['name']}"
      assert_equal [t["confidential"], t["peer_authenticated"]],
                   [got.confidential, got.peer_authenticated],
                   "guarantees mismatch for #{t['name']}"
    end
  end

  def test_frame_roundtrips_object_bytes_unchanged
    t, = Naalp::Transport.by_name("npamp")
    mu = Naalp::Transport.frame(t, "\x01\x02\x03".b)
    assert_equal Naalp::Transport::MEDIA_TYPE, mu.media_type
    assert_equal "\x01\x02\x03".b, mu.object
  end

  def test_object_rejects_wrong_media_type
    mu = Naalp::Transport::MessageUnit.new("npamp", "application/json", "x".b)
    err = assert_raises(Naalp::Transport::TransportError) { mu.object }
    assert_equal "Malformed", err.kind
  end

  def test_emit_boundary_matrix
    C["emit_matrix"].each do |c|
      t, ok = Naalp::Transport.by_name(c["transport"])
      assert ok, "unknown transport #{c['transport']}"
      if c["result"] == "ok"
        mu = Naalp::Transport.emit(t, "obj".b, c["sensitive"], c["require_peer_auth"])
        assert_equal "obj".b, mu.object, c.inspect
      else
        err = assert_raises(Naalp::Transport::TransportError, c.inspect) do
          Naalp::Transport.emit(t, "obj".b, c["sensitive"], c["require_peer_auth"])
        end
        assert_equal c["result"], err.kind, c.inspect
      end
    end
  end
end
