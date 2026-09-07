# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C8 delivery conformance for the Ruby SDK (design.md §9; R-9.1..9.4), graded against the shared
# independent corpus vectors/delivery/cases.json (NOT produced by this code): the four monotonic
# stage names, the byte-exact signed delivery.update body for each stage, and the T1 content-id
# framing.
#
# The remaining C8 substance -- the persist-before-acknowledge WAL tracker, the live full-duplex
# switchboard, and the content-free relay (whose audit trail is a real C7 chain over content ids) --
# is real behaviour demonstrated in isolation (a tempfile WAL, threads, and the shared Naalp::Audit
# chain); the corpus carries no vector for those, so they are NOT corpus-graded (stated honestly).
# The delivery.update SIGNATURE is real deterministic ML-DSA-65, also demonstrated in isolation
# (skips LOUDLY where the platform lacks it -- never a false green).
#
# Written test-first; the module is absent until ported, so this fails RED on require until
# impl/ruby/lib/naalp/delivery.rb lands, and a mutation forcing the encoded stage field to a constant
# flips test_update_bodies_match_oracle.
#
# Run:  ruby -Ilib -Itest test/test_delivery.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'tempfile'
require 'naalp'

def delivery_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "delivery", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/delivery/cases.json not found"
end

ALG = Naalp::COSE::ALG_MLDSA65
SEED = ("\x00" * 32).b

class DeliveryConformance < Minitest::Test
  C = delivery_vectors

  def pk
    Naalp::COSE.mldsa_keygen("ML-DSA-65", SEED)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def test_stage_vocabulary
    C["stages"].each do |s|
      assert_equal s["name"], Naalp::Delivery.stage_name(s["value"]), s.inspect
    end
    assert_equal "unknown", Naalp::Delivery.stage_name(99)
    assert_equal C["stages"].map { |s| s["value"] },
                 [Naalp::Delivery::STAGE_PERSISTED_ORIGIN, Naalp::Delivery::STAGE_ACCEPTED_RELAY,
                  Naalp::Delivery::STAGE_PERSISTED_TARGET, Naalp::Delivery::STAGE_PRESENTED]
  end

  # THIS is the mutation-target assertion: each of the four stages encodes a distinct body,
  # byte-for-byte the non-circular oracle. Corpus-graded (no signature needed).
  def test_update_bodies_match_oracle
    obj = [C["obj_content_id_hex"]].pack("H*")
    C["updates"].each do |uv|
      u = Naalp::Delivery::DeliveryUpdate.new(obj, uv["stage"], uv["at"])
      assert_equal uv["body_hex"], u.bytes.unpack1("H*"), "update stage=#{uv['stage']}"
    end
  end

  # NOT corpus-graded (no signature vector). Real deterministic ML-DSA round-trip in isolation.
  def test_sign_verify_update_in_isolation
    key = pk
    obj = [C["obj_content_id_hex"]].pack("H*")
    u = Naalp::Delivery::DeliveryUpdate.new(obj, Naalp::Delivery::STAGE_PRESENTED, 103)
    sig = Naalp::Delivery.sign_update(u, ALG, SEED)
    assert Naalp::Delivery.verify_update(u, ALG, key, sig)
    bad = sig.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    refute Naalp::Delivery.verify_update(u, ALG, key, bad)
  end

  # Real WAL behaviour in isolation: monotonic stages, persist-before-ack, StageOutOfOrder on
  # regression, idempotent re-report, and durable recovery after reopen.
  def test_tracker_monotonic_persist_and_replay
    obj = [C["obj_content_id_hex"]].pack("H*")
    f = Tempfile.new("naalp-wal")
    path = f.path
    f.close
    begin
      t = Naalp::Delivery.open_tracker(path)
      t.advance(obj, Naalp::Delivery::STAGE_PERSISTED_ORIGIN, 100)
      t.advance(obj, Naalp::Delivery::STAGE_PERSISTED_TARGET, 102) # skipping ahead is permitted
      err = assert_raises(Naalp::Delivery::DeliveryError) do
        t.advance(obj, Naalp::Delivery::STAGE_ACCEPTED_RELAY, 103) # regression rejected
      end
      assert_equal "StageOutOfOrder", err.kind
      # re-reporting the current stage is an idempotent no-op that still returns the update
      same = t.advance(obj, Naalp::Delivery::STAGE_PERSISTED_TARGET, 104)
      assert_equal Naalp::Delivery::STAGE_PERSISTED_TARGET, same.stage
      assert_equal [Naalp::Delivery::STAGE_PERSISTED_TARGET, true], t.stage(obj)
      t.close
      # reopen -> replay recovers the last durable stage
      t2 = Naalp::Delivery.open_tracker(path)
      assert_equal [Naalp::Delivery::STAGE_PERSISTED_TARGET, true], t2.stage(obj)
      assert_equal [0, false], t2.stage("unseen".b)
      t2.close
    ensure
      File.unlink(path) if File.exist?(path)
    end
  end

  # Two connections held open, objects relayed through both directions concurrently.
  def test_switchboard_full_duplex
    sb = Naalp::Delivery::Switchboard.new(4)
    begin
      left = sb.left
      right = sb.right
      left.send("L->R".b)
      right.send("R->L".b)
      assert_equal "L->R".b, right.recv
      assert_equal "R->L".b, left.recv
    ensure
      sb.close
    end
  end

  # A relay retains only a C7 receipt chain over content ids (no payload). The retained trail
  # verifies as a valid chain, and the content-id framing matches the shared T1 framing.
  def test_content_free_relay_audit_trail_verifies
    key = pk
    relay = Naalp::Delivery::ContentFreeRelay.new(ALG, SEED)
    a = relay.route("object-one".b, 100)
    b = relay.route("object-two".b, 101)
    assert_equal "object-one".b, a # returned for immediate forwarding
    assert_equal "object-two".b, b
    receipts, sigs = relay.audit_trail
    assert_equal 2, receipts.length
    assert_equal Naalp::Delivery.content_id("object-one".b), receipts[0].obj
    assert_equal "\x20\x30".b, Naalp::Delivery.content_id("object-one".b)[0, 2] # T1 framing prefix
    assert_nil Naalp::Audit.verify_chain(receipts, sigs, ALG, key)
  end
end
