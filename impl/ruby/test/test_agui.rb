# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C21 NAALP-AGUI UI-consent-binding conformance for the Ruby SDK (design.md §24; R-AGUI-1..6), graded
# against the shared independent corpus vectors/agui/cases.json (NOT produced by this code): the closed
# UI-event kind vocabulary, the receipt-chained UIEvent body/head/id bytes (including the minimal event
# and the >2^53 seq carried as a string), the action content ids (shown vs substituted), the shown-chain
# walk with its final head, the malformed/absent-field/non-canonical rejections, and the hole-detection
# position for an omitted shown-event.
#
# The consent binding itself -- a human §7 approval bound to the EXACT action content id shown, and the
# rejection of a SUBSTITUTED action (different content id) -- and the signed shown-chain are real
# behaviour demonstrated in isolation with REAL deterministic ML-DSA-65 (the corpus carries no signed
# vector, stated honestly, so those are NOT corpus-graded), reusing the corpus action/substituted ids.
# Where deterministic ML-DSA is unavailable those tests skip LOUDLY (never a false green).
#
# Written test-first; the AGUI module is absent until ported, so this fails RED (uninitialized constant
# Naalp::AGUI) until impl/ruby/lib/naalp/agui.rb lands and naalp.rb requires it. THE mutation target is
# test_event_bodies_match_oracle: forcing the event kind field to a constant flips it on its assertion.
#
# Run:  ruby -Ilib -Itest test/test_agui.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

def agui_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "agui", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/agui/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
PROFILE = Naalp::COSE::PROFILE_PUBLIC

AguiKey = Struct.new(:seed, :pk, :id)

class AguiConformance < Minitest::Test
  C = agui_vectors

  def mk_key(n)
    seed = ([n & 0xFF].pack("C") * 32).b
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    AguiKey.new(seed, pk, Naalp::Identity.signer_id(ALG, pk))
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def chain_events
    sess = hb(C["session_hex"])
    C["chain"]["events"].map do |ev|
      Naalp::AGUI::UIEvent.new(sess, ev["kind"], hb(ev["action_hex"]), ev["seq"], hb(ev["prev_hex"]))
    end
  end

  # ---- the closed UI-event kind vocabulary ----------------------------------------------

  def test_kind_vocabulary
    C["kind_vocabulary"].each do |kv|
      assert_equal kv["name"], Naalp::AGUI.kind_name(kv["code"]), kv.inspect
      assert Naalp::AGUI.is_known_kind(kv["code"])
    end
    refute Naalp::AGUI.is_known_kind(C["unknown_kind"])
    assert_equal "unknown", Naalp::AGUI.kind_name(C["unknown_kind"])
  end

  # ---- UIEvent body / head / id bytes (THE mutation target) ------------------------------

  # Each receipt-chained UIEvent encodes {1:session,2:kind,3:action,4:seq,5:prev} byte-for-byte the
  # oracle, over the three-event chain, the minimal event, and a >2^53 seq carried as a string. Forcing
  # the kind field to a constant flips a body_hex assertion.
  def test_event_bodies_match_oracle
    evs = C["chain"]["events"]
    assert evs.length >= 2
    sess = hb(C["session_hex"])
    evs.each do |ev|
      e = Naalp::AGUI::UIEvent.new(sess, ev["kind"], hb(ev["action_hex"]), ev["seq"], hb(ev["prev_hex"]))
      assert_equal ev["body_hex"], e.bytes.unpack1("H*"), ev["kind"].to_s
      assert_equal ev["head_hex"], e.head.unpack1("H*"), ev["kind"].to_s
      assert_equal ev["id_hex"], e.id.unpack1("H*"), ev["kind"].to_s
    end

    # the minimal event (empty session/action, seq 0, genesis prev).
    mn = C["minimal"]
    e = Naalp::AGUI::UIEvent.new(hb(mn["session_hex"]), mn["kind"], hb(mn["action_hex"]), mn["seq"],
                                 hb(mn["prev_hex"]))
    assert_equal mn["body_hex"], e.bytes.unpack1("H*")
    assert_equal mn["id_hex"], e.id.unpack1("H*")

    # a >2^53 seq (carried in the corpus as a STRING to avoid float64 rounding) round-trips exact.
    bs = C["big_seq"]
    e = Naalp::AGUI::UIEvent.new(sess, bs["kind"], hb(bs["action_hex"]), Integer(bs["seq_str"]),
                                 hb(bs["prev_hex"]))
    assert_equal bs["body_hex"], e.bytes.unpack1("H*")
    assert_equal bs["id_hex"], e.id.unpack1("H*")
  end

  # ---- action content ids (shown vs substituted) -----------------------------------------

  def test_action_content_ids_match_oracle
    assert_equal C["action_cid_hex"], Naalp::AGUI.content_id(hb(C["action_bytes_hex"])).unpack1("H*")
    assert_equal C["substituted_cid_hex"],
                 Naalp::AGUI.content_id(hb(C["substituted_bytes_hex"])).unpack1("H*")
    refute_equal C["action_cid_hex"], C["substituted_cid_hex"]
  end

  # ---- the shown-chain walk (contiguity, heads) ------------------------------------------

  def test_walk_shown_matches_oracle
    shown = Naalp::AGUI.walk_shown(chain_events)
    assert_equal 3, shown.length
    assert_equal C["chain"]["final_head_hex"], shown[-1].head.unpack1("H*")
    # each event re-parses from its own body bytes.
    chain_events.zip(C["chain"]["events"]).each do |e, ev|
      got = Naalp::AGUI.parse_ui_event(e.bytes)
      assert_equal ev["kind"], got.kind
      assert_equal ev["seq"], got.seq
    end
  end

  # ---- malformed / absent-field / non-canonical rejections -------------------------------

  def test_rejections
    ec = C["edge_cases"]
    # a body whose mandatory field 5 (prev) is absent is UIMalformed.
    err = assert_raises(Naalp::AGUI::AguiError) do
      Naalp::AGUI.parse_ui_event(hb(ec["empty_vs_absent"]["absent_field"]["body_hex"]))
    end
    assert_equal "UIMalformed", err.kind
    # a ui-event-shaped body lacking its field-5 back-pointer is UIMalformed.
    err = assert_raises(Naalp::AGUI::AguiError) do
      Naalp::AGUI.parse_ui_event(hb(ec["look_alike"]["body_hex"]))
    end
    assert_equal "UIMalformed", err.kind
    # descending-key body is rejected NonCanonical at decode.
    assert_raises(Naalp::CBOR::NonCanonical) do
      Naalp::CBOR.decode(hb(ec["keys_out_of_order"]["noncanonical_body_hex"]))
    end
    # an empty action is a valid, distinct wire body from a populated one.
    eva = ec["empty_vs_absent"]
    e_empty = Naalp::AGUI.parse_ui_event(hb(eva["empty_action"]["body_hex"]))
    assert_equal eva["empty_action"]["id_hex"], e_empty.id.unpack1("H*")
    assert_equal "".b, e_empty.action
  end

  # ---- hole detection: an omitted shown-event leaves a positioned hole --------------------

  def test_hole_detection_matches_oracle
    evs = chain_events
    # a contiguous chain has no hole.
    assert_equal [0, false], Naalp::AGUI.detect_hole(evs)
    # omit ev1 (present indices ev0, ev2): the gap is detected at the corpus position.
    gappy = [evs[0], evs[2]]
    pos, hole = Naalp::AGUI.detect_hole(gappy)
    assert hole
    assert_equal C["hole"]["position"], pos
    # walking a gappy chain is UIChainBroken.
    err = assert_raises(Naalp::AGUI::AguiError) { Naalp::AGUI.walk_shown(gappy) }
    assert_equal "UIChainBroken", err.kind
  end

  # ---- the consent binding, in isolation (NOT corpus-graded; uses corpus action ids) ------

  # A real ML-DSA-65 signed shown chain: shown -> args-shown -> approved, all naming action_cid,
  # receipt-chained.
  def signed_consent_chain(ui_key, action_cid)
    events = []
    objs = []
    h = Naalp::AGUI.genesis
    sess = hb(C["session_hex"])
    [[0, Naalp::AGUI::KIND_SHOWN], [1, Naalp::AGUI::KIND_ARGS_SHOWN], [2, Naalp::AGUI::KIND_APPROVED]].each do |seq, kind|
      e = Naalp::AGUI::UIEvent.new(sess, kind, action_cid, seq, h)
      objs << Naalp::AGUI.sign_ui_event(e, ALG, ui_key.seed)
      events << e
      h = e.head
    end
    [events, objs]
  end

  def test_verify_consent_binds_exact_action
    ui = mk_key(31)
    approver = mk_key(32)
    action_bytes = hb(C["action_bytes_hex"])
    action_cid = hb(C["action_cid_hex"])
    events, objs = signed_consent_chain(ui, action_cid)

    # the signed shown chain verifies structurally + cryptographically.
    got = Naalp::AGUI.verify_shown_chain(objs, PROFILE, ALG, ui.pk)
    assert_equal 3, got.length

    # a human §7 approval binding the shown action content id.
    appr = Naalp::Approval::ApprovalRecord.new(action_cid, approver.id, Naalp::Policy::DESTRUCTIVE,
                                               "\x01".b, 1_000_000)
    sig = Naalp::Approval.sign_approval(appr, ALG, approver.seed)
    # executing the EXACT action shown+approved is authorized.
    assert_nil Naalp::AGUI.verify_consent(events, action_bytes, appr, ALG, approver.pk, sig, 500)

    # executing a SUBSTITUTED action (different content id) is rejected ActionSubstituted.
    err = assert_raises(Naalp::AGUI::AguiError) do
      Naalp::AGUI.verify_consent(events, hb(C["substituted_bytes_hex"]), appr, ALG, approver.pk, sig, 500)
    end
    assert_equal "ActionSubstituted", err.kind
  end

  def test_verify_consent_no_approved_event
    # a shown chain with NO approved event has no human consent to bind.
    ui = mk_key(33)
    approver = mk_key(34)
    action_cid = hb(C["action_cid_hex"])
    sess = hb(C["session_hex"])
    e0 = Naalp::AGUI::UIEvent.new(sess, Naalp::AGUI::KIND_SHOWN, action_cid, 0, Naalp::AGUI.genesis)
    e1 = Naalp::AGUI::UIEvent.new(sess, Naalp::AGUI::KIND_ARGS_SHOWN, action_cid, 1, e0.head)
    appr = Naalp::Approval::ApprovalRecord.new(action_cid, approver.id, Naalp::Policy::DESTRUCTIVE,
                                               "\x01".b, 1_000_000)
    sig = Naalp::Approval.sign_approval(appr, ALG, approver.seed)
    err = assert_raises(Naalp::AGUI::AguiError) do
      Naalp::AGUI.verify_consent([e0, e1], hb(C["action_bytes_hex"]), appr, ALG, approver.pk, sig, 500)
    end
    assert_equal "UINoConsent", err.kind
  end

  def test_verify_shown_chain_rejects_tampered_signature
    ui = mk_key(35)
    action_cid = hb(C["action_cid_hex"])
    _events, objs = signed_consent_chain(ui, action_cid)
    bad = objs[1].dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    objs[1] = bad
    err = assert_raises(StandardError) do
      Naalp::AGUI.verify_shown_chain(objs, PROFILE, ALG, ui.pk)
    end
    assert_equal "BadSignature", err.kind
  end
end
