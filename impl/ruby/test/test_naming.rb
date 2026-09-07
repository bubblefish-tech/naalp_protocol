# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C19 name-bindings + signed A2A task-state profile conformance for the Ruby SDK (design.md §22;
# R-NAME-1..6, R-A2A-1..7), graded against the shared independent corpus vectors/naming/cases.json
# (NOT produced by this code): the name-binding and task-transition body/head/content-id byte parity,
# the A2A Agent Card attestation content-id (a C18 naalp-description-import), the offline name-history
# walk, hole/fork detection with the non-repudiable NameForkProof, the A2A legal-edge table (every
# legal edge accepted, every illegal edge rejected), the signed task-chain verifier (illegal edge /
# non-contiguous / bad start / foreign card / gap / bad signature), the >2^53 seq round-trip, the
# minimal encodings, the strict canonical-key rejection, and the look-alike cross-parse rejection.
#
# The chain verifiers run over REAL deterministic ML-DSA-65 signed COSE_Sign1 objects (OpenSSL 3.6.2,
# rnd=0). The two cross-language pins (SHA-384 of the seq-0 signed binding and transition, seed=0x11*32)
# are the Go+Rust+Python reference constants; asserting them proves Ruby == Go == Rust == Python
# byte-identical signed objects. The A2A legal-edge table is the C19 mutation target: forcing
# legal_edge to accept every edge (as the sibling naming red-evidence records) flips
# test_transition_table_matches_oracle on the illegal-edge assertion.
#
# Written test-first; the Naming module is absent until ported, so this fails RED (uninitialized
# constant Naalp::Naming) until impl/ruby/lib/naalp/naming.rb lands and naalp.rb requires it.
#
# Run:  ruby -Ilib -Itest test/test_naming.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'openssl'
require 'naalp'

def naming_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "naming", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/naming/cases.json not found"
end

ALG = Naalp::COSE::ALG_MLDSA65
PROFILE = Naalp::COSE::PROFILE_PUBLIC

# The Go + Rust + Python reference pins for the deterministic signed seq-0 binding/transition
# (seed = 0x11 * 32). Asserting them proves Ruby is byte-identical to the other reference ports.
PIN_SIGNED_BINDING_SHA384 = "a9179b939fffb1bce6abb4cd594b20e08f9d855729047ce4cb287da191234c10fecc9b232f80be902f70a3da490bcb91"
PIN_SIGNED_TRANSITION_SHA384 = "60a9902f51e3308149cf2ace5cb65cd4541b4cc7bd4ec5f9a120dd44f93560b6358dcb96cb04b0daedd4cbbdf31f5787"

KeyMat = Struct.new(:seed, :pk, :id)

def naming_key(seed_byte)
  seed = ([seed_byte] * 32).pack("C*").b
  pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
  KeyMat.new(seed, pk, Naalp::Identity.signer_id(ALG, pk))
end

class NamingConformance < Minitest::Test
  C = naming_vectors

  def hb(s)
    [s].pack("H*")
  end

  def ml_dsa_or_skip
    naming_key(0x11)
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def bindings
    n = C["name"]
    n["bindings"].map { |b| Naalp::Naming::NameBinding.new(n["name_utf8"], hb(b["signer_hex"]), b["seq"], hb(b["prev_hex"])) }
  end

  def transitions
    a = C["a2a"]
    task = a["task_utf8"].b
    card = hb(a["card"]["card_id_hex"])
    a["transitions"].map { |t| Naalp::Naming::Transition.new(task, card, t["from"], t["to"], t["seq"], hb(t["prev_hex"])) }
  end

  def card_import
    c = C["a2a"]["card"]
    ops = c["operations"].map { |o| Naalp::Description::Operation.new(o["name"], o["effect"], o["requires_approval"]) }
    Naalp::Description::Import.new(hb(c["importer_hex"]), c["format"], hb(c["foreign_hex"]), ops)
  end

  # ---- byte parity (design §22) --------------------------------------------------------

  # Ruby encoding == the non-circular oracle, byte-for-byte, for every binding/transition/card body,
  # head and content id. A mutation to any bytes field flips a *_hex assertion. Corpus-graded.
  def test_byte_parity_against_oracle
    n = C["name"]
    assert_equal 3, n["bindings"].length
    bindings.each_with_index do |nb, i|
      bv = n["bindings"][i]
      assert_equal bv["body_hex"], nb.bytes.unpack1("H*"), "binding[#{i}].bytes"
      assert_equal bv["head_hex"], nb.head.unpack1("H*"), "binding[#{i}].head"
      assert_equal bv["id_hex"], nb.id.unpack1("H*"), "binding[#{i}].id"
    end
    # The fork sibling b' at seq 1 also encodes byte-identically.
    fp = n["fork"]["b_prime"]
    bp = Naalp::Naming::NameBinding.new(n["name_utf8"], hb(fp["signer_hex"]), fp["seq"], hb(fp["prev_hex"]))
    assert_equal fp["body_hex"], bp.bytes.unpack1("H*")

    a = C["a2a"]
    assert_equal 4, a["transitions"].length
    transitions.each_with_index do |tr, i|
      tv = a["transitions"][i]
      assert_equal tv["body_hex"], tr.bytes.unpack1("H*"), "transition[#{i}].bytes"
      assert_equal tv["head_hex"], tr.head.unpack1("H*"), "transition[#{i}].head"
      assert_equal tv["id_hex"], tr.id.unpack1("H*"), "transition[#{i}].id"
    end

    im = card_import
    assert_equal a["card"]["import_body_hex"], im.bytes.unpack1("H*"), "card import body"
    assert_equal a["card"]["card_id_hex"], im.id.unpack1("H*"), "card import id (the bound card)"
  end

  # ---- name-history walk ---------------------------------------------------------------

  def test_walk_history_matches_oracle
    n = C["name"]
    bs = bindings
    events = Naalp::Naming.walk_history(bs)
    assert_equal n["walk"].length, events.length
    events.each_with_index do |e, i|
      assert_equal n["walk"][i]["seq"], e.seq
      assert_equal n["walk"][i]["signer_hex"], e.signer.unpack1("H*")
    end
    # The current signer is the last event's signer.
    assert_equal n["bindings"][-1]["signer_hex"], events[-1].signer.unpack1("H*")
    # A name change mid-chain breaks the walk (one name per chain).
    bad1 = Naalp::Naming::NameBinding.new("other.name", bs[1].signer, bs[1].seq, bs[1].prev)
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.walk_history([bs[0], bad1]) }
    assert_equal "NameChainBroken", err.kind
  end

  def test_name_hole_detected_with_position
    n = C["name"]
    bs = bindings
    _pos, hole = Naalp::Naming.detect_hole(bs)
    refute hole, "contiguous chain wrongly reported a hole"
    present = [bs[0], bs[2]] # seq 1 deleted
    pos, hole = Naalp::Naming.detect_hole(present)
    assert hole
    assert_equal n["hole"]["first_hole_position"], pos
  end

  def test_name_fork_detected_with_position
    ml_dsa_or_skip
    n = C["name"]
    bs = bindings
    fp = n["fork"]["b_prime"]
    bp = Naalp::Naming::NameBinding.new(n["name_utf8"], hb(fp["signer_hex"]), fp["seq"], hb(fp["prev_hex"]))
    pos, fork = Naalp::Naming.detect_fork(bs[1], bp)
    assert fork
    assert_equal n["fork"]["position"], pos
    # Identical bindings are a benign duplicate; a different seq is a distinct binding.
    refute Naalp::Naming.detect_fork(bs[1], bs[1])[1]
    refute Naalp::Naming.detect_fork(bs[1], bs[2])[1]

    # Signed non-repudiable proof: one authority signs BOTH conflicting bindings.
    accused = naming_key(0x11)
    foreign = naming_key(0x22)
    signed_a = Naalp::Naming.sign_binding(bs[1], ALG, accused.seed)
    signed_b = Naalp::Naming.sign_binding(bp, ALG, accused.seed)
    proof = Naalp::Naming::NameForkProof.new(accused.id.b, signed_a, signed_b)
    assert_equal n["fork"]["position"], proof.verify(PROFILE, ALG, accused.pk)
    # A foreign key does not verify the accused's signatures.
    err = assert_raises(Naalp::Naming::NamingError) { proof.verify(PROFILE, ALG, foreign.pk) }
    assert_equal "BadSignature", err.kind
    # An unnamed accused, and identical bodies, are NameForkProofInvalid.
    err = assert_raises(Naalp::Naming::NamingError) do
      Naalp::Naming::NameForkProof.new("".b, signed_a, signed_b).verify(PROFILE, ALG, accused.pk)
    end
    assert_equal "NameForkProofInvalid", err.kind
    err = assert_raises(Naalp::Naming::NamingError) do
      Naalp::Naming::NameForkProof.new(accused.id.b, signed_a, signed_a).verify(PROFILE, ALG, accused.pk)
    end
    assert_equal "NameForkProofInvalid", err.kind
  end

  def test_name_chain_verify_fail_closed
    ml_dsa_or_skip
    n = C["name"]
    accused = naming_key(0x11)
    foreign = naming_key(0x22)
    # Build a signed chain via the Registrar (rotation A -> B -> C).
    reg = Naalp::Naming::Registrar.new(n["name_utf8"], ALG, accused.seed)
    bs = []
    objs = []
    n["bindings"].each do |bv|
      nb, obj = reg.append(hb(bv["signer_hex"]))
      bs << nb
      objs << obj
    end
    bs.each_with_index { |nb, i| assert_equal n["bindings"][i]["body_hex"], nb.bytes.unpack1("H*"), "registrar reproduces oracle body" }
    verified = Naalp::Naming.verify_chain(objs, PROFILE, ALG, accused.pk)
    assert_equal bs.length, Naalp::Naming.walk_history(verified).length
    # A reordered chain breaks the prev/seq linkage.
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_chain([objs[0], objs[2], objs[1]], PROFILE, ALG, accused.pk) }
    assert_equal "NameChainBroken", err.kind
    # A tampered object fails its signature.
    corrupt = objs[1].dup
    corrupt.setbyte(corrupt.bytesize - 1, corrupt.getbyte(corrupt.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_chain([objs[0], corrupt, objs[2]], PROFILE, ALG, accused.pk) }
    assert_equal "BadSignature", err.kind
    # A foreign verifier authenticates none of the bindings.
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_chain(objs, PROFILE, ALG, foreign.pk) }
    assert_equal "BadSignature", err.kind
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_binding(objs[0], PROFILE, ALG, foreign.pk) }
    assert_equal "BadSignature", err.kind
  end

  # ---- A2A legal-edge table (THIS is the mutation-target assertion) ----------------------

  def test_transition_table_matches_oracle
    a = C["a2a"]
    assert_equal a["legal_edges"].length, Naalp::Naming.legal_edges.length
    a["legal_edges"].each do |e|
      assert Naalp::Naming.legal_edge(e[0], e[1]), "legal edge #{e[0]}->#{e[1]}"
      assert_nil Naalp::Naming.verify_transition(e[0], e[1])
    end
    a["illegal_edges"].each do |e|
      refute Naalp::Naming.legal_edge(e[0], e[1]), "illegal edge #{e[0]}->#{e[1]} wrongly accepted"
      err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_transition(e[0], e[1]) }
      assert_equal "IllegalTransition", err.kind
    end
    # Categories match the oracle.
    assert_equal a["states"]["start"], Naalp::Naming::START_STATE
    a["states"]["terminal"].each { |s| assert Naalp::Naming.terminal?(s) }
    a["states"]["interrupted"].each { |s| assert Naalp::Naming.interrupted?(s) }
    # A terminal state has no legal out-edge.
    a["states"]["terminal"].each do |s|
      (0..7).each { |to| refute Naalp::Naming.legal_edge(s, to), "terminal #{s} has out-edge to #{to}" }
    end
  end

  def test_task_chain_legal_and_illegal
    ml_dsa_or_skip
    a = C["a2a"]
    k = naming_key(0x11)
    card = hb(a["card"]["card_id_hex"])
    task = a["task_utf8"].b
    objs = transitions.map { |t| Naalp::Naming.sign_transition(t, ALG, k.seed) }
    # LEGAL ordered lifecycle verifies.
    assert_equal 4, Naalp::Naming.verify_task_chain(objs, card, PROFILE, ALG, k.pk).length

    chain_err = lambda do |trs|
      err = assert_raises(Naalp::Naming::NamingError) do
        Naalp::Naming.verify_task_chain(trs.map { |t| Naalp::Naming.sign_transition(t, ALG, k.seed) }, card, PROFILE, ALG, k.pk)
      end
      err.kind
    end

    t0 = Naalp::Naming::Transition.new(task, card, Naalp::Naming::STATE_SUBMITTED, Naalp::Naming::STATE_WORKING, 0, Naalp::Naming.genesis)
    # ILLEGAL edge inside a chain: working -> submitted.
    illegal = Naalp::Naming::Transition.new(task, card, Naalp::Naming::STATE_WORKING, Naalp::Naming::STATE_SUBMITTED, 1, t0.head)
    assert_equal "IllegalTransition", chain_err.call([t0, illegal])
    # NON-CONTIGUOUS from: input-required -> working after a working->? gap.
    noncontig = Naalp::Naming::Transition.new(task, card, Naalp::Naming::STATE_INPUT_REQUIRED, Naalp::Naming::STATE_WORKING, 1, t0.head)
    assert_equal "IllegalTransition", chain_err.call([t0, noncontig])
    # BAD START: seq-0 does not leave the start state.
    badstart = Naalp::Naming::Transition.new(task, card, Naalp::Naming::STATE_WORKING, Naalp::Naming::STATE_INPUT_REQUIRED, 0, Naalp::Naming.genesis)
    assert_equal "IllegalTransition", chain_err.call([badstart])
    # FOREIGN CARD.
    fc = Naalp::Naming::Transition.new(task, hb(a["foreign_card_id_hex"]), Naalp::Naming::STATE_SUBMITTED, Naalp::Naming::STATE_WORKING, 0, Naalp::Naming.genesis)
    assert_equal "ForeignCard", chain_err.call([fc])
    # GAP: present [t0, t2].
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_task_chain([objs[0], objs[2]], card, PROFILE, ALG, k.pk) }
    assert_equal "TaskChainBroken", err.kind
    # BAD SIGNATURE.
    corrupt = objs[0].dup
    corrupt.setbyte(corrupt.bytesize - 1, corrupt.getbyte(corrupt.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.verify_task_chain([corrupt, objs[1], objs[2], objs[3]], card, PROFILE, ALG, k.pk) }
    assert_equal "BadSignature", err.kind
  end

  def test_task_gap_detected_with_position
    a = C["a2a"]
    trs = transitions
    refute Naalp::Naming.detect_task_gap(trs)[1]
    present = [trs[0], trs[2]]
    pos, gap = Naalp::Naming.detect_task_gap(present)
    assert gap
    assert_equal a["gap"]["first_gap_position"], pos
  end

  def test_card_attestation_binds_profile
    ml_dsa_or_skip
    a = C["a2a"]
    k = naming_key(0x11)
    im = card_import
    card = im.id
    assert_equal a["card"]["card_id_hex"], card.unpack1("H*")
    submit, ok = im.operation("submit")
    assert ok
    assert_equal Naalp::Policy::IDEMPOTENT_WRITE, submit.effect_class
    assert submit.requires_approval_flag
    # A chain bound to this card verifies.
    objs = transitions.map { |t| Naalp::Naming.sign_transition(t, ALG, k.seed) }
    assert_equal 4, Naalp::Naming.verify_task_chain(objs, card, PROFILE, ALG, k.pk).length
    # A different importer yields a different card id; a chain carrying it is refused.
    other = Naalp::Description::Import.new("IMPORTER_ID_B".b, im.format, im.foreign, im.operations)
    refute_equal card, other.id
    foreign_t = Naalp::Naming::Transition.new(a["task_utf8"].b, other.id,
                                              Naalp::Naming::STATE_SUBMITTED, Naalp::Naming::STATE_WORKING, 0, Naalp::Naming.genesis)
    err = assert_raises(Naalp::Naming::NamingError) do
      Naalp::Naming.verify_task_chain([Naalp::Naming.sign_transition(foreign_t, ALG, k.seed)], card, PROFILE, ALG, k.pk)
    end
    assert_equal "ForeignCard", err.kind
  end

  def test_malformed_rejected
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.parse_name_binding([0x80].pack("C*")) } # empty CBOR array
    assert_equal "NameMalformed", err.kind
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.parse_transition([0x00].pack("C*")) } # a bare uint 0
    assert_equal "NameMalformed", err.kind
  end

  # ---- cross-language signed-object byte parity (Ruby == Go == Rust == Python) -----------

  def test_cross_lang_signed_binding_pin
    ml_dsa_or_skip
    nb = bindings[0]
    seed = ([0x11] * 32).pack("C*").b
    obj = Naalp::Naming.sign_binding(nb, ALG, seed)
    assert_equal PIN_SIGNED_BINDING_SHA384, OpenSSL::Digest::SHA384.hexdigest(obj),
                 "Ruby signed name-binding must be byte-identical to Go+Rust+Python"
  end

  def test_cross_lang_signed_transition_pin
    ml_dsa_or_skip
    tr = transitions[0]
    seed = ([0x11] * 32).pack("C*").b
    obj = Naalp::Naming.sign_transition(tr, ALG, seed)
    assert_equal PIN_SIGNED_TRANSITION_SHA384, OpenSSL::Digest::SHA384.hexdigest(obj),
                 "Ruby signed task-transition must be byte-identical to Go+Rust+Python"
  end

  # ---- >2^53 seq round-trip, minimal, canonical-key, look-alike --------------------------

  def test_oversized_seq_round_trip
    n = C["name"]
    a = C["a2a"]
    bseq = n["big_seq"]["seq_str"].to_i
    assert_operator bseq, :>, (1 << 53)
    nb = Naalp::Naming::NameBinding.new(n["name_utf8"], hb(n["big_seq"]["signer_hex"]), bseq, hb(n["big_seq"]["prev_hex"]))
    assert_equal n["big_seq"]["body_hex"], nb.bytes.unpack1("H*")
    assert_equal bseq, Naalp::Naming.parse_name_binding(nb.bytes).seq

    tseq = a["big_seq"]["seq_str"].to_i
    tr = Naalp::Naming::Transition.new(a["task_utf8"].b, hb(a["card"]["card_id_hex"]),
                                       a["big_seq"]["from"], a["big_seq"]["to"], tseq, hb(a["big_seq"]["prev_hex"]))
    assert_equal a["big_seq"]["body_hex"], tr.bytes.unpack1("H*")
    assert_equal tseq, Naalp::Naming.parse_transition(tr.bytes).seq
  end

  def test_minimal
    n = C["name"]["minimal"]
    a = C["a2a"]["minimal"]
    nb = Naalp::Naming::NameBinding.new(n["name_utf8"], hb(n["signer_hex"]), n["seq"], hb(n["prev_hex"]))
    assert_equal n["body_hex"], nb.bytes.unpack1("H*")
    assert_equal n["id_hex"], nb.id.unpack1("H*")
    refute_nil Naalp::Naming.parse_name_binding(nb.bytes)
    tr = Naalp::Naming::Transition.new(hb(a["task_hex"]), hb(a["card_hex"]), a["from"], a["to"], a["seq"], hb(a["prev_hex"]))
    assert_equal a["body_hex"], tr.bytes.unpack1("H*")
    refute_nil Naalp::Naming.parse_transition(tr.bytes)
  end

  def test_keys_out_of_order_rejected
    n = C["name"]
    koo = n["keys_out_of_order"]
    b0 = n["bindings"][0]
    nb = Naalp::Naming::NameBinding.new(n["name_utf8"], hb(b0["signer_hex"]), b0["seq"], hb(b0["prev_hex"]))
    assert_equal koo["canonical_binding_body_hex"], nb.bytes.unpack1("H*")
    refute_nil Naalp::CBOR.decode(hb(koo["canonical_binding_body_hex"]))
    assert_raises(Naalp::CBOR::NonCanonical) { Naalp::CBOR.decode(hb(koo["noncanonical_binding_body_hex"])) }
  end

  def test_look_alike_rejected_by_sibling
    la = C["name"]["look_alike"]
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.parse_transition(hb(la["binding_body_hex"])) }
    assert_equal "NameMalformed", err.kind
    err = assert_raises(Naalp::Naming::NamingError) { Naalp::Naming.parse_name_binding(hb(la["transition_body_hex"])) }
    assert_equal "NameMalformed", err.kind
  end
end
