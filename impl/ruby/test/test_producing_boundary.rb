# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# NA-IETF-1 producing-boundary disclosure (the OPTIONAL, self-asserted ext key 15, §2.5.4) known-answer
# tests for the Ruby SDK, graded against the independent oracle (tools/producing_boundary_oracle.py ->
# vectors/producing_boundary/cases.json), i.e. Ruby == Go == Rust == Python == oracle.
#
# Five properties, mirroring impl/go/envelope/producing_boundary_test.go, all mutation-surviving:
#   1. MATCHES ORACLE -- every case reproduces the oracle's body-no-id / content-id / full-body bytes;
#      a real ML-DSA-65 sign+verify yields exactly the oracle's accept/reject verdict; and the parsed
#      disclosure (present/kind/boundary/reporting) matches. Non-canonical sub-map bytes are rejected
#      NonCanonical at the codec.
#   2. UNDER SIGNATURE -- the disclosure is folded into the SIGNER's signed body: splicing a different
#      boundary into a signed object (keeping its id + signature) is rejected.
#   3. READER ROUND-TRIP -- set/get carries the value; the field is OPTIONAL; the setter DROPS a
#      reporting-boundary under observed (an observer relays from no one).
#   4. MALFORMED IGNORED [MUTATION ANCHOR] -- a well-formed object carrying a MALFORMED disclosure
#      (reporting under observed) in the non-critical ext map still verifies and is NOT surfaced.
#   5. CEXT REJECTED [MUTATION ANCHOR] -- the disclosure in the CRITICAL cext map is UnknownCriticalExt.
#
# Run:  ruby -Ilib -Itest test/test_producing_boundary.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'naalp'

include Naalp::CBOR

PB_ALG = Naalp::COSE::ALG_MLDSA65
# a LOCAL test signing seed -- the verdict is a sign+verify round-trip, not a reproduction of the
# oracle's signature (full_hex is the object BODY, not a signed COSE object, so byte-parity needs no
# signing).
PB_SEED = (0...32).to_a.pack("C*")

# the producing-boundary value sub-map WIRE keys (§2.5.4), used to build ext/cext DIRECTLY so the test
# grades the impl against the oracle's independent wire layout, not the impl's own private constants.
PB_K_BOUNDARY, PB_K_KIND, PB_K_REPORTING = 1, 2, 3

def pb_kind_ok
  ->(_ch, _k) { true }
end

def find_producing_boundary_vector
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "producing_boundary", "cases.json")
    return p if File.file?(p)
    d = File.dirname(d)
  end
  nil
end

def pb_load
  p = find_producing_boundary_vector
  return nil unless p
  JSON.parse(File.read(p, encoding: "utf-8"))
end

# basePBObject builds the shared base object (fields 2..10) from logical fields -- never from the
# oracle hex, so a constant encoder diverges from the pinned bytes.
def pb_base_object(corpus)
  base = corpus["base_object"]
  Naalp.object(
    kind: base["kind"], channel: base["channel"], tier: base["tier"],
    signer: [base["signer_hex"]].pack("H*"), created: base["created"], effect: base["effect"],
    causes: (base["causes_hex"] || []).map { |h| [h].pack("H*") }, profile: base["profile"],
    body: T.new(base["body_str"]),
  )
end

# Build the ext[15]/cext[15] sub-map DIRECTLY from the case's logical fields (the ONLY variable per
# case), reproducing the oracle bytes for well-formed AND malformed values -- the malformed cases
# cannot be built via Naalp::Envelope.set_producing_boundary by design, so they are constructed here.
def pb_apply_placement(o, tc)
  return if tc["placement"] == "absent"
  sub = []
  sub << [U.new(PB_K_BOUNDARY), B.new([tc["boundary_hex"]].pack("H*"))] unless tc["boundary_hex"].nil?
  sub << [U.new(PB_K_KIND), U.new(tc["kind"])] unless tc["kind"].nil?
  sub << [U.new(PB_K_REPORTING), B.new([tc["reporting_hex"]].pack("H*"))] unless tc["reporting_hex"].nil?
  ext = M.new([[U.new(Naalp::Envelope::PRODUCING_BOUNDARY_KEY), M.new(sub)]])
  case tc["placement"]
  when "ext"
    o.ext = ext
  when "cext"
    o.cext = ext
  else
    raise "unknown placement #{tc["placement"].inspect}"
  end
end

class ProducingBoundaryMatchesOracle < Minitest::Test
  def test_matches_oracle
    corpus = pb_load
    skip "committed producing_boundary vector not present (standalone install)" unless corpus
    assert_equal Naalp::Envelope::PRODUCING_BOUNDARY_KEY, corpus["producing_boundary_key"],
                 "corpus key != impl key"
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", PB_SEED)

    corpus["cases"].each do |tc|
      o = pb_base_object(corpus)
      pb_apply_placement(o, tc)
      # byte parity: body-without-id, content id, full body (all pre-signature).
      assert_equal tc["body_no_id_hex"], Naalp::CBOR.encode(o.body_map(false)).unpack1("H*"),
                   "body-no-id (#{tc["name"]})"
      cid = o.content_id
      assert_equal tc["content_id_hex"], cid.unpack1("H*"), "content-id (#{tc["name"]})"
      o.id = cid
      assert_equal tc["full_hex"], Naalp::CBOR.encode(o.body_map(true)).unpack1("H*"),
                   "full-body (#{tc["name"]})"

      # verdict: sign for real and verify offline; assert accept vs the named error.
      o2 = pb_base_object(corpus)
      pb_apply_placement(o2, tc)
      signed = Naalp::Envelope.sign(o2, PB_ALG, PB_SEED)
      if tc["expect"] == "accept"
        got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, signed)
        pb, present = Naalp::Envelope.producing_boundary(got)
        assert_equal tc["present"], present, "present (#{tc["name"]})"
        if present
          s = tc["surfaced"]
          assert_equal s["kind"], pb.kind, "kind (#{tc["name"]})"
          assert_equal s["boundary_hex"], pb.boundary.unpack1("H*"), "boundary (#{tc["name"]})"
          want_rep = s["reporting_hex"] || ""
          assert_equal want_rep, (pb.reporting || "".b).unpack1("H*"), "reporting (#{tc["name"]})"
        end
      else
        err = assert_raises(Naalp::Envelope::EnvelopeError) do
          Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, signed)
        end
        assert_equal tc["expect"], err.kind, "verdict error (#{tc["name"]})"
      end
    end

    # non-canonical disclosure bodies (sub-map keys out of order) are rejected at the CBOR layer.
    (corpus["negatives"] || []).each do |neg|
      o = pb_base_object(corpus)
      prot = Naalp::Envelope.protected_header(PB_ALG, o.signer, o.profile)
      signed = Naalp::COSE.cose_sign1(PB_ALG, PB_SEED, prot, [neg["payload_hex"]].pack("H*"))
      err = assert_raises(StandardError) do
        Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, signed)
      end
      kind = err.respond_to?(:kind) ? err.kind : nil
      assert_equal neg["expect"], kind, "negative verdict (#{neg["name"]})"
    end
  end
end

# ProducingBoundaryUnderSignature proves the disclosure is folded into the SIGNER's COSE_Sign1 signed
# input (ext, field 11, is part of the signed body): changing the boundary in a signed object's
# payload without re-signing breaks verification. A self-asserted disclosure that is NOT under the
# signer's signature would be forgeable, defeating attributability.
class ProducingBoundaryUnderSignature < Minitest::Test
  def test_under_signature
    corpus = pb_load
    skip "committed producing_boundary vector not present" unless corpus
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", PB_SEED)
    o = pb_base_object(corpus)
    Naalp::Envelope.set_producing_boundary(
      o, Naalp::Envelope::ProducingBoundary.new([tc_x].pack("H*"), Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED))
    signed = Naalp::Envelope.sign(o, PB_ALG, PB_SEED)
    # baseline: the signed object verifies and reads back the disclosure.
    got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, signed)
    pb, present = Naalp::Envelope.producing_boundary(got)
    assert present && pb.kind == Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED, "read-back"

    # tamper: change the boundary and re-encode the body WITHOUT re-signing; keep the original id and
    # reuse the original signature bytes -- a real forgery attempt that MUST be rejected.
    tampered = pb_base_object(corpus)
    Naalp::Envelope.set_producing_boundary(
      tampered, Naalp::Envelope::ProducingBoundary.new([tc_y].pack("H*"), Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED))
    tampered.id = o.id # keep original content id -- a splice, not a re-sign
    payload = Naalp::CBOR.encode(tampered.body_map(true))
    prot, _payload, sig = Naalp::COSE.parse_sign1_raw(signed)
    forged = Naalp::COSE.assemble_sign1_raw(prot, payload, sig)
    assert_raises(StandardError) do
      Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, forged)
    end
  end

  def tc_x; "424f554e444152595f58"; end
  def tc_y; "4f524947494e5f59"; end
end

# ProducingBoundaryReaderRoundTrip proves set/get carry the value, that the field is OPTIONAL (a fresh
# object has none), that a reported disclosure carries its reporting-boundary, and that the setter
# DROPS a reporting-boundary under observed (an observer relays from no one) so a caller cannot
# accidentally build a malformed disclosure.
class ProducingBoundaryReaderRoundTrip < Minitest::Test
  def test_reader_round_trip
    corpus = pb_load
    skip "committed producing_boundary vector not present" unless corpus
    o = pb_base_object(corpus)
    _pb, present = Naalp::Envelope.producing_boundary(o)
    refute present, "fresh object must have no producing-boundary disclosure"
    x = ["424f554e444152595f58"].pack("H*")
    y = ["4f524947494e5f59"].pack("H*")

    Naalp::Envelope.set_producing_boundary(
      o, Naalp::Envelope::ProducingBoundary.new(x, Naalp::Envelope::PRODUCING_BOUNDARY_REPORTED, y))
    pb, present = Naalp::Envelope.producing_boundary(o)
    assert present
    assert_equal Naalp::Envelope::PRODUCING_BOUNDARY_REPORTED, pb.kind
    assert_equal x, pb.boundary
    assert_equal y, pb.reporting

    # the setter drops a reporting-boundary under observed: read-back has no reporting.
    Naalp::Envelope.set_producing_boundary(
      o, Naalp::Envelope::ProducingBoundary.new(x, Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED, y))
    pb, present = Naalp::Envelope.producing_boundary(o)
    assert present
    assert_equal Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED, pb.kind
    assert_nil pb.reporting, "observed disclosure must drop reporting"
  end
end

# ProducingBoundaryMalformedIgnored is the MUTATION ANCHOR for the may-ignore rule: a well-formed
# object carrying a MALFORMED producing-boundary in the non-critical ext map (a reporting-boundary
# under observed) still Signs and Verifies, and the disclosure is NOT surfaced. Removing the
# "reporting under observed -> malformed" check in Naalp::Envelope.producing_boundary flips present
# false->true and this test pass->fail; that check is the observer-relays-from-no-one invariant.
class ProducingBoundaryMalformedIgnored < Minitest::Test
  def test_malformed_ignored
    corpus = pb_load
    skip "committed producing_boundary vector not present" unless corpus
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", PB_SEED)
    o = pb_base_object(corpus)
    # malformed ext[15] = {1:X, 2:observed, 3:Y} built directly (the setter refuses to build it).
    o.ext = M.new([[U.new(Naalp::Envelope::PRODUCING_BOUNDARY_KEY), M.new([
      [U.new(PB_K_BOUNDARY), B.new(["424f554e444152595f58"].pack("H*"))],
      [U.new(PB_K_KIND), U.new(Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED)],
      [U.new(PB_K_REPORTING), B.new(["4f524947494e5f59"].pack("H*"))],
    ])]])
    signed = Naalp::Envelope.sign(o, PB_ALG, PB_SEED)
    got = Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, signed) # must NOT raise (may-ignore)
    _pb, present = Naalp::Envelope.producing_boundary(got)
    refute present, "a malformed disclosure (reporting under observed) must NOT be surfaced"
  end
end

# ProducingBoundaryCextRejected is the MUTATION ANCHOR for the fail-closed rule: the disclosure placed
# in the CRITICAL cext map (field 12) is an unrecognized critical extension and the object is rejected
# UnknownCriticalExt. A disclosure must never masquerade as a must-understand gate.
class ProducingBoundaryCextRejected < Minitest::Test
  def test_cext_rejected
    corpus = pb_load
    skip "committed producing_boundary vector not present" unless corpus
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", PB_SEED)
    o = pb_base_object(corpus)
    o.cext = M.new([[U.new(Naalp::Envelope::PRODUCING_BOUNDARY_KEY), M.new([
      [U.new(PB_K_BOUNDARY), B.new(["424f554e444152595f58"].pack("H*"))],
      [U.new(PB_K_KIND), U.new(Naalp::Envelope::PRODUCING_BOUNDARY_OBSERVED)],
    ])]])
    signed = Naalp::Envelope.sign(o, PB_ALG, PB_SEED)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify(Naalp::COSE::PROFILE_PUBLIC, PB_ALG, pk, pb_kind_ok, signed)
    end
    assert_equal "UnknownCriticalExt", err.kind
  end
end
