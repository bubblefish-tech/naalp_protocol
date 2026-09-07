# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# NAALP-MCP binding-profile conformance for the Ruby SDK (design.md §19; Companion-Spec
# Requirement 6.1), graded against the shared independent corpus vectors/mcp/cases.json (NOT produced
# by this code): the annotation-set wire bytes, the published annotation->effect mapping table, every
# malformed-annotation rejection, the tool-call body/content-id/tool-id/args-id/call-binding bytes,
# the more-severe effect resolution (accept + EffectUnderDeclared verdicts), the approval-binding
# content ids (a changed argument or changed tool description yields a new call content id), and the
# edge cases (non-canonical rejection, empty-vs-absent annotations, minimal, look-alike).
#
# The end-to-end governance path -- a real ML-DSA-65 signed McpToolCall verified through the frozen
# envelope, its enforced effect resolved to the more severe, and the per-call approval consumed
# single-use through the §7 ledger -- is real behaviour demonstrated in isolation (the corpus carries
# no signed-object vector, stated honestly, so it is NOT corpus-graded). Where deterministic ML-DSA is
# unavailable those tests skip LOUDLY (never a false green).
#
# Written test-first; the MCP module is absent until ported, so this fails RED (uninitialized constant
# Naalp::MCP) until impl/ruby/lib/naalp/mcp.rb lands and naalp.rb requires it. THE mutation target is
# test_mapped_effect_matches_oracle: dropping the fail-closed destructive default (or forcing the
# mapping to a constant) flips it on its assertion.
#
# Run:  ruby -Ilib -Itest test/test_mcp.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'naalp'

def mcp_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "mcp", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/mcp/cases.json not found"
end

def hb(hex)
  [hex].pack("H*")
end

ALG = Naalp::COSE::ALG_MLDSA65
PROFILE = Naalp::COSE::PROFILE_PUBLIC

# corpus hint cbor-key (string) -> Annotations attribute name
HINT_ATTR = { 1 => :read_only, 2 => :destructive, 3 => :idempotent, 4 => :open_world }.freeze

# Build an Annotations from a corpus hints dict (string cbor-key -> 0/1).
def ann(hints)
  a = Naalp::MCP::Annotations.new
  hints.each { |k, v| a.public_send("#{HINT_ATTR[k.to_i]}=", v == 1) }
  a
end

McpKey = Struct.new(:seed, :pk, :id)

class McpConformance < Minitest::Test
  C = mcp_vectors

  # A real ML-DSA-65 keypair + self-certifying id, or a loud skip where the platform lacks it.
  def mk_key(n)
    seed = ([n & 0xFF].pack("C") * 32).b
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    McpKey.new(seed, pk, Naalp::Identity.signer_id(ALG, pk))
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  # ---- annotation wire bytes (design §6.1) ----------------------------------------------

  def test_annotations_encode_match_oracle
    assert C["annotations"].length >= 2
    C["annotations"].each do |av|
      a = ann(av["hints"])
      assert_equal av["annotations_hex"], a.encode.unpack1("H*"), av["name"]
    end
  end

  # ---- the published annotation -> effect mapping table (THE mutation target) ------------

  # Each annotation set maps to the closed four-effect lattice by the published table; an absent
  # readOnlyHint defaults false, an absent destructiveHint defaults TRUE (the fail-closed collapse to
  # destructive), openWorldHint never enters the mapping. Forcing the mapping to a constant, or
  # dropping the destructive default, flips this assertion.
  def test_mapped_effect_matches_oracle
    C["annotations"].each do |av|
      assert_equal av["mapped_effect"], Naalp::MCP.map_annotations_to_effect(ann(av["hints"])), av["name"]
    end
  end

  def test_malformed_annotations_rejected
    C["malformed_annotations"].each do |mv|
      v = Naalp::CBOR.decode(hb(mv["annotations_hex"]))
      err = assert_raises(Naalp::MCP::McpError, mv["name"]) do
        Naalp::MCP.annotations_from_value(v)
      end
      assert_equal "MalformedAnnotation", err.kind, mv["name"]
    end
  end

  # ---- tool-call body / content-id / tool-id / args-id / call-binding bytes --------------

  def test_tool_call_bodies_match_oracle
    assert C["tool_calls"].length >= 2
    C["tool_calls"].each do |tv|
      tc = Naalp::MCP::ToolCall.new(hb(tv["tool_hex"]), hb(tv["args_hex"]), ann(tv["hints"]))
      assert_equal tv["body_hex"], tc.bytes.unpack1("H*"), tv["name"]
      assert_equal tv["content_id_hex"], tc.content_id.unpack1("H*"), tv["name"]
      cb = tc.call_binding
      assert_equal tv["tool_id_hex"], cb.tool_id.unpack1("H*"), tv["name"]
      assert_equal tv["args_id_hex"], cb.args_id.unpack1("H*"), tv["name"]
      assert_equal tv["call_binding_hex"], cb.bytes.unpack1("H*"), tv["name"]
      assert_equal tv["call_content_id_hex"], cb.content_id.unpack1("H*"), tv["name"]
      assert_equal tv["annotation_mapped_effect"],
                   Naalp::MCP.map_annotations_to_effect(tc.annotations), tv["name"]
      # a tool call re-parses from its own body bytes
      got = Naalp::MCP.tool_call_from_body(Naalp::CBOR.decode(tc.bytes))
      assert_equal tc.tool, got.tool, tv["name"]
      assert_equal tc.args, got.args, tv["name"]
    end
  end

  # ---- more-severe effect resolution (the good-regulator attenuator) ---------------------

  def test_resolution_matches_oracle
    assert C["resolution"].length >= 2
    C["resolution"].each do |rv|
      mapped = rv["annotation_mapped"]
      declared = rv["declared"]
      if rv["verdict"] == "accept"
        enforced, mismatch = Naalp::MCP.resolve_enforced_effect(mapped, declared)
        assert_equal rv["enforced"], enforced, rv["name"]
        assert_equal rv["mismatch"], mismatch, rv["name"]
      else
        err = assert_raises(Naalp::MCP::McpError, rv["name"]) do
          Naalp::MCP.resolve_enforced_effect(mapped, declared)
        end
        assert_equal rv["verdict"], err.kind, rv["name"]
      end
    end
  end

  # NOT corpus-graded: a declared effect outside the closed lattice is rejected, never defaulted.
  def test_resolve_effect_outside_lattice
    err = assert_raises(Naalp::MCP::McpError) do
      Naalp::MCP.resolve_enforced_effect(Naalp::Policy::READ_ONLY, 4)
    end
    assert_equal "EffectOutsideLattice", err.kind
  end

  # ---- the approval binds the exact call (AC-6.1.2 / AC-6.1.3) ---------------------------

  def test_approval_binding_content_ids_match_oracle
    binds = C["approval_binding"]
    assert binds.length >= 3
    seen = {}
    binds.each do |bv|
      cb = Naalp::MCP.new_call_binding(hb(bv["tool_hex"]), hb(bv["args_hex"]))
      assert_equal bv["tool_id_hex"], cb.tool_id.unpack1("H*"), bv["name"]
      assert_equal bv["args_id_hex"], cb.args_id.unpack1("H*"), bv["name"]
      assert_equal bv["call_binding_hex"], cb.bytes.unpack1("H*"), bv["name"]
      assert_equal bv["call_content_id_hex"], cb.content_id.unpack1("H*"), bv["name"]
      seen[bv["call_content_id_hex"]] = true
    end
    # a changed argument (T,B) and a changed tool description (T2,A) each yield a DISTINCT call content
    # id from the base (T,A) -- so a prior approval bound to (T,A) matches neither.
    assert_equal binds.length, seen.length
  end

  # ---- edge cases (design §6.1 CDDL) ----------------------------------------------------

  def test_edge_cases
    ec = C["edge_cases"]

    # canonical body parses; the descending-key body is rejected NonCanonical at decode.
    koo = ec["keys_out_of_order"]
    Naalp::MCP.tool_call_from_body(Naalp::CBOR.decode(hb(koo["canonical_body_hex"])))
    assert_raises(Naalp::CBOR::NonCanonical) do
      Naalp::CBOR.decode(hb(koo["noncanonical_body_hex"]))
    end

    # an empty annotations map is PRESENT and valid (all MCP defaults -> destructive); an
    # annotations-absent body is a distinct wire shape and is rejected ToolCallMalformed.
    eva = ec["empty_vs_absent"]
    empty = eva["empty_annotations"]
    tc = Naalp::MCP.tool_call_from_body(Naalp::CBOR.decode(hb(empty["body_hex"])))
    assert_equal empty["content_id_hex"], tc.content_id.unpack1("H*")
    assert_equal empty["mapped_effect"], Naalp::MCP.map_annotations_to_effect(tc.annotations)
    err = assert_raises(Naalp::MCP::McpError) do
      Naalp::MCP.tool_call_from_body(Naalp::CBOR.decode(hb(eva["absent_annotations"]["body_hex"])))
    end
    assert_equal "ToolCallMalformed", err.kind

    # the smallest valid tool call: empty tool, empty args, empty annotations (-> destructive).
    mn = ec["minimal"]
    tc = Naalp::MCP::ToolCall.new(hb(mn["tool_hex"]), hb(mn["args_hex"]), Naalp::MCP::Annotations.new)
    assert_equal mn["body_hex"], tc.bytes.unpack1("H*")
    assert_equal mn["content_id_hex"], tc.content_id.unpack1("H*")
    assert_equal mn["mapped_effect"], Naalp::MCP.map_annotations_to_effect(tc.annotations)

    # a 2-field call-binding fed to the tool-call parser is rejected (a tool call is 3 fields).
    la = ec["look_alike"]
    err = assert_raises(Naalp::MCP::McpError) do
      Naalp::MCP.tool_call_from_body(Naalp::CBOR.decode(hb(la["call_binding_body_hex"])))
    end
    assert_equal "ToolCallMalformed", err.kind
  end

  # ---- end-to-end signed governance path, in isolation (NOT corpus-graded) ---------------

  def test_verify_tool_call_in_isolation
    signer = mk_key(11)
    tc = Naalp::MCP::ToolCall.new('{"name":"delete_file"}'.b, '{"path":"a"}'.b,
                                  Naalp::MCP::Annotations.new(read_only: false, destructive: true))
    obj = tc.envelope_object(signer.id, 1, PROFILE, Naalp::Policy::DESTRUCTIVE, [])
    signed = Naalp::MCP.sign_tool_call(obj, ALG, signer.seed)
    r = Naalp::MCP.verify_tool_call(PROFILE, ALG, signer.pk, signed)
    assert_equal Naalp::Policy::DESTRUCTIVE, r.enforced
    assert_equal Naalp::Policy::DESTRUCTIVE, r.annotation_mapped
    refute r.mismatch
    assert_equal obj.content_id, r.content_id

    # a benign annotation with a severe DECLARED effect: enforced is the more severe, mismatch true.
    tc2 = Naalp::MCP::ToolCall.new("t".b, "a".b, Naalp::MCP::Annotations.new(read_only: true))
    obj2 = tc2.envelope_object(signer.id, 1, PROFILE, Naalp::Policy::DESTRUCTIVE, [])
    r2 = Naalp::MCP.verify_tool_call(PROFILE, ALG, signer.pk,
                                     Naalp::MCP.sign_tool_call(obj2, ALG, signer.seed))
    assert_equal Naalp::Policy::DESTRUCTIVE, r2.enforced
    assert r2.mismatch

    # a tampered signature is rejected BadSignature (envelope crypto).
    bad = signed.dup
    bad.setbyte(bad.bytesize - 1, bad.getbyte(bad.bytesize - 1) ^ 1)
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::MCP.verify_tool_call(PROFILE, ALG, signer.pk, bad)
    end
    assert_equal "BadSignature", err.kind
  end

  def test_under_declared_rejected_in_isolation
    # A wrapper whose DECLARED effect sits below its own carried annotations' mapping is rejected
    # EffectUnderDeclared at the enforcement point (a signed, attributable inconsistency).
    signer = mk_key(12)
    tc = Naalp::MCP::ToolCall.new("t".b, "a".b,
                                  Naalp::MCP::Annotations.new(read_only: false, destructive: true))
    obj = tc.envelope_object(signer.id, 1, PROFILE, Naalp::Policy::READ_ONLY, [])
    signed = Naalp::MCP.sign_tool_call(obj, ALG, signer.seed)
    err = assert_raises(Naalp::MCP::McpError) do
      Naalp::MCP.verify_tool_call(PROFILE, ALG, signer.pk, signed)
    end
    assert_equal "EffectUnderDeclared", err.kind
  end

  def test_authorize_call_binds_exact_call_and_consumes_once
    signer = mk_key(13)
    approver = mk_key(14)
    tc = Naalp::MCP::ToolCall.new('{"name":"transfer"}'.b, '{"to":"acct-1"}'.b,
                                  Naalp::MCP::Annotations.new(read_only: false, destructive: true))
    obj = tc.envelope_object(signer.id, 1, PROFILE, Naalp::Policy::DESTRUCTIVE, [])
    r = Naalp::MCP.verify_tool_call(PROFILE, ALG, signer.pk,
                                    Naalp::MCP.sign_tool_call(obj, ALG, signer.seed))
    call_cid = r.tool_call.call_binding.content_id
    appr = Naalp::Approval::ApprovalRecord.new(call_cid, approver.id, Naalp::Policy::DESTRUCTIVE,
                                               "\x01\x02".b, 1_000_000)
    sig = Naalp::Approval.sign_approval(appr, ALG, approver.seed)
    Dir.mktmpdir do |tmp|
      ledger = Naalp::Approval.open_ledger(File.join(tmp, "consume.log"))
      begin
        assert_nil Naalp::MCP.authorize_call(r, appr, ALG, approver.pk, sig, signer.id, 500, ledger)
        assert ledger.consumed?(appr.id)
        # single-use: a replay of the same approval is AlreadyConsumed, no second append.
        err = assert_raises(Naalp::Approval::ApprovalError) do
          Naalp::MCP.authorize_call(r, appr, ALG, approver.pk, sig, signer.id, 500, ledger)
        end
        assert_equal "AlreadyConsumed", err.kind
        assert_equal 1, ledger.count
      ensure
        ledger.close
      end
    end
  end

  def test_authorize_call_wrong_binding_requires_approval
    # An approval that binds a DIFFERENT call (different args) does not satisfy this call: the mismatch
    # is a held outcome surfaced as ApprovalRequired, with no ledger append (fail-closed).
    signer = mk_key(15)
    approver = mk_key(16)
    tc = Naalp::MCP::ToolCall.new('{"name":"transfer"}'.b, '{"to":"acct-1"}'.b,
                                  Naalp::MCP::Annotations.new(read_only: false, destructive: true))
    obj = tc.envelope_object(signer.id, 1, PROFILE, Naalp::Policy::DESTRUCTIVE, [])
    r = Naalp::MCP.verify_tool_call(PROFILE, ALG, signer.pk,
                                    Naalp::MCP.sign_tool_call(obj, ALG, signer.seed))
    other = Naalp::MCP.new_call_binding('{"name":"transfer"}'.b, '{"to":"acct-2"}'.b).content_id
    appr = Naalp::Approval::ApprovalRecord.new(other, approver.id, Naalp::Policy::DESTRUCTIVE,
                                               "\x01".b, 1_000_000)
    sig = Naalp::Approval.sign_approval(appr, ALG, approver.seed)
    Dir.mktmpdir do |tmp|
      ledger = Naalp::Approval.open_ledger(File.join(tmp, "consume.log"))
      begin
        err = assert_raises(Naalp::MCP::McpError) do
          Naalp::MCP.authorize_call(r, appr, ALG, approver.pk, sig, signer.id, 500, ledger)
        end
        assert_equal "ApprovalRequired", err.kind
        assert_equal 0, ledger.count
      ensure
        ledger.close
      end
    end
  end
end
