# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C15 multi-hop agent-delegation conformance for the Ruby SDK (design.md §18; R-DEL-1..8), graded
# against the shared independent corpus vectors/delegation/cases.json (NOT produced by this code):
# the DelegationGrant body/content-id byte parity, the D2 scope-containment truth table, and the
# 12-step leaf->root D3 chain verifier's verdict for every scenario (both the authorized outcomes and
# every named deny). The chain scenarios are driven as REAL ML-DSA-65 signed grant chains (each grant
# a signed envelope whose issuer is its verified signer, real envelope content-ids wired into
# `causes`), so the delegation CREDENTIAL path uses the real crypto (R-DEL-2/3), not a stand-in.
#
# Dedicated crypto tests port the Go/Python tamper/forge/baseline/NFC checks. The D4 two-gate
# composition (authorize_destructive) wires delegation onto the new approval module's single-use
# consume ledger and proves the replay guarantee end-to-end. test_attenuation_denies_escalation is
# the mutation target: removing the CapExceedsParent effect-attenuation check flips it (a child would
# exceed its parent). Signature/isolation tests skip LOUDLY where deterministic ML-DSA is
# unavailable -- never a false green.
#
# Written test-first; the Delegation module is absent until ported, so this fails RED (uninitialized
# constant Naalp::Delegation) until impl/ruby/lib/naalp/delegation.rb lands and naalp.rb requires it.
#
# Run:  ruby -Ilib -Itest test/test_delegation.rb      (from impl/ruby/)
require 'minitest/autorun'
require 'json'
require 'set'
require 'tmpdir'
require 'openssl'
require 'naalp'

def delegation_vectors
  d = File.expand_path(File.dirname(__FILE__))
  6.times do
    p = File.join(d, "vectors", "delegation", "cases.json")
    return JSON.parse(File.read(p, encoding: "utf-8")) if File.file?(p)
    d = File.dirname(d)
  end
  raise "vectors/delegation/cases.json not found"
end

ALG = Naalp::COSE::ALG_MLDSA65
PROFILE = Naalp::COSE::PROFILE_PUBLIC

KeyMat = Struct.new(:seed, :pk, :id)

# Deterministic real ML-DSA-65 key material per label. The seed is SHA-256 of the label, so distinct
# labels get distinct (collision-free) identities; a scenario reuses one identity per label. Cached
# across the run (keygen is deterministic, so caching only saves time). Returns nil-on-skip caller
# guards handle the platform-lacks-ML-DSA case loudly.
KEYCACHE = {}

def key_for(label)
  KEYCACHE[label] ||= begin
    seed = OpenSSL::Digest::SHA256.digest("naalp-ruby-deleg::#{label}")
    pk = Naalp::COSE.mldsa_keygen("ML-DSA-65", seed)
    KeyMat.new(seed, pk, Naalp::Identity.signer_id(ALG, pk))
  end
end

class DelegationConformance < Minitest::Test
  C = delegation_vectors

  def ml_dsa_or_skip
    key_for("__probe__")
  rescue Exception => e
    skip "deterministic ML-DSA unavailable (needs OpenSSL >= 3.5): #{e.class}"
  end

  def content_id_of(b)
    Naalp::CBOR.content_id(b)
  end

  # Build, sign (real ML-DSA-65), and verify a DelegationGrant; return [Resolved, signed_bytes].
  def sign_grant(issuer_key, subject_id, effect_cap, max_depth, not_before, not_after, scope, causes)
    g = Naalp::Delegation::Grant.new(subject_id, effect_cap, max_depth, not_before, not_after, scope)
    obj = g.envelope_object(issuer_key.id, 1, PROFILE, causes)
    signed = Naalp::Delegation.sign_grant(obj, ALG, issuer_key.seed)
    [Naalp::Delegation.verify_grant_object(PROFILE, ALG, issuer_key.pk, signed), signed]
  end

  # Build, sign, and verify a real action object by the signer (D3 step 1), then the Action.
  def build_action(signer_key, effect, scope, causes)
    obj = Naalp::Envelope::Object.new(
      kind: 2, channel: 1, signer: signer_key.id, created: 1, effect: effect,
      body: Naalp::CBOR::T.new("action"), tier: 0, profile: PROFILE, causes: causes)
    signed = Naalp::Envelope.sign(obj, ALG, signer_key.seed)
    validator = ->(ch, k) { Naalp::Delegation.composed_kind_validator(ch, k) }
    o = Naalp::Envelope.verify(PROFILE, ALG, signer_key.pk, validator, signed)
    Naalp::Delegation::Action.new(o.signer, o.effect, scope, o.causes)
  end

  # ---- DelegationGrant body / content-id byte parity (design §18.1) ---------------------

  # Ruby encoding == the non-circular oracle, byte-for-byte, for every grant body and content id.
  # A mutation to any Bytes() field flips a *_hex assertion. Corpus-graded (no signature needed).
  def test_grant_bytes_match_oracle
    assert C["grants"].any?
    C["grants"].each do |gj|
      g = Naalp::Delegation::Grant.new(gj["subject"], gj["effect_cap"], gj["max_depth"],
                                       gj["not_before"], gj["not_after"], gj["scope"])
      assert_equal gj["body_hex"], g.bytes.unpack1("H*"), gj["name"]
      assert_equal gj["content_id_hex"], g.content_id.unpack1("H*"), gj["name"]
    end
  end

  # ---- D2 scope-containment truth table (design §18.1) ----------------------------------

  def test_scope_containment_matches_oracle
    assert C["scope_containment"].any?
    C["scope_containment"].each do |r|
      assert_equal r["contained"], Naalp::Delegation.scope_contained(r["child"], r["parent"]),
                   "ScopeContained(#{r['child'].inspect}, #{r['parent'].inspect})"
    end
  end

  # ---- the 12-step D3 chain verifier verdicts (design §18.2), REAL signed chains ---------

  def test_chain_scenarios_match_oracle
    ml_dsa_or_skip
    assert C["scenarios"].any?
    C["scenarios"].each do |sc|
      keys = {}
      kf = lambda { |label| keys[label] ||= key_for("#{sc['name']}::#{label}") }

      grant_cid = Array.new(sc["grants"].length)
      grants = {}
      sc["grants"].each_with_index do |gj, i|
        ik = kf.call(gj["issuer"])
        sk = kf.call(gj["subject"])
        causes = gj["causes"].map { |ci| grant_cid[ci] }
        res, = sign_grant(ik, sk.id, gj["effect_cap"], gj["max_depth"],
                          gj["not_before"], gj["not_after"], gj["scope"], causes)
        grant_cid[i] = res.content_id
        grants[res.content_id.b] = res
      end

      act = sc["action"]
      action = build_action(kf.call(act["signer"]), act["effect"], act["scope"],
                            act["causes"].map { |ci| grant_cid[ci] })
      anchors = Set.new(sc["anchors"].map { |a| kf.call(a).id })
      revoked = {}
      sc["revoked"].each { |r| revoked[grant_cid[r["grant"]].b] = r["pos"] }

      if sc["expect"] == "authorized"
        assert_nil Naalp::Delegation.verify_chain(action, grants, anchors, revoked, sc["now"]),
                   "#{sc['name']}: expected authorized"
      else
        err = assert_raises(Naalp::Delegation::DelegationError, sc["name"]) do
          Naalp::Delegation.verify_chain(action, grants, anchors, revoked, sc["now"])
        end
        assert_equal sc["expect"], err.kind, sc["name"]
      end
    end
  end

  # ---- dedicated real-crypto deny paths (ported from the Go/Python behavioural tests) -----

  # a->m->b, effects/depths attenuating; a is the trust anchor. Returns the built chain context.
  def valid_2hop(effect)
    a = key_for("2hop-A-#{effect}") # trust anchor / root issuer
    m = key_for("2hop-M-#{effect}") # middle
    b = key_for("2hop-B-#{effect}") # actor
    root, = sign_grant(a, m.id, Naalp::Policy::DESTRUCTIVE, 2, 0, 1_000_000, "", [])
    leaf, leaf_signed = sign_grant(m, b.id, Naalp::Policy::DESTRUCTIVE, 1, 0, 1_000_000, "", [root.content_id])
    grants = { root.content_id.b => root, leaf.content_id.b => leaf }
    action = build_action(b, effect, "", [leaf.content_id])
    { a: a, m: m, b: b, grants: grants, anchors: Set.new([a.id]), action: action, leaf_signed: leaf_signed }
  end

  def test_valid_2hop_authorized
    ml_dsa_or_skip
    bc = valid_2hop(Naalp::Policy::NON_IDEMPOTENT_WRITE)
    assert_nil Naalp::Delegation.verify_chain(bc[:action], bc[:grants], bc[:anchors], {}, 500)
  end

  # MUTATION TARGET: a valid chain but an action effect ABOVE the leaf effect_cap must be denied
  # CapExceedsParent (a child can never exceed its parent's authority).
  def test_attenuation_denies_escalation
    ml_dsa_or_skip
    a = key_for("att-A")
    m = key_for("att-M")
    b = key_for("att-B")
    root, = sign_grant(a, m.id, Naalp::Policy::NON_IDEMPOTENT_WRITE, 2, 0, 1_000_000, "", [])
    leaf, = sign_grant(m, b.id, Naalp::Policy::NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "", [root.content_id])
    grants = { root.content_id.b => root, leaf.content_id.b => leaf }
    action = build_action(b, Naalp::Policy::DESTRUCTIVE, "", [leaf.content_id]) # 3 > leaf cap 2
    err = assert_raises(Naalp::Delegation::DelegationError) do
      Naalp::Delegation.verify_chain(action, grants, Set.new([a.id]), {}, 500)
    end
    assert_equal "CapExceedsParent", err.kind
  end

  def test_tampered_grant_signature_rejected
    ml_dsa_or_skip
    bc = valid_2hop(Naalp::Policy::NON_IDEMPOTENT_WRITE)
    tampered = bc[:leaf_signed].dup
    tampered.setbyte(tampered.bytesize - 1, tampered.getbyte(tampered.bytesize - 1) ^ 1)
    err = assert_raises(StandardError) do
      Naalp::Delegation.verify_grant_object(PROFILE, ALG, bc[:m].pk, tampered)
    end
    assert_equal "BadSignature", err.kind
  end

  def test_forged_issuer_rejected
    ml_dsa_or_skip
    real = key_for("forge-real")
    victim = key_for("forge-victim") # the id the forger tries to impersonate
    subject = key_for("forge-subject")
    g = Naalp::Delegation::Grant.new(subject.id, Naalp::Policy::NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "")
    obj = g.envelope_object(victim.id, 1, PROFILE, []) # claim victim as issuer...
    signed = Naalp::Delegation.sign_grant(obj, ALG, real.seed) # ...but sign with real's key
    err = assert_raises(StandardError) do
      Naalp::Delegation.verify_grant_object(PROFILE, ALG, real.pk, signed)
    end
    assert_equal "SignerMismatch", err.kind
  end

  # A baseline-only endpoint (no tier-1 kind) correctly rejects a DelegationGrant as UnknownKind.
  def test_baseline_verifier_rejects_grant_kind
    ml_dsa_or_skip
    issuer = key_for("base-issuer")
    subject = key_for("base-subject")
    g = Naalp::Delegation::Grant.new(subject.id, Naalp::Policy::NON_IDEMPOTENT_WRITE, 1, 0, 1_000_000, "")
    obj = g.envelope_object(issuer.id, 1, PROFILE, [])
    signed = Naalp::Delegation.sign_grant(obj, ALG, issuer.seed)
    baseline = lambda do |channel, kind|
      Naalp::Channels.lookup(channel, kind)
      true
    rescue Naalp::Channels::UnknownKind
      false
    end
    err = assert_raises(Naalp::Envelope::EnvelopeError) do
      Naalp::Envelope.verify(PROFILE, ALG, issuer.pk, baseline, signed)
    end
    assert_equal "UnknownKind", err.kind
  end

  def test_non_nfc_subject_rejected
    ml_dsa_or_skip
    issuer = key_for("nfc-issuer")
    non_nfc = "é" # 'é' as e + combining acute (NFD, not NFC)
    g = Naalp::Delegation::Grant.new(non_nfc, Naalp::Policy::READ_ONLY, 0, 0, 1, "")
    err = assert_raises(Naalp::Delegation::DelegationError) do
      g.envelope_object(issuer.id, 1, PROFILE, [])
    end
    assert_equal "NonNFC", err.kind
  end

  # ---- D4 two-gate composition with the single-use approval ledger (R-DEL-8) --------------

  def destructive_setup(tmpdir)
    bc = valid_2hop(Naalp::Policy::DESTRUCTIVE)
    ledger = Naalp::Approval.open_ledger(File.join(tmpdir, "consume.log"))
    approver = key_for("d4-approver")
    args_cid = content_id_of("the exact canonical action args")
    appr = Naalp::Approval::ApprovalRecord.new(args_cid, approver.id, Naalp::Policy::DESTRUCTIVE,
                                               "\x01\x02\x03\x04".b, 1_000_000)
    sig = Naalp::Approval.sign_approval(appr, ALG, approver.seed)
    [bc, ledger, approver, appr, sig, args_cid]
  end

  def test_composition_both_gates_authorize_and_consume
    ml_dsa_or_skip
    Dir.mktmpdir do |tmp|
      bc, ledger, approver, appr, sig, args_cid = destructive_setup(tmp)
      begin
        assert_nil Naalp::Delegation.authorize_destructive(
          bc[:action], bc[:grants], bc[:anchors], {}, 500,
          appr, ALG, approver.pk, sig, args_cid, ledger)
        assert ledger.consumed?(appr.id)
      ensure
        ledger.close
      end
    end
  end

  def test_composition_chain_without_approval_denies
    ml_dsa_or_skip
    Dir.mktmpdir do |tmp|
      bc, ledger, approver, appr, sig, _args_cid = destructive_setup(tmp)
      begin
        other = content_id_of("some other args the approval does not bind")
        err = assert_raises(Naalp::Delegation::DelegationError) do
          Naalp::Delegation.authorize_destructive(
            bc[:action], bc[:grants], bc[:anchors], {}, 500,
            appr, ALG, approver.pk, sig, other, ledger)
        end
        assert_equal "ApprovalRequired", err.kind
        assert_equal 0, ledger.count # fail-closed: no append on a rejected action
      ensure
        ledger.close
      end
    end
  end

  def test_composition_broken_chain_precedes_approval
    ml_dsa_or_skip
    Dir.mktmpdir do |tmp|
      bc, ledger, approver, appr, sig, args_cid = destructive_setup(tmp)
      begin
        err = assert_raises(Naalp::Delegation::DelegationError) do
          Naalp::Delegation.authorize_destructive(
            bc[:action], bc[:grants], Set.new, {}, 500, # no anchors -> untrusted root
            appr, ALG, approver.pk, sig, args_cid, ledger)
        end
        assert_equal "UntrustedChainRoot", err.kind # chain checked first
        assert_equal 0, ledger.count
      ensure
        ledger.close
      end
    end
  end

  def test_composition_approval_replay_rejected
    ml_dsa_or_skip
    Dir.mktmpdir do |tmp|
      bc, ledger, approver, appr, sig, args_cid = destructive_setup(tmp)
      begin
        Naalp::Delegation.authorize_destructive(
          bc[:action], bc[:grants], bc[:anchors], {}, 500,
          appr, ALG, approver.pk, sig, args_cid, ledger)
        err = assert_raises(Naalp::Delegation::DelegationError) do
          Naalp::Delegation.authorize_destructive(
            bc[:action], bc[:grants], bc[:anchors], {}, 500,
            appr, ALG, approver.pk, sig, args_cid, ledger)
        end
        assert_equal "AlreadyConsumed", err.kind # a spent approval is not fresh authority
        assert_equal 1, ledger.count
      ensure
        ledger.close
      end
    end
  end
end
