# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C21 portable gateway-decision object for the Ruby SDK (design.md §24; R-GW-1..6).
#
# A GatewayDecision is a SIGNED decision object an enforcement gateway of ANY vendor emits as
# PORTABLE EVIDENCE that it decided about an action. Its load-bearing property, exactly as the C18
# signed description, is that authority lives in the SIGNED BYTES, never in the connection or the
# host that served them: verify_decision takes NO serving-party/connection identity, so the same
# signed decision RE-VERIFIES IDENTICALLY when a party OTHER than the gateway serves it (the
# third-party re-serve property). It introduces NO new envelope, encoding, signature, identity, or
# audit mechanism: the object is an ordinary signed N-AALP body (COSE_Sign1), reusing the closed C5
# effect lattice and the T1 content-id framing unchanged. This is the EVIDENCE FORMAT ONLY -- never
# a policy language. Every check is fail-closed: a failing object is rejected whole, returns its
# named error, and causes no state change. An independent transcription of the design, graded
# against the shared vectors/gateway/cases.json.
#
# Also carries the evidence-record family (E6.3 egress-attestation + S1 decision-record + S3
# checkpoint + R1/R8 ordering-disclosure / foreign-profile-pin), ported from
# impl/go/gateway/{ordering,decision_record,checkpoint,egress_attestation}.go and mirroring
# impl/python/naalp/gateway.py; graded against the shared vectors/{decision_record,checkpoint,
# egress_attestation}/cases.json plus gateway/cases.json's optional_fields{} block.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'policy'

module Naalp
  module Gateway
    # The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    HEAD_SIZE = 48

    # The closed set a gateway may emit; a code outside the set is rejected (UnknownGatewayDecision).
    DECISION_ALLOW = 0 # the gateway allows the action
    DECISION_DENY  = 1 # the gateway denies the action
    DECISION_HOLD  = 2 # the gateway holds the action pending a further step

    # decision code -> name (diagnostics); an unknown code has no entry.
    DECISION_NAMES = { DECISION_ALLOW => "allow", DECISION_DENY => "deny", DECISION_HOLD => "hold" }.freeze

    # Named, fail-closed errors. #kind is a stable string mirroring the Go/Rust/Python error kinds.
    class GwMalformed < StandardError
      def kind; "GwMalformed"; end
    end
    class UnknownGatewayDecision < StandardError
      def kind; "UnknownGatewayDecision"; end
    end
    class BadSignature < StandardError
      def kind; "BadSignature"; end
    end
    class UnknownAlg < StandardError
      def kind; "UnknownAlg"; end
    end
    class ProfileDowngrade < StandardError
      def kind; "ProfileDowngrade"; end
    end
    class KeyAlgMismatch < StandardError
      def kind; "KeyAlgMismatch"; end
    end
    class DecisionMalformed < StandardError
      def kind; "DecisionMalformed"; end
    end
    class TermDispositionMalformed < StandardError
      def kind; "TermDispositionMalformed"; end
    end
    class UnknownOrderingBasis < StandardError
      def kind; "UnknownOrderingBasis"; end
    end
    class OrderingDisclosureMalformed < StandardError
      def kind; "OrderingDisclosureMalformed"; end
    end
    class CheckpointMalformed < StandardError
      def kind; "CheckpointMalformed"; end
    end
    class WitnessRootMismatch < StandardError
      def kind; "WitnessRootMismatch"; end
    end
    class InclusionProofInvalid < StandardError
      def kind; "InclusionProofInvalid"; end
    end
    class ForeignProfileMalformed < StandardError
      def kind; "ForeignProfileMalformed"; end
    end
    class EgMalformed < StandardError
      def kind; "EgMalformed"; end
    end
    class UnknownEgressBinding < StandardError
      def kind; "UnknownEgressBinding"; end
    end

    # Internal sentinel: the recursive inclusion-proof root recomputation ran out of path entries
    # (or had entries left over) before reaching the single-leaf base case. Always surfaced to
    # callers as InclusionProofInvalid -- never exported.
    class PathLengthMismatch < StandardError; end
    private_constant :PathLengthMismatch

    # A signed decision an enforcement gateway emits as portable evidence. decision is the
    # closed-set outcome; action is the content id of the action decided about; policy is the
    # opaque deciding-policy identity (a name, not a program); effect is the action's C5 class.
    # ordering (field 5, R1) and foreign_profile (field 6, R8) are OPTIONAL: nil reads exactly as
    # an absent field (correspondence-only ordering / no foreign-profile pin) -- never a stronger
    # claim inferred from silence.
    GatewayDecision = Struct.new(:decision, :action, :policy, :effect, :ordering, :foreign_profile) do
      def initialize(decision, action, policy, effect, ordering: nil, foreign_profile: nil)
        super(decision, action, policy, effect, ordering, foreign_profile)
      end

      # Deterministic-CBOR encoding {1: decision, 2: action, 3: policy, 4: effect, ?5: ordering,
      # ?6: foreign-profile}. Fields 5/6 are OMITTED entirely when nil (the same omit-when-absent
      # precedent as naalp-decision-record's optional fields 3/6/7).
      def bytes
        pairs = [
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(decision)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(action)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(policy)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::U.new(effect)],
        ]
        pairs << [Naalp::CBOR::U.new(5), ordering.to_cbor] unless ordering.nil?
        pairs << [Naalp::CBOR::U.new(6), foreign_profile.to_cbor] unless foreign_profile.nil?
        Naalp::CBOR.encode(Naalp::CBOR::M.new(pairs))
      end

      # The decision's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The decision's T1 content-id: multihash(0x20, 0x30 [48]) || SHA-384(body) (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end

      # The C5 effect class, normalized fail-closed: an unrecognized value is destructive (R-6.2).
      def effect_class
        Naalp::Policy.normalize_effect(effect)
      end
    end

    # A GatewayDecision that has passed signature verification. It carries NOTHING about who served
    # the bytes -- the authority is the signature, so the resolved evidence is identical regardless
    # of the serving party (the third-party re-serve property).
    ResolvedDecision = Struct.new(:decision, :action, :policy, :effect)

    module_function

    # Reports whether code is one of the closed decision codes.
    def known_decision?(code)
      DECISION_NAMES.key?(code)
    end

    # The decision name, or "unknown".
    def decision_name(code)
      DECISION_NAMES.fetch(code, "unknown")
    end

    # Returns the CBOR value for integer key k within a decoded map's pairs list, or nil if
    # absent. Mirrors the Go/Python embedded-field accessor field(m, k)/_mfield(pairs, k): a key
    # that is not a matching Naalp::CBOR::U simply does not match -- it never causes the whole map
    # to be rejected. Canonical decoding already forbids duplicate/out-of-order keys at every
    # nesting level (cbor.rb's strict decoder), so the first match is the only match.
    def mfield(pairs, k)
      pairs.each { |key, val| return val if key.is_a?(Naalp::CBOR::U) && key.v == k }
      nil
    end

    # Reconstruct a GatewayDecision from its body bytes alone. It does NOT validate the decision
    # code against the closed set, the ordering-disclosure's basis-conditioned well-formedness, or
    # the foreign-profile-pin's field well-formedness -- those are verify_decision's job (mirroring
    # the decision-record parse/validate split), so a decision carrying an unknown code, or an
    # ordering/foreign-profile that is structurally decodable but semantically malformed, can be
    # represented (and then rejected). It DOES enforce field-1-4 presence/type and, when field 5/6
    # is PRESENT, that it decodes to the expected CBOR shape: present-with-wrong-type fails here
    # (GwMalformed), never silently treated as absent. Fail-closed on any malformed shape: a
    # non-canonical body, a non-map, or an absent/wrong-typed field 1-4 is GwMalformed.
    def parse_decision(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise GwMalformed, "decision body is not well-formed deterministic CBOR"
      end
      raise GwMalformed, "decision body is not a map" unless v.is_a?(Naalp::CBOR::M)
      fields = {}
      v.pairs.each { |k, val| fields[k.v] = val if k.is_a?(Naalp::CBOR::U) }
      dec = fields[1]
      action = fields[2]
      pol = fields[3]
      eff = fields[4]
      unless dec.is_a?(Naalp::CBOR::U) && action.is_a?(Naalp::CBOR::B) &&
             pol.is_a?(Naalp::CBOR::B) && eff.is_a?(Naalp::CBOR::U)
        raise GwMalformed, "decision body missing or wrong-typed field 1-4"
      end
      gd = GatewayDecision.new(dec.v, action.v, pol.v, eff.v)
      ord_v = mfield(v.pairs, 5)
      unless ord_v.nil?
        ordering = ordering_from_cbor(ord_v)
        raise GwMalformed, "field 5 (ordering) is present but malformed" if ordering.nil?
        gd.ordering = ordering
      end
      fp_v = mfield(v.pairs, 6)
      unless fp_v.nil?
        fp = foreign_profile_from_cbor(fp_v)
        raise GwMalformed, "field 6 (foreign-profile) is present but malformed" if fp.nil?
        gd.foreign_profile = fp
      end
      gd
    end

    # The bare {1: alg} COSE_Sign1 protected header (§4), as the reference's cose.Sign1 emits.
    def gateway_protected_header(alg)
      Naalp::CBOR.encode(Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::N.new(alg)]]))
    end

    # Produce the tagged COSE_Sign1 object over the decision body, signed by the gateway.
    def sign_decision(d, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, gateway_protected_header(alg), d.bytes)
    end

    # Read the alg (label 1) value from an encoded protected header.
    def alg_from_protected(prot)
      v = Naalp::CBOR.decode(prot)
      raise GwMalformed, "protected header is not a map" unless v.is_a?(Naalp::CBOR::M)
      v.pairs.each do |k, val|
        if k.is_a?(Naalp::CBOR::U) && k.v == 1 && (val.is_a?(Naalp::CBOR::N) || val.is_a?(Naalp::CBOR::U))
          return val.v
        end
      end
      raise GwMalformed, "protected header has no alg"
    end

    # Verify a gateway decision end-to-end and return the resolved evidence. It (1) verifies the
    # signed object under the profile with real crypto (signature, alg registry, profile floor)
    # against the gateway's key; (2) reconstructs it from the signed bytes; (3) validates the
    # decision code against the closed set (UnknownGatewayDecision); (4) if field 5 (ordering) is
    # present, its basis-conditioned well-formedness (UnknownOrderingBasis /
    # OrderingDisclosureMalformed); and (5) if field 6 (foreign-profile) is present, its own
    # well-formedness (ForeignProfileMalformed). It takes NO serving-party or connection identity:
    # the authority is the signature over the bytes, so the same obj yields an identical
    # ResolvedDecision whether the gateway or an unrelated third party served it. Any failure
    # raises its named error and resolves nothing (fail-closed).
    def verify_decision(obj, profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise UnknownAlg, "unregistered alg #{halg}" unless known
      raise ProfileDowngrade, "signature level below the profile minimum" if level < Naalp::COSE.profile_min_level(profile)
      raise KeyAlgMismatch, "alg #{halg} does not match the verifier key alg #{alg}" if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      raise BadSignature, "signature does not verify" unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
      d = parse_decision(payload)
      raise UnknownGatewayDecision, "decision code #{d.decision} outside the closed set" unless known_decision?(d.decision)
      d.ordering.validate unless d.ordering.nil?
      d.foreign_profile.validate unless d.foreign_profile.nil?
      ResolvedDecision.new(d.decision, d.action.dup, d.policy.dup, Naalp::Policy.normalize_effect(d.effect))
    end

    # =================================================================================================
    # Evidence-record family (E6.3 egress-attestation + S1 decision-record + S3 checkpoint + R1/R8
    # ordering-disclosure / foreign-profile-pin), ported from impl/go/gateway/{ordering,
    # decision_record,checkpoint,egress_attestation}.go; graded against the shared
    # vectors/{decision_record,checkpoint,egress_attestation}/cases.json plus gateway/cases.json's
    # optional_fields{} block.
    # =================================================================================================

    # ---- ordering-disclosure embeddable group (design.md §26.3) ------------------------------------
    #
    # `ordering-disclosure` states what, if anything, establishes decision->effect / record->event
    # ORDER, and from which observational domain, rather than leaving the reader to assume more than
    # the bytes support. It is carried as a field inside naalp-decision-record (mandatory, field 5),
    # naalp-egress-attestation (optional, field 6), and naalp-gateway-decision (optional, field 5) --
    # never as a top-level object of its own, so it has no head/id of its own; it is embedded
    # directly as a nested CBOR map value inside its carrying record.
    #
    # correspondence-only (0) is the weakest claim and the value a verifier MUST read when the field
    # is ABSENT on an optional carrier -- never a stronger claim inferred from silence.
    # single-boundary (1) names one covering boundary. external-mechanism (2) names an external
    # sequencing mechanism and, optionally, the log relation binding the record under it.
    #
    # Well-formedness is fail-closed and NATIVE: correspondence-only requires keys 2/3/4 absent;
    # single-boundary requires key 2 present and 3/4 absent; external-mechanism requires key 3
    # present (4 optional) and key 2 absent. Any violation rejects the WHOLE carrying record
    # (OrderingDisclosureMalformed).

    ORDERING_CORRESPONDENCE_ONLY = 0 # the record orders only its own two-party construction (the weakest claim)
    ORDERING_SINGLE_BOUNDARY     = 1 # one boundary observed both terms and is named
    ORDERING_EXTERNAL_MECHANISM  = 2 # an external sequencing mechanism is named

    ORDERING_BASIS_NAMES = {
      ORDERING_CORRESPONDENCE_ONLY => "correspondence-only",
      ORDERING_SINGLE_BOUNDARY => "single-boundary",
      ORDERING_EXTERNAL_MECHANISM => "external-mechanism",
    }.freeze

    # Enforcement-disposition codes -- the closed set (design.md §26.4).
    ENFORCEMENT_ENFORCED = 1 # the producer states it actually enforces this outcome
    ENFORCEMENT_ADVISED  = 2 # the producer's own unverifiable self-account that it only advises

    # Term-disposition kind codes -- reused unchanged from the §2.5.4 producing-boundary kind
    # vocabulary.
    TERM_OBSERVED = 1 # the term was observed first-hand
    TERM_REPORTED = 2 # the term was reported, relayed from a named source

    # The embeddable group {1: basis, ?2: boundary, ?3: mechanism, ?4: relation} (design.md
    # §26.3). It is never a top-level signed object; it is always a field inside another record.
    # The zero value (basis=correspondence-only, no boundary/mechanism/relation) is the weakest
    # claim and is exactly what an ABSENT optional ordering-disclosure field reads as.
    OrderingDisclosure = Struct.new(:basis, :boundary, :mechanism, :relation) do
      def initialize(basis, boundary: "".b, mechanism: "".b, relation: "".b)
        super(basis, boundary || "".b, mechanism || "".b, relation || "".b)
      end

      # Returns self as a nested CBOR map VALUE (never top-level bytes -- self is always embedded
      # as a field inside its carrying record).
      def to_cbor
        pairs = [[Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(basis)]]
        pairs << [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(boundary)] unless boundary.empty?
        pairs << [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(mechanism)] unless mechanism.empty?
        pairs << [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(relation)] unless relation.empty?
        Naalp::CBOR::M.new(pairs)
      end

      # Checks (a) basis is in the closed set (UnknownOrderingBasis) and (b) the
      # basis-conditioned field well-formedness rule (design.md §26.3, native and fail-closed --
      # any violation rejects the whole carrying record, OrderingDisclosureMalformed).
      # UnknownOrderingBasis is checked and raised FIRST: an out-of-set basis is never
      # additionally reported as malformed.
      def validate
        unless Naalp::Gateway.known_ordering_basis?(basis)
          raise UnknownOrderingBasis, "ordering-disclosure basis is outside the closed set " \
            "correspondence-only/single-boundary/external-mechanism"
        end
        case basis
        when Naalp::Gateway::ORDERING_CORRESPONDENCE_ONLY
          unless boundary.empty? && mechanism.empty? && relation.empty?
            raise OrderingDisclosureMalformed, "correspondence-only requires keys 2/3/4 absent"
          end
        when Naalp::Gateway::ORDERING_SINGLE_BOUNDARY
          if boundary.empty? || !mechanism.empty? || !relation.empty?
            raise OrderingDisclosureMalformed, "single-boundary requires key 2 present, keys 3/4 absent"
          end
        when Naalp::Gateway::ORDERING_EXTERNAL_MECHANISM
          if !boundary.empty? || mechanism.empty?
            raise OrderingDisclosureMalformed, "external-mechanism requires key 2 absent, key 3 present"
          end
        end
      end
    end

    # The weakest ordering-disclosure claim, exactly what a verifier reads for an absent optional
    # ordering-disclosure field.
    def correspondence_only
      OrderingDisclosure.new(ORDERING_CORRESPONDENCE_ONLY)
    end

    # Reports whether code is one of the closed ordering-basis codes.
    def known_ordering_basis?(code)
      ORDERING_BASIS_NAMES.key?(code)
    end

    # The ordering-basis name, or "unknown".
    def ordering_basis_name(code)
      ORDERING_BASIS_NAMES.fetch(code, "unknown")
    end

    # Decode a nested ordering-disclosure map value. Returns nil on any wrong shape, including an
    # optional key present under the WRONG CBOR type (never silently treated as absent).
    def ordering_from_cbor(v)
      return nil unless v.is_a?(Naalp::CBOR::M)
      basis_v = mfield(v.pairs, 1)
      return nil unless basis_v.is_a?(Naalp::CBOR::U)
      boundary = mechanism = relation = "".b
      v2 = mfield(v.pairs, 2)
      unless v2.nil?
        return nil unless v2.is_a?(Naalp::CBOR::B)
        boundary = v2.v
      end
      v3 = mfield(v.pairs, 3)
      unless v3.nil?
        return nil unless v3.is_a?(Naalp::CBOR::B)
        mechanism = v3.v
      end
      v4 = mfield(v.pairs, 4)
      unless v4.nil?
        return nil unless v4.is_a?(Naalp::CBOR::B)
        relation = v4.v
      end
      OrderingDisclosure.new(basis_v.v, boundary: boundary, mechanism: mechanism, relation: relation)
    end

    # The embeddable group {1: kind, ?2: source} (design.md §26.4). `kind` is carried as a plain
    # uint on the wire (the CDDL does not close its value set the way ordering-basis does), so
    # TermDisposition itself validates no closed set -- only naalp-decision-record's own field-6
    # key set (the record's own field numbers) is fail-closed (TermDispositionMalformed).
    TermDisposition = Struct.new(:kind, :source) do
      def initialize(kind, source: "".b)
        super(kind, source || "".b)
      end

      def to_cbor
        pairs = [[Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(kind)]]
        pairs << [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(source)] unless source.empty?
        Naalp::CBOR::M.new(pairs)
      end
    end

    # Decode a nested term-disposition map value. Returns nil on any wrong shape.
    def term_disposition_from_cbor(v)
      return nil unless v.is_a?(Naalp::CBOR::M)
      kind_v = mfield(v.pairs, 1)
      return nil unless kind_v.is_a?(Naalp::CBOR::U)
      source = "".b
      v2 = mfield(v.pairs, 2)
      unless v2.nil?
        return nil unless v2.is_a?(Naalp::CBOR::B)
        source = v2.v
      end
      TermDisposition.new(kind_v.v, source: source)
    end

    # ---- ForeignProfilePin: GatewayDecision field 6, R8 --------------------------------------------

    # The embeddable group {1: id, 2: revision} (naalp-foreign-profile-pin, R8). Present on
    # GatewayDecision field 6 iff the decision was over foreign-protocol evidence: it pins the
    # foreign evidence profile's identifier (an absolute URI) AND the revision pinned at decision
    # time -- binding the reference, not just the class. Both fields are mandatory tstr; the group
    # carries no other keys. It is never a top-level signed object -- always embedded as field 6 of
    # its carrying naalp-gateway-decision, so it has no head/id of its own (mirroring
    # OrderingDisclosure).
    ForeignProfilePin = Struct.new(:id, :revision, :unknown_field) do
      def initialize(id = "", revision = "", unknown_field = false)
        super(id || "", revision || "", unknown_field)
      end

      # Returns self as a nested CBOR map VALUE {1: tstr(id), 2: tstr(revision)}.
      def to_cbor
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(id)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(revision)],
        ])
      end

      # Checks the foreign-profile-pin's own well-formedness (R8): both id and revision are
      # mandatory non-empty tstr, and no key besides 1/2 may be present. A missing, empty, or
      # extra field rejects the WHOLE carrying naalp-gateway-decision (ForeignProfileMalformed).
      def validate
        if id.empty? || revision.empty? || unknown_field
          raise ForeignProfileMalformed, "foreign-profile-pin is not well-formed (id and " \
            "revision are mandatory tstr, no other keys)"
        end
      end
    end

    # Decode a nested foreign-profile-pin map value. Decode is STRUCTURAL only, mirroring
    # ordering_from_cbor: a key present under the WRONG CBOR type fails decode (returns nil, never
    # silently treated as absent); a key that is simply ABSENT decodes to the empty string,
    # leaving the mandatory-presence check to validate (mirroring OrderingDisclosure's own
    # decode/validate split). A key besides 1/2 marks the group's unknown-field flag, also caught
    # by validate -- the closed 2-key set is enforced semantically, not by refusing to decode a
    # map that merely carries an extra key.
    def foreign_profile_from_cbor(v)
      return nil unless v.is_a?(Naalp::CBOR::M)
      id_ = ""
      v1 = mfield(v.pairs, 1)
      unless v1.nil?
        return nil unless v1.is_a?(Naalp::CBOR::T)
        id_ = v1.v
      end
      revision = ""
      v2 = mfield(v.pairs, 2)
      unless v2.nil?
        return nil unless v2.is_a?(Naalp::CBOR::T)
        revision = v2.v
      end
      unknown = v.pairs.any? { |k, _val| !(k.is_a?(Naalp::CBOR::U) && [1, 2].include?(k.v)) }
      ForeignProfilePin.new(id_, revision, unknown)
    end

    # ---- naalp-decision-record: S1, the full governed-decision accountability record --------------
    #
    # A DecisionRecord is the SIGNED record a governed decision point emits that it decided about an
    # action under a CLOSED, uniquely-selected condition set. It carries the T/T+n accountability
    # triple (§26.1): UNIQUE SELECTION (field 2, the governing set in the clear as content ids);
    # GOVERNED-AT-T (field 3, the naalp-consume-receipt spent at decision time); BINDING-FIXED-BY-T
    # (established off-record by inclusion under a witnessed naalp-checkpoint-root). The record is
    # deliberately CLOCK-FREE: it carries no claimed timestamp anywhere in its own body; both time
    # properties are POSITIONAL, never a self-asserted timestamp. It introduces no new envelope,
    # encoding, signature, or identity mechanism: an ordinary N-AALP signed body (COSE_Sign1),
    # reusing the closed gw-decision outcome vocabulary unchanged.
    #
    # Following parse_decision/verify_decision's split: parse_decision_record reconstructs the
    # record from its body bytes ALONE and performs only STRUCTURAL checks (field presence and CBOR
    # type); it does NOT validate the outcome against the closed gw-decision set, the ordering
    # disclosure's well-formedness, the deny/hold-with-consume rule, or the terms key set -- those
    # are validate_decision_record's job.

    # The governed-decision accountability record (design.md §26.4). `action` is the content id of
    # the action decided about; `governing` is the closed governing condition set, content ids, in
    # the clear (may be empty); `consume` is OPTIONAL field 3 (content id of the consume-receipt
    # spent at decision time; "" == absent); `outcome` is field 4 (allow/deny/hold, reuses the
    # closed gw-decision set); `ordering` is field 5, MANDATORY (no silent default -- every record
    # states its ordering basis); `terms` is OPTIONAL field 6 (per-term observed/reported, keyed by
    # this record's OWN field numbers 1..5; empty/nil == absent); `enforcement` is OPTIONAL field 7
    # (enforced(1)/advised(2); 0 == absent).
    DecisionRecord = Struct.new(:action, :governing, :consume, :outcome, :ordering, :terms, :enforcement) do
      def initialize(action, governing, outcome, ordering, consume: "".b, terms: nil, enforcement: 0)
        super(action, governing.map(&:dup), consume || "".b, outcome, ordering, terms ? terms.dup : {}, enforcement || 0)
      end

      # Deterministic-CBOR encoding {1:action, 2:governing[], ?3:consume, 4:outcome, 5:ordering,
      # ?6:terms, ?7:enforcement}. Fields 3/6/7 are OMITTED when absent (consume empty, terms
      # empty, enforcement zero) -- the omit-when-absent precedent (naalp-approval ?6:audience).
      def bytes
        pairs = [
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(action)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::A.new(governing.map { |g| Naalp::CBOR::B.new(g) })],
        ]
        pairs << [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(consume)] unless consume.empty?
        pairs << [Naalp::CBOR::U.new(4), Naalp::CBOR::U.new(outcome)]
        pairs << [Naalp::CBOR::U.new(5), ordering.to_cbor]
        unless terms.nil? || terms.empty?
          tm = terms.map { |k, td| [Naalp::CBOR::U.new(k), td.to_cbor] }
          pairs << [Naalp::CBOR::U.new(6), Naalp::CBOR::M.new(tm)]
        end
        pairs << [Naalp::CBOR::U.new(7), Naalp::CBOR::U.new(enforcement)] unless enforcement.zero?
        Naalp::CBOR.encode(Naalp::CBOR::M.new(pairs))
      end

      # The record's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The record's T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # Reconstruct a DecisionRecord from its body bytes alone. It performs ONLY structural checks
    # (mandatory-field presence and CBOR type); it does NOT validate the outcome against the
    # closed gw-decision set, the ordering disclosure's basis-conditioned well-formedness, the
    # deny/hold-with-consume rule, or the terms key set -- see validate_decision_record.
    # Fail-closed on any malformed shape (DecisionMalformed).
    def parse_decision_record(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise DecisionMalformed, "decision-record body is not well-formed deterministic CBOR"
      end
      raise DecisionMalformed, "decision-record body is not a map" unless v.is_a?(Naalp::CBOR::M)
      action = mfield(v.pairs, 1)
      gov_v = mfield(v.pairs, 2)
      unless action.is_a?(Naalp::CBOR::B) && gov_v.is_a?(Naalp::CBOR::A)
        raise DecisionMalformed, "missing or wrong-typed field 1/2"
      end
      governing = gov_v.items.map do |e|
        raise DecisionMalformed, "governing array element not a bstr" unless e.is_a?(Naalp::CBOR::B)
        e.v
      end
      consume = "".b
      consume_v = mfield(v.pairs, 3)
      unless consume_v.nil?
        raise DecisionMalformed, "field 3 (consume) wrong type" unless consume_v.is_a?(Naalp::CBOR::B)
        consume = consume_v.v
      end
      outcome_v = mfield(v.pairs, 4)
      raise DecisionMalformed, "missing or wrong-typed field 4 (outcome)" unless outcome_v.is_a?(Naalp::CBOR::U)
      ord_v = mfield(v.pairs, 5)
      raise DecisionMalformed, "missing mandatory field 5 (ordering)" if ord_v.nil?
      ordering = ordering_from_cbor(ord_v)
      raise DecisionMalformed, "field 5 (ordering) malformed" if ordering.nil?
      terms = {}
      terms_v = mfield(v.pairs, 6)
      unless terms_v.nil?
        raise DecisionMalformed, "field 6 (terms) wrong type" unless terms_v.is_a?(Naalp::CBOR::M)
        terms_v.pairs.each do |k, val|
          raise DecisionMalformed, "terms map key not a uint" unless k.is_a?(Naalp::CBOR::U)
          td = term_disposition_from_cbor(val)
          raise DecisionMalformed, "terms map value malformed" if td.nil?
          terms[k.v] = td
        end
      end
      enforcement = 0
      enf_v = mfield(v.pairs, 7)
      unless enf_v.nil?
        raise DecisionMalformed, "field 7 (enforcement) wrong type" unless enf_v.is_a?(Naalp::CBOR::U)
        enforcement = enf_v.v
      end
      DecisionRecord.new(action.v, governing, outcome_v.v, ordering, consume: consume, terms: terms, enforcement: enforcement)
    end

    # Reports whether k is one of the record's own field numbers 1..5 -- the only valid keys for
    # the field-6 terms map (design.md §26.4; TermDispositionMalformed otherwise).
    def valid_decision_record_term_key?(k)
      k >= 1 && k <= 5
    end

    # Performs the semantic, closed-set, and native well-formedness checks parse_decision_record
    # deliberately does not (mirroring verify_decision's parse/validate split):
    #
    # 1. Outcome must be in the closed gw-decision set (UnknownGatewayDecision).
    # 2. Ordering must satisfy its basis-conditioned well-formedness rule (UnknownOrderingBasis /
    #    OrderingDisclosureMalformed) -- checked BEFORE the deny/hold-consume rule so a record
    #    whose ordering is itself malformed is never additionally reported as a consume violation.
    # 3. A deny/hold outcome carrying a field-3 consume reference is rejected in full
    #    (DecisionMalformed) -- nothing was consumed, so a value here would assert authority spent
    #    for an action the record's own outcome says was not taken.
    # 4. Every terms map key must be one of the record's own field numbers 1..5
    #    (TermDispositionMalformed).
    def validate_decision_record(d)
      raise UnknownGatewayDecision, "decision-record outcome #{d.outcome} outside the closed set" unless known_decision?(d.outcome)
      d.ordering.validate
      if d.outcome != DECISION_ALLOW && !d.consume.empty?
        raise DecisionMalformed, "a deny/hold outcome must not carry a field-3 consume reference"
      end
      d.terms.each_key do |k|
        raise TermDispositionMalformed, "a terms map key is outside the record's own field set 1..5" unless valid_decision_record_term_key?(k)
      end
    end

    # Produce the tagged COSE_Sign1 object over the record body, signed by the governed decision
    # point.
    def sign_decision_record(d, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, gateway_protected_header(alg), d.bytes)
    end

    # A DecisionRecord that has passed signature verification and full semantic validation.
    ResolvedDecisionRecord = Struct.new(:action, :governing, :consume, :outcome, :ordering, :terms, :enforcement)

    # Verify a decision record end-to-end: (1) the signed object under the profile with real
    # crypto; (2) structural reconstruction (parse_decision_record); and (3) full semantic
    # validation (validate_decision_record). It takes no serving-party or connection identity --
    # the authority is the signature over the bytes, mirroring verify_decision. Any failure raises
    # its named error and resolves nothing (fail-closed).
    def verify_decision_record(obj, profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise UnknownAlg, "unregistered alg #{halg}" unless known
      raise ProfileDowngrade, "signature level below the profile minimum" if level < Naalp::COSE.profile_min_level(profile)
      raise KeyAlgMismatch, "alg #{halg} does not match the verifier key alg #{alg}" if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      raise BadSignature, "signature does not verify" unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
      d = parse_decision_record(payload)
      validate_decision_record(d)
      ResolvedDecisionRecord.new(d.action.dup, d.governing.map(&:dup), d.consume.dup, d.outcome, d.ordering, d.terms.dup, d.enforcement)
    end

    # ---- naalp-checkpoint-root / naalp-witness-cosign / naalp-inclusion-proof: S3 ------------------
    #
    # S3 is the neither-party anchor for the BINDING-FIXED-BY-T leg of the accountability triple
    # (design.md §26.5). Tree construction follows RFC 9162
    # (https://www.rfc-editor.org/rfc/rfc9162.html) §2.1 EXACTLY, SHA-384-profiled: leaf hash =
    # HASH(0x00 || leaf); interior node hash = HASH(0x01 || left || right); MTH({}) = HASH() (the
    # empty hash); MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for
    # the largest power of two k < n. §2.1.2's PATH(m, D[n]) recursion (leaf-to-root sibling order)
    # generates the audit path; §2.1.3.1's inverse recursion recomputes the root from (leaf, index,
    # size, path) and compares against the named root (InclusionProofInvalid on mismatch,
    # fail-closed).
    #
    # naalp-checkpoint-root is a log operator's signed Merkle tree head over a leaf set of record
    # content ids, chaining by `prev` (genesis = HEAD_SIZE zero bytes). naalp-witness-cosign carries
    # the wire hook for an independent countersignature over one exact checkpoint by content id;
    # naalp-inclusion-proof proves one record's content id was a leaf under a named checkpoint. Two
    # witness-cosigned roots at one (log, size) carrying different root values are fork evidence.

    # A log operator's signed Merkle tree head over a leaf set of record content ids (design.md
    # §26.5).
    CheckpointRoot = Struct.new(:log, :size, :root, :prev, :at) do
      # Deterministic-CBOR encoding {1:log, 2:size, 3:root, 4:prev, 5:at}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(log)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(size)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(root)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(prev)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::U.new(at)],
        ]))
      end

      # The checkpoint's SHA-384 head (48 octets) -- the `prev` the NEXT checkpoint chains from.
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The checkpoint's T1 content-id (50 octets) -- what an inclusion proof's `root` field and a
      # witness-cosign's `root` field both name.
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # The HEAD_SIZE all-zero prev value a log's first checkpoint chains from.
    def genesis_prev
      ("\x00" * HEAD_SIZE).b
    end

    # Reconstruct a CheckpointRoot from its body bytes alone. Fail-closed on any malformed shape
    # (CheckpointMalformed): every one of the five fields is mandatory.
    def parse_checkpoint_root(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise CheckpointMalformed, "checkpoint-root body is not well-formed deterministic CBOR"
      end
      raise CheckpointMalformed, "checkpoint-root body is not a map" unless v.is_a?(Naalp::CBOR::M)
      log = mfield(v.pairs, 1)
      size = mfield(v.pairs, 2)
      root = mfield(v.pairs, 3)
      prev = mfield(v.pairs, 4)
      at = mfield(v.pairs, 5)
      unless log.is_a?(Naalp::CBOR::B) && size.is_a?(Naalp::CBOR::U) && root.is_a?(Naalp::CBOR::B) &&
             prev.is_a?(Naalp::CBOR::B) && at.is_a?(Naalp::CBOR::U)
        raise CheckpointMalformed, "missing or wrong-typed field 1-5"
      end
      CheckpointRoot.new(log.v, size.v, root.v, prev.v, at.v)
    end

    # Produce the tagged COSE_Sign1 object over the checkpoint body, signed by the log operator.
    def sign_checkpoint_root(c, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, gateway_protected_header(alg), c.bytes)
    end

    # A witness's countersignature over one exact checkpoint by content id (design.md §26.5).
    # Whether the witness's observational domain is genuinely distinct from both parties to the
    # decisions the checkpoint covers is a structural deployment fact checkable in substance at
    # T+n -- the wire supplies the hook; it does not manufacture the independence itself.
    WitnessCosign = Struct.new(:witness, :root, :at) do
      # Deterministic-CBOR encoding {1:witness, 2:root, 3:at}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(witness)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(root)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(at)],
        ]))
      end

      # The cosign's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The cosign's T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # Reconstruct a WitnessCosign from its body bytes alone. Fail-closed on any malformed shape:
    # every one of the three fields is mandatory.
    def parse_witness_cosign(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise CheckpointMalformed, "witness-cosign body is not well-formed deterministic CBOR"
      end
      raise CheckpointMalformed, "witness-cosign body is not a map" unless v.is_a?(Naalp::CBOR::M)
      witness = mfield(v.pairs, 1)
      root = mfield(v.pairs, 2)
      at = mfield(v.pairs, 3)
      unless witness.is_a?(Naalp::CBOR::B) && root.is_a?(Naalp::CBOR::B) && at.is_a?(Naalp::CBOR::U)
        raise CheckpointMalformed, "missing or wrong-typed field 1-3"
      end
      WitnessCosign.new(witness.v, root.v, at.v)
    end

    # Produce the tagged COSE_Sign1 object over the cosign body, signed by the witness.
    def sign_witness_cosign(w, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, gateway_protected_header(alg), w.bytes)
    end

    # Checks that w names the EXACT checkpoint it accompanies (WitnessRootMismatch, design.md
    # §26.5): w.root must equal accompanied_checkpoint_id, the content id of the
    # naalp-checkpoint-root object w claims to cosign. Fail-closed.
    def validate_witness_cosign(w, accompanied_checkpoint_id)
      unless w.root == accompanied_checkpoint_id
        raise WitnessRootMismatch, "witness-cosign names a root content id that does not match the checkpoint it accompanies"
      end
    end

    # Proves one record's content id existed as a leaf under a named checkpoint (design.md §26.5,
    # RFC 9162 §2.1.3.1).
    InclusionProof = Struct.new(:root, :leaf, :index, :path) do
      # Deterministic-CBOR encoding {1:root, 2:leaf, 3:index, 4:path[]}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(root)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(leaf)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(index)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::A.new(path.map { |p| Naalp::CBOR::B.new(p) })],
        ]))
      end

      # The proof's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The proof's T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # Reconstruct an InclusionProof from its body bytes alone. Fail-closed on any malformed shape:
    # every one of the four fields is mandatory.
    def parse_inclusion_proof(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise CheckpointMalformed, "inclusion-proof body is not well-formed deterministic CBOR"
      end
      raise CheckpointMalformed, "inclusion-proof body is not a map" unless v.is_a?(Naalp::CBOR::M)
      root = mfield(v.pairs, 1)
      leaf = mfield(v.pairs, 2)
      index = mfield(v.pairs, 3)
      path_v = mfield(v.pairs, 4)
      unless root.is_a?(Naalp::CBOR::B) && leaf.is_a?(Naalp::CBOR::B) && index.is_a?(Naalp::CBOR::U) && path_v.is_a?(Naalp::CBOR::A)
        raise CheckpointMalformed, "missing or wrong-typed field 1-4"
      end
      path = path_v.items.map do |e|
        raise CheckpointMalformed, "path array element not a bstr" unless e.is_a?(Naalp::CBOR::B)
        e.v
      end
      InclusionProof.new(root.v, leaf.v, index.v, path)
    end

    # ---- RFC 9162 §2.1 Merkle tree math (SHA-384-profiled) -----------------------------------------

    # leaf_hash = HASH(0x00 || leaf) (RFC 9162 §2.1's LEAF_HASH, leaf/interior domain separation).
    def leaf_hash(leaf)
      OpenSSL::Digest::SHA384.digest("\x00".b + leaf)
    end

    # node_hash = HASH(0x01 || left || right) (RFC 9162 §2.1's NODE_HASH).
    def node_hash(l, r)
      OpenSSL::Digest::SHA384.digest("\x01".b + l + r)
    end

    # The largest power of two strictly less than n (n > 1), per RFC 9162 §2.1's k = "the largest
    # power of two smaller than n".
    def largest_power_of_two_less_than(n)
      k = 1
      k *= 2 while 2 * k < n
      k
    end

    # Computes MTH(leaves) per RFC 9162 §2.1: MTH({}) = HASH() (SHA-384 of the empty string);
    # MTH({d0}) = LEAF_HASH(d0); MTH(D[n]) = NODE_HASH(MTH(D[0:k]), MTH(D[k:n])) for the largest
    # power of two k < n. leaves are raw leaf VALUES (record content ids); LEAF_HASH is applied
    # internally -- callers never hash a leaf before calling merkle_root. `leaves=nil` is accepted
    # as the empty list (mirroring Go's nil-slice-len-0 semantics for MerkleRoot(nil)).
    def merkle_root(leaves)
      n = leaves.nil? ? 0 : leaves.length
      return OpenSSL::Digest::SHA384.digest("".b) if n == 0 # MTH({}) = HASH(""), the empty-list base case
      return leaf_hash(leaves[0]) if n == 1
      k = largest_power_of_two_less_than(n)
      node_hash(merkle_root(leaves[0...k]), merkle_root(leaves[k..-1]))
    end

    # Computes the RFC 9162 §2.1.2 PATH(index, leaves) audit path (leaf-to-root sibling order --
    # the list's FIRST entry is the leaf's immediate sibling, the LAST is closest to the root,
    # exactly the order naalp-inclusion-proof's `path` field carries).
    def generate_inclusion_proof_path(leaves, index)
      raise InclusionProofInvalid, "leaf index out of range" if index < 0 || index >= leaves.length
      gen_path(leaves, index)
    end

    def gen_path(leaves, index)
      n = leaves.length
      return [] if n <= 1 # PATH(0, {d0}) = {} -- the single-leaf base case
      k = largest_power_of_two_less_than(n)
      if index < k
        gen_path(leaves[0...k], index) + [merkle_root(leaves[k..-1])]
      else
        gen_path(leaves[k..-1], index - k) + [merkle_root(leaves[0...k])]
      end
    end

    # The exact structural inverse of gen_path: at each level it consumes the LAST remaining path
    # entry (closest to the root) as this level's sibling and recurses into the appropriate half
    # with the entries that remain.
    def recompute_root(leaf_h, index, size, path)
      if size == 1
        raise PathLengthMismatch unless path.empty?
        return leaf_h
      end
      raise PathLengthMismatch if path.empty?
      k = largest_power_of_two_less_than(size)
      last = path[-1]
      rest = path[0...-1]
      if index < k
        node_hash(recompute_root(leaf_h, index, k, rest), last)
      else
        node_hash(last, recompute_root(leaf_h, index - k, size - k, rest))
      end
    end

    # Recomputes the audit path bottom-up (RFC 9162 §2.1.3.1, the inverse of PATH()) from (leaf,
    # index, size, path) and compares the result against root. `size` is the tree size the proof
    # is checked against -- the resolved naalp-checkpoint-root's own `size` field, NOT carried
    # inside naalp-inclusion-proof itself (the proof names the checkpoint by content id; the
    # verifier is expected to already hold the resolved checkpoint to learn its size). Fail-closed:
    # any mismatch, out-of-range index, or path-length mismatch is InclusionProofInvalid.
    def verify_inclusion_proof(leaf, index, size, path, root)
      raise InclusionProofInvalid, "index out of range for the claimed tree size" if size == 0 || index >= size
      begin
        got = recompute_root(leaf_hash(leaf), index, size, path.dup)
      rescue PathLengthMismatch
        raise InclusionProofInvalid, "inclusion path length does not match the claimed tree size"
      end
      raise InclusionProofInvalid, "inclusion audit path does not recompute to the named root" unless got == root
    end

    # ---- naalp-egress-attestation: E6.3 --------------------------------------------------------------
    #
    # A naalp-egress-attestation is a SIGNED attestation a gateway/sidecar emits that an object of a
    # given effect class, bound to a given audience, crossed an egress boundary at a given time --
    # third-party verifiable WITHOUT the payload. It is a near-clone of GatewayDecision: the gateway
    # is the SIGNER, and verify_egress_attestation takes NO serving-party or connection identity --
    # the authority is the signature over the bytes, so the identical attested evidence re-verifies
    # whether the gateway or an unrelated third party serves it. `binding` is a closed set
    # (content_bound/content_free); `digest` is either the T1 content-id of the crossed object
    # (content_bound) or a hiding commitment SHA-384(content_id||salt) (content_free) -- never
    # both; `effect` is the C5 effect class of the crossed object; `audience` is the bound
    # destination (empty-permitted); `at` is the crossing time in epoch milliseconds. Field 6
    # (`ordering`) is OPTIONAL: ABSENT reads correspondence-only, never a stronger claim inferred
    # from silence.
    #
    # The content_free binding lets a gateway attest an egress crossing WITHOUT disclosing which
    # object crossed. egress_commit/open_egress_commitment is the open/verify pair: the gateway (or
    # anyone it later discloses content-id+salt to) can PROVE which object a content_free
    # attestation names, without the attestation bytes themselves ever carrying the content-id.

    BINDING_CONTENT_BOUND = 0 # digest is the crossed object's T1 content-id
    BINDING_CONTENT_FREE  = 1 # digest is a hiding commitment SHA-384(content_id||salt)

    BINDING_NAMES = { BINDING_CONTENT_BOUND => "content_bound", BINDING_CONTENT_FREE => "content_free" }.freeze

    # Reports whether code is one of the closed binding codes.
    def known_binding?(code)
      BINDING_NAMES.key?(code)
    end

    # The binding name, or "unknown".
    def binding_name(code)
      BINDING_NAMES.fetch(code, "unknown")
    end

    # A signed attestation a gateway/sidecar emits that an object crossed an egress boundary.
    # `binding` selects how `digest` is interpreted (content_bound: the crossed object's T1
    # content-id; content_free: a hiding commitment). `effect` is the crossed object's C5 effect
    # class. `audience` is the bound destination (empty-permitted). `at` is the crossing time,
    # epoch ms. `ordering` is the OPTIONAL field 6: nil == ABSENT (reads correspondence-only).
    EgressAttestation = Struct.new(:binding, :digest, :effect, :audience, :at, :ordering) do
      def initialize(binding, digest, effect, audience, at, ordering: nil)
        super(binding, digest, effect, audience, at, ordering)
      end

      # Deterministic-CBOR encoding {1:binding, 2:digest, 3:effect, 4:audience, 5:at, ?6:ordering}.
      # Field 6 is OMITTED when `ordering` is nil.
      def bytes
        pairs = [
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(binding)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(digest)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(effect)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(audience)],
          [Naalp::CBOR::U.new(5), Naalp::CBOR::U.new(at)],
        ]
        pairs << [Naalp::CBOR::U.new(6), ordering.to_cbor] unless ordering.nil?
        Naalp::CBOR.encode(Naalp::CBOR::M.new(pairs))
      end

      # The attestation's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The attestation's T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end

      # The attestation's C5 effect class, normalized fail-closed: a value the evaluator does not
      # recognize is treated as destructive, never as a weaker class.
      def effect_class
        Naalp::Policy.normalize_effect(effect)
      end
    end

    # Reconstruct an EgressAttestation from its body bytes alone. It does NOT validate the binding
    # code against the closed set -- that is verify_egress_attestation's job -- so an attestation
    # carrying an unknown binding can be represented (and then rejected). Fail-closed on a
    # malformed shape: every one of the five mandatory fields is required, and a
    # present-but-wrong-typed field 6 fails here too.
    def parse_egress_attestation(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise EgMalformed, "egress-attestation body is not well-formed deterministic CBOR"
      end
      raise EgMalformed, "egress-attestation body is not a map" unless v.is_a?(Naalp::CBOR::M)
      binding = mfield(v.pairs, 1)
      digest = mfield(v.pairs, 2)
      effect = mfield(v.pairs, 3)
      audience = mfield(v.pairs, 4)
      at = mfield(v.pairs, 5)
      unless binding.is_a?(Naalp::CBOR::U) && digest.is_a?(Naalp::CBOR::B) && effect.is_a?(Naalp::CBOR::U) &&
             audience.is_a?(Naalp::CBOR::B) && at.is_a?(Naalp::CBOR::U)
        raise EgMalformed, "missing or wrong-typed field 1-5"
      end
      ordering = nil
      ord_v = mfield(v.pairs, 6)
      unless ord_v.nil?
        ordering = ordering_from_cbor(ord_v)
        raise EgMalformed, "field 6 (ordering) is present but malformed" if ordering.nil?
      end
      EgressAttestation.new(binding.v, digest.v, effect.v, audience.v, at.v, ordering: ordering)
    end

    # Produce the tagged COSE_Sign1 object over the attestation body, signed by the gateway.
    def sign_egress_attestation(a, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, gateway_protected_header(alg), a.bytes)
    end

    # An EgressAttestation that has passed signature verification. It carries NOTHING about WHO
    # served the bytes -- the authority is the signature, so the resolved evidence is identical
    # regardless of the serving party (the third-party re-serve property).
    ResolvedEgressAttestation = Struct.new(:binding, :digest, :effect, :audience, :at, :ordering)

    # Performs the semantic, closed-set checks parse_egress_attestation deliberately does not
    # (mirroring gateway's Parse/Verify split): the binding must be in the closed set
    # (UnknownEgressBinding), and -- if present -- the field-6 ordering disclosure must satisfy
    # its basis-conditioned well-formedness rule (UnknownOrderingBasis/OrderingDisclosureMalformed).
    def validate_egress_attestation(a)
      raise UnknownEgressBinding, "egress attestation binding code is outside the closed set content_bound/content_free" unless known_binding?(a.binding)
      a.ordering.validate unless a.ordering.nil?
    end

    # Verifies an egress attestation end-to-end and returns the resolved evidence. It (1) verifies
    # the signed object under the profile with real crypto against the GATEWAY's key; (2)
    # reconstructs it from the signed bytes; and (3) validates the binding code against the closed
    # set (UnknownEgressBinding), and the ordering disclosure if present. It takes NO serving-party
    # or connection identity: the authority is the signature over the bytes, so the same `obj`
    # yields an identical ResolvedEgressAttestation whether the gateway or an unrelated third party
    # served it (the third-party re-serve property). Any failure raises its named error and
    # resolves nothing (fail-closed).
    def verify_egress_attestation(obj, profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise UnknownAlg, "unregistered alg #{halg}" unless known
      raise ProfileDowngrade, "signature level below the profile minimum" if level < Naalp::COSE.profile_min_level(profile)
      raise KeyAlgMismatch, "alg #{halg} does not match the verifier key alg #{alg}" if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      raise BadSignature, "signature does not verify" unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
      a = parse_egress_attestation(payload)
      validate_egress_attestation(a)
      ResolvedEgressAttestation.new(a.binding, a.digest.dup, Naalp::Policy.normalize_effect(a.effect), a.audience.dup, a.at, a.ordering)
    end

    # ---- content_free commitment open/verify pair --------------------------------------------------

    # The content_free hiding commitment over an object's T1 content-id and a salt:
    # SHA-384(object_cid || salt) (48 octets). The commitment reveals nothing about object_cid
    # without the salt; a gateway builds it once to populate a content_free attestation's `digest`
    # field, and retains object_cid+salt to later prove which object crossed via
    # open_egress_commitment.
    def egress_commit(object_cid, salt)
      OpenSSL::Digest::SHA384.digest(object_cid + salt)
    end

    # Proves which object crossed under a content_free attestation. It recomputes
    # egress_commit(object_cid, salt) and compares it, in constant time, against `a.digest`.
    # Returns true iff `a` is a content_free attestation AND the recomputed commitment matches: a
    # wrong salt or a wrong object_cid both fail to open (return false), and a content_bound
    # attestation never opens (its digest is not a commitment).
    def open_egress_commitment(a, object_cid, salt)
      return false if a.binding != BINDING_CONTENT_FREE
      want = egress_commit(object_cid, salt)
      return false if want.bytesize != a.digest.bytesize
      OpenSSL.fixed_length_secure_compare(want, a.digest)
    end
  end
end
