# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C20 governed negotiation, advisory risk labels, and trust references for the Ruby SDK
# (design.md §23; R-NEG-1..6, R-RISK-1..6, R-TRUST-1..4).
#
# C20 adds three signed surfaces carried on N-AALP's own signed object. It introduces NO new envelope,
# encoding, signature, identity, or audit mechanism (R-11.3): each object is an ordinary signed N-AALP
# body (COSE_Sign1, §4), reusing the closed C5 effect lattice (Naalp::Policy), the T1 content-id
# framing (§2.3), and the §8.2 causal partial order (the `causes` field) UNCHANGED.
#
#   - Governed negotiation: a Message {1:negotiation, 2:role, 3:profile, 4:causes[]} is one signed step
#     -- an OFFER, a COUNTER, or an ACCEPT -- causally linked to its predecessor(s) by content-id,
#     SELECTING a profile from a CLOSED pre-registered set (no free-form/runtime capability, §23.9). An
#     ACCEPT MUST DESCEND from its offer by walking the causes DAG (verify_accept), else it is rejected
#     (NotDescended). An unknown profile/role is rejected.
#   - Advisory risk labels: a RiskLabel {1:code, 2:critical} + a LabeledObject {1:effect, 2:labels[]}.
#     The R-2.5 critical-extension rule applies (an unknown CRITICAL label is rejected, an unknown
#     non-critical one is ignored). LOAD-BEARING invariant: carrying a risk label NEVER changes an
#     object's effect class -- effect_class derives from the effect field ALONE (Naalp::Policy).
#   - Trust references: a TrustRef {1:registry, 2:reference, 3:subject} carries a third-party trust
#     statement as a CHECKABLE signed object -- verify_trust_ref recomputes the referenced content-id
#     over the external record. NO wire field weighs it: there is no score/rank/ordering and no scoring
#     function, by design (§23.7).
#
# Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
# causes no state change. An independent transcription of the design (cross-read against
# impl/go/negotiation and impl/python/naalp/negotiation.py), graded against the shared
# vectors/negotiation/cases.json. The Message/LabeledObject/TrustRef signatures are real deterministic
# ML-DSA-65 (COSE_Sign1), NOT corpus-graded.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'policy'

module Naalp
  module Negotiation
    # The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    HEAD_SIZE = 48

    # A named, fail-closed C20 error; #kind is the stable error kind (§15), mirroring the Go/Rust kinds.
    class NegotiationError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # ==== governed negotiation ===================================================================

    # Negotiation message roles (the closed set); a role outside it is rejected (UnknownRole).
    ROLE_OFFER = 0   # the initiating offer (root of a negotiation; no causes)
    ROLE_COUNTER = 1 # a counter-offer chaining onto the offer or a prior counter
    ROLE_ACCEPT = 2  # the accept; it MUST descend from its offer

    ROLE_NAMES = { ROLE_OFFER => "offer", ROLE_COUNTER => "counter", ROLE_ACCEPT => "accept" }.freeze

    # Pre-registered negotiation profiles (the closed set); a profile outside it is rejected
    # (UnknownProfile). A negotiation SELECTS a pre-registered profile; it never carries a free-form
    # capability string or a runtime-generated handler.
    PROFILE_BASELINE = 0  # the baseline capability profile
    PROFILE_STREAMING = 1 # the native-streaming capability profile (C9)
    PROFILE_BATCH = 2     # the batched-delivery capability profile

    PROFILE_NAMES = { PROFILE_BASELINE => "baseline", PROFILE_STREAMING => "streaming", PROFILE_BATCH => "batch" }.freeze

    # One signed step of a governed negotiation: an offer, a counter, or an accept. It is causally
    # linked to its predecessor(s) by content-id in causes (empty for an offer) and SELECTS a
    # pre-registered profile.
    Message = Struct.new(:negotiation, :role, :profile, :causes) do
      # Deterministic-CBOR encoding {1: negotiation, 2: role, 3: profile, 4: causes[]}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(negotiation)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(role)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::U.new(profile)],
          [Naalp::CBOR::U.new(4), Naalp::CBOR::A.new((causes || []).map { |c| Naalp::CBOR::B.new(c) })],
        ]))
      end

      # The Message's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The Message's T1 content-id (50 octets) -- the id a successor names in its causes.
      def id
        Naalp::CBOR.content_id(bytes)
      end
    end

    # ==== advisory risk labels ===================================================================

    # A risk label's advisory class in the vocabulary (a REGISTRY attribute of the code, distinct from
    # the per-carriage critical flag).
    CLASS_INFORMING = 0 # purely informational
    CLASS_GATING = 1    # a policy MAY require an additional gate when this label is present

    RISK_CLASS_NAMES = { CLASS_INFORMING => "informing", CLASS_GATING => "gating" }.freeze

    # The closed standard risk-label vocabulary.
    RISK_SENSITIVE = 1  # gating: the object touches sensitive material
    RISK_EGRESS = 2     # gating: the object causes data egress
    RISK_REVERSIBLE = 3 # informing: the object's effect is reversible

    # The first code of the private/experimental extensible range: a code at or above it is unknown to
    # a verifier that lacks it (carried critical -> rejected R-2.5; carried non-critical -> ignored).
    EXTENSIBLE_RANGE_START = 0x1000

    # code -> class for the closed standard vocabulary (the authority the registry is cross-checked
    # against; Go == Rust == Python == oracle).
    RISK_VOCAB = { RISK_SENSITIVE => CLASS_GATING, RISK_EGRESS => CLASS_GATING, RISK_REVERSIBLE => CLASS_INFORMING }.freeze

    # One advisory risk label carried on an object. code is the label code; critical is the
    # per-carriage must-understand flag (uint 1/0 -- the spine carries no CBOR boolean).
    RiskLabel = Struct.new(:code, :critical) do
      # Whether the label is carried critical (must-understand).
      def critical?
        critical == 1
      end

      # The label's CBOR map value {1: code, 2: critical}.
      def to_map
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(code)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(critical)],
        ])
      end

      # Deterministic-CBOR encoding of the risk-label body.
      def bytes
        Naalp::CBOR.encode(to_map)
      end
    end

    # A minimal N-AALP object carrying an effect (field 1, C5) and a set of advisory risk labels. It
    # exists to demonstrate -- provably, in isolation -- the load-bearing invariant that carrying a
    # risk label NEVER changes the object's effect class.
    LabeledObject = Struct.new(:effect, :labels) do
      # Deterministic-CBOR encoding {1: effect, 2: labels[]}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(effect)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::A.new((labels || []).map(&:to_map))],
        ]))
      end

      # The LabeledObject's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The LabeledObject's T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end

      # The object's C5 effect class, derived from the effect field ALONE and normalized fail-closed
      # (unknown -> destructive, R-6.2). It DELIBERATELY does not consult the risk labels: a risk label
      # is an advisory dimension, never a fifth effect, so the closed lattice is untouched by any label
      # the object carries. This is the load-bearing C20 invariant.
      def effect_class
        Naalp::Policy.normalize_effect(effect)
      end

      # Apply the critical-extension rule to the object's carried labels.
      def validate_labels
        Naalp::Negotiation.validate_labels(labels || [])
      end
    end

    # ==== trust references (checkable, never weighed) ============================================

    # A third-party trust statement carried as a CHECKABLE signed object. registry is an opaque
    # external-registry identifier (an ERC-8004-style reputation/identity registry -- a name, not a URL
    # the wire resolves); reference is the T1 content-id of the referenced external record; subject is
    # the opaque id the statement is about. The wire CARRIES the reference; NO field here weighs it.
    TrustRef = Struct.new(:registry, :reference, :subject) do
      # Deterministic-CBOR encoding {1: registry, 2: reference, 3: subject}.
      def bytes
        Naalp::CBOR.encode(Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::B.new(registry)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::B.new(reference)],
          [Naalp::CBOR::U.new(3), Naalp::CBOR::B.new(subject)],
        ]))
      end

      # The TrustRef's SHA-384 head (48 octets).
      def head
        OpenSSL::Digest::SHA384.digest(bytes)
      end

      # The TrustRef's own T1 content-id (50 octets).
      def id
        Naalp::CBOR.content_id(bytes)
      end

      # The content-id the trust ref binds (the carried external-record reference).
      def reference_id
        reference.dup
      end

      # Whether the carried reference is the T1 content-id of record -- i.e. the reference recomputes
      # over the presented external bytes. This is the CHECK a relying party runs; it computes NO
      # score. A changed record yields a different content-id, so binds_record returns false.
      def binds_record(record)
        reference == Naalp::CBOR.content_id(record.dup.force_encoding(Encoding::BINARY))
      end
    end

    # A TrustRef that has passed signature verification and (given the external record) the content-id
    # recompute. It carries NO score, rank, or trust weight.
    ResolvedTrustRef = Struct.new(:registry, :reference, :subject)

    module_function

    # ---- role / profile vocabulary ----

    # Whether r is one of the three defined negotiation roles.
    def known_role?(r)
      ROLE_NAMES.key?(r)
    end

    # The role name, or "unknown" for an out-of-range code.
    def role_name(r)
      ROLE_NAMES.fetch(r, "unknown")
    end

    # Whether p is one of the pre-registered profiles (the closed set).
    def registered_profile?(p)
      PROFILE_NAMES.key?(p)
    end

    # The profile name, or "unknown" for an unregistered code.
    def profile_name(p)
      PROFILE_NAMES.fetch(p, "unknown")
    end

    # ---- message constructors ----

    # Build an offer (the root of a negotiation): role offer, no causes.
    def new_offer(negotiation, profile)
      Message.new(negotiation, ROLE_OFFER, profile, [])
    end

    # Build a counter chaining onto the predecessor named by predecessor_id.
    def new_counter(negotiation, profile, predecessor_id)
      Message.new(negotiation, ROLE_COUNTER, profile, [predecessor_id])
    end

    # Build an accept chaining onto the predecessor named by predecessor_id (must descend from its
    # offer, checked by verify_accept).
    def new_accept(negotiation, profile, predecessor_id)
      Message.new(negotiation, ROLE_ACCEPT, profile, [predecessor_id])
    end

    # Reconstruct a Message from its body bytes alone. It does NOT validate the role or profile against
    # the closed sets -- that is verify_message's job -- so a message carrying an unknown role or
    # profile can be represented (and then rejected). Fail-closed (NegMalformed) on any malformed
    # shape, a non-canonical body, or a mistyped field.
    def parse_message(b)
      m = decode_map(b)
      raise NegotiationError.new("NegMalformed", "object is not a well-formed negotiation body") if m.nil?
      neg = bstr_field(m, 1)
      role = uint_field(m, 2)
      prof = uint_field(m, 3)
      causes_v = field(m, 4)
      if neg.nil? || role.nil? || prof.nil? || causes_v.nil? || !causes_v.is_a?(Naalp::CBOR::A)
        raise NegotiationError.new("NegMalformed", "object is not a well-formed negotiation body")
      end
      causes = causes_v.items.map do |e|
        raise NegotiationError.new("NegMalformed", "cause is not a bstr") unless e.is_a?(Naalp::CBOR::B)
        e.v
      end
      Message.new(neg, role, prof, causes)
    end

    # ---- causal descent ----

    # Build the content-id -> Message index the descent walk resolves predecessors through. The key is
    # the binary string form of the T1 content-id (Message#id).
    def index_by_id(msgs)
      idx = {}
      msgs.each { |m| idx[m.id] = m }
      idx
    end

    # Whether from_msg reaches target_id by following causes edges resolved through by_id: a real
    # reachability walk over the causal DAG. A cause that cannot be resolved through by_id cannot extend
    # the chain through it, so a forged causes pointer to an id the verifier never saw does not
    # manufacture descent. Fail-closed.
    def descends(from_msg, target_id, by_id)
      target = target_id.dup.force_encoding(Encoding::BINARY)
      seen = {}
      stack = (from_msg.causes || []).dup
      until stack.empty?
        cid = stack.pop
        return true if cid == target
        next if seen[cid]
        seen[cid] = true
        pred = by_id[cid]
        next if pred.nil? # an unresolved cause: the chain cannot be walked through it
        stack.concat(pred.causes || [])
      end
      false
    end

    # Whether accept descends from offer by walking the causes DAG through by_id (a counter or a chain
    # of counters between them is traversed). Performs no signature check.
    def descends_msg(accept, offer, by_id)
      descends(accept, offer.id, by_id)
    end

    # Check an accept against its offer over a set of verified messages, fail-closed. It requires offer
    # to be a genuine offer selecting a pre-registered profile (NotOffer / UnknownProfile), accept to
    # be an accept selecting a pre-registered profile (NotAccept / UnknownProfile), and the accept to
    # DESCEND from the offer (NotDescended otherwise). Returns the AGREED profile. It authorizes
    # nothing; it accepts or rejects.
    def verify_accept(accept, offer, by_id)
      raise NegotiationError.new("NotOffer", "the object presented as the offer is not an offer role") if offer.role != ROLE_OFFER
      raise NegotiationError.new("UnknownProfile", "offer selects a profile outside the closed set") unless registered_profile?(offer.profile)
      raise NegotiationError.new("NotAccept", "the object presented as the accept is not an accept role") if accept.role != ROLE_ACCEPT
      raise NegotiationError.new("UnknownProfile", "accept selects a profile outside the closed set") unless registered_profile?(accept.profile)
      raise NegotiationError.new("NotDescended", "accept does not descend from its offer along the causes chain") unless descends_msg(accept, offer, by_id)
      accept.profile
    end

    # ---- risk-label vocabulary ----

    # The class name ("gating"/"informing"), or "" for an out-of-range value.
    def risk_class_name(c)
      RISK_CLASS_NAMES.fetch(c, "")
    end

    # A code's vocabulary class and whether the code is a registered standard label. Returns
    # [class, known].
    def risk_class_of(code)
      RISK_VOCAB.key?(code) ? [RISK_VOCAB[code], true] : [CLASS_INFORMING, false]
    end

    # Whether code is in the closed standard vocabulary.
    def registered_risk?(code)
      RISK_VOCAB.key?(code)
    end

    # Whether code lies in the private/experimental extensible range.
    def in_extensible_range?(code)
      code >= EXTENSIBLE_RANGE_START
    end

    # Parse one risk-label map, rejecting a malformed shape (NegMalformed) or a critical flag outside
    # {0,1} (MalformedCriticalFlag). Fail-closed.
    def risk_label_from_value(v)
      raise NegotiationError.new("NegMalformed", "risk label is not a map") unless v.is_a?(Naalp::CBOR::M)
      code = uint_field(v, 1)
      crit = uint_field(v, 2)
      raise NegotiationError.new("NegMalformed", "risk label missing a field") if code.nil? || crit.nil?
      raise NegotiationError.new("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}") if crit > 1
      RiskLabel.new(code, crit)
    end

    # Apply the critical-extension rule (R-2.5) to a set of carried risk labels: return the RECOGNIZED
    # (standard-vocabulary) labels, DROP unknown non-critical labels, and REJECT an unknown CRITICAL
    # label (UnknownCriticalRisk). A critical flag outside {0,1} is MalformedCriticalFlag. It NEVER
    # inspects or returns an effect -- risk labels are an advisory dimension, never a fifth effect.
    # Fail-closed.
    def validate_labels(labels)
      recognized = []
      labels.each do |l|
        raise NegotiationError.new("MalformedCriticalFlag", "risk-label critical flag is outside {0,1}") if l.critical > 1
        if registered_risk?(l.code)
          recognized << l
          next
        end
        raise NegotiationError.new("UnknownCriticalRisk", "an unknown critical risk label is rejected (R-2.5)") if l.critical?
        # unknown non-critical: ignored (dropped from the recognized set)
      end
      recognized
    end

    # Reconstruct a LabeledObject from its body bytes alone. Fail-closed (NegMalformed) on a malformed
    # shape; a critical flag outside {0,1} is MalformedCriticalFlag.
    def parse_labeled_object(b)
      m = decode_map(b)
      raise NegotiationError.new("NegMalformed", "object is not a well-formed labeled-object body") if m.nil?
      eff = uint_field(m, 1)
      labels_v = field(m, 2)
      if eff.nil? || labels_v.nil? || !labels_v.is_a?(Naalp::CBOR::A)
        raise NegotiationError.new("NegMalformed", "object is not a well-formed labeled-object body")
      end
      labels = labels_v.items.map { |e| risk_label_from_value(e) }
      LabeledObject.new(eff, labels)
    end

    # ---- trust references ----

    # Reconstruct a TrustRef from its body bytes alone. Fail-closed (NegMalformed).
    def parse_trust_ref(b)
      m = decode_map(b)
      raise NegotiationError.new("NegMalformed", "object is not a well-formed trust-ref body") if m.nil?
      reg = bstr_field(m, 1)
      ref = bstr_field(m, 2)
      subj = bstr_field(m, 3)
      if reg.nil? || ref.nil? || subj.nil?
        raise NegotiationError.new("NegMalformed", "object is not a well-formed trust-ref body")
      end
      TrustRef.new(reg, ref, subj)
    end

    # ---- signatures (real deterministic ML-DSA COSE_Sign1, demonstrated in isolation) ----

    # The COSE protected header {1: alg} as deterministic CBOR (alg is a negative int).
    def protected_header(alg)
      Naalp::CBOR.encode(Naalp::CBOR::M.new([[Naalp::CBOR::U.new(1), Naalp::CBOR::N.new(alg)]]))
    end

    # The tagged COSE_Sign1 over the Message body (real deterministic ML-DSA).
    def sign_message(m, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), m.bytes)
    end

    # The tagged COSE_Sign1 over the LabeledObject body.
    def sign_labeled_object(o, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), o.bytes)
    end

    # The tagged COSE_Sign1 over the TrustRef body.
    def sign_trust_ref(r, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), r.bytes)
    end

    # Verify a tagged COSE_Sign1 object's full signature and return its signed payload bytes.
    # Fail-closed (BadSignature).
    def verify_body(obj, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      raise NegotiationError.new("BadSignature", "signature does not verify") unless Naalp::COSE.cose_verify1_raw(alg, pubkey, tbs, sig)
      payload
    end

    # Verify the Message's full signature, reconstruct it from the signed body bytes, and validate it
    # against the closed sets: the role MUST be offer/counter/accept (UnknownRole) and the selected
    # profile MUST be pre-registered (UnknownProfile). Fail-closed.
    def verify_message(obj, _profile, alg, pubkey)
      payload = verify_body(obj, alg, pubkey)
      msg = parse_message(payload)
      raise NegotiationError.new("UnknownRole", "negotiation message role is not offer/counter/accept") unless known_role?(msg.role)
      raise NegotiationError.new("UnknownProfile", "negotiation selects a profile outside the closed set") unless registered_profile?(msg.profile)
      msg
    end

    # Verify the signature, reconstruct the object, and apply the critical-extension rule to its labels
    # (an unknown critical label is rejected). Returns [object, recognized_labels]. The returned
    # object's effect_class is unchanged by any label. Fail-closed.
    def verify_labeled_object(obj, _profile, alg, pubkey)
      payload = verify_body(obj, alg, pubkey)
      o = parse_labeled_object(payload)
      recognized = validate_labels(o.labels)
      [o, recognized]
    end

    # Verify a trust reference end-to-end: (1) verify the signed object with real crypto
    # (BadSignature); (2) reconstruct it from the signed bytes; and (3) confirm the reference by
    # RECOMPUTING the external record's content-id and requiring it to equal the carried reference
    # (ReferenceMismatch otherwise). Returns the resolved reference -- and NOTHING that scores it: this
    # module has no trust-weighting function, by design. Fail-closed.
    def verify_trust_ref(obj, _profile, alg, pubkey, external_record)
      payload = verify_body(obj, alg, pubkey)
      r = parse_trust_ref(payload)
      raise NegotiationError.new("ReferenceMismatch", "trust-ref reference does not recompute over the record") unless r.binds_record(external_record)
      ResolvedTrustRef.new(r.registry, r.reference, r.subject)
    end

    # ---- small deterministic-CBOR field accessors ----

    # Strict-canonical decode to a CBOR map, or nil on any decode error / non-map (a non-canonical body
    # decodes to nil -> NegMalformed at the call site).
    def decode_map(b)
      v = begin
        Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        return nil
      end
      v.is_a?(Naalp::CBOR::M) ? v : nil
    end

    def field(m, k)
      m.pairs.each { |key, val| return val if key.is_a?(Naalp::CBOR::U) && key.v == k }
      nil
    end

    def bstr_field(m, k)
      v = field(m, k)
      v.is_a?(Naalp::CBOR::B) ? v.v : nil
    end

    def uint_field(m, k)
      v = field(m, k)
      v.is_a?(Naalp::CBOR::U) ? v.v : nil
    end
  end
end
