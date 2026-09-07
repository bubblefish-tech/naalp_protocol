# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# The N-AALP error object and the numeric error-code registry for the Ruby SDK (design.md §3.5,
# R3.3/R3.4, T3.3). The naalp-error object is the Control/Error body (channel 0x0000, kind 3, effect
# read_only) that carries one fail-closed rejection reason as {1:code, 2:name, ?3:detail,
# ?4:subject}. The registry is the ordered 129-entry name<->code table below (the code for NAMES[i]
# is i+1; 0 is reserved). NAMES is the single source the machine-readable registry
# (vectors/registry/error-codes.csv) and the CDDL naalp-error-code enum are generated to match, and
# scripts/registry_drift.py asserts the three agree; the table itself is graded against the
# non-circular oracle by the error.name_for_code conformance op.
#
# Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a registered
# code whose name disagrees with the registry is rejected Malformed (the code is authoritative -- the
# strengthening direction); a code outside the registry is opaque and non-fatal (the name is
# diagnostic only), so a receiver interoperates with a peer emitting a later-registered code.
#
# Ported from impl/go/naalperror/naalperror.go (copied verbatim), cross-read against the
# byte-identical impl/rust/src/naalperror.rs and impl/typescript/naalp/naalperror.mjs.
require_relative 'cbor'

module Naalp
  module Naalperror
    # STANDARDS_MAX is the top of the RFC-Required standards range; codes >= 0x8000 are private-use.
    STANDARDS_MAX = 0x7FFF

    # NAMES is the ordered error-code registry: the code for NAMES[i] is i+1 (0 is reserved and MUST
    # NOT appear on the wire). Order is the fields-of-record authority for every code (§3.5). Copied
    # verbatim from impl/go/naalperror/naalperror.go Names.
    NAMES = [
      "NonCanonical", "DepthExceeded", "Malformed", "ContentIdMismatch", "HeaderBodyMismatch",
      "UnsupportedVersion", "UnknownCriticalExt", "UnknownKind", "RangeError", "NonNFC",
      "WrongAudience", "TooLarge", "TooManyCauses", "TooManyExtensions", "TooManyChunks",
      "UnknownAlg", "KeyAlgMismatch", "ProfileDowngrade", "HybridIncomplete", "SuiteMismatch",
      "CompositeRefused", "BadSignature", "SignerMismatch", "RotationUnauthorized", "KeyRevoked",
      "EffectNotAuthorized", "UnauthenticatedPrincipal", "MalformedSafetyLabel", "ApprovalRequired",
      "ApprovalMismatch", "ApprovalExpired", "AlreadyConsumed", "ConsumeFork", "ConsumeForkInvalid",
      "ConsumeReceiptUnsigned", "LedgerCorrupt", "LedgerUnsigned", "AudienceMismatch",
      "FreshnessSelfAsserted", "UnknownRefusalOutcome", "RefusalDetailLeak", "ChainBroken",
      "Equivocation", "CausalViolation", "ReceiptUnsigned", "ForkProofInvalid", "StageOutOfOrder",
      "StreamDigestMismatch", "StreamStateError", "ConfidentialTransportRequired", "PeerUnauthenticated",
      "NotDelivered", "MappingError", "EffectDeclarationMismatch", "StateTransitionError",
      "CapExceedsParent", "TransformCycle", "InputGateBypass", "TaskStateError", "ScopeOverlapConflict",
      "ReconcileMismatch", "WrongFlow", "SeqGap", "AboveCeiling", "GapDetected", "CommitMismatch",
      "ContMalformed", "GrantExpired", "GrantNotYetValid", "GrantRevoked", "UntrustedChainRoot",
      "DelegationDepthExceeded", "GrantMalformed", "NameMalformed", "NameChainBroken",
      "NameForkProofInvalid", "IllegalTransition", "TaskChainBroken", "ForeignCard", "DescMalformed",
      "MalformedApprovalFlag", "DirForkProofInvalid", "ImporterMismatch", "UnknownDescriptionFormat",
      "VerifierKeyMismatch", "NegMalformed", "UnknownRole", "UnknownProfile", "NotDescended",
      "NotOffer", "NotAccept", "MalformedCriticalFlag", "UnknownCriticalRisk", "ReferenceMismatch",
      "MalformedAnnotation", "EffectUnderDeclared", "EffectOutsideLattice", "ToolCallMalformed",
      "PayMalformed", "UnknownPaymentFormat", "GwMalformed", "UnknownGatewayDecision", "UIMalformed",
      "UIChainBroken", "UnknownUIEventKind", "ActionSubstituted", "UINoConsent", "StaleEpoch",
      "Unauthorized", "OwnerImmutable", "MemberExists", "MemberUnknown", "OwnerExists", "RoleInvalid",
      "RoomOpMismatch", "OpUnknown", "PrincipalUnknown", "PrincipalExists", "RebindUnauthorized",
      # Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
      "EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
      "TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed", "HazardMalformed", "HazardNotCovered", "HazardUnknown",
    ].freeze

    CODE_BY_NAME = NAMES.each_with_index.each_with_object({}) { |(n, i), h| h[n] = i + 1 }.freeze

    # A named, fail-closed naalp-error decode error; #kind is the stable error kind mirroring
    # impl/go (reuses cose.ErrMalformed), impl/rust (cose::Error{kind:"Malformed"}), and
    # impl/typescript (NaalperrorError). Decode has exactly one reject kind: "Malformed".
    class Error < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # A decoded naalp-error body. #detail is "" if field 3 was absent; #subject is nil if field 4 was
    # absent.
    Object = Struct.new(:code, :name, :detail, :subject)

    module_function

    # name_for_code returns [name, registered] for a code: registered=true with the registered name
    # for 1 <= code <= 129, else registered=false with name="". A code of 0, or any value past the
    # registered range, is unregistered (opaque per the open-registry rule).
    def name_for_code(code)
      c = code.to_i
      return [NAMES[c - 1], true] if c >= 1 && c <= NAMES.length
      ["", false]
    end

    # code_for_name returns [code, registered] for a name: registered=true with the registered code
    # when the name is in the registry, else registered=false with code=0.
    def code_for_name(name)
      c = CODE_BY_NAME[name]
      return [c, true] unless c.nil?
      [0, false]
    end

    # encode returns the deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body
    # {1:code, 2:name, ?3:detail, ?4:subject}. detail=="" (or nil) omits field 3; subject==nil omits
    # field 4. The integer keys 1..4 are already in canonical ascending order.
    def encode(code, name, detail = "", subject = nil)
      pairs = [
        [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(code)],
        [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(name)],
      ]
      pairs << [Naalp::CBOR::U.new(3), Naalp::CBOR::T.new(detail)] if detail && !detail.empty?
      pairs << [Naalp::CBOR::U.new(4), Naalp::CBOR::B.new(subject)] unless subject.nil?
      Naalp::CBOR.encode(Naalp::CBOR::M.new(pairs))
    end

    # decode parses a naalp-error body and enforces the dual-carriage rules. A structurally malformed
    # body (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name) is
    # rejected Malformed. A registered code whose name disagrees with the registry is rejected
    # Malformed (the code is authoritative). An unregistered code is accepted opaque (name diagnostic
    # only).
    def decode(data)
      begin
        v = Naalp::CBOR.decode(data)
      rescue Naalp::CBOR::NonCanonical, Naalp::CBOR::DepthExceeded => e
        raise Error.new("Malformed", "naalp-error body is not well-formed deterministic CBOR: #{e}")
      end
      raise Error.new("Malformed", "naalp-error body is not a map") unless v.is_a?(Naalp::CBOR::M)

      code = nil
      name = nil
      detail = ""
      subject = nil
      have_code = false
      have_name = false

      v.pairs.each do |k, val|
        raise Error.new("Malformed", "non-uint naalp-error key") unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          raise Error.new("Malformed", "code not a uint") unless val.is_a?(Naalp::CBOR::U)
          code = val.v
          have_code = true
        when 2
          raise Error.new("Malformed", "name not a tstr") unless val.is_a?(Naalp::CBOR::T)
          name = val.v
          have_name = true
        when 3
          raise Error.new("Malformed", "detail not a tstr") unless val.is_a?(Naalp::CBOR::T)
          detail = val.v
        when 4
          raise Error.new("Malformed", "subject not a bstr") unless val.is_a?(Naalp::CBOR::B)
          subject = val.v
        else
          raise Error.new("Malformed", "unknown naalp-error field #{k.v}") # closed grammar
        end
      end

      raise Error.new("Malformed", "naalp-error body missing code or name") unless have_code && have_name

      reg_name, registered = name_for_code(code)
      if registered && reg_name != name
        raise Error.new("Malformed", "registered code disagrees with the registry name")
      end

      Object.new(code, name, detail, subject)
    end
  end
end
