# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C5 effect vocabulary and authorization for the Ruby SDK (§6).
#
# The closed four-value effect set aligned 1:1 with the N-PAMP Bridge SafetyLabel; an
# unrecognized value fails closed to destructive (R-6.2); authorization is the §6.1 lattice
# (action <= ceiling). N-PAMP states the label "describes intent and does not replace
# authorization"; ResolveAuthPrincipal + Grant#authorize_object close that hole (§6.3): only a
# signature-derived identity is an authorization principal (R-6.5), and a Grant authorizes an
# object iff the presenter's resolved identity matches the grant's principal AND the object's
# effect does not exceed the grant's ceiling. The optional signed safety label is a CBOR map
# {1:risk, 2:scope} (R-6.4); a malformed label is rejected whole, never silently accepted.
require_relative 'cbor'

module Naalp
  module Policy
    READ_ONLY = 0
    IDEMPOTENT_WRITE = 1
    NON_IDEMPOTENT_WRITE = 2
    DESTRUCTIVE = 3

    NAMES = ["read_only", "idempotent_write", "non_idempotent_write", "destructive"].freeze

    # A named, fail-closed policy error; #kind is the stable error kind mirroring Go/Rust/Python
    # (design §6, §15): UnauthenticatedPrincipal, EffectNotAuthorized, MalformedSafetyLabel.
    class PolicyError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    # PrincipalSource is where a claimed identity came from. Only a signature-derived identity
    # is an authorization principal (R-6.5).
    SOURCE_SIGNATURE = 0          # the verified COSE signature's signer id
    SOURCE_TRANSPORT_METADATA = 1 # e.g. a TLS peer name / connection tag
    SOURCE_FOREIGN_HEADER = 2     # e.g. an X-Agent-ID or a carried foreign header
    SOURCE_CLIENT_NAME = 3        # e.g. a self-asserted clientInfo.name

    # The non-critical ext key under which the optional safety label is carried (ext[1],
    # design.md §6.4).
    SAFETY_LABEL_EXT_KEY = 1

    # SafetyLabel is the OPTIONAL signed safety annotation (R-6.4). It is attributable to the
    # object's signer and auditable. It is an ACCOUNTABLE CLAIM, not a guarantee the content is
    # safe (design.md §6.4).
    class SafetyLabel
      attr_reader :risk, :scope

      def initialize(risk, scope)
        @risk = risk.to_s
        @scope = scope.to_s
      end

      # The deterministic-CBOR map {1: risk, 2: scope}.
      def to_value
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(@risk)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::T.new(@scope)],
        ])
      end

      # The deterministic-CBOR bytes of the safety-label map.
      def encode
        Naalp::CBOR.encode(to_value)
      end

      # An ext map carrying only this safety label, ready to place in an object's field 11 (or
      # merge into an existing ext map).
      def ext
        Naalp::CBOR::M.new([[Naalp::CBOR::U.new(SAFETY_LABEL_EXT_KEY), to_value]])
      end

      def ==(other)
        other.is_a?(SafetyLabel) && other.risk == risk && other.scope == scope
      end
      alias eql? ==

      def hash
        [risk, scope].hash
      end
    end

    # Grant is a capability an endpoint issues to an authenticated signer id: the most dangerous
    # effect that principal is permitted to carry. The default max_effect (READ_ONLY) is the
    # least-privilege default, so a bare Grant authorizes only read_only.
    class Grant
      attr_reader :principal, :max_effect

      def initialize(principal, max_effect = READ_ONLY)
        @principal = principal.to_s
        @max_effect = max_effect
      end

      # AuthorizeObject is the endpoint policy check that makes the effect an authorization
      # input, not a hint (R-6.3). It (1) resolves the presenter's identity, refusing any
      # non-signature source (R-6.5); (2) requires that identity to match the grant's principal
      # -- no matching grant means no authority; (3) normalizes the object's effect fail-closed
      # (R-6.2) and denies it if it exceeds the grant's ceiling. It performs no side effect and
      # raises a named PolicyError on any failure (fail-closed).
      def authorize_object(src, presented, object_effect)
        who = Policy.resolve_auth_principal(src, presented)
        if who != @principal
          raise PolicyError.new("EffectNotAuthorized", "object effect exceeds the granted capability")
        end
        unless Policy.authorizes(@max_effect, Policy.normalize_effect(object_effect))
          raise PolicyError.new("EffectNotAuthorized", "object effect exceeds the granted capability")
        end
        nil
      end
    end

    module_function

    # Map a raw effect value to the closed set; anything outside 0..3 is destructive (R-6.2).
    def normalize_effect(v)
      (v >= 0 && v <= 3) ? v : DESTRUCTIVE
    end

    def safety_label_name(e)
      NAMES[normalize_effect(e)]
    end

    # The §6.1 lattice: an action of class `action` is permitted under `ceiling` iff action <= ceiling.
    def authorizes(ceiling, action)
      action <= ceiling
    end

    # ResolveAuthPrincipal returns the authorization principal id iff it is signature-derived and
    # non-empty (R-6.5). A transport-metadata, foreign-header, or client-supplied name is refused
    # with UnauthenticatedPrincipal -- it is never treated as an authorization identity.
    def resolve_auth_principal(src, id)
      if src != SOURCE_SIGNATURE || id.nil? || id.empty?
        raise PolicyError.new("UnauthenticatedPrincipal",
          "an authorization identity must be signature-derived, not transport/foreign/client-asserted")
      end
      id
    end

    # The signed safety-label body {1: risk, 2: scope} (R-6.4).
    def safety_label_bytes(risk, scope)
      SafetyLabel.new(risk, scope).encode
    end

    # SafetyLabelFromExt extracts the optional safety label from an object's ext map. Returns
    # [label, true] when a well-formed label is present, [nil, false] when absent (including a
    # nil ext), and raises PolicyError("MalformedSafetyLabel") when the ext[1] entry is present
    # but not exactly {1:tstr, 2:tstr} -- a malformed label is rejected, never silently accepted.
    def safety_label_from_ext(ext)
      return [nil, false] if ext.nil?
      ext.pairs.each do |k, v|
        next unless k.is_a?(Naalp::CBOR::U) && k.v == SAFETY_LABEL_EXT_KEY
        unless v.is_a?(Naalp::CBOR::M)
          raise PolicyError.new("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
        end
        risk = nil
        scope = nil
        have_risk = false
        have_scope = false
        v.pairs.each do |kk, vv|
          unless kk.is_a?(Naalp::CBOR::U) && vv.is_a?(Naalp::CBOR::T)
            raise PolicyError.new("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
          end
          case kk.v
          when 1
            risk = vv.v
            have_risk = true
          when 2
            scope = vv.v
            have_scope = true
          else
            raise PolicyError.new("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
          end
        end
        unless have_risk && have_scope
          raise PolicyError.new("MalformedSafetyLabel", "safety label is not {1:tstr risk, 2:tstr scope}")
        end
        return [SafetyLabel.new(risk, scope), true]
      end
      [nil, false]
    end
  end
end
