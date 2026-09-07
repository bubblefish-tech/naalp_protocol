# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Manufacturing Add-ons Component F, the physical-hazard authorization extension (design.md
# addendum; requirements F1-F5; wire authority `spec/naalp-draft-01.cddl`), Ruby port of
# impl/rust/naalp-hazard/src/lib.rs (mirroring
# impl/csharp/Hazard.cs and impl/java/.../Hazard.java).
#
# `effect` (Envelope field 7, Naalp::Policy) describes DATA reversibility. `hazard` is a new,
# ORTHOGONAL dimension describing PHYSICAL danger: a data-reversible action may still be a high
# physical hazard. The two dimensions are never merged and neither derives the other.
#
# This module adds no new cryptography and no new CBOR codec of its own: every encode call
# delegates to Naalp::CBOR.encode / Naalp::CBOR.content_id, exactly as the Rust reference crate
# adds no crypto/encoding of its own over the graded `naalp` core.
#
# The fail-closed rules (F2, F3):
# - .from_code is the ONE fail-closed decode entry point: any missing or out-of-range raw value
#   normalizes to MOTION_IN_SHARED_SPACE -- the highest class -- never to "absent" or any weaker
#   class.
# - .hazard_authorized requires an EXACT class match (not a <= ceiling the way the effect
#   lattice's Naalp::Policy.authorizes works) AND full containment of the claim's envelope inside
#   the grant's on every axis, the speed bound, and the time window. Any single failing dimension
#   denies the WHOLE claim -- there is no partial authorization.
# - .hazard_authorized_optional additionally covers the case where an action carries NO hazard
#   claim at all: there is no envelope to check containment against, so it denies immediately with
#   a distinct error (HazardUnknown) rather than fabricating a sentinel envelope and running the
#   ordinary coverage check.
require_relative 'cbor'
require_relative 'identity'

module Naalp
  module Hazard
    # ---- errors ---------------------------------------------------------------------------

    # (HazardMalformed) a hazard-claim/hazard-authorization/envelope body is not the CDDL shape
    # (spec/naalp-draft-01.cddl), a spatial-bounds axis has min > max, axes is empty, or frame is
    # not Unicode NFC.
    class HazardMalformed < StandardError
      def kind; "HazardMalformed"; end
    end

    # (HazardNotCovered) a well-formed claim's class or envelope is not fully covered by the
    # presented authorization.
    class HazardNotCovered < StandardError
      def kind; "HazardNotCovered"; end
    end

    # (HazardUnknown) the hazard value for an action requiring one is unrecognized or absent, and
    # -- for the fully-absent case -- no envelope exists to check coverage against at all.
    class HazardUnknown < StandardError
      def kind; "HazardUnknown"; end
    end

    def self.malformed_error
      HazardMalformed.new("hazard body is not the spec/naalp-draft-01.cddl shape, or an axis/frame is invalid")
    end

    def self.not_covered_error
      HazardNotCovered.new("declared hazard class or envelope is not fully covered by the authorization")
    end

    def self.unknown_error
      HazardUnknown.new("hazard value unrecognized or absent; no claim to check coverage against")
    end

    # ---- hazard-class (F2: closed, fail-closed to the highest class) ----------------------

    # The closed five-value hazard-class vocabulary (spec/naalp-draft-01.cddl). MOTION_IN_SHARED_SPACE
    # is BOTH a named class (4) and the fail-closed default for an unrecognized or absent raw value
    # (F2) -- the assumption that "the producer did not tell us" is at least as dangerous as the
    # worst named class.
    NONE = 0
    TOOL_ACTUATION = 1
    THERMAL = 2
    ENERGY_RELEASE = 3
    MOTION_IN_SHARED_SPACE = 4

    CLASS_NAMES = {
      NONE => "none",
      TOOL_ACTUATION => "tool_actuation",
      THERMAL => "thermal",
      ENERGY_RELEASE => "energy_release",
      MOTION_IN_SHARED_SPACE => "motion_in_shared_space",
    }.freeze

    module_function

    # Fail-closed decode (F2). `nil` (the raw value was absent) or any value outside 0..4
    # (unrecognized) normalizes to MOTION_IN_SHARED_SPACE -- never to a weaker class, and never a
    # decode failure (there is no "invalid hazard" outcome; there is only "the worst case we must
    # assume"). Accepts an arbitrary-magnitude non-negative Integer (or nil) so a malformed wire
    # value outside even a byte range still normalizes correctly rather than raising.
    def from_code(code)
      return code if code.is_a?(Integer) && code >= 0 && code <= 4
      MOTION_IN_SHARED_SPACE # F2: unknown/absent -> highest class
    end

    def class_to_value(cls)
      Naalp::CBOR::U.new(cls)
    end

    # ---- spatial-bounds ---------------------------------------------------------------------

    # A named coordinate frame plus a signed axis-aligned bounding region in that frame, integer
    # millimeters (spec/naalp-draft-01.cddl `spatial-bounds`).
    SpatialBounds = Struct.new(:frame, :axes) do
      # Structural validity (spec/naalp-draft-01.cddl): non-empty axes, every min <= max, frame
      # non-empty and Unicode NFC.
      def well_formed?
        return false if axes.nil? || axes.empty?
        return false if axes.any? { |min, max| min > max }
        return false if frame.nil? || frame.empty?
        begin
          Naalp::Identity.require_nfc(frame)
        rescue Naalp::Identity::NonNFC
          return false
        end
        true
      end

      def to_value
        axes_v = axes.map { |min, max| Naalp::CBOR::A.new([Naalp::Hazard.int_value(min), Naalp::Hazard.int_value(max)]) }
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::T.new(frame)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::A.new(axes_v)],
        ])
      end

      # Deterministic-CBOR encoding of {1:frame,2:axes}. Malformed input still encodes (encoding
      # is not the validity gate); callers MUST check #well_formed? before treating a
      # SpatialBounds as authoritative, exactly as .from_value does on decode.
      def bytes
        Naalp::CBOR.encode(to_value)
      end
    end

    # Parse a `spatial-bounds` map. Rejects a non-map, an out-of-range/wrong-typed key or value, a
    # missing key, empty axes, an axis with min > max, or a non-NFC/empty frame -- fail-closed
    # (HazardMalformed), never a partially-valid result.
    def spatial_bounds_from_value(v)
      raise malformed_error unless v.is_a?(Naalp::CBOR::M)
      frame = nil
      have_frame = false
      axes = nil
      have_axes = false
      v.pairs.each do |k, val|
        raise malformed_error unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          raise malformed_error unless val.is_a?(Naalp::CBOR::T)
          frame = val.v
          have_frame = true
        when 2
          raise malformed_error unless val.is_a?(Naalp::CBOR::A) && !val.items.empty?
          out = []
          val.items.each do |it|
            raise malformed_error unless it.is_a?(Naalp::CBOR::A) && it.items.length == 2
            min = int_from_value(it.items[0])
            max = int_from_value(it.items[1])
            raise malformed_error if min > max
            out << [min, max]
          end
          axes = out
          have_axes = true
        else
          raise malformed_error
        end
      end
      raise malformed_error unless have_frame && have_axes
      sb = SpatialBounds.new(frame, axes)
      raise malformed_error unless sb.well_formed?
      sb
    end

    def int_value(v)
      v >= 0 ? Naalp::CBOR::U.new(v) : Naalp::CBOR::N.new(v)
    end

    def int_from_value(v)
      case v
      when Naalp::CBOR::U then v.v
      when Naalp::CBOR::N then v.v
      else raise malformed_error
      end
    end

    # Full containment (F3): same frame id (a bound in one frame says nothing about a bound in a
    # different, unrelated frame), the SAME axis count in the SAME order, and every claim axis's
    # [min,max] a subset of the matching grant axis's [min,max].
    def spatial_contained(claim, grant)
      return false if claim.frame != grant.frame
      return false if claim.axes.length != grant.axes.length
      claim.axes.each_with_index do |(cmin, cmax), i|
        gmin, gmax = grant.axes[i]
        return false unless cmin >= gmin && cmax <= gmax
      end
      true
    end

    # ---- hazard-window ------------------------------------------------------------------------

    # A validity window, epoch ms, the same convention as `naalp-object` field 6 (created) and
    # `naalp-delegation-grant` fields 4/5.
    HazardWindow = Struct.new(:not_before, :not_after) do
      def to_value
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), Naalp::CBOR::U.new(not_before)],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(not_after)],
        ])
      end
    end

    def hazard_window_from_value(v)
      raise malformed_error unless v.is_a?(Naalp::CBOR::M)
      not_before = nil
      not_after = nil
      v.pairs.each do |k, val|
        raise malformed_error unless k.is_a?(Naalp::CBOR::U) && val.is_a?(Naalp::CBOR::U)
        case k.v
        when 1 then not_before = val.v
        when 2 then not_after = val.v
        else raise malformed_error
        end
      end
      raise malformed_error if not_before.nil? || not_after.nil?
      HazardWindow.new(not_before, not_after)
    end

    # ---- hazard-envelope -----------------------------------------------------------------------

    # The full physical envelope a claim or an authorization bounds itself by. All three fields
    # are MANDATORY on the wire (spec/naalp-draft-01.cddl) -- a silently-absent axis would be
    # fail-OPEN in a physical-safety context, so an issuer that means "unbounded" states so
    # explicitly with wide numeric bounds; the wire never infers permissiveness from silence here
    # (deliberate contrast with `naalp-delegation-grant`'s optional scope).
    HazardEnvelope = Struct.new(:spatial, :speed_bound_mm_s, :window) do
      def to_value
        Naalp::CBOR::M.new([
          [Naalp::CBOR::U.new(1), spatial.to_value],
          [Naalp::CBOR::U.new(2), Naalp::CBOR::U.new(speed_bound_mm_s)],
          [Naalp::CBOR::U.new(3), window.to_value],
        ])
      end

      # Deterministic-CBOR encoding of {1:spatial,2:speed_bound,3:window}.
      def bytes
        Naalp::CBOR.encode(to_value)
      end

      # The envelope's content id (T1 framing): a pure function of the bytes above.
      def content_id
        Naalp::CBOR.content_id(to_value)
      end
    end

    # Parse a `hazard-envelope` map; fail-closed on any missing/malformed field.
    def hazard_envelope_from_value(v)
      raise malformed_error unless v.is_a?(Naalp::CBOR::M)
      spatial = nil
      speed = nil
      window = nil
      v.pairs.each do |k, val|
        raise malformed_error unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          spatial = spatial_bounds_from_value(val)
        when 2
          raise malformed_error unless val.is_a?(Naalp::CBOR::U)
          speed = val.v
        when 3
          window = hazard_window_from_value(val)
        else
          raise malformed_error
        end
      end
      raise malformed_error if spatial.nil? || speed.nil? || window.nil?
      HazardEnvelope.new(spatial, speed, window)
    end

    # Full containment (F3): spatial_contained AND claim.speed_bound_mm_s <=
    # grant.speed_bound_mm_s AND the claim's window is a sub-interval of the grant's
    # (grant.not_before <= claim.not_before and claim.not_after <= grant.not_after).
    def envelope_contained(claim, grant)
      spatial_contained(claim.spatial, grant.spatial) &&
        claim.speed_bound_mm_s <= grant.speed_bound_mm_s &&
        grant.window.not_before <= claim.window.not_before &&
        claim.window.not_after <= grant.window.not_after
    end

    # ---- naalp-hazard-claim / naalp-hazard-authorization ----------------------------------------

    # A signed physical-hazard claim (spec/naalp-draft-01.cddl `naalp-hazard-claim`). Carriage
    # (the object it accompanies and how) is a wire-impact decision, not this module's concern.
    HazardClaim = Struct.new(:hazard_class, :envelope) do
      def to_value
        Naalp::Hazard.hazard_body_to_value(hazard_class, envelope)
      end

      # Deterministic-CBOR encoding of {1:class,2:envelope}.
      def bytes
        Naalp::CBOR.encode(to_value)
      end

      # The claim's content id (T1 framing).
      def content_id
        Naalp::CBOR.content_id(to_value)
      end
    end

    def hazard_claim_from_value(v)
      cls, envelope = hazard_body_from_value(v)
      HazardClaim.new(cls, envelope)
    end

    # A signed physical-hazard authorization ("a grant" in requirements F3's language;
    # spec/naalp-draft-01.cddl `naalp-hazard-authorization`). Same shape as HazardClaim
    # deliberately: one envelope shape for both sides keeps the containment check symmetric.
    HazardAuthorization = Struct.new(:hazard_class, :envelope) do
      def to_value
        Naalp::Hazard.hazard_body_to_value(hazard_class, envelope)
      end

      # Deterministic-CBOR encoding of {1:class,2:envelope}.
      def bytes
        Naalp::CBOR.encode(to_value)
      end

      # The authorization's content id (T1 framing).
      def content_id
        Naalp::CBOR.content_id(to_value)
      end
    end

    def hazard_authorization_from_value(v)
      cls, envelope = hazard_body_from_value(v)
      HazardAuthorization.new(cls, envelope)
    end

    def hazard_body_to_value(cls, envelope)
      Naalp::CBOR::M.new([
        [Naalp::CBOR::U.new(1), class_to_value(cls)],
        [Naalp::CBOR::U.new(2), envelope.to_value],
      ])
    end

    def hazard_body_from_value(v)
      raise malformed_error unless v.is_a?(Naalp::CBOR::M)
      class_code = nil
      envelope = nil
      v.pairs.each do |k, val|
        raise malformed_error unless k.is_a?(Naalp::CBOR::U)
        case k.v
        when 1
          # An out-of-range class ON THE WIRE (not merely "absent") is a malformed body, not a
          # normalize-to-4 input: F2's fail-closed normalization is for the DECODE step that
          # produces a class from a less-structured source (see .from_code), not for a
          # CDDL-invalid hazard-class value already claiming to be well-formed.
          raise malformed_error unless val.is_a?(Naalp::CBOR::U) && val.v >= 0 && val.v <= 4
          class_code = val.v
        when 2
          envelope = hazard_envelope_from_value(val)
        else
          raise malformed_error
        end
      end
      raise malformed_error if class_code.nil? || envelope.nil?
      [from_code(class_code), envelope]
    end

    # ---- F3: grant-coverage authorization -------------------------------------------------------

    # Authorize a well-formed, present claim against an authorization (F3): EXACT class match
    # (not a <= ceiling -- see the module doc) AND envelope_contained. Any single failing
    # dimension denies the WHOLE claim (HazardNotCovered) -- there is no partial authorization
    # and no fail-open branch.
    def hazard_authorized(claim, grant)
      raise not_covered_error if claim.hazard_class != grant.hazard_class
      raise not_covered_error unless envelope_contained(claim.envelope, grant.envelope)
      nil
    end

    # Authorize an OPTIONAL claim (F2's "absent" case at the object level, distinct from a
    # present-but-unrecognized class byte inside a claim). `nil` -- no hazard-claim object exists
    # at all for an action that requires one -- denies immediately (HazardUnknown) rather than
    # fabricating a sentinel envelope and running the ordinary coverage check: there is no
    # envelope to check containment against, so the honest outcome is a distinct error, not a
    # coverage denial that implies an envelope was compared.
    def hazard_authorized_optional(claim, grant)
      raise unknown_error if claim.nil?
      hazard_authorized(claim, grant)
    end
  end
end
