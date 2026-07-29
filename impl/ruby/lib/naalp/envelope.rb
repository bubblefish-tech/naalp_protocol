# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# N-AALP C3 object envelope for the Ruby SDK — the full signed object and its offline verify.
#
# This is the ergonomic surface a developer uses: build an Object (its channel/kind/effect/body
# and the rest), sign it with a signer, and get a single self-describing, offline-verifiable byte
# string; verify one from the object + key + spec alone. The bytes are byte-identical to the Go,
# Rust and Python reference implementations (the worked example in vectors/worked/example.json is
# the byte-level known-answer for this module).
require_relative 'cbor'
require_relative 'cose'

module Naalp
  module Envelope
    U = Naalp::CBOR::U
    N = Naalp::CBOR::N
    B = Naalp::CBOR::B
    T = Naalp::CBOR::T
    A = Naalp::CBOR::A
    M = Naalp::CBOR::M
    Tag = Naalp::CBOR::Tag

    # object body field numbers (§2.1)
    FIELD_ID = 1
    FIELD_KIND = 2
    FIELD_CHANNEL = 3
    FIELD_TIER = 4
    FIELD_SIGNER = 5
    FIELD_CREATED = 6
    FIELD_EFFECT = 7
    FIELD_CAUSES = 8
    FIELD_PROFILE = 9
    FIELD_BODY = 10
    FIELD_EXT = 11
    FIELD_CEXT = 12

    NAALP_VERSION = 1
    HEADER_LABEL = "naalp".freeze

    # A named, offline-verifiable failure. #kind is a stable string mirroring the Go/Rust/Python
    # error kinds; fail-closed — verify raises on the first violation and changes no state.
    class EnvelopeError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        @kind = kind
        super("#{kind}: #{msg}")
      end
    end

    # A decoded N-AALP object body. #id is set by sign() (content id §2.3).
    class Object
      attr_accessor :id, :kind, :channel, :tier, :signer, :created, :effect,
                    :causes, :profile, :body, :ext, :cext

      def initialize(kind:, channel:, signer:, created:, effect:, body:,
                     tier: 0, profile: Naalp::COSE::PROFILE_PUBLIC,
                     causes: nil, ext: nil, cext: nil)
        @id = nil
        @kind = kind
        @channel = channel
        @tier = tier
        @signer = signer.dup.force_encoding(Encoding::BINARY)
        @created = created
        @effect = effect
        @causes = (causes || []).to_a
        @profile = profile
        @body = body            # a cbor Value (e.g. Naalp::CBOR::M.new([...]))
        @ext = ext              # Naalp::CBOR::M or nil (field 11, non-critical)
        @cext = cext            # Naalp::CBOR::M or nil (field 12, critical)
      end

      def body_map(include_id)
        pairs = []
        pairs << [U.new(FIELD_ID), B.new(@id)] if include_id
        pairs += [
          [U.new(FIELD_KIND), U.new(@kind)],
          [U.new(FIELD_CHANNEL), U.new(@channel)],
          [U.new(FIELD_TIER), U.new(@tier)],
          [U.new(FIELD_SIGNER), B.new(@signer)],
          [U.new(FIELD_CREATED), U.new(@created)],
          [U.new(FIELD_EFFECT), U.new(@effect)],
          [U.new(FIELD_CAUSES), A.new(@causes.map { |c| B.new(c) })],
          [U.new(FIELD_PROFILE), U.new(@profile)],
          [U.new(FIELD_BODY), @body],
        ]
        pairs << [U.new(FIELD_EXT), @ext] unless @ext.nil?
        pairs << [U.new(FIELD_CEXT), @cext] unless @cext.nil?
        M.new(pairs)
      end

      # The object content id over the body without field 1 (§2.3).
      def content_id
        Naalp::CBOR.content_id(body_map(false))
      end
    end

    module_function

    def protected_header(alg, signer, profile)
      naalp = M.new([
        [U.new(1), B.new(signer)],
        [U.new(2), U.new(profile)],
        [U.new(3), U.new(NAALP_VERSION)],
      ])
      Naalp::CBOR.encode(M.new([
        [U.new(1), N.new(alg)],
        [T.new(HEADER_LABEL), naalp],
      ]))
    end

    # Assemble, content-id-bind, and deterministically sign a full N-AALP object with an ML-DSA
    # key derived from `seed`. Returns the tagged COSE_Sign1 object bytes.
    def sign(obj, alg, seed)
      obj.id = obj.content_id
      payload = Naalp::CBOR.encode(obj.body_map(true))
      prot = protected_header(alg, obj.signer, obj.profile)
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      sig = Naalp::COSE.mldsa_sign(alg, seed, tbs)
      Naalp::COSE.assemble_sign1_raw(prot, payload, sig)
    end

    def parse_protected(prot)
      v = Naalp::CBOR.decode(prot)
      raise EnvelopeError.new("Malformed", "protected header not a map") unless v.is_a?(M)
      alg = signer = profile = version = nil
      v.pairs.each do |k, val|
        if k.is_a?(U) && k.v == 1 && val.is_a?(N)
          alg = val.v
        elsif k.is_a?(T) && k.v == HEADER_LABEL && val.is_a?(M)
          val.pairs.each do |kk, vv|
            if kk.is_a?(U) && kk.v == 1 && vv.is_a?(B)
              signer = vv.v
            elsif kk.is_a?(U) && kk.v == 2 && vv.is_a?(U)
              profile = vv.v
            elsif kk.is_a?(U) && kk.v == 3 && vv.is_a?(U)
              version = vv.v
            end
          end
        end
      end
      if alg.nil? || signer.nil? || profile.nil? || version.nil?
        raise EnvelopeError.new("Malformed", "protected header missing routing fields")
      end
      [alg, signer, profile, version]
    end

    ANY_VALUE = [U, N, B, T, A, M, Tag].freeze

    def object_from_map(m)
      fields = {}
      m.pairs.each do |k, v|
        raise EnvelopeError.new("Malformed", "non-uint body key") unless k.is_a?(U)
        fields[k.v] = v
      end

      need = lambda do |fnum, types|
        v = fields[fnum]
        types = [types] unless types.is_a?(Array)
        unless types.any? { |t| v.is_a?(t) }
          raise EnvelopeError.new("Malformed", "field #{fnum} wrong type/absent")
        end
        v
      end

      signer = need.call(FIELD_SIGNER, B).v
      causes_v = need.call(FIELD_CAUSES, A)
      causes = causes_v.items.map do |c|
        raise EnvelopeError.new("Malformed", "cause not a bstr") unless c.is_a?(B)
        c.v
      end
      ext = fields[FIELD_EXT]
      cext = fields[FIELD_CEXT]
      if !ext.nil? && !ext.is_a?(M)
        raise EnvelopeError.new("Malformed", "ext not a map")
      end
      if !cext.nil? && !cext.is_a?(M)
        raise EnvelopeError.new("Malformed", "cext not a map")
      end
      o = Object.new(
        kind: need.call(FIELD_KIND, U).v, channel: need.call(FIELD_CHANNEL, U).v,
        signer: signer, created: need.call(FIELD_CREATED, U).v,
        effect: need.call(FIELD_EFFECT, U).v, body: need.call(FIELD_BODY, ANY_VALUE),
        tier: need.call(FIELD_TIER, U).v, profile: need.call(FIELD_PROFILE, U).v,
        causes: causes, ext: ext, cext: cext,
      )
      idv = fields[FIELD_ID]
      o.id = idv.is_a?(B) ? idv.v : nil
      o
    end

    # Verify a signed N-AALP object end-to-end, offline (R-2.4). Returns the Object on success;
    # raises EnvelopeError (or a cose/cbor error) with a stable #kind on the first named failure.
    # Check order (fail-closed): decode -> content-id -> field ranges -> header/body copies +
    # version -> critical extensions -> kind dispatch -> profile floor -> signature.
    #
    # kind_validator responds to #call(channel, kind) -> truthy iff (channel, kind) is a
    # registered surface (may be a lambda/proc, or a block).
    def verify(profile, alg, pubkey, kind_validator, obj_bytes, known_cext = {}, &blk)
      kind_validator ||= blk
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj_bytes)
      bv = Naalp::CBOR.decode(payload)  # raises NonCanonical on a non-canonical body
      raise EnvelopeError.new("Malformed", "body not a map") unless bv.is_a?(M)

      # content-id: recompute over the body without field 1, compare to the claimed id
      claimed = nil
      without = []
      bv.pairs.each do |k, v|
        if k.is_a?(U) && k.v == FIELD_ID
          raise EnvelopeError.new("Malformed", "id not a bstr") unless v.is_a?(B)
          claimed = v.v
          next
        end
        without << [k, v]
      end
      raise EnvelopeError.new("Malformed", "no content id") if claimed.nil?
      if Naalp::CBOR.content_id(M.new(without)) != claimed
        raise EnvelopeError.new("ContentIdMismatch", "recomputed id differs")
      end

      o = object_from_map(bv)

      # field ranges (§3.3): channel 0..19, effect 0..3, profile 1..3
      if o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3
        raise EnvelopeError.new("RangeError", "field out of range")
      end

      halg, hsigner, hprofile, hversion = parse_protected(prot)
      raise EnvelopeError.new("UnsupportedVersion", "bad naalp-version") if hversion != NAALP_VERSION
      if hsigner != o.signer || hprofile != o.profile
        raise EnvelopeError.new("HeaderBodyMismatch", "protected header disagrees with body")
      end

      unless o.cext.nil?
        o.cext.pairs.each do |k, _v|
          unless k.is_a?(U) && known_cext.key?(k.v)
            raise EnvelopeError.new("UnknownCriticalExt", "unrecognized critical extension")
          end
        end
      end

      if kind_validator.nil? || !kind_validator.call(o.channel, o.kind)
        raise EnvelopeError.new("UnknownKind", "kind/channel not a registered surface")
      end

      level, known = Naalp::COSE.alg_level(halg)
      raise EnvelopeError.new("UnknownAlg", "unregistered alg") unless known
      if level < Naalp::COSE.profile_min_level(profile)
        raise EnvelopeError.new("ProfileDowngrade", "signature level below the profile minimum")
      end
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
        raise EnvelopeError.new("BadSignature", "signature does not verify")
      end
      o
    end
  end
end
