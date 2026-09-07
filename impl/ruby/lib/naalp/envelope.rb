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
require_relative '_wire_constants_gen'

module Naalp
  module Envelope
    U = Naalp::CBOR::U
    N = Naalp::CBOR::N
    B = Naalp::CBOR::B
    T = Naalp::CBOR::T
    A = Naalp::CBOR::A
    M = Naalp::CBOR::M
    Tag = Naalp::CBOR::Tag

    # The signed suite id carried in field 14 for the opt-in ML-DSA-65 + Ed25519 composite signature
    # (§4.2); present iff a composite alg signs the object, so a pure object stays byte-identical to
    # a draft-00 object.
    SUITE_MLDSA65_ED25519 = 1

    # --- T1.3 recheck (the checkable-minimum field, NAALP-REQ-110/111) -------------------------------

    # The ext/cext extension key under which an object NAMES the re-check procedure for the claim in
    # its body (§2.5, NAALP-REQ-111(c) -- the "checkable minimum"). The value is a procedure id into
    # the CLOSED registry below. In the non-critical ext map (field 11) it is may-ignore; in the
    # critical cext map (field 12) it is must-understand and an unknown procedure id is rejected
    # fail-closed (UnknownCriticalExt), the same C3 critical-extension rule reaching the procedure it
    # names. 13 does not collide with the safety-label ext key 1 (§6.4). Byte-identical to impl/go
    # and impl/rust.
    RECHECK_KEY = 13

    # The closed re-check procedure registry (design.md §2.5; T1.3); mirrors the spec
    # recheck-procedure production and vectors/registry/recheck.csv.
    RECHECK_RECOMPUTE_CONTENT_ID = 1 # recompute the content id from the body and compare (§2.3)
    RECHECK_VERIFY_COSE_SIGN1    = 2 # verify the COSE_Sign1 signature under the signer key (§4)
    RECHECK_WALK_CAUSES          = 3 # walk the signed causal partial order offline (§8.2)
    RECHECK_REPLAY_CONSUME_CHECK = 4 # replay the single-use consume ledger for the approval (§7.2)

    # --- T1.6 per-signer forward-only counter (the OPTIONAL detection field, NAALP-REQ-120) ---------

    # The ext extension key under which an object OPTIONALLY carries a forward-only per-signer
    # counter (design.md §2.5.2, NAALP-REQ-120 -- the per-signer counter). The value is a
    # forward-only position (a uint) the signer increments on each object. It lives in the
    # NON-CRITICAL ext map (field 11): a verifier that does not perform duplication-detection ignores
    # it and the object still verifies (may-ignore). Because ext (field 11) is part of the signed
    # body/payload, the counter is covered by the SIGNER's own COSE_Sign1 signature -- the deliberate
    # contrast with the T1.5 consume-receipt position, which is signed by the LEDGER key. 14 does not
    # collide with the safety-label ext key 1 (§6.4) or the recheck ext/cext key 13. Byte-identical to
    # impl/go and impl/rust.
    #
    # The counter is DETECTION, not prevention (NAALP-REQ-120; Security Considerations): a single
    # self-authored sequence proves nothing -- see detect_signer_duplication below. It is a
    # NON-CRITICAL field only -- placing it in the critical cext map is an unrecognized critical
    # extension and is rejected fail-closed (UnknownCriticalExt), because a detection aid is never a
    # must-understand verification gate.
    SIGNER_COUNTER_KEY = 14

    # Field numbers (§2.1), naalp-version (§2.5) and the header label are generated from
    # spec/wire-constants.csv and defined in this module by `require_relative '_wire_constants_gen'`
    # above, so they are authored once and cannot be re-typed and drift (scripts/gen_wire_constants.py).

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
                    :causes, :profile, :body, :ext, :cext, :audience, :suite

      def initialize(kind:, channel:, signer:, created:, effect:, body:,
                     tier: 0, profile: Naalp::COSE::PROFILE_PUBLIC,
                     causes: nil, ext: nil, cext: nil, audience: "", suite: 0)
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
        # field 13 (§2.5.3): the single-use consume binding. Omit-when-empty -- a no-audience object
        # encodes byte-identically to a draft-00 object (additivity). Anchors version 2.
        @audience = audience
        # field 14 (§4.2): the signed suite declaration, present (value 1) iff a composite alg signs
        # this object; 0 = absent, so a pure object stays byte-identical to draft-00.
        @suite = suite
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
        pairs << [U.new(FIELD_AUDIENCE), T.new(@audience)] unless @audience.empty?
        pairs << [U.new(FIELD_SUITE), U.new(@suite)] unless @suite.zero?
        M.new(pairs)
      end

      # The object content id over the body without field 1 (§2.3).
      def content_id
        Naalp::CBOR.content_id(body_map(false))
      end

      # Recheck returns the re-check procedure the object names (RECHECK_KEY, §2.5): present is true
      # when a procedure is named, and critical is true iff it is named in the cext map (field 12,
      # must-understand) rather than the ext map (field 11, may-ignore). cext takes precedence when
      # both carry the key. When no procedure is named the claim is attributable-only
      # (NAALP-REQ-111). Returns [id, present, critical].
      def recheck
        v, ok = cext_get_uint(@cext, RECHECK_KEY)
        return [v, true, true] if ok
        v, ok = cext_get_uint(@ext, RECHECK_KEY)
        return [v, true, false] if ok
        [0, false, false]
      end

      # SetRecheck names proc_id as the body claim's re-check procedure. critical places it in the
      # cext map (field 12, must-understand); otherwise the ext map (field 11, may-ignore). Creates
      # the carrier if absent, replaces an existing entry under the key, and leaves any other
      # extension entries intact.
      def set_recheck(proc_id, critical)
        entry = [U.new(RECHECK_KEY), U.new(proc_id)]
        if critical
          @cext = replace_or_append_pair(@cext, RECHECK_KEY, entry)
        else
          @ext = replace_or_append_pair(@ext, RECHECK_KEY, entry)
        end
      end

      # SignerCounter returns the forward-only per-signer position the object names
      # (SIGNER_COUNTER_KEY, §2.5.2): present is true iff a counter is named in the non-critical ext
      # map (field 11) as a uint. The field is OPTIONAL -- absent (present == false) is valid.
      # present is keyed on the KEY being present, not on the value: a present counter of value 0
      # returns [0, true].
      def signer_counter
        cext_get_uint(@ext, SIGNER_COUNTER_KEY)
      end

      # SetSignerCounter names seq as this object's forward-only per-signer position in the
      # NON-CRITICAL ext map (field 11), covered by the signer's COSE_Sign1 signature. Creates the
      # ext carrier if absent and leaves any other extension entries intact. The counter is
      # deliberately never placed in the critical cext map (it is detection, not a verification gate).
      def set_signer_counter(seq)
        @ext = replace_or_append_pair(@ext, SIGNER_COUNTER_KEY, [U.new(SIGNER_COUNTER_KEY), U.new(seq)])
      end

      private

      # cext_get_uint returns [value, true] iff the CBOR map m carries key as a uint-valued entry;
      # otherwise [0, false]. Mirrors impl/go envelope.cextGetUint / impl/rust cext_get_uint.
      def cext_get_uint(m, key)
        return [0, false] if m.nil?
        m.pairs.each do |k, v|
          next unless k.is_a?(U) && k.v == key
          return v.is_a?(U) ? [v.v, true] : [0, false]
        end
        [0, false]
      end

      # replace_or_append_pair returns a NEW M with entry replacing any existing pair under key, or
      # appended when absent; m == nil creates a fresh single-entry map. Never mutates m in place.
      def replace_or_append_pair(m, key, entry)
        return M.new([entry]) if m.nil?
        new_pairs = []
        replaced = false
        m.pairs.each do |k, v|
          if k.is_a?(U) && k.v == key
            new_pairs << entry
            replaced = true
          else
            new_pairs << [k, v]
          end
        end
        new_pairs << entry unless replaced
        M.new(new_pairs)
      end
    end

    # DuplicationFinding surfaces one detected per-signer counter conflict: two or more DISTINCT
    # objects (distinct content ids) from the SAME signer id that carry the SAME forward-only counter
    # value. A forward-only counter binds each value to at most one object, so a value bound to >= 2
    # distinct objects is the observable fingerprint of the key incrementing in two places (key
    # duplication). The finding surfaces BOTH sides of the contradiction: the reused #counter value
    # and every conflicting content id (#ids, ascending by bytes) -- never a single flag with the
    # evidence hidden. Mirrors impl/go envelope.DuplicationFinding / impl/rust DuplicationFinding.
    class DuplicationFinding
      attr_reader :signer, :counter, :ids

      def initialize(signer, counter, ids)
        @signer = signer.dup.force_encoding(Encoding::BINARY)
        @counter = counter
        @ids = ids.map { |id| id.dup.force_encoding(Encoding::BINARY) }
      end

      def ==(other)
        other.is_a?(DuplicationFinding) && signer == other.signer && counter == other.counter && ids == other.ids
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

    # Assemble, content-id-bind, and sign a full N-AALP object with the opt-in LAMPS composite
    # signature (alg -65537, §4.2). Sets the signed suite field (14) present (value 1) BEFORE the
    # content id so the id covers it; the composite value is deterministic in both legs (ML-DSA-65
    # with ctx=Label, Ed25519 with no ctx). Returns the tagged COSE_Sign1 object bytes.
    def sign_composite(obj, mldsa_seed, ed_seed)
      obj.suite = SUITE_MLDSA65_ED25519
      obj.id = obj.content_id
      payload = Naalp::CBOR.encode(obj.body_map(true))
      prot = protected_header(Naalp::COSE::ALG_COMPOSITE_65_ED25519, obj.signer, obj.profile)
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      sig = Naalp::COSE.composite_sign(mldsa_seed, ed_seed, tbs)
      Naalp::COSE.assemble_sign1_raw(prot, payload, sig)
    end

    def parse_protected(prot)
      # §3.1.1 (R5): the empty protected header is pinned to 0x40; a byte string wrapping an
      # empty CBOR map (the 0x41A0 form -- its unwrapped content is the single byte 0xA0) is the
      # one redundant encoding RFC 9052 §3 otherwise permits, and MUST be rejected as
      # NonCanonical before the header is interpreted (otherwise it dies downstream as a generic
      # Malformed / no-alg, losing the determinism verdict).
      if prot.bytesize == 1 && prot.getbyte(0) == 0xA0
        raise Naalp::CBOR::NonCanonical, "empty protected header must be 0x40, not 0x41A0 (§3.1.1, R5)"
      end
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
      if causes_v.items.length > MAX_CAUSES # causal fan-in bound (§3.4, R7)
        raise EnvelopeError.new("TooManyCauses", "causes[] exceeds the maximum count (§3.4, R7)")
      end
      causes = causes_v.items.map do |c|
        raise EnvelopeError.new("Malformed", "cause not a bstr") unless c.is_a?(B)
        c.v
      end
      ext = fields[FIELD_EXT]
      cext = fields[FIELD_CEXT]
      if !ext.nil? && !ext.is_a?(M)
        raise EnvelopeError.new("Malformed", "ext not a map")
      end
      if !ext.nil? && ext.pairs.length > MAX_EXT # ext cardinality bound (§3.4, R7)
        raise EnvelopeError.new("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
      end
      if !cext.nil? && !cext.is_a?(M)
        raise EnvelopeError.new("Malformed", "cext not a map")
      end
      if !cext.nil? && cext.pairs.length > MAX_CEXT # cext cardinality bound (§3.4, R7)
        raise EnvelopeError.new("TooManyExtensions", "ext/cext exceeds the maximum cardinality (§3.4, R7)")
      end
      aud = fields[FIELD_AUDIENCE]
      if !aud.nil? && !aud.is_a?(T)
        raise EnvelopeError.new("Malformed", "audience not a tstr")
      end
      suite_v = fields[FIELD_SUITE]
      if !suite_v.nil? && !suite_v.is_a?(U)
        raise EnvelopeError.new("Malformed", "suite not a uint")
      end
      o = Object.new(
        kind: need.call(FIELD_KIND, U).v, channel: need.call(FIELD_CHANNEL, U).v,
        signer: signer, created: need.call(FIELD_CREATED, U).v,
        effect: need.call(FIELD_EFFECT, U).v, body: need.call(FIELD_BODY, ANY_VALUE),
        tier: need.call(FIELD_TIER, U).v, profile: need.call(FIELD_PROFILE, U).v,
        causes: causes, ext: ext, cext: cext, audience: aud.nil? ? "" : aud.v,
        suite: suite_v.nil? ? 0 : suite_v.v,
      )
      idv = fields[FIELD_ID]
      o.id = idv.is_a?(B) ? idv.v : nil
      o
    end

    # IsKnownRecheckProcedure reports whether id is a recognized re-check procedure. The registry is
    # CLOSED: an id outside it is unknown, and an unknown id under the critical map is rejected
    # (§2.5).
    def is_known_recheck_procedure(id)
      id >= RECHECK_RECOMPUTE_CONTENT_ID && id <= RECHECK_REPLAY_CONSUME_CHECK
    end

    # DetectSignerDuplication scans a SET of PRESENTED objects for per-signer counter reuse. This is
    # the whole point of the field, and it is DETECTION, not prevention (NAALP-REQ-120): it flags a
    # signer id ONLY when two conflicting sequences from that signer physically MEET in the presented
    # set -- a counter value bound to >= 2 distinct content ids by one signer. Given only ONE object
    # per value (one sequence) it returns no findings; the second conflicting object must be present,
    # unsuppressed, for the duplication to become provable. Objects with no counter do not
    # participate. Output is deterministic (findings ordered by signer id then counter; ids within a
    # finding ascending by bytes).
    #
    # It operates over the SET, never per object: a per-object boolean could never express "these two
    # distinct objects reuse one position," and a single self-authored counter proves nothing on its
    # own. Mirrors impl/go envelope.DetectSignerDuplication / impl/rust detect_signer_duplication.
    def detect_signer_duplication(objs)
      # signer bytes -> counter -> (content-id bytes -> content-id bytes), a set that de-dups a
      # byte-identical re-presentation (one content id twice) so it is NOT a conflict.
      groups = {}
      signer_bytes = {}
      objs.each do |o|
        seq, present = o.signer_counter
        next unless present
        begin
          id = o.content_id
        rescue StandardError
          next # a body that cannot be canonically encoded cannot be a presented object
        end
        sk = o.signer
        signer_bytes[sk] = o.signer
        groups[sk] ||= {}
        groups[sk][seq] ||= {}
        groups[sk][seq][id] = id
      end

      findings = []
      groups.keys.sort.each do |sk|
        by_counter = groups[sk]
        by_counter.keys.sort.each do |c|
          idset = by_counter[c]
          # A (signer, counter) that binds two-or-more DISTINCT content ids is a detected
          # duplication. The >= 2 requirement is the detection-requires-both invariant: relax it to
          # >= 1 and a single sequence would flag (prevention theatre) -- the mutation the "one
          # sequence alone -> not flagged" test is built to catch.
          next if idset.size < 2
          ids = idset.values.sort
          findings << DuplicationFinding.new(signer_bytes[sk], c, ids)
        end
      end
      findings
    end

    # The single-use consume binding gate (§2.5.3), checked at the point of use -- before the consume
    # logic (the CAS append) -- NEVER inside verify(). An in-transit relay, ordering authority, or
    # auditor legitimately verifies objects addressed to some OTHER authority; only the authority
    # about to CONSUME an object enforces that the object is addressed to it. Three branches: (a)
    # absent audience on a consume-once object -> WrongAudience; (b) an audience present but not this
    # authority -> WrongAudience; (c) a non-consume-once object with no audience -> pass. Raises
    # EnvelopeError("WrongAudience") on rejection; returns nil on pass.
    def check_audience(o, self_authority, consume_once)
      if o.audience.empty?
        raise EnvelopeError.new("WrongAudience", "consume-once object has no audience") if consume_once
        return nil
      end
      unless o.audience == self_authority
        raise EnvelopeError.new("WrongAudience", "object audience is not this consuming authority")
      end
      nil
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
      # Object octet-size bound (§3.4, R7): reject an oversized signed object on the raw bytes,
      # before any parse (RFC 8949 §10 decoder-memory guard).
      if obj_bytes.bytesize > MAX_OBJECT_SIZE
        raise EnvelopeError.new("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
      end
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj_bytes)
      # non-canonical -> NonCanonical (§2.6); over-nested -> DepthExceeded (§3.4, R7).
      bv = Naalp::CBOR.decode_bounded(payload, MAX_NESTING_DEPTH)
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

      # A (channel 3, kind 0) Rotation object MUST be a tag-98 COSE_Sign co-signed by the old AND new
      # key (§5.2); a single-signature (tag-18) rotation is missing the old-key co-signature and is
      # rejected RotationUnauthorized (the single-Sign1 rotation-gap fix).
      if rotation_object?(o.channel, o.kind)
        raise EnvelopeError.new("RotationUnauthorized", "single-signature rotation missing the old-key co-signature")
      end

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
        o.cext.pairs.each do |k, v|
          unless k.is_a?(U)
            raise EnvelopeError.new("UnknownCriticalExt", "critical extension key not a uint")
          end
          # RecheckKey (13) is an envelope-recognized critical key: a critical recheck naming an
          # UNKNOWN procedure id is rejected fail-closed (the critical-extension rule reaching the
          # procedure it names, T1.3); a known procedure id is recognized regardless of the caller's
          # known_cext set. A NON-critical recheck (ext, field 11) is never rejected here -- an
          # unknown non-critical procedure is ignored per the may-ignore rule (handled elsewhere).
          if k.v == RECHECK_KEY
            unless v.is_a?(U)
              raise EnvelopeError.new("Malformed", "recheck procedure id not a uint")
            end
            unless is_known_recheck_procedure(v.v)
              raise EnvelopeError.new("UnknownCriticalExt", "unrecognized critical recheck procedure")
            end
            next
          end
          unless known_cext.key?(k.v)
            raise EnvelopeError.new("UnknownCriticalExt", "unrecognized critical extension")
          end
        end
      end

      if kind_validator.nil? || !kind_validator.call(o.channel, o.kind)
        raise EnvelopeError.new("UnknownKind", "kind/channel not a registered surface")
      end

      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      if halg == Naalp::COSE::ALG_COMPOSITE_65_ED25519
        # Opt-in composite path (§4.2/§4.4/§4.5): CompositeRefused (Sovereign floors at level 5, the
        # composite ML-DSA-65 leg is level 3) -> SuiteMismatch (field 14 must declare the matching
        # suite) -> both-legs signature. Verifying key = mldsaPub || ed25519Pub.
        if profile == Naalp::COSE::PROFILE_SOVEREIGN
          raise EnvelopeError.new("CompositeRefused", "composite refused on the Sovereign profile")
        end
        if o.suite != SUITE_MLDSA65_ED25519
          raise EnvelopeError.new("SuiteMismatch", "field 14 does not declare the composite suite")
        end
        mldsa_pub = pubkey[0, Naalp::COSE::MLDSA65_PUB_SIZE]
        ed_pub = pubkey[Naalp::COSE::MLDSA65_PUB_SIZE..]
        unless ed_pub.bytesize == 32 && Naalp::COSE.composite_verify(mldsa_pub, ed_pub, tbs, sig)
          raise EnvelopeError.new("BadSignature", "composite signature does not verify")
        end
        return o
      end
      # pure path: a non-composite alg MUST NOT carry the signed suite field (§4.2).
      unless o.suite.zero?
        raise EnvelopeError.new("SuiteMismatch", "pure object carries a composite suite field")
      end
      level, known = Naalp::COSE.alg_level(halg)
      raise EnvelopeError.new("UnknownAlg", "unregistered alg") unless known
      if level < Naalp::COSE.profile_min_level(profile)
        raise EnvelopeError.new("ProfileDowngrade", "signature level below the profile minimum")
      end
      unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
        raise EnvelopeError.new("BadSignature", "signature does not verify")
      end
      o
    end

    # --- §5.2 Rotation object (tag-98 COSE_Sign, old+new co-signature) ---

    # The OPEN-DECISION toggle (design.md §4.4 profile floor applied to a rotation): a Sovereign/High
    # verifier gates the OLD (authorizing) leg by the profile floor too (DEFAULT, fail-closed) rather
    # than only the NEW leg. Ratified default = true (matches impl/go rotationOldLegFloorApplies).
    ROTATION_OLD_LEG_FLOOR_APPLIES = true

    def rotation_object?(channel, kind)
      channel == 3 && kind == 0
    end

    def composite_alg?(alg)
      alg == Naalp::COSE::ALG_COMPOSITE_65_ED25519 || alg == Naalp::COSE::ALG_COMPOSITE_44_ED25519
    end

    # Build a §5.2 Rotation object as a tag-98 COSE_Sign co-signed by the OLD then the NEW key in
    # fixed order; the body protected header names the NEW (go-forward) key. Permitted ONLY for the
    # Identity Rotation object (channel 3, kind 0); a composite leg is rejected fail-closed. Bytes are
    # byte-identical to the Go, Rust and Python reference implementations.
    def sign_rotation_object(obj, old_alg, old_seed, new_alg, new_seed)
      unless rotation_object?(obj.channel, obj.kind)
        raise EnvelopeError.new("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
      end
      if composite_alg?(old_alg) || composite_alg?(new_alg)
        raise EnvelopeError.new("Malformed", "composite-inside-rotation is undecided")
      end
      obj.suite = 0 # a rotation object is never composite
      obj.id = obj.content_id
      payload = Naalp::CBOR.encode(obj.body_map(true))
      body_prot = protected_header(new_alg, obj.signer, obj.profile)
      old_leg = Naalp::COSE.signature_leg(body_prot, old_alg, old_seed, payload)
      new_leg = Naalp::COSE.signature_leg(body_prot, new_alg, new_seed, payload)
      Naalp::COSE.assemble_sign_raw(body_prot, payload, [old_leg, new_leg])
    end

    # Verify a tag-98 Rotation object (§5.2): the same object-body checks as verify, then EXACTLY two
    # legs in fixed order (old-key then new-key) BOTH verifying. Any missing/wrong/bad old leg is
    # RotationUnauthorized. Permitted ONLY for (channel 3, kind 0).
    def verify_rotation_object(profile, old_alg, old_pk, new_alg, new_pk, kind_validator, obj_bytes, known_cext = {})
      # Object octet-size bound (§3.4, R7): the tag-98 rotation object is a top-level signed
      # object too, so it is size-checked on raw bytes before any parse.
      if obj_bytes.bytesize > MAX_OBJECT_SIZE
        raise EnvelopeError.new("TooLarge", "object exceeds the maximum octet size (§3.4, R7)")
      end
      body_prot, payload, legs = Naalp::COSE.parse_sign_raw(obj_bytes)
      bv = Naalp::CBOR.decode_bounded(payload, MAX_NESTING_DEPTH)
      raise EnvelopeError.new("Malformed", "body not a map") unless bv.is_a?(M)

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
      if o.channel > 19 || o.effect > 3 || o.profile < 1 || o.profile > 3
        raise EnvelopeError.new("RangeError", "field out of range")
      end

      halg, hsigner, hprofile, hversion = parse_protected(body_prot)
      raise EnvelopeError.new("UnsupportedVersion", "bad naalp-version") if hversion != NAALP_VERSION
      if hsigner != o.signer || hprofile != o.profile
        raise EnvelopeError.new("HeaderBodyMismatch", "protected header disagrees with body")
      end
      unless o.cext.nil?
        o.cext.pairs.each do |k, v|
          unless k.is_a?(U)
            raise EnvelopeError.new("UnknownCriticalExt", "critical extension key not a uint")
          end
          # RecheckKey (13) is an envelope-recognized critical key: a critical recheck naming an
          # UNKNOWN procedure id is rejected fail-closed (the critical-extension rule reaching the
          # procedure it names, T1.3); a known procedure id is recognized regardless of the caller's
          # known_cext set. A NON-critical recheck (ext, field 11) is never rejected here -- an
          # unknown non-critical procedure is ignored per the may-ignore rule (handled elsewhere).
          if k.v == RECHECK_KEY
            unless v.is_a?(U)
              raise EnvelopeError.new("Malformed", "recheck procedure id not a uint")
            end
            unless is_known_recheck_procedure(v.v)
              raise EnvelopeError.new("UnknownCriticalExt", "unrecognized critical recheck procedure")
            end
            next
          end
          unless known_cext.key?(k.v)
            raise EnvelopeError.new("UnknownCriticalExt", "unrecognized critical extension")
          end
        end
      end

      unless rotation_object?(o.channel, o.kind)
        raise EnvelopeError.new("UnknownKind", "tag-98 permitted only for the Identity Rotation object")
      end
      if kind_validator.nil? || !kind_validator.call(o.channel, o.kind)
        raise EnvelopeError.new("UnknownKind", "kind/channel not a registered surface")
      end
      raise EnvelopeError.new("Malformed", "composite-inside-rotation is undecided") if composite_alg?(halg)
      raise EnvelopeError.new("KeyAlgMismatch", "body header alg is not the new key alg") if halg != new_alg

      raise EnvelopeError.new("RotationUnauthorized", "rotation must carry exactly two legs") if legs.length != 2
      old_leg_alg = Naalp::COSE.alg_from_protected(legs[0][0])
      new_leg_alg = Naalp::COSE.alg_from_protected(legs[1][0])
      if composite_alg?(old_leg_alg) || composite_alg?(new_leg_alg)
        raise EnvelopeError.new("Malformed", "composite leg in a rotation")
      end
      if old_leg_alg != old_alg || new_leg_alg != new_alg
        raise EnvelopeError.new("RotationUnauthorized", "legs not in (old, new) order")
      end

      new_level, nknown = Naalp::COSE.alg_level(new_leg_alg)
      raise EnvelopeError.new("UnknownAlg", "unregistered alg") unless nknown
      if new_level < Naalp::COSE.profile_min_level(profile)
        raise EnvelopeError.new("ProfileDowngrade", "new-leg level below the profile minimum")
      end
      if ROTATION_OLD_LEG_FLOOR_APPLIES
        old_level, oknown = Naalp::COSE.alg_level(old_leg_alg)
        raise EnvelopeError.new("UnknownAlg", "unregistered alg") unless oknown
        if old_level < Naalp::COSE.profile_min_level(profile)
          raise EnvelopeError.new("ProfileDowngrade", "old-leg level below the profile minimum")
        end
      end

      old_tbs = Naalp::COSE.signature_to_be_signed(body_prot, old_leg_alg, payload)
      unless Naalp::COSE.cose_verify1_raw(old_leg_alg, old_pk, old_tbs, legs[0][1])
        raise EnvelopeError.new("RotationUnauthorized", "old leg does not verify")
      end
      new_tbs = Naalp::COSE.signature_to_be_signed(body_prot, new_leg_alg, payload)
      unless Naalp::COSE.cose_verify1_raw(new_leg_alg, new_pk, new_tbs, legs[1][1])
        raise EnvelopeError.new("RotationUnauthorized", "new leg does not verify")
      end
      o
    end

    # --- NA-IETF-1 producing-boundary disclosure (OPTIONAL, self-asserted ext key 15, §2.5.4) -------

    # The ext extension key under which an object OPTIONALLY carries a per-object producing-boundary
    # disclosure (design.md §2.5.4, NA-IETF-1): the trust boundary that emitted the object and whether
    # that boundary OBSERVED the event it describes first-hand or is RELAYING a report of it. It rides
    # the NON-CRITICAL ext map (field 11): a verifier that does not understand it, or that reads a
    # malformed value, IGNORES the entry and the object still verifies (may-ignore). Because ext is
    # part of the signed body/payload, the disclosure is covered by the SIGNER's own COSE_Sign1
    # signature -- a SELF-ASSERTED claim. 15 collides with neither the safety-label ext key 1 (§6.4),
    # the recheck ext/cext key 13 (§2.5.1), nor the signer-counter ext key 14 (§2.5.2). Byte-identical
    # to impl/go, impl/rust and impl/python.
    PRODUCING_BOUNDARY_KEY = 15

    # The producing-boundary kind (§2.5.4): a closed enum naming whether the emitting boundary
    # witnessed the event directly or is relaying a report of it.
    PRODUCING_BOUNDARY_OBSERVED = 1   # this boundary witnessed the event directly (first-hand)
    PRODUCING_BOUNDARY_REPORTED = 2   # this boundary is relaying a report it did not witness

    # The producing-boundary value sub-map keys (§2.5.4).
    PB_FIELD_BOUNDARY  = 1   # bstr -- the emitting trust boundary (party id)
    PB_FIELD_KIND      = 2   # 1 observed / 2 reported
    PB_FIELD_REPORTING = 3   # bstr -- report origin; present iff kind == reported

    # A decoded producing-boundary disclosure (PRODUCING_BOUNDARY_KEY, §2.5.4). #boundary is the
    # emitting trust boundary (the same bstr party-id form as Object#signer). #kind is
    # PRODUCING_BOUNDARY_OBSERVED or PRODUCING_BOUNDARY_REPORTED. #reporting names the report origin
    # and is non-nil ONLY when kind is PRODUCING_BOUNDARY_REPORTED (an observer relays from no one).
    class ProducingBoundary
      attr_accessor :boundary, :kind, :reporting

      def initialize(boundary, kind, reporting = nil)
        @boundary = boundary.dup.force_encoding(Encoding::BINARY)
        @kind = kind
        @reporting = reporting.nil? ? nil : reporting.dup.force_encoding(Encoding::BINARY)
      end

      def ==(other)
        other.is_a?(ProducingBoundary) && boundary == other.boundary && kind == other.kind &&
          reporting == other.reporting
      end
    end

    # Return [ProducingBoundary, true] iff `o` carries a WELL-FORMED producing-boundary disclosure in
    # the non-critical ext map (field 11, PRODUCING_BOUNDARY_KEY): a non-empty boundary (key 1), a
    # kind (key 2) in {observed, reported}, and a reporting-boundary (key 3) absent unless the kind is
    # reported. A malformed value is IGNORED -- returns [nil, false], NEVER raising (may-ignore). An
    # absent disclosure returns [nil, false]. An unrecognized sub-key is ignored and does not by itself
    # make an otherwise well-formed value malformed.
    def producing_boundary(o)
      return [nil, false] if o.ext.nil?
      val = nil
      found = false
      o.ext.pairs.each do |k, v|
        if k.is_a?(U) && k.v == PRODUCING_BOUNDARY_KEY
          val = v
          found = true
          break
        end
      end
      return [nil, false] unless found && val.is_a?(M)

      boundary = nil
      kind = nil
      reporting = nil
      have_reporting = false
      val.pairs.each do |k, v|
        return [nil, false] unless k.is_a?(U)
        case k.v
        when PB_FIELD_BOUNDARY
          return [nil, false] unless v.is_a?(B)
          boundary = v.v
        when PB_FIELD_KIND
          return [nil, false] unless v.is_a?(U)
          kind = v.v
        when PB_FIELD_REPORTING
          return [nil, false] unless v.is_a?(B)
          reporting = v.v
          have_reporting = true
        else
          # an unrecognized sub-key -- may-ignore. It does not surface a disclosure of its own and
          # does not invalidate a well-formed {boundary, kind, reporting?} core.
        end
      end
      # well-formedness (§2.5.4). Any failure returns [nil, false] (may-ignore), never an error.
      return [nil, false] if boundary.nil? || boundary.empty?
      return [nil, false] if kind != PRODUCING_BOUNDARY_OBSERVED && kind != PRODUCING_BOUNDARY_REPORTED
      if have_reporting && kind != PRODUCING_BOUNDARY_REPORTED
        return [nil, false] # a reporting-boundary under observed: an observer relays from no one
      end
      [ProducingBoundary.new(boundary, kind, have_reporting ? reporting : nil), true]
    end

    # Name `pb` as `o`'s producing-boundary disclosure in the NON-CRITICAL ext map (field 11), covered
    # by the signer's COSE_Sign1 signature. Creates the ext carrier if absent and leaves any other
    # extension entries intact. The reporting-boundary is emitted ONLY when non-nil AND the kind is
    # reported, so a caller cannot accidentally emit a malformed observed-with-reporting disclosure (an
    # observer relays from no one). Sub-map keys are appended in ascending order; encode emits
    # canonical CBOR regardless, so the object stays deterministic.
    def set_producing_boundary(o, pb)
      sub = [[U.new(PB_FIELD_BOUNDARY), B.new(pb.boundary)], [U.new(PB_FIELD_KIND), U.new(pb.kind)]]
      if !pb.reporting.nil? && pb.kind == PRODUCING_BOUNDARY_REPORTED
        sub << [U.new(PB_FIELD_REPORTING), B.new(pb.reporting)]
      end
      entry = [U.new(PRODUCING_BOUNDARY_KEY), M.new(sub)]
      if o.ext.nil?
        o.ext = M.new([entry])
        return
      end
      new_pairs = []
      replaced = false
      o.ext.pairs.each do |k, v|
        if k.is_a?(U) && k.v == PRODUCING_BOUNDARY_KEY
          new_pairs << entry
          replaced = true
        else
          new_pairs << [k, v]
        end
      end
      new_pairs << entry unless replaced
      o.ext = M.new(new_pairs)
    end
  end
end
