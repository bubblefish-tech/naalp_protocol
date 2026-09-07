# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# NAALP-MCP binding profile for the Ruby SDK (design.md §19; Companion-Spec Requirement 6.1) -- a
# draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
# signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
# (envelope §2) on the Bridge channel, and it REUSES the closed effect lattice (policy), the approval +
# single-use consume ledger (approval), and the T1 content-id framing (§2.3) unchanged.
#
# What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that a
# tool's annotations are unenforced hints a malicious server can lie about -- "clients MUST consider
# tool annotations to be untrusted unless they come from trusted servers". This profile turns that
# anonymous, untrusted hint into a SIGNED effect claim by a named key:
#
#   - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are carried
#     OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization identity --
#     the wrapping signer is the authority (R-14.6).
#   - PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice
#     (read_only < idempotent_write < non_idempotent_write < destructive). Because the spine carries no
#     CBOR boolean (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT hint takes
#     its MCP default. destructiveHint's default of TRUE is why an un-annotated write maps to destructive
#     -- the fail-closed rule.
#   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
#     DECLARED effect, under its ML-DSA signature. A verifier independently recomputes the
#     annotation-derived effect and enforces the MORE SEVERE of the two (resolve_enforced_effect -- the
#     good-regulator attenuator: a disagreeing input collapses UP, never down). A signer that DECLARES
#     BELOW its own carried annotations is rejected fail-closed (EffectUnderDeclared); an annotation set
#     mapping outside the lattice is rejected (MalformedAnnotation), never defaulted to benign.
#   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
#     (tool_id + args_id). A changed tool description or changed arguments yields a new content id and
#     invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
#
# Every check is fail-closed (§15). Ported from impl/go/mcp (cross-read against impl/python/naalp/mcp.py).
# The byte surface (annotation encoding, the mapping table, tool-call bodies/content-ids, call bindings,
# the resolution verdicts) is graded against the shared vectors/mcp/cases.json; the signed governance
# path (verify_tool_call / authorize_call) uses real deterministic ML-DSA-65 and is demonstrated in
# isolation only (the corpus carries no signed vector).
require_relative 'cbor'
require_relative 'cose'
require_relative 'envelope'
require_relative 'policy'
require_relative 'channels'
require_relative 'approval'

module Naalp
  module MCP
    U = Naalp::CBOR::U
    B = Naalp::CBOR::B
    M = Naalp::CBOR::M

    # Channel binding, the tier-1 kind code, and the tier for the MCP wrapper (design §6.1). McpToolCall
    # is kind 1 on the Bridge channel -- a named escalation over the frozen baseline Carriage kind (0),
    # which stays untouched (R-15A.2).
    CHANNEL_BRIDGE = 0x000D      # Bridge channel (foreign carriage lives here)
    KIND_MCP_TOOL_CALL = 1       # tier-1 kind code (baseline Carriage is kind 0)
    TIER = 1                     # a named escalation adding the governed MCP wrapper (R-15A.2)

    # Annotation CBOR keys inside a naalp-mcp-annotations map. Each value is the uint 1 (true) / 0
    # (false) -- the spine carries no CBOR boolean (design §3.1).
    KEY_READ_ONLY = 1            # MCP readOnlyHint
    KEY_DESTRUCTIVE = 2          # MCP destructiveHint
    KEY_IDEMPOTENT = 3           # MCP idempotentHint
    KEY_OPEN_WORLD = 4           # MCP openWorldHint (ADVISORY -- not an effect determinant)

    # MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
    # write maps to destructive -- the fail-closed default.
    DEFAULT_READ_ONLY = false
    DEFAULT_DESTRUCTIVE = true
    DEFAULT_IDEMPOTENT = false

    # A named, fail-closed MCP-profile error; #kind is the stable error kind (mirroring the Go/Rust/
    # Python kinds MalformedAnnotation, EffectUnderDeclared, EffectOutsideLattice, ToolCallMalformed,
    # and the reused §7 ApprovalRequired).
    class McpError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    module_function

    # T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets), identical
    # to the spine framing over raw bytes.
    def content_id(b)
      Naalp::CBOR.content_id(b.dup.force_encoding(Encoding::BINARY))
    end

    # ---- the transcribed MCP annotation set (naalp-mcp-annotations) -------------------------------

    # The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL: nil
    # means the hint was absent (the MCP default applies in the mapping), so an absent hint and a
    # present false are distinct on the wire though they may resolve to the same effect. open_world is
    # carried for accountability but never enters the effect mapping (design §5).
    class Annotations
      attr_accessor :read_only, :destructive, :idempotent, :open_world

      def initialize(read_only: nil, destructive: nil, idempotent: nil, open_world: nil)
        @read_only = read_only       # MCP readOnlyHint
        @destructive = destructive   # MCP destructiveHint
        @idempotent = idempotent     # MCP idempotentHint
        @open_world = open_world     # MCP openWorldHint (advisory only)
      end

      # Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1.
      def to_value
        pairs = []
        pairs << [U.new(KEY_READ_ONLY), U.new(@read_only ? 1 : 0)] unless @read_only.nil?
        pairs << [U.new(KEY_DESTRUCTIVE), U.new(@destructive ? 1 : 0)] unless @destructive.nil?
        pairs << [U.new(KEY_IDEMPOTENT), U.new(@idempotent ? 1 : 0)] unless @idempotent.nil?
        pairs << [U.new(KEY_OPEN_WORLD), U.new(@open_world ? 1 : 0)] unless @open_world.nil?
        M.new(pairs)
      end

      # The deterministic-CBOR bytes of the annotation map (keys sorted by encode).
      def encode
        Naalp::CBOR.encode(to_value)
      end
    end

    # Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a
    # non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a
    # duplicate key, or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map
    # outside the closed lattice, so it is rejected, never defaulted to benign (AC-6.1.2).
    def annotations_from_value(v)
      raise McpError.new("MalformedAnnotation", "annotation set is not a map") unless v.is_a?(M)
      a = Annotations.new
      seen = {}
      v.pairs.each do |k, val|
        raise McpError.new("MalformedAnnotation", "non-uint annotation key") unless k.is_a?(U)
        unless val.is_a?(U) && val.v <= 1 # a hint value outside {0,1} maps outside the lattice
          raise McpError.new("MalformedAnnotation", "annotation hint value is outside {0,1}")
        end
        raise McpError.new("MalformedAnnotation", "duplicate annotation key") if seen[k.v]
        seen[k.v] = true
        flag = val.v == 1
        case k.v
        when KEY_READ_ONLY
          a.read_only = flag
        when KEY_DESTRUCTIVE
          a.destructive = flag
        when KEY_IDEMPOTENT
          a.idempotent = flag
        when KEY_OPEN_WORLD
          a.open_world = flag
        else
          raise McpError.new("MalformedAnnotation", "annotation key outside the closed mapping")
        end
      end
      a
    end

    # ---- the published annotation -> effect mapping table (design §6.1) ---------------------------

    # Map a tool's transcribed annotations to the closed four-effect lattice by the published table,
    # applying the MCP default for each absent hint:
    #
    #     readOnlyHint true                                  -> read_only
    #     readOnlyHint false, destructiveHint true           -> destructive
    #     readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
    #     readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write
    #
    # An absent readOnlyHint defaults false (a write); an absent destructiveHint defaults TRUE
    # (destructive) -- so a tool with no annotations maps to destructive, the fail-closed collapse to
    # the most-severe. openWorldHint is never consulted (design §5).
    def map_annotations_to_effect(a)
      ro = a.read_only.nil? ? DEFAULT_READ_ONLY : a.read_only
      de = a.destructive.nil? ? DEFAULT_DESTRUCTIVE : a.destructive
      idem = a.idempotent.nil? ? DEFAULT_IDEMPOTENT : a.idempotent
      return Naalp::Policy::READ_ONLY if ro
      return Naalp::Policy::DESTRUCTIVE if de
      return Naalp::Policy::IDEMPOTENT_WRITE if idem
      Naalp::Policy::NON_IDEMPOTENT_WRITE
    end

    # The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect
    # and the wrapping signer's declared effect, return [enforced, mismatch] -- the enforced effect
    # being the MORE SEVERE (equal to `declared` on success), and mismatch whether the two disagreed
    # (attributable to the wrapping signer). A declared value outside the closed lattice is
    # EffectOutsideLattice; a declared value BELOW the annotation-derived effect is EffectUnderDeclared
    # (a wrapper's declared effect can never sit under its own carried annotations' mapping).
    def resolve_enforced_effect(annotation_mapped, declared)
      if declared > Naalp::Policy::DESTRUCTIVE
        raise McpError.new("EffectOutsideLattice", "declared effect outside the closed four-effect lattice")
      end
      if declared < annotation_mapped
        raise McpError.new("EffectUnderDeclared", "declared effect is below the annotation-mapped effect")
      end
      [declared, declared != annotation_mapped]
    end

    # ---- the wrapper body (naalp-mcp-tool-call) ---------------------------------------------------

    # The wrapper body (envelope field 10). `tool` and `args` are the foreign MCP bytes, carried
    # octet-for-octet (carriage, not adoption); `annotations` is the wrapping signer's transcription of
    # the tool's hints, on which the mapping operates. The wrapper's OWN effect is envelope field 7, not
    # a body field.
    class ToolCall
      attr_reader :tool, :args, :annotations

      def initialize(tool, args, annotations)
        @tool = tool.dup.force_encoding(Encoding::BINARY)
        @args = args.dup.force_encoding(Encoding::BINARY)
        @annotations = annotations
      end

      def to_map
        M.new([
          [U.new(1), B.new(@tool)],
          [U.new(2), B.new(@args)],
          [U.new(3), @annotations.to_value],
        ])
      end

      # Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.
      def bytes
        Naalp::CBOR.encode(to_map)
      end

      # The tool-call body's content id (T1 framing).
      def content_id
        Naalp::MCP.content_id(bytes)
      end

      # The (tool_id, args_id) binding whose content id an approval binds for this call.
      def call_binding
        Naalp::MCP.new_call_binding(@tool, @args)
      end

      # Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel,
      # kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as field
      # 10, and `causes`. The caller signs it; the signer BECOMES accountable for the declared effect
      # and the annotation transcription. A declared effect outside the closed lattice is rejected
      # fail-closed. Under-declaration is NOT rejected here -- it is a signed, attributable claim whose
      # inconsistency verify_tool_call surfaces as EffectUnderDeclared at the enforcement point.
      def envelope_object(signer, created, profile, declared, causes)
        if declared > Naalp::Policy::DESTRUCTIVE
          raise McpError.new("EffectOutsideLattice", "declared effect outside the closed lattice")
        end
        Naalp::Envelope::Object.new(
          kind: KIND_MCP_TOOL_CALL, channel: CHANNEL_BRIDGE, tier: TIER,
          signer: signer, created: created, effect: declared,
          causes: causes.to_a, profile: profile, body: to_map)
      end
    end

    # Sign an McpToolCall envelope object with a real deterministic ML-DSA key; the signer becomes
    # accountable for the declared effect and the carried annotations.
    def sign_tool_call(obj, alg, seed)
      Naalp::Envelope.sign(obj, alg, seed)
    end

    # Parse an envelope object body (a decoded cbor Value) into a ToolCall. A body that is not exactly
    # {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a
    # malformed annotation set is MalformedAnnotation. Fail-closed.
    def tool_call_from_body(v)
      raise McpError.new("ToolCallMalformed", "tool-call body is not a map") unless v.is_a?(M)
      tool = nil
      args = nil
      ann = nil
      have_ann = false
      v.pairs.each do |k, val|
        raise McpError.new("ToolCallMalformed", "non-uint tool-call body key") unless k.is_a?(U)
        case k.v
        when 1
          raise McpError.new("ToolCallMalformed", "tool is not a bstr") unless val.is_a?(B)
          tool = val.v
        when 2
          raise McpError.new("ToolCallMalformed", "args is not a bstr") unless val.is_a?(B)
          args = val.v
        when 3
          ann = annotations_from_value(val) # raises MalformedAnnotation
          have_ann = true
        else
          raise McpError.new("ToolCallMalformed", "unknown tool-call body field #{k.v}")
        end
      end
      if tool.nil? || args.nil? || !have_ann
        raise McpError.new("ToolCallMalformed", "tool-call body missing a mandatory field")
      end
      ToolCall.new(tool, args, ann)
    end

    # ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

    # Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content
    # id. An approval binds the content id of THIS binding, so a changed tool description (new tool_id)
    # OR changed arguments (new args_id) yields a new call content id and invalidates a prior approval
    # bound to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
    class CallBinding
      attr_reader :tool_id, :args_id

      def initialize(tool_id, args_id)
        @tool_id = tool_id.dup.force_encoding(Encoding::BINARY)
        @args_id = args_id.dup.force_encoding(Encoding::BINARY)
      end

      def to_map
        M.new([[U.new(1), B.new(@tool_id)], [U.new(2), B.new(@args_id)]])
      end

      # Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.
      def bytes
        Naalp::CBOR.encode(to_map)
      end

      # The call content id an approval binds.
      def content_id
        Naalp::MCP.content_id(bytes)
      end
    end

    # Compute the binding from the raw tool and args bytes.
    def new_call_binding(tool, args)
      CallBinding.new(content_id(tool), content_id(args))
    end

    # ---- kind validation (composes with the frozen baseline) --------------------------------------

    # Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).
    def kind_validator?(channel, kind)
      channel == CHANNEL_BRIDGE && kind == KIND_MCP_TOOL_CALL
    end

    def baseline_kind_validator?(channel, kind)
      Naalp::Channels.lookup(channel, kind)
      true
    rescue Naalp::Channels::UnknownKind
      false
    end

    # Accepts the frozen baseline kinds OR the tier-1 McpToolCall -- the validator an MCP-aware endpoint
    # passes to envelope.verify. A baseline-only endpoint using the baseline validator alone correctly
    # rejects an McpToolCall as UnknownKind (fail-closed).
    def composed_kind_validator(channel, kind)
      baseline_kind_validator?(channel, kind) || kind_validator?(channel, kind)
    end

    # ---- verified tool call -----------------------------------------------------------------------

    # An MCP tool call that has passed envelope verification and effect resolution. It carries the
    # enforced effect (the more-severe value C5 authorizes on), whether the annotation and declared
    # effect disagreed (mismatch -- attributable to signer), and the parsed tool call.
    Resolved = Struct.new(:content_id, :signer, :tool_call, :annotation_mapped, :declared, :enforced,
                          :mismatch)

    # Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the signed
    # object with real crypto (envelope.verify against the composed validator -- content id, ranges,
    # header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge McpToolCall; (3) parses
    # the tool-call body (rejecting a malformed annotation set); (4) recomputes the annotation-derived
    # effect from the CARRIED annotations, independent of the declared effect; (5) resolves the enforced
    # effect to the MORE SEVERE, rejecting under-declaration. The enforced effect equals the declared
    # envelope effect on success, so the object's field 7 is the correct C5 authorization input. Any
    # failure returns its named error and authorizes nothing (fail-closed).
    def verify_tool_call(profile, alg, pubkey, signed_obj)
      validator = ->(ch, k) { composed_kind_validator(ch, k) }
      o = Naalp::Envelope.verify(profile, alg, pubkey, validator, signed_obj)
      if o.channel != CHANNEL_BRIDGE || o.kind != KIND_MCP_TOOL_CALL || o.tier != TIER
        raise McpError.new("ToolCallMalformed", "not a tier-1 Bridge McpToolCall")
      end
      tc = tool_call_from_body(o.body)
      mapped = map_annotations_to_effect(tc.annotations)
      declared = o.effect # envelope.verify already range-checked field 7 to 0..3
      enforced, mismatch = resolve_enforced_effect(mapped, declared)
      Resolved.new(o.id, o.signer, tc, mapped, declared, enforced, mismatch)
    end

    # ---- the per-call approval gate (reuses §7 approval + consume ledger) --------------------------

    # Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
    # EXACT call binding content id (tool_id + args_id) -- so it satisfies neither a call with different
    # arguments nor a call whose tool description changed (Requirement 6.1) -- its granted effect must
    # cover the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it is consumed
    # single-use by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: a
    # non-matching or under-granting approval denies ApprovalRequired with no ledger append; an
    # already-spent approval denies AlreadyConsumed; the consume (the single state change) happens only
    # when every check holds. Returns nil on authorization.
    def authorize_call(r, appr, approver_alg, approver_pubkey, appr_sig, by, now, ledger)
      call_cid = r.tool_call.call_binding.content_id
      begin
        Naalp::Approval.verify_approval(appr, approver_alg, approver_pubkey, appr_sig, call_cid, now)
      rescue Naalp::Approval::ApprovalError => e
        # A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
        raise McpError.new("ApprovalRequired", "approval does not bind this exact call") if e.kind == "ApprovalMismatch"
        raise
      end
      unless Naalp::Policy.authorizes(appr.grant, r.enforced)
        raise McpError.new("ApprovalRequired", "the approval's granted effect does not cover the call")
      end
      ledger.consume(appr.id, by) # AlreadyConsumed on replay (fail-closed, no double-spend)
      nil
    end
  end
end
