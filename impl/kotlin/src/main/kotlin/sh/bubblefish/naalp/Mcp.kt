// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp

//
// The NAALP-MCP binding profile for the Kotlin SDK (design.md §19; Companion-Spec Requirement 6.1) — a
// draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
// signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
// (envelope §2) on the Bridge channel, and it REUSES the closed effect lattice (Policy), the approval +
// single-use consume ledger (Approval), and the T1 content-id framing (§2.3) unchanged.
//
// What the profile adds is the governance MCP itself lacks. The MCP specification states plainly that a
// tool's annotations are unenforced hints a malicious server can lie about — "clients MUST consider tool
// annotations to be untrusted unless they come from trusted servers". This profile turns that anonymous,
// untrusted hint into a SIGNED effect claim by a named key:
//
//   - CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are carried
//     OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization identity —
//     the wrapping signer is the authority (R-14.6).
//   - PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice (read_only <
//     idempotent_write < non_idempotent_write < destructive). Because the spine carries no CBOR boolean
//     (design §3.1), each JSON hint is transcribed as the uint 1/0; an ABSENT hint takes its MCP default.
//     destructiveHint's default of TRUE is why an un-annotated write maps to destructive — fail-closed.
//   - THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's DECLARED
//     effect, under its ML-DSA signature. A verifier independently recomputes the annotation-derived effect
//     and enforces the MORE SEVERE of the two (resolveEnforcedEffect — the good-regulator attenuator: a
//     disagreeing input collapses UP, never down). A signer that DECLARES BELOW its own carried annotations
//     is rejected fail-closed (EffectUnderDeclared); an annotation set mapping outside the lattice is
//     rejected (MalformedAnnotation), never defaulted to benign.
//   - THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding (tool_id +
//     args_id). A changed tool description or changed arguments yields a new content id and invalidates a
//     prior approval (Requirement 6.1), reusing the §7 Approval + consume ledger.
//
// Every check is fail-closed (§15). Ported from impl/go/mcp (cross-read against impl/python/naalp/mcp.py);
// the byte surface (annotation encoding, the mapping table, tool-call bodies/content-ids, call bindings,
// the resolution verdicts, the edge cases) is graded against the shared vectors/mcp/cases.json. The signed
// governance path (verifyToolCall / authorizeCall) uses real deterministic ML-DSA-65 and is demonstrated
// in isolation only (the corpus carries no signed vector).
//
object Mcp {

    // Channel binding, the tier-1 kind code, and the tier for the MCP wrapper (design §6.1). McpToolCall
    // is kind 1 on the Bridge channel — a named escalation over the frozen baseline Carriage kind (0),
    // which stays untouched (R-15A.2).
    const val CHANNEL_BRIDGE = 0x000DL // Bridge channel (foreign carriage lives here)
    const val KIND_MCP_TOOL_CALL = 1L  // tier-1 kind code (baseline Carriage is kind 0)
    const val TIER = 1L                // a named escalation adding the governed MCP wrapper (R-15A.2)

    // Annotation CBOR keys inside a naalp-mcp-annotations map. Each value is the uint 1 (true) / 0 (false)
    // — the spine carries no CBOR boolean (design §3.1).
    const val KEY_READ_ONLY = 1L    // MCP readOnlyHint
    const val KEY_DESTRUCTIVE = 2L  // MCP destructiveHint
    const val KEY_IDEMPOTENT = 3L   // MCP idempotentHint
    const val KEY_OPEN_WORLD = 4L   // MCP openWorldHint (ADVISORY — not an effect determinant)

    // MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
    // write maps to destructive — the fail-closed default.
    const val DEFAULT_READ_ONLY = false
    const val DEFAULT_DESTRUCTIVE = true
    const val DEFAULT_IDEMPOTENT = false

    // ---- the transcribed MCP annotation set (naalp-mcp-annotations) ------------------------------

    // The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL: null
    // means the hint was absent (the MCP default applies in the mapping), so an absent hint and a present
    // false are distinct on the wire though they may resolve to the same effect. openWorld is carried for
    // accountability but never enters the effect mapping (design §5). Kotlin's nullable Boolean is the
    // idiom for the Go `*bool`, so no BoolPtr helper is needed.
    class Annotations(
        var readOnly: Boolean?,     // MCP readOnlyHint
        var destructive: Boolean?,  // MCP destructiveHint
        var idempotent: Boolean?,   // MCP idempotentHint
        var openWorld: Boolean?,    // MCP openWorldHint (advisory only)
    ) {
        // Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1.
        fun toValue(): Cbor.M {
            val pairs = ArrayList<Cbor.Pair>(4)
            readOnly?.let { pairs.add(Cbor.Pair(Cbor.U(KEY_READ_ONLY), Cbor.U(if (it) 1 else 0))) }
            destructive?.let { pairs.add(Cbor.Pair(Cbor.U(KEY_DESTRUCTIVE), Cbor.U(if (it) 1 else 0))) }
            idempotent?.let { pairs.add(Cbor.Pair(Cbor.U(KEY_IDEMPOTENT), Cbor.U(if (it) 1 else 0))) }
            openWorld?.let { pairs.add(Cbor.Pair(Cbor.U(KEY_OPEN_WORLD), Cbor.U(if (it) 1 else 0))) }
            return Cbor.M(pairs)
        }

        // The deterministic-CBOR bytes of the annotation map (keys sorted by encode).
        fun encode(): ByteArray = Cbor.encode(toValue())
    }

    // Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a non-uint
    // key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a duplicate key, or an
    // annotation key outside the closed mapping {1,2,3,4}. Such a set would map outside the closed lattice,
    // so it is rejected, never defaulted to benign (AC-6.1.2).
    fun annotationsFromValue(v: Cbor.Value): Annotations {
        if (v !is Cbor.M) throw NaalpException("MalformedAnnotation", "annotation set is not a map")
        val a = Annotations(null, null, null, null)
        val seen = HashSet<Long>()
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("MalformedAnnotation", "non-uint annotation key")
            val u = p.v
            if (u !is Cbor.U || u.v > 1L) throw NaalpException("MalformedAnnotation", "annotation hint value is outside {0,1}")
            if (!seen.add(k.v)) throw NaalpException("MalformedAnnotation", "duplicate annotation key")
            val flag = u.v == 1L
            when (k.v) {
                KEY_READ_ONLY -> a.readOnly = flag
                KEY_DESTRUCTIVE -> a.destructive = flag
                KEY_IDEMPOTENT -> a.idempotent = flag
                KEY_OPEN_WORLD -> a.openWorld = flag
                else -> throw NaalpException("MalformedAnnotation", "annotation key outside the closed mapping")
            }
        }
        return a
    }

    // ---- the published annotation -> effect mapping table (design §6.1) --------------------------

    // Map a tool's transcribed annotations to the closed four-effect lattice by the published table
    // (vectors/registry/mcp.csv), applying the MCP default for each absent hint:
    //
    //   readOnlyHint true                                  -> read_only
    //   readOnlyHint false, destructiveHint true           -> destructive
    //   readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
    //   readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write
    //
    // An absent readOnlyHint defaults false (a write); an absent destructiveHint defaults TRUE
    // (destructive) — so a tool with no annotations maps to destructive, the fail-closed collapse to the
    // most-severe. openWorldHint is never consulted (design §5).
    fun mapAnnotationsToEffect(a: Annotations): Long {
        val ro = a.readOnly ?: DEFAULT_READ_ONLY
        val de = a.destructive ?: DEFAULT_DESTRUCTIVE
        val idem = a.idempotent ?: DEFAULT_IDEMPOTENT
        if (ro) return Policy.READ_ONLY
        if (de) return Policy.DESTRUCTIVE
        if (idem) return Policy.IDEMPOTENT_WRITE
        return Policy.NON_IDEMPOTENT_WRITE
    }

    // The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect and
    // the wrapping signer's declared effect, return (enforced, mismatch): the enforced effect is the MORE
    // SEVERE (equal to `declared` on success), and mismatch is whether the two disagreed (attributable to
    // the wrapping signer). A declared value outside the closed lattice is EffectOutsideLattice; a declared
    // value BELOW the annotation-derived effect is EffectUnderDeclared (a wrapper's declared effect can
    // never sit under its own carried annotations' mapping).
    fun resolveEnforcedEffect(annotationMapped: Long, declared: Long): kotlin.Pair<Long, Boolean> {
        if (declared > Policy.DESTRUCTIVE) {
            throw NaalpException("EffectOutsideLattice", "declared effect outside the closed four-effect lattice")
        }
        if (declared < annotationMapped) {
            throw NaalpException("EffectUnderDeclared", "declared effect is below the annotation-mapped effect")
        }
        return kotlin.Pair(declared, declared != annotationMapped)
    }

    // ---- the wrapper body (naalp-mcp-tool-call) --------------------------------------------------

    // The wrapper body (envelope field 10). tool and args are the foreign MCP bytes, carried
    // octet-for-octet (carriage, not adoption); annotations is the wrapping signer's transcription of the
    // tool's hints, on which the mapping operates. The wrapper's OWN effect is envelope field 7, not a
    // body field.
    class ToolCall(tool: ByteArray, args: ByteArray, val annotations: Annotations) {
        val tool: ByteArray = tool.copyOf()
        val args: ByteArray = args.copyOf()

        fun toMap(): Cbor.M = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.B(tool)),
                Cbor.Pair(Cbor.U(2), Cbor.B(args)),
                Cbor.Pair(Cbor.U(3), annotations.toValue()),
            )
        )

        // Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}.
        fun bytes(): ByteArray = Cbor.encode(toMap())

        // The tool-call body's content id (T1 framing).
        fun contentId(): ByteArray = Cbor.contentId(bytes())

        // The (tool_id, args_id) binding whose content id an approval binds for this call.
        fun callBinding(): CallBinding = newCallBinding(tool, args)

        // Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel, kind
        // McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as field 10,
        // and `causes`. The caller signs it; the signer BECOMES accountable for the declared effect and the
        // annotation transcription. A declared effect outside the closed lattice is rejected fail-closed.
        // Under-declaration is NOT rejected here — it is a signed, attributable claim whose inconsistency
        // verifyToolCall surfaces as EffectUnderDeclared at the enforcement point.
        fun envelopeObject(signer: ByteArray, created: Long, profile: Long, declared: Long, causes: List<ByteArray>): Envelope.Object {
            if (declared > Policy.DESTRUCTIVE) {
                throw NaalpException("EffectOutsideLattice", "declared effect outside the closed lattice")
            }
            return Envelope.Object(
                kind = KIND_MCP_TOOL_CALL, channel = CHANNEL_BRIDGE, signer = signer,
                created = created, effect = declared, body = toMap(), tier = TIER,
                profile = profile, causes = causes,
            )
        }
    }

    // Parse an envelope object body (a decoded CBOR value) into a ToolCall. A body that is not exactly
    // {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a
    // malformed annotation set is MalformedAnnotation. Fail-closed.
    fun toolCallFromBody(v: Cbor.Value): ToolCall {
        if (v !is Cbor.M) throw NaalpException("ToolCallMalformed", "tool-call body is not a map")
        var tool: ByteArray? = null
        var args: ByteArray? = null
        var ann: Annotations? = null
        for (p in v.pairs) {
            val k = p.k
            if (k !is Cbor.U) throw NaalpException("ToolCallMalformed", "non-uint tool-call body key")
            when (k.v) {
                1L -> { val b = p.v; if (b !is Cbor.B) throw NaalpException("ToolCallMalformed", "tool is not a bstr"); tool = b.v }
                2L -> { val b = p.v; if (b !is Cbor.B) throw NaalpException("ToolCallMalformed", "args is not a bstr"); args = b.v }
                3L -> ann = annotationsFromValue(p.v) // throws MalformedAnnotation
                else -> throw NaalpException("ToolCallMalformed", "unknown tool-call body field ${k.v}")
            }
        }
        if (tool == null || args == null || ann == null) {
            throw NaalpException("ToolCallMalformed", "tool-call body missing a mandatory field")
        }
        return ToolCall(tool, args, ann)
    }

    // ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

    // Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content id.
    // An approval binds the content id of THIS binding, so a changed tool description (new tool_id) OR
    // changed arguments (new args_id) yields a new call content id and invalidates a prior approval bound
    // to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3).
    class CallBinding(toolId: ByteArray, argsId: ByteArray) {
        val toolId: ByteArray = toolId.copyOf() // multihash(0x20, SHA-384(tool bytes))
        val argsId: ByteArray = argsId.copyOf() // multihash(0x20, SHA-384(args bytes))

        fun toMap(): Cbor.M = Cbor.M(
            listOf(
                Cbor.Pair(Cbor.U(1), Cbor.B(toolId)),
                Cbor.Pair(Cbor.U(2), Cbor.B(argsId)),
            )
        )

        // Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}.
        fun bytes(): ByteArray = Cbor.encode(toMap())

        // The call content id an approval binds.
        fun contentId(): ByteArray = Cbor.contentId(bytes())
    }

    // Compute the binding from the raw tool and args bytes.
    fun newCallBinding(tool: ByteArray, args: ByteArray): CallBinding =
        CallBinding(Cbor.contentId(tool), Cbor.contentId(args))

    // ---- kind validation (composes with the frozen baseline) -------------------------------------

    // Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall).
    fun kindValidator(channel: Long, kind: Long): Boolean = channel == CHANNEL_BRIDGE && kind == KIND_MCP_TOOL_CALL

    // Accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator an MCP-aware endpoint
    // passes to Envelope.verify. A baseline-only endpoint using the baseline validator alone correctly
    // rejects an McpToolCall as UnknownKind (fail-closed).
    fun composedKindValidator(channel: Long, kind: Long): Boolean {
        val baseline = try {
            Channels.lookup(channel, kind); true
        } catch (e: NaalpException) {
            false
        }
        return baseline || kindValidator(channel, kind)
    }

    // ---- verified tool call --------------------------------------------------------------------

    // An MCP tool call that has passed envelope verification and effect resolution. It carries the enforced
    // effect (the more-severe value C5 authorizes on), whether the annotation and declared effect disagreed
    // (mismatch — attributable to the signer), and the parsed tool call.
    class Resolved(
        val contentId: ByteArray,
        val signer: ByteArray,
        val toolCall: ToolCall,
        val annotationMapped: Long,
        val declared: Long,
        val enforced: Long,
        val mismatch: Boolean,
    )

    // Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the signed
    // object with real crypto (Envelope.verify against the composed validator — content id, ranges,
    // header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge McpToolCall; (3) parses
    // the tool-call body (rejecting a malformed annotation set); (4) recomputes the annotation-derived
    // effect from the CARRIED annotations, independent of the declared effect; (5) resolves the enforced
    // effect to the MORE SEVERE, rejecting under-declaration. The enforced effect equals the declared
    // envelope effect on success, so the object's field 7 is the correct C5 authorization input. Any
    // failure throws its named error and authorizes nothing (fail-closed).
    fun verifyToolCall(profile: Long, alg: Int, pubkey: ByteArray, signedObj: ByteArray): Resolved {
        val validator = Envelope.KindValidator { ch, k -> composedKindValidator(ch, k) }
        val o = Envelope.verify(profile, alg, pubkey, validator, signedObj)
        if (o.channel != CHANNEL_BRIDGE || o.kind != KIND_MCP_TOOL_CALL || o.tier != TIER) {
            throw NaalpException("ToolCallMalformed", "not a tier-1 Bridge McpToolCall")
        }
        val tc = toolCallFromBody(o.body)
        val mapped = mapAnnotationsToEffect(tc.annotations)
        val declared = o.effect // Envelope.verify already range-checked field 7 to 0..3
        val (enforced, mismatch) = resolveEnforcedEffect(mapped, declared)
        val id = o.id ?: throw NaalpException("Malformed", "verified object has no content id")
        return Resolved(id, o.signer, tc, mapped, declared, enforced, mismatch)
    }

    // ---- the per-call approval gate (reuses the §7 Approval + consume ledger) ---------------------

    // Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
    // EXACT call binding content id (tool_id + args_id) — so it satisfies neither a call with different
    // arguments nor a call whose tool description changed (Requirement 6.1) — its granted effect must cover
    // the call's ENFORCED (more-severe) effect, it must be unexpired at `now`, and it is consumed
    // single-use by `by` through the §7 ledger. Precedence and fail-closed behaviour mirror the spine: a
    // non-matching or under-granting approval denies ApprovalRequired with no ledger append; an
    // already-spent approval denies AlreadyConsumed; the consume (the single state change) happens only
    // when every check holds.
    fun authorizeCall(
        r: Resolved,
        appr: Approval.ApprovalRecord,
        apprAlg: Int,
        apprPubkey: ByteArray,
        apprSig: ByteArray,
        by: String,
        now: Long,
        ledger: Approval.Ledger,
    ) {
        val callCID = r.toolCall.callBinding().contentId()
        try {
            Approval.verifyApproval(appr, apprAlg, apprPubkey, apprSig, callCID, now)
        } catch (e: NaalpException) {
            // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
            if (e.kind == "ApprovalMismatch") {
                throw NaalpException("ApprovalRequired", "approval does not bind this exact call")
            }
            throw e
        }
        if (!Policy.authorizes(appr.grant, r.enforced)) {
            throw NaalpException("ApprovalRequired", "the approval's granted effect does not cover the call")
        }
        ledger.consume(appr.id(), by) // AlreadyConsumed on replay (fail-closed, no double-spend)
    }
}
