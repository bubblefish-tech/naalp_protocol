// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
package sh.bubblefish.naalp;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * NAALP-MCP binding profile for the Java SDK (design.md §19; Companion-Spec Requirement 6.1) — a
 * draft-01 ADDITIVE tier-1 surface over the frozen spine. It introduces NO new envelope, encoding,
 * signature, identity, or audit mechanism (R-11.3): an MCP tool call is a normal N-AALP object
 * ({@link Envelope}) on the Bridge channel, and it REUSES the closed effect lattice ({@link Policy}),
 * the approval + single-use consume ledger ({@link Approval}), and the T1 content-id framing (§2.3)
 * unchanged.
 *
 * <p>What the profile adds is the governance MCP itself lacks. The MCP specification states plainly
 * that a tool's annotations are unenforced hints a malicious server can lie about — "clients MUST
 * consider tool annotations to be untrusted unless they come from trusted servers". This profile turns
 * that anonymous, untrusted hint into a SIGNED effect claim by a named key:
 *
 * <ul>
 *   <li>CARRIAGE, NOT ADOPTION. The MCP tool-definition bytes and the tool-call argument bytes are
 *       carried OCTET-FOR-OCTET; a foreign identity inside them never becomes an N-AALP authorization
 *       identity — the wrapping signer is the authority (R-14.6).
 *   <li>PUBLISHED MAPPING TABLE. The tool's annotations map to the closed four-effect lattice by
 *       {@link #mapAnnotationsToEffect} (the table in vectors/registry/mcp.csv). Because the spine
 *       carries no CBOR boolean (design §3.1), each hint is the uint 1/0; an ABSENT hint takes its MCP
 *       default. destructiveHint's default of TRUE is why an un-annotated write maps to destructive —
 *       the fail-closed default.
 *   <li>THE WRAPPING SIGNER IS ACCOUNTABLE. The wrapper's envelope effect (field 7) is the signer's
 *       DECLARED effect, under its ML-DSA signature. A verifier independently recomputes the
 *       annotation-derived effect and enforces the MORE SEVERE of the two
 *       ({@link #resolveEnforcedEffect} — the good-regulator attenuator: a disagreeing input collapses
 *       UP, never down). A signer that DECLARES BELOW its own carried annotations is rejected
 *       fail-closed (EffectUnderDeclared); an annotation set mapping outside the lattice is rejected
 *       (MalformedAnnotation), never defaulted to benign.
 *   <li>THE APPROVAL BINDS THE EXACT CALL. An approval binds the content id of the call binding
 *       (tool_id + args_id). A changed tool description or changed arguments yields a new content id
 *       and invalidates a prior approval (Requirement 6.1), reusing the §7 approval + consume ledger.
 * </ul>
 *
 * <p>Every check is fail-closed (§15). An independent transcription of impl/go/mcp (cross-checked
 * against impl/python/naalp/mcp): the byte surface (annotation encoding, mapping table, tool-call
 * bodies/content-ids, call bindings, resolution verdicts) is graded against vectors/mcp/cases.json;
 * the signed governance path ({@link #verifyToolCall} / {@link #authorizeCall}) uses real deterministic
 * ML-DSA-65 and is demonstrated in isolation (the corpus carries no signed vector).
 */
public final class Mcp {
    /** Bridge channel (foreign carriage lives here). */
    public static final long CHANNEL_BRIDGE = 0x000D;
    /** Tier-1 kind code (baseline Carriage is kind 0). */
    public static final long KIND_MCP_TOOL_CALL = 1;
    /** A named escalation adding the governed MCP wrapper (R-15A.2). */
    public static final long TIER = 1;

    // Annotation CBOR keys inside a naalp-mcp-annotations map. The value is the uint 1/0 (no CBOR bool).
    public static final long KEY_READ_ONLY = 1;    // MCP readOnlyHint
    public static final long KEY_DESTRUCTIVE = 2;   // MCP destructiveHint
    public static final long KEY_IDEMPOTENT = 3;   // MCP idempotentHint
    public static final long KEY_OPEN_WORLD = 4;   // MCP openWorldHint (ADVISORY — not an effect determinant)

    // MCP documented defaults for an ABSENT hint. destructiveHint defaults to TRUE, so an un-annotated
    // write maps to destructive — the fail-closed default.
    public static final boolean DEFAULT_READ_ONLY = false;
    public static final boolean DEFAULT_DESTRUCTIVE = true;
    public static final boolean DEFAULT_IDEMPOTENT = false;

    private Mcp() {}

    private static byte[] sha384(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-384").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-384 unavailable", e);
        }
    }

    /** T1 content-id framing multihash(0x20, SHA-384(b)) = 0x20 0x30 || SHA-384(b) (50 octets),
     * identical to the spine framing over raw bytes. */
    private static byte[] contentId(byte[] b) {
        byte[] d = sha384(b);
        byte[] out = new byte[2 + d.length];
        out[0] = 0x20;
        out[1] = 0x30;
        System.arraycopy(d, 0, out, 2, d.length);
        return out;
    }

    // ---- the transcribed MCP annotation set (naalp-mcp-annotations) -------------------------------

    /** The wrapping signer's transcription of a tool's MCP ToolAnnotations. Each hint is OPTIONAL:
     * {@code null} means the hint was absent (the MCP default applies in the mapping), so an absent
     * hint and a present false are distinct on the wire though they may resolve to the same effect.
     * {@code openWorld} is carried for accountability but never enters the effect mapping (design §5). */
    public static final class Annotations {
        public final Boolean readOnly;     // MCP readOnlyHint
        public final Boolean destructive;  // MCP destructiveHint
        public final Boolean idempotent;   // MCP idempotentHint
        public final Boolean openWorld;    // MCP openWorldHint (advisory only)

        public Annotations(Boolean readOnly, Boolean destructive, Boolean idempotent, Boolean openWorld) {
            this.readOnly = readOnly;
            this.destructive = destructive;
            this.idempotent = idempotent;
            this.openWorld = openWorld;
        }

        /** Encode the annotation set as its CBOR map: present hints only, uint keys -> uint 0/1. */
        public Cbor.M toValue() {
            List<Cbor.Pair> pairs = new ArrayList<>();
            if (readOnly != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(KEY_READ_ONLY), new Cbor.U(readOnly ? 1 : 0)));
            }
            if (destructive != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(KEY_DESTRUCTIVE), new Cbor.U(destructive ? 1 : 0)));
            }
            if (idempotent != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(KEY_IDEMPOTENT), new Cbor.U(idempotent ? 1 : 0)));
            }
            if (openWorld != null) {
                pairs.add(new Cbor.Pair(new Cbor.U(KEY_OPEN_WORLD), new Cbor.U(openWorld ? 1 : 0)));
            }
            return new Cbor.M(pairs);
        }

        /** The deterministic-CBOR bytes of the annotation map (keys sorted by encode). */
        public byte[] encode() {
            return Cbor.encode(toValue());
        }
    }

    /** Parse a naalp-mcp-annotations map. Rejects (MalformedAnnotation, fail-closed): a non-map, a
     * non-uint key, a non-uint value, a hint value outside {0,1} (it transcribes no boolean), a
     * duplicate key, or an annotation key outside the closed mapping {1,2,3,4}. Such a set would map
     * outside the closed lattice, so it is rejected, never defaulted to benign (AC-6.1.2). */
    public static Annotations annotationsFromValue(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("MalformedAnnotation", "annotation set is not a map");
        }
        Boolean ro = null;
        Boolean de = null;
        Boolean idem = null;
        Boolean ow = null;
        Set<Long> seen = new HashSet<>();
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) {
                throw new NaalpException("MalformedAnnotation", "non-uint annotation key");
            }
            if (!(p.val instanceof Cbor.U vu) || vu.v > 1) { // a hint value outside {0,1} maps outside the lattice
                throw new NaalpException("MalformedAnnotation", "annotation hint value is outside {0,1}");
            }
            long key = ku.v;
            if (!seen.add(key)) {
                throw new NaalpException("MalformedAnnotation", "duplicate annotation key");
            }
            boolean flag = vu.v == 1;
            if (key == KEY_READ_ONLY) {
                ro = flag;
            } else if (key == KEY_DESTRUCTIVE) {
                de = flag;
            } else if (key == KEY_IDEMPOTENT) {
                idem = flag;
            } else if (key == KEY_OPEN_WORLD) {
                ow = flag;
            } else {
                throw new NaalpException("MalformedAnnotation", "annotation key outside the closed mapping");
            }
        }
        return new Annotations(ro, de, idem, ow);
    }

    // ---- the published annotation -> effect mapping table (design §6.1) ---------------------------

    /** Map a tool's transcribed annotations to the closed four-effect lattice by the published table,
     * applying the MCP default for each absent hint:
     *
     * <pre>
     *   readOnlyHint true                                  -> read_only
     *   readOnlyHint false, destructiveHint true           -> destructive
     *   readOnlyHint false, destructiveHint false, idem T  -> idempotent_write
     *   readOnlyHint false, destructiveHint false, idem F  -> non_idempotent_write
     * </pre>
     *
     * An absent readOnlyHint defaults false (a write); an absent destructiveHint defaults TRUE
     * (destructive) — so a tool with no annotations maps to destructive, the fail-closed collapse to
     * the most-severe. openWorldHint is never consulted (design §5). */
    public static long mapAnnotationsToEffect(Annotations a) {
        boolean ro = a.readOnly == null ? DEFAULT_READ_ONLY : a.readOnly;
        boolean de = a.destructive == null ? DEFAULT_DESTRUCTIVE : a.destructive;
        boolean idem = a.idempotent == null ? DEFAULT_IDEMPOTENT : a.idempotent;
        if (ro) {
            return Policy.READ_ONLY;
        }
        if (de) {
            return Policy.DESTRUCTIVE;
        }
        if (idem) {
            return Policy.IDEMPOTENT_WRITE;
        }
        return Policy.NON_IDEMPOTENT_WRITE;
    }

    /** The result of the more-severe resolution: the enforced effect and whether the annotation-derived
     * and declared effects disagreed (attributable to the wrapping signer). */
    public static final class Resolution {
        public final long enforced;
        public final boolean mismatch;

        Resolution(long enforced, boolean mismatch) {
            this.enforced = enforced;
            this.mismatch = mismatch;
        }
    }

    /** The more-severe resolution (the good-regulator attenuator). Given the annotation-derived effect
     * and the wrapping signer's declared effect, return the enforced effect (the MORE SEVERE, equal to
     * {@code declared} on success) and whether the two disagreed. A declared value outside the closed
     * lattice is EffectOutsideLattice; a declared value BELOW the annotation-derived effect is
     * EffectUnderDeclared (a wrapper's declared effect can never sit under its own carried annotations'
     * mapping). */
    public static Resolution resolveEnforcedEffect(long annotationMapped, long declared) {
        if (declared > Policy.DESTRUCTIVE) {
            throw new NaalpException("EffectOutsideLattice", "declared effect outside the closed four-effect lattice");
        }
        if (declared < annotationMapped) {
            throw new NaalpException("EffectUnderDeclared", "declared effect is below the annotation-mapped effect");
        }
        return new Resolution(declared, declared != annotationMapped);
    }

    // ---- the wrapper body (naalp-mcp-tool-call) ---------------------------------------------------

    /** The wrapper body (envelope field 10). {@code tool} and {@code args} are the foreign MCP bytes,
     * carried octet-for-octet (carriage, not adoption); {@code annotations} is the wrapping signer's
     * transcription of the tool's hints, on which the mapping operates. The wrapper's OWN effect is
     * envelope field 7, not a body field. */
    public static final class ToolCall {
        public final byte[] tool;
        public final byte[] args;
        public final Annotations annotations;

        public ToolCall(byte[] tool, byte[] args, Annotations annotations) {
            this.tool = tool.clone();
            this.args = args.clone();
            this.annotations = annotations;
        }

        Cbor.M toMap() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(tool)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(args)),
                    new Cbor.Pair(new Cbor.U(3), annotations.toValue())));
        }

        /** Deterministic-CBOR encoding of the tool-call body {1:tool,2:args,3:annotations}. */
        public byte[] bytes() {
            return Cbor.encode(toMap());
        }

        /** The tool-call body's content id (T1 framing). */
        public byte[] contentId() {
            return Mcp.contentId(bytes());
        }

        /** The (tool_id, args_id) binding whose content id an approval binds for this call. */
        public CallBinding callBinding() {
            return newCallBinding(tool, args);
        }

        /** Build the (unsigned) N-AALP envelope object carrying this tool call: tier 1, Bridge channel,
         * kind McpToolCall, the wrapping signer's DECLARED effect as field 7, the tool-call body as
         * field 10, and {@code causes}. The caller signs it; the signer BECOMES accountable for the
         * declared effect and the annotation transcription. A declared effect outside the closed lattice
         * is rejected fail-closed. Under-declaration is NOT rejected here — it is a signed, attributable
         * claim whose inconsistency {@link #verifyToolCall} surfaces as EffectUnderDeclared at the
         * enforcement point. */
        public Envelope.Object envelopeObject(byte[] signer, long created, long profile, long declared,
                                              List<byte[]> causes) {
            if (declared > Policy.DESTRUCTIVE) {
                throw new NaalpException("EffectOutsideLattice", "declared effect outside the closed lattice");
            }
            return new Envelope.Object(KIND_MCP_TOOL_CALL, CHANNEL_BRIDGE, TIER, signer, created, declared,
                    profile, toMap(), causes, null, null);
        }
    }

    /** Sign an McpToolCall envelope object with a real deterministic ML-DSA key; the signer becomes
     * accountable for the declared effect and the carried annotations. */
    public static byte[] signToolCall(Envelope.Object obj, int alg, byte[] seed) {
        return Envelope.sign(obj, alg, seed);
    }

    /** Parse an envelope object body (a decoded cbor Value) into a ToolCall. A body that is not exactly
     * {1:tool bstr, 2:args bstr, 3:annotations map} with those value types is ToolCallMalformed; a
     * malformed annotation set is MalformedAnnotation. Fail-closed. */
    public static ToolCall toolCallFromBody(Cbor.Value v) {
        if (!(v instanceof Cbor.M m)) {
            throw new NaalpException("ToolCallMalformed", "tool-call body is not a map");
        }
        byte[] tool = null;
        byte[] args = null;
        Annotations ann = null;
        boolean haveAnn = false;
        for (Cbor.Pair p : m.pairs) {
            if (!(p.k instanceof Cbor.U ku)) {
                throw new NaalpException("ToolCallMalformed", "non-uint tool-call body key");
            }
            long k = ku.v;
            if (k == 1) {
                if (!(p.val instanceof Cbor.B b)) {
                    throw new NaalpException("ToolCallMalformed", "tool is not a bstr");
                }
                tool = b.v;
            } else if (k == 2) {
                if (!(p.val instanceof Cbor.B b)) {
                    throw new NaalpException("ToolCallMalformed", "args is not a bstr");
                }
                args = b.v;
            } else if (k == 3) {
                ann = annotationsFromValue(p.val); // raises MalformedAnnotation
                haveAnn = true;
            } else {
                throw new NaalpException("ToolCallMalformed", "unknown tool-call body field " + k);
            }
        }
        if (tool == null || args == null || !haveAnn) {
            throw new NaalpException("ToolCallMalformed", "tool-call body missing a mandatory field");
        }
        return new ToolCall(tool, args, ann);
    }

    // ---- the call binding an approval binds (naalp-mcp-call-binding) ------------------------------

    /** Names the exact tool call by content id: the tool bytes' content id AND the args bytes' content
     * id. An approval binds the content id of THIS binding, so a changed tool description (new tool_id)
     * OR changed arguments (new args_id) yields a new call content id and invalidates a prior approval
     * bound to the old one (Requirement 6.1 / AC-6.1.2, AC-6.1.3). */
    public static final class CallBinding {
        public final byte[] toolId;
        public final byte[] argsId;

        public CallBinding(byte[] toolId, byte[] argsId) {
            this.toolId = toolId.clone();
            this.argsId = argsId.clone();
        }

        Cbor.M toMap() {
            return new Cbor.M(List.of(
                    new Cbor.Pair(new Cbor.U(1), new Cbor.B(toolId)),
                    new Cbor.Pair(new Cbor.U(2), new Cbor.B(argsId))));
        }

        /** Deterministic-CBOR encoding of the call binding {1:tool_id, 2:args_id}. */
        public byte[] bytes() {
            return Cbor.encode(toMap());
        }

        /** The call content id an approval binds. */
        public byte[] contentId() {
            return Mcp.contentId(bytes());
        }
    }

    /** Compute the binding from the raw tool and args bytes. */
    public static CallBinding newCallBinding(byte[] tool, byte[] args) {
        return new CallBinding(contentId(tool), contentId(args));
    }

    // ---- kind validation (composes with the frozen baseline) --------------------------------------

    /** Accepts exactly this surface's tier-1 kind (Bridge channel, McpToolCall). */
    public static boolean kindValidator(long channel, long kind) {
        return channel == CHANNEL_BRIDGE && kind == KIND_MCP_TOOL_CALL;
    }

    private static boolean baselineKindValidator(long channel, long kind) {
        try {
            Channels.lookup(channel, kind);
            return true;
        } catch (NaalpException e) {
            return false;
        }
    }

    /** Accepts the frozen baseline kinds OR the tier-1 McpToolCall — the validator an MCP-aware
     * endpoint passes to {@link Envelope#verify}. A baseline-only endpoint using the baseline validator
     * alone correctly rejects an McpToolCall as UnknownKind (fail-closed). */
    public static boolean composedKindValidator(long channel, long kind) {
        return baselineKindValidator(channel, kind) || kindValidator(channel, kind);
    }

    // ---- verified tool call -----------------------------------------------------------------------

    /** An MCP tool call that has passed envelope verification and effect resolution. It carries the
     * enforced effect (the more-severe value C5 authorizes on), whether the annotation and declared
     * effect disagreed (mismatch — attributable to signer), and the parsed tool call. */
    public static final class Resolved {
        public final byte[] contentId;
        public final byte[] signer;
        public final ToolCall toolCall;
        public final long annotationMapped;
        public final long declared;
        public final long enforced;
        public final boolean mismatch;

        Resolved(byte[] contentId, byte[] signer, ToolCall toolCall, long annotationMapped, long declared,
                 long enforced, boolean mismatch) {
            this.contentId = contentId;
            this.signer = signer;
            this.toolCall = toolCall;
            this.annotationMapped = annotationMapped;
            this.declared = declared;
            this.enforced = enforced;
            this.mismatch = mismatch;
        }
    }

    /** Verify a signed MCP wrapper end-to-end and resolve its enforced effect. It (1) verifies the
     * signed object with real crypto ({@link Envelope#verify} against the composed validator — content
     * id, ranges, header/body, kind dispatch, signature); (2) confirms it is a tier-1 Bridge
     * McpToolCall; (3) parses the tool-call body (rejecting a malformed annotation set); (4) recomputes
     * the annotation-derived effect from the CARRIED annotations, independent of the declared effect;
     * (5) resolves the enforced effect to the MORE SEVERE, rejecting under-declaration. The enforced
     * effect equals the declared envelope effect on success, so the object's field 7 is the correct C5
     * authorization input. Any failure returns its named error and authorizes nothing (fail-closed). */
    public static Resolved verifyToolCall(int profile, int alg, byte[] pubkey, byte[] signedObj) {
        Envelope.Object o = Envelope.verify(profile, alg, pubkey, Mcp::composedKindValidator, signedObj, null);
        if (o.channel != CHANNEL_BRIDGE || o.kind != KIND_MCP_TOOL_CALL || o.tier != TIER) {
            throw new NaalpException("ToolCallMalformed", "not a tier-1 Bridge McpToolCall");
        }
        ToolCall tc = toolCallFromBody(o.body);
        long mapped = mapAnnotationsToEffect(tc.annotations);
        long declared = o.effect; // envelope.verify already range-checked field 7 to 0..3
        Resolution res = resolveEnforcedEffect(mapped, declared);
        return new Resolved(o.id, o.signer, tc, mapped, declared, res.enforced, res.mismatch);
    }

    // ---- the per-call approval gate (reuses §7 approval + consume ledger) --------------------------

    /** Enforce the profile's per-call approval gate for a verified tool call. The approval MUST bind the
     * EXACT call binding content id (tool_id + args_id) — so it satisfies neither a call with different
     * arguments nor a call whose tool description changed (Requirement 6.1) — its granted effect must
     * cover the call's ENFORCED (more-severe) effect, it must be unexpired at {@code now}, and it is
     * consumed single-use by {@code by} through the §7 ledger. Precedence and fail-closed behaviour
     * mirror the spine: a non-matching or under-granting approval denies ApprovalRequired with no ledger
     * append; an already-spent approval denies AlreadyConsumed; the consume (the single state change)
     * happens only when every check holds. */
    public static void authorizeCall(Resolved r, Approval.ApprovalRecord appr, int approverAlg,
                                     byte[] approverPubkey, byte[] apprSig, String by, long now,
                                     Approval.Ledger ledger) {
        byte[] callCid = r.toolCall.callBinding().contentId();
        try {
            Approval.verifyApproval(appr, approverAlg, approverPubkey, apprSig, callCid, now);
        } catch (NaalpException e) {
            // A mismatch on the exact call bytes is a held outcome, not a silent pass (§7.3/§7.4).
            if (e.kind.equals("ApprovalMismatch")) {
                throw new NaalpException("ApprovalRequired", "approval does not bind this exact call");
            }
            throw e;
        }
        if (!Policy.authorizes(appr.grant, r.enforced)) {
            throw new NaalpException("ApprovalRequired", "the approval's granted effect does not cover the call");
        }
        ledger.consume(appr.id(), by); // AlreadyConsumed on replay (fail-closed, no double-spend)
    }
}
